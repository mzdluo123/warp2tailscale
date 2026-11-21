# warp2tailscale

将一台 Linux 主机作为 Tailscale 出口。默认通过 Cloudflare WARP（MASQUE）访问公网，也可通过宿主机网络直接出站。客户端选中出口节点后，普通应用即可按系统路由访问公网。两种模式都在节点内的 gVisor 用户态网络栈接管客户端侧 TCP。

```text
Tailscale 客户端 ⇄ WireGuard ⇄ tsnet ┬─ TCP 中继 ───┬─ WARP 内存网络栈 ⇄ MASQUE ⇄ 公网
                                     └─ UDP/ICMP NAT ┘
Tailscale 客户端 ⇄ WireGuard ⇄ tsnet ── TCP/UDP 中继 ── 宿主机套接字 ⇄ 公网（direct）
```

## 协议支持

| 流量 | `warp`（默认） | `direct` |
|---|---|---|
| 公网 IPv4 / IPv6 TCP | 通过 WARP gVisor 栈连接公网。 | 通过宿主机 TCP socket 连接公网。 |
| 公网 IPv4 / IPv6 UDP | WARP 内存栈做源地址转换。 | 按流使用宿主机 UDP socket。 |
| Tailscale 出口 DNS | PeerAPI 检查客户端权限和查询名，再经 WARP 向 `1.1.1.1:53` 查询。 | 同样的 PeerAPI 校验，经宿主机连接 `1.1.1.1:53`。 |
| 公网 IPv4 / IPv6 ICMP | 支持 echo 和流关联的 ICMP 错误，包括超时、不可达和 MTU 通知。 | 支持 echo。UDP socket 收到的不可达、Packet Too Big 等错误目前不会转成客户端侧 ICMP 报文。 |

`policy.udp: all` 允许任意公网目的端口，包括 DNS、QUIC 和 HTTP/3。`dns-only` 限制为 UDP/53。PeerAPI DNS 在两种模式下都使用 TCP。设置 `policy.icmp: true` 开启公网 echo。 直连在隔离网络中验证了双栈 1200 字节 UDP 回显。超过 Tailscale MTU 的 UDP 回包依赖客户端路径上的分片重组，2400 字节 IPv4 回显在 tsnet 客户端测试中超时。

WARP 会话断开时，节点关闭该会话中的连接，并拒绝新的出口连接，直到隧道恢复。WARP 公网测试中，HTTP/3、双栈 ping 以及 160 和 1200 字节的 UDP 回显成功。2400 字节的 UDP 回显双栈均超时，节点已观察到 IP 重组并向 WARP 发送分片。内存网络中的双栈大数据报往返测试通过。IPv6 含多重扩展头的报文沿用 Tailscale 内层解析器的限制。

## 在 Linux 上运行

需要 Go 1.26.4 或更新版本，以及一个可注册设备的 Tailnet 账号。WARP 模式还需要可建立 MASQUE 连接的网络。在仓库根目录构建，本地修改的依赖由根模块的 `replace` 指向。

```bash
mkdir -p bin
CGO_ENABLED=0 go build -o bin/exitnode ./cmd/exitnode
(cd third_party/usque && CGO_ENABLED=0 go build -o ../../bin/usque .)
cp config.example.yaml config.yaml
install -d -m 700 state/warp state/tsnet
```

**WARP 模式。** 省略 `egress.mode` 时使用 `warp`。已有 usque 注册文件可用 `install -m 600 /path/to/warp.json state/warp/config.json` 安装。首次注册可执行以下命令并按提示阅读和接受 Cloudflare 条款。

```bash
(umask 077 && ./bin/usque -c state/warp/config.json register)
chmod 600 state/warp/config.json
```

**直连模式。** 在配置文件中设置以下选项。可以删除整个 `warp` 段并跳过 WARP 注册和 usque 构建。

```yaml
egress:
  mode: direct
```

公网 IPv4 和 IPv6 分别使用服务进程所在网络命名空间的路由。宿主机应使用自己的公网出口，并避免将默认路由指回这个 Tailscale 出口。启用 `policy.icmp` 时，Linux 的 `net.ipv4.ping_group_range` 必须包含服务用户的组 ID，程序会在启动时检查双栈 ping socket 权限。可设 `policy.icmp: false` 仅运行 TCP 和 UDP。

**加入 Tailnet。** 以下 Bash 命令交互式读取 Tailscale auth key。后续启动会复用 `state/tsnet` 中的设备身份。

```bash
read -rsp 'Tailscale auth key: ' tskey && echo
TS_AUTHKEY="$tskey" ./bin/exitnode -config config.yaml
```

在 Tailscale 管理后台批准该设备作为出口节点，再在客户端选择配置中的节点名并启用 Tailscale DNS。独立客户端可以用以下命令检查默认 DNS 和实际公网出口。WARP 模式的 trace 应包含 `warp=on` 或 `warp=plus`。直连模式的 `ip=` 应与宿主机直接访问同一目标时一致。

```bash
curl --noproxy '*' -fsS https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|warp)='
dig @100.100.100.100 example.com AAAA
```

`tailscale.port` 可设置 Tailscale UDP 首选监听端口；0 自动选择。Tailnet 若启用了客户端端口随机化，以节点实际通告的端点为准。

常驻部署可使用仓库中的 systemd 单元。它以 `warp2tailscale` 用户运行，从 `/opt/warp2tailscale/exitnode` 启动，读取 `/etc/warp2tailscale/config.yaml`。配置内的相对路径以工作目录 `/var/lib/warp2tailscale` 为基准。首次注册与后续服务应使用同一个状态目录和服务用户。[systemd 单元](deploy/warp2tailscale.service)

计划重启时，出口先拒绝新的 TCP 连接，再通过仍在线的 Tailscale 隧道向存续连接发送 RST。`tcp.shutdown_grace_period` 为报文送出和处理客户端响应预留时间，默认 2 秒。正常完成的 TCP 传输继续使用 FIN。断电、强制终止或链路丢包时，客户端仍可能超时。

## TCP 调优

修改 YAML 后重启节点。缓冲区按连接设置，在客户端侧 gVisor 栈及启用 WARP 时的公网侧 gVisor 栈上生效。两种出站模式下，拥塞算法和 BBR 参数都作用于节点向 Tailscale 客户端发送数据的内层 TCP。直连的公网侧 socket 使用宿主机 TCP 设置。[完整示例配置](config.example.yaml)

| 配置项 | 可选值 | 示例配置 |
|---|---|---|
| `congestion.type` | `bbr`、`cubic`、`reno` | `bbr` |
| `congestion.initial_cwnd_packets` | 4–128 个 MSS，0 使用默认值 | 32 |
| `congestion.pacing_burst_packets` | 每次发包最多 1–32 个 MSS，0 使用栈默认值 1 | 24 |
| `congestion.pacing_burst_window` | 0–10 ms，以当前速率限制每一批可提前发送的数据量，0 仅使用包数限制 | 1ms |
| `congestion.max_pacing_bytes_per_second` | 每条客户端方向 TCP 的 pacing 速率上限，0 由 BBR 估算 | 0 |
| `warp.http3_receive_ring` | 启用 32 槽 HTTP/3 数据报接收环形队列。两种队列的容量均为 32，重启生效。 | `false` |
| `warp.packet_queue_packets` | WARP 出口队列容量，1–256 包，0 使用默认值 32 | 32 |
| `runtime.max_procs` | Go 同时执行的逻辑处理器数，0 使用运行时默认值 | 1 |
| `runtime.udp_gso` | `true` 允许 WireGuard 和 MASQUE 使用 UDP GSO，`false` 在本进程禁用。省略时沿用两个库的环境设置。重启后生效。 | `true` |
| `tcp.send_buffer_bytes` | 4096–67108864 字节，0 使用栈默认值 | 8388608（8 MiB） |
| `tcp.receive_buffer_bytes` | 同上 | 4194304（4 MiB） |

同一台出口节点、同一个双栈客户端和同一公网 CDN，使用无代理 HTTPS 分段下载，每组 5 次、每次 15 MiB。下载时每 200 ms 向出口节点的 Tailscale 地址发一个 ping。下表给出各轮吞吐、RTT 和出口服务每传输 1 MiB 消耗的 CPU 时间的中位数。

| BBR 突发 / 时间上限 / 单流速率上限 / Go 并行度 | 吞吐 MB/s | 空闲 RTT P50 | 下载时 RTT P95 | CPU ms/MiB |
|---|---:|---:|---:|---:|
| 16 MSS / 关闭 / 自动 / 自动 | 5.96 | 184 ms | 186 ms | 56.78 |
| 16 MSS / 关闭 / 自动 / 自动（另一时段） | 3.06 | 203 ms | 237 ms | 114.10 |
| 32 MSS / 2 ms / 12 MB/s / 2 | 4.97 | 175 ms | 178 ms | 65.62 |
| 16 MSS / 2 ms / 24 MB/s / 自动 | 4.90 | 217 ms | 228 ms | 71.00 |

上表中 Go 并行度为 2 的测试使用 32 MSS、2 ms 的突发上限和 32 包的 WARP 队列。表内各轮在下载开始、结束时均确认 Tailscale 直连。不同轮次可能走不同的 IPv4 或 IPv6 公网端点，空闲 RTT 也随之变化。CPU 统计包含服务同时处理的其他流量，表中差异不能全归因于配置。另一次非稳定路径测试中，下载期间的 RTT P95 达到 1001 ms。当时选用的配置也遇到过持续 120 秒的下载超时，当次只收到约 4 MB，采到的 250 个 ping 中丢失 46.4%。这些测试没有注入丢包。

## 验证

### 单核吞吐和延迟

要给整个出口进程分配一个逻辑 CPU，可在 systemd 服务的 `[Service]` 中设置 `CPUAffinity=1`，并将 YAML 的 `runtime.max_procs` 设为 `1`。将 CPU 编号换成该主机可用的编号。前者约束所有线程，后者控制 Go 的执行并行度。

在支持 x86-64-v4 的 Linux amd64 主机上，可用以下命令构建针对该指令集的出口程序。通用构建命令见上文。

```sh
CGO_ENABLED=0 GOAMD64=v4 go build -trimpath -o bin/exitnode ./cmd/exitnode
```

下面的测试在一个逻辑 CPU 上运行两个 tsnet 端点，传输 512 MiB，同时通过第二条 TCP 连接测量小请求的往返时间。输出包括应用吞吐、CPU 时间、空闲和负载下的 RTT P95。它只测 Tailscale 段。测完整出口时，另从独立客户端经 WARP 做不限速 HTTPS 下载，同时测到出口和公网地址的 RTT，并记录直连端点是否切换。

```sh
CGO_ENABLED=0 GOAMD64=v4 go test -tags exitbench -c -o bin/exitbench tailscale.com/tsnet
GOMAXPROCS=1 TS_NO_LOGS_NO_SUPPORT=true taskset -c 1 bin/exitbench \
  -test.cpu=1 -test.run '^TestExitSingleCoreTransfer$' -test.v
```

s2 上启用 `runtime.udp_gso` 后，WireGuard 实际将多个数据报交给 Linux 做软件分段。一个直连端点保持稳定的测试时段内，单流三轮下载的中位数为 13.60 MB/s，16 流为 28.63 MB/s；空闲 RTT 为 177 ms，下载时的 RTT P95 分别为 178 和 179 ms。另一个时段在 24 流下出现过明显的延迟波动。详细的上传、下载系统调用、GSO 开关对照和 WARP 试验结果见验收记录。[单核验收记录](docs/single-core.md)

### 包处理和协议检查

可用下列命令测量 TCP 校验和验证、接收缓冲区复制和应用读取这段路径的耗时与堆分配。

```sh
go test tailscale.com/wgengine/netstack/gro -run '^$' -bench '^BenchmarkTCPReceive$' -benchmem -cpu 1 -count 3
```

在同一台 Linux 出口服务器上交替运行优化前后的版本，1200 字节 TCP 载荷的中位耗时从 438 ns 降到 170 ns，每包堆分配从 1 次降到 0 次。评估实际出口服务时，还需同时记录完整下载期间的服务 CPU 时间、下载字节数和负载下的 RTT。

WARP 接收路径使用基于 quic-go v0.59.0 的本地版本。QUIC 接收队列接管解析器已复制的 DATAGRAM 载荷，开启 `warp.http3_receive_ring` 时，HTTP/3 流在收到首个数据报时分配 32 槽环形队列。可单独测量这两段的每包耗时和分配量。

```sh
(cd third_party/quic-go && go test -run '^$' -cpu 1 -benchmem \
  -bench '^Benchmark(ParseEnqueueReceiveDatagram|StreamDatagramQueue)$' . ./http3)
```

`bash scripts/test-mvp.sh local` 构建程序并运行 Go 测试。已选中出口且启用 Tailscale DNS 的双栈 Linux 客户端可运行 `bash scripts/test-mvp.sh client`；需要支持 HTTP/3 的 curl、dig 和 ping。它会验证默认解析、双栈 HTTPS、显式 UDP/53、HTTP/3 和公网 echo。直连测试设置 `EXIT_EGRESS=direct`，并用 `EXIT_DIRECT_IPV4` 和 `EXIT_DIRECT_IPV6` 指定宿主机的公网出口地址。测试旧策略时可设置 `EXIT_UDP_POLICY=dns-only EXIT_ICMP=false`。示例中的 `logging.quiet_flows: true` 关闭逐流和 DNS 查询日志，保留节点启动与 WARP 会话状态。需要核对单条连接时，设为 `false` 并重启。按 TCP 四元组核对 BBR 日志与本地 tailscale0 抓包的用法见 `python3 scripts/verify-bbr-flow.py --help`。

本项目包含修改过的上游源码。相应许可证见 [Tailscale](third_party/tailscale/LICENSE)、[gVisor](third_party/gvisor/LICENSE)、[wireguard-go](third_party/wireguard/LICENSE)、[usque](third_party/usque/LICENSE.md) 和 [quic-go](third_party/quic-go/LICENSE)。

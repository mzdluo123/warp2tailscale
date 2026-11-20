# warp2tailscale

把 Cloudflare WARP 作为 Tailscale 出口。节点在一个 Go 进程中运行 tsnet、两个 gVisor 网络栈和 usque 的 MASQUE 隧道。客户端选中出口节点后，普通应用即可按系统路由访问公网。

```text
Tailscale 客户端 ⇄ WireGuard ⇄ tsnet / gVisor TCP ⇄ Go 中继 ⇄ WARP 内存网络栈 ⇄ MASQUE ⇄ 公网
```

## 协议支持

| 流量 | 行为 |
|---|---|
| 公网 IPv4 / IPv6 TCP | 经 WARP 转发。节点向客户端发送的内层 TCP 支持 BBRv1、CUBIC 和 Reno。 |
| 公网 UDP/53 | 保留数据报边界，转发到客户端指定的公网 DNS 服务器。 |
| Tailscale 出口 DNS | PeerAPI 检查客户端权限和查询名，然后通过 WARP 向 `1.1.1.1:53` 发送 DNS-over-TCP 查询。 |
| 其他公网 UDP、ICMP | 丢弃。仅支持 QUIC 的应用及公网 ping 无法使用。 |

WARP 会话断开时，节点关闭该会话中的连接，并拒绝新的出口连接，直到隧道恢复。Tailnet 和 WARP 的外层连接使用宿主机网络。

## 在 Linux 上运行

需要 Go 1.26.4 或更新版本、一个可注册设备的 Tailnet 账号，以及可建立 MASQUE 连接的网络。在仓库根目录构建，四个本地修改的依赖由根模块的 `replace` 指向。

```bash
mkdir -p bin
CGO_ENABLED=0 go build -o bin/exitnode ./cmd/exitnode
(cd third_party/usque && CGO_ENABLED=0 go build -o ../../bin/usque .)
cp config.example.yaml config.yaml
install -d -m 700 state/warp state/tsnet
```

**获取 WARP 凭据。** 已有 usque 注册文件可用 `install -m 600 /path/to/warp.json state/warp/config.json` 安装。首次注册可执行以下命令并按提示阅读和接受 Cloudflare 条款。

```bash
(umask 077 && ./bin/usque -c state/warp/config.json register)
chmod 600 state/warp/config.json
```

**加入 Tailnet。** 以下 Bash 命令交互式读取 Tailscale auth key。后续启动会复用 `state/tsnet` 中的设备身份。

```bash
read -rsp 'Tailscale auth key: ' tskey && echo
TS_AUTHKEY="$tskey" ./bin/exitnode -config config.yaml
```

在 Tailscale 管理后台批准该设备作为出口节点，再在客户端选择配置中的节点名并启用 Tailscale DNS。独立客户端可以用以下命令检查默认 DNS 和实际公网出口。trace 中应出现 `warp=on` 或 `warp=plus`。

```bash
curl --noproxy '*' -fsS https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|warp)='
dig @100.100.100.100 example.com AAAA
```

常驻部署可使用仓库中的 systemd 单元。它以 `warp2tailscale` 用户运行，从 `/opt/warp2tailscale/exitnode` 启动，读取 `/etc/warp2tailscale/config.yaml`。配置内的相对路径以工作目录 `/var/lib/warp2tailscale` 为基准。首次注册与后续服务应使用同一个状态目录和服务用户。[systemd 单元](deploy/warp2tailscale.service)

## TCP 调优

修改 YAML 后重启节点。缓冲区按连接设置，在客户端侧和 WARP 侧两个 TCP 栈上生效。拥塞算法和 BBR 参数作用于节点向 Tailscale 客户端发送数据的内层 TCP。[完整示例配置](config.example.yaml)

| 配置项 | 可选值 | 示例配置 |
|---|---|---|
| `congestion.type` | `bbr`、`cubic`、`reno` | `bbr` |
| `congestion.initial_cwnd_packets` | 4–128 个 MSS，0 使用默认值 | 32 |
| `congestion.pacing_burst_packets` | 1–16 个 MSS，0 使用默认值 | 1 |
| `tcp.send_buffer_bytes` | 4096–67108864 字节，0 使用栈默认值 | 0 |
| `tcp.receive_buffer_bytes` | 同上 | 0 |

一次约 190 ms RTT 的跨机实测中，初始窗口固定为 32 MSS，将 pacing burst 从 1 调到 16 MSS，同一 8 MiB 公网下载由 0.62 MB/s 增至 3.31 MB/s。该路径上，发送/接收缓冲区从 4/2 MiB 调到 8/4 MiB 的收益小于样本间波动。

## 验证

`bash scripts/test-mvp.sh local` 构建程序并运行 Go 测试。已选中出口且启用 Tailscale DNS 的双栈 Linux 客户端可运行 `bash scripts/test-mvp.sh client`；需要 curl、dig 和 Python 3。它会验证默认解析、IPv4/IPv6 HTTPS 和显式 UDP/53。按 TCP 四元组核对 BBR 日志与本地 tailscale0 抓包的用法见 `python3 scripts/verify-bbr-flow.py --help`。

本项目包含修改过的上游源码。相应许可证见 [Tailscale](third_party/tailscale/LICENSE)、[gVisor](third_party/gvisor/LICENSE)、[wireguard-go](third_party/wireguard/LICENSE) 和 [usque](third_party/usque/LICENSE.md)。

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# The client commands run on the chosen test client. Set CLIENT_NS when it is a
# local Linux test namespace. --resolve pins only the target, retaining HTTPS
# certificate verification and bypassing the client's special DNS paths.
client() {
  if [[ -n ${CLIENT_NS:-} ]]; then sudo ip netns exec "$CLIENT_NS" "$@"; else "$@"; fi
}
case ${1:-local} in
  local)
    mkdir -p bin
    CGO_ENABLED=0 go build -o bin/exitnode ./cmd/exitnode
    CGO_ENABLED=0 go build -o bin/warp-smoke ./cmd/warp-smoke
    CGO_ENABLED=0 go build -tags mvptest -o bin/exitnode-test ./cmd/exitnode
    go test ./...
    (cd third_party/quic-go && go test -run '^Test(ReceivedDatagram(OwnsPayload|RingWrapAndOverflow)|DatagramRingSelection)$' . ./http3)
    go test tailscale.com/net/batching tailscale.com/wgengine/netstack/gro gvisor.dev/gvisor/pkg/buffer gvisor.dev/gvisor/pkg/tcpip/stack
    go test -run "^TestReceiveBatch(BindBuffers|Size)$" tailscale.com/wgengine/magicsock
    go test -count=1 -run "TestExitTCPShutdown|TestFallback(TCPHandler|UDPPriority)|TestUDPConn|TestDialUDP" tailscale.com/tsnet
    go test -count=1 -v -run 'TestBBR|TestDisconnect|TestEndpointBufferSelection' github.com/Diniboy1123/usque/bridge gvisor.dev/gvisor/pkg/tcpip/transport/tcp
    ;;
  smoke)
    : "${WARP_CONFIG:?set to registered usque config}"
    go run ./cmd/warp-smoke
    ;;
  client)
    # Exercise the name resolution used by applications before pinning any IP.
    trace=$(client curl -q --noproxy '*' --max-time 20 -fsS https://www.cloudflare.com/cdn-cgi/trace)
    grep -Eq '^warp=(on|plus)$' <<<"$trace"
    for kind in A AAAA; do
      answer=$(client dig +time=5 +tries=2 +noall +answer @100.100.100.100 example.com "$kind")
      grep -E "[[:space:]]$kind[[:space:]]" <<<"$answer"
    done
    for fam in 4 6; do
      addr=104.16.123.96
      resolver=1.1.1.1
      type=A
      if [[ $fam == 6 ]]; then addr='[2606:4700::6810:7b60]'; resolver=2606:4700:4700::1111; type=AAAA; fi
      trace=$(client curl --noproxy '*' --retry 2 --max-time 25 "-$fam" --resolve "www.cloudflare.com:443:$addr" -fsS https://www.cloudflare.com/cdn-cgi/trace)
      grep -E '^(ip|warp)=' <<<"$trace"
      grep -Eq '^warp=(on|plus)$' <<<"$trace"
      answer=$(client dig +time=5 +tries=3 +noall +answer "@$resolver" example.com "$type")
      grep -E "[[:space:]]$type[[:space:]]" <<<"$answer"
      if [[ ${EXIT_UDP_POLICY:-all} == all ]]; then
        quic=$(client curl -q --http3-only --noproxy '*' --max-time 20 "-$fam" --resolve "www.cloudflare.com:443:$addr" -fsS https://www.cloudflare.com/cdn-cgi/trace -w 'http=%{http_version}\n')
        grep -Eq '^warp=(on|plus)$' <<<"$quic"
        grep -Fx 'http=3' <<<"$quic"
      fi
      if [[ ${EXIT_ICMP:-true} == true ]]; then
        client ping "-$fam" -n -c 2 -W 3 "$resolver"
      fi
    done
    client curl --noproxy '*' --max-time 20 --resolve dns.google:443:8.8.8.8 -fsS 'https://dns.google/resolve?name=example.com&type=A' | python3 -c 'import sys,json; assert json.load(sys.stdin)["Status"] == 0'
    if [[ ${EXIT_UDP_POLICY:-all} == dns-only && -n ${NODE_LOG:-} ]]; then
      client python3 -c 'import socket; socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b"policy-check",("9.9.9.9",443))'
      for _ in {1..30}; do
        grep -q 'reject proto=udp .*dst=9.9.9.9:443 ' "$NODE_LOG" && break
        sleep .1
      done
      grep 'reject proto=udp .*dst=9.9.9.9:443 ' "$NODE_LOG" | tail -1
    fi
    ;;
  download)
    : "${BENCH_IP:?pin deb.debian.org IPv4 for the duration of both runs}"
    row=$(client curl --http1.1 --noproxy '*' --resolve "deb.debian.org:443:$BENCH_IP" --max-time 90 --range 0-2097151 -fsS https://deb.debian.org/debian/ls-lR.gz -o /dev/null -w '%{http_code} %{local_port} %{size_download} %{speed_download} %{time_total}')
    read -r status port bytes rate seconds <<<"$row"
    [[ $status == 206 && $bytes == 2097152 ]]
    echo "$row"
    ;;
  capture-check)
    : "${CAPTURE:?host eth0 pcap}" "${MASQUE_IP:?configured IPv4 outer endpoint}"
    # The capture must cover both the application destinations and the outer flow.
    outer=$(tcpdump -nnqr "$CAPTURE" "host $MASQUE_IP and udp port 443" | wc -l)
    targets='dst host 104.16.123.96 or dst host 2606:4700::6810:7b60 or dst host 1.1.1.1 or dst host 2606:4700:4700::1111 or dst host 8.8.8.8 or dst host 9.9.9.9'
    if [[ -n ${BENCH_IP:-} ]]; then targets="$targets or dst host $BENCH_IP"; fi
    direct=$(tcpdump -nnqr "$CAPTURE" "$targets" | wc -l)
    echo "outer_packets=$outer direct_target_packets=$direct"
    [[ $outer -gt 0 && $direct -eq 0 ]]
    ;;
  *) echo "usage: $0 {local|smoke|client|download|capture-check}" >&2; exit 2;;
esac

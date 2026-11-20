#!/usr/bin/env python3
"""Correlate one gVisor sender with payload delivered on a client Tailscale capture."""
import argparse
import ipaddress
import re
import subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("capture", type=Path)
p.add_argument("server_log", type=Path)
p.add_argument("sender", type=ipaddress.ip_address)
p.add_argument("sender_port", type=int)
p.add_argument("client", type=ipaddress.ip_address)
p.add_argument("client_port", type=int)
args = p.parse_args()
for port in (args.sender_port, args.client_port):
    if not 0 < port < 65536:
        p.error("expected a numeric TCP port in 1..65535")

flow = f"flow={{{args.sender_port} {args.sender} {args.client_port} {args.client}}} cc=bbr "
records = [line for line in args.server_log.read_text().splitlines() if flow in line]
paced = [line for line in records if re.search(r"paced_waits=[1-9]\d*", line)]
if not paced:
    p.exit(1, "no matching BBR sender with observed pacing waits\n")

bpf = (f"tcp and src host {args.sender} and src port {args.sender_port} "
       f"and dst host {args.client} and dst port {args.client_port}")
# Absolute sequence numbers let retransmissions and overlapping GRO segments
# be counted once. These bounded download probes are smaller than 2**31 bytes.
rows = subprocess.run(["tcpdump", "-nn", "-tt", "-S", "-r", str(args.capture), bpf],
                      capture_output=True, text=True, check=True).stdout.splitlines()
intervals = []
first_seq = None
for row in rows:
    packet = re.search(r"seq (\d+):\d+,.* length (\d+)$", row)
    if packet:
        seq, size = map(int, packet.groups())
        if first_seq is None:
            first_seq = seq
        offset = ((seq - first_seq + 2**31) % 2**32) - 2**31
        intervals.append((offset, offset + size))
if not intervals:
    p.exit(1, "no matching inner TCP payload in capture\n")
unique = 0
end = min(start for start, _ in intervals)
for start, stop in sorted(intervals):
    unique += max(0, stop - max(start, end))
    end = max(end, stop)
print(paced[-1])
print(f"inner_data_packets={len(intervals)} unique_tcp_payload_bytes={unique}")

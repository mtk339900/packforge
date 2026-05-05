# PacketForge

A raw packet crafter and sniffer written in C — no libpcap, no libc networking abstractions beyond BSD sockets. Think Scapy but compiled, zero-dependency, and ~10× faster to launch.

> Requires **root** or `CAP_NET_RAW` / `CAP_NET_ADMIN`.

---

## Features

| Layer | Protocols |
|-------|-----------|
| L2    | Ethernet  |
| L3    | IPv4, ARP |
| L4    | TCP, UDP, ICMP |

- **craft** — build and inject any packet with full field control  
- **sniff** — colorized live dissector with optional `.pcap` output  
- **arp-scan** — subnet scanner using raw ARP probes  
- **ping** — ICMP echo using raw L2 sockets (bypasses the kernel pinger)  
- Correct one's-complement checksums for IP / TCP / UDP / ICMP  
- Pseudo-header checksum computation for TCP & UDP  
- `.pcap` output compatible with Wireshark / tshark  
- Promiscuous mode on request  

---

## Build

```bash
git clone https://github.com/mtk339900/packforge
cd packforge
make
sudo make install        # optional: installs to /usr/local/bin
```

Requirements: `gcc`, `make`, `pthread` (standard on every Linux distro).

---

## Usage

### Sniff
```bash
# Basic — print all packets on eth0
sudo packforge sniff -i eth0

# Verbose: show Ethernet addresses + IP fields
sudo packforge sniff -i eth0 -v

# Extra verbose: + full hex dump
sudo packforge sniff -i eth0 -vv

# Capture 100 packets and write to file
sudo packforge sniff -i eth0 -c 100 -w capture.pcap
```

### Craft
```bash
# TCP SYN
sudo packforge craft -i eth0 --proto tcp \
    --src-ip 192.168.1.10 --dst-ip 192.168.1.1 \
    --sport 54321 --dport 80 --flags SYN

# TCP SYN+ACK
sudo packforge craft -i eth0 --proto tcp \
    --src-ip 10.0.0.2 --dst-ip 10.0.0.1 \
    --sport 80 --dport 54321 --flags SYN,ACK \
    --seq 0 --ack-seq 1

# UDP with payload (send 5 times)
sudo packforge craft -i eth0 --proto udp \
    --src-ip 192.168.1.10 --dst-ip 192.168.1.1 \
    --sport 5000 --dport 53 --payload "hello" -n 5

# ICMP Echo Request
sudo packforge craft -i eth0 --proto icmp \
    --src-ip 192.168.1.10 --dst-ip 192.168.1.1

# ARP Request
sudo packforge craft -i eth0 --proto arp \
    --src-ip 192.168.1.10 --dst-ip 192.168.1.1

# Spoof source MAC + IP
sudo packforge craft -i eth0 --proto tcp \
    --src-mac de:ad:be:ef:00:01 --dst-mac ff:ff:ff:ff:ff:ff \
    --src-ip 10.10.10.1 --dst-ip 10.10.10.2 \
    --sport 1234 --dport 4444 --flags RST
```

### ARP Scan
```bash
sudo packforge arp-scan -i eth0 --range 192.168.1.0/24
```
```
[*] ARP scanning 192.168.1.0/24 (254 hosts) on eth0
    IP                  MAC
    -----------------------------------------------
[+] 192.168.1.1         c8:3a:35:12:ab:cd
[+] 192.168.1.105       b8:27:eb:44:11:22
[*] Scan complete.
```

### Ping
```bash
sudo packforge ping -i eth0 --dst 192.168.1.1 -c 4
```
```
[*] PING 192.168.1.1 from eth0 via eth0
[+] Reply from 192.168.1.1: seq=1  time=0.43 ms
[+] Reply from 192.168.1.1: seq=2  time=0.38 ms
```

---

## Architecture

```
packforge/
├── src/
│   ├── main.c               # CLI dispatcher (sniff / craft / arp-scan / ping)
│   ├── net/
│   │   ├── checksum.{h,c}   # RFC 1071 one's-complement checksum
│   │   ├── ethernet.{h}     # Ethernet header definitions
│   │   ├── ip.{h,c}         # IPv4 header builder
│   │   ├── tcp.{h,c}        # TCP header builder + flag parser
│   │   ├── udp.{h,c}        # UDP header builder
│   │   ├── icmp.{h,c}       # ICMP header builder
│   │   └── arp.{h,c}        # ARP header builder
│   ├── forge/
│   │   └── forge.{h,c}      # PacketBuilder — layered packet assembly API
│   ├── sniff/
│   │   ├── sniffer.{h,c}    # AF_PACKET capture loop + promiscuous mode
│   │   └── dissect.{h,c}    # Protocol dissector with ANSI colorized output
│   └── util/
│       ├── iface.{h,c}      # Interface MAC/IP/index lookup
│       └── pcap.{h,c}       # libpcap-compatible .pcap writer
└── Makefile
```

---

## PacketBuilder API

```c
#include "forge/forge.h"

PacketBuilder *b = pf_new();

// Stack layers bottom-up
pf_add_ethernet(b, src_mac, dst_mac, ETH_P_IP);
pf_add_ip(b, src_ip, dst_ip, IPPROTO_TCP, 64 /*ttl*/);
pf_add_tcp(b, 12345, 80, 0, 0, TCP_SYN, 65535);
pf_add_payload(b, (uint8_t *)"GET / HTTP/1.0\r\n\r\n", 18);

// Send (checksums computed automatically)
pf_send(b, "eth0", 1 /*count*/);

pf_free(b);
```

---

## Comparison

| Feature            | PacketForge | Scapy   |
|--------------------|-------------|---------|
| Language           | C           | Python  |
| Startup time       | ~1 ms       | ~300 ms |
| External deps      | none        | many    |
| .pcap output       | ✓           | ✓       |
| Live dissector     | ✓           | ✓       |
| Packet crafting    | ✓           | ✓       |
| Scriptable         | C API       | Python  |
| IPv6               | planned     | ✓       |

---

## Roadmap

- [ ] IPv6 + ICMPv6
- [ ] DNS / HTTP payload helpers
- [ ] BPF-style packet filter  
- [ ] TCP handshake automation
- [ ] Flood mode with rate control
- [ ] JSON output mode

---

## Legal

For authorized testing, education, and research only. Do not use on networks you don't own or have explicit permission to test.

---

## License

MIT

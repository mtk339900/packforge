#include "forge.h"
#include "../net/ethernet.h"
#include "../net/ip.h"
#include "../net/tcp.h"
#include "../net/udp.h"
#include "../net/icmp.h"
#include "../net/arp.h"
#include "../net/checksum.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

/* ------------------------------------------------------------------ */

PacketBuilder *pf_new(void) {
    PacketBuilder *b = calloc(1, sizeof(*b));
    if (b) pf_reset(b);
    return b;
}

void pf_free(PacketBuilder *b) { free(b); }

void pf_reset(PacketBuilder *b) {
    memset(b, 0, sizeof(*b));
    b->eth_off       = -1;
    b->ip_off        = -1;
    b->transport_off = -1;
    b->payload_off   = -1;
}

/* ------------------------------------------------------------------ */

int pf_add_ethernet(PacketBuilder *b,
                    const uint8_t *src_mac, const uint8_t *dst_mac,
                    uint16_t ethertype) {
    if ((int)b->len + ETH_HDR_LEN > PF_MAX_PKT) return -1;
    b->eth_off = (int)b->len;
    EthHeader *eth = (EthHeader *)(b->buf + b->eth_off);
    memcpy(eth->src, src_mac, ETH_ALEN);
    memcpy(eth->dst, dst_mac, ETH_ALEN);
    eth->ethertype = htons(ethertype);
    b->len += ETH_HDR_LEN;
    return 0;
}

int pf_add_ip(PacketBuilder *b, uint32_t src, uint32_t dst,
              uint8_t proto, uint8_t ttl) {
    if ((int)b->len + IP_HDR_LEN > PF_MAX_PKT) return -1;
    b->ip_off  = (int)b->len;
    b->src_ip  = src;
    b->dst_ip  = dst;
    b->ip_proto = proto;
    /* payload_len placeholder = 0; fixed in pf_finalize */
    pf_build_ip((IPv4Header *)(b->buf + b->ip_off), proto, src, dst, 0, ttl);
    b->len += IP_HDR_LEN;
    return 0;
}

int pf_add_tcp(PacketBuilder *b, uint16_t sport, uint16_t dport,
               uint32_t seq, uint32_t ack_seq, uint8_t flags, uint16_t window) {
    if ((int)b->len + TCP_HDR_LEN > PF_MAX_PKT) return -1;
    b->transport_off = (int)b->len;
    pf_build_tcp((TCPHeader *)(b->buf + b->transport_off),
                 sport, dport, seq, ack_seq, flags, window);
    b->len += TCP_HDR_LEN;
    return 0;
}

int pf_add_udp(PacketBuilder *b, uint16_t sport, uint16_t dport) {
    if ((int)b->len + UDP_HDR_LEN > PF_MAX_PKT) return -1;
    b->transport_off = (int)b->len;
    pf_build_udp((UDPHeader *)(b->buf + b->transport_off), sport, dport, 0);
    b->len += UDP_HDR_LEN;
    return 0;
}

int pf_add_icmp(PacketBuilder *b, uint8_t type, uint8_t code,
                uint16_t id, uint16_t seq) {
    if ((int)b->len + ICMP_HDR_LEN > PF_MAX_PKT) return -1;
    b->transport_off = (int)b->len;
    pf_build_icmp((ICMPHeader *)(b->buf + b->transport_off), type, code, id, seq);
    b->len += ICMP_HDR_LEN;
    return 0;
}

int pf_add_arp(PacketBuilder *b, uint16_t op,
               const uint8_t *sha, uint32_t spa,
               const uint8_t *tha, uint32_t tpa) {
    if ((int)b->len + ARP_HDR_LEN > PF_MAX_PKT) return -1;
    b->transport_off = (int)b->len;
    pf_build_arp((ARPHeader *)(b->buf + b->transport_off),
                 op, sha, spa, tha, tpa);
    b->len += ARP_HDR_LEN;
    return 0;
}

int pf_add_payload(PacketBuilder *b, const uint8_t *data, size_t len) {
    if (b->len + len > PF_MAX_PKT) return -1;
    b->payload_off = (int)b->len;
    memcpy(b->buf + b->payload_off, data, len);
    b->len += len;
    return 0;
}

/* ------------------------------------------------------------------ */

int pf_finalize(PacketBuilder *b) {
    if (b->ip_off < 0 || b->transport_off < 0) return 0;  /* nothing to do */

    size_t transport_len = b->len - (size_t)b->transport_off;

    /* Fix IP total length and recompute IP checksum */
    IPv4Header *ip = (IPv4Header *)(b->buf + b->ip_off);
    ip->tot_len  = htons((uint16_t)(IP_HDR_LEN + transport_len));
    ip->checksum = 0;
    ip->checksum = pf_checksum(ip, IP_HDR_LEN);

    uint32_t src = ip->src_ip;
    uint32_t dst = ip->dst_ip;

    switch (b->ip_proto) {
    case IPPROTO_TCP: {
        TCPHeader *tcp = (TCPHeader *)(b->buf + b->transport_off);
        pf_finalize_tcp(tcp, (uint16_t)transport_len, src, dst);
        break;
    }
    case IPPROTO_UDP: {
        UDPHeader *udp = (UDPHeader *)(b->buf + b->transport_off);
        size_t payload_len = (b->payload_off >= 0) ?
            b->len - (size_t)b->payload_off : 0;
        udp->length = htons((uint16_t)(UDP_HDR_LEN + payload_len));
        pf_finalize_udp(udp, (uint16_t)transport_len, src, dst);
        break;
    }
    case IPPROTO_ICMP: {
        ICMPHeader *icmp = (ICMPHeader *)(b->buf + b->transport_off);
        pf_finalize_icmp(icmp, (uint16_t)transport_len);
        break;
    }
    default:
        break;
    }

    return 0;
}

/* ------------------------------------------------------------------ */

ssize_t pf_send(PacketBuilder *b, const char *iface, int count) {
    if (pf_finalize(b) < 0) return -1;

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket(AF_PACKET)"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sock);
        return -1;
    }

    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    ssize_t sent = -1;
    for (int i = 0; i < count; i++) {
        sent = sendto(sock, b->buf, b->len, 0,
                      (struct sockaddr *)&sll, sizeof(sll));
        if (sent < 0) { perror("sendto"); break; }
    }

    close(sock);
    return sent;
}

const uint8_t *pf_bytes(const PacketBuilder *b, size_t *out_len) {
    if (out_len) *out_len = b->len;
    return b->buf;
}

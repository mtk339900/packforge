#include "dissect.h"
#include "../net/ethernet.h"
#include "../net/ip.h"
#include "../net/tcp.h"
#include "../net/udp.h"
#include "../net/icmp.h"
#include "../net/arp.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* ── ANSI colours ─────────────────────────────────────────────────── */
#define C_RST   "\033[0m"
#define C_BOLD  "\033[1m"
#define C_DIM   "\033[2m"
#define C_CYAN  "\033[96m"
#define C_GRN   "\033[92m"
#define C_YELL  "\033[93m"
#define C_RED   "\033[91m"
#define C_MAG   "\033[95m"
#define C_BLUE  "\033[94m"
#define C_WHT   "\033[97m"

static int g_pkt_count = 0;

/* ── Helpers ──────────────────────────────────────────────────────── */

static void print_mac(const uint8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void hex_dump(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if      (i % 16 == 0) printf("    %04zx  ", i);
        printf("%02x ", data[i]);
        if (i % 16 == 7)  printf(" ");
        if (i % 16 == 15 || i == len - 1) {
            /* pad */
            size_t col = i % 16;
            if (col < 15) {
                for (size_t p = col + 1; p < 16; p++) {
                    printf("   ");
                    if (p == 7) printf(" ");
                }
            }
            printf(" |");
            size_t start = i - col;
            for (size_t j = start; j <= i; j++)
                putchar((data[j] >= 0x20 && data[j] < 0x7f) ? data[j] : '.');
            printf("|\n");
        }
    }
}

/* ── Main entry ───────────────────────────────────────────────────── */

void pf_dissect_print(const uint8_t *pkt, size_t len, int verbose) {
    if (len < (size_t)ETH_HDR_LEN) return;

    g_pkt_count++;

    /* Timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *t = localtime(&ts.tv_sec);
    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", t);

    printf(C_DIM "#%05d" C_RST "  " C_DIM "%s.%06ld" C_RST "  ",
           g_pkt_count, tbuf, ts.tv_nsec / 1000);

    const EthHeader *eth = (const EthHeader *)pkt;
    uint16_t etype = ntohs(eth->ethertype);

    /* ── IPv4 ── */
    if (etype == ETH_P_IP && len >= (size_t)(ETH_HDR_LEN + IP_HDR_LEN)) {

        const IPv4Header *ip = (const IPv4Header *)(pkt + ETH_HDR_LEN);
        uint8_t  ihl         = (ip->ihl_ver & 0x0F) * 4;
        uint16_t tot         = ntohs(ip->tot_len);
        char     src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->src_ip, src, sizeof(src));
        inet_ntop(AF_INET, &ip->dst_ip, dst, sizeof(dst));

        const uint8_t *trans     = pkt + ETH_HDR_LEN + ihl;
        size_t         trans_len = len  - ETH_HDR_LEN - ihl;

        /* TCP */
        if (ip->proto == IPPROTO_TCP && trans_len >= TCP_HDR_LEN) {
            const TCPHeader *tcp = (const TCPHeader *)trans;
            char fbuf[64];
            pf_tcp_flags_str(tcp->flags, fbuf, sizeof(fbuf));
            size_t data_off = (tcp->data_off >> 4) * 4;
            size_t payload  = (trans_len > data_off) ? trans_len - data_off : 0;

            printf(C_CYAN C_BOLD "TCP  " C_RST
                   C_WHT "%s" C_RST ":%u  →  " C_WHT "%s" C_RST ":%u  "
                   "[" C_RED "%s" C_RST "]  "
                   "seq=%u  win=%u  payload=%zu B\n",
                   src, ntohs(tcp->sport),
                   dst, ntohs(tcp->dport),
                   fbuf,
                   ntohl(tcp->seq), ntohs(tcp->window),
                   payload);

            if (verbose >= 1)
                printf("         " C_DIM "ack=%u  urgptr=%u  tos=0x%02x  ttl=%u  ip_id=%u\n" C_RST,
                       ntohl(tcp->ack_seq), ntohs(tcp->urg_ptr),
                       ip->tos, ip->ttl, ntohs(ip->id));
        }
        /* UDP */
        else if (ip->proto == IPPROTO_UDP && trans_len >= UDP_HDR_LEN) {
            const UDPHeader *udp = (const UDPHeader *)trans;
            uint16_t payload = ntohs(udp->length) > UDP_HDR_LEN ?
                               ntohs(udp->length) - UDP_HDR_LEN : 0;

            printf(C_GRN C_BOLD "UDP  " C_RST
                   C_WHT "%s" C_RST ":%u  →  " C_WHT "%s" C_RST ":%u  "
                   "payload=%u B\n",
                   src, ntohs(udp->sport),
                   dst, ntohs(udp->dport),
                   payload);

            if (verbose >= 1)
                printf("         " C_DIM "ttl=%u  tot=%u\n" C_RST, ip->ttl, tot);
        }
        /* ICMP */
        else if (ip->proto == IPPROTO_ICMP && trans_len >= ICMP_HDR_LEN) {
            const ICMPHeader *icmp = (const ICMPHeader *)trans;
            printf(C_YELL C_BOLD "ICMP " C_RST
                   C_WHT "%s" C_RST "  →  " C_WHT "%s" C_RST "  "
                   "type=%u(%s)  code=%u  id=%u  seq=%u\n",
                   src, dst,
                   icmp->type, pf_icmp_type_str(icmp->type),
                   icmp->code, ntohs(icmp->id), ntohs(icmp->seq));
        }
        /* Other IP */
        else {
            printf(C_MAG "IP/%u " C_RST
                   C_WHT "%s" C_RST "  →  " C_WHT "%s" C_RST "  len=%u\n",
                   ip->proto, src, dst, tot);
        }

        if (verbose >= 1) {
            printf("         " C_DIM "eth  ");
            print_mac(eth->src);
            printf("  →  ");
            print_mac(eth->dst);
            printf(C_RST "\n");
        }

    }
    /* ── ARP ── */
    else if (etype == ETH_P_ARP && len >= (size_t)(ETH_HDR_LEN + ARP_HDR_LEN)) {
        const ARPHeader *arp = (const ARPHeader *)(pkt + ETH_HDR_LEN);
        char spa[INET_ADDRSTRLEN], tpa[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->spa, spa, sizeof(spa));
        inet_ntop(AF_INET, arp->tpa, tpa, sizeof(tpa));
        const char *op = (ntohs(arp->op) == ARP_REQUEST) ? "Request" : "Reply";

        printf(C_BLUE C_BOLD "ARP  " C_RST
               "%-7s  " C_WHT "%s" C_RST " [",
               op, spa);
        print_mac(arp->sha);
        printf("]  →  " C_WHT "%s" C_RST " [", tpa);
        print_mac(arp->tha);
        printf("]\n");
    }
    /* ── Other Ethernet ── */
    else {
        printf(C_DIM "ETH  ethertype=0x%04x  len=%zu\n" C_RST, etype, len);
    }

    /* ── Hex dump ── */
    if (verbose >= 2) {
        printf(C_DIM "  hex dump (%zu bytes):\n" C_RST, len);
        hex_dump(pkt, len);
    }

    fflush(stdout);
}

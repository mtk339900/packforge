/*
 * PacketForge — raw packet crafter & sniffer
 *
 * Usage:
 *   packforge sniff    [-i IFACE] [-c COUNT] [-w FILE.pcap] [-v] [-vv]
 *   packforge craft    [-i IFACE] --proto tcp|udp|icmp|arp
 *                      [--src-mac MAC] [--dst-mac MAC]
 *                      [--src-ip  IP]  [--dst-ip  IP]
 *                      [--sport N] [--dport N] [--flags SYN,ACK]
 *                      [--ttl N]  [--seq N]   [--payload "str"]
 *                      [-n COUNT]
 *   packforge arp-scan [-i IFACE] --range 192.168.1.0/24
 *   packforge ping     [-i IFACE] --dst IP [-c COUNT]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "forge/forge.h"
#include "sniff/sniffer.h"
#include "sniff/dissect.h"
#include "net/ethernet.h"
#include "net/ip.h"
#include "net/tcp.h"
#include "net/udp.h"
#include "net/icmp.h"
#include "net/arp.h"
#include "util/iface.h"
#include "util/pcap.h"

/* ───────────────────────────── helpers ─────────────────────────────── */

static void die(const char *msg) {
    fprintf(stderr, "[!] %s\n", msg);
    exit(EXIT_FAILURE);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "\n"
        "  PacketForge — raw packet crafter & sniffer\n"
        "  Requires root / CAP_NET_RAW\n\n"
        "  Usage:\n\n"
        "    %s sniff    [-i IFACE] [-c COUNT] [-w FILE.pcap] [-v|-vv]\n"
        "    %s craft    [-i IFACE] --proto tcp|udp|icmp|arp\n"
        "                 [--src-mac MAC]  [--dst-mac MAC]\n"
        "                 [--src-ip IP]    [--dst-ip IP]\n"
        "                 [--sport N]      [--dport N]\n"
        "                 [--flags SYN,ACK] [--ttl N]\n"
        "                 [--seq N]        [--payload TEXT]\n"
        "                 [-n COUNT]\n"
        "    %s arp-scan [-i IFACE] --range 192.168.1.0/24\n"
        "    %s ping     [-i IFACE] --dst IP [-c COUNT]\n\n",
        prog, prog, prog, prog);
    exit(EXIT_FAILURE);
}

/* ─────────────────────────── sniff mode ────────────────────────────── */

static int cmd_sniff(int argc, char **argv) {
    SnifferCfg cfg = {
        .iface   = NULL,
        .count   = 0,
        .verbose = 0,
        .pcap_out = NULL,
        .handler  = NULL,
        .userdata = NULL,
    };

    static struct option opts[] = {
        {"iface",   required_argument, 0, 'i'},
        {"count",   required_argument, 0, 'c'},
        {"write",   required_argument, 0, 'w'},
        {"verbose", no_argument,       0, 'v'},
        {0, 0, 0, 0},
    };

    int ch, idx = 0;
    optind = 1;
    while ((ch = getopt_long(argc, argv, "i:c:w:v", opts, &idx)) != -1) {
        switch (ch) {
        case 'i': cfg.iface   = optarg; break;
        case 'c': cfg.count   = atoi(optarg); break;
        case 'w': cfg.pcap_out = optarg; break;
        case 'v': cfg.verbose++; break;
        default:  usage(argv[0]);
        }
    }

    return pf_sniff(&cfg);
}

/* ─────────────────────────── craft mode ────────────────────────────── */

static int cmd_craft(int argc, char **argv) {
    const char *iface    = "eth0";
    const char *proto    = "tcp";
    const char *src_mac_s = NULL, *dst_mac_s = NULL;
    const char *src_ip_s  = NULL, *dst_ip_s  = NULL;
    int         sport    = 12345, dport = 80;
    const char *flags_s  = "SYN";
    int         ttl      = 64;
    uint32_t    seq      = 0, ack_seq = 0;
    int         window   = 65535;
    const char *payload  = NULL;
    int         count    = 1;
    uint8_t     icmp_type = ICMP_ECHO_REQUEST, icmp_code = 0;
    uint16_t    icmp_id = 1, icmp_seq = 1;

    static struct option opts[] = {
        {"iface",    required_argument, 0, 'i'},
        {"proto",    required_argument, 0, 'P'},
        {"src-mac",  required_argument, 0, 'S'},
        {"dst-mac",  required_argument, 0, 'D'},
        {"src-ip",   required_argument, 0, 's'},
        {"dst-ip",   required_argument, 0, 'd'},
        {"sport",    required_argument, 0, 1001},
        {"dport",    required_argument, 0, 1002},
        {"flags",    required_argument, 0, 1003},
        {"ttl",      required_argument, 0, 1004},
        {"seq",      required_argument, 0, 1005},
        {"ack-seq",  required_argument, 0, 1006},
        {"window",   required_argument, 0, 1007},
        {"payload",  required_argument, 0, 1008},
        {"icmp-type",required_argument, 0, 1009},
        {"icmp-code",required_argument, 0, 1010},
        {"count",    required_argument, 0, 'n'},
        {0, 0, 0, 0},
    };

    int ch, idx = 0;
    optind = 1;
    while ((ch = getopt_long(argc, argv, "i:P:S:D:s:d:n:", opts, &idx)) != -1) {
        switch (ch) {
        case 'i':    iface    = optarg; break;
        case 'P':    proto    = optarg; break;
        case 'S':    src_mac_s = optarg; break;
        case 'D':    dst_mac_s = optarg; break;
        case 's':    src_ip_s  = optarg; break;
        case 'd':    dst_ip_s  = optarg; break;
        case 1001:   sport    = atoi(optarg); break;
        case 1002:   dport    = atoi(optarg); break;
        case 1003:   flags_s  = optarg; break;
        case 1004:   ttl      = atoi(optarg); break;
        case 1005:   seq      = (uint32_t)atol(optarg); break;
        case 1006:   ack_seq  = (uint32_t)atol(optarg); break;
        case 1007:   window   = atoi(optarg); break;
        case 1008:   payload  = optarg; break;
        case 1009:   icmp_type = (uint8_t)atoi(optarg); break;
        case 1010:   icmp_code = (uint8_t)atoi(optarg); break;
        case 'n':    count    = atoi(optarg); break;
        default:     usage(argv[0]);
        }
    }

    /* --- Resolve interface MAC and IP --- */
    uint8_t  my_mac[6] = {0};
    uint32_t my_ip     = 0;
    if (pf_iface_info(iface, my_mac, &my_ip) < 0)
        die("Cannot get interface info. Check interface name.");

    uint8_t src_mac[6], dst_mac[6];
    if (src_mac_s) { if (pf_parse_mac(src_mac_s, src_mac) < 0) die("Bad src-mac"); }
    else            memcpy(src_mac, my_mac, 6);
    if (dst_mac_s) { if (pf_parse_mac(dst_mac_s, dst_mac) < 0) die("Bad dst-mac"); }
    else            memcpy(dst_mac, ETH_BROADCAST, 6);

    uint32_t src_ip = my_ip, dst_ip = 0;
    if (src_ip_s && pf_parse_ip(src_ip_s, &src_ip) < 0) die("Bad src-ip");
    if (dst_ip_s && pf_parse_ip(dst_ip_s, &dst_ip) < 0) die("Bad dst-ip");
    if (!dst_ip && strcmp(proto, "arp") != 0)             die("--dst-ip required");

    /* --- Build packet --- */
    PacketBuilder *b = pf_new();
    if (!b) die("Out of memory");

    uint16_t ethertype = (strcmp(proto, "arp") == 0) ? ETH_P_ARP : ETH_P_IP;
    pf_add_ethernet(b, src_mac, dst_mac, ethertype);

    if (strcmp(proto, "tcp") == 0) {
        uint8_t flags = pf_parse_tcp_flags(flags_s);
        pf_add_ip(b, src_ip, dst_ip, IPPROTO_TCP, (uint8_t)ttl);
        pf_add_tcp(b, (uint16_t)sport, (uint16_t)dport, seq, ack_seq, flags, (uint16_t)window);
    } else if (strcmp(proto, "udp") == 0) {
        pf_add_ip(b, src_ip, dst_ip, IPPROTO_UDP, (uint8_t)ttl);
        pf_add_udp(b, (uint16_t)sport, (uint16_t)dport);
    } else if (strcmp(proto, "icmp") == 0) {
        pf_add_ip(b, src_ip, dst_ip, IPPROTO_ICMP, (uint8_t)ttl);
        pf_add_icmp(b, icmp_type, icmp_code, icmp_id, icmp_seq);
    } else if (strcmp(proto, "arp") == 0) {
        if (!dst_ip_s) die("--dst-ip required for ARP");
        pf_add_arp(b, ARP_REQUEST, src_mac, src_ip, NULL, dst_ip);
    } else {
        die("Unknown protocol. Use: tcp, udp, icmp, arp");
    }

    if (payload)
        pf_add_payload(b, (const uint8_t *)payload, strlen(payload));

    /* --- Print what we're about to send --- */
    size_t pkt_len;
    pf_finalize(b);
    pf_bytes(b, &pkt_len);

    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    if (src_ip) inet_ntop(AF_INET, &src_ip, src_str, sizeof(src_str));
    if (dst_ip) inet_ntop(AF_INET, &dst_ip, dst_str, sizeof(dst_str));

    printf("[*] Crafting %s packet  %s:%d → %s:%d  len=%zu B  x%d\n",
           proto,
           src_ip ? src_str : "?", sport,
           dst_ip ? dst_str : "?", dport,
           pkt_len, count);

    ssize_t n = pf_send(b, iface, count);
    if (n < 0) { pf_free(b); return 1; }
    printf("[+] Sent %zd bytes\n", n);

    pf_free(b);
    return 0;
}

/* ─────────────────────────── arp-scan mode ──────────────────────────── */

/* Shared state for the ARP reply listener thread */
typedef struct {
    int      sock;
    int      stop;
    uint32_t network;   /* network address (host byte order) */
    uint32_t mask;      /* subnet mask     (host byte order) */
} ARPScanState;

static void *arp_listener(void *arg) {
    ARPScanState *st = (ARPScanState *)arg;
    uint8_t buf[2048];

    while (!st->stop) {
        ssize_t n = recv(st->sock, buf, sizeof(buf), 0);
        if (n < (ssize_t)(ETH_HDR_LEN + ARP_HDR_LEN)) continue;

        const EthHeader  *eth = (EthHeader *)buf;
        if (ntohs(eth->ethertype) != ETH_P_ARP) continue;
        const ARPHeader  *arp = (ARPHeader *)(buf + ETH_HDR_LEN);
        if (ntohs(arp->op) != ARP_REPLY) continue;

        uint32_t sender_ip;
        memcpy(&sender_ip, arp->spa, 4);
        uint32_t h = ntohl(sender_ip);
        if ((h & st->mask) != st->network) continue;

        char ip_s[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->spa, ip_s, sizeof(ip_s));
        printf("[+]  %-18s  %02x:%02x:%02x:%02x:%02x:%02x\n",
               ip_s,
               arp->sha[0], arp->sha[1], arp->sha[2],
               arp->sha[3], arp->sha[4], arp->sha[5]);
        fflush(stdout);
    }
    return NULL;
}

static int cmd_arp_scan(int argc, char **argv) {
    const char *iface  = "eth0";
    const char *range  = NULL;

    static struct option opts[] = {
        {"iface", required_argument, 0, 'i'},
        {"range", required_argument, 0, 'r'},
        {0, 0, 0, 0},
    };

    int ch, idx = 0;
    optind = 1;
    while ((ch = getopt_long(argc, argv, "i:r:", opts, &idx)) != -1) {
        switch (ch) {
        case 'i': iface = optarg; break;
        case 'r': range = optarg; break;
        default:  usage(argv[0]);
        }
    }
    if (!range) die("--range required (e.g. 192.168.1.0/24)");

    /* Parse CIDR */
    char range_buf[64];
    strncpy(range_buf, range, sizeof(range_buf) - 1);
    char *slash = strchr(range_buf, '/');
    if (!slash) die("Bad range: expected x.x.x.x/prefix");
    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 1 || prefix > 30) die("Prefix must be 1-30");

    struct in_addr base_addr;
    if (inet_pton(AF_INET, range_buf, &base_addr) != 1) die("Bad base IP");
    uint32_t mask    = prefix ? (~0u << (32 - prefix)) : 0;
    uint32_t network = ntohl(base_addr.s_addr) & mask;
    uint32_t total   = ~mask - 1;          /* usable hosts */

    /* Interface info */
    uint8_t  my_mac[6];
    uint32_t my_ip;
    if (pf_iface_info(iface, my_mac, &my_ip) < 0)
        die("Cannot get interface info");

    /* Raw socket */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("ioctl"); return 1; }

    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    bind(sock, (struct sockaddr *)&sll, sizeof(sll));

    /* Start listener thread */
    ARPScanState st = { .sock = sock, .stop = 0,
                        .network = network, .mask = mask };
    pthread_t tid;
    pthread_create(&tid, NULL, arp_listener, &st);

    printf("[*] ARP scanning %s (%u hosts) on %s\n", range, total, iface);
    printf("    %-18s  %s\n", "IP", "MAC");
    printf("    %s\n", "-----------------------------------------------");

    /* Send ARP requests */
    PacketBuilder *b = pf_new();
    for (uint32_t i = 1; i <= total; i++) {
        uint32_t tgt = htonl(network + i);

        pf_reset(b);
        pf_add_ethernet(b, my_mac, ETH_BROADCAST, ETH_P_ARP);
        pf_add_arp(b, ARP_REQUEST, my_mac, my_ip, NULL, tgt);

        sendto(sock, b->buf, b->len, 0,
               (struct sockaddr *)&sll, sizeof(sll));

        usleep(2000);   /* 2 ms between probes */
    }
    pf_free(b);

    /* Wait a bit for stragglers */
    usleep(300000);
    st.stop = 1;
    pthread_cancel(tid);
    pthread_join(tid, NULL);
    close(sock);

    printf("[*] Scan complete.\n");
    return 0;
}

/* ─────────────────────────── ping mode ─────────────────────────────── */

static volatile int ping_stop = 0;
static void ping_sig(int s) { (void)s; ping_stop = 1; }

static int cmd_ping(int argc, char **argv) {
    const char *iface  = "eth0";
    const char *dst_s  = NULL;
    int         count  = 4;

    static struct option opts[] = {
        {"iface", required_argument, 0, 'i'},
        {"dst",   required_argument, 0, 'd'},
        {"count", required_argument, 0, 'c'},
        {0, 0, 0, 0},
    };

    int ch, idx = 0;
    optind = 1;
    while ((ch = getopt_long(argc, argv, "i:d:c:", opts, &idx)) != -1) {
        switch (ch) {
        case 'i': iface = optarg; break;
        case 'd': dst_s = optarg; break;
        case 'c': count = atoi(optarg); break;
        default:  usage(argv[0]);
        }
    }
    if (!dst_s) die("--dst IP required");

    uint8_t  my_mac[6];
    uint32_t my_ip;
    if (pf_iface_info(iface, my_mac, &my_ip) < 0)
        die("Cannot get interface info");

    uint32_t dst_ip;
    if (pf_parse_ip(dst_s, &dst_ip) < 0) die("Bad destination IP");

    /* Raw L2 socket to send */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("ioctl"); return 1; }

    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    bind(sock, (struct sockaddr *)&sll, sizeof(sll));

    signal(SIGINT, ping_sig);
    srand((unsigned)time(NULL));

    char dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst_ip, dst_str, sizeof(dst_str));
    printf("[*] PING %s from %s via %s\n", dst_str, iface, iface);

    PacketBuilder *b = pf_new();
    uint16_t pid = (uint16_t)(getpid() & 0xFFFF);

    for (int i = 1; i <= count && !ping_stop; i++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        pf_reset(b);
        pf_add_ethernet(b, my_mac, ETH_BROADCAST, ETH_P_IP);
        pf_add_ip(b, my_ip, dst_ip, IPPROTO_ICMP, 64);
        pf_add_icmp(b, ICMP_ECHO_REQUEST, 0, pid, (uint16_t)i);

        if (sendto(sock, b->buf, b->len, 0,
                   (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("sendto"); break;
        }

        /* Listen for the echo reply (with 1-second timeout) */
        uint8_t rbuf[2048];
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int got_reply = 0;
        while (!got_reply) {
            ssize_t n = recv(sock, rbuf, sizeof(rbuf), 0);
            if (n < (ssize_t)(ETH_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN)) break;

            uint16_t etype = ntohs(((EthHeader *)rbuf)->ethertype);
            if (etype != ETH_P_IP) continue;

            const IPv4Header *ip = (IPv4Header *)(rbuf + ETH_HDR_LEN);
            if (ip->proto != IPPROTO_ICMP) continue;
            if (ip->src_ip != dst_ip) continue;

            uint8_t ihl = (ip->ihl_ver & 0x0F) * 4;
            const ICMPHeader *icmp =
                (ICMPHeader *)(rbuf + ETH_HDR_LEN + ihl);
            if (icmp->type != ICMP_ECHO_REPLY) continue;
            if (ntohs(icmp->id) != pid) continue;

            clock_gettime(CLOCK_MONOTONIC, &t1);
            double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                        (t1.tv_nsec - t0.tv_nsec) / 1e6;

            printf("[+] Reply from %s: seq=%d  time=%.2f ms\n",
                   dst_str, i, ms);
            got_reply = 1;
        }
        if (!got_reply)
            printf("[!] No reply from %s: seq=%d  (timeout)\n", dst_str, i);

        if (i < count && !ping_stop) sleep(1);
    }

    pf_free(b);
    close(sock);
    return 0;
}

/* ───────────────────────────── main ────────────────────────────────── */

int main(int argc, char **argv) {
    srand((unsigned)time(NULL));

    if (argc < 2) usage(argv[0]);

    const char *cmd = argv[1];

    /* Shift argv so subcommand parsers see their own args */
    int  sub_argc = argc - 1;
    char **sub_argv = argv + 1;

    if      (strcmp(cmd, "sniff")    == 0) return cmd_sniff(sub_argc, sub_argv);
    else if (strcmp(cmd, "craft")    == 0) return cmd_craft(sub_argc, sub_argv);
    else if (strcmp(cmd, "arp-scan") == 0) return cmd_arp_scan(sub_argc, sub_argv);
    else if (strcmp(cmd, "ping")     == 0) return cmd_ping(sub_argc, sub_argv);
    else {
        fprintf(stderr, "[!] Unknown command: %s\n", cmd);
        usage(argv[0]);
    }

    return 0;
}

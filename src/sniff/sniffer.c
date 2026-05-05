#include "sniffer.h"
#include "dissect.h"
#include "../util/pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

static volatile int g_stop = 0;

static void handle_sig(int sig) {
    (void)sig;
    g_stop = 1;
}

int pf_sniff(const SnifferCfg *cfg) {
    signal(SIGINT,  handle_sig);
    signal(SIGTERM, handle_sig);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket(AF_PACKET)"); return -1; }

    /* Bind to a specific interface if requested */
    if (cfg->iface) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, cfg->iface, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            perror("ioctl SIOCGIFINDEX");
            close(sock);
            return -1;
        }
        struct sockaddr_ll sll = {0};
        sll.sll_family   = AF_PACKET;
        sll.sll_ifindex  = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("bind"); close(sock); return -1;
        }
    }

    /* Put socket in promiscuous mode when bound to an interface */
    if (cfg->iface) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, cfg->iface, IFNAMSIZ - 1);
        ioctl(sock, SIOCGIFFLAGS, &ifr);
        ifr.ifr_flags |= IFF_PROMISC;
        ioctl(sock, SIOCSIFFLAGS, &ifr);
    }

    PcapWriter *pw = NULL;
    if (cfg->pcap_out) {
        pw = pcap_writer_open(cfg->pcap_out);
        if (pw)
            fprintf(stderr, "[*] Writing packets to %s\n", cfg->pcap_out);
        else
            fprintf(stderr, "[!] Could not open %s for writing\n", cfg->pcap_out);
    }

    fprintf(stderr, "[*] Listening on %s ... (Ctrl+C to stop)\n",
            cfg->iface ? cfg->iface : "all interfaces");

    uint8_t buf[65535];
    int captured = 0;
    int limit    = cfg->count;

    while (!g_stop && (limit == 0 || captured < limit)) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (g_stop) break;
            perror("recv");
            break;
        }

        if (pw)
            pcap_writer_write(pw, buf, (uint32_t)n);

        if (cfg->handler)
            cfg->handler(buf, (size_t)n, cfg->userdata);
        else
            pf_dissect_print(buf, (size_t)n, cfg->verbose);

        captured++;
    }

    if (pw) pcap_writer_close(pw);
    close(sock);
    fprintf(stderr, "\n[*] %d packet(s) captured.\n", captured);
    return captured;
}

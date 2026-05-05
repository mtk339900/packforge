#include "iface.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* On Linux, SIOCGIFHWADDR lives in net/if.h via sys/ioctl.h */
#include <linux/if.h>
#include <linux/sockios.h>

int pf_iface_info(const char *iface, uint8_t *mac_out, uint32_t *ip_out) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (mac_out) {
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            perror("ioctl SIOCGIFHWADDR"); close(sock); return -1;
        }
        memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    }

    if (ip_out) {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
            perror("ioctl SIOCGIFADDR"); close(sock); return -1;
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
        *ip_out = sin->sin_addr.s_addr;   /* network byte order */
    }

    close(sock);
    return 0;
}

int pf_iface_index(const char *iface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    int ret = ioctl(sock, SIOCGIFINDEX, &ifr);
    close(sock);
    return (ret < 0) ? -1 : ifr.ifr_ifindex;
}

int pf_parse_mac(const char *str, uint8_t *mac_out) {
    unsigned int b[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac_out[i] = (uint8_t)b[i];
    return 0;
}

int pf_parse_ip(const char *str, uint32_t *ip_out) {
    struct in_addr a;
    if (inet_pton(AF_INET, str, &a) != 1) return -1;
    *ip_out = a.s_addr;   /* network byte order */
    return 0;
}

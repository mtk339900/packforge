#include "checksum.h"
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

uint16_t pf_checksum(const void *data, size_t len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        uint16_t last = 0;
        *(uint8_t *)&last = *(const uint8_t *)ptr;
        sum += last;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

/* IPv4 pseudo-header for TCP/UDP checksum */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t seg_len;
} __attribute__((packed)) PseudoHdr;

static uint16_t transport_checksum(uint8_t proto, uint32_t src_ip, uint32_t dst_ip,
                                    const void *seg, uint16_t seg_len) {
    PseudoHdr ph = {
        .src_ip  = src_ip,
        .dst_ip  = dst_ip,
        .zero    = 0,
        .proto   = proto,
        .seg_len = htons(seg_len),
    };

    size_t total = sizeof(ph) + seg_len;
    /* Pad to even length for checksum */
    uint8_t *buf = calloc(1, total + 1);
    if (!buf) return 0;
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), seg, seg_len);

    uint16_t csum = pf_checksum(buf, total);
    free(buf);
    return csum;
}

uint16_t pf_tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                          const void *tcp_seg, uint16_t tcp_len) {
    return transport_checksum(IPPROTO_TCP, src_ip, dst_ip, tcp_seg, tcp_len);
}

uint16_t pf_udp_checksum(uint32_t src_ip, uint32_t dst_ip,
                          const void *udp_seg, uint16_t udp_len) {
    return transport_checksum(IPPROTO_UDP, src_ip, dst_ip, udp_seg, udp_len);
}

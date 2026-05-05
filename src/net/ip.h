#ifndef PF_IP_H
#define PF_IP_H

#include <stdint.h>

typedef struct {
    uint8_t  ihl_ver;    /* version[7:4] | IHL[3:0] */
    uint8_t  tos;
    uint16_t tot_len;    /* total length including IP header */
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed)) IPv4Header;

#define IP_HDR_LEN 20

/*
 * Fill and checksum an IP header.
 * payload_len = size of everything after the IP header.
 * ttl = 0 means use default (64).
 */
void pf_build_ip(IPv4Header *hdr, uint8_t proto,
                 uint32_t src, uint32_t dst,
                 uint16_t payload_len, uint8_t ttl);

/* Re-compute IP checksum after manually editing a field */
void pf_recompute_ip_checksum(IPv4Header *hdr);

#endif

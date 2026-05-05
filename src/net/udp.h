#ifndef PF_UDP_H
#define PF_UDP_H

#include <stdint.h>

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint16_t length;    /* UDP header + payload */
    uint16_t checksum;
} __attribute__((packed)) UDPHeader;

#define UDP_HDR_LEN 8

void pf_build_udp(UDPHeader *hdr, uint16_t sport, uint16_t dport, uint16_t payload_len);
void pf_finalize_udp(UDPHeader *hdr, uint16_t udp_seg_len, uint32_t src_ip, uint32_t dst_ip);

#endif

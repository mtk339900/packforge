#ifndef PF_ICMP_H
#define PF_ICMP_H

#include <stdint.h>

#define ICMP_ECHO_REPLY    0
#define ICMP_ECHO_REQUEST  8
#define ICMP_DEST_UNREACH  3
#define ICMP_TIME_EXCEEDED 11

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} __attribute__((packed)) ICMPHeader;

#define ICMP_HDR_LEN 8

void pf_build_icmp(ICMPHeader *hdr, uint8_t type, uint8_t code,
                   uint16_t id, uint16_t seq);

/* Compute and set checksum; icmp_len = ICMP header + any payload */
void pf_finalize_icmp(ICMPHeader *hdr, uint16_t icmp_len);

const char *pf_icmp_type_str(uint8_t type);

#endif

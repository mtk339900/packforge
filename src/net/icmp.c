#include "icmp.h"
#include "checksum.h"
#include <string.h>
#include <netinet/in.h>

void pf_build_icmp(ICMPHeader *hdr, uint8_t type, uint8_t code,
                   uint16_t id, uint16_t seq) {
    hdr->type     = type;
    hdr->code     = code;
    hdr->checksum = 0;
    hdr->id       = htons(id);
    hdr->seq      = htons(seq);
}

void pf_finalize_icmp(ICMPHeader *hdr, uint16_t icmp_len) {
    hdr->checksum = 0;
    hdr->checksum = pf_checksum(hdr, icmp_len);
}

const char *pf_icmp_type_str(uint8_t type) {
    switch (type) {
        case 0:  return "Echo Reply";
        case 3:  return "Dest Unreachable";
        case 8:  return "Echo Request";
        case 11: return "Time Exceeded";
        case 12: return "Parameter Problem";
        default: return "Unknown";
    }
}

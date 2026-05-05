#include "udp.h"
#include "checksum.h"
#include <string.h>
#include <netinet/in.h>

void pf_build_udp(UDPHeader *hdr, uint16_t sport, uint16_t dport, uint16_t payload_len) {
    hdr->sport    = htons(sport);
    hdr->dport    = htons(dport);
    hdr->length   = htons((uint16_t)(UDP_HDR_LEN + payload_len));
    hdr->checksum = 0;
}

void pf_finalize_udp(UDPHeader *hdr, uint16_t udp_seg_len, uint32_t src_ip, uint32_t dst_ip) {
    hdr->checksum = 0;
    hdr->checksum = pf_udp_checksum(src_ip, dst_ip, hdr, udp_seg_len);
}

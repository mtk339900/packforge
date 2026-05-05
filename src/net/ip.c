#include "ip.h"
#include "checksum.h"
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

void pf_build_ip(IPv4Header *hdr, uint8_t proto,
                 uint32_t src, uint32_t dst,
                 uint16_t payload_len, uint8_t ttl) {
    memset(hdr, 0, IP_HDR_LEN);
    hdr->ihl_ver  = (4 << 4) | 5;       /* IPv4, IHL = 5 dwords = 20 bytes */
    hdr->tos      = 0;
    hdr->tot_len  = htons((uint16_t)(IP_HDR_LEN + payload_len));
    hdr->id       = htons((uint16_t)(rand() & 0xFFFF));
    hdr->frag_off = 0;
    hdr->ttl      = ttl ? ttl : 64;
    hdr->proto    = proto;
    hdr->checksum = 0;
    hdr->src_ip   = src;
    hdr->dst_ip   = dst;
    hdr->checksum = pf_checksum(hdr, IP_HDR_LEN);
}

void pf_recompute_ip_checksum(IPv4Header *hdr) {
    hdr->checksum = 0;
    hdr->checksum = pf_checksum(hdr, IP_HDR_LEN);
}

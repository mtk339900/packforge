#include "arp.h"
#include <string.h>
#include <netinet/in.h>

void pf_build_arp(ARPHeader *hdr, uint16_t op,
                  const uint8_t *sha, uint32_t spa,
                  const uint8_t *tha, uint32_t tpa) {
    hdr->htype = htons(ARPHRD_ETHER);
    hdr->ptype = htons(0x0800);
    hdr->hlen  = 6;
    hdr->plen  = 4;
    hdr->op    = htons(op);
    memcpy(hdr->sha, sha, 6);
    memcpy(hdr->spa, &spa, 4);
    if (tha)
        memcpy(hdr->tha, tha, 6);
    else
        memset(hdr->tha, 0x00, 6);
    memcpy(hdr->tpa, &tpa, 4);
}

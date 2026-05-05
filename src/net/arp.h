#ifndef PF_ARP_H
#define PF_ARP_H

#include <stdint.h>

#define ARP_REQUEST  1
#define ARP_REPLY    2
#define ARPHRD_ETHER 1

typedef struct {
    uint16_t htype;      /* hardware type: 1 = Ethernet */
    uint16_t ptype;      /* protocol type: 0x0800 = IPv4 */
    uint8_t  hlen;       /* hardware address length: 6 */
    uint8_t  plen;       /* protocol address length: 4 */
    uint16_t op;         /* 1 = request, 2 = reply */
    uint8_t  sha[6];     /* sender hardware address */
    uint8_t  spa[4];     /* sender protocol (IP) address */
    uint8_t  tha[6];     /* target hardware address */
    uint8_t  tpa[4];     /* target protocol (IP) address */
} __attribute__((packed)) ARPHeader;

#define ARP_HDR_LEN ((int)sizeof(ARPHeader))   /* 28 */

/*
 * Build an ARP request or reply.
 * tha = NULL → zeroed (appropriate for requests).
 * spa / tpa are in network byte order (as from inet_aton / inet_pton).
 */
void pf_build_arp(ARPHeader *hdr, uint16_t op,
                  const uint8_t *sha, uint32_t spa,
                  const uint8_t *tha, uint32_t tpa);

#endif

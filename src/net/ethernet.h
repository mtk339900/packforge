#ifndef PF_ETHERNET_H
#define PF_ETHERNET_H

#include <stdint.h>

#define ETH_ALEN    6
#define ETH_P_IP    0x0800
#define ETH_P_ARP   0x0806
#define ETH_P_IPV6  0x86DD

typedef struct {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t ethertype;        /* network byte order */
} __attribute__((packed)) EthHeader;

#define ETH_HDR_LEN ((int)sizeof(EthHeader))   /* 14 */

static const uint8_t ETH_BROADCAST[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};

#endif

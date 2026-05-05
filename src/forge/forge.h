#ifndef PF_FORGE_H
#define PF_FORGE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define PF_MAX_PKT 65535

typedef struct {
    uint8_t  buf[PF_MAX_PKT];
    size_t   len;

    int      eth_off;        /* byte offset of Ethernet header, or -1 */
    int      ip_off;         /* byte offset of IP header, or -1 */
    int      transport_off;  /* byte offset of TCP/UDP/ICMP/ARP, or -1 */
    int      payload_off;    /* byte offset of payload, or -1 */

    uint8_t  ip_proto;       /* IPPROTO_TCP / UDP / ICMP */
    uint32_t src_ip;         /* network byte order */
    uint32_t dst_ip;         /* network byte order */
} PacketBuilder;

/* Lifecycle */
PacketBuilder *pf_new(void);
void           pf_free(PacketBuilder *b);
void           pf_reset(PacketBuilder *b);

/* Layer builders — call in order: ethernet → ip → transport → payload */
int pf_add_ethernet(PacketBuilder *b,
                    const uint8_t *src_mac, const uint8_t *dst_mac,
                    uint16_t ethertype);

int pf_add_ip(PacketBuilder *b, uint32_t src, uint32_t dst,
              uint8_t proto, uint8_t ttl);

int pf_add_tcp(PacketBuilder *b, uint16_t sport, uint16_t dport,
               uint32_t seq, uint32_t ack_seq, uint8_t flags, uint16_t window);

int pf_add_udp(PacketBuilder *b, uint16_t sport, uint16_t dport);

int pf_add_icmp(PacketBuilder *b, uint8_t type, uint8_t code,
                uint16_t id, uint16_t seq);

int pf_add_arp(PacketBuilder *b, uint16_t op,
               const uint8_t *sha, uint32_t spa,
               const uint8_t *tha, uint32_t tpa);

int pf_add_payload(PacketBuilder *b, const uint8_t *data, size_t len);

/*
 * Finalize: fix IP total-length, recompute all checksums.
 * Called automatically by pf_send(); call manually if you need the bytes.
 */
int pf_finalize(PacketBuilder *b);

/*
 * Send the packet on `iface`, `count` times (1 = single shot).
 * Requires CAP_NET_RAW.
 */
ssize_t pf_send(PacketBuilder *b, const char *iface, int count);

/* Return pointer to raw bytes and fill *out_len. */
const uint8_t *pf_bytes(const PacketBuilder *b, size_t *out_len);

#endif

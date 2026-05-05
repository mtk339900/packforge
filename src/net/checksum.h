#ifndef PF_CHECKSUM_H
#define PF_CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

/* Standard one's-complement Internet checksum (RFC 1071) */
uint16_t pf_checksum(const void *data, size_t len);

/* TCP checksum (includes pseudo-header) */
uint16_t pf_tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                          const void *tcp_seg, uint16_t tcp_len);

/* UDP checksum (includes pseudo-header) */
uint16_t pf_udp_checksum(uint32_t src_ip, uint32_t dst_ip,
                          const void *udp_seg, uint16_t udp_len);

#endif

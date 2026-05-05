#ifndef PF_TCP_H
#define PF_TCP_H

#include <stdint.h>
#include <stddef.h>

/* Flag bits */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  data_off;   /* data offset (4 bits, upper) | reserved */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} __attribute__((packed)) TCPHeader;

#define TCP_HDR_LEN 20

/* Build a TCP header (checksum left at 0; call pf_finalize_tcp after) */
void pf_build_tcp(TCPHeader *hdr, uint16_t sport, uint16_t dport,
                  uint32_t seq, uint32_t ack_seq,
                  uint8_t flags, uint16_t window);

/* Compute and set TCP checksum; tcp_seg_len = TCP header + payload */
void pf_finalize_tcp(TCPHeader *hdr, uint16_t tcp_seg_len,
                     uint32_t src_ip, uint32_t dst_ip);

/* Parse a flag string like "SYN", "SYN,ACK", "FIN,ACK" */
uint8_t pf_parse_tcp_flags(const char *str);

/* Render flags to a string; buf must be >= 32 bytes */
const char *pf_tcp_flags_str(uint8_t flags, char *buf, size_t len);

#endif

#include "tcp.h"
#include "checksum.h"
#include <string.h>
#include <netinet/in.h>

void pf_build_tcp(TCPHeader *hdr, uint16_t sport, uint16_t dport,
                  uint32_t seq, uint32_t ack_seq,
                  uint8_t flags, uint16_t window) {
    memset(hdr, 0, TCP_HDR_LEN);
    hdr->sport    = htons(sport);
    hdr->dport    = htons(dport);
    hdr->seq      = htonl(seq);
    hdr->ack_seq  = htonl(ack_seq);
    hdr->data_off = (5 << 4);             /* 5 dwords = 20 bytes, no options */
    hdr->flags    = flags;
    hdr->window   = htons(window ? window : 65535);
    hdr->checksum = 0;
    hdr->urg_ptr  = 0;
}

void pf_finalize_tcp(TCPHeader *hdr, uint16_t tcp_seg_len,
                     uint32_t src_ip, uint32_t dst_ip) {
    hdr->checksum = 0;
    hdr->checksum = pf_tcp_checksum(src_ip, dst_ip, hdr, tcp_seg_len);
}

uint8_t pf_parse_tcp_flags(const char *str) {
    uint8_t f = 0;
    if (strstr(str, "SYN")) f |= TCP_SYN;
    if (strstr(str, "ACK")) f |= TCP_ACK;
    if (strstr(str, "FIN")) f |= TCP_FIN;
    if (strstr(str, "RST")) f |= TCP_RST;
    if (strstr(str, "PSH")) f |= TCP_PSH;
    if (strstr(str, "URG")) f |= TCP_URG;
    if (strstr(str, "ECE")) f |= TCP_ECE;
    if (strstr(str, "CWR")) f |= TCP_CWR;
    return f;
}

const char *pf_tcp_flags_str(uint8_t flags, char *buf, size_t len) {
    buf[0] = '\0';
#define APPEND(s) do { \
    if (strlen(buf) + strlen(s) + 2 < len) { \
        if (buf[0]) strncat(buf, "|", len - strlen(buf) - 1); \
        strncat(buf, s, len - strlen(buf) - 1); \
    } \
} while(0)
    if (flags & TCP_SYN) APPEND("SYN");
    if (flags & TCP_ACK) APPEND("ACK");
    if (flags & TCP_FIN) APPEND("FIN");
    if (flags & TCP_RST) APPEND("RST");
    if (flags & TCP_PSH) APPEND("PSH");
    if (flags & TCP_URG) APPEND("URG");
    if (flags & TCP_ECE) APPEND("ECE");
    if (flags & TCP_CWR) APPEND("CWR");
    if (!buf[0]) strncpy(buf, "NONE", len - 1);
#undef APPEND
    return buf;
}

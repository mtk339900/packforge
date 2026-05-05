#ifndef PF_PCAP_H
#define PF_PCAP_H

#include <stdint.h>
#include <stdio.h>

typedef struct {
    FILE    *fp;
    uint64_t written;
} PcapWriter;

/* Open a new pcap file (DLT_EN10MB).  Returns NULL on error. */
PcapWriter *pcap_writer_open(const char *path);

/* Append one captured packet. ts_usec = microseconds since epoch. */
int pcap_writer_write(PcapWriter *pw, const uint8_t *pkt, uint32_t caplen);

void pcap_writer_close(PcapWriter *pw);

#endif

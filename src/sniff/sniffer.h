#ifndef PF_SNIFFER_H
#define PF_SNIFFER_H

#include <stdint.h>
#include <stddef.h>

/* Callback invoked for every captured packet */
typedef void (*PacketHandler)(const uint8_t *pkt, size_t len, void *userdata);

typedef struct {
    const char    *iface;      /* NULL = all interfaces */
    int            count;      /* 0 = unlimited */
    int            verbose;    /* 0=normal, 1=+eth, 2=+hex dump */
    const char    *pcap_out;   /* NULL = don't write pcap */
    PacketHandler  handler;    /* NULL = use built-in dissect printer */
    void          *userdata;
} SnifferCfg;

/*
 * Block and capture packets according to cfg.
 * Returns number captured, or -1 on fatal error.
 * Stops on SIGINT / SIGTERM or when count is reached.
 */
int pf_sniff(const SnifferCfg *cfg);

#endif

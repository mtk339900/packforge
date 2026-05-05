#ifndef PF_DISSECT_H
#define PF_DISSECT_H

#include <stdint.h>
#include <stddef.h>

/*
 * Parse and pretty-print a raw Ethernet frame.
 *
 * verbose levels:
 *   0 = one-line summary
 *   1 = + Ethernet addresses and IP fields
 *   2 = + full hex dump
 */
void pf_dissect_print(const uint8_t *pkt, size_t len, int verbose);

#endif

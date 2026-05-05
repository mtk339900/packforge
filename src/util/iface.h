#ifndef PF_IFACE_H
#define PF_IFACE_H

#include <stdint.h>

/*
 * Query kernel for the MAC address and IPv4 address of an interface.
 * mac_out: 6-byte buffer (may be NULL to skip)
 * ip_out:  pointer to uint32_t in network byte order (may be NULL to skip)
 * Returns 0 on success, -1 on error.
 */
int pf_iface_info(const char *iface, uint8_t *mac_out, uint32_t *ip_out);

/*
 * Return the ifindex for an interface name.
 * Returns -1 on error.
 */
int pf_iface_index(const char *iface);

/* Parse "aa:bb:cc:dd:ee:ff" into a 6-byte array. Returns 0 on success. */
int pf_parse_mac(const char *str, uint8_t *mac_out);

/* Parse "192.168.1.1" into network-byte-order uint32_t. Returns 0 on success. */
int pf_parse_ip(const char *str, uint32_t *ip_out);

#endif

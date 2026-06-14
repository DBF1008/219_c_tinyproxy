/* tinyproxy - SOCKS5 protocol helpers
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _TINYPROXY_SOCKS5_H_
#define _TINYPROXY_SOCKS5_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Build a SOCKS5 CONNECT request buffer.
 * Detects whether host is an IPv4 address, IPv6 address, or domain name
 * and sets the ATYP field accordingly per RFC 1928.
 *
 * Returns the total number of bytes written to buff, or -1 on error.
 */
int socks5_build_connect_request(unsigned char *buff, size_t bufsize,
                                  const char *host, uint16_t port);

#endif

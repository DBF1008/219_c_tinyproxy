/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 2024 tinyproxy authors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Helpers for talking to a SOCKS5 upstream proxy (RFC 1928). */

#ifndef TINYPROXY_SOCKS5_H
#define TINYPROXY_SOCKS5_H

#include <stddef.h>

/*
 * Largest possible serialized SOCKS5 CONNECT request:
 *      4 bytes header (VER, CMD, RSV, ATYP)
 *    + 1 byte  domain-name length
 *    + 255 bytes domain name
 *    + 2 bytes port
 */
#define SOCKS5_CONNECT_REQUEST_MAX 262

/*
 * Serialize a SOCKS5 CONNECT request (RFC 1928) for the destination
 * host:port into buff, choosing the address type automatically:
 *
 *      - an IPv4 address literal -> ATYP=1 (4-byte address)
 *      - an IPv6 address literal -> ATYP=4 (16-byte address)
 *      - anything else           -> ATYP=3 (domain name, up to 255 bytes)
 *
 * port is given in host byte order.  bufflen is the size of buff and must
 * be at least SOCKS5_CONNECT_REQUEST_MAX.
 *
 * Returns the number of bytes written to buff on success, or -1 if the
 * host name is longer than 255 bytes or buff is too small.
 */
int build_socks5_connect_request (unsigned char *buff, size_t bufflen,
                                  const char *host, unsigned short port);

#endif /* TINYPROXY_SOCKS5_H */

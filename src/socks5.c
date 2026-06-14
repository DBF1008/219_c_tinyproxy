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

/* Build the request packets that tinyproxy sends to a SOCKS5 upstream
 * proxy.  Apart from the optional config.h (pulled in only when built
 * in-tree, for the feature-test macros that expose inet_pton()/htons()
 * under -ansi) this has no tinyproxy-internal dependencies, so the
 * encoding can be unit-tested in isolation.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "socks5.h"

#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int build_socks5_connect_request (unsigned char *buff, size_t bufflen,
                                  const char *host, unsigned short port)
{
        size_t addrlen;
        unsigned short netport;

        /*
         * Require room for the largest possible request up front so the
         * inet_pton()/memcpy() calls below can never write past the buffer.
         */
        if (bufflen < SOCKS5_CONNECT_REQUEST_MAX)
                return -1;

        buff[0] = 5;            /* SOCKS version */
        buff[1] = 1;            /* CONNECT command */
        buff[2] = 0;            /* reserved */

        if (inet_pton (AF_INET, host, &buff[4]) > 0) {
                /* host is an IPv4 address literal */
                buff[3] = 1;    /* ATYP = IPv4 */
                addrlen = 4;
        } else if (inet_pton (AF_INET6, host, &buff[4]) > 0) {
                /* host is an IPv6 address literal */
                buff[3] = 4;    /* ATYP = IPv6 */
                addrlen = 16;
        } else {
                /* host is a domain name */
                size_t hostlen = strlen (host);

                if (hostlen > 255)
                        return -1;

                buff[3] = 3;    /* ATYP = domain name */
                buff[4] = (unsigned char) hostlen;      /* length prefix */
                memcpy (&buff[5], host, hostlen);
                addrlen = 1 + hostlen;
        }

        netport = htons (port);
        memcpy (&buff[4 + addrlen], &netport, 2);

        return (int) (4 + addrlen + 2);
}

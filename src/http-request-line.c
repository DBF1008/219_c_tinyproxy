/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 2026 The Tinyproxy Authors
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

/*
 * See http-request-line.h for the contract.  This file intentionally depends
 * only on the C library so it can be linked into a standalone unit test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "http-request-line.h"

char *build_http_request_head (unsigned proto_minor,
                               const char *method, const char *path,
                               const char *host, const char *port_suffix,
                               const char *authstr)
{
        struct in6_addr dst;
        const char *lbracket, *rbracket;
        char *buf;
        int needed;

        if (port_suffix == NULL)
                port_suffix = "";

        /* Decide how the host is rendered in the Host header.  An IPv6 address
         * literal must be wrapped in brackets; everything else (IPv4 literal or
         * host name) is emitted verbatim.  This decision is independent of
         * whether a Proxy-Authorization header is required, so the two always
         * compose. */
        if (inet_pton (AF_INET6, host, &dst) > 0) {
                lbracket = "[";
                rbracket = "]";
        } else {
                lbracket = "";
                rbracket = "";
        }

        /* Size the buffer with a dry-run snprintf, then format for real.  The
         * caller-supplied strings are passed as arguments (never as the format
         * string), so a '%' in e.g. the request path cannot be misinterpreted.
         * The two branches use literal format strings (rather than a shared
         * variable) so the compiler can still type-check the arguments. */
        if (authstr != NULL) {
                needed = snprintf (NULL, 0,
                                   "%s %s HTTP/1.%u\r\n"
                                   "Host: %s%s%s%s\r\n"
                                   "Connection: close\r\n"
                                   "Proxy-Authorization: Basic %s\r\n",
                                   method, path, proto_minor,
                                   lbracket, host, rbracket, port_suffix,
                                   authstr);
                if (needed < 0)
                        return NULL;
                buf = (char *) malloc ((size_t) needed + 1);
                if (buf == NULL)
                        return NULL;
                snprintf (buf, (size_t) needed + 1,
                          "%s %s HTTP/1.%u\r\n"
                          "Host: %s%s%s%s\r\n"
                          "Connection: close\r\n"
                          "Proxy-Authorization: Basic %s\r\n",
                          method, path, proto_minor,
                          lbracket, host, rbracket, port_suffix,
                          authstr);
        } else {
                needed = snprintf (NULL, 0,
                                   "%s %s HTTP/1.%u\r\n"
                                   "Host: %s%s%s%s\r\n"
                                   "Connection: close\r\n",
                                   method, path, proto_minor,
                                   lbracket, host, rbracket, port_suffix);
                if (needed < 0)
                        return NULL;
                buf = (char *) malloc ((size_t) needed + 1);
                if (buf == NULL)
                        return NULL;
                snprintf (buf, (size_t) needed + 1,
                          "%s %s HTTP/1.%u\r\n"
                          "Host: %s%s%s%s\r\n"
                          "Connection: close\r\n",
                          method, path, proto_minor,
                          lbracket, host, rbracket, port_suffix);
        }

        return buf;
}

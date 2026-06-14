/* tinyproxy - SOCKS5 protocol helpers
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <string.h>
#include <arpa/inet.h>
#include "socks5.h"

/*
 * Build a SOCKS5 CONNECT request buffer.
 * Detects whether host is an IPv4 address, IPv6 address, or domain name
 * and sets the ATYP field accordingly per RFC 1928.
 *
 * Returns the total number of bytes written to buff, or -1 on error.
 */
int
socks5_build_connect_request(unsigned char *buff, size_t bufsize,
                              const char *host, uint16_t port)
{
        struct in_addr addr4;
        struct in6_addr addr6;
        unsigned short net_port;
        size_t len;

        buff[0] = 5;   /* SOCKS version */
        buff[1] = 1;   /* CONNECT command */
        buff[2] = 0;   /* reserved */

        net_port = htons(port);

        /* Try IPv4: ATYP=1, 4 address bytes + 2 port bytes = 10 total */
        if (inet_pton(AF_INET, host, &addr4) == 1) {
                if (bufsize < 10) return -1;
                buff[3] = 1;
                memcpy(&buff[4], &addr4, 4);
                memcpy(&buff[8], &net_port, 2);
                return 10;
        }

        /* Try IPv6: ATYP=4, 16 address bytes + 2 port bytes = 22 total */
        if (inet_pton(AF_INET6, host, &addr6) == 1) {
                if (bufsize < 22) return -1;
                buff[3] = 4;
                memcpy(&buff[4], &addr6, 16);
                memcpy(&buff[20], &net_port, 2);
                return 22;
        }

        /* Fall back to domain name: ATYP=3 */
        len = strlen(host);
        if (len > 255) return -1;
        if (bufsize < 7 + len) return -1;
        buff[3] = 3;
        buff[4] = (unsigned char)len;
        memcpy(&buff[5], host, len);
        memcpy(&buff[5 + len], &net_port, 2);
        return (int)(7 + len);
}

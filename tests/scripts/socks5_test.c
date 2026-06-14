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

/*
 * Regression test for the SOCKS5 upstream CONNECT request encoder.
 *
 * This pins the exact RFC 1928 wire format produced for the three kinds of
 * destination tinyproxy can be asked to reach through a SOCKS5 upstream:
 * an IPv4 literal (ATYP=1), an IPv6 literal (ATYP=4) and a domain name
 * (ATYP=3).  The IPv6 case is the regression that motivated splitting the
 * encoder out: it used to be (incorrectly) sent as a domain name.
 *
 * The encoder source is compiled straight in so the test has no dependency
 * on the rest of tinyproxy and can be built with a single compiler call:
 *
 *     cc tests/scripts/socks5_test.c -o socks5_test && ./socks5_test
 */

#include <stdio.h>
#include <string.h>

#include "../../src/socks5.c"

static int failures = 0;

static void hexdump (const char *label, const unsigned char *p, int n)
{
        int i;

        fprintf (stderr, "  %-5s:", label);
        for (i = 0; i < n; i++)
                fprintf (stderr, " %02x", p[i]);
        fprintf (stderr, "\n");
}

/* Build a request for host:port and assert it equals expected[0..explen). */
static void check_ok (const char *name, const char *host, unsigned short port,
                      const unsigned char *expected, int explen)
{
        unsigned char buff[512];
        int n;

        n = build_socks5_connect_request (buff, sizeof (buff), host, port);

        if (n != explen || memcmp (buff, expected, (size_t) explen) != 0) {
                fprintf (stderr, "FAIL: %s (host=%s port=%u)\n",
                         name, host, port);
                fprintf (stderr, "  got len=%d, want len=%d\n", n, explen);
                hexdump ("want", expected, explen);
                if (n > 0)
                        hexdump ("got", buff, n);
                failures++;
        } else {
                printf ("ok: %s\n", name);
        }
}

/* Assert that building a request fails (returns -1). */
static void check_err (const char *name, const char *host, unsigned short port,
                       size_t bufflen)
{
        unsigned char buff[512];
        int n;

        if (bufflen > sizeof (buff))
                bufflen = sizeof (buff);

        n = build_socks5_connect_request (buff, bufflen, host, port);
        if (n != -1) {
                fprintf (stderr, "FAIL: %s expected error, got len=%d\n",
                         name, n);
                failures++;
        } else {
                printf ("ok: %s (rejected as expected)\n", name);
        }
}

/* IPv4 literal 1.2.3.4:80 -> ATYP=1, 4-byte address. */
static const unsigned char expect_ipv4[] = {
        0x05, 0x01, 0x00, 0x01,                 /* VER CMD RSV ATYP */
        0x01, 0x02, 0x03, 0x04,                 /* 1.2.3.4 */
        0x00, 0x50                              /* port 80 */
};

/* IPv6 literal [2001:db8::1]:443 -> ATYP=4, 16-byte address. */
static const unsigned char expect_ipv6[] = {
        0x05, 0x01, 0x00, 0x04,                 /* VER CMD RSV ATYP */
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x01, 0xbb                              /* port 443 */
};

/* IPv6 loopback [::1]:1 -> ATYP=4, exercises the all-zero / compressed form. */
static const unsigned char expect_ipv6_lo[] = {
        0x05, 0x01, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x01                              /* port 1 */
};

/* Domain example.com:8080 -> ATYP=3, length-prefixed name. */
static const unsigned char expect_domain[] = {
        0x05, 0x01, 0x00, 0x03,                 /* VER CMD RSV ATYP */
        0x0b,                                   /* length = 11 */
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x1f, 0x90                              /* port 8080 */
};

int main (void)
{
        char longhost[257];
        char maxhost[256];
        unsigned char expect_max[4 + 1 + 255 + 2];
        int i;

        check_ok ("IPv4 1.2.3.4:80", "1.2.3.4", 80,
                  expect_ipv4, sizeof (expect_ipv4));
        check_ok ("IPv6 [2001:db8::1]:443", "2001:db8::1", 443,
                  expect_ipv6, sizeof (expect_ipv6));
        check_ok ("IPv6 [::1]:1", "::1", 1,
                  expect_ipv6_lo, sizeof (expect_ipv6_lo));
        check_ok ("domain example.com:8080", "example.com", 8080,
                  expect_domain, sizeof (expect_domain));

        /* A 255-byte name is the maximum that fits in the length prefix. */
        memset (maxhost, 'a', 255);
        maxhost[255] = '\0';
        expect_max[0] = 0x05;
        expect_max[1] = 0x01;
        expect_max[2] = 0x00;
        expect_max[3] = 0x03;
        expect_max[4] = 0xff;                   /* length = 255 */
        for (i = 0; i < 255; i++)
                expect_max[5 + i] = 'a';
        expect_max[260] = 0x00;                 /* port 80 hi */
        expect_max[261] = 0x50;                 /* port 80 lo */
        check_ok ("max-length domain (255 bytes)", maxhost, 80,
                  expect_max, sizeof (expect_max));

        /* A 256-byte name does not fit and must be rejected. */
        memset (longhost, 'a', 256);
        longhost[256] = '\0';
        check_err ("over-long domain (256 bytes)", longhost, 80, sizeof (longhost));

        /* A buffer smaller than the worst case must be rejected. */
        check_err ("buffer too small", "1.2.3.4", 80, 261);

        if (failures) {
                fprintf (stderr, "\n%d SOCKS5 encoder test(s) FAILED\n",
                         failures);
                return 1;
        }

        printf ("\nall SOCKS5 encoder tests passed\n");
        return 0;
}

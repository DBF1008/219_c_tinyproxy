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
 * Regression tests for build_http_request_head().
 *
 * The bug under test: when tinyproxy forwarded a request to an IPv6 address
 * literal through an HTTP upstream proxy that required Basic authentication,
 * the "Proxy-Authorization" header was silently dropped (the IPv6 "Host"
 * formatting branch returned before the auth branch could run), producing
 * 407/502 errors that did not occur for IPv4 or host name targets.
 *
 * These tests pin down that the two concerns -- IPv6 Host bracketing and
 * Proxy-Authorization injection -- compose for every target type.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http-request-line.h"

/* base64 of "user:pass"; the exact value is irrelevant, we just track it. */
#define AUTH "dXNlcjpwYXNz"

static int failures;

static void check (int cond, const char *desc)
{
        if (cond) {
                printf ("  ok    - %s\n", desc);
        } else {
                printf ("  FAIL  - %s\n", desc);
                failures++;
        }
}

static int has (const char *haystack, const char *needle)
{
        return haystack != NULL && strstr (haystack, needle) != NULL;
}

/* Verify an exact, byte-for-byte rendering to lock the header format. */
static void check_exact (const char *got, const char *want, const char *desc)
{
        if (got != NULL && strcmp (got, want) == 0) {
                printf ("  ok    - %s\n", desc);
        } else {
                printf ("  FAIL  - %s\n", desc);
                printf ("          want: %s\n", want ? want : "(null)");
                printf ("          got : %s\n", got ? got : "(null)");
                failures++;
        }
}

int main (void)
{
        char *out;

        printf ("# build_http_request_head: target-type x upstream-auth matrix\n");

        /* --- IPv4 literal target -------------------------------------- */
        printf ("IPv4 target, no upstream auth:\n");
        out = build_http_request_head (1, "GET", "/", "127.0.0.1", ":3128", NULL);
        check (has (out, "Host: 127.0.0.1:3128\r\n"), "Host has plain IPv4, no brackets");
        check (!has (out, "Proxy-Authorization"), "no Proxy-Authorization without auth");
        free (out);

        printf ("IPv4 target, with upstream auth:\n");
        out = build_http_request_head (0, "GET", "/", "127.0.0.1", ":3128", AUTH);
        check_exact (out,
                     "GET / HTTP/1.0\r\n"
                     "Host: 127.0.0.1:3128\r\n"
                     "Connection: close\r\n"
                     "Proxy-Authorization: Basic " AUTH "\r\n",
                     "IPv4 + auth renders exactly (HTTP/1.0)");
        free (out);

        /* --- host name target ----------------------------------------- */
        printf ("host name target, no upstream auth:\n");
        out = build_http_request_head (1, "GET", "/", "example.com", "", NULL);
        check_exact (out,
                     "GET / HTTP/1.1\r\n"
                     "Host: example.com\r\n"
                     "Connection: close\r\n",
                     "host name (default port) renders exactly");
        check (!has (out, "["), "host name is not bracketed");
        free (out);

        printf ("host name target, with upstream auth:\n");
        out = build_http_request_head (1, "GET", "/", "example.com", ":8080", AUTH);
        check (has (out, "Host: example.com:8080\r\n"), "Host has host name + port");
        check (has (out, "Proxy-Authorization: Basic " AUTH "\r\n"),
               "Proxy-Authorization present for host name target");
        free (out);

        /* --- IPv6 address literal target ------------------------------ */
        printf ("IPv6 literal target, no upstream auth:\n");
        out = build_http_request_head (1, "GET", "/", "2001:db8::1", ":8080", NULL);
        check (has (out, "Host: [2001:db8::1]:8080\r\n"), "IPv6 Host is bracketed");
        check (!has (out, "Proxy-Authorization"), "no Proxy-Authorization without auth");
        free (out);

        /* THE REGRESSION CASE: IPv6 literal + upstream auth.
         * Before the fix this returned a request WITHOUT Proxy-Authorization. */
        printf ("IPv6 literal target, with upstream auth (regression):\n");
        out = build_http_request_head (1, "GET", "/", "2001:db8::1", ":8080", AUTH);
        check_exact (out,
                     "GET / HTTP/1.1\r\n"
                     "Host: [2001:db8::1]:8080\r\n"
                     "Connection: close\r\n"
                     "Proxy-Authorization: Basic " AUTH "\r\n",
                     "IPv6 + auth: bracketed Host AND Proxy-Authorization both present");
        free (out);

        /* IPv6 with default port (empty suffix) still brackets + authenticates. */
        printf ("IPv6 literal target (default port), with upstream auth:\n");
        out = build_http_request_head (1, "GET", "/", "::1", "", AUTH);
        check (has (out, "Host: [::1]\r\n"), "IPv6 (no port) Host is bracketed");
        check (has (out, "Proxy-Authorization: Basic " AUTH "\r\n"),
               "Proxy-Authorization present for IPv6 default-port target");
        free (out);

        if (failures == 0)
                printf ("\nAll checks passed.\n");
        else
                printf ("\n%d check(s) FAILED.\n", failures);

        return failures == 0 ? 0 : 1;
}

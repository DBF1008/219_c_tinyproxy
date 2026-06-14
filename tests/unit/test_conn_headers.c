/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1998 Steven Young <sdyoung@miranda.org>
 * Copyright (C) 1999-2005 Robert James Kaes <rjkaes@users.sourceforge.net>
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
 * Regression tests for remove_connection_headers().
 *
 * History: the cleanup loop walked the candidate headers {"connection",
 * "proxy-connection"} but did `return 0` the moment a candidate was absent.
 * As a result a request that carried only "Proxy-Connection" never had the
 * hop-by-hop headers it enumerated stripped, leaking connection-level headers
 * to the downstream server.  These tests pin down the fixed behaviour for the
 * three scenarios that matter:
 *
 *   1) only "Proxy-Connection" present (the original bug),
 *   2) both "Connection" and "Proxy-Connection" present,
 *   3) header values carrying extension tokens / multiple tokens,
 *
 * plus a guard against re-introducing the CVE-2023-49606 double-free when a
 * header lists one of the connection headers as a token.
 *
 * The function under test depends only on the pseudomap container, so it is
 * linked here directly together with pseudomap.c and sblist.c -- no proxy
 * runtime, sockets, or configuration involved.
 */

#include "conn-headers.h"
#include "pseudomap.h"

#include <stdio.h>
#include <stdlib.h>

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond, msg)                                        \
        do {                                                    \
                g_checks++;                                     \
                if (cond) {                                     \
                        printf ("    ok   - %s\n", (msg));      \
                } else {                                        \
                        g_failures++;                           \
                        printf ("    FAIL - %s\n", (msg));      \
                }                                               \
        } while (0)

/* pseudomap_append() duplicates both key and value internally, so casting
   away const on the string literals we pass as values is safe. */
static void add (pseudomap *m, const char *key, const char *value)
{
        if (!pseudomap_append (m, key, (char *) value)) {
                fprintf (stderr, "pseudomap_append failed (out of memory?)\n");
                exit (2);
        }
}

/* presence test; lookup is case-insensitive, matching real header handling. */
static int present (pseudomap *m, const char *key)
{
        return pseudomap_find (m, key) != NULL;
}

/*
 * Scenario 1: only "Proxy-Connection" is present.  This is the exact case the
 * old early-return mishandled -- both the enumerated hop-by-hop header and the
 * "Proxy-Connection" header itself must be removed.
 */
static void scenario_only_proxy_connection (void)
{
        pseudomap *m = pseudomap_create ();

        add (m, "Host", "example.com");
        add (m, "Proxy-Connection", "close, X-Custom-Hop");
        add (m, "X-Custom-Hop", "consumed-at-proxy");
        add (m, "X-Keep", "keep-me");

        remove_connection_headers (m);

        CHECK (!present (m, "proxy-connection"),
               "Proxy-Connection header itself is removed");
        CHECK (!present (m, "x-custom-hop"),
               "hop-by-hop header listed only by Proxy-Connection is removed");
        CHECK (present (m, "host"), "unrelated Host header is preserved");
        CHECK (present (m, "x-keep"), "unrelated X-Keep header is preserved");

        pseudomap_destroy (m);
}

/*
 * Scenario 2: both "Connection" and "Proxy-Connection" are present.  Tokens
 * from *both* headers must be stripped -- the X-Hop-B check is the one that
 * regresses if the loop ever stops after the first candidate again.
 */
static void scenario_both_headers (void)
{
        pseudomap *m = pseudomap_create ();

        add (m, "Host", "example.com");
        add (m, "Connection", "close, X-Hop-A");
        add (m, "Proxy-Connection", "keep-alive, X-Hop-B");
        add (m, "X-Hop-A", "a");
        add (m, "X-Hop-B", "b");
        add (m, "Content-Type", "text/plain");

        remove_connection_headers (m);

        CHECK (!present (m, "connection"), "Connection header is removed");
        CHECK (!present (m, "proxy-connection"),
               "Proxy-Connection header is removed");
        CHECK (!present (m, "x-hop-a"),
               "hop-by-hop header listed by Connection is removed");
        CHECK (!present (m, "x-hop-b"),
               "hop-by-hop header listed by Proxy-Connection is removed");
        CHECK (present (m, "host"), "Host header is preserved");
        CHECK (present (m, "content-type"), "Content-Type header is preserved");

        pseudomap_destroy (m);
}

/*
 * Scenario 3: a value carrying several tokens, including standard hop-by-hop
 * names and an "extension" token, separated by a mix of commas and spaces.
 * Every enumerated token must be removed, unrelated headers untouched.
 */
static void scenario_extension_tokens (void)
{
        pseudomap *m = pseudomap_create ();

        add (m, "Proxy-Connection", "close, TE,Upgrade ,  X-Extension-Token");
        add (m, "TE", "trailers");
        add (m, "Upgrade", "h2c");
        add (m, "X-Extension-Token", "v");
        add (m, "Host", "example.com");

        remove_connection_headers (m);

        CHECK (!present (m, "te"), "TE token is removed");
        CHECK (!present (m, "upgrade"), "Upgrade token is removed");
        CHECK (!present (m, "x-extension-token"),
               "extension token is removed regardless of separators");
        CHECK (!present (m, "proxy-connection"),
               "Proxy-Connection header is removed");
        CHECK (present (m, "host"), "Host header is preserved");

        pseudomap_destroy (m);
}

/*
 * Guard: a header that lists one of the connection headers as a token must not
 * trigger a double free (CVE-2023-49606), and both connection headers must
 * still be removed.  Exercising both candidates also depends on the loop no
 * longer bailing out early.
 */
static void scenario_self_referential_tokens (void)
{
        pseudomap *m = pseudomap_create ();

        add (m, "Connection", "Proxy-Connection, close");
        add (m, "Proxy-Connection", "keep-alive");
        add (m, "Host", "example.com");

        remove_connection_headers (m);

        CHECK (!present (m, "connection"),
               "Connection header is removed (self-reference guard)");
        CHECK (!present (m, "proxy-connection"),
               "Proxy-Connection header is removed (self-reference guard)");
        CHECK (present (m, "host"), "Host header is preserved");

        pseudomap_destroy (m);
}

int main (void)
{
        printf ("== remove_connection_headers regression tests ==\n");

        printf ("[scenario 1] only Proxy-Connection present\n");
        scenario_only_proxy_connection ();

        printf ("[scenario 2] both Connection and Proxy-Connection present\n");
        scenario_both_headers ();

        printf ("[scenario 3] extension / multi-token values\n");
        scenario_extension_tokens ();

        printf ("[scenario 4] self-referential tokens (CVE-2023-49606 guard)\n");
        scenario_self_referential_tokens ();

        printf ("\n%d checks run, %d failure(s)\n", g_checks, g_failures);

        return g_failures ? 1 : 0;
}

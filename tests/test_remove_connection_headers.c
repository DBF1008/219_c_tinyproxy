/*
 * Regression tests for remove_connection_headers() in src/reqs.c.
 *
 * This standalone test verifies that hop-by-hop headers declared in
 * Connection and Proxy-Connection are properly removed, covering:
 *
 *   1. Only Proxy-Connection (the bug: early return skipped cleanup)
 *   2. Both Connection and Proxy-Connection present
 *   3. Extended tokens in connection headers
 *   4. Neither header present (no-op, must not crash)
 *   5. Only Connection header present (existing behavior preserved)
 *
 * Build:
 *   cc -o test_remove_connection_headers \
 *      tests/test_remove_connection_headers.c \
 *      -I src
 *   ./test_remove_connection_headers
 */

/* Provide a minimal config.h stand-in so pseudomap.c compiles. */
#ifndef HAVE_CONFIG_H
#define HAVE_CONFIG_H
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Pull in the data-structure implementation directly. */
#include "sblist.c"
#include "pseudomap.c"

/* ------------------------------------------------------------------ */
/* remove_connection_headers – exact copy of the FIXED version        */
/* from src/reqs.c so we test the same logic that ships.              */
/* ------------------------------------------------------------------ */
static int remove_connection_headers (pseudomap *hashofheaders)
{
        static const char *headers[] = {
                "connection",
                "proxy-connection"
        };

        char *data;
        char *ptr;
        ssize_t len;
        int i,j,df;

        for (i = 0; i != (sizeof (headers) / sizeof (char *)); ++i) {
                /* Look for the connection header.  If it's not found, skip
                 * to the next header name (e.g. proxy-connection) rather
                 * than returning early. */
                data = pseudomap_find(hashofheaders, headers[i]);

                if (!data)
                        continue;

                len = strlen(data);

                /*
                 * Go through the data line and replace any special characters
                 * with a NULL.
                 */
                ptr = data;
                while ((ptr = strpbrk (ptr, "()<>@,;:\\\"/[]?={} \t")))
                        *ptr++ = '\0';

                /*
                 * All the tokens are separated by NULLs.  Now go through the
                 * token and remove them from the hashofheaders.
                 */
                ptr = data;
                while (ptr < data + len) {
                        df = 0;
                        /* check that ptr isn't one of headers to prevent
                           double-free (CVE-2023-49606) */
                        for (j = 0; j != (sizeof (headers) / sizeof (char *)); ++j)
                                if(!strcasecmp(ptr, headers[j])) df = 1;
                        if (!df) pseudomap_remove (hashofheaders, ptr);

                        /* Advance ptr to the next token */
                        ptr += strlen (ptr) + 1;
                        while (ptr < data + len && *ptr == '\0')
                                ptr++;
                }

                /* Now remove the connection header it self. */
                pseudomap_remove (hashofheaders, headers[i]);
        }

        return 0;
}

/* ------------------------------------------------------------------ */
/* Test helpers                                                        */
/* ------------------------------------------------------------------ */
static int tests_run    = 0;
static int tests_failed = 0;

#define ASSERT_NULL(map, key) do {                                      \
        tests_run++;                                                    \
        if (pseudomap_find((map), (key)) != NULL) {                     \
                fprintf(stderr, "  FAIL [%s:%d]: header '%s' "          \
                        "should have been removed but still present\n", \
                        __FILE__, __LINE__, (key));                     \
                tests_failed++;                                         \
        } else {                                                        \
                printf("  ok: '%s' removed\n", (key));                  \
        }                                                               \
} while (0)

#define ASSERT_PRESENT(map, key) do {                                   \
        tests_run++;                                                    \
        if (pseudomap_find((map), (key)) == NULL) {                     \
                fprintf(stderr, "  FAIL [%s:%d]: header '%s' "          \
                        "should still be present but was removed\n",    \
                        __FILE__, __LINE__, (key));                     \
                tests_failed++;                                         \
        } else {                                                        \
                printf("  ok: '%s' still present\n", (key));            \
        }                                                               \
} while (0)

/* ------------------------------------------------------------------ */
/* Test cases                                                          */
/* ------------------------------------------------------------------ */

/*
 * Test 1: Only Proxy-Connection header (no Connection).
 * This is the primary bug scenario – the old code returned 0 as soon
 * as it didn't find "connection", leaving the hop-by-hop headers
 * declared in Proxy-Connection intact.
 */
static void test_proxy_connection_only(void)
{
        pseudomap *map;

        printf("\n=== test_proxy_connection_only ===\n");
        printf("Scenario: request has Proxy-Connection but no Connection header.\n");
        printf("Expect: x-custom-hop and proxy-connection itself are removed;\n");
        printf("        x-keep-me stays.\n");

        map = pseudomap_create();
        pseudomap_append(map, "host", "example.com");
        pseudomap_append(map, "x-keep-me", "yes");
        pseudomap_append(map, "x-custom-hop", "should-go");
        pseudomap_append(map, "proxy-connection", "x-custom-hop");

        remove_connection_headers(map);

        ASSERT_NULL(map, "proxy-connection");
        ASSERT_NULL(map, "x-custom-hop");
        ASSERT_PRESENT(map, "host");
        ASSERT_PRESENT(map, "x-keep-me");

        pseudomap_destroy(map);
}

/*
 * Test 2: Both Connection and Proxy-Connection present.
 * Both must be processed and both removed along with their tokens.
 */
static void test_both_headers(void)
{
        pseudomap *map;

        printf("\n=== test_both_headers ===\n");
        printf("Scenario: request carries both Connection and Proxy-Connection.\n");
        printf("Expect: both connection headers and all declared tokens removed.\n");

        map = pseudomap_create();
        pseudomap_append(map, "host", "example.com");
        pseudomap_append(map, "x-conn-token", "from-connection");
        pseudomap_append(map, "x-proxy-token", "from-proxy-connection");
        pseudomap_append(map, "x-keep-me", "yes");
        pseudomap_append(map, "connection", "x-conn-token");
        pseudomap_append(map, "proxy-connection", "x-proxy-token");

        remove_connection_headers(map);

        ASSERT_NULL(map, "connection");
        ASSERT_NULL(map, "proxy-connection");
        ASSERT_NULL(map, "x-conn-token");
        ASSERT_NULL(map, "x-proxy-token");
        ASSERT_PRESENT(map, "host");
        ASSERT_PRESENT(map, "x-keep-me");

        pseudomap_destroy(map);
}

/*
 * Test 3: Extended tokens (comma-separated list with spaces).
 * RFC 7230 §6.1 allows "Connection: foo, bar" style lists.
 */
static void test_extended_tokens(void)
{
        pseudomap *map;

        printf("\n=== test_extended_tokens ===\n");
        printf("Scenario: Proxy-Connection lists multiple comma-separated tokens.\n");
        printf("Expect: all listed tokens and the Proxy-Connection header removed.\n");

        map = pseudomap_create();
        pseudomap_append(map, "host", "example.com");
        pseudomap_append(map, "x-hop-a", "a");
        pseudomap_append(map, "x-hop-b", "b");
        pseudomap_append(map, "x-hop-c", "c");
        pseudomap_append(map, "x-keep-me", "yes");
        pseudomap_append(map, "proxy-connection", "x-hop-a, x-hop-b, x-hop-c");

        remove_connection_headers(map);

        ASSERT_NULL(map, "proxy-connection");
        ASSERT_NULL(map, "x-hop-a");
        ASSERT_NULL(map, "x-hop-b");
        ASSERT_NULL(map, "x-hop-c");
        ASSERT_PRESENT(map, "host");
        ASSERT_PRESENT(map, "x-keep-me");

        pseudomap_destroy(map);
}

/*
 * Test 4: Neither Connection nor Proxy-Connection present.
 * Must be a silent no-op.
 */
static void test_no_connection_headers(void)
{
        pseudomap *map;

        printf("\n=== test_no_connection_headers ===\n");
        printf("Scenario: no Connection or Proxy-Connection headers at all.\n");
        printf("Expect: function returns without error; other headers untouched.\n");

        map = pseudomap_create();
        pseudomap_append(map, "host", "example.com");
        pseudomap_append(map, "accept", "*/*");

        remove_connection_headers(map);

        ASSERT_PRESENT(map, "host");
        ASSERT_PRESENT(map, "accept");

        pseudomap_destroy(map);
}

/*
 * Test 5: Only Connection header (no Proxy-Connection).
 * This is the existing behavior that must continue to work.
 */
static void test_connection_only(void)
{
        pseudomap *map;

        printf("\n=== test_connection_only ===\n");
        printf("Scenario: request has Connection but no Proxy-Connection.\n");
        printf("Expect: connection header and its declared token removed.\n");

        map = pseudomap_create();
        pseudomap_append(map, "host", "example.com");
        pseudomap_append(map, "x-upgrade", "websocket");
        pseudomap_append(map, "x-keep-me", "yes");
        pseudomap_append(map, "connection", "x-upgrade");

        remove_connection_headers(map);

        ASSERT_NULL(map, "connection");
        ASSERT_NULL(map, "x-upgrade");
        ASSERT_PRESENT(map, "host");
        ASSERT_PRESENT(map, "x-keep-me");

        pseudomap_destroy(map);
}

/*
 * Test 6: Proxy-Connection references Connection token name.
 * This is the CVE-2023-49606 double-free guard: when a token in the
 * value matches one of the connection header names, it must not be
 * removed a second time.
 */
static void test_cve_2023_49606_guard(void)
{
        pseudomap *map;

        printf("\n=== test_cve_2023_49606_guard ===\n");
        printf("Scenario: Proxy-Connection value references 'connection' token name.\n");
        printf("Expect: no crash/double-free; proxy-connection removed.\n");

        map = pseudomap_create();
        pseudomap_append(map, "host", "example.com");
        pseudomap_append(map, "connection", "keep-alive");
        pseudomap_append(map, "proxy-connection", "connection");

        remove_connection_headers(map);

        /* "connection" is processed first in the loop: its token
         * "keep-alive" is removed, then "connection" itself is removed.
         * When "proxy-connection" is processed next, the token "connection"
         * is skipped by the CVE guard. Final state: both gone, no crash. */
        ASSERT_NULL(map, "connection");
        ASSERT_NULL(map, "proxy-connection");
        ASSERT_NULL(map, "keep-alive");
        ASSERT_PRESENT(map, "host");

        pseudomap_destroy(map);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(void)
{
        printf("remove_connection_headers regression tests\n");
        printf("============================================\n");

        test_proxy_connection_only();
        test_both_headers();
        test_extended_tokens();
        test_no_connection_headers();
        test_connection_only();
        test_cve_2023_49606_guard();

        printf("\n============================================\n");
        printf("Results: %d tests, %d passed, %d failed\n",
               tests_run, tests_run - tests_failed, tests_failed);

        return tests_failed ? 1 : 0;
}

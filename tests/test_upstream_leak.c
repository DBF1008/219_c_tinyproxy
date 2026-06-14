/*
 * test_upstream_leak.c -- Regression test for upstream auth-field leaks.
 *
 * Verifies that free_upstream_list() and the upstream_add() duplicate-
 * default cleanup path release ALL heap-allocated fields:
 *   - HTTP  upstream: ua.authstr
 *   - SOCKS upstream: ua.user and pass
 *
 * Build (from project root, requires gcc or clang):
 *   cc -DNDEBUG -DUPSTREAM_SUPPORT -Isrc \
 *      -include tests/test_alloc.h \
 *      tests/test_upstream_leak.c src/upstream.c src/base64.c \
 *      -o tests/test_upstream_leak
 *
 * Run:
 *   ./tests/test_upstream_leak
 *
 * Exit 0 = all tests pass (no leaks).  Non-zero = failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

/* ------------------------------------------------------------------ */
/* Minimal stubs for external dependencies required by upstream.c     */
/* ------------------------------------------------------------------ */

/* log.h -- upstream.c calls log_message for diagnostics */
void log_message(int level, const char *fmt, ...)
{
    (void)level;
    (void)fmt;
}

/* basicauth.h + base64.h -- HTTP upstream builds an auth string */
#include "base64.h"

ssize_t basicauth_string(const char *user, const char *pass,
                         char *buf, size_t bufsize)
{
    char tmp[256 + 2];
    int l;
    if (!user || !pass) return -1;
    l = snprintf(tmp, sizeof tmp, "%s:%s", user, pass);
    if (l < 0 || l >= (ssize_t)sizeof tmp) return 0;
    if (bufsize < (BASE64ENC_BYTES((unsigned)l) + 1)) return 0;
    base64enc(buf, tmp, l);
    return BASE64ENC_BYTES(l);
}

/* hostspec.h -- upstream_build parses domain filters */
#include "hostspec.h"

int hostspec_parse(char *domain, struct hostspec *h)
{
    if (!domain || !domain[0]) return -1;
    h->type = HST_STRING;
    h->address.string = strdup(domain);   /* tracked via test_alloc.h */
    return 0;
}

int hostspec_match(const char *ip, const struct hostspec *h)
{
    (void)ip;
    (void)h;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Include upstream API                                               */
/* ------------------------------------------------------------------ */
#include "upstream.h"

/* ------------------------------------------------------------------ */
/* Test harness                                                       */
/* ------------------------------------------------------------------ */
static int tests_run    = 0;
static int tests_failed = 0;

static long alloc_before;

static void snap(void)     { alloc_before = g_alloc_count; }
static long delta(void)    { return g_alloc_count - alloc_before; }

#define RUN(fn) do { \
    tests_run++; \
    printf("  %-60s ", #fn); \
    fflush(stdout); \
    if (fn()) { printf("PASS\n"); } \
    else      { printf("FAIL (delta=%ld, g_alloc_count=%ld)\n", \
                       delta(), g_alloc_count); tests_failed++; } \
} while (0)

/* ------------------------------------------------------------------ */
/* Test: HTTP upstream with credentials                               */
/* ------------------------------------------------------------------ */
static int test_http_auth(void)
{
    struct upstream *list = NULL;
    snap();
    if (upstream_add("proxy.example.com", 8080, ".example.com",
                     "alice", "s3cret", PT_HTTP, &list) != UBE_SUCCESS)
        return 0;
    if (!list || !list->ua.authstr) return 0;
    free_upstream_list(list);
    return delta() == 0;
}

/* ------------------------------------------------------------------ */
/* Test: SOCKS5 upstream with user + pass                             */
/* ------------------------------------------------------------------ */
static int test_socks5_auth(void)
{
    struct upstream *list = NULL;
    snap();
    if (upstream_add("socks.example.com", 1080, ".internal.net",
                     "bob", "p@ss", PT_SOCKS5, &list) != UBE_SUCCESS)
        return 0;
    if (!list || !list->ua.user || !list->pass) return 0;
    free_upstream_list(list);
    return delta() == 0;
}

/* ------------------------------------------------------------------ */
/* Test: SOCKS4 upstream with user + pass                             */
/* ------------------------------------------------------------------ */
static int test_socks4_auth(void)
{
    struct upstream *list = NULL;
    snap();
    if (upstream_add("socks4.example.com", 1080, NULL,
                     "charlie", "hunter2", PT_SOCKS4, &list) != UBE_SUCCESS)
        return 0;
    if (!list || !list->ua.user) return 0;
    free_upstream_list(list);
    return delta() == 0;
}

/* ------------------------------------------------------------------ */
/* Test: PT_NONE (bypass rule, no auth)                               */
/* ------------------------------------------------------------------ */
static int test_none_no_auth(void)
{
    struct upstream *list = NULL;
    snap();
    if (upstream_add(NULL, 0, ".blocked.com",
                     NULL, NULL, PT_NONE, &list) != UBE_SUCCESS)
        return 0;
    free_upstream_list(list);
    return delta() == 0;
}

/* ------------------------------------------------------------------ */
/* Test: HTTP upstream without credentials                            */
/* ------------------------------------------------------------------ */
static int test_http_no_auth(void)
{
    struct upstream *list = NULL;
    snap();
    if (upstream_add("proxy.example.com", 8080, NULL,
                     NULL, NULL, PT_HTTP, &list) != UBE_SUCCESS)
        return 0;
    free_upstream_list(list);
    return delta() == 0;
}

/* ------------------------------------------------------------------ */
/* Test: Mixed list with multiple proxy types and auth modes          */
/* ------------------------------------------------------------------ */
static int test_mixed_list(void)
{
    struct upstream *list = NULL;
    snap();

    upstream_add("http.proxy", 3128, ".web.com",
                 "u1", "p1", PT_HTTP, &list);
    upstream_add("socks.proxy", 1080, ".vpn.com",
                 "u2", "p2", PT_SOCKS5, &list);
    upstream_add("socks4.proxy", 1080, NULL,
                 "u3", "p3", PT_SOCKS4, &list);
    upstream_add("http2.proxy", 8080, NULL,
                 "u4", "p4", PT_HTTP, &list);
    upstream_add(NULL, 0, ".local",
                 NULL, NULL, PT_NONE, &list);

    free_upstream_list(list);
    return delta() == 0;
}

/* ------------------------------------------------------------------ */
/* Test: Duplicate-default upstream triggers cleanup path             */
/*   The SECOND upstream_add must free the rejected node completely.  */
/* ------------------------------------------------------------------ */
static int test_dup_default_cleanup(void)
{
    struct upstream *list = NULL;
    snap();

    /* First default: SOCKS5 with auth -- accepted */
    if (upstream_add("first.proxy", 1080, NULL,
                     "u1", "p1", PT_SOCKS5, &list) != UBE_SUCCESS)
        return 0;

    /* Second default: HTTP with auth -- rejected as duplicate.
     * The cleanup in upstream_add must free ua.authstr. */
    upstream_add("second.proxy", 8080, NULL,
                 "u2", "p2", PT_HTTP, &list);

    /* The original entry is still there */
    if (!list) return 0;

    free_upstream_list(list);
    return delta() == 0;
}

/* ------------------------------------------------------------------ */
/* Test: Simulate 100 config-reload cycles (the original bug)         */
/* ------------------------------------------------------------------ */
static int test_reload_storm(void)
{
    int i;
    snap();
    for (i = 0; i < 100; i++) {
        struct upstream *list = NULL;
        upstream_add("p1.ex.com", 8080, ".d1.com",
                     "alice", "s1", PT_HTTP, &list);
        upstream_add("p2.ex.com", 1080, ".d2.com",
                     "bob", "s2", PT_SOCKS5, &list);
        upstream_add("p3.ex.com", 1080, NULL,
                     "charlie", "s3", PT_SOCKS4, &list);
        upstream_add("p4.ex.com", 3128, NULL,
                     "dave", "s4", PT_HTTP, &list);
        upstream_add(NULL, 0, ".bypass.net",
                     NULL, NULL, PT_NONE, &list);
        free_upstream_list(list);
    }
    return delta() == 0;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */
int main(void)
{
    printf("Upstream auth-field leak regression tests\n");
    printf("==========================================\n");

    RUN(test_http_auth);
    RUN(test_socks5_auth);
    RUN(test_socks4_auth);
    RUN(test_none_no_auth);
    RUN(test_http_no_auth);
    RUN(test_mixed_list);
    RUN(test_dup_default_cleanup);
    RUN(test_reload_storm);

    printf("==========================================\n");
    printf("Results: %d/%d passed\n", tests_run - tests_failed, tests_run);

    if (tests_failed) {
        printf("LEAK DETECTED -- %d test(s) failed\n", tests_failed);
        return 1;
    }
    printf("No leaks detected.\n");
    return 0;
}

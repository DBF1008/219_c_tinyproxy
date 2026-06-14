/* tinyproxy - regression test for the upstream auth-string memory leak.
 *
 * Background
 * ----------
 * free_upstream_list() (called from free_config() on every config reload)
 * used to release only `host` and the HST_STRING `target`, leaking the
 * authentication strings: the HTTP `ua.authstr` and the SOCKS `ua.user` /
 * `pass`.  Repeated reloads of a config carrying upstream credentials thus
 * grew the heap without bound.  The same omission existed in the
 * "duplicate default upstream" cleanup path inside upstream_add().
 *
 * What this test proves
 * ---------------------
 * It compiles upstream.c into this single translation unit with a counting
 * allocator wired in at the heap.h macro layer (safemalloc/safestrdup/
 * safefree), and the few external dependencies stubbed.  Every allocation
 * made while an upstream list is built must be matched by a free when the
 * list is torn down, so the live-allocation counter must return to zero.
 * The check covers each proxy type, the duplicate-default cleanup path, and
 * a long build/free loop that models repeated reloads.
 *
 * Because the counter is exact, this test FAILS against the original buggy
 * upstream.c (auth strings never freed -> counter stays positive) and PASSES
 * against the fixed version -- a genuine regression guard, independent of
 * valgrind/ASan (handy on platforms where leak detection is unavailable).
 *
 * Standalone build & run (from the repository root):
 *     cc -std=gnu99 -Wall -Isrc -DUPSTREAM_SUPPORT \
 *        -o /tmp/upstream_leak_test tests/upstream_leak_test.c && /tmp/upstream_leak_test
 *
 * It can also be wired into `make check` as a check_PROGRAMS entry.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Pull in the type definitions (struct upstream, struct hostspec, the enums)
 * before we install our counting allocator and dependency stubs.
 */
#include "../src/upstream.h"

/* --------------------------------------------------------------------------
 * Counting allocator.
 *
 * One outstanding allocation == +1; freeing a non-NULL pointer == -1, which
 * mirrors the real safefree() semantics (free(NULL) / safefree on a NULL
 * lvalue is a no-op).  upstream.c only ever uses malloc/strdup/free, so those
 * are the only primitives we need.
 * ------------------------------------------------------------------------ */
static long live_allocs = 0;

static void *count_malloc (size_t n)
{
        void *p = malloc (n);
        if (p)
                live_allocs++;
        return p;
}

static char *count_strdup (const char *s)
{
        char *p = strdup (s);
        if (p)
                live_allocs++;
        return p;
}

static void count_free (void *p)
{
        if (p) {
                free (p);
                live_allocs--;
        }
}

/*
 * Bypass heap.h entirely (its include guard) so that our macros below are the
 * ones upstream.c sees.  safefree() frees and NULLs its lvalue, exactly like
 * the production macro.
 */
#define TINYPROXY_HEAP_H
#define safemalloc(x)   count_malloc (x)
#define safestrdup(x)   count_strdup (x)
#define safefree(x)     (count_free (x), (x) = NULL)

/* --------------------------------------------------------------------------
 * Stubs for upstream.c's external dependencies.  Definitions appear before
 * the (later) header declarations pulled in by upstream.c, which is legal.
 * ------------------------------------------------------------------------ */

/* log.h: silence all logging. */
void log_message (int level, const char *fmt, ...)
{
        (void) level;
        (void) fmt;
}

/*
 * basicauth.h: the real routine base64-encodes "user:pass".  For the leak
 * test only the contract matters -- produce a non-empty token (which
 * upstream_build then safestrdup()s, and which we therefore track) or return
 * 0 on overflow.
 */
ssize_t basicauth_string (const char *user, const char *pass,
                          char *buf, size_t bufsize)
{
        int n = snprintf (buf, bufsize, "%s:%s",
                          user ? user : "", pass ? pass : "");
        if (n < 0 || (size_t) n >= bufsize)
                return 0;
        return n;
}

/*
 * hostspec.h: treat every domain as a string spec so that the
 * target.address.string allocation/free path is exercised too.
 */
int hostspec_parse (char *domain, struct hostspec *h)
{
        h->type = HST_STRING;
        h->address.string = count_strdup (domain);
        return h->address.string ? 0 : 1;
}

int hostspec_match (const char *ip, const struct hostspec *h)
{
        (void) ip;
        (void) h;
        return 0;
}

/* Finally, compile the code under test. */
#include "../src/upstream.c"

/* --------------------------------------------------------------------------
 * Test harness.
 * ------------------------------------------------------------------------ */
static int failures = 0;

static void check_zero (const char *scenario)
{
        if (live_allocs != 0) {
                printf ("  [FAIL] %-44s %ld allocation(s) leaked\n",
                        scenario, live_allocs);
                failures++;
        } else {
                printf ("  [ ok ] %-44s no leak\n", scenario);
        }
}

/* Build a list with one upstream of the given shape, free it, expect zero. */
static void one_shot (const char *scenario, const char *host, int port,
                      char *domain, const char *user, const char *pass,
                      proxy_type type)
{
        struct upstream *list = NULL;
        enum upstream_build_error ube;

        ube = upstream_add (host, port, domain, user, pass, type, &list);
        if (ube != UBE_SUCCESS || list == NULL) {
                printf ("  [FAIL] %-44s build failed (ube=%d)\n",
                        scenario, (int) ube);
                failures++;
                /* still attempt to reclaim whatever was built */
                free_upstream_list (list);
                return;
        }

        free_upstream_list (list);
        check_zero (scenario);
}

/* A representative mixed list spanning every proxy type. */
static struct upstream *build_mixed_list (void)
{
        struct upstream *list = NULL;

        /* default HTTP upstream with auth (-> ua.authstr) */
        upstream_add ("http.example", 3128, NULL,
                      "alice", "secret", PT_HTTP, &list);
        /* SOCKS5 upstream for a domain, with auth (-> ua.user + pass + host
         * + target string) */
        upstream_add ("socks5.example", 1080, (char *) "10.0.0.0/8",
                      "bob", "hunter2", PT_SOCKS5, &list);
        /* SOCKS4 upstream for a domain, with auth */
        upstream_add ("socks4.example", 1081, (char *) "192.168.0.0/16",
                      "carol", "pw", PT_SOCKS4, &list);
        /* a "none" rule (-> target string only) */
        upstream_add (NULL, 0, (char *) "direct.example",
                      NULL, NULL, PT_NONE, &list);

        return list;
}

int main (void)
{
        printf ("upstream auth-string leak regression test\n");

        /* Per-type one-shot build/free cycles. */
        one_shot ("HTTP default upstream w/ auth",
                  "http.example", 3128, NULL, "alice", "secret", PT_HTTP);
        one_shot ("HTTP domain upstream w/ auth",
                  "http.example", 3128, (char *) "10.0.0.0/8",
                  "alice", "secret", PT_HTTP);
        one_shot ("SOCKS5 default upstream w/ auth",
                  "socks5.example", 1080, NULL, "bob", "hunter2", PT_SOCKS5);
        one_shot ("SOCKS5 domain upstream w/ auth",
                  "socks5.example", 1080, (char *) "10.0.0.0/8",
                  "bob", "hunter2", PT_SOCKS5);
        one_shot ("SOCKS4 domain upstream w/ auth",
                  "socks4.example", 1081, (char *) "192.168.0.0/16",
                  "carol", "pw", PT_SOCKS4);
        one_shot ("upstream without auth",
                  "plain.example", 8080, NULL, NULL, NULL, PT_HTTP);
        one_shot ("none rule",
                  NULL, 0, (char *) "direct.example", NULL, NULL, PT_NONE);

        /* Duplicate-default cleanup path (upstream_add upstream_cleanup):
         * the second default is rejected and must be fully reclaimed by the
         * cleanup goto, leaving the balance where the first add left it. */
        {
                struct upstream *list = NULL;
                long after_first;

                upstream_add ("http.example", 3128, NULL,
                              "alice", "secret", PT_HTTP, &list);
                after_first = live_allocs;

                /* second default HTTP upstream with auth -> hits cleanup */
                upstream_add ("http2.example", 3129, NULL,
                              "dave", "topsecret", PT_HTTP, &list);

                if (live_allocs != after_first) {
                        printf ("  [FAIL] %-44s %ld allocation(s) leaked\n",
                                "duplicate default cleanup",
                                live_allocs - after_first);
                        failures++;
                } else {
                        printf ("  [ ok ] %-44s no leak\n",
                                "duplicate default cleanup");
                }

                free_upstream_list (list);
                check_zero ("duplicate default: list teardown");
        }

        /* Reload simulation: build and free a mixed list many times; the
         * live-allocation balance must return to zero after every teardown,
         * never accumulating across iterations. */
        {
                const int iterations = 1000;
                int i;
                long peak = 0;

                for (i = 0; i < iterations; i++) {
                        struct upstream *list = build_mixed_list ();
                        if (live_allocs > peak)
                                peak = live_allocs;
                        free_upstream_list (list);
                        if (live_allocs != 0)
                                break;          /* leak: stop and report */
                }

                if (live_allocs != 0) {
                        printf ("  [FAIL] %-44s leaked after iteration %d "
                                "(balance=%ld)\n",
                                "reload loop (1000x mixed list)", i, live_allocs);
                        failures++;
                } else {
                        printf ("  [ ok ] %-44s balance 0 after %dx "
                                "(peak live=%ld/iter)\n",
                                "reload loop (1000x mixed list)",
                                iterations, peak);
                }
        }

        printf ("\n%s (%d failure%s)\n",
                failures ? "FAILED" : "PASSED",
                failures, failures == 1 ? "" : "s");
        return failures ? 1 : 0;
}

/* test_socks_creds.c - SOCKS5 credential validation regression tests
 *
 * Tests that upstream_add() properly validates SOCKS5 username and
 * password lengths per RFC 1929 (1 to 255 bytes each).
 *
 * Compile via: make check (from tests/ directory)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define UPSTREAM_SUPPORT
#include "upstream.h"

/* Stub for log_message (avoids linking against log.o and its deps) */
void log_message(int level, const char *fmt, ...)
{
    va_list ap;
    (void)level;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

static int tests_run = 0;
static int tests_failed = 0;

#define ASSERT_UBE(desc, expr, expected) do { \
    int _got = (int)(expr); \
    int _exp = (int)(expected); \
    tests_run++; \
    if (_got != _exp) { \
        fprintf(stderr, "FAIL [%s:%d]: %s\n" \
                "  got: %d, expected: %d\n", \
                __FILE__, __LINE__, (desc), _got, _exp); \
        tests_failed++; \
    } \
} while(0)

/* Allocate a string of exactly n printable ASCII characters. */
static char *make_string(size_t n)
{
    char *s;
    size_t i;
    s = malloc(n + 1);
    if (!s) {
        fprintf(stderr, "malloc failed\n");
        exit(2);
    }
    for (i = 0; i < n; i++)
        s[i] = 'A' + (i % 26);
    s[n] = '\0';
    return s;
}

/* ---- SOCKS5: valid credentials ---- */

static void test_socks5_min_creds(void)
{
    struct upstream *list = NULL;
    ASSERT_UBE("SOCKS5 min-length creds (1+1) should succeed",
               upstream_add("127.0.0.1", 1080, NULL,
                            "u", "p", PT_SOCKS5, &list),
               UBE_SUCCESS);
    free_upstream_list(list);
}

static void test_socks5_max_creds(void)
{
    struct upstream *list = NULL;
    char *u255 = make_string(255);
    char *p255 = make_string(255);
    ASSERT_UBE("SOCKS5 max-length creds (255+255) should succeed",
               upstream_add("127.0.0.1", 1080, NULL,
                            u255, p255, PT_SOCKS5, &list),
               UBE_SUCCESS);
    free(u255);
    free(p255);
    free_upstream_list(list);
}

static void test_socks5_typical_creds(void)
{
    struct upstream *list = NULL;
    ASSERT_UBE("SOCKS5 typical creds should succeed",
               upstream_add("127.0.0.1", 1080, NULL,
                            "alice", "secret123", PT_SOCKS5, &list),
               UBE_SUCCESS);
    free_upstream_list(list);
}

/* ---- SOCKS5: invalid credentials ---- */

static void test_socks5_empty_username(void)
{
    struct upstream *list = NULL;
    ASSERT_UBE("SOCKS5 empty username should fail",
               upstream_add("127.0.0.1", 1080, NULL,
                            "", "pass", PT_SOCKS5, &list),
               UBE_SOCKS_CREDLEN);
    free_upstream_list(list);
}

static void test_socks5_empty_password(void)
{
    struct upstream *list = NULL;
    ASSERT_UBE("SOCKS5 empty password should fail",
               upstream_add("127.0.0.1", 1080, NULL,
                            "user", "", PT_SOCKS5, &list),
               UBE_SOCKS_CREDLEN);
    free_upstream_list(list);
}

static void test_socks5_user_256(void)
{
    struct upstream *list = NULL;
    char *u256 = make_string(256);
    ASSERT_UBE("SOCKS5 256-byte username should fail",
               upstream_add("127.0.0.1", 1080, NULL,
                            u256, "pass", PT_SOCKS5, &list),
               UBE_SOCKS_CREDLEN);
    free(u256);
    free_upstream_list(list);
}

static void test_socks5_pass_256(void)
{
    struct upstream *list = NULL;
    char *p256 = make_string(256);
    ASSERT_UBE("SOCKS5 256-byte password should fail",
               upstream_add("127.0.0.1", 1080, NULL,
                            "user", p256, PT_SOCKS5, &list),
               UBE_SOCKS_CREDLEN);
    free(p256);
    free_upstream_list(list);
}

static void test_socks5_both_oversized(void)
{
    struct upstream *list = NULL;
    char *big = make_string(300);
    ASSERT_UBE("SOCKS5 300-byte both creds should fail",
               upstream_add("127.0.0.1", 1080, NULL,
                            big, big, PT_SOCKS5, &list),
               UBE_SOCKS_CREDLEN);
    free(big);
    free_upstream_list(list);
}

/* ---- SOCKS5: no credentials (no-auth mode) ---- */

static void test_socks5_no_creds(void)
{
    struct upstream *list = NULL;
    ASSERT_UBE("SOCKS5 with no credentials (no-auth) should succeed",
               upstream_add("127.0.0.1", 1080, NULL,
                            NULL, NULL, PT_SOCKS5, &list),
               UBE_SUCCESS);
    free_upstream_list(list);
}

/* ---- SOCKS5: NULL user with non-NULL pass ---- */

static void test_socks5_null_user_with_pass(void)
{
    struct upstream *list = NULL;
    ASSERT_UBE("SOCKS5 NULL user with non-NULL pass should succeed (no-auth)",
               upstream_add("127.0.0.1", 1080, NULL,
                            NULL, "orphan", PT_SOCKS5, &list),
               UBE_SUCCESS);
    free_upstream_list(list);
}

/* ---- SOCKS4: should not be affected by SOCKS5 validation ---- */

static void test_socks4_creds_not_validated(void)
{
    struct upstream *list = NULL;
    /* SOCKS4 doesn't use user/pass in current code (SOCKS4a with
       empty userid), so no credential length validation is needed. */
    ASSERT_UBE("SOCKS4 with empty creds should succeed (no validation)",
               upstream_add("127.0.0.1", 1080, NULL,
                            "", "", PT_SOCKS4, &list),
               UBE_SUCCESS);
    free_upstream_list(list);
}

/* ---- HTTP upstream: regression guard ---- */

static void test_http_unaffected(void)
{
    struct upstream *list = NULL;
    ASSERT_UBE("HTTP upstream with valid creds should succeed",
               upstream_add("127.0.0.1", 3128, NULL,
                            "user", "pass", PT_HTTP, &list),
               UBE_SUCCESS);
    free_upstream_list(list);
}

/* ---- Error string check ---- */

static void test_error_string(void)
{
    const char *msg;
    tests_run++;
    msg = upstream_build_error_string(UBE_SOCKS_CREDLEN);
    if (!msg || !msg[0]) {
        fprintf(stderr, "FAIL [%s:%d]: UBE_SOCKS_CREDLEN error string "
                "is empty or NULL\n", __FILE__, __LINE__);
        tests_failed++;
    }
}

int main(void)
{
    printf("Running SOCKS5 credential validation tests...\n");

    test_socks5_min_creds();
    test_socks5_max_creds();
    test_socks5_typical_creds();
    test_socks5_empty_username();
    test_socks5_empty_password();
    test_socks5_user_256();
    test_socks5_pass_256();
    test_socks5_both_oversized();
    test_socks5_no_creds();
    test_socks5_null_user_with_pass();
    test_socks4_creds_not_validated();
    test_http_unaffected();
    test_error_string();

    printf("%d tests run, %d failed\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}

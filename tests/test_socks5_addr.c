/*
 * Regression test for socks5_build_connect_request().
 *
 * Verifies that SOCKS5 CONNECT requests are correctly encoded for
 * IPv4 (ATYP=1), IPv6 (ATYP=4), and domain name (ATYP=3) targets
 * per RFC 1928.
 *
 * Compile standalone:
 *   cc -o test_socks5_addr -I../src test_socks5_addr.c ../src/socks5.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "socks5.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  TEST: %-50s ", #name); \
} while(0)

#define PASS() do { tests_passed++; printf("[PASS]\n"); } while(0)
#define FAIL(msg) do { printf("[FAIL] %s\n", msg); } while(0)

/* IPv4 address: 192.168.1.1:80 → ATYP=1 */
static void test_ipv4_basic(void)
{
    unsigned char buff[64];
    int len;

    TEST(ipv4_basic_192_168_1_1);
    len = socks5_build_connect_request(buff, sizeof(buff), "192.168.1.1", 80);
    if (len != 10) { FAIL("expected length 10"); return; }
    if (buff[0] != 5 || buff[1] != 1 || buff[2] != 0) { FAIL("header bytes"); return; }
    if (buff[3] != 1) { FAIL("ATYP should be 1 for IPv4"); return; }
    /* 192.168.1.1 = 0xC0A80101 */
    if (buff[4] != 192 || buff[5] != 168 || buff[6] != 1 || buff[7] != 1) {
        FAIL("IPv4 address bytes"); return;
    }
    /* port 80 = 0x0050 in network byte order */
    if (buff[8] != 0x00 || buff[9] != 0x50) { FAIL("port bytes"); return; }
    PASS();
}

/* IPv4 loopback: 127.0.0.1:443 */
static void test_ipv4_loopback(void)
{
    unsigned char buff[64];
    int len;

    TEST(ipv4_loopback_127_0_0_1);
    len = socks5_build_connect_request(buff, sizeof(buff), "127.0.0.1", 443);
    if (len != 10) { FAIL("expected length 10"); return; }
    if (buff[3] != 1) { FAIL("ATYP should be 1"); return; }
    if (buff[4] != 127 || buff[5] != 0 || buff[6] != 0 || buff[7] != 1) {
        FAIL("address bytes"); return;
    }
    /* port 443 = 0x01BB */
    if (buff[8] != 0x01 || buff[9] != 0xBB) { FAIL("port bytes"); return; }
    PASS();
}

/* IPv6 full address: 2001:db8::1:443 → ATYP=4 */
static void test_ipv6_full(void)
{
    unsigned char buff[64];
    struct in6_addr expected;
    int len;

    TEST(ipv6_full_2001_db8_1);
    inet_pton(AF_INET6, "2001:db8::1", &expected);
    len = socks5_build_connect_request(buff, sizeof(buff), "2001:db8::1", 443);
    if (len != 22) { FAIL("expected length 22"); return; }
    if (buff[0] != 5 || buff[1] != 1 || buff[2] != 0) { FAIL("header bytes"); return; }
    if (buff[3] != 4) { FAIL("ATYP should be 4 for IPv6"); return; }
    if (memcmp(&buff[4], &expected, 16) != 0) { FAIL("IPv6 address bytes"); return; }
    /* port 443 = 0x01BB */
    if (buff[20] != 0x01 || buff[21] != 0xBB) { FAIL("port bytes"); return; }
    PASS();
}

/* IPv6 loopback: ::1:8080 → ATYP=4 */
static void test_ipv6_loopback(void)
{
    unsigned char buff[64];
    struct in6_addr expected;
    int len;

    TEST(ipv6_loopback_colon_1);
    inet_pton(AF_INET6, "::1", &expected);
    len = socks5_build_connect_request(buff, sizeof(buff), "::1", 8080);
    if (len != 22) { FAIL("expected length 22"); return; }
    if (buff[3] != 4) { FAIL("ATYP should be 4"); return; }
    if (memcmp(&buff[4], &expected, 16) != 0) { FAIL("address mismatch"); return; }
    /* port 8080 = 0x1F90 */
    if (buff[20] != 0x1F || buff[21] != 0x90) { FAIL("port bytes"); return; }
    PASS();
}

/* IPv6 with all zeros except last byte: 2001:db8:85a3::8a2e:370:7334 */
static void test_ipv6_complex(void)
{
    unsigned char buff[64];
    struct in6_addr expected;
    int len;

    TEST(ipv6_complex_address);
    inet_pton(AF_INET6, "2001:db8:85a3::8a2e:370:7334", &expected);
    len = socks5_build_connect_request(buff, sizeof(buff),
                                       "2001:db8:85a3::8a2e:370:7334", 8443);
    if (len != 22) { FAIL("expected length 22"); return; }
    if (buff[3] != 4) { FAIL("ATYP should be 4"); return; }
    if (memcmp(&buff[4], &expected, 16) != 0) { FAIL("address mismatch"); return; }
    PASS();
}

/* Domain name: example.com:80 → ATYP=3 */
static void test_domain_name(void)
{
    unsigned char buff[64];
    int len;

    TEST(domain_example_com);
    len = socks5_build_connect_request(buff, sizeof(buff), "example.com", 80);
    if (len != 18) { FAIL("expected length 18 (7+11)"); return; }
    if (buff[0] != 5 || buff[1] != 1 || buff[2] != 0) { FAIL("header bytes"); return; }
    if (buff[3] != 3) { FAIL("ATYP should be 3 for domain"); return; }
    if (buff[4] != 11) { FAIL("domain length should be 11"); return; }
    if (memcmp(&buff[5], "example.com", 11) != 0) { FAIL("domain bytes"); return; }
    /* port 80 */
    if (buff[16] != 0x00 || buff[17] != 0x50) { FAIL("port bytes"); return; }
    PASS();
}

/* Single-char domain: a:80 */
static void test_domain_single_char(void)
{
    unsigned char buff[64];
    int len;

    TEST(domain_single_char);
    len = socks5_build_connect_request(buff, sizeof(buff), "a", 80);
    if (len != 8) { FAIL("expected length 8 (7+1)"); return; }
    if (buff[3] != 3) { FAIL("ATYP should be 3"); return; }
    if (buff[4] != 1) { FAIL("domain length should be 1"); return; }
    if (buff[5] != 'a') { FAIL("domain byte"); return; }
    PASS();
}

/* 255-char domain (maximum allowed) */
static void test_domain_max_length(void)
{
    unsigned char buff[512];
    char host[256];
    int len;

    TEST(domain_max_255_chars);
    memset(host, 'a', 255);
    host[255] = '\0';
    len = socks5_build_connect_request(buff, sizeof(buff), host, 80);
    if (len != 262) { FAIL("expected length 262 (7+255)"); return; }
    if (buff[3] != 3) { FAIL("ATYP should be 3"); return; }
    if (buff[4] != 255) { FAIL("domain length should be 255"); return; }
    PASS();
}

/* Domain longer than 255 chars → rejected */
static void test_long_domain_rejected(void)
{
    unsigned char buff[512];
    char long_host[300];
    int len;

    TEST(long_domain_rejected);
    memset(long_host, 'a', 256);
    long_host[256] = '\0';
    len = socks5_build_connect_request(buff, sizeof(buff), long_host, 80);
    if (len != -1) { FAIL("should reject domain > 255 chars"); return; }
    PASS();
}

/* Buffer too small for IPv4 → rejected */
static void test_small_buffer_ipv4(void)
{
    unsigned char buff[5];
    int len;

    TEST(small_buffer_ipv4_rejected);
    len = socks5_build_connect_request(buff, sizeof(buff), "1.2.3.4", 80);
    if (len != -1) { FAIL("should reject undersized buffer for IPv4"); return; }
    PASS();
}

/* Buffer too small for IPv6 → rejected */
static void test_small_buffer_ipv6(void)
{
    unsigned char buff[10];
    int len;

    TEST(small_buffer_ipv6_rejected);
    len = socks5_build_connect_request(buff, sizeof(buff), "::1", 80);
    if (len != -1) { FAIL("should reject undersized buffer for IPv6"); return; }
    PASS();
}

/* Buffer too small for domain → rejected */
static void test_small_buffer_domain(void)
{
    unsigned char buff[6];
    int len;

    TEST(small_buffer_domain_rejected);
    len = socks5_build_connect_request(buff, sizeof(buff), "example.com", 80);
    if (len != -1) { FAIL("should reject undersized buffer for domain"); return; }
    PASS();
}

/* High port (65535) encoding */
static void test_high_port(void)
{
    unsigned char buff[64];
    int len;

    TEST(high_port_65535);
    len = socks5_build_connect_request(buff, sizeof(buff), "10.0.0.1", 65535);
    if (len != 10) { FAIL("unexpected length"); return; }
    if (buff[8] != 0xFF || buff[9] != 0xFF) { FAIL("port 65535 encoding"); return; }
    PASS();
}

/* Port 1 encoding */
static void test_low_port(void)
{
    unsigned char buff[64];
    int len;

    TEST(low_port_1);
    len = socks5_build_connect_request(buff, sizeof(buff), "10.0.0.1", 1);
    if (len != 10) { FAIL("unexpected length"); return; }
    if (buff[8] != 0x00 || buff[9] != 0x01) { FAIL("port 1 encoding"); return; }
    PASS();
}

int main(void)
{
    printf("Running SOCKS5 address encoding tests...\n\n");

    /* IPv4 tests */
    test_ipv4_basic();
    test_ipv4_loopback();

    /* IPv6 tests */
    test_ipv6_full();
    test_ipv6_loopback();
    test_ipv6_complex();

    /* Domain name tests */
    test_domain_name();
    test_domain_single_char();
    test_domain_max_length();
    test_long_domain_rejected();

    /* Buffer size tests */
    test_small_buffer_ipv4();
    test_small_buffer_ipv6();
    test_small_buffer_domain();

    /* Port encoding tests */
    test_high_port();
    test_low_port();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}

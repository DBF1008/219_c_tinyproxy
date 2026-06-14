/*
 * Regression test for establish_http_connection() in src/reqs.c
 *
 * Verifies that the HTTP request headers sent to an upstream proxy
 * correctly combine:
 *   - IPv6 bracket wrapping for the Host header
 *   - Proxy-Authorization header injection for authenticated upstreams
 *
 * Previously, a three-way if/else-if/else branch made IPv6 formatting
 * and Proxy-Authorization mutually exclusive, causing the auth header
 * to be silently dropped for IPv6 targets (resulting in 407/502 errors).
 *
 * This test replicates the formatting logic from establish_http_connection()
 * and captures the output via a pipe to validate all target-type/auth
 * combinations.
 *
 * Build:  cc -o test_establish_http_connection tests/scripts/test_establish_http_connection.c
 * Run:    ./test_establish_http_connection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>
#include <assert.h>

/* ---------- Minimal replicas of tinyproxy types ---------- */

#define HTTP_PORT 80
#define HTTP_PORT_SSL 443

typedef enum { PT_NONE = 0, PT_HTTP, PT_SOCKS4, PT_SOCKS5 } proxy_type;

struct upstream {
    struct upstream *next;
    char *host;
    union {
        char *user;
        char *authstr;
    } ua;
    char *pass;
    int port;
    proxy_type type;
};

struct request_s {
    char *method;
    char *protocol;
    char *host;
    uint16_t port;
    char *path;
};

struct conn_s {
    int client_fd;
    int server_fd;
    struct {
        unsigned int major;
        unsigned int minor;
    } protocol;
    struct upstream *upstream_proxy;
};

/* ---------- Replica of write_message (writes to fd) ---------- */

static int write_message(int fd, const char *fmt, ...)
{
    char buf[8192];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= sizeof(buf))
        return -1;

    if (write(fd, buf, n) != n)
        return -1;

    return 0;
}

/*
 * ---------- Replica of establish_http_connection (FIXED version) ----------
 *
 * This MUST match the logic in src/reqs.c::establish_http_connection().
 * If the production code changes, update this replica accordingly.
 */

static int
establish_http_connection(struct conn_s *connptr, struct request_s *request)
{
    char portbuff[7];
    char dst[sizeof(struct in6_addr)];
    char hostbuff[NI_MAXHOST + 8];
    int ret;

    /* Build a port string if it's not a standard port */
    if (request->port != HTTP_PORT && request->port != HTTP_PORT_SSL)
        snprintf(portbuff, 7, ":%u", request->port);
    else
        portbuff[0] = '\0';

    /* Format the Host header value: wrap IPv6 literals in [] */
    if (inet_pton(AF_INET6, request->host, dst) > 0) {
        snprintf(hostbuff, sizeof(hostbuff), "[%s]%s",
                 request->host, portbuff);
    } else {
        snprintf(hostbuff, sizeof(hostbuff), "%s%s",
                 request->host, portbuff);
    }

    /* Send the request line and Host header */
    ret = write_message(connptr->server_fd,
                        "%s %s HTTP/1.%u\r\n"
                        "Host: %s\r\n",
                        request->method, request->path,
                        connptr->protocol.major != 1 ? 0 :
                                 connptr->protocol.minor,
                        hostbuff);
    if (ret < 0)
        return ret;

    /* Inject Proxy-Authorization for authenticated HTTP upstream
     * proxies, regardless of whether the target is IPv4, IPv6,
     * or a domain name. */
    if (connptr->upstream_proxy &&
        connptr->upstream_proxy->type == PT_HTTP &&
        connptr->upstream_proxy->ua.authstr) {
        ret = write_message(connptr->server_fd,
                            "Proxy-Authorization: Basic %s\r\n",
                            connptr->upstream_proxy->ua.authstr);
        if (ret < 0)
            return ret;
    }

    /* Finish the header block */
    return write_message(connptr->server_fd,
                         "Connection: close\r\n");
}

/* ---------- Test harness ---------- */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/*
 * Capture the output of establish_http_connection() via a pipe
 * and return it as a malloc'd string.
 */
static char *capture_output(struct conn_s *conn, struct request_s *req)
{
    int pipefd[2];
    char buf[8192];
    ssize_t n;

    if (pipe(pipefd) < 0) {
        perror("pipe");
        return NULL;
    }

    conn->server_fd = pipefd[1];

    int ret = establish_http_connection(conn, req);
    close(pipefd[1]);

    if (ret < 0) {
        close(pipefd[0]);
        return NULL;
    }

    n = read(pipefd[0], buf, sizeof(buf) - 1);
    close(pipefd[0]);

    if (n < 0) {
        perror("read");
        return NULL;
    }

    buf[n] = '\0';
    return strdup(buf);
}

static void check_contains(const char *test_name, const char *output,
                           const char *expected)
{
    tests_run++;
    if (strstr(output, expected) != NULL) {
        tests_passed++;
        printf("  PASS: %s\n", test_name);
    } else {
        tests_failed++;
        printf("  FAIL: %s\n", test_name);
        printf("    expected to find: \"%s\"\n", expected);
        printf("    in output:\n%s\n", output);
    }
}

static void check_not_contains(const char *test_name, const char *output,
                               const char *unexpected)
{
    tests_run++;
    if (strstr(output, unexpected) == NULL) {
        tests_passed++;
        printf("  PASS: %s\n", test_name);
    } else {
        tests_failed++;
        printf("  FAIL: %s\n", test_name);
        printf("    did NOT expect to find: \"%s\"\n", unexpected);
        printf("    in output:\n%s\n", output);
    }
}

/* ---------- Test helpers ---------- */

static struct upstream *make_http_upstream(const char *authstr)
{
    struct upstream *up = calloc(1, sizeof(*up));
    up->type = PT_HTTP;
    up->ua.authstr = strdup(authstr);
    return up;
}

static void free_upstream(struct upstream *up)
{
    if (up) {
        free(up->ua.authstr);
        free(up);
    }
}

static void make_request(struct request_s *req, const char *method,
                         const char *host, uint16_t port, const char *path)
{
    memset(req, 0, sizeof(*req));
    req->method = strdup(method);
    req->host = strdup(host);
    req->port = port;
    req->path = strdup(path);
}

static void free_request(struct request_s *req)
{
    free(req->method);
    free(req->host);
    free(req->path);
}

static void make_conn(struct conn_s *conn, struct upstream *up)
{
    memset(conn, 0, sizeof(*conn));
    conn->protocol.major = 1;
    conn->protocol.minor = 1;
    conn->upstream_proxy = up;
}

/* ---------- Test cases ---------- */

/*
 * Test 1: IPv4 target, no upstream auth
 * Expected: Host without brackets, no Proxy-Authorization
 */
static void test_ipv4_no_auth(void)
{
    struct conn_s conn;
    struct request_s req;
    char *output;

    printf("\n[Test 1] IPv4 target, no upstream auth\n");
    make_conn(&conn, NULL);
    make_request(&req, "GET", "192.168.1.1", 80, "/index.html");

    output = capture_output(&conn, &req);
    assert(output != NULL);

    check_contains("request line", output, "GET /index.html HTTP/1.1\r\n");
    check_contains("Host header (no brackets)", output,
                   "Host: 192.168.1.1\r\n");
    check_not_contains("no Proxy-Authorization", output,
                       "Proxy-Authorization");
    check_contains("Connection close", output, "Connection: close\r\n");

    free(output);
    free_request(&req);
}

/*
 * Test 2: IPv4 target, with upstream auth
 * Expected: Host without brackets, Proxy-Authorization present
 */
static void test_ipv4_with_auth(void)
{
    struct conn_s conn;
    struct request_s req;
    struct upstream *up;
    char *output;

    printf("\n[Test 2] IPv4 target, with upstream auth\n");
    up = make_http_upstream("dXNlcjpwYXNz"); /* base64("user:pass") */
    make_conn(&conn, up);
    make_request(&req, "GET", "10.0.0.1", 8080, "/page");

    output = capture_output(&conn, &req);
    assert(output != NULL);

    check_contains("request line", output, "GET /page HTTP/1.1\r\n");
    check_contains("Host with port", output, "Host: 10.0.0.1:8080\r\n");
    check_contains("Proxy-Authorization present", output,
                   "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n");
    check_contains("Connection close", output, "Connection: close\r\n");

    free(output);
    free_request(&req);
    free_upstream(up);
}

/*
 * Test 3: IPv6 target, no upstream auth
 * Expected: Host WITH brackets, no Proxy-Authorization
 */
static void test_ipv6_no_auth(void)
{
    struct conn_s conn;
    struct request_s req;
    char *output;

    printf("\n[Test 3] IPv6 target (::1), no upstream auth\n");
    make_conn(&conn, NULL);
    make_request(&req, "GET", "::1", 80, "/test");

    output = capture_output(&conn, &req);
    assert(output != NULL);

    check_contains("request line", output, "GET /test HTTP/1.1\r\n");
    check_contains("Host header with brackets", output,
                   "Host: [::1]\r\n");
    check_not_contains("no Proxy-Authorization", output,
                       "Proxy-Authorization");
    check_contains("Connection close", output, "Connection: close\r\n");

    free(output);
    free_request(&req);
}

/*
 * Test 4: IPv6 target, WITH upstream auth  (THE BUG FIX)
 * Expected: Host WITH brackets AND Proxy-Authorization present
 */
static void test_ipv6_with_auth(void)
{
    struct conn_s conn;
    struct request_s req;
    struct upstream *up;
    char *output;

    printf("\n[Test 4] IPv6 target (::1), WITH upstream auth *** BUG FIX ***\n");
    up = make_http_upstream("dXNlcjpwYXNz"); /* base64("user:pass") */
    make_conn(&conn, up);
    make_request(&req, "GET", "::1", 80, "/test");

    output = capture_output(&conn, &req);
    assert(output != NULL);

    check_contains("request line", output, "GET /test HTTP/1.1\r\n");
    check_contains("Host header with brackets", output,
                   "Host: [::1]\r\n");
    check_contains("Proxy-Authorization present *** BUG FIX ***", output,
                   "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n");
    check_contains("Connection close", output, "Connection: close\r\n");

    free(output);
    free_request(&req);
    free_upstream(up);
}

/*
 * Test 5: Full IPv6 address with non-standard port and upstream auth
 * Expected: [2001:db8::1]:8443 with Proxy-Authorization
 */
static void test_ipv6_full_with_port_and_auth(void)
{
    struct conn_s conn;
    struct request_s req;
    struct upstream *up;
    char *output;

    printf("\n[Test 5] Full IPv6 [2001:db8::1]:8443 with upstream auth\n");
    up = make_http_upstream("YWRtaW46c2VjcmV0"); /* base64("admin:secret") */
    make_conn(&conn, up);
    make_request(&req, "GET", "2001:db8::1", 8443, "/api/data");

    output = capture_output(&conn, &req);
    assert(output != NULL);

    check_contains("request line", output, "GET /api/data HTTP/1.1\r\n");
    check_contains("Host with brackets and port", output,
                   "Host: [2001:db8::1]:8443\r\n");
    check_contains("Proxy-Authorization present", output,
                   "Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n");
    check_contains("Connection close", output, "Connection: close\r\n");

    free(output);
    free_request(&req);
    free_upstream(up);
}

/*
 * Test 6: Domain name target, with upstream auth
 * Expected: Host without brackets, Proxy-Authorization present
 */
static void test_domain_with_auth(void)
{
    struct conn_s conn;
    struct request_s req;
    struct upstream *up;
    char *output;

    printf("\n[Test 6] Domain target, with upstream auth\n");
    up = make_http_upstream("dXNlcjpwYXNz");
    make_conn(&conn, up);
    make_request(&req, "GET", "www.example.com", 80, "/");

    output = capture_output(&conn, &req);
    assert(output != NULL);

    check_contains("request line", output, "GET / HTTP/1.1\r\n");
    check_contains("Host without brackets", output,
                   "Host: www.example.com\r\n");
    check_contains("Proxy-Authorization present", output,
                   "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n");
    check_contains("Connection close", output, "Connection: close\r\n");

    free(output);
    free_request(&req);
    free_upstream(up);
}

/*
 * Test 7: Domain name target, no upstream auth
 * Expected: Host without brackets, no Proxy-Authorization
 */
static void test_domain_no_auth(void)
{
    struct conn_s conn;
    struct request_s req;
    char *output;

    printf("\n[Test 7] Domain target, no upstream auth\n");
    make_conn(&conn, NULL);
    make_request(&req, "GET", "www.example.com", 443, "/secure");

    output = capture_output(&conn, &req);
    assert(output != NULL);

    check_contains("request line", output, "GET /secure HTTP/1.1\r\n");
    check_contains("Host without brackets, no port (443 is standard)", output,
                   "Host: www.example.com\r\n");
    check_not_contains("no Proxy-Authorization", output,
                       "Proxy-Authorization");
    check_contains("Connection close", output, "Connection: close\r\n");

    free(output);
    free_request(&req);
}

/*
 * Test 8: IPv6 loopback with non-standard port, no auth
 * Expected: [::1]:9090, no Proxy-Authorization
 */
static void test_ipv6_with_port_no_auth(void)
{
    struct conn_s conn;
    struct request_s req;
    char *output;

    printf("\n[Test 8] IPv6 [::1]:9090, no auth\n");
    make_conn(&conn, NULL);
    make_request(&req, "GET", "::1", 9090, "/status");

    output = capture_output(&conn, &req);
    assert(output != NULL);

    check_contains("request line", output, "GET /status HTTP/1.1\r\n");
    check_contains("Host with brackets and port", output,
                   "Host: [::1]:9090\r\n");
    check_not_contains("no Proxy-Authorization", output,
                       "Proxy-Authorization");
    check_contains("Connection close", output, "Connection: close\r\n");

    free(output);
    free_request(&req);
}

/*
 * Test 9: SOCKS5 upstream (non-HTTP) should NOT inject Proxy-Authorization
 * even with IPv6 target.
 */
static void test_ipv6_socks_upstream(void)
{
    struct conn_s conn;
    struct request_s req;
    struct upstream *up;
    char *output;

    printf("\n[Test 9] IPv6 target, SOCKS5 upstream (no Proxy-Auth)\n");
    up = calloc(1, sizeof(*up));
    up->type = PT_SOCKS5;
    up->ua.user = strdup("socksuser");
    up->pass = strdup("sockspass");
    make_conn(&conn, up);
    make_request(&req, "GET", "fe80::1", 80, "/");

    output = capture_output(&conn, &req);
    assert(output != NULL);

    check_contains("Host with brackets", output, "Host: [fe80::1]\r\n");
    check_not_contains("no Proxy-Authorization for SOCKS", output,
                       "Proxy-Authorization");
    check_contains("Connection close", output, "Connection: close\r\n");

    free(output);
    free_request(&req);
    free(up->ua.user);
    free(up->pass);
    free(up);
}

/*
 * Test 10: HTTP upstream with NULL authstr (no credentials configured)
 * Expected: no Proxy-Authorization header even with IPv6 target
 */
static void test_ipv6_http_upstream_no_credentials(void)
{
    struct conn_s conn;
    struct request_s req;
    struct upstream *up;
    char *output;

    printf("\n[Test 10] IPv6 target, HTTP upstream but no credentials\n");
    up = calloc(1, sizeof(*up));
    up->type = PT_HTTP;
    up->ua.authstr = NULL; /* no credentials */
    make_conn(&conn, up);
    make_request(&req, "GET", "2001:db8::dead:beef", 80, "/");

    output = capture_output(&conn, &req);
    assert(output != NULL);

    check_contains("Host with brackets", output,
                   "Host: [2001:db8::dead:beef]\r\n");
    check_not_contains("no Proxy-Authorization without credentials", output,
                       "Proxy-Authorization");
    check_contains("Connection close", output, "Connection: close\r\n");

    free(output);
    free_request(&req);
    free(up);
}

/* ---------- Main ---------- */

int main(void)
{
    printf("=== establish_http_connection() regression tests ===\n");
    printf("Testing IPv6 bracket + Proxy-Authorization coexistence\n");

    test_ipv4_no_auth();
    test_ipv4_with_auth();
    test_ipv6_no_auth();
    test_ipv6_with_auth();                /* THE BUG FIX */
    test_ipv6_full_with_port_and_auth();  /* THE BUG FIX + port */
    test_domain_with_auth();
    test_domain_no_auth();
    test_ipv6_with_port_no_auth();
    test_ipv6_socks_upstream();
    test_ipv6_http_upstream_no_credentials();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}

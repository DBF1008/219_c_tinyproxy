/*
 * test_alloc.c -- Shared allocation-tracking implementation.
 *
 * Compiled WITHOUT -include test_alloc.h so that the real libc
 * malloc/free/strdup are used inside these wrappers.  Linked with
 * test TUs that DO have the -include redirection, sharing the
 * global g_alloc_count counter via external linkage.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Shared live-allocation counter (external linkage).
 * Incremented on every tracked allocation, decremented on every free.
 * A value of 0 after a test means all memory was released. */
long g_alloc_count = 0;

void *test_malloc(size_t size)
{
    void *p = malloc(size);
    if (p) g_alloc_count++;
    return p;
}

void *test_calloc(size_t nmemb, size_t size)
{
    void *p = calloc(nmemb, size);
    if (p) g_alloc_count++;
    return p;
}

void *test_realloc(void *ptr, size_t size)
{
    void *p;
    if (!ptr) return test_malloc(size);
    if (size == 0) {
        if (ptr) { g_alloc_count--; free(ptr); }
        return NULL;
    }
    p = realloc(ptr, size);
    return p;
}

void test_free(void *p)
{
    if (p) {
        g_alloc_count--;
        free(p);
    }
}

char *test_strdup(const char *s)
{
    size_t len;
    char *p;
    if (!s) return NULL;
    len = strlen(s) + 1;
    p = (char *)test_malloc(len);
    if (!p) return NULL;
    memcpy(p, s, len);
    return p;
}

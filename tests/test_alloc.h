/*
 * test_alloc.h -- Allocation-tracking macro redirections.
 *
 * Force-included via: cc -include tests/test_alloc.h
 *
 * Redirects every malloc/calloc/realloc/free/strdup call in the
 * compiled translation unit to tracking wrappers defined in
 * test_alloc.c.  All TUs share one g_alloc_count via external linkage.
 *
 * Compile test_alloc.c separately WITHOUT this header (it uses the
 * real libc malloc/free internally), then link it with the test.
 *
 * After the code under test runs, g_alloc_count == 0 means no leaks.
 *
 * This file MUST be included BEFORE any project headers.
 */
#ifndef TEST_ALLOC_H
#define TEST_ALLOC_H

#include <stddef.h>

/* Shared live-allocation counter -- defined in test_alloc.c */
extern long g_alloc_count;

/* Tracking wrapper declarations */
void *test_malloc(size_t size);
void *test_calloc(size_t nmemb, size_t size);
void *test_realloc(void *ptr, size_t size);
void  test_free(void *p);
char *test_strdup(const char *s);

/* Redirect standard allocation functions to tracking wrappers */
#define malloc  test_malloc
#define calloc  test_calloc
#define realloc test_realloc
#define free    test_free
#define strdup  test_strdup

#endif /* TEST_ALLOC_H */

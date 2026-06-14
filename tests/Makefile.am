SUBDIRS = scripts

AM_CFLAGS = -DNDEBUG -I$(top_srcdir)/src

check_PROGRAMS = test_socks_creds
test_socks_creds_SOURCES = test_socks_creds.c
test_socks_creds_LDADD = $(top_builddir)/src/upstream.o
test_socks_creds_CFLAGS = $(AM_CFLAGS)

TESTS = test_socks_creds

SUBDIRS = scripts

# Self-contained C regression test for the upstream auth-string memory leak.
# It compiles ../src/upstream.c into a single translation unit with a counting
# allocator, so it needs no other objects and no running daemon. Run via
# `make check`.
check_PROGRAMS = upstream_leak_test
upstream_leak_test_SOURCES = upstream_leak_test.c
upstream_leak_test_CPPFLAGS = -I$(top_srcdir)/src -DUPSTREAM_SUPPORT
TESTS = upstream_leak_test

SUBDIRS = scripts

check_PROGRAMS = test_socks5_addr

test_socks5_addr_SOURCES = test_socks5_addr.c \
	$(top_srcdir)/src/socks5.c \
	$(top_srcdir)/src/socks5.h
test_socks5_addr_CPPFLAGS = -I$(top_srcdir)/src

TESTS = test_socks5_addr

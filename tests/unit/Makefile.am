# tinyproxy - A fast light-weight HTTP proxy
# Copyright (C) 2026 The Tinyproxy Authors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# Self-contained unit tests.  build_http_request_head() lives in its own
# dependency-free translation unit, so the test links it directly and needs
# none of the rest of tinyproxy (and no generated config.h).

check_PROGRAMS = test_http_request_line

test_http_request_line_SOURCES = \
	test_http_request_line.c \
	$(top_srcdir)/src/http-request-line.c \
	$(top_srcdir)/src/http-request-line.h

test_http_request_line_CPPFLAGS = -I$(top_srcdir)/src

TESTS = $(check_PROGRAMS)

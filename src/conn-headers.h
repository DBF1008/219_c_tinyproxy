/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1998 Steven Young <sdyoung@miranda.org>
 * Copyright (C) 1999 Robert James Kaes <rjkaes@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Cleanup of the hop-by-hop headers enumerated by the "Connection" and
 * "Proxy-Connection" headers.  This lives in its own translation unit so the
 * logic can be unit tested in isolation (see tests/unit/test_conn_headers.c);
 * it depends only on the pseudomap container, not on the rest of the proxy.
 */

#ifndef _TINYPROXY_CONN_HEADERS_H_
#define _TINYPROXY_CONN_HEADERS_H_

#include "pseudomap.h"

/*
 * Remove the headers that were listed as tokens in the "Connection" and
 * "Proxy-Connection" headers, and then remove those two headers themselves.
 * Both headers are processed independently: a message carrying only one of
 * them (commonly just "Proxy-Connection") is still fully cleaned up.
 *
 * Always returns 0.
 */
int remove_connection_headers (pseudomap *hashofheaders);

#endif

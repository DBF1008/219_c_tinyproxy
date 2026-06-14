/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 2026 The Tinyproxy Authors
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

/*
 * Formatting of the leading bytes of an HTTP request that tinyproxy forwards
 * to an origin server or to an HTTP upstream proxy.  This logic is kept in its
 * own translation unit, free of any tinyproxy-internal dependencies, so that
 * the (otherwise subtle) interaction between IPv6 "Host" formatting and the
 * upstream "Proxy-Authorization" header can be exercised by unit tests.
 */

#ifndef _TINYPROXY_HTTP_REQUEST_LINE_H_
#define _TINYPROXY_HTTP_REQUEST_LINE_H_

/*
 * Build the leading bytes of a forwarded HTTP request: the request line, the
 * "Host" header, "Connection: close" and -- when an upstream proxy credential
 * is supplied -- a "Proxy-Authorization" header.  No terminating blank line is
 * emitted; the remaining client headers are appended by the caller.
 *
 * The two concerns below are deliberately orthogonal so that they always
 * compose, regardless of target type:
 *
 *   - Host formatting: when @host is an IPv6 address literal (as recognised by
 *     inet_pton()), it is wrapped in "[" "]" in the Host header.  @port_suffix
 *     is appended verbatim after the (bracketed) host, e.g. ":8080" or "".
 *
 *   - Upstream authentication: when @authstr is non-NULL it is emitted as
 *     "Proxy-Authorization: Basic <authstr>".  Pass NULL to omit it.
 *
 * @proto_minor is the already-resolved HTTP minor version to advertise.
 *
 * Returns a newly malloc()'d, NUL-terminated string that the caller must
 * free(), or NULL on allocation failure.
 */
char *build_http_request_head (unsigned proto_minor,
                               const char *method, const char *path,
                               const char *host, const char *port_suffix,
                               const char *authstr);

#endif /* _TINYPROXY_HTTP_REQUEST_LINE_H_ */

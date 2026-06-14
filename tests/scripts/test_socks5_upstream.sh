#!/bin/sh

# Regression tests for tinyproxy's SOCKS5 upstream username/password support.
#
# These cover the boundary-credential scenarios for RFC 1929, where the
# username and password are each carried in a field prefixed by a single
# length octet and therefore may not exceed 255 bytes:
#
#   1. config-stage validation  - a 255-byte credential is accepted while a
#                                 256-byte one is rejected (instead of being
#                                 silently truncated onto the wire);
#   2. request encoding         - a maximum-length (255-byte) credential is
#                                 transmitted to the upstream in full and with
#                                 the correct length octet;
#   3. method negotiation       - the client aborts cleanly if the upstream
#                                 selects an authentication method that the
#                                 client never offered.
#
# The test is self-contained: it drives the freshly built tinyproxy binary
# against a small SOCKS5 mock (socks5_upstream_server.pl) over 127.0.0.1.
#
# Copyright (C) 2026 Tinyproxy contributors
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.

set -u

SCRIPTS_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASEDIR=$(CDPATH= cd -- "$SCRIPTS_DIR/../.." && pwd)
TINYPROXY_BIN="$BASEDIR/src/tinyproxy"
MOCK="$SCRIPTS_DIR/socks5_upstream_server.pl"
TEMPLATE="$BASEDIR/data/templates/default.html"

if [ ! -x "$TINYPROXY_BIN" ]; then
	echo "SKIP: tinyproxy binary not found at $TINYPROXY_BIN (build it first)"
	exit 77
fi

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/tp-socks5.XXXXXX") || exit 1
TP_PID=""
MOCK_PID=""

cleanup() {
	[ -n "$TP_PID" ] && kill "$TP_PID" 2>/dev/null
	[ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
	rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

free_port() {
	perl -MIO::Socket::INET -e '
		my $s = IO::Socket::INET->new(Proto => "tcp",
		                              LocalAddr => "127.0.0.1",
		                              LocalPort => 0, Listen => 1) or exit 1;
		print $s->sockport;'
}

wait_for_port() {
	# $1 = port, $2 = max tenths of a second.  Opens (and drops) a probe
	# connection, so only use this for tinyproxy, never for the single-shot
	# mock whose one accept() must be reserved for tinyproxy.
	_p="$1"
	_max="${2:-50}"
	_i=0
	while [ "$_i" -lt "$_max" ]; do
		if perl -MIO::Socket::INET -e '
			exit(IO::Socket::INET->new(PeerAddr => "127.0.0.1",
			                           PeerPort => $ARGV[0],
			                           Proto => "tcp",
			                           Timeout => 1) ? 0 : 1)' "$_p" 2>/dev/null
		then
			return 0
		fi
		_i=$((_i + 1))
		sleep 0.1
	done
	return 1
}

wait_for_file() {
	# $1 = file, $2 = max tenths of a second
	_f="$1"
	_max="${2:-50}"
	_i=0
	while [ "$_i" -lt "$_max" ]; do
		[ -s "$_f" ] && return 0
		_i=$((_i + 1))
		sleep 0.1
	done
	return 1
}

start_tinyproxy() {
	# $1 = config file
	"$TINYPROXY_BIN" -d -c "$1" > "$WORKDIR/tp.out" 2>&1 &
	TP_PID=$!
}

stop_tinyproxy() {
	if [ -n "$TP_PID" ]; then
		kill "$TP_PID" 2>/dev/null
		wait "$TP_PID" 2>/dev/null
		TP_PID=""
	fi
}

write_common_conf() {
	# $1 = config file, $2 = port, rest appended by caller
	cat > "$1" <<EOF
Port $2
Listen 127.0.0.1
Timeout 60
Allow 127.0.0.1
PidFile "$WORKDIR/tinyproxy.pid"
LogFile "$WORKDIR/tinyproxy.log"
LogLevel Info
DefaultErrorFile "$TEMPLATE"
EOF
}

USER255=$(perl -e 'print "u" x 255')
PASS255=$(perl -e 'print "p" x 255')
USER256=$(perl -e 'print "u" x 256')

# ---------------------------------------------------------------------------
# Test 1: config-stage credential length validation
# ---------------------------------------------------------------------------
test_config_length() {
	echo "Test 1: config-stage credential length validation"
	cfg="$WORKDIR/conf-len.conf"
	log="$WORKDIR/tinyproxy.log"
	port=$(free_port)
	: > "$log"
	write_common_conf "$cfg" "$port"
	cat >> "$cfg" <<EOF
Upstream socks5 $USER255:$PASS255@127.0.0.1:9999 ".ok.test"
Upstream socks5 $USER256:pp@127.0.0.1:9999 ".bad.test"
EOF

	start_tinyproxy "$cfg"
	if ! wait_for_port "$port" 50; then
		bad "config-length: tinyproxy did not start"
		cat "$WORKDIR/tp.out"
		stop_tinyproxy
		return
	fi
	stop_tinyproxy

	logs="$log $WORKDIR/tp.out"

	if grep -q "User / pass in upstream config too long" $logs; then
		ok "256-byte credential rejected at config time"
	else
		bad "256-byte credential was NOT rejected"
		cat $logs
	fi

	if grep -q "Added upstream socks5 127.0.0.1:9999 for .ok.test" $logs; then
		ok "255-byte credential accepted at config time"
	else
		bad "255-byte credential was NOT accepted"
		cat $logs
	fi

	# The rejected (256-byte) upstream must not have been added to the list.
	if grep -q "Added upstream socks5 127.0.0.1:9999 for .bad.test" $logs; then
		bad "256-byte credential was added despite being too long"
	else
		ok "256-byte credential was not added to the upstream list"
	fi
}

# ---------------------------------------------------------------------------
# Test 2: a maximum-length (255-byte) credential is encoded and sent in full
# ---------------------------------------------------------------------------
test_auth_encoding() {
	echo "Test 2: 255-byte credential is sent to the upstream in full"
	cfg="$WORKDIR/conf-auth.conf"
	res="$WORKDIR/auth.result"
	rdy="$WORKDIR/auth.ready"
	mlog="$WORKDIR/auth.mock.log"
	tpport=$(free_port)
	mport=$(free_port)
	rm -f "$res" "$rdy"

	perl "$MOCK" --port "$mport" --mode auth \
		--expect-user "$USER255" --expect-pass "$PASS255" \
		--result-file "$res" --ready-file "$rdy" --timeout 15 > "$mlog" 2>&1 &
	MOCK_PID=$!
	if ! wait_for_file "$rdy" 50; then
		bad "auth-encoding: mock SOCKS5 server did not start"
		cat "$mlog"
		MOCK_PID=""
		return
	fi

	write_common_conf "$cfg" "$tpport"
	echo "Upstream socks5 $USER255:$PASS255@127.0.0.1:$mport" >> "$cfg"

	start_tinyproxy "$cfg"
	if ! wait_for_port "$tpport" 50; then
		bad "auth-encoding: tinyproxy did not start"
		cat "$WORKDIR/tp.out"
		stop_tinyproxy
		kill "$MOCK_PID" 2>/dev/null
		MOCK_PID=""
		return
	fi

	code=$(curl -s -o "$WORKDIR/auth.body" -w "%{http_code}" --max-time 15 \
	       -x "http://127.0.0.1:$tpport" "http://socks.test/" 2>>"$WORKDIR/curl.log")
	curl_rc=$?
	stop_tinyproxy
	wait "$MOCK_PID" 2>/dev/null
	MOCK_PID=""
	result=$(cat "$res" 2>/dev/null)

	case "$result" in
		OK*) ok "upstream received the full 255-byte credential ($result)" ;;
		*)   bad "mock did not confirm the credential (result='$result')"
		     cat "$mlog" ;;
	esac

	if [ "$curl_rc" = "0" ] && [ "$code" = "200" ]; then
		ok "request through the SOCKS5 upstream succeeded (HTTP $code)"
	else
		bad "request did not succeed (curl_rc=$curl_rc http_code=$code)"
	fi
}

# ---------------------------------------------------------------------------
# Test 3: the client aborts if the upstream selects an unoffered auth method
# ---------------------------------------------------------------------------
test_unoffered_method() {
	echo "Test 3: client rejects an auth method it never offered"
	cfg="$WORKDIR/conf-neg.conf"
	res="$WORKDIR/neg.result"
	rdy="$WORKDIR/neg.ready"
	mlog="$WORKDIR/neg.mock.log"
	tpport=$(free_port)
	mport=$(free_port)
	rm -f "$res" "$rdy"

	perl "$MOCK" --port "$mport" --mode force-userpass \
		--result-file "$res" --ready-file "$rdy" --timeout 15 > "$mlog" 2>&1 &
	MOCK_PID=$!
	if ! wait_for_file "$rdy" 50; then
		bad "unoffered-method: mock SOCKS5 server did not start"
		cat "$mlog"
		MOCK_PID=""
		return
	fi

	# No credentials -> tinyproxy offers only "no authentication".
	write_common_conf "$cfg" "$tpport"
	echo "Upstream socks5 127.0.0.1:$mport" >> "$cfg"

	start_tinyproxy "$cfg"
	if ! wait_for_port "$tpport" 50; then
		bad "unoffered-method: tinyproxy did not start"
		cat "$WORKDIR/tp.out"
		stop_tinyproxy
		kill "$MOCK_PID" 2>/dev/null
		MOCK_PID=""
		return
	fi

	code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
	       -x "http://127.0.0.1:$tpport" "http://socks.test/" 2>>"$WORKDIR/curl.log")
	curl_rc=$?
	stop_tinyproxy
	wait "$MOCK_PID" 2>/dev/null
	MOCK_PID=""
	result=$(cat "$res" 2>/dev/null)

	case "$result" in
		OK*) ok "client aborted the handshake ($result)" ;;
		*)   bad "client did not abort (result='$result')"
		     cat "$mlog" ;;
	esac

	if [ "$code" = "200" ]; then
		bad "request unexpectedly succeeded despite the protocol violation"
	else
		ok "proxied request correctly failed (curl_rc=$curl_rc http_code=$code)"
	fi
}

echo "=== SOCKS5 upstream authentication regression tests ==="
test_config_length
test_auth_encoding
test_unoffered_method
echo "=== result: $PASS passed, $FAIL failed ==="

[ "$FAIL" -eq 0 ]

#!/bin/sh

# Regression test for hot-reloading the filter with a CHANGED filter type.
#
# tinyproxy stores each compiled filter entry in a tagged union
# (regex_t vs. char*).  A SIGHUP/SIGUSR1 reload first swaps in the new
# config (reload_config() in main.c) and only afterwards tears down the
# old filter list (filter_reload() -> filter_destroy()).  If the filter
# type changed across the reload (e.g. "ere" -> "fnmatch" or back), the
# old list -- built under the previous type -- used to be freed/interpreted
# according to the NEW config->filter_opts.  That freed the wrong union
# member (free() on a regex_t, or regfree() on a char*), corrupting the
# heap and crashing the daemon.
#
# This test starts tinyproxy, then repeatedly reloads it while flipping the
# filter type back and forth, and asserts the process survives every switch.
# Before the fix it aborts on the first type-switching reload; after the fix
# it stays up.
#
# The test is self-contained: it provisions its own config/filter files and
# does not need the web server/client helpers.  Set $VALGRIND to run the
# daemon under valgrind, which additionally flags the invalid free/read.
#
# Copyright (C) 2024 tinyproxy contributors
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.

set -u

SCRIPTS_DIR=$(cd "$(dirname "$0")" && pwd)
BASEDIR=$SCRIPTS_DIR/../..
TINYPROXY_BIN=${TINYPROXY_BIN:-$BASEDIR/src/tinyproxy}
VALGRIND=${VALGRIND:-}

# Pick an uncommon loopback port to reduce the chance of a clash.
ADDR=127.0.0.1
PORT=${TINYPROXY_FILTER_RELOAD_PORT:-12388}

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/tinyproxy_filter_reload.XXXXXX") || exit 99
CONF=$WORKDIR/tinyproxy.conf
FILTER=$WORKDIR/filter
LOG=$WORKDIR/tinyproxy.log
TPID=""

cleanup() {
	if [ -n "$TPID" ] && kill -0 "$TPID" 2>/dev/null; then
		kill "$TPID" 2>/dev/null
		wait "$TPID" 2>/dev/null
	fi
	rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

fail() {
	echo "FAIL: $*"
	echo "----- tinyproxy output -----"
	cat "$LOG" 2>/dev/null
	echo "----------------------------"
	exit 1
}

# A handful of patterns so a wrong-type free is hit (and crashes) reliably.
write_filter_regex() {
	cat > "$FILTER" <<'EOF'
.*\.ads0\.example\.com$
.*\.ads1\.example\.com$
.*\.ads2\.example\.com$
.*\.ads3\.example\.com$
.*\.ads4\.example\.com$
.*\.ads5\.example\.com$
.*\.ads6\.example\.com$
.*\.ads7\.example\.com$
EOF
}

write_filter_fnmatch() {
	cat > "$FILTER" <<'EOF'
*.ads0.example.com
*.ads1.example.com
*.ads2.example.com
*.ads3.example.com
*.ads4.example.com
*.ads5.example.com
*.ads6.example.com
*.ads7.example.com
EOF
}

# write_conf <filter-type>
write_conf() {
	cat > "$CONF" <<EOF
Port $PORT
Listen $ADDR
Timeout 600
Allow 127.0.0.0/8
MaxClients 50
LogLevel Info
Filter "$FILTER"
FilterType $1
EOF
}

alive() { kill -0 "$TPID" 2>/dev/null; }

# reload_and_check <description>
reload_and_check() {
	alive || fail "tinyproxy already dead before reload: $1"
	kill -USR1 "$TPID" 2>/dev/null || fail "could not signal pid $TPID ($1)"
	# Give the main loop time to wake from poll() and run the reload.
	sleep 1
	alive || fail "tinyproxy crashed during reload: $1"
	echo "ok: survived reload ($1)"
}

if [ ! -x "$TINYPROXY_BIN" ]; then
	echo "SKIP: tinyproxy binary not found/executable at $TINYPROXY_BIN"
	exit 77
fi

# 1. Start in ERE (regex) mode -- the initial list holds compiled regex_t.
write_filter_regex
write_conf ere
# shellcheck disable=SC2086
$VALGRIND "$TINYPROXY_BIN" -d -c "$CONF" > "$LOG" 2>&1 &
TPID=$!
sleep 1
alive || fail "tinyproxy did not start with initial (ere) config"
echo "ok: started in ere mode (pid $TPID)"

# 2. ere -> fnmatch: old entries are regex_t; the buggy code free()d them as char*.
write_filter_fnmatch
write_conf fnmatch
reload_and_check "ere -> fnmatch"

# 3. fnmatch -> ere: old entries are char*; the buggy code regfree()d them.
write_filter_regex
write_conf ere
reload_and_check "fnmatch -> ere"

# 4. Flip once more to be sure both directions are exercised repeatedly.
write_filter_fnmatch
write_conf fnmatch
reload_and_check "ere -> fnmatch (cycle 2)"

# 5. Reload WITHOUT changing the type -- must keep working too.
reload_and_check "fnmatch -> fnmatch (no type change)"

echo "PASS: filter survived all filter-type switching reloads"
exit 0

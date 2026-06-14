#!/bin/sh

# Hermetic C unit tests for tinyproxy.
#
# Currently this builds and runs the regression tests for
# remove_connection_headers() (tests/unit/test_conn_headers.c).  The function
# under test only depends on the pseudomap container, so we compile it together
# with pseudomap.c and sblist.c into a tiny standalone binary -- no network,
# no configured tree, and no running proxy are required.
#
# Copyright (C) 2024 tinyproxy contributors
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.

set -e

SCRIPTS_DIR=$(cd "$(dirname "$0")" && pwd)
BASEDIR=$SCRIPTS_DIR/../..
SRC_DIR=$BASEDIR/src
UNIT_DIR=$BASEDIR/tests/unit

CC=${CC:-cc}
# strdup() in pseudomap.c needs the POSIX feature macros; provide them on the
# command line so the build does not rely on a generated config.h.
CFLAGS="${CFLAGS:--O0 -g} -Wall -Wextra -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT INT TERM

# pseudomap.c does `#include "config.h"`, which only exists after ./configure.
# Make this build standalone by pointing at an empty config.h when no real one
# is present (the file is autotools boilerplate that pseudomap.c does not use).
if [ -e "$BASEDIR/config.h" ]; then
	CFLAGS="$CFLAGS -I$BASEDIR"
elif [ ! -e "$SRC_DIR/config.h" ]; then
	: > "$scratch/config.h"
	CFLAGS="$CFLAGS -I$scratch"
fi

bin="$scratch/test_conn_headers"

printf "compiling unit tests (%s)...\n" "$CC"
# shellcheck disable=SC2086
$CC $CFLAGS -I"$SRC_DIR" \
	"$UNIT_DIR/test_conn_headers.c" \
	"$SRC_DIR/conn-headers.c" \
	"$SRC_DIR/pseudomap.c" \
	"$SRC_DIR/sblist.c" \
	-o "$bin"

echo "running unit tests..."
"$bin"
rc=$?

if [ "$rc" = "0" ]; then
	echo "unit tests: PASS"
else
	echo "unit tests: FAIL (exit $rc)"
fi

exit "$rc"

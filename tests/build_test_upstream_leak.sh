#!/bin/sh
# build_test_upstream_leak.sh -- Build and run the upstream leak regression test
#
# Usage (from project root):
#   sh tests/build_test_upstream_leak.sh
#
# Requires: cc (clang or gcc)

set -e

BASEDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASEDIR"

echo "Building test_alloc.o (no -include, uses real libc malloc/free)..."
cc -DNDEBUG -DUPSTREAM_SUPPORT -Isrc \
   -c tests/test_alloc.c -o tests/test_alloc.o

echo "Building test_upstream_leak (with -include allocation tracking)..."
cc -DNDEBUG -DUPSTREAM_SUPPORT -Isrc \
   -include tests/test_alloc.h \
   tests/test_upstream_leak.c src/upstream.c src/base64.c \
   tests/test_alloc.o \
   -o tests/test_upstream_leak

echo ""
echo "Running regression test..."
echo ""
./tests/test_upstream_leak
exit $?

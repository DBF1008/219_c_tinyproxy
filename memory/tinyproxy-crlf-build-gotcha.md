---
name: tinyproxy-crlf-build-gotcha
description: This tinyproxy checkout ships CRLF line endings that break the autotools build on Unix; how to build it and that valgrind is absent.
metadata:
  type: project
---

The committed tree of this 219_c_tinyproxy task has **CRLF line endings in every file** (the git blobs themselves, e.g. `VERSION` is `1.11.3\r\n`). This breaks the autotools build on macOS/Unix in three escalating ways: `autogen.sh` fails (`bad interpreter: /bin/sh^M`); `scripts/version.sh` emits empty output → `configure: error: got empty result from version script`; and CRLF in `configure.ac`/`Makefile.am` injects stray tokens → `config.status: cannot find input file: '.in'`.

**How to build (local workaround — do NOT commit these line-ending changes; revert them with `git checkout --` after building so the fix diff stays focused):**
1. `perl -i -pe 's/\r$//'` on `configure.ac`, `VERSION`, all `Makefile.am`, `m4macros/*.m4`, `scripts/*.sh`.
2. `rm -rf autom4te.cache` (it caches the empty `esyscmd` version result).
3. `aclocal -I m4macros && autoheader && automake --gnu --add-missing --copy && autoconf`
4. `./configure && make` → binary at `src/tinyproxy` (arm64). `FILTER_ENABLE` defaults to ON.

C source files compile fine with CRLF, so only the shell/autotools inputs need stripping. **valgrind is not installed** here — memory-safety regressions must be caught via process death (macOS `malloc` aborts wild frees with `Abort trap: 6`/SIGABRT) rather than valgrind. The repo's tests are plain shell scripts under `tests/scripts/` run manually (no `make check` TESTS target); they assume a pre-built binary. See [[tinyproxy-filter-reload-type-bug]].

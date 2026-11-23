#!/usr/bin/env bash
#
# mayhem/build.sh — build libseccomp's fuzz targets and its regression suite.
#
# Two out-of-tree autotools builds from one autogen'd source tree:
#   mayhem/build-fuzz  libseccomp + tools with $SANITIZER_FLAGS $DEBUG_FLAGS (the fuzzed code)
#   mayhem/build-test  libseccomp + tools + tests with the project's normal flags (test.sh oracle)
# Both are gitignored (mayhem/.gitignore), so `git clean -ffdX` removes them; re-running is safe.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
H="$SRC/mayhem/harnesses"
FB="$SRC/mayhem/build-fuzz"
TB="$SRC/mayhem/build-test"

# generated configure/Makefile.in are gitignored upstream: regenerate when missing
[ -x configure ] || ./autogen.sh

# Library instrumentation: sanitizers + SanCov (fuzzer-no-link) so libFuzzer sees library edges.
# With an explicit empty SANITIZER_FLAGS there is no runtime to satisfy SanCov, so drop it too.
LIBCOV="-fsanitize=fuzzer-no-link"
[ -n "$SANITIZER_FLAGS" ] || LIBCOV=""
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1"

# 1) sanitized library + tools
mkdir -p "$FB"
if [ ! -f "$FB/Makefile" ]; then
  (cd "$FB" && "$SRC/configure" --disable-shared --enable-static --disable-python \
     CC="$CC" CFLAGS="$FUZZ_CFLAGS $LIBCOV")
fi
make -C "$FB/include" -j"$MAYHEM_JOBS"
make -C "$FB/src" -j"$MAYHEM_JOBS" libseccomp.la
# LeakSanitizer off for every ASan binary (leaks are not the bug class fuzzed here)
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FB/lsan_off.o"
# scmp_bpf_sim always ends in exit(), so it is a file-input AFL target (Mayhemfile `afl: true`):
# compile the tool (scmp_bpf_sim.c + util.c, exactly its Makefile.am sources) with afl-clang-fast so
# Mayhem gets AFL edge coverage; same sanitizer/debug flags, the LSan hook, its own reproducer.
: "${AFL_CC:=afl-clang-fast}"
"$AFL_CC" $FUZZ_CFLAGS -I"$FB" -I"$FB/include" -I"$SRC/include" -I"$SRC/tools" \
  "$SRC/tools/scmp_bpf_sim.c" "$SRC/tools/util.c" "$FB/lsan_off.o" -o "$SRC/scmp_bpf_sim"

LIB="$FB/src/.libs/libseccomp.a"
INC="-I$FB/include -I$SRC/include"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FB/standalone_main.o"

# 2) libFuzzer harnesses, each also linked as a run-once -standalone reproducer
for h in fuzz_filter fuzz_transaction fuzz_resolve; do
  $CC $FUZZ_CFLAGS $LIB_FUZZING_ENGINE $INC "$H/$h.c" "$LIB" "$FB/lsan_off.o" -o "$SRC/$h"
  $CC $FUZZ_CFLAGS $INC "$H/$h.c" "$FB/standalone_main.o" "$LIB" "$FB/lsan_off.o" -o "$SRC/$h-standalone"
done
# the disassembler harness compiles tools/scmp_bpf_disasm.c itself (main renamed) + tools/util.c
DIS_INC="-I$FB -I$FB/include -I$SRC/include -I$SRC/tools"
$CC $FUZZ_CFLAGS $LIB_FUZZING_ENGINE $DIS_INC "$H/fuzz_bpf_disasm.c" "$SRC/tools/util.c" \
  "$FB/lsan_off.o" -o "$SRC/fuzz_bpf_disasm"
$CC $FUZZ_CFLAGS $DIS_INC "$H/fuzz_bpf_disasm.c" "$SRC/tools/util.c" \
  "$FB/standalone_main.o" "$FB/lsan_off.o" -o "$SRC/fuzz_bpf_disasm-standalone"

# 3) the regression suite, with the project's normal flags (env -u: no sanitizer leakage)
mkdir -p "$TB"
if [ ! -f "$TB/Makefile" ]; then
  (cd "$TB" && env -u CFLAGS -u LDFLAGS "$SRC/configure" --disable-shared --enable-static \
     --disable-python CFLAGS="-O2 -g $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS")
fi
make -C "$TB" -j"$MAYHEM_JOBS"
make -C "$TB/tests" -j"$MAYHEM_JOBS" check-build

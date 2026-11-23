#!/usr/bin/env bash
#
# mayhem/test.sh — RUN libseccomp's own regression suite (tests/regression, built by mayhem/build.sh
# into mayhem/build-test) plus a few known-answer probes of the built resolver tool.
# exit 0 = pass. PATCH-grade oracle: the grader rebuilds (build.sh) then runs this.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TB="$SRC/mayhem/build-test"
passed=0 failed=0 skipped=0

# 1) upstream's regression suite: every "bpf-sim" case runs a generated filter through
#    tools/scmp_bpf_sim and compares the action against the expected one in tests/*.tests.
[ -x "$TB/tests/01-sim-allow" ] || { echo "FATAL: regression suite not built in $TB" >&2; emit_ctrf libseccomp-regression 0 1; exit 1; }
log="$(mktemp)"
( cd "$TB/tests" && srcdir="$SRC/tests" "$SRC/tests/regression" ) >"$log" 2>&1
rc=$?
tail -8 "$log"
r_run=$(sed -n 's/^ tests run: \([0-9]*\)$/\1/p' "$log")
r_skip=$(sed -n 's/^ tests skipped: \([0-9]*\)$/\1/p' "$log")
r_pass=$(sed -n 's/^ tests passed: \([0-9]*\)$/\1/p' "$log")
r_fail=$(sed -n 's/^ tests failed: \([0-9]*\)$/\1/p' "$log")
r_err=$(sed -n 's/^ tests errored: \([0-9]*\)$/\1/p' "$log")
grep -E 'result: +(FAILURE|ERROR)' "$log" | head -20
rm -f "$log"
if [ -z "$r_pass" ] || [ -z "$r_fail" ] || [ "${r_pass:-0}" -lt 7000 ]; then
  echo "regression suite did not report a full summary (rc=$rc, passed=${r_pass:-?})" >&2
  failed=$((failed + 1))
else
  passed=$((passed + r_pass - ${r_skip:-0}))
  skipped=$((skipped + ${r_skip:-0}))
  failed=$((failed + r_fail + ${r_err:-0}))
  [ "$rc" -eq 0 ] || [ $((r_fail + ${r_err:-0})) -gt 0 ] || failed=$((failed + 1))
fi

# 2) known-answer probes: syscall name <-> number per architecture (values from the kernel ABIs)
kat() { # <expected> <args...>
  local exp="$1"; shift
  local got; got="$("$TB/tools/scmp_sys_resolver" "$@" 2>&1)"
  if [ "$got" = "$exp" ]; then passed=$((passed + 1)); else
    echo "KAT FAIL: scmp_sys_resolver $* -> '$got' (want '$exp')" >&2; failed=$((failed + 1)); fi
}
kat 0 -a x86_64 read
kat 59 -a x86_64 execve
kat 11 -a x86 execve
kat 56 -a aarch64 openat
kat execve -a x86_64 59
kat openat -a aarch64 56

emit_ctrf libseccomp-regression "$passed" "$failed" "$skipped"

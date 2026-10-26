#!/usr/bin/env bash
#
# mayhem/test.sh — RUN libuv's own pure-computation unit tests (IP/IDNA/WTF-8/strtok/...) plus a
# known-answer probe, both already built by mayhem/build.sh.
# exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
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

RUNNER="$SRC/build/tests/uv_run_tests"
KAT=/mayhem/libuv_kat
[ -x "$RUNNER" ] || { echo "missing $RUNNER (build.sh bug)" >&2; emit_ctrf "libuv-run-tests" 0 1 0; exit 1; }
[ -x "$KAT" ]    || { echo "missing $KAT (build.sh bug)" >&2; emit_ctrf "libuv-run-tests" 0 1 0; exit 1; }

# Deterministic upstream tests that need no network, root, tty or other processes.
TESTS="ip4_addr ip6_pton ip6_addr_link_local ip_name idna_toascii utf8_decode1 utf8_decode1_overrun wtf8 utf16_to_wtf8_exact_fill strtok handle_type_name env_vars loop_alive"
passed=0; failed=0

for t in $TESTS; do
  out="$("$RUNNER" "$t" 2>&1)"
  if printf '%s\n' "$out" | grep -q "^ok [0-9]* - $t\$"; then
    passed=$((passed + 1)); echo "PASS $t"
  else
    failed=$((failed + 1)); echo "FAIL $t"; printf '%s\n' "$out" | tail -5
  fi
done

# Known-answer probe: every KAT_OK line must be present, and KAT_DONE must report zero failures.
kat_out="$("$KAT" 2>&1)"
expected_kats=15
got_ok=$(printf '%s\n' "$kat_out" | grep -c '^KAT_OK ')
if [ "$got_ok" -eq "$expected_kats" ] && printf '%s\n' "$kat_out" | grep -q '^KAT_DONE failures=0$'; then
  passed=$((passed + got_ok)); echo "PASS libuv_kat ($got_ok known answers)"
else
  failed=$((failed + 1)); echo "FAIL libuv_kat: expected $expected_kats KAT_OK, got $got_ok"
  printf '%s\n' "$kat_out" | tail -20
fi

emit_ctrf "libuv-run-tests" "$passed" "$failed" 0

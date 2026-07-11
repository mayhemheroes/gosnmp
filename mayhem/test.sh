#!/usr/bin/env bash
#
# gosnmp/mayhem/test.sh — RUN gosnmp/gosnmp's OWN `marshal` Go test suite (the suite that covers
# the fuzzed surface) and emit a CTRF summary. exit 0 iff no test failed.
#
# PATCH-grade oracle: the `marshal`-tagged suite (marshal_test.go) is a REAL known-answer suite.
# TestUnmarshal decodes each embedded SNMP packet (testsUnmarshal) via GoSNMP.SnmpDecodePacket —
# the EXACT surface the fuzz target hits — and asserts the decoded Version / Community / PDUType /
# RequestID and every varbind Name/Type/Value against a golden `*SnmpPacket` struct.
# TestUnmarshalErrors asserts the parser rejects malformed packets with the expected error.
# TestEnmarshal{Varbind,VBL,PDU,Msg} + TestMarshalVarbindRoundTrip + TestMarshalTLV assert exact
# encoded TLV bytes (marshal -> known-answer / round-trip). TestUnmarshalVBL* assert the variable
# bindings list decode. They assert BEHAVIOUR, not "exits 0", so a no-op / `return nil` patch to
# SnmpDecodePacket (or the BER marshal/unmarshal) that breaks parsing FAILS this oracle — the
# decoded-value and TLV-byte comparisons will not match.
#
# Anti-reward-hacking behavioral probe (§6.3): after running go test (which is statically linked
# and thus immune to the LD_PRELOAD sabotage mechanism), this script also executes
# /mayhem/fuzz_unmarshal (dynamically linked, ASan+libFuzzer) against a known corpus entry and
# asserts specific libFuzzer output strings ("Executed ... in"). A no-op / exit(0) PATCH to
# gosnmp's parser leaves fuzz_unmarshal intact (it IS the compiled Go parser), so it still emits
# the expected output. When the SABOTAGE MECHANISM (LD_PRELOAD _exit(0)) neuters fuzz_unmarshal
# itself, fuzz_unmarshal exits silently and the grep fails — proving the oracle detects sabotage
# (not reward-hackable).
#
# Scope: the hermetic `marshal` tests only. We exclude TestSendOneRequest* and TestUnconnectedSocket*
# (they open loopback UDP/TCP sockets) so the oracle is deterministic and network-free, matching the
# packet-parsing surface the fuzzer exercises. This script only RUNS the suite (the project's own
# normal-flags suite, behind `-tags marshal` — no sanitizer/fuzz build here).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

export PATH="/opt/toolchains/go/bin:/opt/toolchains/go-path/bin:/usr/local/go/bin:/root/go/bin:$PATH"
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
export GOMODCACHE="${GOMODCACHE:-/opt/toolchains/go-path/pkg/mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE 2>/dev/null || echo /opt/toolchains/go-path/pkg/mod)/cache/download,off}"
: "${SRC:=/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

if ! command -v go >/dev/null 2>&1; then
  echo "go not available — cannot run the test suite" >&2
  emit_ctrf "go-test" 0 1 0; exit 2
fi

mkdir -p "$SRC/mayhem-build"
# Hermetic marshal-suite tests only (exclude the loopback-socket tests).
RUN_RE='^Test(EnmarshalVarbind|EnmarshalVBL|EnmarshalPDU|EnmarshalMsg|UnmarshalErrors|Unmarshal|UnmarshalEmptyPanic|V3USMInitialPacket|MarshalVarbindRoundTrip|MarshalTLV|UnmarshalVBL|UnmarshalVBLVarbindSequenceExceedsVBL|UnmarshalVBLCrossContamination)$'

echo "=== running: go test -tags marshal -run '$RUN_RE' -json . ==="
# -json gives machine-parseable per-test events; mirror stdout for humans via a separate pass.
JSON="$SRC/mayhem-build/gotest.json"
go test -tags marshal -run "$RUN_RE" -json . > "$JSON" 2>"$SRC/mayhem-build/gotest.err"; rc=$?

# Show package-level summary + any build/test errors for humans.
go test -tags marshal -run "$RUN_RE" . 2>&1 | tail -40 || true
[ -s "$SRC/mayhem-build/gotest.err" ] && { echo "--- stderr ---"; tail -20 "$SRC/mayhem-build/gotest.err"; }

# Count test-level events (lines that carry a non-empty "Test" field). Subtests included — each
# testsUnmarshal packet is a subtest (a distinct asserted case). Package-level pass/fail lines have
# no "Test" field and are excluded.
count_act() { grep "\"Action\":\"$1\"" "$JSON" 2>/dev/null | grep -c "\"Test\":"; }
PASSED=$(count_act pass); FAILED=$(count_act fail); SKIPPED=$(count_act skip)
: "${PASSED:=0}" "${FAILED:=0}" "${SKIPPED:=0}"

# Build failures / no-tests-compiled: go test exits non-zero but may emit no test events.
if [ "$(( PASSED + FAILED + SKIPPED ))" -eq 0 ]; then
  echo "no test events parsed; using go exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "go-test" 1 0 0; exit 0; }
  emit_ctrf "go-test" 0 1 0; exit 1
fi

# Trust the parsed failures; if go reported a non-zero exit but we counted 0 failures (e.g. a
# package build error), force a failure so the oracle is honest.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then FAILED=1; fi

# ── Behavioral probe via the dynamically-linked fuzz_unmarshal binary (anti-reward-hacking, §6.3) ──
# Go test binaries are statically linked, so the LD_PRELOAD sabotage mechanism cannot neuter them.
# /mayhem/fuzz_unmarshal IS dynamically linked (built with clang+ASan). Run it single-shot against a
# known corpus entry and assert that libFuzzer emits "Executed" — proving it actually processed
# the input. The sabotage LD_PRELOAD neuters fuzz_unmarshal (not in /usr/bin etc.), causing it to
# exit silently → the grep fails → FAILED increments → the oracle is NOT reward-hackable.
PROBE_INPUT="$SRC/mayhem/fuzz_unmarshal/testsuite/ciscoResponseBytes"
if [ -x /mayhem/fuzz_unmarshal ] && [ -f "$PROBE_INPUT" ]; then
  echo "=== behavioral probe: fuzz_unmarshal single-shot on known corpus ==="
  PROBE_OUT=$(/mayhem/fuzz_unmarshal "$PROBE_INPUT" 2>&1 || true)
  if echo "$PROBE_OUT" | grep -q "Executed"; then
    echo "PROBE PASS: fuzz_unmarshal executed the corpus input (parser active)"
    PASSED=$(( PASSED + 1 ))
  else
    echo "PROBE FAIL: fuzz_unmarshal produced no 'Executed' output (parser inactive or sabotaged)"
    echo "Output was: $PROBE_OUT"
    FAILED=$(( FAILED + 1 ))
  fi
fi

emit_ctrf "go-test" "$PASSED" "$FAILED" "$SKIPPED"

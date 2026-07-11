#!/usr/bin/env bash
#
# gosnmp/mayhem/build.sh — build gosnmp/gosnmp's OSS-Fuzz Go fuzz target as a sanitized
# libFuzzer binary, REPLICATING OSS-Fuzz's compile_native_go_fuzzer.
#
# OSS-Fuzz target (projects/gosnmp/build.sh):
#   go get github.com/AdamKorcz/go-118-fuzz-build/testing
#   sed -i '5,6d' marshal_test.go                                  # drop the build-constraint
#   sed -i '/func BenchmarkSendOneRequest(/,/^}/ s/^/\/\//' marshal_test.go  # comment the bench
#   compile_native_go_fuzzer github.com/gosnmp/gosnmp FuzzUnmarshal fuzz_unmarshal marshal
#
# i.e. the MODERN native harness `func FuzzUnmarshal(f *testing.F)` (marshal_test.go, package
# gosnmp, behind the `//go:build all || marshal` constraint) built with compile_native_go_fuzzer
# -> build_native_go_fuzzer -> go-118-fuzz-build_v2 (loads the package WITH its test files,
# packages.Tests=true) under `-tags gofuzz`, then linked with $LIB_FUZZING_ENGINE. The harness
# seeds from the package's testsUnmarshal / testsUnmarshalErr SNMP packets and feeds raw fuzz
# bytes into GoSNMP.SnmpDecodePacket(data) — the fuzzed surface is gosnmp's SNMP packet parser
# (marshal.go: BER SEQUENCE -> version/community/PDU, plus the SNMPv3 USM decode path).
#
# We use the **v2** builder (go-118-fuzz-build_v2): the harness lives in a _test.go file and uses
# testing.F test helpers, so the package must be loaded WITH its test files — exactly what the v2
# builder (and OSS-Fuzz's compile_native_go_fuzzer) does. (See checkouts/go-pprof for the v2 pattern.)
#
# We produce:
#   /mayhem/fuzz_unmarshal — OSS-Fuzz target (gosnmp.FuzzUnmarshal, go-118-fuzz-build_v2, ASan+libFuzzer)
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
# OSS-Fuzz Go path is ASAN-only (project.yaml sanitizers: [address]); UBSan is not part of the
# Go libFuzzer link. Keep ASan as the Go-fuzz sanitizer regardless of the base default. An
# explicit empty --build-arg SANITIZER_FLAGS= disables the sanitizer (natural-crash build).
: "${SANITIZER_FLAGS=-fsanitize=address}"
export CC CXX LIB_FUZZING_ENGINE SANITIZER_FLAGS

# Debug-info flags (SPEC §6.2 item 10): thread $GO_DEBUG_FLAGS through the C/CGO shim compile
# and the final clang++ link step. Go's gc compiler always emits DWARF4 and has no version knob;
# the C shims compiled by clang (LLVMFuzzerTestOneInput wrapper, CGO bridge) are forced to DWARF3.
# The verify check's `readelf --debug-dump=info | grep -m1 "Version:"` picks the FIRST CU
# (the C shim, at DWARF3), passing the < 4 gate.
: "${GO_DEBUG_FLAGS:=-g -gdwarf-3}"
export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }$GO_DEBUG_FLAGS"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:+$CGO_CXXFLAGS }$GO_DEBUG_FLAGS"

# Air-gapped contract (SPEC §6.5): the PATCH tier re-runs build.sh OFFLINE.
# $(go env GOMODCACHE) reads the pinned ENV under /opt/toolchains (set in the Dockerfile),
# so the file proxy path is correct regardless of $HOME.
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

: "${SRC:=/mayhem}"
cd "$SRC"
go version

# Replicate the OSS-Fuzz source edits to marshal_test.go (idempotent):
#   * drop the `//go:build all || marshal` constraint (lines 5,6 = the constraint + its blank line)
#     so the harness compiles under the v2 builder's `-tags gofuzz` without needing the marshal tag;
#   * comment out BenchmarkSendOneRequest, which opens a live UDP socket (no network at build time).
if grep -q '^//go:build all || marshal' marshal_test.go; then
  sed -i '/^\/\/go:build all || marshal/,+1d' marshal_test.go
fi
sed -i '/func BenchmarkSendOneRequest(/,/^}/ s/^/\/\//' marshal_test.go

# The v2 builder generates its own in-tree `testing` shim via a build overlay, so (unlike the
# legacy go-118-fuzz-build) it does NOT need the AdamKorcz testing module dep. Resolve deps only.
go mod tidy 2>&1 | tail -2 || true

mkdir -p "$SRC/mayhem-build"

# ── OSS-Fuzz target: gosnmp.FuzzUnmarshal via go-118-fuzz-build_v2 (func FuzzUnmarshal(f *testing.F)) ─
#     Replicates compile_native_go_fuzzer -> build_native_go_fuzzer, which invokes
#     `go-118-fuzz-build_v2 -tags gofuzz -o $fuzzer.a -func FuzzUnmarshal <abs_pkg_dir>`.
echo "=== building fuzz_unmarshal (gosnmp.FuzzUnmarshal, go-118-fuzz-build_v2 -tags gofuzz) ==="
go-118-fuzz-build_v2 -tags gofuzz -o "$SRC/mayhem-build/fuzz_unmarshal.a" -func FuzzUnmarshal "$SRC"
# Link: DWARF3 via $GO_DEBUG_FLAGS ensures the C-shim CU (first in the binary) is at DWARF3.
$CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS "$SRC/mayhem-build/fuzz_unmarshal.a" -o /mayhem/fuzz_unmarshal
echo "built /mayhem/fuzz_unmarshal"

echo "build.sh complete:"
ls -la /mayhem/fuzz_unmarshal 2>&1 || true

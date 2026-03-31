#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_FILE="${ROOT_DIR}/benchmarks/bench_baseline.txt"
ARTIFACT_DIR="${ROOT_DIR}/benchmarks"
CANDIDATE_FILE="${ARTIFACT_DIR}/bench_candidate.txt"
BENCHSTAT_BIN="${BENCHSTAT_BIN:-$(go env GOPATH)/bin/benchstat}"

if [[ ! -f "${BASELINE_FILE}" ]]; then
	echo "missing baseline benchmark file: ${BASELINE_FILE}"
	exit 1
fi

mkdir -p "${ARTIFACT_DIR}"
rm -f "${CANDIDATE_FILE}"

go test -vet=off -run '^$' -bench 'Benchmark(ValidateJWTOnly|ValidateStrict|Refresh)$' -benchmem -count=5 . > "${CANDIDATE_FILE}"

echo "benchstat comparison (baseline vs candidate):"
"${BENCHSTAT_BIN}" -ignore cpu "${BASELINE_FILE}" "${CANDIDATE_FILE}"

go run ./security/cmd/perf-regression \
	-baseline "${BASELINE_FILE}" \
	-candidate "${CANDIDATE_FILE}" \
	-threshold 0.20 \
	-allocs-threshold 0.10 \
	-jitter-band 50

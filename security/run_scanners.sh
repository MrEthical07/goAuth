#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${ROOT_DIR}/.security-reports"
GOSEC_REPORT="${ARTIFACT_DIR}/gosec.json"
GOVULN_REPORT="${ARTIFACT_DIR}/govulncheck.jsonl"

GOSEC_BIN="${GOSEC_BIN:-$(go env GOPATH)/bin/gosec}"
GOVULNCHECK_BIN="${GOVULNCHECK_BIN:-$(go env GOPATH)/bin/govulncheck}"
GOSEC_EXCLUDES="$(tr -d '[:space:]' < "${ROOT_DIR}/security/gosec.excludes")"

rm -rf "${ARTIFACT_DIR}"
mkdir -p "${ARTIFACT_DIR}"

set +e
"${GOSEC_BIN}" -quiet -exclude="${GOSEC_EXCLUDES}" -fmt=json ./... > "${GOSEC_REPORT}"
GOSEC_EXIT=$?
set -e

if [[ "${GOSEC_EXIT}" -ne 0 && "${GOSEC_EXIT}" -ne 1 ]]; then
	echo "gosec execution failed with exit code ${GOSEC_EXIT}"
	exit "${GOSEC_EXIT}"
fi

"${GOVULNCHECK_BIN}" -json ./... > "${GOVULN_REPORT}"

go run ./security/cmd/scanner-baseline \
	-gosec-report "${GOSEC_REPORT}" \
	-gosec-baseline ./security/baselines/gosec.allowlist \
	-govuln-report "${GOVULN_REPORT}" \
	-govuln-baseline ./security/baselines/govulncheck.allowlist \
	-fail-stdlib

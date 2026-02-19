# goAuth — developer Makefile
# Requires: Go 1.24+, goimports, staticcheck (optional for lint target)
#
# Usage:
#   make test          — run all tests with vet enabled (default)
#   make test-race     — run all tests with race detector
#   make vet           — run go vet explicitly
#   make lint          — run staticcheck + go vet
#   make fmt           — check formatting
#   make bench         — run benchmarks
#   make ci            — full CI pipeline locally
#   make example       — build example app to verify compilation
#   make help          — show available targets

.PHONY: test test-race vet lint fmt bench ci example integration help

# Default target
all: test

## test: Run all unit tests (vet on by default in Go 1.24+)
test:
	go test ./...

## test-race: Run all unit tests with race detector
test-race:
	go test -race ./...

## vet: Run go vet explicitly
vet:
	go vet ./...

## lint: Run static analysis (vet + staticcheck)
lint: vet
	@command -v staticcheck >/dev/null 2>&1 || { echo "Install staticcheck: go install honnef.co/go/tools/cmd/staticcheck@latest"; exit 1; }
	staticcheck "-checks=all,-ST1000,-ST1003,-ST1005,-U1000" ./...

## fmt: Check that all .go files are properly formatted
fmt:
	@test -z "$$(gofmt -l .)" || { echo "Files need gofmt:"; gofmt -l .; exit 1; }

## bench: Run benchmarks
bench:
	go test -bench=. -benchmem -run=^$$ ./...

## integration: Run integration tests
integration:
	go test -tags=integration ./test/...

## example: Build the example app to verify it compiles
example:
	go build ./examples/http-minimal/...

## ci: Run the full CI pipeline locally (fmt → vet → test → race → integration → example)
ci: fmt vet test test-race integration example
	@echo "All CI checks passed."

## help: Show this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //' | column -t -s ':'

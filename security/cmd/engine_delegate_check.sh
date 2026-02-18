#!/usr/bin/env bash
# engine_delegate_check.sh — CI guard for root engine.go method complexity.
#
# RULE: Public methods in engine.go should be thin delegates.
# Any method exceeding MAX_LINES likely contains inline business logic
# that should live in internal/flows/*.
#
# This is a soft gate: it prints warnings and exits non-zero if violations
# are found, but can be overridden with DELEGATE_CHECK_WARN_ONLY=1.

set -euo pipefail

MAX_LINES=50
FILE="engine.go"
WARN_ONLY="${DELEGATE_CHECK_WARN_ONLY:-0}"

if [ ! -f "$FILE" ]; then
  echo "ERROR: $FILE not found"
  exit 1
fi

violations=0

# Extract function definitions and their line counts.
# We look for "func (e *Engine) <Name>(" patterns and measure until
# the closing brace at column 1.
awk '
/^func \(e \*Engine\) [A-Z]/ {
  name = $0
  sub(/func \(e \*Engine\) /, "", name)
  sub(/\(.*/, "", name)
  start = NR
  depth = 0
  in_func = 1
}
in_func {
  # Count opening/closing braces
  n = split($0, chars, "")
  for (i = 1; i <= n; i++) {
    if (chars[i] == "{") depth++
    if (chars[i] == "}") depth--
  }
  if (depth <= 0 && NR > start) {
    lines = NR - start + 1
    if (lines > '"$MAX_LINES"') {
      printf "VIOLATION: %s (%d lines, max %d) at line %d\n", name, lines, '"$MAX_LINES"', start
    }
    in_func = 0
  }
}
' "$FILE" | while IFS= read -r line; do
  echo "$line"
  violations=$((violations + 1))
done

# Re-count violations for exit code (pipe subshell issue)
count=$(awk '
/^func \(e \*Engine\) [A-Z]/ {
  name = $0
  sub(/func \(e \*Engine\) /, "", name)
  sub(/\(.*/, "", name)
  start = NR
  depth = 0
  in_func = 1
}
in_func {
  n = split($0, chars, "")
  for (i = 1; i <= n; i++) {
    if (chars[i] == "{") depth++
    if (chars[i] == "}") depth--
  }
  if (depth <= 0 && NR > start) {
    lines = NR - start + 1
    if (lines > '"$MAX_LINES"') {
      count++
    }
    in_func = 0
  }
}
END { print count+0 }
' "$FILE")

if [ "$count" -gt 0 ]; then
  echo ""
  echo "Found $count public method(s) in $FILE exceeding $MAX_LINES lines."
  echo "Business logic should live in internal/flows/*, not in the root engine."
  echo "Methods that delegate to flows.Service should be ≤ $MAX_LINES lines."
  if [ "$WARN_ONLY" = "1" ]; then
    echo "(DELEGATE_CHECK_WARN_ONLY=1 — treating as warning)"
    exit 0
  fi
  exit 1
else
  echo "All public Engine methods in $FILE are within the $MAX_LINES-line budget."
fi

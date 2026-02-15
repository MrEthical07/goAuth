# Email Verification Lifecycle

## What it does

Creates and confirms verification artifacts for account verification workflows.

## Main entry points

- `Engine.RequestEmailVerification`
- `Engine.ConfirmEmailVerification`

## Flow

request verification artifact → persist verification state in Redis with TTL and attempt limits → caller delivers artifact out-of-band → confirmation consumes artifact and updates account verification status through provider.

## Security behavior

- Verification artifacts are bounded by TTL and attempts.
- Consumption semantics prevent replay.

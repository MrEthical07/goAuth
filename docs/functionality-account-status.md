# Account Status Controls

## What it does

Exposes operational controls for account state transitions and session safety.

## Main entry points

- `Engine.DisableAccount`
- `Engine.EnableAccount`
- `Engine.LockAccount`
- `Engine.UnlockAccount`
- `Engine.DeleteAccount`

## Flow

status transition request → provider status update → affected session invalidation where required → audit event emission.

## Security behavior

- Disabled/locked/deleted accounts are blocked from normal auth flows.
- Administrative transitions are explicit and observable through audits.

# examples/session-profiles

A scripted walkthrough of goAuth **session profiles**: one engine serving two
kinds of client with different session lifetimes.

| Profile  | Model    | Lifetime |
|----------|----------|----------|
| `web`    | fixed    | ends 15 days after login, however often it is refreshed |
| `mobile` | renewing | ends after 90 days without a successful refresh; never later than 365 days after login |

## Run

```bash
go run ./examples/session-profiles
```

No external Redis required: it uses [miniredis](https://github.com/alicebob/miniredis) in-process.

## What it shows

1. Logging the same user in as `web` and as `mobile` with
   `goAuth.WithSessionProfile(ctx, name)`; the two sessions coexist.
2. `ListActiveSessions` reporting each session's `Profile`, its `ExpiresAt`
   ceiling and, for the renewing profile, `IdleExpiresAt`.
3. A refresh moving the mobile idle window forward while the ceiling stays
   put (the web session has no idle window to renew).
4. A profile name that is not configured being refused with
   `ErrUnknownSessionProfile` before any password is verified.

The profile is chosen by `profileFor`, from a server-side signal (which client
application's endpoint was called), never from input the end user controls.

See [docs/session.md](../../docs/session.md#session-profiles) for the full
model, the expiry math and the migration notes.

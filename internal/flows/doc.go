// Package flows contains pure-function orchestrators for every Engine operation.
//
// Each flow function (RunLogin, RunValidate, RunRefresh, etc.) accepts a typed
// dependency struct and returns results without side-effects beyond those
// dependencies. This design enables exhaustive unit testing with mock
// dependencies and keeps the Engine type thin.
//
// # Architecture boundaries
//
// Flow functions coordinate calls to session store, JWT manager, rate limiter,
// audit dispatcher, and metrics. They do NOT own any of these resources —
// ownership stays with the Engine.
//
// # What this package must NOT do
//
//   - Hold mutable state between calls.
//   - Import goAuth (to avoid import cycles).
//   - Perform I/O directly — all I/O is mediated through dependency interfaces.
package flows

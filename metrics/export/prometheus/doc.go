// Package prometheus provides Prometheus collectors for goAuth metrics.
//
// [NewPrometheusExporter] accepts an [goAuth.Engine] and exposes an [http.Handler]
// that renders all goAuth counters and histograms in Prometheus text exposition format.
// Counter names are prefixed goauth_*_total; the single histogram is
// goauth_validate_latency_seconds.
//
// # What this package must NOT do
//
//   - Register metrics in a global Prometheus registry — callers mount the Handler.
//   - Mutate engine state.
package prometheus

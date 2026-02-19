// Package otel provides OpenTelemetry metric exporter bindings for goAuth counters and
// histograms.
//
// [NewOTelExporter] registers Int64ObservableCounter instruments for each goAuth metric
// and Int64ObservableGauge per histogram bucket. A single callback reads
// [goAuth.Engine.MetricsSnapshot] on each collection cycle.
//
// # What this package must NOT do
//
//   - Own the OTel MeterProvider — callers supply the Meter.
//   - Mutate engine state.
package otel

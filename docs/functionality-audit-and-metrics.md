# Audit and Metrics Emission

## What it does

Records security-significant events and publishes operational counters/histograms.

## Main entry points

- Audit primitives in `audit.go` and `audit_dispatcher.go`
- `Engine.MetricsSnapshot`
- Exporters under `metrics/export/prometheus` and `metrics/export/otel`

## Flow

auth/account event → emit audit event to configured sink/dispatcher → increment metrics counters and optional latency histograms → exporter renders/publishes data.

## Concurrency & performance

- Metrics increments are atomic and allocation-light in hot paths.
- Dispatcher buffering can drop events under sustained pressure; dropped counts are exposed.

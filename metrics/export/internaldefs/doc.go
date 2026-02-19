// Package internaldefs exposes stable metric name and label definitions shared by
// exporter implementations.
//
// Counter and histogram definitions live here so that both the Prometheus and OTel
// exporters share identical metric names and bucket boundaries. Changes to definitions
// in this package affect all exporters simultaneously.
//
// # What this package must NOT do
//
//   - Import goAuth or any exporter package.
//   - Perform I/O.
package internaldefs

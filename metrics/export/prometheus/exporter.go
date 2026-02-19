package prometheus

import (
	"net/http"
	"strconv"
	"strings"

	goAuth "github.com/MrEthical07/goAuth"
	"github.com/MrEthical07/goAuth/metrics/export/internaldefs"
)

type metricsSource interface {
	MetricsSnapshot() goAuth.MetricsSnapshot
	AuditDropped() uint64
}

// PrometheusExporter renders goAuth metrics in Prometheus text exposition format.
//
//	Docs: docs/metrics.md
type PrometheusExporter struct {
	source metricsSource
}

// NewPrometheusExporter creates a Prometheus exporter that reads from the given [goAuth.Engine].
//
//	Docs: docs/metrics.md
func NewPrometheusExporter(engine *goAuth.Engine) *PrometheusExporter {
	return &PrometheusExporter{source: engine}
}

// NewPrometheusExporterFromSource creates a Prometheus exporter from a
// custom [MetricsSource].
//
//	Docs: docs/metrics.md
func NewPrometheusExporterFromSource(source metricsSource) *PrometheusExporter {
	return &PrometheusExporter{source: source}
}

// Handler returns an http.Handler that serves Prometheus metrics.
//
//	Docs: docs/metrics.md
func (p *PrometheusExporter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(p.Render()))
	})
}

// Render writes the current metrics in Prometheus text exposition format.
//
//	Docs: docs/metrics.md
func (p *PrometheusExporter) Render() string {
	if p == nil || p.source == nil {
		return ""
	}

	snapshot := p.source.MetricsSnapshot()
	dropped := p.source.AuditDropped()
	if len(snapshot.Counters) == 0 && len(snapshot.Histograms) == 0 && dropped == 0 {
		return ""
	}

	var b strings.Builder
	b.Grow(8192)

	for _, def := range internaldefs.CounterDefs {
		writeCounter(&b, def.Name, def.Help, snapshot.Counters[def.ID])
	}

	for _, def := range internaldefs.HistogramDefs {
		nonCumulative := internaldefs.NormalizeBuckets(snapshot.Histograms[def.ID])
		cumulative := internaldefs.CumulativeBuckets(nonCumulative)
		writeHistogram(&b, def.Name, def.Help, cumulative)
	}

	writeCounter(&b, "goauth_audit_dropped_total", "Dropped audit events due to dispatcher backpressure.", dropped)

	return b.String()
}

func writeCounter(b *strings.Builder, name, help string, value uint64) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(escapeHelp(help))
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" counter\n")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(value, 10))
	b.WriteByte('\n')
}

func writeHistogram(b *strings.Builder, name, help string, cumulative [8]uint64) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(escapeHelp(help))
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" histogram\n")

	for i, le := range internaldefs.HistogramBounds {
		b.WriteString(name)
		b.WriteString("_bucket{le=\"")
		b.WriteString(le)
		b.WriteString("\"} ")
		b.WriteString(strconv.FormatUint(cumulative[i], 10))
		b.WriteByte('\n')
	}

	count := cumulative[len(cumulative)-1]
	b.WriteString(name)
	b.WriteString("_count ")
	b.WriteString(strconv.FormatUint(count, 10))
	b.WriteByte('\n')

	// Sum is not available in core snapshots; keep a stable field for compatibility.
	b.WriteString(name)
	b.WriteString("_sum 0\n")
}

func escapeHelp(help string) string {
	help = strings.ReplaceAll(help, "\\", "\\\\")
	help = strings.ReplaceAll(help, "\n", "\\n")
	return help
}

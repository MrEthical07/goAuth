package otel

import (
	"context"
	"errors"
	"fmt"

	goAuth "github.com/MrEthical07/goAuth"
	"github.com/MrEthical07/goAuth/metrics/export/internaldefs"
	"go.opentelemetry.io/otel/metric"
)

var (
	ErrNilMeter  = errors.New("nil meter")
	ErrNilSource = errors.New("nil metrics source")
)

type metricsSource interface {
	MetricsSnapshot() goAuth.MetricsSnapshot
	AuditDropped() uint64
}

type observedCounter struct {
	id         goAuth.MetricID
	instrument metric.Int64ObservableCounter
}

type observedHistogram struct {
	id      goAuth.MetricID
	buckets [8]metric.Int64ObservableGauge
	count   metric.Int64ObservableGauge
}

type OTelExporter struct {
	source       metricsSource
	registration metric.Registration
	counters     []observedCounter
	histograms   []observedHistogram
	auditDropped metric.Int64ObservableCounter
}

func NewOTelExporter(meter metric.Meter, engine *goAuth.Engine) (*OTelExporter, error) {
	return NewOTelExporterFromSource(meter, engine)
}

func NewOTelExporterFromSource(meter metric.Meter, source metricsSource) (*OTelExporter, error) {
	if meter == nil {
		return nil, ErrNilMeter
	}
	if source == nil {
		return nil, ErrNilSource
	}

	exporter := &OTelExporter{
		source:     source,
		counters:   make([]observedCounter, 0, len(internaldefs.CounterDefs)),
		histograms: make([]observedHistogram, 0, len(internaldefs.HistogramDefs)),
	}

	observables := make([]metric.Observable, 0, len(internaldefs.CounterDefs)+len(internaldefs.HistogramDefs)*9+1)

	for _, def := range internaldefs.CounterDefs {
		ins, err := meter.Int64ObservableCounter(def.Name, metric.WithDescription(def.Help))
		if err != nil {
			return nil, fmt.Errorf("create observable counter %s: %w", def.Name, err)
		}
		exporter.counters = append(exporter.counters, observedCounter{id: def.ID, instrument: ins})
		observables = append(observables, ins)
	}

	for _, def := range internaldefs.HistogramDefs {
		h := observedHistogram{id: def.ID}
		for i := 0; i < len(internaldefs.HistogramBoundSuffix); i++ {
			name := def.Name + "_bucket_le_" + internaldefs.HistogramBoundSuffix[i]
			ins, err := meter.Int64ObservableGauge(name, metric.WithDescription("Cumulative histogram bucket count."))
			if err != nil {
				return nil, fmt.Errorf("create histogram bucket gauge %s: %w", name, err)
			}
			h.buckets[i] = ins
			observables = append(observables, ins)
		}
		countName := def.Name + "_count"
		countIns, err := meter.Int64ObservableGauge(countName, metric.WithDescription("Histogram total sample count."))
		if err != nil {
			return nil, fmt.Errorf("create histogram count gauge %s: %w", countName, err)
		}
		h.count = countIns
		observables = append(observables, countIns)
		exporter.histograms = append(exporter.histograms, h)
	}

	auditDropped, err := meter.Int64ObservableCounter(
		"goauth_audit_dropped_total",
		metric.WithDescription("Dropped audit events due to dispatcher backpressure."),
	)
	if err != nil {
		return nil, fmt.Errorf("create audit dropped counter: %w", err)
	}
	exporter.auditDropped = auditDropped
	observables = append(observables, auditDropped)

	registration, err := meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		snapshot := exporter.source.MetricsSnapshot()
		for _, c := range exporter.counters {
			observer.ObserveInt64(c.instrument, int64(snapshot.Counters[c.id]))
		}
		for _, h := range exporter.histograms {
			nonCumulative := internaldefs.NormalizeBuckets(snapshot.Histograms[h.id])
			cumulative := internaldefs.CumulativeBuckets(nonCumulative)
			for i := 0; i < len(cumulative); i++ {
				observer.ObserveInt64(h.buckets[i], int64(cumulative[i]))
			}
			observer.ObserveInt64(h.count, int64(cumulative[len(cumulative)-1]))
		}
		observer.ObserveInt64(exporter.auditDropped, int64(exporter.source.AuditDropped()))
		return nil
	}, observables...)
	if err != nil {
		return nil, fmt.Errorf("register callback: %w", err)
	}

	exporter.registration = registration
	return exporter, nil
}

func (e *OTelExporter) Close() error {
	if e == nil || e.registration == nil {
		return nil
	}
	return e.registration.Unregister()
}

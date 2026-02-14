package prometheus

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	goAuth "github.com/MrEthical07/goAuth"
)

type fakeSource struct {
	snapshot goAuth.MetricsSnapshot
	dropped  uint64
}

func (f fakeSource) MetricsSnapshot() goAuth.MetricsSnapshot { return f.snapshot }
func (f fakeSource) AuditDropped() uint64                    { return f.dropped }

func TestRenderEmptyWhenMetricsDisabled(t *testing.T) {
	exp := NewPrometheusExporterFromSource(fakeSource{
		snapshot: goAuth.MetricsSnapshot{
			Counters:   map[goAuth.MetricID]uint64{},
			Histograms: map[goAuth.MetricID][]uint64{},
		},
		dropped: 0,
	})

	if got := exp.Render(); got != "" {
		t.Fatalf("expected empty output for disabled metrics, got:\n%s", got)
	}
}

func TestRenderDeterministicIncludesCounterAndHistogram(t *testing.T) {
	exp := NewPrometheusExporterFromSource(fakeSource{
		snapshot: goAuth.MetricsSnapshot{
			Counters: map[goAuth.MetricID]uint64{
				goAuth.MetricLoginSuccess: 7,
			},
			Histograms: map[goAuth.MetricID][]uint64{
				goAuth.MetricValidateLatency: {1, 2, 3, 4, 5, 6, 7, 8},
			},
		},
		dropped: 2,
	})

	out := exp.Render()
	if !strings.Contains(out, "goauth_login_success_total 7") {
		t.Fatalf("expected login_success counter in output, got:\n%s", out)
	}
	if !strings.Contains(out, "goauth_validate_latency_seconds_bucket{le=\"0.005\"} 1") {
		t.Fatalf("expected first histogram bucket in output, got:\n%s", out)
	}
	if !strings.Contains(out, "goauth_validate_latency_seconds_bucket{le=\"+Inf\"} 36") {
		t.Fatalf("expected +Inf cumulative bucket in output, got:\n%s", out)
	}
	if !strings.Contains(out, "goauth_audit_dropped_total 2") {
		t.Fatalf("expected audit dropped counter in output, got:\n%s", out)
	}
}

func TestHandlerWritesPrometheusContentType(t *testing.T) {
	exp := NewPrometheusExporterFromSource(fakeSource{
		snapshot: goAuth.MetricsSnapshot{
			Counters:   map[goAuth.MetricID]uint64{goAuth.MetricLoginSuccess: 1},
			Histograms: map[goAuth.MetricID][]uint64{},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	exp.Handler().ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Fatalf("expected prometheus content type, got %q", got)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func BenchmarkRender(b *testing.B) {
	exp := NewPrometheusExporterFromSource(fakeSource{
		snapshot: goAuth.MetricsSnapshot{
			Counters: map[goAuth.MetricID]uint64{
				goAuth.MetricLoginSuccess:                1000,
				goAuth.MetricLoginFailure:                40,
				goAuth.MetricRefreshSuccess:              800,
				goAuth.MetricRefreshFailure:              10,
				goAuth.MetricSessionCreated:              800,
				goAuth.MetricSessionInvalidated:          20,
				goAuth.MetricPasswordResetConfirmFailure: 3,
			},
			Histograms: map[goAuth.MetricID][]uint64{
				goAuth.MetricValidateLatency: {10, 20, 30, 40, 50, 60, 70, 80},
			},
		},
		dropped: 0,
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = exp.Render()
	}
}

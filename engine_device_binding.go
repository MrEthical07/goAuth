package goAuth

import (
	"context"
	"time"

	internalflows "github.com/MrEthical07/goAuth/internal/flows"
	"github.com/MrEthical07/goAuth/internal"
	"github.com/MrEthical07/goAuth/session"
)

const deviceAnomalyWindow = time.Minute

func (e *Engine) validateDeviceBinding(ctx context.Context, sess *session.Session) error {
	if e == nil || sess == nil || !e.config.DeviceBinding.Enabled {
		return nil
	}
	return internalflows.RunValidateDeviceBinding(ctx, internalflows.DeviceBindingSession{
		SessionID:     sess.SessionID,
		UserID:        sess.UserID,
		TenantID:      sess.TenantID,
		IPHash:        sess.IPHash,
		UserAgentHash: sess.UserAgentHash,
	}, internalflows.DeviceBindingDeps{
		Config: internalflows.DeviceBindingConfig{
			Enabled:                 e.config.DeviceBinding.Enabled,
			EnforceIPBinding:        e.config.DeviceBinding.EnforceIPBinding,
			DetectIPChange:          e.config.DeviceBinding.DetectIPChange,
			EnforceUserAgentBinding: e.config.DeviceBinding.EnforceUserAgentBinding,
			DetectUserAgentChange:   e.config.DeviceBinding.DetectUserAgentChange,
		},
		ClientIPFromContext:        clientIPFromContext,
		UserAgentFromContext:       userAgentFromContext,
		HashBindingValue:           internal.HashBindingValue,
		ShouldEmitDeviceAnomaly:    e.shouldEmitDeviceAnomaly,
		MetricInc:                  func(id int) { e.metricInc(MetricID(id)) },
		EmitAudit:                  e.emitAudit,
		EventDeviceAnomalyDetected: auditEventDeviceAnomalyDetected,
		EventDeviceBindingRejected: auditEventDeviceBindingRejected,
		MetricDeviceIPMismatch:     int(MetricDeviceIPMismatch),
		MetricDeviceUAMismatch:     int(MetricDeviceUAMismatch),
		MetricDeviceRejected:       int(MetricDeviceRejected),
		ErrDeviceBindingRejected:   ErrDeviceBindingRejected,
	})
}

func (e *Engine) shouldEmitDeviceAnomaly(ctx context.Context, sessionID, kind string) bool {
	if e == nil || e.sessionStore == nil || sessionID == "" {
		return true
	}
	ok, err := e.sessionStore.ShouldEmitDeviceAnomaly(ctx, sessionID, kind, deviceAnomalyWindow)
	if err != nil {
		return false
	}
	return ok
}

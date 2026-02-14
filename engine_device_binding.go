package goAuth

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/MrEthical07/goAuth/internal"
	"github.com/MrEthical07/goAuth/session"
)

const deviceAnomalyWindow = time.Minute

func (e *Engine) validateDeviceBinding(ctx context.Context, sess *session.Session) error {
	if e == nil || sess == nil || !e.config.DeviceBinding.Enabled {
		return nil
	}

	cfg := e.config.DeviceBinding

	ipMismatch := false
	ipEmit := false
	if cfg.EnforceIPBinding || cfg.DetectIPChange {
		storedPresent := !isZeroHash(sess.IPHash)
		currentIP, currentPresent := bindingFromContext(clientIPFromContext(ctx))
		ipMismatch = bindingMismatch(storedPresent, sess.IPHash, currentPresent, currentIP, cfg.EnforceIPBinding)
		if ipMismatch {
			ipEmit = e.shouldEmitDeviceAnomaly(ctx, sess.SessionID, "ip")
		}
	}

	uaMismatch := false
	uaEmit := false
	if cfg.EnforceUserAgentBinding || cfg.DetectUserAgentChange {
		storedPresent := !isZeroHash(sess.UserAgentHash)
		currentUA, currentPresent := bindingFromContext(userAgentFromContext(ctx))
		uaMismatch = bindingMismatch(storedPresent, sess.UserAgentHash, currentPresent, currentUA, cfg.EnforceUserAgentBinding)
		if uaMismatch {
			uaEmit = e.shouldEmitDeviceAnomaly(ctx, sess.SessionID, "ua")
		}
	}

	if ipMismatch && ipEmit {
		e.metricInc(MetricDeviceIPMismatch)
	}
	if uaMismatch && uaEmit {
		e.metricInc(MetricDeviceUAMismatch)
	}

	if ((ipMismatch && cfg.DetectIPChange && ipEmit) || (uaMismatch && cfg.DetectUserAgentChange && uaEmit)) &&
		e.shouldEmitDeviceAnomaly(ctx, sess.SessionID, "detect") {
		e.emitAudit(ctx, auditEventDeviceAnomalyDetected, true, sess.UserID, sess.TenantID, sess.SessionID, nil, func() map[string]string {
			meta := map[string]string{}
			if ipMismatch && cfg.DetectIPChange {
				meta["ip_mismatch"] = "1"
			}
			if uaMismatch && cfg.DetectUserAgentChange {
				meta["ua_mismatch"] = "1"
			}
			return meta
		})
	}

	if (ipMismatch && cfg.EnforceIPBinding) || (uaMismatch && cfg.EnforceUserAgentBinding) {
		if e.shouldEmitDeviceAnomaly(ctx, sess.SessionID, "reject") {
			e.metricInc(MetricDeviceRejected)
			e.emitAudit(ctx, auditEventDeviceBindingRejected, false, sess.UserID, sess.TenantID, sess.SessionID, ErrDeviceBindingRejected, func() map[string]string {
				meta := map[string]string{}
				if ipMismatch && cfg.EnforceIPBinding {
					meta["enforced_ip_mismatch"] = "1"
				}
				if uaMismatch && cfg.EnforceUserAgentBinding {
					meta["enforced_ua_mismatch"] = "1"
				}
				return meta
			})
		}
		return ErrDeviceBindingRejected
	}

	return nil
}

func bindingFromContext(v string) ([32]byte, bool) {
	if v == "" {
		return [32]byte{}, false
	}
	return internal.HashBindingValue(v), true
}

func isZeroHash(h [32]byte) bool {
	var zero [32]byte
	return subtle.ConstantTimeCompare(h[:], zero[:]) == 1
}

func bindingMismatch(storedPresent bool, storedHash [32]byte, currentPresent bool, currentHash [32]byte, enforce bool) bool {
	if enforce {
		if !storedPresent || !currentPresent {
			return true
		}
		return subtle.ConstantTimeCompare(storedHash[:], currentHash[:]) != 1
	}
	if !storedPresent && !currentPresent {
		return false
	}
	if !storedPresent || !currentPresent {
		return true
	}
	return subtle.ConstantTimeCompare(storedHash[:], currentHash[:]) != 1
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

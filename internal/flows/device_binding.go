package flows

import (
	"context"
	"crypto/subtle"
)

type DeviceBindingSession struct {
	SessionID     string
	UserID        string
	TenantID      string
	IPHash        [32]byte
	UserAgentHash [32]byte
}

type DeviceBindingConfig struct {
	Enabled                 bool
	EnforceIPBinding        bool
	DetectIPChange          bool
	EnforceUserAgentBinding bool
	DetectUserAgentChange   bool
}

type DeviceBindingDeps struct {
	Config                    DeviceBindingConfig
	ClientIPFromContext       func(context.Context) string
	UserAgentFromContext      func(context.Context) string
	HashBindingValue          func(string) [32]byte
	ShouldEmitDeviceAnomaly   func(context.Context, string, string) bool
	MetricInc                 func(int)
	EmitAudit                 func(context.Context, string, bool, string, string, string, error, func() map[string]string)
	EventDeviceAnomalyDetected string
	EventDeviceBindingRejected string
	MetricDeviceIPMismatch    int
	MetricDeviceUAMismatch    int
	MetricDeviceRejected      int
	ErrDeviceBindingRejected  error
}

func RunValidateDeviceBinding(ctx context.Context, sess DeviceBindingSession, deps DeviceBindingDeps) error {
	if !deps.Config.Enabled {
		return nil
	}

	ipMismatch := false
	ipEmit := false
	if deps.Config.EnforceIPBinding || deps.Config.DetectIPChange {
		storedPresent := !isZeroHash(sess.IPHash)
		currentIP, currentPresent := bindingFromContext(deps.ClientIPFromContext(ctx), deps.HashBindingValue)
		ipMismatch = bindingMismatch(storedPresent, sess.IPHash, currentPresent, currentIP, deps.Config.EnforceIPBinding)
		if ipMismatch {
			ipEmit = deps.ShouldEmitDeviceAnomaly(ctx, sess.SessionID, "ip")
		}
	}

	uaMismatch := false
	uaEmit := false
	if deps.Config.EnforceUserAgentBinding || deps.Config.DetectUserAgentChange {
		storedPresent := !isZeroHash(sess.UserAgentHash)
		currentUA, currentPresent := bindingFromContext(deps.UserAgentFromContext(ctx), deps.HashBindingValue)
		uaMismatch = bindingMismatch(storedPresent, sess.UserAgentHash, currentPresent, currentUA, deps.Config.EnforceUserAgentBinding)
		if uaMismatch {
			uaEmit = deps.ShouldEmitDeviceAnomaly(ctx, sess.SessionID, "ua")
		}
	}

	if ipMismatch && ipEmit {
		deps.MetricInc(deps.MetricDeviceIPMismatch)
	}
	if uaMismatch && uaEmit {
		deps.MetricInc(deps.MetricDeviceUAMismatch)
	}

	if ((ipMismatch && deps.Config.DetectIPChange && ipEmit) || (uaMismatch && deps.Config.DetectUserAgentChange && uaEmit)) &&
		deps.ShouldEmitDeviceAnomaly(ctx, sess.SessionID, "detect") {
		deps.EmitAudit(ctx, deps.EventDeviceAnomalyDetected, true, sess.UserID, sess.TenantID, sess.SessionID, nil, func() map[string]string {
			meta := map[string]string{}
			if ipMismatch && deps.Config.DetectIPChange {
				meta["ip_mismatch"] = "1"
			}
			if uaMismatch && deps.Config.DetectUserAgentChange {
				meta["ua_mismatch"] = "1"
			}
			return meta
		})
	}

	if (ipMismatch && deps.Config.EnforceIPBinding) || (uaMismatch && deps.Config.EnforceUserAgentBinding) {
		if deps.ShouldEmitDeviceAnomaly(ctx, sess.SessionID, "reject") {
			deps.MetricInc(deps.MetricDeviceRejected)
			deps.EmitAudit(ctx, deps.EventDeviceBindingRejected, false, sess.UserID, sess.TenantID, sess.SessionID, deps.ErrDeviceBindingRejected, func() map[string]string {
				meta := map[string]string{}
				if ipMismatch && deps.Config.EnforceIPBinding {
					meta["enforced_ip_mismatch"] = "1"
				}
				if uaMismatch && deps.Config.EnforceUserAgentBinding {
					meta["enforced_ua_mismatch"] = "1"
				}
				return meta
			})
		}
		return deps.ErrDeviceBindingRejected
	}

	return nil
}

func bindingFromContext(v string, hashFn func(string) [32]byte) ([32]byte, bool) {
	if v == "" {
		return [32]byte{}, false
	}
	return hashFn(v), true
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

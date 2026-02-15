package rate

import "errors"

var (
	// ErrRateLimited is an exported constant or variable used by the authentication engine.
	ErrRateLimited = errors.New("rate limited")
	// ErrRedisUnavailable is an exported constant or variable used by the authentication engine.
	ErrRedisUnavailable = errors.New("redis unavailable")
)

package rate

import "errors"

var (
	ErrRateLimited      = errors.New("rate limited")
	ErrRedisUnavailable = errors.New("redis unavailable")
)

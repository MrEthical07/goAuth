package stores

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	// ErrExternalSignupNotFound means the handle is unknown, already used,
	// expired or belongs to another tenant.
	ErrExternalSignupNotFound = errors.New("external sign-up ticket not found")
	// ErrExternalSignupUnavailable means Redis could not be reached.
	ErrExternalSignupUnavailable = errors.New("external sign-up store unavailable")
)

const externalSignupRecordVersion = 1

// ExternalSignupRecord is the verified identity a deferred external sign-up
// holds between the two steps. It carries no token: the ID token was spent in
// step one.
type ExternalSignupRecord struct {
	Version        int    `json:"v"`
	TenantID       string `json:"t"`
	Provider       string `json:"p"`
	Subject        string `json:"s"`
	Email          string `json:"e"`
	EmailVerified  bool   `json:"ev"`
	IsPrivateEmail bool   `json:"pe,omitempty"`
	DisplayName    string `json:"n,omitempty"`
	ExpiresAt      int64  `json:"x"`
}

// ExternalSignupStore keeps deferred external sign-ups, one key per ticket:
// "<prefix>:<tenant>:<hex sha256 of the handle>". The handle itself is a bearer
// secret and is never stored; only its hash names the key, so a dump of Redis
// cannot be replayed.
type ExternalSignupStore struct {
	redis  redis.UniversalClient
	prefix string
	now    func() time.Time
}

// NewExternalSignupStore creates the store. An empty prefix selects "axs".
func NewExternalSignupStore(redisClient redis.UniversalClient, prefix string) *ExternalSignupStore {
	if prefix == "" {
		prefix = "axs"
	}
	return &ExternalSignupStore{redis: redisClient, prefix: prefix, now: time.Now}
}

// WithClock sets the time source the store compares ticket expiry against (the
// wall clock by default) and returns the store. Call it before use.
func (s *ExternalSignupStore) WithClock(now func() time.Time) *ExternalSignupStore {
	s.now = nowFn(now)
	return s
}

func (s *ExternalSignupStore) key(tenantID, handle string) string {
	sum := sha256.Sum256([]byte(handle))
	return s.prefix + ":" + normalizeTenantID(tenantID) + ":" + hex.EncodeToString(sum[:])
}

// Save stores record under handle for ttl. The handle must not already exist;
// 32 random bytes make a collision a non-event, but a collision is refused
// rather than overwritten.
func (s *ExternalSignupStore) Save(ctx context.Context, tenantID, handle string, record ExternalSignupRecord, ttl time.Duration) error {
	record.Version = externalSignupRecordVersion
	record.TenantID = normalizeTenantID(tenantID)
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	ok, err := s.redis.SetNX(ctx, s.key(tenantID, handle), data, ttl).Result()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrExternalSignupUnavailable, err)
	}
	if !ok {
		return fmt.Errorf("%w: handle collision", ErrExternalSignupUnavailable)
	}
	return nil
}

// takeExternalSignupLua reads and deletes the ticket in one step, so of any
// number of concurrent callers exactly one gets it. It is a script and not
// GETDEL because GETDEL needs Redis 6.2 and the supported floor is 6.0.
//
// KEYS: ticket. Returns the stored value, or nil when there is none.
var takeExternalSignupLua = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if v then
  redis.call('DEL', KEYS[1])
end
return v
`)

// Take atomically reads and deletes the ticket: of any number of
// concurrent callers, exactly one gets the record. The ticket is consumed even
// when it turns out to be expired or foreign. A handle from another tenant is
// looked up under that tenant's key space and so is simply not found; the
// stored tenant is checked as well.
func (s *ExternalSignupStore) Take(ctx context.Context, tenantID, handle string) (*ExternalSignupRecord, error) {
	res, err := takeExternalSignupLua.Run(ctx, s.redis, []string{s.key(tenantID, handle)}).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrExternalSignupNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrExternalSignupUnavailable, err)
	}
	data, ok := res.(string)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected script result", ErrExternalSignupUnavailable)
	}
	var record ExternalSignupRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil || record.Version != externalSignupRecordVersion {
		return nil, ErrExternalSignupNotFound
	}
	if record.TenantID != normalizeTenantID(tenantID) {
		return nil, ErrExternalSignupNotFound
	}
	if s.now().Unix() > record.ExpiresAt {
		return nil, ErrExternalSignupNotFound
	}
	return &record, nil
}

// Delete removes the ticket. It is idempotent.
func (s *ExternalSignupStore) Delete(ctx context.Context, tenantID, handle string) error {
	if err := s.redis.Del(ctx, s.key(tenantID, handle)).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrExternalSignupUnavailable, err)
	}
	return nil
}

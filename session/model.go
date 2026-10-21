package session

// Session is the in-memory representation of a user session. It is serialized
// to Redis using the v5 binary wire format via [Encode]/[Decode], or the v6
// format when Profile is set.
type Session struct {
	// SchemaVersion is the on-wire session schema version decoded from Redis.
	// New writes encode with CurrentSchemaVersion, or with
	// ProfileSchemaVersion when Profile is non-empty.
	SchemaVersion uint8

	SessionID string
	UserID    string
	TenantID  string

	Role string

	Mask interface{}

	PermissionVersion uint32
	RoleVersion       uint32
	AccountVersion    uint32
	Status            uint8
	RefreshHash       [32]byte
	IPHash            [32]byte
	UserAgentHash     [32]byte

	CreatedAt int64
	ExpiresAt int64

	// Profile names the session profile the session was created under. Empty
	// for a legacy session, which is stored in the v5 format exactly as
	// before; a non-empty value is stored in the v6 format.
	Profile string

	// IdleExpiresAt is the unix time at which a renewing-profile session
	// lapses unless it is refreshed or used first. It is filled in by the
	// read-only getters from the key's remaining lifetime and is never
	// encoded; it is zero for legacy and fixed-profile sessions.
	IdleExpiresAt int64
}

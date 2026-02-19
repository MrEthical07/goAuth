package session

// Session is the in-memory representation of a user session. It is serialized
// to Redis using the v5 binary wire format via [Encode]/[Decode].
type Session struct {
	// SchemaVersion is the on-wire session schema version decoded from Redis.
	// New writes always encode with CurrentSchemaVersion.
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
}

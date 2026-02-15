package session

// Session defines a public type used by goAuth APIs.
//
// Session instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Session struct {
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

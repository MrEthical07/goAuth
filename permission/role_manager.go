package permission

import (
	"errors"
	"sync"
	"sync/atomic"
)

// RoleManager maps role names to pre-computed permission bitmasks.
// After [RoleManager.Freeze], masks are immutable and safe for concurrent reads.
//
//	Docs: docs/permission.md
type RoleManager struct {
	registry *Registry

	mu     sync.RWMutex
	roles  map[string]interface{}
	frozen atomic.Bool
}

// NewRoleManager creates a [RoleManager] backed by the given [Registry].
//
//	Docs: docs/permission.md
func NewRoleManager(registry *Registry) *RoleManager {
	return &RoleManager{
		registry: registry,
		roles:    make(map[string]interface{}),
	}
}

// RegisterRole creates a role with the given permissions and registers it.
// Must be called before [RoleManager.Freeze].
//
//	Docs: docs/permission.md
func (rm *RoleManager) RegisterRole(
	roleName string,
	permissionNames []string,
	maxBits int,
	rootReserved bool,
) error {

	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.frozen.Load() {
		return errors.New("role manager frozen")
	}

	if roleName == "" {
		return errors.New("role name empty")
	}

	if _, exists := rm.roles[roleName]; exists {
		return errors.New("role already registered")
	}

	var mask interface{}

	switch maxBits {
	case 64:
		m := Mask64(0)
		mask = &m
	case 128:
		mask = &Mask128{}
	case 256:
		mask = &Mask256{}
	case 512:
		mask = &Mask512{}
	default:
		return errors.New("invalid maxBits")
	}

	for _, perm := range permissionNames {
		bit, ok := rm.registry.Bit(perm)
		if !ok {
			return errors.New("permission not registered: " + perm)
		}

		switch m := mask.(type) {
		case *Mask64:
			m.Set(bit)
		case *Mask128:
			m.Set(bit)
		case *Mask256:
			m.Set(bit)
		case *Mask512:
			m.Set(bit)
		}
	}

	rm.roles[roleName] = mask
	return nil
}

/*
====================================
GET MASK FOR ROLE
*/

// GetMask returns the pre-computed bitmask for the named role, or false
// if the role is not registered.
func (rm *RoleManager) GetMask(roleName string) (interface{}, bool) {
	// Post-freeze lookups are lock-free: role masks are immutable after Build().
	if rm.frozen.Load() {
		mask, ok := rm.roles[roleName]
		return mask, ok
	}

	rm.mu.RLock()
	defer rm.mu.RUnlock()

	mask, ok := rm.roles[roleName]
	return mask, ok
}

/*
====================================
FREEZE
*/

// Freeze prevents further role registrations.
func (rm *RoleManager) Freeze() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.frozen.Store(true)
}

/*
====================================
COUNT
*/

// Count returns the number of registered roles.
func (rm *RoleManager) Count() int {
	if rm.frozen.Load() {
		return len(rm.roles)
	}

	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return len(rm.roles)
}

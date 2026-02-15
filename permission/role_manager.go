package permission

import (
	"errors"
	"sync"
)

// RoleManager defines a public type used by goAuth APIs.
//
// RoleManager instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type RoleManager struct {
	registry *Registry

	mu     sync.RWMutex
	roles  map[string]interface{}
	frozen bool
}

// NewRoleManager describes the newrolemanager operation and its observable behavior.
//
// NewRoleManager may return an error when input validation, dependency calls, or security checks fail.
// NewRoleManager does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func NewRoleManager(registry *Registry) *RoleManager {
	return &RoleManager{
		registry: registry,
		roles:    make(map[string]interface{}),
	}
}

// RegisterRole describes the registerrole operation and its observable behavior.
//
// RegisterRole may return an error when input validation, dependency calls, or security checks fail.
// RegisterRole does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (rm *RoleManager) RegisterRole(
	roleName string,
	permissionNames []string,
	maxBits int,
	rootReserved bool,
) error {

	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.frozen {
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

// GetMask describes the getmask operation and its observable behavior.
//
// GetMask may return an error when input validation, dependency calls, or security checks fail.
// GetMask does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (rm *RoleManager) GetMask(roleName string) (interface{}, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	mask, ok := rm.roles[roleName]
	return mask, ok
}

/*
====================================
FREEZE
*/

// Freeze describes the freeze operation and its observable behavior.
//
// Freeze may return an error when input validation, dependency calls, or security checks fail.
// Freeze does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (rm *RoleManager) Freeze() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.frozen = true
}

/*
====================================
COUNT
*/

// Count describes the count operation and its observable behavior.
//
// Count may return an error when input validation, dependency calls, or security checks fail.
// Count does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (rm *RoleManager) Count() int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return len(rm.roles)
}

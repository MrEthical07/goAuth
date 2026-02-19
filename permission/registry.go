package permission

import (
	"errors"
	"sync"
)

// Registry maps permission names to bit positions within a bitmask.
// Supports widths of 64, 128, 256, or 512 bits.
//
//	Docs: docs/permission.md
type Registry struct {
	maxBits      int
	rootReserved bool
	rootBit      int

	mu        sync.RWMutex
	nameToBit map[string]int
	bitToName map[int]string
	frozen    bool
}

// NewRegistry creates a permission [Registry] that maps permission names
// to bit positions. maxBits selects the mask width (64/128/256/512);
// rootBitReserved reserves bit 0 for a super-admin root permission.
//
//	Docs: docs/permission.md
func NewRegistry(maxBits int, rootReserved bool) (*Registry, error) {
	if maxBits != 64 && maxBits != 128 && maxBits != 256 && maxBits != 512 {
		return nil, errors.New("invalid maxBits")
	}

	r := &Registry{
		maxBits:      maxBits,
		rootReserved: rootReserved,
		nameToBit:    make(map[string]int),
		bitToName:    make(map[int]string),
	}

	if rootReserved {
		r.rootBit = maxBits - 1
	}

	return r, nil
}

// Register assigns the next available bit to the named permission.
// Returns the assigned bit index. Must be called before [Registry.Freeze].
//
//	Docs: docs/permission.md
func (r *Registry) Register(name string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.frozen {
		return -1, errors.New("registry frozen")
	}

	if name == "" {
		return -1, errors.New("permission name cannot be empty")
	}

	if _, exists := r.nameToBit[name]; exists {
		return -1, errors.New("permission already registered")
	}

	nextBit := len(r.nameToBit)

	if r.rootReserved && nextBit >= r.rootBit {
		return -1, errors.New("permission limit exceeded (root bit reserved)")
	}

	if !r.rootReserved && nextBit >= r.maxBits {
		return -1, errors.New("permission limit exceeded")
	}

	r.nameToBit[name] = nextBit
	r.bitToName[nextBit] = name

	return nextBit, nil
}

// Bit returns the bit index for the named permission, or false if not registered.
func (r *Registry) Bit(name string) (int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	bit, ok := r.nameToBit[name]
	return bit, ok
}

// Name returns the permission name for the given bit index, or false if unassigned.
func (r *Registry) Name(bit int) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	name, ok := r.bitToName[bit]
	return name, ok
}

// Freeze prevents further registrations. Must be called before the
// registry is used for validation.
func (r *Registry) Freeze() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frozen = true
}

// Count returns the number of registered permissions.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.nameToBit)
}

// RootBit returns the reserved root permission bit, or false if root-bit
// reservation is disabled.
func (r *Registry) RootBit() (int, bool) {
	if !r.rootReserved {
		return -1, false
	}
	return r.rootBit, true
}

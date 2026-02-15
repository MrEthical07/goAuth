package permission

import (
	"errors"
	"sync"
)

// Registry defines a public type used by goAuth APIs.
//
// Registry instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Registry struct {
	maxBits      int
	rootReserved bool
	rootBit      int

	mu        sync.RWMutex
	nameToBit map[string]int
	bitToName map[int]string
	frozen    bool
}

// NewRegistry describes the newregistry operation and its observable behavior.
//
// NewRegistry may return an error when input validation, dependency calls, or security checks fail.
// NewRegistry does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
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

// Register describes the register operation and its observable behavior.
//
// Register may return an error when input validation, dependency calls, or security checks fail.
// Register does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
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

// Bit describes the bit operation and its observable behavior.
//
// Bit may return an error when input validation, dependency calls, or security checks fail.
// Bit does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (r *Registry) Bit(name string) (int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	bit, ok := r.nameToBit[name]
	return bit, ok
}

// Name describes the name operation and its observable behavior.
//
// Name may return an error when input validation, dependency calls, or security checks fail.
// Name does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (r *Registry) Name(bit int) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	name, ok := r.bitToName[bit]
	return name, ok
}

// Freeze describes the freeze operation and its observable behavior.
//
// Freeze may return an error when input validation, dependency calls, or security checks fail.
// Freeze does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (r *Registry) Freeze() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frozen = true
}

// Count describes the count operation and its observable behavior.
//
// Count may return an error when input validation, dependency calls, or security checks fail.
// Count does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.nameToBit)
}

// RootBit describes the rootbit operation and its observable behavior.
//
// RootBit may return an error when input validation, dependency calls, or security checks fail.
// RootBit does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (r *Registry) RootBit() (int, bool) {
	if !r.rootReserved {
		return -1, false
	}
	return r.rootBit, true
}

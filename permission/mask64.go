package permission

// Mask64 defines a public type used by goAuth APIs.
//
// Mask64 instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Mask64 uint64

// Has describes the has operation and its observable behavior.
//
// Has may return an error when input validation, dependency calls, or security checks fail.
// Has does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (m *Mask64) Has(bit int, rootReserved bool) bool {
	if bit < 0 || bit >= 64 {
		return false
	}

	if rootReserved {
		// root bit = highest bit
		if (*m & (1 << 63)) != 0 {
			return true
		}
	}

	return (*m & (1 << bit)) != 0
}

// Set describes the set operation and its observable behavior.
//
// Set may return an error when input validation, dependency calls, or security checks fail.
// Set does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (m *Mask64) Set(bit int) {
	if bit < 0 || bit >= 64 {
		return
	}
	*m |= (1 << bit)
}

// Clear describes the clear operation and its observable behavior.
//
// Clear may return an error when input validation, dependency calls, or security checks fail.
// Clear does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (m *Mask64) Clear(bit int) {
	if bit < 0 || bit >= 64 {
		return
	}
	*m &^= (1 << bit)
}

// Raw describes the raw operation and its observable behavior.
//
// Raw may return an error when input validation, dependency calls, or security checks fail.
// Raw does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (m *Mask64) Raw() uint64 {
	return uint64(*m)
}

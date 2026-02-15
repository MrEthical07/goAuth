package permission

// Mask128 defines a public type used by goAuth APIs.
//
// Mask128 instances are intended to be configured during initialization and then treated as immutable unless documented otherwise.
type Mask128 struct {
	A uint64
	B uint64
}

// Has describes the has operation and its observable behavior.
//
// Has may return an error when input validation, dependency calls, or security checks fail.
// Has does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (m *Mask128) Has(bit int, rootReserved bool) bool {
	if bit < 0 || bit >= 128 {
		return false
	}

	if rootReserved {
		// root bit = highest bit of B
		if (m.B & (1 << 63)) != 0 {
			return true
		}
	}

	if bit < 64 {
		return (m.A & (1 << bit)) != 0
	}

	return (m.B & (1 << (bit - 64))) != 0
}

// Set describes the set operation and its observable behavior.
//
// Set may return an error when input validation, dependency calls, or security checks fail.
// Set does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (m *Mask128) Set(bit int) {
	if bit < 0 || bit >= 128 {
		return
	}

	if bit < 64 {
		m.A |= (1 << bit)
	} else {
		m.B |= (1 << (bit - 64))
	}
}

// Clear describes the clear operation and its observable behavior.
//
// Clear may return an error when input validation, dependency calls, or security checks fail.
// Clear does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func (m *Mask128) Clear(bit int) {
	if bit < 0 || bit >= 128 {
		return
	}

	if bit < 64 {
		m.A &^= (1 << bit)
	} else {
		m.B &^= (1 << (bit - 64))
	}
}

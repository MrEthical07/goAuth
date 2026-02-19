package permission

// Mask128 is a 128-bit permission bitmask supporting up to 128 permissions.
type Mask128 struct {
	A uint64
	B uint64
}

// Has reports whether the given bit is set. If rootBitReserved is true
// and the root bit is set, Has returns true for all bits.
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

// Set sets the given bit in the mask.
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

// Clear clears the given bit in the mask.
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

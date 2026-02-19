package permission

// Mask64 is a 64-bit permission bitmask supporting up to 64 permissions.
type Mask64 uint64

// Has reports whether the given bit is set. If rootBitReserved is true
// and the root bit is set, Has returns true for all bits.
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

// Set sets the given bit in the mask.
func (m *Mask64) Set(bit int) {
	if bit < 0 || bit >= 64 {
		return
	}
	*m |= (1 << bit)
}

// Clear clears the given bit in the mask.
func (m *Mask64) Clear(bit int) {
	if bit < 0 || bit >= 64 {
		return
	}
	*m &^= (1 << bit)
}

// Raw returns the underlying uint64 value.
func (m *Mask64) Raw() uint64 {
	return uint64(*m)
}

package permission

type Mask64 uint64

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

func (m *Mask64) Set(bit int) {
	if bit < 0 || bit >= 64 {
		return
	}
	*m |= (1 << bit)
}

func (m *Mask64) Clear(bit int) {
	if bit < 0 || bit >= 64 {
		return
	}
	*m &^= (1 << bit)
}

func (m *Mask64) Raw() uint64 {
	return uint64(*m)
}

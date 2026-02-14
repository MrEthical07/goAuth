package permission

type Mask128 struct {
	A uint64
	B uint64
}

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

package permission

type Mask256 struct {
	A uint64
	B uint64
	C uint64
	D uint64
}

func (m *Mask256) Has(bit int, rootReserved bool) bool {
	if bit < 0 || bit >= 256 {
		return false
	}

	if rootReserved {
		// root bit = highest bit of D
		if (m.D & (1 << 63)) != 0 {
			return true
		}
	}

	switch {
	case bit < 64:
		return (m.A & (1 << bit)) != 0
	case bit < 128:
		return (m.B & (1 << (bit - 64))) != 0
	case bit < 192:
		return (m.C & (1 << (bit - 128))) != 0
	default:
		return (m.D & (1 << (bit - 192))) != 0
	}
}

func (m *Mask256) Set(bit int) {
	if bit < 0 || bit >= 256 {
		return
	}

	switch {
	case bit < 64:
		m.A |= (1 << bit)
	case bit < 128:
		m.B |= (1 << (bit - 64))
	case bit < 192:
		m.C |= (1 << (bit - 128))
	default:
		m.D |= (1 << (bit - 192))
	}
}

func (m *Mask256) Clear(bit int) {
	if bit < 0 || bit >= 256 {
		return
	}

	switch {
	case bit < 64:
		m.A &^= (1 << bit)
	case bit < 128:
		m.B &^= (1 << (bit - 64))
	case bit < 192:
		m.C &^= (1 << (bit - 128))
	default:
		m.D &^= (1 << (bit - 192))
	}
}

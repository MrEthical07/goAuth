package permission

type Mask512 struct {
	A uint64
	B uint64
	C uint64
	D uint64
	E uint64
	F uint64
	G uint64
	H uint64
}

func (m *Mask512) Has(bit int, rootReserved bool) bool {
	if bit < 0 || bit >= 512 {
		return false
	}

	if rootReserved {
		// root bit = highest bit of H
		if (m.H & (1 << 63)) != 0 {
			return true
		}
	}

	idx := bit / 64
	offset := bit % 64

	switch idx {
	case 0:
		return (m.A & (1 << offset)) != 0
	case 1:
		return (m.B & (1 << offset)) != 0
	case 2:
		return (m.C & (1 << offset)) != 0
	case 3:
		return (m.D & (1 << offset)) != 0
	case 4:
		return (m.E & (1 << offset)) != 0
	case 5:
		return (m.F & (1 << offset)) != 0
	case 6:
		return (m.G & (1 << offset)) != 0
	default:
		return (m.H & (1 << offset)) != 0
	}
}

func (m *Mask512) Set(bit int) {
	if bit < 0 || bit >= 512 {
		return
	}

	idx := bit / 64
	offset := bit % 64

	switch idx {
	case 0:
		m.A |= (1 << offset)
	case 1:
		m.B |= (1 << offset)
	case 2:
		m.C |= (1 << offset)
	case 3:
		m.D |= (1 << offset)
	case 4:
		m.E |= (1 << offset)
	case 5:
		m.F |= (1 << offset)
	case 6:
		m.G |= (1 << offset)
	case 7:
		m.H |= (1 << offset)
	}
}

func (m *Mask512) Clear(bit int) {
	if bit < 0 || bit >= 512 {
		return
	}

	idx := bit / 64
	offset := bit % 64

	switch idx {
	case 0:
		m.A &^= (1 << offset)
	case 1:
		m.B &^= (1 << offset)
	case 2:
		m.C &^= (1 << offset)
	case 3:
		m.D &^= (1 << offset)
	case 4:
		m.E &^= (1 << offset)
	case 5:
		m.F &^= (1 << offset)
	case 6:
		m.G &^= (1 << offset)
	case 7:
		m.H &^= (1 << offset)
	}
}

package permission

import (
	"encoding/binary"
	"errors"
)

// EncodeMask serializes a permission bitmask into a byte slice for JWT
// embedding.
//
//	Performance: O(1), single allocation.
//	Docs: docs/permission.md, docs/jwt.md
func EncodeMask(mask interface{}) ([]byte, error) {
	switch m := mask.(type) {
	case *Mask64:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(*m))
		return b, nil
	case *Mask128:
		b := make([]byte, 16)
		binary.BigEndian.PutUint64(b[0:], m.A)
		binary.BigEndian.PutUint64(b[8:], m.B)
		return b, nil
	case *Mask256:
		b := make([]byte, 32)
		binary.BigEndian.PutUint64(b[0:], m.A)
		binary.BigEndian.PutUint64(b[8:], m.B)
		binary.BigEndian.PutUint64(b[16:], m.C)
		binary.BigEndian.PutUint64(b[24:], m.D)
		return b, nil
	case *Mask512:
		b := make([]byte, 64)
		binary.BigEndian.PutUint64(b[0:], m.A)
		binary.BigEndian.PutUint64(b[8:], m.B)
		binary.BigEndian.PutUint64(b[16:], m.C)
		binary.BigEndian.PutUint64(b[24:], m.D)
		binary.BigEndian.PutUint64(b[32:], m.E)
		binary.BigEndian.PutUint64(b[40:], m.F)
		binary.BigEndian.PutUint64(b[48:], m.G)
		binary.BigEndian.PutUint64(b[56:], m.H)
		return b, nil
	default:
		return nil, errors.New("invalid mask type")
	}
}

// DecodeMask deserializes a byte slice back into a typed permission mask
// ([Mask64], [Mask128], [Mask256], or [Mask512]).
//
//	Performance: O(1).
//	Docs: docs/permission.md, docs/jwt.md
func DecodeMask(data []byte) (interface{}, error) {
	switch len(data) {
	case 8:
		val := binary.BigEndian.Uint64(data)
		m := Mask64(val)
		return &m, nil
	case 16:
		return &Mask128{
			A: binary.BigEndian.Uint64(data[0:8]),
			B: binary.BigEndian.Uint64(data[8:16]),
		}, nil
	case 32:
		return &Mask256{
			A: binary.BigEndian.Uint64(data[0:8]),
			B: binary.BigEndian.Uint64(data[8:16]),
			C: binary.BigEndian.Uint64(data[16:24]),
			D: binary.BigEndian.Uint64(data[24:32]),
		}, nil
	case 64:
		return &Mask512{
			A: binary.BigEndian.Uint64(data[0:8]),
			B: binary.BigEndian.Uint64(data[8:16]),
			C: binary.BigEndian.Uint64(data[16:24]),
			D: binary.BigEndian.Uint64(data[24:32]),
			E: binary.BigEndian.Uint64(data[32:40]),
			F: binary.BigEndian.Uint64(data[40:48]),
			G: binary.BigEndian.Uint64(data[48:56]),
			H: binary.BigEndian.Uint64(data[56:64]),
		}, nil
	default:
		return nil, errors.New("invalid mask size")
	}
}

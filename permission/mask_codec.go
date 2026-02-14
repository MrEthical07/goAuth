package permission

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func EncodeMask(mask interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)

	switch m := mask.(type) {
	case *Mask64:
		return uint64ToBytes(uint64(*m)), nil
	case *Mask128:
		binary.Write(buf, binary.BigEndian, m.A)
		binary.Write(buf, binary.BigEndian, m.B)
	case *Mask256:
		binary.Write(buf, binary.BigEndian, m.A)
		binary.Write(buf, binary.BigEndian, m.B)
		binary.Write(buf, binary.BigEndian, m.C)
		binary.Write(buf, binary.BigEndian, m.D)
	case *Mask512:
		binary.Write(buf, binary.BigEndian, m.A)
		binary.Write(buf, binary.BigEndian, m.B)
		binary.Write(buf, binary.BigEndian, m.C)
		binary.Write(buf, binary.BigEndian, m.D)
		binary.Write(buf, binary.BigEndian, m.E)
		binary.Write(buf, binary.BigEndian, m.F)
		binary.Write(buf, binary.BigEndian, m.G)
		binary.Write(buf, binary.BigEndian, m.H)
	default:
		return nil, errors.New("invalid mask type")
	}

	return buf.Bytes(), nil
}

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

func uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

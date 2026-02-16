package permission

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// EncodeMask describes the encodemask operation and its observable behavior.
//
// EncodeMask may return an error when input validation, dependency calls, or security checks fail.
// EncodeMask does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
func EncodeMask(mask interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	write := func(v uint64) error {
		return binary.Write(buf, binary.BigEndian, v)
	}

	switch m := mask.(type) {
	case *Mask64:
		return uint64ToBytes(uint64(*m)), nil
	case *Mask128:
		if err := write(m.A); err != nil {
			return nil, err
		}
		if err := write(m.B); err != nil {
			return nil, err
		}
	case *Mask256:
		if err := write(m.A); err != nil {
			return nil, err
		}
		if err := write(m.B); err != nil {
			return nil, err
		}
		if err := write(m.C); err != nil {
			return nil, err
		}
		if err := write(m.D); err != nil {
			return nil, err
		}
	case *Mask512:
		if err := write(m.A); err != nil {
			return nil, err
		}
		if err := write(m.B); err != nil {
			return nil, err
		}
		if err := write(m.C); err != nil {
			return nil, err
		}
		if err := write(m.D); err != nil {
			return nil, err
		}
		if err := write(m.E); err != nil {
			return nil, err
		}
		if err := write(m.F); err != nil {
			return nil, err
		}
		if err := write(m.G); err != nil {
			return nil, err
		}
		if err := write(m.H); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid mask type")
	}

	return buf.Bytes(), nil
}

// DecodeMask describes the decodemask operation and its observable behavior.
//
// DecodeMask may return an error when input validation, dependency calls, or security checks fail.
// DecodeMask does not mutate shared global state and can be used concurrently when the receiver and dependencies are concurrently safe.
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

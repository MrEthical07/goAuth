package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/MrEthical07/goAuth/permission"
)

const (
	sessionFormatVersionCurrent = 5
	sessionFormatVersionV4      = 4
	sessionFormatVersionV3      = 3
	sessionFormatVersionV2      = 2
	sessionFormatVersionV1      = 1
)

func Encode(s *Session) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteByte(sessionFormatVersionCurrent)

	if len(s.UserID) > 255 {
		return nil, errors.New("userID too long")
	}
	buf.WriteByte(byte(len(s.UserID)))
	buf.WriteString(s.UserID)

	if len(s.TenantID) > 255 {
		return nil, errors.New("tenantID too long")
	}
	buf.WriteByte(byte(len(s.TenantID)))
	buf.WriteString(s.TenantID)

	if len(s.Role) > 255 {
		return nil, errors.New("role too long")
	}
	buf.WriteByte(byte(len(s.Role)))
	buf.WriteString(s.Role)

	if err := binary.Write(&buf, binary.BigEndian, s.PermissionVersion); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, s.RoleVersion); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, s.AccountVersion); err != nil {
		return nil, err
	}
	buf.WriteByte(s.Status)

	maskBytes, err := permission.EncodeMask(s.Mask)
	if err != nil {
		return nil, err
	}

	if len(maskBytes) > 255 {
		return nil, errors.New("mask too large")
	}

	buf.WriteByte(byte(len(maskBytes)))
	buf.Write(maskBytes)

	buf.Write(s.RefreshHash[:])
	buf.Write(s.IPHash[:])
	buf.Write(s.UserAgentHash[:])

	if err := binary.Write(&buf, binary.BigEndian, s.CreatedAt); err != nil {
		return nil, err
	}

	if err := binary.Write(&buf, binary.BigEndian, s.ExpiresAt); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func Decode(data []byte) (*Session, error) {
	reader := bytes.NewReader(data)

	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != sessionFormatVersionCurrent &&
		version != sessionFormatVersionV4 &&
		version != sessionFormatVersionV3 &&
		version != sessionFormatVersionV2 &&
		version != sessionFormatVersionV1 {
		return nil, errors.New("invalid session version")
	}

	s := &Session{}

	userLen, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	userID := make([]byte, userLen)
	if _, err := io.ReadFull(reader, userID); err != nil {
		return nil, err
	}
	s.UserID = string(userID)

	tenantLen, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	tenantID := make([]byte, tenantLen)
	if _, err := io.ReadFull(reader, tenantID); err != nil {
		return nil, err
	}
	s.TenantID = string(tenantID)

	roleLen, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	role := make([]byte, roleLen)
	if _, err := io.ReadFull(reader, role); err != nil {
		return nil, err
	}
	s.Role = string(role)

	if err := binary.Read(reader, binary.BigEndian, &s.PermissionVersion); err != nil {
		return nil, err
	}
	if version == sessionFormatVersionCurrent || version == sessionFormatVersionV4 || version == sessionFormatVersionV3 {
		if err := binary.Read(reader, binary.BigEndian, &s.RoleVersion); err != nil {
			return nil, err
		}
	}
	if version == sessionFormatVersionCurrent || version == sessionFormatVersionV4 {
		if err := binary.Read(reader, binary.BigEndian, &s.AccountVersion); err != nil {
			return nil, err
		}

		status, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		s.Status = status
	} else {
		s.AccountVersion = 1
		s.Status = 0
	}

	maskSize, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	maskBytes := make([]byte, maskSize)
	if _, err := io.ReadFull(reader, maskBytes); err != nil {
		return nil, err
	}

	mask, err := permission.DecodeMask(maskBytes)
	if err != nil {
		return nil, err
	}
	s.Mask = mask

	if version == sessionFormatVersionCurrent || version == sessionFormatVersionV4 || version == sessionFormatVersionV3 || version == sessionFormatVersionV2 {
		if _, err := io.ReadFull(reader, s.RefreshHash[:]); err != nil {
			return nil, err
		}
	}
	if version == sessionFormatVersionCurrent {
		if _, err := io.ReadFull(reader, s.IPHash[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(reader, s.UserAgentHash[:]); err != nil {
			return nil, err
		}
	}

	if err := binary.Read(reader, binary.BigEndian, &s.CreatedAt); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.BigEndian, &s.ExpiresAt); err != nil {
		return nil, err
	}

	return s, nil
}

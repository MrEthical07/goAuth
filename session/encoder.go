package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/MrEthical07/goAuth/permission"
)

var errSessionTruncated = io.ErrUnexpectedEOF

const (
	// CurrentSchemaVersion is the schema version legacy sessions (those
	// without a profile) are encoded with, and the version older records are
	// migrated up to. It stays 5: raising it would rewrite every existing
	// session into a format earlier releases cannot read.
	CurrentSchemaVersion = 5

	// ProfileSchemaVersion is the schema version of a session created under a
	// named session profile. It is the v5 layout followed by a length-prefixed
	// profile name after ExpiresAt, and is written only for such sessions.
	// Migration never converts a v5 record into v6.
	ProfileSchemaVersion = 6

	// MaxProfileNameLen is the longest session profile name that can be
	// stored.
	MaxProfileNameLen = 32

	sessionFormatVersionProfile = ProfileSchemaVersion
	sessionFormatVersionCurrent = CurrentSchemaVersion
	sessionFormatVersionV4      = 4
	sessionFormatVersionV3      = 3
	sessionFormatVersionV2      = 2
	sessionFormatVersionV1      = 1
)

// Encode serializes a [Session] into a compact binary format (v5 wire
// protocol, or v6 when s.Profile is set). The result is stored as the Redis
// value.
//
//	Performance: single allocation; ~200 bytes per session.
//	Docs: docs/session.md
func Encode(s *Session) ([]byte, error) {
	var buf bytes.Buffer

	// A session with a profile is always v6 and one without is always v5;
	// SchemaVersion (zero, or what Decode read) must agree with that.
	schemaVersion := byte(sessionFormatVersionCurrent)
	if s.Profile != "" {
		schemaVersion = sessionFormatVersionProfile
	}
	if s.SchemaVersion != 0 && s.SchemaVersion != schemaVersion {
		return nil, fmt.Errorf("unsupported session schema version for encode: %d", s.SchemaVersion)
	}
	if len(s.Profile) > MaxProfileNameLen {
		return nil, errors.New("profile name too long")
	}

	buf.WriteByte(schemaVersion)

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

	if schemaVersion == sessionFormatVersionProfile {
		buf.WriteByte(byte(len(s.Profile)))
		buf.WriteString(s.Profile)
	}

	return buf.Bytes(), nil
}

// Decode deserializes the binary wire format back into a [Session].
// Returns an error if the version byte is unsupported or the payload is
// truncated.
//
//	Docs: docs/session.md
func Decode(data []byte) (*Session, error) {
	if len(data) < 1 {
		return nil, io.EOF
	}

	version := data[0]
	if version < sessionFormatVersionV1 || version > sessionFormatVersionProfile {
		return nil, fmt.Errorf("unsupported session schema version: %d", version)
	}

	s := &Session{SchemaVersion: version}
	pos := 1

	// --- String fields (direct byte indexing, no intermediate allocations) ---

	// UserID
	if pos >= len(data) {
		return nil, errSessionTruncated
	}
	n := int(data[pos])
	pos++
	if pos+n > len(data) {
		return nil, errSessionTruncated
	}
	s.UserID = string(data[pos : pos+n])
	pos += n

	// TenantID
	if pos >= len(data) {
		return nil, errSessionTruncated
	}
	n = int(data[pos])
	pos++
	if pos+n > len(data) {
		return nil, errSessionTruncated
	}
	s.TenantID = string(data[pos : pos+n])
	pos += n

	// Role
	if pos >= len(data) {
		return nil, errSessionTruncated
	}
	n = int(data[pos])
	pos++
	if pos+n > len(data) {
		return nil, errSessionTruncated
	}
	s.Role = string(data[pos : pos+n])
	pos += n

	// --- Versioned fixed fields ---

	// PermissionVersion (all versions)
	if pos+4 > len(data) {
		return nil, errSessionTruncated
	}
	s.PermissionVersion = binary.BigEndian.Uint32(data[pos:])
	pos += 4

	// RoleVersion (v3+)
	if version >= sessionFormatVersionV3 {
		if pos+4 > len(data) {
			return nil, errSessionTruncated
		}
		s.RoleVersion = binary.BigEndian.Uint32(data[pos:])
		pos += 4
	}

	// AccountVersion + Status (v4+)
	if version >= sessionFormatVersionV4 {
		if pos+5 > len(data) {
			return nil, errSessionTruncated
		}
		s.AccountVersion = binary.BigEndian.Uint32(data[pos:])
		pos += 4
		s.Status = data[pos]
		pos++
	} else {
		s.AccountVersion = 1
		s.Status = 0
	}

	// Mask (pass sub-slice directly to DecodeMask — no intermediate copy)
	if pos >= len(data) {
		return nil, errSessionTruncated
	}
	maskSize := int(data[pos])
	pos++
	if pos+maskSize > len(data) {
		return nil, errSessionTruncated
	}
	mask, err := permission.DecodeMask(data[pos : pos+maskSize])
	if err != nil {
		return nil, err
	}
	s.Mask = mask
	pos += maskSize

	// RefreshHash (v2+)
	if version >= sessionFormatVersionV2 {
		if pos+32 > len(data) {
			return nil, errSessionTruncated
		}
		copy(s.RefreshHash[:], data[pos:pos+32])
		pos += 32
	}

	// IPHash + UserAgentHash (v5+)
	if version >= sessionFormatVersionCurrent {
		if pos+64 > len(data) {
			return nil, errSessionTruncated
		}
		copy(s.IPHash[:], data[pos:pos+32])
		pos += 32
		copy(s.UserAgentHash[:], data[pos:pos+32])
		pos += 32
	}

	// Timestamps
	if pos+16 > len(data) {
		return nil, errSessionTruncated
	}
	s.CreatedAt = int64(binary.BigEndian.Uint64(data[pos:]))
	pos += 8
	s.ExpiresAt = int64(binary.BigEndian.Uint64(data[pos:]))
	pos += 8

	// Profile (v6): a non-empty name, at most MaxProfileNameLen bytes.
	if version >= sessionFormatVersionProfile {
		if pos >= len(data) {
			return nil, errSessionTruncated
		}
		n = int(data[pos])
		pos++
		if n < 1 || n > MaxProfileNameLen {
			return nil, errors.New("invalid session profile name length")
		}
		if pos+n > len(data) {
			return nil, errSessionTruncated
		}
		s.Profile = string(data[pos : pos+n])
	}

	return s, nil
}

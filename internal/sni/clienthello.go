// Package sni parses the Server Name Indication extension from TLS ClientHello messages.
// Supports TLS 1.0 through 1.3 per RFC 6066 section 3.
package sni

import (
	"encoding/binary"
	"fmt"
)

const (
	sniExtensionType = 0x0000
)

// Parse extracts the SNI hostname from a TLS ClientHello record.
// data must begin with the TLS record header (content type, version, length).
// Returns empty string if no SNI extension is present.
func Parse(data []byte) (string, error) {
	if len(data) < 5 {
		return "", fmt.Errorf("record too short: %d bytes", len(data))
	}

	contentType := data[0]
	if contentType != 0x16 {
		return "", fmt.Errorf("not a TLS handshake record: type 0x%02x", contentType)
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return "", fmt.Errorf("truncated record: have %d, want %d", len(data), 5+recordLen)
	}

	payload := data[5 : 5+recordLen]
	if len(payload) < 4 {
		return "", fmt.Errorf("handshake payload too short: %d", len(payload))
	}

	msgType := payload[0]
	if msgType != 0x01 {
		return "", fmt.Errorf("not a ClientHello: msg_type %d", msgType)
	}

	return parseClientHelloBody(payload[4:])
}

func parseClientHelloBody(body []byte) (string, error) {
	pos := 0

	// client_version (2 bytes)
	if len(body) < pos+2 {
		return "", fmt.Errorf("truncated at version")
	}
	pos += 2

	// random (32 bytes)
	if len(body) < pos+32 {
		return "", fmt.Errorf("truncated at random")
	}
	pos += 32

	// session_id
	if len(body) < pos+1 {
		return "", fmt.Errorf("truncated at session_id length")
	}
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if len(body) < pos {
		return "", fmt.Errorf("truncated at session_id")
	}

	// cipher_suites
	if len(body) < pos+2 {
		return "", fmt.Errorf("truncated at cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2 + csLen
	if len(body) < pos {
		return "", fmt.Errorf("truncated at cipher_suites")
	}

	// compression_methods
	if len(body) < pos+1 {
		return "", fmt.Errorf("truncated at compression length")
	}
	cmLen := int(body[pos])
	pos += 1 + cmLen
	if len(body) < pos {
		return "", fmt.Errorf("truncated at compression_methods")
	}

	// extensions (optional)
	if pos == len(body) {
		return "", nil
	}
	if len(body) < pos+2 {
		return "", fmt.Errorf("truncated at extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	extEnd := pos + extLen
	if len(body) < extEnd {
		return "", fmt.Errorf("truncated in extensions")
	}

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[pos:])
		extDataLen := int(binary.BigEndian.Uint16(body[pos+2:]))
		pos += 4
		if pos+extDataLen > extEnd {
			return "", fmt.Errorf("extension data overflows")
		}
		if extType == sniExtensionType {
			return parseSNIExtension(body[pos : pos+extDataLen])
		}
		pos += extDataLen
	}

	return "", nil
}

func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("SNI extension too short")
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	end := 2 + listLen
	if len(data) < end {
		end = len(data)
	}
	data = data[2:end]

	pos := 0
	for pos+3 <= len(data) {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1:]))
		pos += 3
		if pos+nameLen > len(data) {
			return "", fmt.Errorf("SNI name overflows")
		}
		if nameType == 0x00 {
			return string(data[pos : pos+nameLen]), nil
		}
		pos += nameLen
	}

	return "", nil
}

package sni

import (
	"testing"
)

// Constructed TLS ClientHello with SNI extension for "api.example.com".
// Contains all required fields with correct lengths.
var realClientHello = []byte{
	// TLS Record Header: Handshake, TLS 1.0, length=71
	0x16, 0x03, 0x01, 0x00, 0x47,
	// Handshake Type: ClientHello (0x01), body length=67
	0x01, 0x00, 0x00, 0x43,
	// Client Version: TLS 1.2
	0x03, 0x03,
	// Random (32 bytes)
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	// Session ID: empty
	0x00,
	// Cipher Suites: 1 suite (TLS_RSA_WITH_AES_128_CBC_SHA)
	0x00, 0x02, 0x00, 0x2F,
	// Compression Methods: 1 method (null)
	0x01, 0x00,
	// Extensions block length: 24
	0x00, 0x18,
	// SNI Extension (type=0x0000, data length=20)
	0x00, 0x00, 0x00, 0x14,
	// Server Name List length: 18
	0x00, 0x12,
	// Server Name: type=host_name(0x00), length=15, "api.example.com"
	0x00, 0x00, 0x0F,
	0x61, 0x70, 0x69, 0x2E, 0x65, 0x78, 0x61, 0x6D,
	0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D,
}

func TestParseRealClientHello(t *testing.T) {
	// This test uses the embedded real ClientHello which contains SNI "api.example.com"
	sni, err := Parse(realClientHello)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if sni != "api.example.com" {
		t.Fatalf("expected SNI %q, got %q", "api.example.com", sni)
	}
}

func TestParseNonTLS(t *testing.T) {
	_, err := Parse([]byte("GET / HTTP/1.1\r\n"))
	if err == nil {
		t.Fatal("expected error for non-TLS data")
	}
}

func TestParseShortData(t *testing.T) {
	_, err := Parse([]byte{0x16, 0x03, 0x01})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestParseEmptyExtension(t *testing.T) {
	// Minimal ClientHello with no extensions
	hello := []byte{
		0x16,             // ContentType: handshake
		0x03, 0x01,       // Version: TLS 1.0
		0x00, 0x2f,       // Record payload length: 47
		0x01,             // HandshakeType: ClientHello
		0x00, 0x00, 0x2b, // Body length: 43
		0x03, 0x03,       // ClientVersion: TLS 1.2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random bytes 0-7
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random bytes 8-15
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random bytes 16-23
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random bytes 24-31
		0x00,                   // SessionID length: 0
		0x00, 0x02, 0x00, 0x00, // CipherSuites: 1 suite (TLS_NULL_WITH_NULL_NULL)
		0x01, 0x00, // CompressionMethods: 1 method (null)
		0x00, 0x00, // Extensions length: 0
	}
	sni, err := Parse(hello)
	if err != nil {
		t.Fatalf("Parse failed for no-extension hello: %v", err)
	}
	if sni != "" {
		t.Fatalf("expected empty SNI, got %q", sni)
	}
}

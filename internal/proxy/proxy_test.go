package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"sniproxy/internal/router"
)

func TestProxySNIRouting(t *testing.T) {
	// Start backend TLS servers (echo servers)
	backend1 := startTLSEchoServer(t)
	backend2 := startTLSEchoServer(t)
	backendDefault := startTLSEchoServer(t)

	r := router.New(map[string][]string{
		backend1.Addr:   {"api.example.com"},
		backend2.Addr:   {"*.other.com"},
	}, backendDefault.Addr)

	// Start proxy listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := ln.Addr().String()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go AcceptLoop(ctx, ln, r, logger)
	time.Sleep(100 * time.Millisecond) // let accept loop start

	// Test exact match: connect with SNI "api.example.com"
	conn1, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName:         "api.example.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("exact match dial: %v", err)
	}
	// Verify connection works (handshake completed with backend)
	conn1.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 32)
	conn1.Write([]byte("hello"))
	n, err := conn1.Read(buf)
	if err != nil {
		t.Fatalf("exact match read: %v", err)
	}
	if n == 0 {
		t.Fatal("exact match: no data echoed")
	}
	conn1.Close()

	// Test wildcard match
	conn2, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName:         "foo.other.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("wildcard dial: %v", err)
	}
	conn2.Close()

	// Test default fallback
	conn3, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName:         "unknown.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("default fallback dial: %v", err)
	}
	conn3.Close()
}

// startTLSEchoServer starts a TLS echo server on a random port.
func startTLSEchoServer(t *testing.T) *tlsServer {
	t.Helper()
	cert := generateSelfSignedCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &tlsServer{Addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				io.Copy(c, c) // echo
				c.Close()
			}(conn)
		}
	}()
	return s
}

type tlsServer struct {
	Addr string
	ln   net.Listener
}

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

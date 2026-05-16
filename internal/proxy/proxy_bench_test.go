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
	"testing"
	"time"

	"sniproxy/internal/router"
	"sniproxy/internal/sni"
)

var benchBackends []*benchBackend

type benchBackend struct {
	addr string
	ln   net.Listener
}

func setupBenchBackends(b *testing.B, n int) []*benchBackend {
	backends := make([]*benchBackend, n)
	for i := 0; i < n; i++ {
		cert := generateBenchCert()
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
		if err != nil {
			b.Fatal(err)
		}
		backends[i] = &benchBackend{addr: ln.Addr().String(), ln: ln}
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					io.Copy(io.Discard, c)
					c.Close()
				}(conn)
			}
		}(ln)
	}
	return backends
}

func generateBenchCert() tls.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func BenchmarkHandleConnection(b *testing.B) {
	backends := setupBenchBackends(b, 1)
	defer func() {
		for _, bb := range backends {
			bb.ln.Close()
		}
	}()

	r := router.New(map[string][]string{
		backends[0].addr: {"api.example.com"},
	}, backends[0].addr)

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	proxyAddr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go AcceptLoop(ctx, ln, NewRouterRef(r), 0, logger)
	time.Sleep(50 * time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
			ServerName:         "api.example.com",
			InsecureSkipVerify: true,
		})
		if err != nil {
			b.Fatal(err)
		}
		conn.Write([]byte("hello world"))
		conn.Close()
	}
}

func BenchmarkHandleConnectionParallel(b *testing.B) {
	backends := setupBenchBackends(b, 4)
	defer func() {
		for _, bb := range backends {
			bb.ln.Close()
		}
	}()

	routes := map[string][]string{}
	for i, bb := range backends {
		sniHost := "host" + string(rune('a'+i)) + ".example.com"
		routes[bb.addr] = []string{sniHost}
	}
	r := router.New(routes, backends[0].addr)

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	proxyAddr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go AcceptLoop(ctx, ln, NewRouterRef(r), 0, logger)
	time.Sleep(50 * time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			sniHost := "host" + string(rune('a'+i%4)) + ".example.com"
			conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
				ServerName:         sniHost,
				InsecureSkipVerify: true,
			})
			if err != nil {
				b.Fatal(err)
			}
			conn.Write([]byte("bench"))
			conn.Close()
			i++
		}
	})
}

func BenchmarkSNIParse(b *testing.B) {
	hello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x47,
		0x01, 0x00, 0x00, 0x43,
		0x03, 0x03,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00,
		0x00, 0x02, 0x00, 0x2F,
		0x01, 0x00,
		0x00, 0x18,
		0x00, 0x00, 0x00, 0x14,
		0x00, 0x12,
		0x00, 0x00, 0x0F,
		0x61, 0x70, 0x69, 0x2E, 0x65, 0x78, 0x61, 0x6D,
		0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		sniHost, _ := sni.Parse(hello)
		_ = sniHost
	}
}

func BenchmarkSNIParseBytes(b *testing.B) {
	hello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x47,
		0x01, 0x00, 0x00, 0x43,
		0x03, 0x03,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00,
		0x00, 0x02, 0x00, 0x2F,
		0x01, 0x00,
		0x00, 0x18,
		0x00, 0x00, 0x00, 0x14,
		0x00, 0x12,
		0x00, 0x00, 0x0F,
		0x61, 0x70, 0x69, 0x2E, 0x65, 0x78, 0x61, 0x6D,
		0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		sniBytes, _ := sni.ParseBytes(hello)
		_ = sniBytes
	}
}

func BenchmarkRouterLookup(b *testing.B) {
	routes := map[string][]string{}
	for i := range 1000 {
		sniHost := "host" + itoa(i) + ".example.com"
		backend := "10.0.0." + itoa(i%255) + ":443"
		routes[backend] = append(routes[backend], sniHost)
	}
	r := router.New(routes, "10.0.0.254:8443")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = r.Lookup("host123.example.com")
	}
}

func BenchmarkRouterLookupBytes(b *testing.B) {
	routes := map[string][]string{}
	for i := range 1000 {
		sniHost := "host" + itoa(i) + ".example.com"
		backend := "10.0.0." + itoa(i%255) + ":443"
		routes[backend] = append(routes[backend], sniHost)
	}
	r := router.New(routes, "10.0.0.254:8443")

	key := []byte("host123.example.com")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = r.LookupBytes(key)
	}
}

func BenchmarkAcceptLoopMaxConns(b *testing.B) {
	backends := setupBenchBackends(b, 1)
	defer func() {
		for _, bb := range backends {
			bb.ln.Close()
		}
	}()

	r := router.New(map[string][]string{
		backends[0].addr: {"api.example.com"},
	}, backends[0].addr)

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	proxyAddr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go AcceptLoop(ctx, ln, NewRouterRef(r), 100, logger)
	time.Sleep(50 * time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
				ServerName:         "api.example.com",
				InsecureSkipVerify: true,
			})
			if err != nil {
				continue
			}
			conn.Close()
		}
	})
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}

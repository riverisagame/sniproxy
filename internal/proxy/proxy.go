package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	"sniproxy/internal/router"
	"sniproxy/internal/sni"
)

const (
	peekTimeout   = 30 * time.Second
	dialTimeout   = 10 * time.Second
	keepAliveIdle = 15 * time.Second
)

// AcceptLoop accepts connections and handles each in a new goroutine.
// Blocks until ctx is cancelled.
func AcceptLoop(ctx context.Context, ln net.Listener, r *router.Router, logger *slog.Logger) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				logger.Error("accept failed", "error", err)
				continue
			}
		}
		go handleConnection(ctx, conn, r, logger)
	}
}

func handleConnection(ctx context.Context, clientConn net.Conn, r *router.Router, logger *slog.Logger) {
	defer clientConn.Close()

	remote := clientConn.RemoteAddr().String()
	tcpConn, ok := clientConn.(*net.TCPConn)
	if !ok {
		logger.Debug("not a TCP connection", "remote", remote)
		return
	}

	// Step 1: Read TLS record header (5 bytes)
	if err := tcpConn.SetReadDeadline(time.Now().Add(peekTimeout)); err != nil {
		return
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(tcpConn, hdr); err != nil {
		logger.Debug("read TLS header failed", "remote", remote, "error", err)
		return
	}
	if hdr[0] != 0x16 {
		logger.Debug("not a TLS handshake", "remote", remote, "type", hdr[0])
		return
	}
	recordLen := int(hdr[3])<<8 | int(hdr[4])
	if recordLen < 2 || recordLen > 16384 {
		logger.Debug("invalid TLS record length", "remote", remote, "len", recordLen)
		return
	}

	// Step 2: Read full TLS record
	totalLen := 5 + recordLen
	buf := make([]byte, totalLen)
	copy(buf, hdr)
	if _, err := io.ReadFull(tcpConn, buf[5:]); err != nil {
		logger.Debug("read TLS record body failed", "remote", remote, "error", err)
		return
	}

	// Step 3: Parse SNI
	sniHost, err := sni.Parse(buf)
	if err != nil {
		logger.Debug("SNI parse failed", "remote", remote, "error", err)
		return
	}

	// Step 4: Route lookup
	backend := r.Lookup(sniHost)
	logger.Debug("SNI route", "remote", remote, "sni", sniHost, "backend", backend)

	// Step 5: Clear deadline for forwarding phase
	tcpConn.SetDeadline(time.Time{})

	// Step 6: Dial backend
	backendConn, err := net.DialTimeout("tcp", backend, dialTimeout)
	if err != nil {
		logger.Error("backend dial failed", "remote", remote, "sni", sniHost, "backend", backend, "error", err)
		return
	}
	defer backendConn.Close()
	btcpConn, ok := backendConn.(*net.TCPConn)
	if !ok {
		logger.Debug("backend not a TCP connection", "remote", remote)
		return
	}

	// Step 7: Set keepalive on both connections
	setKeepAlive(tcpConn)
	setKeepAlive(btcpConn)

	logger.Info("connected", "remote", remote, "sni", sniHost, "backend", backend)

	// Step 8: Replay ClientHello to backend
	if _, err := backendConn.Write(buf); err != nil {
		logger.Debug("replay ClientHello failed", "remote", remote, "error", err)
		return
	}

	// Step 9: Bidirectional zero-copy forwarding (splice on Linux)
	start := time.Now()
	var rx, tx int64

	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(btcpConn, tcpConn) // client -> backend
		rx = n
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(tcpConn, btcpConn) // backend -> client
		tx = n
		done <- struct{}{}
	}()

	// Wait for both directions
	select {
	case <-done:
	case <-ctx.Done():
	}
	<-done

	dur := time.Since(start)
	logger.Info("close", "remote", remote, "sni", sniHost, "rx", rx, "tx", tx, "dur", dur.Round(time.Millisecond).String())
}

func setKeepAlive(conn *net.TCPConn) {
	conn.SetKeepAlive(true)
	conn.SetKeepAlivePeriod(keepAliveIdle)
}

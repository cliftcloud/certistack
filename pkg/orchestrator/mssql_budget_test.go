// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe/synthetic"
)

// listenEvery accepts connections on 127.0.0.1 without end, hands each to
// serve, counts them, and stops with the test.
func listenEvery(t *testing.T, serve func(net.Conn)) (port int, connections *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		l.Close()
		wg.Wait()
	})
	var count atomic.Int32
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				serve(conn)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, &count
}

// A strict-encryption retry is part of one mssql probe attempt: the budget the
// retry wrapper sets bounds the cleartext attempt and the TLS one together.
// A silent server is not retried as strict and is cut off at the budget; a
// server that drops every connection is not tried forever; and a TDS 8.0 strict
// server passes on the first attempt.
func TestRunProberWithRetryBoundsAnMSSQLProbeThatRetriesAsStrict(t *testing.T) {
	silentPort, silentConnections := listenEvery(t, func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
	start := time.Now()
	result, _ := runProberWithRetry(context.Background(), synthetic.NewMSSQLProber("127.0.0.1", silentPort, 30*time.Second, "silent"), 600*time.Millisecond, 0)
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond || result.Passed {
		t.Fatalf("silent server: %+v after %v, want a failure at the 600ms budget", result, elapsed)
	}
	if got := silentConnections.Load(); got != 1 {
		t.Errorf("silent server saw %d connections, want 1: silence is no strict-encryption cue and the attempt used the whole budget", got)
	}

	dropPort, dropConnections := listenEvery(t, func(net.Conn) {})
	start = time.Now()
	result, attempts := runProberWithRetry(context.Background(), synthetic.NewMSSQLProber("127.0.0.1", dropPort, 30*time.Second, "drops"), 900*time.Millisecond, 0)
	if elapsed := time.Since(start); elapsed > 2*time.Second || result.Passed || !strings.Contains(result.Error, "TDS 8.0 strict") {
		t.Fatalf("dropping server: %+v after %v and %d attempts, want a failure at the 900ms budget that names the strict retry", result, elapsed, attempts)
	}
	// An attempt is the cleartext connection and one strict retry; the last may
	// be cut off by the budget between the two.
	if got := int(dropConnections.Load()); got < attempts || got > 2*attempts {
		t.Errorf("dropping server saw %d connections in %d attempts, want one or two per attempt", got, attempts)
	}

	// A TDS 8.0 strict server: TLS only, ALPN tds/8.0, PRELOGIN inside.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sql.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"tds/8.0"}, MinVersion: tls.VersionTLS12}
	strictPort, _ := listenEvery(t, func(raw net.Conn) {
		conn := tls.Server(raw, config)
		if conn.Handshake() != nil || conn.ConnectionState().NegotiatedProtocol != "tds/8.0" {
			return
		}
		header := make([]byte, 8)
		if _, err := io.ReadFull(conn, header); err != nil || header[0] != 0x12 {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, int(binary.BigEndian.Uint16(header[2:]))-8)); err != nil {
			return
		}
		payload := []byte{0x00, 0, 11, 0, 6, 0x01, 0, 17, 0, 1, 0xff, 16, 0, 0x0f, 0xa0, 0, 1, 0x03}
		reply := append([]byte{0x04, 0x01, 0, 0, 0, 0, 1, 0}, payload...)
		binary.BigEndian.PutUint16(reply[2:], uint16(len(reply)))
		_, _ = conn.Write(reply)
	})
	result, attempts = runProberWithRetry(context.Background(), synthetic.NewMSSQLProber("127.0.0.1", strictPort, 30*time.Second, "strict"), 3*time.Second, 0)
	if !result.Passed || attempts != 1 || !strings.Contains(result.Detail, "TDS 8.0 strict") || !strings.Contains(result.Detail, "version 16.0.4000.1") {
		t.Fatalf("strict server: %+v after %d attempts, want a pass on the first", result, attempts)
	}
}

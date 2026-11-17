// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
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
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// The plan's server_name travels from the probe the plan lists to the mssql
// prober and into the result. The server is a TDS 8.0 strict endpoint with a
// self-signed certificate that no trust store holds: the probe without a
// server_name passes and says the certificate was not verified, and the probe
// with one fails on the certificate and records the name it asked for.
func TestAnMSSQLServerNameReachesTheProberAndTheResult(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sql.example.test"}, DNSNames: []string{"sql.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"tds/8.0"}, MinVersion: tls.VersionTLS12}
	port, _ := listenEvery(t, func(raw net.Conn) {
		conn := tls.Server(raw, tlsConfig)
		if conn.Handshake() != nil {
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

	probes := []config.Probe{
		{Type: "mssql", TargetIP: "127.0.0.1", Port: port, TimeoutSec: 3, Retries: 1, Description: "SQL Server answers"},
		{Type: "mssql", TargetIP: "127.0.0.1", Port: port, ServerName: "sql.example.test", TimeoutSec: 3, Retries: 1, Description: "SQL Server answers"},
	}
	results := probeStageResults(t, &Orchestrator{}, 9932, probes...)
	bare, named := results[0], results[1]

	if !bare.Passed || bare.ServerName != "" || !strings.Contains(bare.Detail, "certificate not verified") {
		t.Errorf("the probe without a server_name = %+v, want a pass that records none and says the certificate was not verified", bare)
	}
	if named.Passed || named.ServerName != "sql.example.test" {
		t.Fatalf("the probe with a server_name = %+v, want a failure on the certificate that records the name", named)
	}
	for _, want := range []string{`server_name "sql.example.test"`, "verified TDS 8.0 strict handshake", "unknown authority"} {
		if !strings.Contains(named.Error, want) {
			t.Errorf("error %q lacks %q", named.Error, want)
		}
	}
	requireDistinctEvidence(t, bare, named, func(result *probe.Result) { result.Passed, result.Error = false, "" })
}

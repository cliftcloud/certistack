// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// caPEM is a real certificate in PEM form, as a private PVE CA file holds it.
func caPEM(t *testing.T) []byte {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
}

// paddedCA is a valid CA file of exactly size bytes: the certificate, then
// comment lines PEM parsers skip.
func paddedCA(t *testing.T, size int) []byte {
	t.Helper()
	data := caPEM(t)
	if len(data) >= size {
		t.Fatalf("a certificate is %d bytes, more than the %d asked for", len(data), size)
	}
	padding := bytes.Repeat([]byte("#"), size-len(data)-1)
	return append(append(data, padding...), '\n')
}

// The PVE TLS CA file is read as a bounded regular file. A 16 MiB file
// was read whole (19,957,200 bytes allocated by the loader, and the controller
// staged all of it on the node); the limit is MaxCAFileBytes, at which a valid
// file still loads.
func TestLoadCustomCAReadsABoundedFile(t *testing.T) {
	dir := t.TempDir()

	exact := filepath.Join(dir, "exact.pem")
	if err := os.WriteFile(exact, paddedCA(t, MaxCAFileBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadCustomCA(&tls.Config{}, exact); err != nil {
		t.Fatalf("a CA file of exactly %d bytes is refused: %v", MaxCAFileBytes, err)
	}

	over := filepath.Join(dir, "over.pem")
	if err := os.WriteFile(over, paddedCA(t, MaxCAFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadCustomCA(&tls.Config{}, over); err == nil || !strings.Contains(err.Error(), "larger than the 1048576 bytes") {
		t.Errorf("a CA file one byte over the limit: %v", err)
	}

	// The reporter's file: 16 MiB, refused after a stat, without being read.
	huge := filepath.Join(dir, "huge.pem")
	f, err := os.Create(huge)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(16 << 20); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = loadCustomCA(&tls.Config{}, huge)
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("a 16 MiB CA file: %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Errorf("refusing a 16 MiB CA file allocated %d bytes; it must not be read", allocated)
	}

	// A file that is not a regular file, or is gone, is an error that names it.
	if err := loadCustomCA(&tls.Config{}, dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory as the CA file: %v", err)
	}
	if err := loadCustomCA(&tls.Config{}, filepath.Join(dir, "missing.pem")); err == nil || !strings.Contains(err.Error(), "read PVE TLS CA file") {
		t.Fatalf("a missing CA file: %v", err)
	}

	// A link to a regular CA file is followed: the certificate is public, and a
	// link to a mounted secret store is how it is often supplied.
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(exact, link); err != nil {
		t.Logf("no symbolic links here (%v); the link case is not exercised", err)
	} else if err := loadCustomCA(&tls.Config{}, link); err != nil {
		t.Fatalf("a link to a regular CA file is refused: %v", err)
	}
}

// A client built on an oversized CA file reports why on its first
// request and sends nothing, as it does for any bad TLS configuration.
func TestClientWithAnOversizedCAFileSendsNothing(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`{"version":"8.4"}`)})
	}))
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "pve-ca.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, append(pemData, bytes.Repeat([]byte("#"), MaxCAFileBytes)...), 0o600); err != nil {
		t.Fatal(err)
	}
	client := NewClient(Config{BaseURL: server.URL, TokenID: "certistack@pve!t", TokenSecret: "secret", TLSCAFile: caPath})
	if err := client.Do(context.Background(), "GET", "version", nil, nil); err == nil || !strings.Contains(err.Error(), "PVE TLS CA file") || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversized CA file: %v", err)
	}
	if requests != 0 {
		t.Fatalf("%d request(s) reached the server through a client whose CA file was refused", requests)
	}
}

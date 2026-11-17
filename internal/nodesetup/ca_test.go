// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// testCertificate returns a self-signed certificate as PEM.
func testCertificate(t *testing.T, subject string, isCA bool, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: subject, Organization: []string{"Proxmox Virtual Environment"}},
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestParseCABundleKeepsTheCAAndNamesWhatItTrusts(t *testing.T) {
	ca := testCertificate(t, "PVE Cluster Manager CA", true, testNow.AddDate(10, 0, 0))
	bundle, err := ParseCABundle(append([]byte("# the cluster CA\n"), ca...), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Certificates) != 1 || !strings.Contains(bundle.Certificates[0].Subject, "PVE Cluster Manager CA") {
		t.Fatalf("certificates = %+v", bundle.Certificates)
	}
	fingerprint := bundle.Certificates[0].SHA256
	if len(fingerprint) != 32*3-1 || strings.ToUpper(fingerprint) != fingerprint || strings.Count(fingerprint, ":") != 31 {
		t.Errorf("fingerprint %q is not colon-separated upper-case hex", fingerprint)
	}
	if string(bundle.PEM) != string(ca) {
		t.Errorf("the PEM was changed:\n%s\nwant\n%s", bundle.PEM, ca)
	}
}

func TestParseCABundleRefusesWhatIsNotACABundle(t *testing.T) {
	ca := testCertificate(t, "PVE CA", true, testNow.AddDate(10, 0, 0))
	leaf := testCertificate(t, "pve.example.com", false, testNow.AddDate(1, 0, 0))
	expired := testCertificate(t, "Old CA", true, testNow.Add(-time.Hour))
	key := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("secret")})
	for _, c := range []struct {
		name string
		data []byte
		want string
	}{
		{"text", []byte("this is not a certificate\n"), "not PEM"},
		{"empty", nil, "not PEM"},
		{"a leaf only", leaf, "no CA certificate"},
		{"an expired CA", expired, "expired on 2026-10-05"},
		{"a private key beside the CA", append(append([]byte(nil), ca...), key...), "contains a private key"},
		{"a corrupt certificate", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), "cannot be parsed"},
	} {
		if _, err := ParseCABundle(c.data, testNow); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error = %v, want it to contain %q", c.name, err, c.want)
		}
	}
}

func TestParseCABundleDropsNonCACertificatesAndSaysSo(t *testing.T) {
	ca := testCertificate(t, "PVE CA", true, testNow.AddDate(10, 0, 0))
	leaf := testCertificate(t, "pve.example.com", false, testNow.AddDate(1, 0, 0))
	bundle, err := ParseCABundle(append(append([]byte(nil), leaf...), ca...), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.IgnoredLeaves != 1 || string(bundle.PEM) != string(ca) {
		t.Errorf("ignored %d, PEM kept:\n%s", bundle.IgnoredLeaves, bundle.PEM)
	}
}

func TestWriteCAFileWritesAtomicallyWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pve-root-ca.pem")
	data := testCertificate(t, "PVE CA", true, testNow.AddDate(10, 0, 0))
	changed, err := WriteCAFile(path, data)
	if err != nil || !changed {
		t.Fatalf("changed %v, error %v", changed, err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(data) {
		t.Error("the content written differs")
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
			t.Errorf("mode %04o, want 0644", info.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("the directory holds %d entries after the write, want only the CA", len(entries))
	}
	// The same content again changes nothing.
	if changed, err := WriteCAFile(path, data); err != nil || changed {
		t.Errorf("rewriting the same CA: changed %v, error %v", changed, err)
	}
	// A new CA replaces the old one.
	newer := testCertificate(t, "PVE CA 2", true, testNow.AddDate(10, 0, 0))
	if changed, err := WriteCAFile(path, newer); err != nil || !changed {
		t.Fatalf("replacing the CA: changed %v, error %v", changed, err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(newer) {
		t.Error("the CA was not replaced")
	}
}

func TestWriteCAFileNeverReplacesAFileThatIsNotACA(t *testing.T) {
	dir := t.TempDir()
	data := testCertificate(t, "PVE CA", true, testNow.AddDate(10, 0, 0))

	env := filepath.Join(dir, "controller.env")
	if err := os.WriteFile(env, []byte("PVE_TOKEN_SECRET=do-not-lose-me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteCAFile(env, data); err == nil || !strings.Contains(err.Error(), "not a PEM certificate file") {
		t.Fatalf("error = %v", err)
	}
	if got, _ := os.ReadFile(env); string(got) != "PVE_TOKEN_SECRET=do-not-lose-me\n" {
		t.Error("the file that is not a CA was changed")
	}

	if _, err := WriteCAFile(dir, data); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: error = %v", err)
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link.pem")
		if err := os.Symlink(env, link); err != nil {
			t.Fatal(err)
		}
		if _, err := WriteCAFile(link, data); err == nil {
			t.Error("a symbolic link was replaced")
		}
	}
	missing := filepath.Join(dir, "no", "such", "dir", "ca.pem")
	if _, err := WriteCAFile(missing, data); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("a missing directory: error = %v", err)
	}
	// An empty file is fine to fill.
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteCAFile(empty, data); err != nil {
		t.Errorf("an empty file: %v", err)
	}
}

func TestWriteCAFileLeavesNoTemporaryFileWhenTheMoveFails(t *testing.T) {
	dir := t.TempDir()
	// The destination is a non-empty directory: the existing-file check refuses
	// it before anything is created.
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteCAFile(target, []byte("data")); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("leftovers in %s: %v", dir, entries)
	}
}

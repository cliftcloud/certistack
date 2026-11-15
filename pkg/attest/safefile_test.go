// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// writeKeyFixture writes a key file readable only by its owner, as a
// protected key must be on every platform: mode 0600, or on Windows an
// owner-only ACL rather than the temporary directory's inherited one.
func writeKeyFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := createExclusive(path, 0600, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSynced(f, data, 0600); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// withFileStep installs step as the file hook for one test.
func withFileStep(t *testing.T, step func(step, path string) error) {
	t.Helper()
	previous := fileStep
	fileStep = step
	t.Cleanup(func() { fileStep = previous })
}

// simulatedCrash stops a save at a hook the way process death would: no
// error path or rollback runs.
type simulatedCrash struct{}

func crashAt(t *testing.T, want, wantPath string) {
	t.Helper()
	withFileStep(t, func(step, path string) error {
		if step == want && path == wantPath {
			panic(simulatedCrash{})
		}
		return nil
	})
}

func runUntilCrash(t *testing.T, save func() error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != (simulatedCrash{}) {
			t.Fatalf("save did not stop at the simulated crash: recovered %v", recovered)
		}
	}()
	err := save()
	t.Fatalf("save returned %v instead of stopping at the simulated crash", err)
}

func symlinksSupported(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("symbolic links unavailable in this environment: %v", err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists (err %v); want it absent", path, err)
	}
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func publicKeyFile(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub) + "\n"
}

func signedReport(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	report := BuildReport(&config.Plan{PlanID: "key-rotation"}, "node1", time.Second, true, nil, "")
	if err := report.SignReport(priv); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A forced report overwrite never truncates the previous report
// before the new one is complete.
func TestReportForcedOverwriteIsAtomic(t *testing.T) {
	_, priv := newKey(t)
	path := filepath.Join(t.TempDir(), "report.json")
	first := BuildReport(&config.Plan{PlanID: "atomic-report"}, "node1", time.Second, true, nil, "")
	if err := first.SignReport(priv); err != nil {
		t.Fatal(err)
	}
	if err := first.Save(path); err != nil {
		t.Fatal(err)
	}
	firstBytes := readFile(t, path)
	second := BuildReport(&config.Plan{PlanID: "atomic-report"}, "node1", time.Second, false, nil, "")
	if err := second.SignReport(priv); err != nil {
		t.Fatal(err)
	}

	crashAt(t, "publishing", path)
	runUntilCrash(t, func() error { return second.SaveWithForce(path, true) })
	if got := readFile(t, path); got != firstBytes {
		t.Fatal("an interrupted forced overwrite changed the previous report")
	}
	if err := os.Remove(stagingPath(path)); err != nil {
		t.Fatal(err)
	}

	withFileStep(t, func(string, string) error { return nil })
	if err := second.SaveWithForce(path, true); err != nil {
		t.Fatal(err)
	}
	verified, valid, err := VerifyReportSignatureOnly([]byte(readFile(t, path)))
	if err != nil || !valid || verified.ReportID != second.ReportID {
		t.Fatalf("forced overwrite did not publish the new report: valid=%v err=%v", valid, err)
	}
	assertAbsent(t, stagingPath(path))
}

// A keyring of exactly the limit loads, one byte more is refused.
func TestKeyringFileLimit(t *testing.T) {
	pub, _ := newKey(t)
	line := hex.EncodeToString(pub)
	dir := t.TempDir()
	atLimit := writeInput(t, dir, "at-limit", append(bytes.Repeat([]byte("\n"), MaxKeyringFileBytes-len(line)), line...))
	if kr, err := LoadKeyringFile(atLimit); err != nil || len(kr.PublicKeys()) != 1 {
		t.Fatalf("a keyring of exactly %d bytes: %v", MaxKeyringFileBytes, err)
	}
	over := writeInput(t, dir, "over", append(bytes.Repeat([]byte("\n"), MaxKeyringFileBytes-len(line)+1), line...))
	if _, err := LoadKeyringFile(over); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("a keyring one byte over the limit: %v", err)
	}
}

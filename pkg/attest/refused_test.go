// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const refusedRunID = "run-6f1a0c52-3a0e-4d6b-9d58-7a2b6c1f9e10"

// The kept file is the banner, the reason on one line, the marker and the
// worker's bytes unchanged; it is private, in the refused/ subdirectory, and
// nothing else is left beside it.
func TestARefusedResultIsKeptMarkedAndPrivate(t *testing.T) {
	base := t.TempDir()
	raw := []byte("{\"report\":{\"plan_id\":\"x\"},\n\"error\":\"\"}\r\n\x00\xff trailing \"bytes\"")
	path, err := SaveRefusedResult(base, refusedRunID, "the report names node \"a\"\nand run \"b\"‮; and more", raw)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "refused", refusedRunID+".refused.txt"); path != want {
		t.Fatalf("path = %s, want %s", path, want)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitN(string(got), "\n", 4)
	if len(lines) != 4 {
		t.Fatalf("file has %d lines before the raw bytes, want banner, reason and marker:\n%q", len(lines), got)
	}
	// The wording is part of the product's promise (docs/troubleshooting.md
	// quotes it), so it is spelled out here, not taken from the constant.
	const banner = "REFUSED, NOT EVIDENCE: this worker result failed the controller's checks and was never signed"
	if lines[0] != banner {
		t.Errorf("first line = %q, want %q", lines[0], banner)
	}
	if want := "Reason: the report names node \"a\"; and run \"b\"; and more"; lines[1] != want {
		t.Errorf("reason line = %q, want %q (one line, no bidi control)", lines[1], want)
	}
	if lines[2] != RefusedRawMarker {
		t.Errorf("third line = %q, want the marker", lines[2])
	}
	if !bytes.Equal([]byte(lines[3]), raw) {
		t.Errorf("raw bytes = %q, want %q unchanged", lines[3], raw)
	}
	if names := entries(t, filepath.Dir(path)); len(names) != 1 {
		t.Errorf("refused directory holds %v, want the one file (no staging file left)", names)
	}
	if names := entries(t, base); len(names) != 1 || names[0] != "refused" {
		t.Errorf("report directory root holds %v, want only refused/", names)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("refused result mode = %v, %v; want 0600", info, err)
		}
		dir, err := os.Stat(filepath.Dir(path))
		if err != nil || dir.Mode().Perm() != 0o700 {
			t.Errorf("refused directory mode = %v, %v; want 0700", dir, err)
		}
	}
}

// Nothing that reads reports can take the kept file for one. It has no .json
// name in any letter case, it is not JSON, and the verifier refuses it even when
// the worker's bytes in it are a report with a valid signature.
func TestARefusedResultCannotBeMistakenForAReport(t *testing.T) {
	pub, priv := newKey(t)
	signed := signedReport(t, priv)
	// The worker's result is {"report": ..., "error": ...}; the worst case is a
	// kept file whose bytes are a complete, validly signed report.
	for name, raw := range map[string][]byte{
		"a signed report as the whole result": signed,
		"a result that wraps a report":        append(append([]byte(`{"report":`), signed...), '}'),
		"not JSON":                            []byte("panic: runtime error"),
		"nothing":                             nil,
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			path, err := SaveRefusedResult(base, refusedRunID, "contradicts the request", raw)
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Base(path)
			for _, pattern := range []string{"*.json", "*.JSON", "*.json.*", "*.receipt.json"} {
				if ok, _ := filepath.Match(pattern, name); ok {
					t.Errorf("%s matches the report glob %s", name, pattern)
				}
			}
			if strings.EqualFold(filepath.Ext(path), ".json") || strings.HasSuffix(strings.ToLower(path), ".json") {
				t.Errorf("%s ends in .json", path)
			}
			if filepath.Dir(path) == base {
				t.Errorf("%s is in the report directory's root", path)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if json.Valid(data) {
				t.Error("the kept file is valid JSON")
			}
			if _, valid, err := VerifyReport(data, []ed25519.PublicKey{pub}); err == nil || valid {
				t.Errorf("VerifyReport accepted the kept file: valid=%v err=%v", valid, err)
			}
			if _, valid, err := VerifyReportSignatureOnly(data); err == nil || valid {
				t.Errorf("VerifyReportSignatureOnly accepted the kept file: valid=%v err=%v", valid, err)
			}
			if _, err := CanonicalizeReportJSON(data); err == nil {
				t.Error("the kept file canonicalizes as a report")
			}
		})
	}
}

// The run ID names the file, so it may hold nothing that leaves the directory.
func TestARefusedResultRunIDCannotLeaveTheDirectory(t *testing.T) {
	base := t.TempDir()
	for _, id := range []string{"", ".", "..", "../x", "a/b", `a\b`, "run-x\x00", "run x", ".hidden", "run-" + strings.Repeat("a", 200), "run-é"} {
		if path, err := SaveRefusedResult(base, id, "reason", []byte("x")); err == nil {
			t.Errorf("run ID %q was accepted as %s", id, path)
		}
	}
	if names := entries(t, base); len(names) != 0 {
		t.Errorf("%v were created for refused run IDs", names)
	}
	if path, err := DefaultRefusedPath("", refusedRunID); err != nil || !strings.HasPrefix(filepath.ToSlash(path), "/var/lib/certistack/reports/refused/") {
		t.Errorf("default path = %s, %v; want it under the default report directory", path, err)
	}
}

// A kept file is never replaced, and is never written through a link.
func TestARefusedResultIsNeverReplacedOrWrittenThroughALink(t *testing.T) {
	base := t.TempDir()
	first, err := SaveRefusedResult(base, refusedRunID, "first", []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveRefusedResult(base, refusedRunID, "second", []byte("two")); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("a second result for one run: err = %v, want it refused", err)
	}
	if data, _ := os.ReadFile(first); !strings.Contains(string(data), "Reason: first") || !strings.HasSuffix(string(data), "one") {
		t.Errorf("the first result was changed: %q", data)
	}

	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	elsewhere := t.TempDir()
	linked := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(linked, "refused")); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveRefusedResult(linked, refusedRunID, "reason", []byte("x")); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("a linked refused/ directory: err = %v, want it refused", err)
	}
	if names := entries(t, elsewhere); len(names) != 0 {
		t.Errorf("the link target holds %v", names)
	}
	notDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(notDir, "refused"), []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveRefusedResult(notDir, refusedRunID, "reason", []byte("x")); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a refused path that is a file: err = %v, want it refused", err)
	}
}

// A result larger than a report may be is cut, and the file says so; the
// file never passes the limit.
func TestARefusedResultIsCutAtTheReportSizeLimit(t *testing.T) {
	old := refusedResultLimit
	defer func() { refusedResultLimit = old }()
	const limit = 1024
	refusedResultLimit = limit
	raw := bytes.Repeat([]byte("0123456789"), 400)
	base := t.TempDir()
	path, err := SaveRefusedResult(base, refusedRunID, "reason", raw)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > limit {
		t.Errorf("file is %d bytes, over the limit of %d", len(data), limit)
	}
	text := string(data)
	if !strings.HasPrefix(text, RefusedBanner+"\n") || !strings.Contains(text, "--- cut here: the first ") || !strings.HasSuffix(text, " of the worker's 4000 bytes are kept ---\n") {
		t.Errorf("a cut result does not say so:\n%s", text[max(0, len(text)-200):])
	}
	// A result that fills the file to the limit exactly is kept whole; one byte
	// more is cut.
	room := limit - len(RefusedBanner+"\nReason: reason\n"+RefusedRawMarker+"\n")
	for _, tc := range []struct {
		id   string
		size int
		cut  bool
	}{{"run-exact", room, false}, {"run-over", room + 1, true}} {
		raw := bytes.Repeat([]byte("a"), tc.size)
		path, err = SaveRefusedResult(base, tc.id, "reason", raw)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(path)
		if got := bytes.Contains(data, []byte("cut here")); got != tc.cut || len(data) > limit {
			t.Errorf("%d bytes of result (room %d): cut = %v, want %v; file is %d bytes", tc.size, room, got, tc.cut, len(data))
		}
		if !tc.cut && !bytes.HasSuffix(data, raw) {
			t.Errorf("a result inside the limit was not kept whole")
		}
	}
	// A reason that is itself huge is bounded.
	path, err = SaveRefusedResult(base, "run-reason", strings.Repeat("é", 20000), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); len(data) > 12<<10 || !strings.Contains(string(data), "...\n") {
		t.Errorf("a %d-byte reason was not bounded", len(data))
	}
}

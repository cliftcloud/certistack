// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func statePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "certistack", "telemetry.json")
}

func enabledState(t *testing.T, business bool) State {
	t.Helper()
	st, err := NewInstall(business)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestMissingStateMeansNeverAskedAndOff(t *testing.T) {
	st, status := ReadState(statePath(t))
	if status != StateMissing {
		t.Fatalf("status = %v, want StateMissing", status)
	}
	if st.Answered || st.Enabled || st.InstallID != "" {
		t.Fatalf("a missing file produced state %+v", st)
	}
}

func TestStateRoundTripAndMode(t *testing.T) {
	path := statePath(t)
	st := enabledState(t, true)
	st.LastTestRun = "2026-10-01"
	st.LastSent = "2026-10-01T12:00:00Z"
	if err := st.AddCluster("pve-lab-cluster"); err != nil {
		t.Fatal(err)
	}
	if err := WriteState(path, st); err != nil {
		t.Fatal(err)
	}
	got, status := ReadState(path)
	if status != StateOK {
		t.Fatalf("status = %v", status)
	}
	if got.InstallID != st.InstallID || got.Salt != st.Salt || !got.Enabled || !got.BusinessUse || len(got.Clusters) != 1 || got.LastTestRun != "2026-10-01" {
		t.Fatalf("round trip changed the state: %+v vs %+v", got, st)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("state file mode = %v, want 0600", info.Mode().Perm())
		}
		dir, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if dir.Mode().Perm() != 0o700 {
			t.Errorf("state directory mode = %v, want 0700", dir.Mode().Perm())
		}
	}
	// A rewrite keeps 0600 and leaves no temporary file behind.
	st.LastSent = "2026-10-02T12:00:00Z"
	if err := WriteState(path, st); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "telemetry.json" {
		t.Errorf("the state directory holds %v, want only telemetry.json", entries)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("rewritten state file mode = %v, want 0600", info.Mode().Perm())
		}
	}
}

func TestWriteStateRepairsALooseExistingModeAndRefusesInvalidState(t *testing.T) {
	path := statePath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteState(path, enabledState(t, false)); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("mode after rewriting a 0644 file = %v, want 0600", info.Mode().Perm())
		}
	}
	bad := State{Answered: true, Enabled: true} // enabled without an identity
	if err := WriteState(path, bad); err == nil {
		t.Error("WriteState accepted an enabled state with no install id")
	}
}

func TestCorruptStateIsOffAndNeverACrash(t *testing.T) {
	good := enabledState(t, false)
	valid := func(mutate func(*State)) string {
		st := good
		mutate(&st)
		return string(mustMarshalState(t, st))
	}
	hex64 := strings.Repeat("ab", 32)
	for name, content := range map[string]string{
		"empty":                    "",
		"not json":                 "this is not json",
		"truncated":                `{"answered": true, "enabled": tr`,
		"array":                    `[]`,
		"null":                     `null`,
		"wrong type":               `{"answered": "yes", "enabled": true}`,
		"trailing data":            valid(func(*State) {}) + `{"answered":false}`,
		"binary":                   "\x00\x01\x02\xff\xfe",
		"huge":                     `{"clusters": [` + strings.Repeat(`"`+hex64+`",`, 4000) + `"x"]}`,
		"enabled without identity": `{"answered": true, "enabled": true}`,
		"enabled unanswered":       valid(func(s *State) { s.Answered = false }),
		"install id not a uuid":    valid(func(s *State) { s.InstallID = "my-laptop" }),
		"install id is a v1 uuid":  valid(func(s *State) { s.InstallID = "5b0f3a52-8f63-1c6e-9d0b-1d2e3f4a5b6c" }),
		"salt too short":           valid(func(s *State) { s.Salt = "abcd" }),
		"cluster is a hostname":    valid(func(s *State) { s.Clusters = []string{"pve01.example.com"} }),
		"cluster duplicated":       valid(func(s *State) { s.Clusters = []string{hex64, hex64} }),
		"bad date":                 valid(func(s *State) { s.LastTestRun = "2026-13-45" }),
		"date with a time":         valid(func(s *State) { s.LastTestRun = "2026-10-01T10:00:00Z" }),
		"bad last_sent":            valid(func(s *State) { s.LastSent = "yesterday" }),
	} {
		t.Run(name, func(t *testing.T) {
			path := statePath(t)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			st, status := ReadState(path)
			if status != StateCorrupt {
				t.Fatalf("status = %v, want StateCorrupt", status)
			}
			if st.Enabled || st.Answered || st.InstallID != "" {
				t.Fatalf("a corrupt file produced state %+v", st)
			}
		})
	}
}

func TestAStateFileThatIsADirectoryIsCorruptNotACrash(t *testing.T) {
	path := statePath(t)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, status := ReadState(path); status != StateCorrupt {
		t.Fatalf("status = %v, want StateCorrupt", status)
	}
}

func TestUnknownMembersAreToleratedSoANewerVersionsFileStillReads(t *testing.T) {
	path := statePath(t)
	st := enabledState(t, false)
	raw := strings.Replace(string(mustMarshalState(t, st)), "{", `{"future_field": 1,`, 1)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, status := ReadState(path); status != StateOK {
		t.Fatalf("status = %v, want StateOK", status)
	}
}

var uuid4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestInstallIDIsARandomUUIDv4WithAPerInstallSalt(t *testing.T) {
	a, b := enabledState(t, false), enabledState(t, false)
	if !uuid4.MatchString(a.InstallID) || !uuid4.MatchString(b.InstallID) {
		t.Fatalf("install ids %q %q are not UUID v4", a.InstallID, b.InstallID)
	}
	if a.InstallID == b.InstallID || a.Salt == b.Salt {
		t.Fatal("two installs got the same id or salt")
	}
	if len(a.Salt) != 64 {
		t.Fatalf("salt = %q, want 64 hex characters", a.Salt)
	}
}

func TestClusterHashesAreSaltedDedupedAndNormalised(t *testing.T) {
	a, b := enabledState(t, false), enabledState(t, false)
	for _, st := range []*State{&a, &b} {
		for _, id := range []string{"pve-lab", "PVE-LAB", " pve-lab ", "other-cluster"} {
			if err := st.AddCluster(id); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(a.Clusters) != 2 {
		t.Fatalf("clusters = %v, want 2 distinct (case and padding ignored)", a.Clusters)
	}
	if a.Clusters[0] == b.Clusters[0] || a.Clusters[1] == b.Clusters[1] {
		t.Error("two installs hashed the same cluster identically: the salt is not used")
	}
	for _, h := range a.Clusters {
		if len(h) != 64 || strings.Contains(h, "pve") {
			t.Errorf("cluster entry %q is not a 64-hex digest", h)
		}
	}
	if err := a.AddCluster(""); err != nil || len(a.Clusters) != 2 {
		t.Errorf("an empty identity must be ignored: err=%v clusters=%d", err, len(a.Clusters))
	}
	noSalt := State{}
	if err := noSalt.AddCluster("x"); err == nil {
		t.Error("AddCluster worked without a salt")
	}
}

func mustMarshalState(t *testing.T, st State) []byte {
	t.Helper()
	out, err := marshalState(st)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

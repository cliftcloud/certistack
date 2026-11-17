// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// planWithoutSigningKey is the repository's valid plan with its
// sign_key_path left out, written to a file.
func planWithoutSigningKey(t *testing.T) (path string, data []byte) {
	t.Helper()
	full, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`(?m)^ *sign_key_path:.*\n`)
	if !line.Match(full) {
		t.Fatal("the fixture has no sign_key_path")
	}
	data = line.ReplaceAll(full, nil)
	path = filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

// The Community Edition writes its reports unsigned and signs nothing, so a plan
// is complete without compliance.sign_key_path, whichever way it is loaded.
func TestAPlanNeedsNoSigningKeyPath(t *testing.T) {
	path, data := planWithoutSigningKey(t)

	plan, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile of a plan without a signing key: %v", err)
	}
	if plan.Compliance.SignKeyPath != "" {
		t.Fatalf("a signing key appeared in the plan: %q", plan.Compliance.SignKeyPath)
	}
	if _, digest, err := LoadFromFileWithDigest(path); err != nil || digest != PlanDigest(data) {
		t.Fatalf("LoadFromFileWithDigest of a plan without a signing key: %v, digest %q", err, digest)
	}
	if _, err := LoadFromReader(strings.NewReader(string(data))); err != nil {
		t.Fatalf("LoadFromReader of a plan without a signing key: %v", err)
	}
	if errs := Validate(plan); len(errs) != 0 {
		t.Fatalf("Validate of a plan without a signing key: %v", errs)
	}
	if errs := ValidateForWorker(plan); len(errs) != 0 {
		t.Fatalf("ValidateForWorker of a plan without a signing key: %v", errs)
	}
	if note := SignKeyPathNote(plan); note != "" {
		t.Fatalf("a plan without a signing key got the signing-key note: %q", note)
	}

	// Nothing else is relaxed: a plan that is wrong in another way is still refused.
	broken := strings.Replace(string(data), "plan_id:", "plan_id_misspelled:", 1)
	brokenPath := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(brokenPath, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromFile(brokenPath); err == nil {
		t.Error("a broken plan loaded")
	}
}

// A plan from the Enterprise Edition names the key that edition signs with. The
// Community Edition accepts the field, so that plans stay portable between the
// editions, and does not look at it: any text is kept as written, whether or not
// a file is there, and whatever its mode or format would be.
func TestACommunityPlanAcceptsASigningKeyPathAndIgnoresIt(t *testing.T) {
	_, data := planWithoutSigningKey(t)
	for name, value := range map[string]string{
		"a path that does not exist":         "/nonexistent/enterprise/signing.ed25519",
		"a relative path":                    "keys/signing.ed25519",
		"a directory":                        os.TempDir(),
		"text that is not a path":            "not a path at all",
		"a path in the Enterprise Edition":   "/etc/certistackd/keys/tenant-7.ed25519",
		"whitespace only (the field is set)": " \t ",
	} {
		withKey := strings.Replace(string(data), "  frameworks:", "  sign_key_path: "+quoteYAML(value)+"\n  frameworks:", 1)
		path := filepath.Join(t.TempDir(), "plan.yaml")
		if err := os.WriteFile(path, []byte(withKey), 0o600); err != nil {
			t.Fatal(err)
		}
		plan, err := LoadFromFile(path)
		if err != nil {
			t.Errorf("%s: the plan was refused: %v", name, err)
			continue
		}
		if plan.Compliance.SignKeyPath != value {
			t.Errorf("%s: sign_key_path = %q, want it kept as written (%q)", name, plan.Compliance.SignKeyPath, value)
		}
		if errs := Validate(plan); len(errs) != 0 {
			t.Errorf("%s: Validate: %v", name, errs)
		}
	}
}

// validate and plan print one note when a plan sets the field; SignKeyPathNote
// is its text. A field left blank is not set.
func TestSignKeyPathNoteSaysTheFieldBelongsToTheEnterpriseEdition(t *testing.T) {
	plan := &Plan{}
	for _, blank := range []string{"", " ", "\t \n"} {
		plan.Compliance.SignKeyPath = blank
		if note := SignKeyPathNote(plan); note != "" {
			t.Errorf("a blank field %q got a note: %q", blank, note)
		}
	}
	plan.Compliance.SignKeyPath = "/etc/certistackd/keys/tenant-7.ed25519"
	note := SignKeyPathNote(plan)
	for _, want := range []string{"compliance.sign_key_path", "Community Edition", "unsigned", "Enterprise Edition"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note %q does not mention %q", note, want)
		}
	}
	if strings.Contains(note, plan.Compliance.SignKeyPath) {
		t.Errorf("the note repeats the path it does not read: %q", note)
	}
	if strings.Contains(note, "\n") {
		t.Errorf("the note is not one line: %q", note)
	}
	if SignKeyPathNote(nil) != "" {
		t.Error("no plan got a note")
	}
}

func quoteYAML(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

// Every note validate prints is one or two sentences, each ending with a full
// stop, the signing-key note included.
func TestEveryPlanNoteEndsWithAFullStop(t *testing.T) {
	plan := &Plan{}
	plan.Network.IPRange = "10.99.0.0/24"
	plan.Network.ZoneID = "vmbr0"
	plan.Network.VNetID = "vmbr1"
	plan.Storage.OverlayStorage = "local"
	plan.AdmissionControl.MaxHostRAMPercent = 99
	plan.Compliance.SignKeyPath = "/secure/certistack/signing.key"
	notes := PlanNotes(plan)
	plan.Storage.OverlayStorage = "local-lvm"
	notes = append(notes, PlanNotes(plan)...)
	if len(notes) != 12 {
		t.Fatalf("got %d notes, want 12 (six from each plan):\n%s", len(notes), strings.Join(notes, "\n"))
	}
	for _, note := range notes {
		if !strings.HasSuffix(note, ".") {
			t.Errorf("the note does not end with a full stop: %q", note)
		}
	}
}

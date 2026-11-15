// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const samplePlanPath = "../../testdata/plans/valid_plan.yaml"

// The digest a report records as plan_sha256 is the SHA-256 of the plan file
// exactly as read, the value sha256sum prints, and the plan is parsed from
// those very bytes.
func TestLoadFromFileWithDigestDigestsTheBytesItParsed(t *testing.T) {
	data, err := os.ReadFile(samplePlanPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, digest, err := LoadFromFileWithDigest(samplePlanPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if want := hex.EncodeToString(sum[:]); digest != want || digest != PlanDigest(data) {
		t.Fatalf("digest = %s, want %s", digest, want)
	}
	loaded, err := LoadFromFile(samplePlanPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan, loaded) {
		t.Fatal("LoadFromFileWithDigest parsed a different plan than LoadFromFile")
	}

	// Exact bytes: a comment changes the digest and not the plan, so a plan
	// file that reads the same to the loader is still a different file.
	edited := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(edited, append(append([]byte(nil), data...), []byte("\n# reviewed\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	sameContent, editedDigest, err := LoadFromFileWithDigest(edited)
	if err != nil {
		t.Fatal(err)
	}
	if editedDigest == digest || !reflect.DeepEqual(sameContent, plan) {
		t.Fatalf("a trailing comment: digest %s (was %s), same plan %v", editedDigest, digest, reflect.DeepEqual(sameContent, plan))
	}
}

// A file the loader refuses has no digest to record.
func TestLoadFromFileWithDigestRefusesWhatLoadFromFileRefuses(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.yaml")
	invalid := filepath.Join(dir, "invalid.yaml")
	huge := filepath.Join(dir, "huge.yaml")
	if err := os.WriteFile(invalid, []byte("version: v1\nplan_id: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(huge, []byte(strings.Repeat("#", maxPlanBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": missing, "invalid": invalid, "oversized": huge} {
		_, wantErr := LoadFromFile(path)
		plan, digest, err := LoadFromFileWithDigest(path)
		if wantErr == nil || err == nil || plan != nil || digest != "" || err.Error() != wantErr.Error() {
			t.Errorf("%s: LoadFromFileWithDigest = %v, %q, %v; LoadFromFile error %v", name, plan, digest, err, wantErr)
		}
	}
}

func TestPlanDigestIsSHA256InLowercaseHex(t *testing.T) {
	// The FIPS 180 test vector for "abc".
	if got, want := PlanDigest([]byte("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Fatalf("PlanDigest(abc) = %s, want %s", got, want)
	}
}

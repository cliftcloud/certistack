// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// The golden fixtures of the static verify page (the website's verify/ page,
// which checks a report's signature in the browser). They are three small,
// SYNTHETIC signed reports (a throwaway key whose seed is public, fake data,
// no hostname, address or lab name):
//
//	valid.json                  a correctly signed report of a passing run (the
//	                            report, its VM and its probes all say passed)
//	tampered.json               valid.json with one byte of a signed member changed
//	valid-stub-timestamp.json   valid.json with a stub signature_timestamp
//	signer.json                 the fixture key, for the "trusted key" the page is given
//
// They are written to testdata/verify-page/ and copied to the website. Ed25519
// signatures are deterministic and everything else is fixed, so regenerating
// them gives the same bytes; this test fails if the committed files differ from
// what the code produces, and
//
//	CERTISTACK_UPDATE_VERIFY_PAGE_FIXTURES=1 go test ./pkg/attest -run VerifyPageFixtures
//
// rewrites them.
//
// The signed bytes carry what a JavaScript canonicalizer can get wrong: a
// float written as 1.0, exponents, a negative zero, the largest exact integer
// (2^53-1), non-ASCII text ("Zürich ✓" and an astral character), escapes, and
// nested objects whose keys sort differently in UTF-16 (RFC 8785) and UTF-8
// order (an astral character against U+FF5E).
const verifyPageFixtureDir = "../../testdata/verify-page"

const updateVerifyPageFixturesEnv = "CERTISTACK_UPDATE_VERIFY_PAGE_FIXTURES"

// canonicalizationProbe is the signed member that exercises canonicalization.
// Numbers are json.Number so their text reaches the document as written.
func canonicalizationProbe() map[string]interface{} {
	num := func(literals ...string) []interface{} {
		out := make([]interface{}, len(literals))
		for i, literal := range literals {
			out[i] = json.Number(literal)
		}
		return out
	}
	return map[string]interface{}{
		"numbers": num("1.0", "1.50", "0.000001", "1e-7", "1E+2", "-0.0", "9007199254740991", "-9007199254740991",
			"9007199254740991.0", "4.5e15", "123456789.123456789", "5e-324", "0.1", "100e-2", "0", "-1.5E-3"),
		"strings": []interface{}{
			"Zürich ✓", "astral \U0001F600 and ～", "tab\there", `quote " and back\slash and / slash`,
			"nul\u0000 and \u001f and del\u007f", "line separator", "<tag> & more", "",
		},
		// No two names here differ only by case: a report with such a pair is
		// refused (the decoder would read both into one field), so the capitals
		// that sort before the lower-case letters are other letters ("C" before
		// "a", "Y" before "z") and not "B" and "Z" beside "b" and "z".
		"unsorted_keys": map[string]interface{}{
			"b": json.Number("1"), "a": json.Number("2"), "C": json.Number("3"), "é": json.Number("4"),
			"z": json.Number("5"), "Y": json.Number("6"), "～": json.Number("7"), "\U0001F600": json.Number("8"),
			"": json.Number("9"), "10": json.Number("10"), "2": json.Number("11"), "aa": json.Number("12"), "a\u0000": json.Number("13"),
		},
		"nested": []interface{}{
			map[string]interface{}{"y": json.Number("1"), "x": []interface{}{map[string]interface{}{"b": true, "a": nil}}},
			[]interface{}{}, map[string]interface{}{}, nil, true, false, json.Number("0"),
		},
	}
}

func verifyPageFixtureKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("certistack verify-page fixture key v1: a throwaway key, its seed is public"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func verifyPageFixtureReport() *Report {
	plan := &config.Plan{
		PlanID: "synthetic-plan-001", Name: "Synthetic verify-page plan", Environment: "Zürich ✓ (synthetic)",
		Compliance: config.Compliance{Frameworks: []string{"SYNTHETIC-1"}, RetentionDays: 30},
	}
	vms := []probe.VMValidationRecord{{
		VMID: 9001, SourceVMID: 101, Name: "synthetic-vm", VerificationStatus: "verified", AllPassed: true,
		BootDurationSeconds: 41.5,
		ProbeResults: []probe.Result{
			{Type: "tcp", Target: "port 8080", Description: "Synthetic service port", Origin: "worker", Passed: true, Duration: 120 * time.Millisecond},
			{Type: "http", Target: "/healthz", Description: "Synthetic health endpoint", Origin: "worker", Passed: true, Duration: 80 * time.Millisecond},
		},
	}}
	report := BuildReport(plan, "synthetic-node", 183500*time.Millisecond, true, vms, "")
	report.ReportID = "5ee0c0de-0000-4000-8000-0000000f1ac7"
	report.Timestamp = "2026-10-02T12:00:00Z"
	report.EngineVersion, report.GitCommit, report.BuildDate = "v0.0.0-fixture", "0000000", "2026-10-01T00:00:00Z"
	target := 300.0
	report.RTOTargetSeconds = &target
	report.PhaseTimings = &PhaseTimings{AdmissionCheckSec: 1.25, PBSMappingSec: 12.5, VMStartSec: 20, ProbesExecutionSec: 5.5, TeardownSec: 3.25, TotalRTOSec: 183.5}
	report.TeardownEvidence = &TeardownEvidence{
		VMStoppedAndDestroyed: true, OverlayFilesRemoved: []string{}, LoopDevicesUnmapped: []string{},
		SDNVNetRemoved: "synthetic-vnet", SDNZoneRemoved: "synthetic-zone", SDNClusterReloaded: true,
		OrphanSweepClean: true, AllCleaned: true, VerifiedAt: "2026-10-02T12:03:10Z",
	}
	return report
}

// verifyPageFixtures builds the three documents and the signer file.
func verifyPageFixtures(t *testing.T) map[string][]byte {
	t.Helper()
	key := verifyPageFixtureKey()
	public := key.Public().(ed25519.PublicKey)

	raw, err := json.Marshal(verifyPageFixtureReport())
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&members); err != nil {
		t.Fatal(err)
	}
	members["x_canonicalization_probe"] = canonicalizationProbe()

	unsigned, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalizeReportJSON(unsigned)
	if err != nil {
		t.Fatalf("canonicalize the fixture: %v", err)
	}
	members["public_key"] = hex.EncodeToString(public)
	members["signer_fingerprint"] = Fingerprint(public)
	members["signature"] = SignCanonical(canonical, key)

	render := func() []byte {
		out, err := json.MarshalIndent(members, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return append(out, '\n')
	}
	valid := render()

	// One byte of a signed member: the last digit of the plan id.
	const planID = `"plan_id": "synthetic-plan-001"`
	if !bytes.Contains(valid, []byte(planID)) {
		t.Fatal("the fixture has no plan_id to tamper with")
	}
	tampered := bytes.Replace(valid, []byte(planID), []byte(`"plan_id": "synthetic-plan-002"`), 1)

	digest, err := SignatureImprint(members["signature"].(string))
	if err != nil {
		t.Fatal(err)
	}
	token, err := StubTimestamper{Now: func() time.Time { return time.Date(2026, 10, 2, 12, 5, 0, 0, time.UTC) }}.Timestamp(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	members[TimestampMember] = token
	stamped := render()

	signer, err := json.MarshalIndent(map[string]string{
		"note":        "A throwaway key for the verify-page fixtures; its seed is derived from a public string. Not a CertiStack signing key.",
		"public_key":  hex.EncodeToString(public),
		"fingerprint": Fingerprint(public),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"valid.json": valid, "tampered.json": tampered, "valid-stub-timestamp.json": stamped, "signer.json": append(signer, '\n'),
	}
}

func TestVerifyPageFixtures_AreReproducibleAndMeanWhatTheyClaim(t *testing.T) {
	fixtures := verifyPageFixtures(t)
	again := verifyPageFixtures(t)
	for name, data := range fixtures {
		if !bytes.Equal(data, again[name]) {
			t.Fatalf("%s is not deterministic: two generations differ", name)
		}
	}

	if os.Getenv(updateVerifyPageFixturesEnv) != "" {
		if err := os.MkdirAll(verifyPageFixtureDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, data := range fixtures {
			if err := os.WriteFile(filepath.Join(verifyPageFixtureDir, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, want := range fixtures {
		got, err := os.ReadFile(filepath.Join(verifyPageFixtureDir, name))
		if err != nil {
			t.Fatalf("%v (regenerate with %s=1)", err, updateVerifyPageFixturesEnv)
		}
		if !bytes.Equal(bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n")), want) {
			t.Errorf("testdata/verify-page/%s differs from what the code generates; regenerate with %s=1 go test ./pkg/attest -run VerifyPageFixtures", name, updateVerifyPageFixturesEnv)
		}
	}

	public := verifyPageFixtureKey().Public().(ed25519.PublicKey)
	trusted := []ed25519.PublicKey{public}

	// valid: signed, verifies against the fixture key, no timestamp.
	report, valid, err := VerifyReport(fixtures["valid.json"], trusted)
	if err != nil || !valid {
		t.Fatalf("valid.json: valid=%v err=%v", valid, err)
	}
	if report.SignatureTimestamp != nil || report.ReportSchemaVersion != CurrentReportSchemaVersion || !report.AllPassed || report.Environment != "Zürich ✓ (synthetic)" {
		t.Errorf("valid.json decodes to %+v", report)
	}
	// The overall pass must be one its own records bear out: a "valid" example
	// whose VM says it failed would teach the wrong reading of a good report.
	if len(report.VMRecords) == 0 {
		t.Error("valid.json has no VM record to bear out its overall pass")
	}
	for _, vm := range report.VMRecords {
		if !vm.AllPassed || vm.VerificationStatus != "verified" {
			t.Errorf("valid.json claims all_passed but VM %d records all_passed=%v verification_status=%q", vm.VMID, vm.AllPassed, vm.VerificationStatus)
		}
		for _, result := range vm.ProbeResults {
			if !result.Passed {
				t.Errorf("valid.json claims all_passed but VM %d probe %q did not pass", vm.VMID, result.Description)
			}
		}
	}

	// tampered: differs from valid by exactly one byte, which the signature catches.
	differing := 0
	for i := range fixtures["valid.json"] {
		if fixtures["valid.json"][i] != fixtures["tampered.json"][i] {
			differing++
		}
	}
	if len(fixtures["valid.json"]) != len(fixtures["tampered.json"]) || differing != 1 {
		t.Errorf("tampered.json differs from valid.json in %d bytes (lengths %d, %d), want exactly 1", differing, len(fixtures["valid.json"]), len(fixtures["tampered.json"]))
	}
	if _, valid, err := VerifyReport(fixtures["tampered.json"], trusted); !errors.Is(err, ErrInvalidSignature) || valid {
		t.Errorf("tampered.json: valid=%v err=%v, want ErrInvalidSignature", valid, err)
	}

	// valid-stub-timestamp: verifies, and its canonical bytes are valid.json's.
	stamped, valid, err := VerifyReport(fixtures["valid-stub-timestamp.json"], trusted)
	if err != nil || !valid {
		t.Fatalf("valid-stub-timestamp.json: valid=%v err=%v", valid, err)
	}
	status, err := EvaluateTimestamp(stamped)
	if err != nil || status.State != TimestampStub || status.Evidence() {
		t.Errorf("valid-stub-timestamp.json timestamp = %+v, %v; want a stub, not evidence", status, err)
	}
	canonicalValid, _ := CanonicalizeReportJSON(fixtures["valid.json"])
	canonicalStamped, _ := CanonicalizeReportJSON(fixtures["valid-stub-timestamp.json"])
	if !bytes.Equal(canonicalValid, canonicalStamped) {
		t.Error("the stub timestamp changed the canonical bytes")
	}

	// The canonical form is what the page's JavaScript must reproduce. Pin the
	// parts that are easy to get wrong, so a change of the canonicalizer under
	// these fixtures is seen here and not first in a browser.
	canonical := string(canonicalValid)
	for _, want := range []string{
		`"numbers":[1,1.5,0.000001,1e-7,100,0,9007199254740991,-9007199254740991,9007199254740991,4500000000000000,123456789.12345679,5e-324,0.1,1,0,-0.0015]`,
		`"strings":["Zürich ✓","astral 😀 and ～","tab\there","quote \" and back\\slash and / slash","nul\u0000 and \u001f and del` + "\u007f" + `","line` + " " + `separator","<tag> & more",""]`,
		`"nested":[{"x":[{"a":null,"b":true}],"y":1},[],{},null,true,false,0]`,
	} {
		if !strings.Contains(canonical, want) {
			t.Errorf("the canonical form lacks\n%s\nin\n%s", want, canonical)
		}
	}
	// UTF-16 order: "" < "10" < "2" < "B" < "Z" < "a" < "a\0" < "aa" < "b" < "z" < "é" < astral < U+FF5E.
	wantKeys := `"unsorted_keys":{"":9,"10":10,"2":11,"C":3,"Y":6,"a":2,"a\u0000":13,"aa":12,"b":1,"z":5,"é":4,"😀":8,"～":7}`
	if !strings.Contains(canonical, wantKeys) {
		t.Errorf("the canonical form lacks the UTF-16 key order\n%s\nin\n%s", wantKeys, canonical)
	}
}

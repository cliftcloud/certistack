// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The Enterprise receiver keeps this very report as its own golden
// (internal/telemetryreport/testdata/client-report.json): the two files are
// the contract, and must stay byte for byte the same. The client's body is the
// same five members in the same order, indented; JSON carries no meaning in
// its whitespace, so the receiver reads both.
func TestTheReceiversGoldenReportIsAPayloadAndEncodesBackToItself(t *testing.T) {
	golden, err := os.ReadFile("testdata/receiver-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(golden))
	dec.DisallowUnknownFields()
	var p Payload
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("the receiver's golden report is not a Payload: %v", err)
	}
	compact, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(compact) != strings.TrimSpace(string(golden)) {
		t.Fatalf("a Payload encodes compactly as\n%s\nnot as the receiver's golden\n%s", compact, golden)
	}
	// And what the client sends, minus whitespace, is that same document.
	var squeezed bytes.Buffer
	if err := json.Compact(&squeezed, p.Encode()); err != nil {
		t.Fatal(err)
	}
	if squeezed.String() != string(compact) {
		t.Fatalf("the sent body is not the golden document:\n%s\n%s", squeezed.String(), compact)
	}
}

// The receiver requires all five members, zero values included, so none may
// ever vanish from the body (an omitempty tag would drop them).
func TestAZeroPayloadStillCarriesAllFiveMembers(t *testing.T) {
	body := Payload{}.Encode()
	var members map[string]any
	if err := json.Unmarshal(body, &members); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"install_id", "version", "cluster_count", "last_test_run", "business_use"} {
		if _, ok := members[name]; !ok {
			t.Errorf("an all-zero payload has no %q member:\n%s", name, body)
		}
	}
}

// The payload is five fields and nothing else. A sixth field is a change to
// what leaves the machine: it needs this test, docs/telemetry.md and the
// receiver changed together, on purpose.
func TestPayloadHasExactlyTheFiveDocumentedFields(t *testing.T) {
	type field struct{ name, tag, kind string }
	want := []field{
		{"InstallID", "install_id", "string"},
		{"Version", "version", "string"},
		{"ClusterCount", "cluster_count", "int"},
		{"LastTestRun", "last_test_run", "string"},
		{"BusinessUse", "business_use", "bool"},
	}
	typ := reflect.TypeOf(Payload{})
	if typ.NumField() != len(want) {
		t.Fatalf("Payload has %d fields, want exactly %d", typ.NumField(), len(want))
	}
	for i, w := range want {
		f := typ.Field(i)
		if f.Name != w.name || f.Tag.Get("json") != w.tag || f.Type.Kind().String() != w.kind {
			t.Errorf("field %d is %s %s `json:%q`, want %s %s `json:%q`", i, f.Name, f.Type, f.Tag.Get("json"), w.name, w.kind, w.tag)
		}
		if f.Tag != reflect.StructTag(`json:"`+w.tag+`"`) {
			t.Errorf("field %s carries tag options beyond the name: %q", f.Name, f.Tag)
		}
	}
}

func TestPayloadGoldenJSON(t *testing.T) {
	body := Payload{
		InstallID:    "5b0f3a52-8f63-4c6e-9d0b-1d2e3f4a5b6c",
		Version:      "0.1.0",
		ClusterCount: 2,
		LastTestRun:  "2026-10-01",
		BusinessUse:  true,
	}.Encode()
	const golden = `{
  "install_id": "5b0f3a52-8f63-4c6e-9d0b-1d2e3f4a5b6c",
  "version": "0.1.0",
  "cluster_count": 2,
  "last_test_run": "2026-10-01",
  "business_use": true
}
`
	if string(body) != golden {
		t.Fatalf("encoded payload:\n%s\nwant:\n%s", body, golden)
	}
	// What the receiver does: a strict decode that refuses any other member.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var back Payload
	if err := dec.Decode(&back); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if back.ClusterCount != 2 || !back.BusinessUse || back.LastTestRun != "2026-10-01" {
		t.Fatalf("round trip lost a field: %+v", back)
	}
}

func TestSanitizeVersionKeepsPrintableASCIIOnlyAndBoundsIt(t *testing.T) {
	long := strings.Repeat("a", 200)
	for _, tc := range []struct{ in, want string }{
		{"0.1.0", "0.1.0"},
		{"v0.1.0-rc2+dirty", "v0.1.0-rc2+dirty"},
		{"dev", "dev"},
		{"", "unknown"},
		{"1.0\r\nX-Injected: yes", "1.0X-Injected: yes"},
		{"café 1.0", "caf 1.0"},
		{"\x00\x7f\x1b[31m", "[31m"},
		{long, long[:64]},
		{"ééé", "unknown"},
	} {
		if got := SanitizeVersion(tc.in); got != tc.want {
			t.Errorf("SanitizeVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

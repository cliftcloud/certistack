// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// Characters that can hide or reorder text, spelled by code point so the test
// source holds none of them literally.
var (
	testRLO  = string(rune(0x202e)) // right-to-left override
	testLRI  = string(rune(0x2066)) // left-to-right isolate
	testZWSP = string(rune(0x200b)) // zero width space
	testLSEP = string(rune(0x2028)) // line separator
)

// assertNoTextHazards fails when text is not valid UTF-8 or still holds a
// terminal escape or a character that reorders or hides text.
func assertNoTextHazards(t *testing.T, what, text string) {
	t.Helper()
	if !utf8.ValidString(text) {
		t.Errorf("%s is not valid UTF-8", what)
	}
	for _, hazard := range []string{"\x1b", "\x00", testRLO, testLRI, testZWSP, testLSEP} {
		if strings.Contains(text, hazard) {
			t.Errorf("%s holds %U", what, []rune(hazard)[0])
		}
	}
}

// The live network diagnostic is text the guest chose end to end: its
// interface names, its agent's error messages, its command's output. Every
// branch of captureLiveNetworkDiagnostic used to put some of it into the kept
// diagnostic with no cap and no cleaning (only the success branch capped it, and
// none cleaned it); the diagnostic is printed and carried into the report.
func TestCaptureLiveNetworkDiagnosticBoundsAndCleansWhatTheGuestSays(t *testing.T) {
	const mac, want = "aa:bb:cc:dd:ee:ff", "10.70.0.99"
	hostile := "\x1b[2J" + testRLO + strings.Repeat("G", 3<<20)
	// Command output travels base64-encoded in one reply line, which the client
	// holds to 4 MiB; 900 KiB of text is a huge output that still arrives.
	output := "\x1b[2J" + testRLO + strings.Repeat("G", 900<<10)
	// The recovered NIC has a hostile name, and a guest can list as many more
	// interfaces as one reply line holds: the inventory alone is far over 16 KiB.
	inventory := []any{map[string]any{
		"name":             "eth0\x1b[31m" + testRLO + strings.Repeat("N", 20<<10),
		"hardware-address": mac,
		"ip-addresses":     []any{map[string]any{"ip-address": "192.0.2.5", "ip-address-type": "ipv4", "prefix": 24}},
	}}
	for i := 0; i < 3000; i++ {
		inventory = append(inventory, map[string]any{
			"name":             fmt.Sprintf("veth%s%04d", strings.Repeat("v", 20), i),
			"hardware-address": fmt.Sprintf("02:00:00:00:%02x:01", i/256),
			"ip-addresses":     []any{map[string]any{"ip-address": "10.99.0.1", "ip-address-type": "ipv4", "prefix": 32}},
		})
	}
	interfaces := map[string]any{"return": inventory}
	encode := func(text string) string { return base64.StdEncoding.EncodeToString([]byte(text)) }

	for name, tc := range map[string]struct {
		replies  map[string]any
		complete bool
	}{
		"guest-exec refused with a huge error text": {map[string]any{
			"guest-network-get-interfaces": interfaces,
			"guest-exec":                   map[string]any{"error": map[string]any{"class": "GenericError", "desc": hostile}},
		}, false},
		"the command fails with a huge stderr": {map[string]any{
			"guest-network-get-interfaces": interfaces,
			"guest-exec":                   map[string]any{"return": map[string]any{"pid": 77}},
			"guest-exec-status":            map[string]any{"return": map[string]any{"exited": true, "exitcode": 2, "err-data": encode(output)}},
		}, false},
		"the command succeeds with a huge stdout": {map[string]any{
			"guest-network-get-interfaces": interfaces,
			"guest-exec":                   map[string]any{"return": map[string]any{"pid": 77}},
			"guest-exec-status":            map[string]any{"return": map[string]any{"exited": true, "exitcode": 0, "out-data": encode(output + "\n" + testLSEP + testZWSP + "tail")}},
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := shortSocketDir(t)
			fakeQGA(t, dir, 9201, tc.replies, nil)
			o := &Orchestrator{opts: Options{QGASocketDir: dir}}
			diagnostic, diagnosis, complete, err := o.captureLiveNetworkDiagnostic(context.Background(), 9201, mac, want)
			if err != nil || complete != tc.complete {
				t.Fatalf("complete=%v err=%v, want complete=%v", complete, err, tc.complete)
			}
			if limit := 16<<10 + len("\n[truncated]"); len(diagnostic) > limit {
				t.Errorf("the diagnostic is %d bytes, want at most %d", len(diagnostic), limit)
			}
			assertNoTextHazards(t, "diagnostic", diagnostic)
			assertNoTextHazards(t, "diagnosis", diagnosis)
			if !strings.Contains(diagnostic, "[interfaces via QGA]") || !strings.Contains(diagnosis, "recovery address "+want) {
				t.Errorf("the diagnostic lost its own content: diagnosis %.100q diagnostic %.100q", diagnosis, diagnostic)
			}
		})
	}
}

func TestNormalizeNetworkDiagnosticCleansAndCutsAtACharacterBoundary(t *testing.T) {
	got := normalizeNetworkDiagnostic("  eth0 \x1b[31mup" + testRLO + testLRI + "\n" + testZWSP + "lo\n")
	if got != "eth0 [31mup\nlo" {
		t.Errorf("normalizeNetworkDiagnostic = %q", got)
	}
	// A two-byte character across the 16 KiB limit is dropped whole, not cut
	// in half.
	cut := normalizeNetworkDiagnostic(strings.Repeat("a", 16<<10-1) + strings.Repeat(string(rune(0xe9)), 10))
	if !utf8.ValidString(cut) || !strings.HasSuffix(cut, "\n[truncated]") || len(cut) > 16<<10+len("\n[truncated]") {
		t.Errorf("cut text: valid=%v length=%d", utf8.ValidString(cut), len(cut))
	}
}

// A diagnostic that reaches the report was not always read through the
// agent: when the live read has no listeners or no agent answered, the run
// reads back the file the guest's own boot script wrote into the overlay, which
// a hostile guest can fill with anything. Whichever way a diagnostic was
// captured, it is cleaned and bounded on its way into the VM's record.
func TestRecordedNetworkDiagnosticIsCleanedWhateverCapturedIt(t *testing.T) {
	hostile := "[captured at boot]\n\x1b[2J" + testRLO + strings.Repeat("O", 40<<10) + "\ntail" + testLSEP
	o := &Orchestrator{networkDiagnostics: map[int]string{
		9301: hostile,
		9302: "[interfaces via QGA]\neth0 aa:bb:cc:dd:ee:ff 10.70.0.15/24",
	}}
	records := []probe.VMValidationRecord{{VMID: 9301}, {VMID: 9302}, {VMID: 9303}}
	o.recordNetworkDiagnostics(records)

	if got := records[0].NetworkRecoveryDiagnostic; len(got) > 16<<10+len("\n[truncated]") || !strings.HasSuffix(got, "\n[truncated]") || !strings.HasPrefix(got, "[captured at boot]\n[2J") {
		t.Errorf("a hostile overlay diagnostic became %d bytes: %.60q...", len(got), got)
	}
	assertNoTextHazards(t, "recorded diagnostic", records[0].NetworkRecoveryDiagnostic)
	if got := records[1].NetworkRecoveryDiagnostic; got != "[interfaces via QGA]\neth0 aa:bb:cc:dd:ee:ff 10.70.0.15/24" {
		t.Errorf("an ordinary diagnostic changed: %q", got)
	}
	if got := records[2].NetworkRecoveryDiagnostic; got != "" {
		t.Errorf("a VM with no diagnostic got %q", got)
	}
}

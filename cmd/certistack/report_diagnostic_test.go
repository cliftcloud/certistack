// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// A guest's capture as the run keeps it: many lines, with indentation, the
// way the failed-VM diagnostic prints them.
const sampleDiagnostic = `[captured after boot settled: 31.20 s after boot; system running; multi-user.target active]
[interfaces]
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth0             UP             192.0.2.10/24
[listeners]
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
[failed services]
[enabled services not active]
ssh.service inactive/dead result=success condition=no
first-boot.service inactive/dead result=success condition=yes
[networkd status]
● 2: eth0
       Link File: /usr/lib/systemd/network/99-default.link
           State: routable (configured)`

func diagnosticReportPath(t *testing.T, diagnostic string) string {
	t.Helper()
	report := twinReport(twinFailID, twinFailTime, false, 100)
	report.VMRecords[0].NetworkRecoveryDiagnostic = diagnostic
	return writeFixtureReport(t, t.TempDir(), "report.json", report, nil)
}

// `report show` printed the diagnostic as the VM's third line, flattened and
// cut at 300 characters, so the services section the capture exists to show was
// never on screen. It is shown whole, after the VM's probes, indented, one line
// of the capture to a line of output.
func TestReportShowPrintsTheWholeNetworkDiagnosticAfterTheProbes(t *testing.T) {
	path := diagnosticReportPath(t, sampleDiagnostic)
	text, _, err := runReportCommand(t, "report", "show", path)
	if err != nil {
		t.Fatal(err)
	}
	heading := "    Network diagnostic (taken inside the guest):\n"
	at := strings.Index(text, heading)
	if at < 0 {
		t.Fatalf("no network diagnostic block:\n%s", text)
	}
	if probes := strings.Index(text, "    Probes ("); probes < 0 || probes > at {
		t.Errorf("the diagnostic is not after the probes:\n%s", text)
	}
	if strings.Contains(text[:at], "[captured after boot settled") {
		t.Errorf("the diagnostic is still shown above the probes:\n%s", text)
	}
	block := text[at+len(heading):]
	if end := strings.Index(block, "\nTeardown"); end >= 0 {
		block = block[:end]
	}
	var want strings.Builder
	for _, line := range strings.Split(sampleDiagnostic, "\n") {
		want.WriteString("      " + line + "\n")
	}
	if !strings.HasPrefix(block, want.String()) {
		t.Errorf("the block is not the capture, a line to a line, indented:\n%s\nwant it to start with:\n%s", block, want.String())
	}
	for _, line := range []string{"ssh.service inactive/dead result=success condition=no", "       Link File: /usr/lib/systemd/network/99-default.link"} {
		if !strings.Contains(block, line) {
			t.Errorf("the block lacks %q:\n%s", line, block)
		}
	}
	if strings.Contains(text, "[cut here") {
		t.Errorf("a capture that fits was said to be cut:\n%s", text)
	}
}

// The JSON view carries the same whole text, and no more than the text view:
// the member keeps its name, and its line breaks.
func TestReportShowJSONCarriesTheWholeNetworkDiagnostic(t *testing.T) {
	path := diagnosticReportPath(t, sampleDiagnostic)
	stdout, _, err := runReportCommand(t, "report", "show", "--json", path)
	if err != nil {
		t.Fatal(err)
	}
	var shown reportView
	if err := json.Unmarshal([]byte(stdout), &shown); err != nil {
		t.Fatal(err)
	}
	if got := shown.Report.VMs[0].NetworkRecovery.Diagnostic; got != sampleDiagnostic {
		t.Errorf("the JSON diagnostic is not the whole capture:\n%s", got)
	}
	if shown.ViewVersion != reportViewVersion || reportViewVersion != 1 {
		t.Errorf("view_version = %d; a member's text gaining line breaks does not change it", shown.ViewVersion)
	}
}

// A capture is a guest's text, so the view cleans it as it cleans every text of
// a report, line by line, and bounds it: bytes, lines and the width of a line.
// A cut says where the whole text is.
func TestReportShowBoundsAndCleansANetworkDiagnosticLineByLine(t *testing.T) {
	hostile := "[interfaces]\r\nlo \x1b[31mred\x1b[0m \u202e reversed\x00\ttabbed\n" + strings.Repeat("A", 5000) + "\n\n\nlast line\n\n"
	for _, asJSON := range []bool{false, true} {
		args := []string{"report", "show", diagnosticReportPath(t, hostile)}
		if asJSON {
			args = append(args, "--json")
		}
		stdout, _, err := runReportCommand(t, args...)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(stdout, "\x1b") || strings.Contains(stdout, "\u202e") {
			t.Errorf("json=%v: a control or bidirectional character reached the output", asJSON)
		}
		for _, r := range stdout {
			if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
				t.Fatalf("json=%v: the output carries the control or format character %U", asJSON, r)
			}
		}
		if strings.Contains(stdout, strings.Repeat("A", maxViewDiagnosticLineRunes+10)) {
			t.Errorf("json=%v: a 5000-character line was not cut", asJSON)
		}
	}
	text, _, err := runReportCommand(t, "report", "show", diagnosticReportPath(t, hostile))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"      [interfaces]\n", "      lo [31mred", "      " + strings.Repeat("A", maxViewDiagnosticLineRunes) + "…\n", "      last line\n", "[cut here: the whole text is the network_recovery_diagnostic of this VM in the report file]"} {
		if !strings.Contains(text, want) {
			t.Errorf("the block lacks %q:\n%s", want, text)
		}
	}
}

func TestReportShowCutsAnOversizedNetworkDiagnosticAtItsBounds(t *testing.T) {
	var many strings.Builder
	for i := 0; i < 3*maxViewDiagnosticLines; i++ {
		fmt.Fprintf(&many, "line %d\n", i)
	}
	text, _, err := runReportCommand(t, "report", "show", diagnosticReportPath(t, many.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, fmt.Sprintf("      line %d\n", maxViewDiagnosticLines-1)) || strings.Contains(text, fmt.Sprintf("      line %d\n", maxViewDiagnosticLines)) {
		t.Errorf("the lines were not cut at %d", maxViewDiagnosticLines)
	}
	if !strings.Contains(text, "[cut here: the whole text is the network_recovery_diagnostic") {
		t.Error("a cut capture does not say where the whole text is")
	}
	huge := strings.Repeat("0123456789abcdef\n", 4*maxViewDiagnosticBytes/17)
	text, _, err = runReportCommand(t, "report", "show", diagnosticReportPath(t, huge))
	if err != nil {
		t.Fatal(err)
	}
	if len(text) > 2*maxViewDiagnosticBytes+maxViewDiagnosticLines*8 || !strings.Contains(text, "[cut here") {
		t.Errorf("a %d-byte capture printed %d bytes", len(huge), len(text))
	}
}

// A report with no diagnostic prints no block, and an empty one counts as none.
func TestReportShowPrintsNoDiagnosticBlockWhenThereIsNone(t *testing.T) {
	for _, diagnostic := range []string{"", "\n\n", " \x1b "} {
		text, _, err := runReportCommand(t, "report", "show", diagnosticReportPath(t, diagnostic))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(text, "Network diagnostic") {
			t.Errorf("diagnostic %q printed a block:\n%s", diagnostic, text)
		}
	}
}

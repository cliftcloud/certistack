// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// diagnosticPath is a PATH holding fake systemctl, journalctl, ip and ss,
// the real text tools the script needs, and nothing else: no networkctl or
// nmcli, as on EL7.
func diagnosticPath(t *testing.T) string {
	t.Helper()
	return diagnosticPathWith(t, nil)
}

// diagnosticPathWith is diagnosticPath with some of its fake tools replaced, or
// added (networkctl, nmcli), by the scripts in extra.
func diagnosticPathWith(t *testing.T, extra map[string]string) string {
	t.Helper()
	bin := t.TempDir()
	fakes := map[string]string{
		"systemctl": `case "$*" in
is-system-running*) echo running ;;
is-active*) echo active ;;
esac`,
		"journalctl": "true",
		// A test can hold a capture inside its body: while CERTISTACK_TEST_GATE
		// is set, ip says it started and waits for that file to appear.
		"ip": `if [ -n "$CERTISTACK_TEST_GATE" ]; then : > "$CERTISTACK_TEST_STARTED"; while [ ! -e "$CERTISTACK_TEST_GATE" ]; do sleep 0.05; done; fi
true`,
		"ss": `echo 'tcp LISTEN 0 128 *:389 *:* users:(("ns-slapd",pid=812,fd=8))'`,
	}
	for name, body := range extra {
		fakes[name] = body
	}
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"awk", "cut", "grep", "head", "tail", "mv", "cat", "mktemp", "chmod", "chown", "rm", "sleep"} {
		if _, faked := fakes[tool]; faked {
			continue // a test that replaces a tool gets its own
		}
		real, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s not found: %v", tool, err)
		}
		if err := os.Symlink(real, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return bin
}

// EL7, 7396: the overlay's diagnostic was taken inside the
// recovery service, with multi-user.target still waiting, and said
// "networkctl: command not found". Each capture now says when it ran, a
// missing tool is named, and the capture replaces the file whole.
func TestBootDiagnosticSaysWhenItRanAndNamesMissingTools(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the diagnostic is a guest shell script")
	}
	path := diagnosticPath(t)
	dir := t.TempDir()
	output := filepath.Join(dir, "network-recovery.txt")
	script := filepath.Join(dir, "capture-network-recovery")
	if err := os.WriteFile(script, []byte(bootDiagnosticScript(output)), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		when string
	}{
		{nil, "[captured during boot: "},
		{[]string{"eth0", "up"}, "[captured on NetworkManager event up for eth0: "},
		{[]string{"after-boot"}, "[captured after boot settled: "},
	} {
		// Each capture is stamped with when it began, in hundredths of a second.
		time.Sleep(30 * time.Millisecond)
		cmd := exec.CommandContext(context.Background(), "/bin/sh", append([]string{script}, tc.args...)...)
		cmd.Env = []string{"PATH=" + path}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("script %v: %v\n%s", tc.args, err, out)
		}
		got := newestCapture(t, dir)
		for _, want := range []string{tc.when, "s after boot; system running; multi-user.target active]", "ns-slapd", "[networkd] not installed", "[networkmanager] not installed"} {
			if !strings.Contains(got, want) {
				t.Errorf("capture %v lacks %q:\n%s", tc.args, want, got)
			}
		}
		if strings.Contains(got, "not found") || strings.Count(got, "[captured ") != 1 {
			t.Errorf("capture %v is noisy or not replaced whole:\n%s", tc.args, got)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The script and the three captures, each published whole under its own
	// name; no temporary file is left.
	if len(entries) != 4 {
		t.Fatalf("files left beside the capture: %v", entries)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			t.Fatalf("a temporary file was left: %s", entry.Name())
		}
	}
}

// newestCapture is what the reader would take from the directory a capture
// script wrote into: the newest capture's whole text.
func newestCapture(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	name := newestDiagnostic(names)
	if name == "" {
		t.Fatalf("no capture in %s: %v", dir, names)
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The live diagnostic, through the guest agent, shares the body.
func TestLiveDiagnosticSaysItWasLive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the diagnostic is a guest shell script")
	}
	cmd := exec.Command("/bin/sh", "-c", LiveDiagnosticCommand())
	cmd.Env = []string{"PATH=" + diagnosticPath(t)}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("live diagnostic: %v\n%s", err, out)
	}
	if !strings.HasPrefix(string(out), "[captured live, through the guest agent: ") || strings.Contains(string(out), "not found") {
		t.Fatalf("live diagnostic:\n%s", out)
	}
}

// The boot diagnostic unit runs after the network is online when the
// guest brings it online, but it must not ask for it. `Wants=` on
// network-online.target pulls the target (and with it the guest's wait-online
// service) into a boot that never had it, so a failed VM would boot slower, or
// differently, than the same guest did in production.
func TestDiagnosticUnitsAreOrderedAfterTheNetworkWithoutPullingItIn(t *testing.T) {
	stageDir := t.TempDir()
	install, err := diagnosticMutations(stageDir)
	if err != nil {
		t.Fatal(err)
	}
	commands := install.commands
	units := map[string]string{}
	for _, command := range commands {
		if len(command) == 3 && command[0] == "upload" && (command[2] == diagnosticUnit || command[2] == diagnosticLateUnit) {
			contents, err := os.ReadFile(command[1])
			if err != nil {
				t.Fatal(err)
			}
			units[command[2]] = string(contents)
		}
	}
	if len(units) != 2 {
		t.Fatalf("staged units = %v, want the boot unit and the after-boot unit", units)
	}
	for destination, unit := range units {
		for _, line := range strings.Split(unit, "\n") {
			for _, pulling := range []string{"Wants=", "Requires=", "BindsTo=", "Requisite="} {
				if strings.HasPrefix(strings.TrimSpace(line), pulling) {
					t.Errorf("%s has %q, which would pull a unit into the guest's boot:\n%s", destination, line, unit)
				}
			}
		}
	}
	if boot := units[diagnosticUnit]; !strings.Contains(boot, "After=NetworkManager.service network-online.target") {
		t.Errorf("the boot unit lost its ordering after the network:\n%s", boot)
	}
}

// The after-boot capture waits for the manager to leave "starting", which it
// never does while a job is pending. A oneshot service's start job lasts as
// long as its script runs, so a oneshot would wait for itself until the wait
// ran out and always report "system starting" (the capture at 12 s in the
// reported run did). It is a simple service ordered after multi-user.target
// and wanted by it, and the boot capture, which does not wait, stays a oneshot.
func TestTheAfterBootUnitDoesNotHoldItsOwnStartJobOpen(t *testing.T) {
	install, err := diagnosticMutations(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	units := map[string]string{}
	for _, command := range install.commands {
		if len(command) == 3 && command[0] == "upload" && (command[2] == diagnosticUnit || command[2] == diagnosticLateUnit) {
			contents, err := os.ReadFile(command[1])
			if err != nil {
				t.Fatal(err)
			}
			units[command[2]] = string(contents)
		}
	}
	late := units[diagnosticLateUnit]
	for _, want := range []string{"Type=simple\n", "After=multi-user.target\n", "WantedBy=multi-user.target\n", " after-boot\n"} {
		if !strings.Contains(late, want) {
			t.Errorf("the after-boot unit lacks %q:\n%s", want, late)
		}
	}
	if strings.Contains(late, "Type=oneshot") {
		t.Errorf("the after-boot unit is a oneshot, which keeps the system \"starting\" while it waits for it to settle:\n%s", late)
	}
	if boot := units[diagnosticUnit]; !strings.Contains(boot, "Type=oneshot") || strings.Contains(boot, "after-boot") {
		t.Errorf("the boot unit changed:\n%s", boot)
	}
}

// Network recovery installs the after-boot capture beside the boot one.
func TestDiagnosticInstallsTheAfterBootCapture(t *testing.T) {
	install, err := diagnosticMutations(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var joined []string
	for _, command := range install.commands {
		joined = append(joined, strings.Join(command, " "))
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{diagnosticLateUnit, "ln-s ../certistack-network-recovery-late.service " + diagnosticLateLink} {
		if !strings.Contains(all, want) {
			t.Errorf("mutations lack %q:\n%s", want, all)
		}
	}
}

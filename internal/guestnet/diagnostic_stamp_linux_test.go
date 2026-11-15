// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build linux

package guestnet

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// newUptimeCaptureEnv is a capture environment whose cut answers the capture's
// read of /proc/uptime with the contents of the file named by
// CERTISTACK_TEST_UPTIME, and is the real cut for everything else.
func newUptimeCaptureEnv(t *testing.T) *captureEnv {
	t.Helper()
	e := newCaptureEnv(t, nil)
	real, err := exec.LookPath("cut")
	if err != nil {
		t.Skipf("cut not found: %v", err)
	}
	shim := filepath.Join(e.path, "cut")
	if err := os.Remove(shim); err != nil {
		t.Fatal(err)
	}
	body := `#!/bin/sh
case "$*" in
*/proc/uptime*) exec ` + real + ` -d' ' -f1 "$CERTISTACK_TEST_UPTIME" ;;
*) exec ` + real + ` "$@" ;;
esac
`
	if err := os.WriteFile(shim, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return e
}

// The capture's start stamp is the second key of the newest-capture
// order, and the only key that follows time when process IDs do not (they wrap,
// and a container hands them out in its own order). Every other test of the
// order starts its captures in PID order, so the stamp was never what decided:
// replacing it with a constant left the package green. These give the script an
// uptime of their own, and read the stamp off the name it publishes under.
func TestEachCaptureIsNamedForTheUptimeItBeganAt(t *testing.T) {
	for _, tc := range []struct {
		name, uptime, stamp string
	}{
		{"hundredths of a second", "12.34 5.67\n", "0000001234"},
		{"a long uptime", "123456.78 9.01\n", "0012345678"},
		{"no fraction", "7\n", "0000000700"},
		{"padded to ten digits", "0.05 0.00\n", "0000000005"},
		{"more digits than fit keep the latest ten", "99999999999.99 1.00\n", "9999999999"},
		{"unreadable", "not a number\n", "0000000000"},
		{"nothing", "\n", "0000000000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newUptimeCaptureEnv(t)
			uptime := filepath.Join(t.TempDir(), "uptime")
			if err := os.WriteFile(uptime, []byte(tc.uptime), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := e.command([]string{"CERTISTACK_TEST_UPTIME=" + uptime})
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("capture: %v\n%s", err, out)
			}
			names := e.captures()
			if len(names) != 1 {
				t.Fatalf("captures = %v, want one", names)
			}
			if match := diagnosticName.FindStringSubmatch(names[0]); match == nil || match[1] != tc.stamp {
				t.Fatalf("the capture published as %s, want the stamp %s", names[0], tc.stamp)
			}
		})
	}
}

// The capture that began at the later uptime is the newest, whatever order the
// two ended in and whichever has the higher process ID: the stamp is compared
// before the PID. Here the capture of the later uptime is the earlier process.
func TestTheLaterUptimeIsTheNewestCaptureWhateverTheProcessIDs(t *testing.T) {
	e := newUptimeCaptureEnv(t)
	run := func(uptime, trigger string) {
		t.Helper()
		file := filepath.Join(t.TempDir(), "uptime")
		if err := os.WriteFile(file, []byte(uptime+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := e.command([]string{"CERTISTACK_TEST_UPTIME=" + file}, trigger).CombinedOutput(); err != nil {
			t.Fatalf("capture: %v\n%s", err, out)
		}
	}
	run("300.00", "after-boot") // the lower process ID, the later uptime
	run("200.00", "")           // the higher process ID, the earlier uptime
	if got := newestCapture(t, e.dir); !strings.Contains(got, "[captured after boot settled: ") {
		t.Fatalf("the capture of the earlier uptime was taken for the newest:\n%s", got)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build linux

package guestnet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests run the real generated capture script under /bin/sh, with fake
// systemctl, ip and the like on PATH, as the reporter's probes did.

type captureEnv struct {
	t      *testing.T
	dir    string // the diagnostic directory, with the script in it
	out    string // the base path the script publishes under
	script string
	path   string
}

func newCaptureEnv(t *testing.T, extra map[string]string) *captureEnv {
	t.Helper()
	dir := t.TempDir()
	e := &captureEnv{t: t, dir: dir, out: filepath.Join(dir, "network-recovery.txt"), script: filepath.Join(dir, "capture-network-recovery"), path: diagnosticPathWith(t, extra)}
	if err := os.WriteFile(e.script, []byte(bootDiagnosticScript(e.out)), 0o700); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *captureEnv) command(env []string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(context.Background(), "/bin/sh", append([]string{e.script}, args...)...)
	cmd.Env = append([]string{"PATH=" + e.path}, env...)
	return cmd
}

// run runs a capture to its end.
func (e *captureEnv) run(args ...string) {
	e.t.Helper()
	if out, err := e.command(nil, args...).CombinedOutput(); err != nil {
		e.t.Fatalf("capture %v: %v\n%s", args, err, out)
	}
}

func TestCaptureRemovesAbandonedTemporaryFiles(t *testing.T) {
	e := newCaptureEnv(t, nil)
	stale := filepath.Join(e.dir, ".capture.abandoned")
	if err := os.WriteFile(stale, []byte("unfinished"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.run()
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatalf("abandoned capture remains: %v", err)
	}
	active := filepath.Join(e.dir, fmt.Sprintf(".capture.%d.synthetic", os.Getpid()))
	if err := os.WriteFile(active, []byte("active"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.run()
	if data, err := os.ReadFile(active); err != nil || string(data) != "active" {
		t.Fatalf("active capture removed: %v", err)
	}
}

// heldCapture is a capture stopped inside its body, after it stamped itself.
type heldCapture struct {
	cmd      *exec.Cmd
	gate     string
	done     chan error
	released bool
}

// hold starts a capture and returns once it is inside its body, where the fake
// ip keeps it until release.
func (e *captureEnv) hold(name string, args ...string) *heldCapture {
	e.t.Helper()
	gate := filepath.Join(e.t.TempDir(), "gate-"+name)
	started := filepath.Join(e.t.TempDir(), "started-"+name)
	cmd := e.command([]string{"CERTISTACK_TEST_GATE=" + gate, "CERTISTACK_TEST_STARTED=" + started}, args...)
	ownProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	held := &heldCapture{cmd: cmd, gate: gate, done: make(chan error, 1)}
	go func() { held.done <- cmd.Wait() }()
	e.t.Cleanup(func() {
		if !held.released {
			killProcessGroup(cmd)
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			return held
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("capture %s never reached its body", name)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// release lets the capture go on and waits for it to end.
func (h *heldCapture) release(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(h.gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := <-h.done
	h.released = true
	if err != nil {
		t.Fatalf("held capture: %v", err)
	}
}

func (e *captureEnv) captures() []string {
	e.t.Helper()
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		e.t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if diagnosticName.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	return names
}

// The reported case. An older capture ("during boot") began first
// and was held inside its body; a newer one ("after boot") ran to the end and
// published; then the older one finished and, with an unconditional rename
// over the shared output, put its older state over the settled capture.
func TestAnOlderCaptureDoesNotReplaceANewerOne(t *testing.T) {
	e := newCaptureEnv(t, nil)
	older := e.hold("boot")
	time.Sleep(100 * time.Millisecond) // captures are stamped to a hundredth of a second
	e.run("after-boot")
	if got := newestCapture(t, e.dir); !strings.Contains(got, "[captured after boot settled: ") {
		t.Fatalf("after the newer capture:\n%s", got)
	}
	older.release(t)
	got := newestCapture(t, e.dir)
	if !strings.Contains(got, "[captured after boot settled: ") || strings.Contains(got, "[captured during boot: ") {
		t.Fatalf("the older capture replaced the settled one:\n%s", got)
	}
	if names := e.captures(); len(names) != 2 {
		t.Fatalf("captures = %v, want both published whole under their own names", names)
	}
}

func permutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var all [][]int
	for _, rest := range permutations(n - 1) {
		for i := 0; i <= len(rest); i++ {
			p := append(append(append([]int(nil), rest[:i]...), n-1), rest[i:]...)
			all = append(all, p)
		}
	}
	return all
}

// Whatever order three overlapping captures end in, the one that began last is
// the one that is read: boot, a NetworkManager event, and the settled capture.
func TestTheCaptureThatBeganLastIsAlwaysTheNewest(t *testing.T) {
	triggers := []struct {
		name string
		args []string
		when string
	}{
		{"boot", nil, "[captured during boot: "},
		{"event", []string{"eth0", "up"}, "[captured on NetworkManager event up for eth0: "},
		{"settled", []string{"after-boot"}, "[captured after boot settled: "},
	}
	for _, order := range permutations(len(triggers)) {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			e := newCaptureEnv(t, nil)
			held := make([]*heldCapture, len(triggers))
			for i, trigger := range triggers {
				held[i] = e.hold(trigger.name, trigger.args...)
				time.Sleep(60 * time.Millisecond)
			}
			for _, i := range order {
				held[i].release(t)
			}
			if got := newestCapture(t, e.dir); !strings.Contains(got, triggers[len(triggers)-1].when) {
				t.Fatalf("releasing in order %v left:\n%s", order, got)
			}
		})
	}
}

func TestNewestDiagnosticPicksTheCaptureThatBeganLast(t *testing.T) {
	entries := []string{
		"network-recovery.txt", "network-recovery.txt.1.2", ".capture.AbC123", "other",
		"network-recovery.txt.0000000100.900", "network-recovery.txt.0000000200.5", "network-recovery.txt.0000000200.40",
		"network-recovery.txt.0000000150.9999", "network-recovery.txt.0000000200.x",
	}
	if got := newestDiagnostic(entries); got != "network-recovery.txt.0000000200.40" {
		t.Fatalf("newest = %q", got)
	}
	if got := newestDiagnostic([]string{"network-recovery.txt", ".capture.x"}); got != "" {
		t.Fatalf("newest of none = %q", got)
	}
	if got := newestDiagnostic(nil); got != "" {
		t.Fatalf("newest of nothing = %q", got)
	}
}

// Only the newest few captures stay in the guest.
func TestOnlyTheNewestCapturesAreKept(t *testing.T) {
	e := newCaptureEnv(t, nil)
	for i := 0; i < diagnosticKeep+4; i++ {
		time.Sleep(15 * time.Millisecond)
		e.run("after-boot")
	}
	if names := e.captures(); len(names) != diagnosticKeep {
		t.Fatalf("captures kept = %d (%v), want %d", len(names), names, diagnosticKeep)
	}
}

// The reported case. A symbolic link planted at the PID-named
// temporary path ("$output.$$") sent the root-owned write into an unrelated
// file, and the final rename published the link itself as the capture. The
// helper plants it at the exact PID the script then keeps by exec.
func TestALinkPlantedAtTheProcessNamedPathIsNotFollowed(t *testing.T) {
	e := newCaptureEnv(t, nil)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("VICTIM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := exec.LookPath("ln")
	if err != nil {
		t.Skip(err)
	}
	helper := filepath.Join(t.TempDir(), "plant")
	body := "#!/bin/sh\n" + ln + " -s " + victim + " " + e.out + ".$$\nexec /bin/sh " + e.script + "\n"
	if err := os.WriteFile(helper, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", helper)
	cmd.Env = []string{"PATH=" + e.path}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capture: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(victim); string(got) != "VICTIM\n" {
		t.Fatalf("the unrelated file was written through the planted link: %q", got)
	}
	names := e.captures()
	if len(names) != 1 {
		t.Fatalf("captures = %v", names)
	}
	info, err := os.Lstat(filepath.Join(e.dir, names[0]))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("the published capture is %v (%v), want a private regular file", info, err)
	}
	if got := newestCapture(t, e.dir); !strings.Contains(got, "[captured during boot: ") {
		t.Fatalf("capture:\n%s", got)
	}
}

// The directory the captures go in is checked first: a link is refused, a
// directory open to others is closed, and nothing is written elsewhere.
func TestTheCaptureDirectoryIsCheckedAndClosed(t *testing.T) {
	t.Run("a link is refused", func(t *testing.T) {
		real := t.TempDir()
		parent := t.TempDir()
		link := filepath.Join(parent, "certistack")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		e := newCaptureEnv(t, nil)
		script := filepath.Join(parent, "capture")
		if err := os.WriteFile(script, []byte(bootDiagnosticScript(filepath.Join(link, "network-recovery.txt"))), 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = []string{"PATH=" + e.path}
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "not a directory of its own") {
			t.Fatalf("capture through a linked directory: %v\n%s", err, out)
		}
		if entries, _ := os.ReadDir(real); len(entries) != 0 {
			t.Fatalf("something was written through the link: %v", entries)
		}
	})
	t.Run("a directory open to others is closed", func(t *testing.T) {
		e := newCaptureEnv(t, nil)
		if err := os.Chmod(e.dir, 0o777); err != nil {
			t.Fatal(err)
		}
		e.run()
		info, err := os.Stat(e.dir)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("the diagnostic directory is %v (%v), want 0700", info.Mode().Perm(), err)
		}
	})
	t.Run("a missing directory is refused", func(t *testing.T) {
		e := newCaptureEnv(t, nil)
		script := filepath.Join(t.TempDir(), "capture")
		if err := os.WriteFile(script, []byte(bootDiagnosticScript(filepath.Join(t.TempDir(), "gone", "network-recovery.txt"))), 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", script)
		cmd.Env = []string{"PATH=" + e.path}
		if err := cmd.Run(); err == nil {
			t.Fatal("a capture into a directory that is not there succeeded")
		}
	})
}

// The temporary file is removed on every way out: here the unit is stopped the
// way systemd does, with SIGTERM to its whole group, while the capture is still
// inside its body.
func TestTheTemporaryFileIsRemovedWhenTheCaptureIsStopped(t *testing.T) {
	e := newCaptureEnv(t, nil)
	held := e.hold("boot")
	temporaries := func() []string {
		matches, _ := filepath.Glob(filepath.Join(e.dir, ".capture.*"))
		return matches
	}
	if len(temporaries()) != 1 {
		t.Fatalf("temporary files while the capture runs = %v, want one", temporaries())
	}
	terminateProcessGroup(held.cmd)
	if err := os.WriteFile(held.gate, nil, 0o600); err != nil { // let anything still waiting on the gate go
		t.Fatal(err)
	}
	<-held.done
	held.released = true
	if left := temporaries(); len(left) != 0 {
		t.Fatalf("a temporary file was left behind: %v", left)
	}
	if names := e.captures(); len(names) != 0 {
		t.Fatalf("a stopped capture published %v", names)
	}
}

var noisyLoop = `i=0; while [ $i -lt 40000 ]; do echo "noisy line $i of output that goes on and on and on and on and on and on and on and on"; i=$((i+1)); done`

func noisyTools() map[string]string {
	return map[string]string{
		"ip": noisyLoop, "ss": noisyLoop, "networkctl": noisyLoop, "nmcli": noisyLoop,
		"systemctl": `case "$*" in
is-system-running*) echo running ;;
is-active*) echo active ;;
list-unit-files*) i=0; while [ $i -lt 400 ]; do echo "svc$i.service enabled enabled"; i=$((i+1)); done ;;
show*) i=0; while [ $i -lt 400 ]; do printf 'Id=svc%s.service\nActiveState=inactive\nSubState=dead\nResult=success\nConditionResult=no\n\n' $i; i=$((i+1)); done ;;
*) ` + noisyLoop + ` ;;
esac`,
		"journalctl": `i=0; while [ $i -lt 40000 ]; do echo "[   $i.000000] Failed to mount /data $i"; i=$((i+1)); done`,
	}
}

// Tools that print without end fill their own section and no more. The
// capture stays under what the reader keeps, and the sections after the noisy
// ones are still there.
func TestEverySectionOfACaptureIsBounded(t *testing.T) {
	e := newCaptureEnv(t, noisyTools())
	e.run("after-boot")
	got := newestCapture(t, e.dir)
	if len(got) > diagnosticReadLimit {
		t.Fatalf("the capture is %d bytes, more than the %d the reader keeps", len(got), diagnosticReadLimit)
	}
	caps := []struct {
		marker string
		limit  int
	}{
		{"[interfaces]", 1024}, {"[routes]", 1024}, {"[listeners]", 2560}, {"[failed services]", 1024},
		{"[enabled services not active]", 1536},
		{"[mounts not active]", 1024}, {"[dependency and device failures]", 2048}, {"[pending jobs]", 1024},
		{"[networkd links]", 1024}, {"[networkd status]", 1024}, {"[networkmanager devices]", 1024}, {"[networkmanager connections]", 1024},
	}
	position := 0
	for i, section := range caps {
		at := strings.Index(got[position:], "\n"+section.marker+"\n")
		if at < 0 {
			t.Fatalf("the section %s is missing or out of order (a noisy section pushed it out?):\n%s", section.marker, got)
		}
		start := position + at + 1 + len(section.marker) + 1
		end := len(got)
		if i+1 < len(caps) {
			if next := strings.Index(got[start:], "\n"+caps[i+1].marker+"\n"); next >= 0 {
				end = start + next + 1
			}
		}
		if size := end - start; size > section.limit+1 { // +1: the newline that ends the cut text
			t.Errorf("section %s holds %d bytes, more than %d", section.marker, size, section.limit)
		}
		position = start
	}
}

// And the file as a whole is cut when even the header is unbounded.
func TestACaptureAsAWholeIsBounded(t *testing.T) {
	tools := map[string]string{"systemctl": `case "$*" in
is-system-running*) ` + noisyLoop + ` ;;
is-active*) echo active ;;
esac`}
	e := newCaptureEnv(t, tools)
	e.run()
	names := e.captures()
	if len(names) != 1 {
		t.Fatalf("captures = %v", names)
	}
	info, err := os.Stat(filepath.Join(e.dir, names[0]))
	if err != nil || info.Size() > diagnosticFileLimit {
		t.Fatalf("the capture is %v bytes (%v), more than the %d the script writes at most", info.Size(), err, diagnosticFileLimit)
	}
}

// The limits of the sections are small enough to fit the reader's, with room
// for the headers: a full set of noisy sections is not itself cut.
func TestSectionLimitsFitWhatTheReaderKeeps(t *testing.T) {
	total := 0
	for _, match := range regexp.MustCompile(`\| cap (\d+)`).FindAllStringSubmatch(diagnosticBody, -1) {
		n, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}
	if total == 0 || total+1024 > diagnosticReadLimit {
		t.Fatalf("the section limits add up to %d bytes; with the headers they must fit in the %d the reader keeps", total, diagnosticReadLimit)
	}
	if diagnosticFileLimit < diagnosticReadLimit {
		t.Fatal("the capture file is cut below what the reader keeps")
	}
}

// The size reported case, through the real reader: a 1,200,325-byte capture
// made guestfish's output exceed the runner's 1 MiB per-stream cap, which
// failed before the reader's own cut could apply. The reader asks for the bytes
// it reports and no more.
func TestAnOversizedCaptureIsCutNotAnError(t *testing.T) {
	const runnerCap = 1 << 20 // internal/sysutil's per-stream limit
	name := "network-recovery.txt.0000000100.321"
	serve := func(contents string) commandRunner {
		return func(_ context.Context, args ...string) (string, error) {
			command := guestfishCommand(args)
			switch command[0] {
			case "ls":
				return name + "\n", nil
			case "cat": // what the reader used to ask for
				if len(contents) > runnerCap {
					return "", errors.New("command output exceeded 1048576 bytes per stream")
				}
				return contents, nil
			case "pread":
				count, err := strconv.Atoi(command[2])
				if err != nil || command[3] != "0" {
					return "", fmt.Errorf("pread %v", command)
				}
				if count < len(contents) {
					return contents[:count], nil
				}
				return contents, nil
			}
			return "", fmt.Errorf("unexpected command %v", command)
		}
	}
	line := "x" + strings.Repeat("0123456789", 9) + "\n"
	for size, want := range map[int]int{
		1_200_325:               diagnosticReadLimit + len("\n[truncated]"), // the reporter's size
		runnerCap + 1:           diagnosticReadLimit + len("\n[truncated]"),
		20 << 10:                diagnosticReadLimit + len("\n[truncated]"), // the reporter's control
		diagnosticReadLimit + 1: diagnosticReadLimit + len("\n[truncated]"),
	} {
		contents := strings.Repeat(line, size/len(line)+1)[:size]
		got, err := readDiagnostics(context.Background(), serve(contents), []string{bootOverlayPath})
		if err != nil || len(got) != want || !strings.HasSuffix(got, "\n[truncated]") {
			t.Errorf("%d-byte capture: %d bytes, %v; want %d bytes and a truncation marker", size, len(got), err, want)
		}
	}
	// At the limit, or under it, nothing is cut.
	for _, size := range []int{1, 100, diagnosticReadLimit - 1, diagnosticReadLimit} {
		contents := strings.Repeat("y", size)
		got, err := readDiagnostics(context.Background(), serve(contents), []string{bootOverlayPath})
		if err != nil || got != contents {
			t.Errorf("%d-byte capture: %d bytes, %v; want it whole", size, len(got), err)
		}
	}
}

func TestACutCaptureEndsOnACharacter(t *testing.T) {
	// "é" is two bytes; a cut that lands between them drops the half.
	whole := strings.Repeat("a", diagnosticReadLimit-1) + "é" + "tail"
	if got := boundedDiagnostic(whole[:diagnosticReadLimit+1]); got != strings.Repeat("a", diagnosticReadLimit-1)+"\n[truncated]" {
		t.Fatalf("cut inside a character: %q", got[len(got)-30:])
	}
	// A character that ends exactly at the limit stays.
	exact := strings.Repeat("a", diagnosticReadLimit-2) + "é" + "tail"
	if got := boundedDiagnostic(exact[:diagnosticReadLimit+1]); got != strings.Repeat("a", diagnosticReadLimit-2)+"é\n[truncated]" {
		t.Fatalf("cut after a character: %q", got[len(got)-30:])
	}
	if got := boundedDiagnostic("  \n  trimmed \n\n"); got != "trimmed" {
		t.Fatalf("whitespace: %q", got)
	}
}

// The reported case (set A): a guest's sshd, enabled at boot, was neither failed
// nor pending when the capture ran, because systemd skipped it (a start condition
// that was not met, host keys that were empty in a backup taken mid-boot). The
// capture listed no failed unit and no job, and showed only that nothing listened
// on port 22. It now lists every enabled service that is not active, with its
// state, result and condition result, and the ones with something to explain
// come first.
func TestCaptureListsEnabledServicesThatAreNotActive(t *testing.T) {
	tools := map[string]string{
		"systemctl": `case "$*" in
is-system-running*) echo running ;;
is-active*) echo active ;;
list-unit-files*) printf 'cron.service enabled enabled\nfirst-boot.service enabled enabled\ngetty@.service enabled enabled\nssh.service enabled enabled\nweird*.service enabled enabled\nbroken.service enabled enabled\nretrying.service enabled enabled\n' ;;
show*)
  echo "$*" > "$0.show"
  printf 'Id=cron.service\nActiveState=active\nSubState=running\nResult=success\nConditionResult=yes\n\n'
  printf 'Id=first-boot.service\nActiveState=inactive\nSubState=dead\nResult=success\nConditionResult=yes\n\n'
  printf 'Id=ssh.service\nActiveState=inactive\nSubState=dead\nResult=success\nConditionResult=no\n\n'
  printf 'Id=broken.service\nActiveState=failed\nSubState=failed\nResult=exit-code\nConditionResult=yes\n\n'
  printf 'Id=retrying.service\nActiveState=activating\nSubState=auto-restart\nResult=success\nConditionResult=yes\n'
  ;;
esac`,
	}
	e := newCaptureEnv(t, tools)
	e.run("after-boot")
	got := newestCapture(t, e.dir)
	_, section, found := strings.Cut(got, "\n[enabled services not active]\n")
	if !found {
		t.Fatalf("the capture has no section of enabled services that are not active:\n%s", got)
	}
	section, _, _ = strings.Cut(section, "\n[")
	want := []string{
		"ssh.service inactive/dead result=success condition=no",
		"broken.service failed/failed result=exit-code condition=yes",
		"retrying.service activating/auto-restart result=success condition=yes",
		"first-boot.service inactive/dead result=success condition=yes",
	}
	lines := strings.Split(strings.TrimSpace(section), "\n")
	if len(lines) != len(want) {
		t.Fatalf("the section holds %d lines, want %d:\n%s", len(lines), len(want), section)
	}
	// An active service is not listed; the ones with something to explain (a
	// condition not met, a result that is not success, a state that is not
	// inactive) come before the ones that are merely inactive.
	if strings.Contains(section, "cron.service") {
		t.Errorf("an active service is listed:\n%s", section)
	}
	for _, line := range want[:3] {
		if !strings.Contains(section, line) {
			t.Errorf("the section lacks %q:\n%s", line, section)
		}
	}
	if lines[len(lines)-1] != want[3] {
		t.Errorf("the service that is only inactive is not last:\n%s", section)
	}
	// Template units and names that are not plain service names are not asked
	// about; the rest are asked about in one call.
	asked, err := os.ReadFile(filepath.Join(e.path, "systemctl.show"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cron.service", "first-boot.service", "ssh.service", "broken.service", "retrying.service"} {
		if !strings.Contains(string(asked), name) {
			t.Errorf("systemctl show was not asked about %s: %s", name, asked)
		}
	}
	for _, name := range []string{"getty@", "weird*"} {
		if strings.Contains(string(asked), name) {
			t.Errorf("systemctl show was asked about %s: %s", name, asked)
		}
	}
}

// With nothing enabled (or no systemd to ask) the section is there and empty,
// and the sections after it are untouched.
func TestCaptureWithNoEnabledServicesStillHasTheSectionsAfterIt(t *testing.T) {
	e := newCaptureEnv(t, nil)
	e.run("after-boot")
	got := newestCapture(t, e.dir)
	if !strings.Contains(got, "\n[enabled services not active]\n[mounts not active]\n") {
		t.Fatalf("an empty services section is not followed by the next section:\n%s", got)
	}
}

// settleTools is a systemctl that says "starting" for the first polls polls and
// "running" after, and a sleep that takes no time and records what it was asked
// to wait.
func settleTools(polls int) map[string]string {
	return map[string]string{
		"systemctl": `case "$*" in
is-system-running*)
  n=$(cat "$0.n" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$0.n"
  if [ "$n" -le ` + strconv.Itoa(polls) + ` ]; then echo starting; else echo running; fi ;;
is-active*) echo active ;;
esac`,
		"sleep": `echo "$*" >> "$0.log"`,
	}
}

func (e *captureEnv) sleeps() []string {
	e.t.Helper()
	data, err := os.ReadFile(filepath.Join(e.path, "sleep.log"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return strings.Fields(string(data))
}

// The after-boot capture is started when multi-user.target is reached, often
// seconds before boot has settled: the reported capture at 12 s still said
// "system starting". It now waits, two seconds at a time, for the manager to
// leave "starting", and is taken then.
func TestTheAfterBootCaptureWaitsForBootToSettle(t *testing.T) {
	e := newCaptureEnv(t, settleTools(3))
	e.run("after-boot")
	got := newestCapture(t, e.dir)
	if !strings.Contains(got, "[captured after boot settled: ") || !strings.Contains(got, "; system running; multi-user.target active]") {
		t.Fatalf("the capture was not taken once the system was running:\n%s", got)
	}
	if sleeps := e.sleeps(); strings.Join(sleeps, " ") != "2 2 2" {
		t.Fatalf("waits = %v, want three of 2 s (one for each poll that found the system starting)", sleeps)
	}
}

// A guest that never settles (a job stuck on a device, a service that keeps
// restarting) is waited for 120 s at most, and the capture says it gave up.
func TestTheAfterBootCaptureGivesUpAfterTwoMinutesAndSaysSo(t *testing.T) {
	e := newCaptureEnv(t, settleTools(1<<30))
	e.run("after-boot")
	got := newestCapture(t, e.dir)
	if !strings.Contains(got, "[captured after waiting 120 s for boot to settle, which it had not: ") || !strings.Contains(got, "; system starting;") {
		t.Fatalf("the capture does not say boot had not settled:\n%s", got)
	}
	if sleeps := e.sleeps(); len(sleeps) != 60 {
		t.Fatalf("%d waits of 2 s, want 60 (120 s)", len(sleeps))
	}
}

// Only the after-boot capture waits: the boot capture and the one on a
// NetworkManager event are taken at once, whatever the manager says.
func TestOnlyTheAfterBootCaptureWaits(t *testing.T) {
	e := newCaptureEnv(t, settleTools(1<<30))
	e.run()
	e.run("eth0", "up")
	if sleeps := e.sleeps(); len(sleeps) != 0 {
		t.Fatalf("a capture other than the after-boot one waited: %v", sleeps)
	}
	for _, want := range []string{"[captured during boot: ", "[captured on NetworkManager event up for eth0: "} {
		if !strings.Contains(newestCaptureWith(t, e.dir, want), want) {
			t.Errorf("no capture says %q", want)
		}
	}
}

// newestCaptureWith is the text of the capture in dir that has the marker.
func newestCaptureWith(t *testing.T, dir, marker string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !diagnosticName.MatchString(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), marker) {
			return string(data)
		}
	}
	return ""
}

// The stamp is taken after the wait, so a capture that waited is newer than one
// that was taken while it waited.
func TestTheAfterBootCaptureIsStampedWhenItBeganNotWhenItWasStarted(t *testing.T) {
	e := newUptimeCaptureEnv(t)
	tools := settleTools(2)
	for name, body := range tools {
		_ = os.Remove(filepath.Join(e.path, name)) // a link to the real tool
		if err := os.WriteFile(filepath.Join(e.path, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The uptime at which the capture reads it is the one file's contents;
	// the fake sleep moves it forward by 2 s each time it is called.
	uptime := filepath.Join(t.TempDir(), "uptime")
	if err := os.WriteFile(uptime, []byte("10.00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.path, "sleep")); err != nil {
		t.Fatal(err)
	}
	sleepBody := "#!/bin/sh\nn=$(cut -d. -f1 \"$CERTISTACK_TEST_UPTIME\"); echo $((n + 2)).00 > \"$CERTISTACK_TEST_UPTIME\"\n"
	if err := os.WriteFile(filepath.Join(e.path, "sleep"), []byte(sleepBody), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := e.command([]string{"CERTISTACK_TEST_UPTIME=" + uptime}, "after-boot").CombinedOutput(); err != nil {
		t.Fatalf("capture: %v\n%s", err, out)
	}
	names := e.captures()
	if len(names) != 1 {
		t.Fatalf("captures = %v", names)
	}
	if match := diagnosticName.FindStringSubmatch(names[0]); match == nil || match[1] != "0000001400" {
		t.Fatalf("the capture published as %s, want the stamp 0000001400 (10 s, and two waits of 2 s)", names[0])
	}
}

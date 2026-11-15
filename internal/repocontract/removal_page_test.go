// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bashBlockAfter is the first ```bash block of doc after the line that starts
// with heading.
func bashBlockAfter(t *testing.T, doc, heading string) string {
	t.Helper()
	start := strings.Index(doc, "\n"+heading)
	if start < 0 {
		t.Fatalf("no heading %q", heading)
	}
	rest := doc[start:]
	open := strings.Index(rest, "\n```bash\n")
	if open < 0 {
		t.Fatalf("no bash block after %q", heading)
	}
	rest = rest[open+len("\n```bash\n"):]
	return rest[:strings.Index(rest, "\n```")]
}

// inFakeRoot rewrites a block's absolute paths into root and drops sudo, so
// that it runs on a copy of the controller's files.
func inFakeRoot(block, root string) string {
	for _, dir := range []string{"/etc/", "/usr/local/bin/", "/root/"} {
		block = strings.ReplaceAll(block, " "+dir, " "+root+dir)
	}
	block = strings.ReplaceAll(block, "sudo sh -c", "sh -c")
	return regexp.MustCompile(`(?m)(^|; )sudo `).ReplaceAllString(block, "$1")
}

// systemctlStub stands in for systemctl in the fake root: disable removes the
// unit's timers.target.wants link, as the real one does for these units, and
// nothing else changes anything.
const systemctlStub = `#!/bin/sh
echo "systemctl $*" >> "$FAKE_ROOT/systemctl.calls"
[ "$1" = disable ] || exit 0
shift
for unit in "$@"; do
  case "$unit" in -*) continue ;; esac
  rm -f "$FAKE_ROOT/etc/systemd/system/timers.target.wants/$unit"
done
`

// The removal page left the units' drop-ins that the automation and telemetry
// pages have the reader make with systemctl edit (the second site's
// environment file, a plan's own time, the usage statistics' opt-in), and the
// timers of plans other than nightly stayed enabled. A reinstall would pick
// them up. Step 1 of the removal page, run on what those pages create, must
// leave nothing of it.
func TestTheRemovalPageTakesBackEverythingTheSchedulingPagesCreate(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	automation := readRepoText(t, "docs", "automation.md")
	telemetryPage := readRepoText(t, "docs", "telemetry.md")
	undo := readRepoText(t, "docs", "undo.md")

	root := t.TempDir()
	units := filepath.Join(root, "etc", "systemd", "system")
	wants := filepath.Join(units, "timers.target.wants")
	write := func(path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	created := 0
	for _, m := range regexp.MustCompile(`sudo tee (/etc/\S+)`).FindAllStringSubmatch(automation, -1) {
		write(filepath.Join(root, m[1]))
		created++
	}
	for _, m := range regexp.MustCompile(`sudo install -m 0755 \S+ (/usr/local/bin/\S+)`).FindAllStringSubmatch(automation, -1) {
		write(filepath.Join(root, m[1]))
		created++
	}
	edited := map[string]bool{}
	for _, m := range regexp.MustCompile("systemctl edit (certistack-[a-z]+@[A-Za-z0-9.-]*\\.(?:service|timer))").FindAllStringSubmatch(automation+telemetryPage, -1) {
		edited[m[1]] = true
		write(filepath.Join(units, m[1]+".d", "override.conf"))
	}
	enabled := map[string]bool{}
	for _, m := range regexp.MustCompile("systemctl enable --now (certistack-validate@[A-Za-z0-9-]+\\.timer)").FindAllStringSubmatch(automation, -1) {
		enabled[m[1]] = true
		if err := os.MkdirAll(wants, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../certistack-validate@.timer", filepath.Join(wants, m[1])); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
	}
	if created < 5 || len(edited) < 3 || len(enabled) < 2 {
		t.Fatalf("the scheduling pages create %d files, %d drop-ins and %d timers by this test's reading; it no longer reads them", created, len(edited), len(enabled))
	}

	bin := filepath.Join(root, "stub-bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(systemctlStub), 0o755); err != nil {
		t.Fatal(err)
	}
	block := inFakeRoot(bashBlockAfter(t, undo, "## 1. Controller"), root)
	cmd := exec.Command(bash, "-euc", block)
	cmd.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "FAKE_ROOT=" + root, "LC_ALL=C"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("step 1 of docs/undo.md failed: %v\n%s\n%s", err, out, block)
	}
	var left []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if info.IsDir() || strings.HasPrefix(rel, "stub-bin") || rel == "systemctl.calls" {
			return nil
		}
		left = append(left, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(left) > 0 {
		t.Errorf("step 1 of docs/undo.md leaves what the scheduling pages created:\n  %s", strings.Join(left, "\n  "))
	}
	for unit := range edited {
		if _, err := os.Stat(filepath.Join(units, unit+".d")); err == nil {
			t.Errorf("the drop-in directory %s.d stays", unit)
		}
	}
}

// Every setup directory has its own key, and setup adds it to root's
// authorized_keys once: the node step removes each of them, whatever their
// number, and keeps every other key.
func TestTheRemovalPageRemovesEveryControllerKeyOnTheNode(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	undo := readRepoText(t, "docs", "undo.md")
	root := t.TempDir()
	keys := filepath.Join(root, "root", ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	other := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther admin@laptop\n"
	content := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFirst certistack-controller\n" + other +
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISecond certistack-controller\n"
	if err := os.WriteFile(keys, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	block := inFakeRoot(bashBlockAfter(t, undo, "### The controller's SSH key"), root)
	// The block ends with grep -c, whose status is 1 for a count of 0.
	out, err := exec.Command(bash, "-c", block).CombinedOutput()
	if exit, ok := err.(*exec.ExitError); err != nil && (!ok || exit.ExitCode() != 1) {
		t.Fatalf("the key block failed: %v\n%s", err, out)
	}
	if got := strings.Fields(string(out)); strings.Join(got, " ") != "2 0" {
		t.Errorf("the counts printed are %q, want 2 then 0", got)
	}
	if data, _ := os.ReadFile(keys); string(data) != other {
		t.Errorf("authorized_keys is now:\n%s", data)
	}
	if !strings.Contains(undo, "one per setup directory") {
		t.Error("docs/undo.md does not say there is one key per setup directory")
	}
}

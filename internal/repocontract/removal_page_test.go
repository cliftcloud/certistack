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

// bashBlockWith is the one ```bash block of doc that holds text.
func bashBlockWith(t *testing.T, doc, text string) string {
	t.Helper()
	var found []string
	for _, block := range regexp.MustCompile("(?s)\n```bash\n(.*?)\n```").FindAllStringSubmatch(doc, -1) {
		if strings.Contains(block[1], text) {
			found = append(found, block[1])
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d bash blocks hold %q, want one", len(found), text)
	}
	return found[0]
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

// Every setup directory has its own key, and setup adds it to root's
// authorized_keys once: the removal steps of docs/manual-setup.md take each of
// them off the node, whatever their number, and keep every other key.
func TestTheRemovalPageRemovesEveryControllerKeyOnTheNode(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	removal := section(t, readRepoText(t, "docs", "manual-setup.md"), "Remove CertiStack")
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
	block := inFakeRoot(bashBlockWith(t, removal, "grep -v ' certistack-controller$' /root/.ssh/authorized_keys"), root)
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
}

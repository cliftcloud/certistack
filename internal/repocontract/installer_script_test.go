// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The one-line installer (scripts/install.sh, served as https://certistack.dev/install.sh) trusts exactly the
// release key SECURITY.md names, installs the release the CHANGELOG records, and runs nothing from a download that
// was cut short. The quickstart's step 1 is that one line.
func TestInstallerScriptPinsTheReleaseKeyAndTheRelease(t *testing.T) {
	script := readRepoText(t, "scripts", "install.sh")
	security := readRepoText(t, "SECURITY.md")

	fingerprint := regexp.MustCompile(`Fingerprint: ((?:[0-9A-F]{4} ?){5} ((?:[0-9A-F]{4} ?){5}))`).FindStringSubmatch(security)
	if fingerprint == nil {
		t.Fatal("SECURITY.md has no release key fingerprint line")
	}
	want := strings.ReplaceAll(fingerprint[1], " ", "")
	if !strings.Contains(script, "\nRELEASE_KEY_FINGERPRINT=\""+want+"\"\n") {
		t.Errorf("scripts/install.sh does not pin the release key fingerprint SECURITY.md names (%s)", want)
	}
	subkey := regexp.MustCompile("40-digit fingerprint ending `([0-9A-F]{16})`").FindStringSubmatch(security)
	if subkey == nil {
		t.Fatal("SECURITY.md does not name the end of the signing subkey's fingerprint")
	}
	if !strings.Contains(script, "\nSIGNING_SUBKEY_SUFFIX=\""+subkey[1]+"\"\n") {
		t.Errorf("scripts/install.sh does not pin the signing subkey ending SECURITY.md names (%s)", subkey[1])
	}

	release := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\] - `).FindStringSubmatch(readRepoText(t, "CHANGELOG.md"))
	if release == nil {
		t.Fatal("CHANGELOG.md has no released version")
	}
	if !strings.Contains(script, "\nVERSION=\"${CERTISTACK_VERSION:-v"+release[1]+"}\"\n") {
		t.Errorf("scripts/install.sh does not install v%s, the newest release in CHANGELOG.md, by default", release[1])
	}

	if !strings.HasPrefix(script, "#!/usr/bin/env bash\n") || !strings.Contains(script, "\nset -euo pipefail\n") {
		t.Error("scripts/install.sh must be a bash script that stops at the first error (set -euo pipefail)")
	}
	lines := strings.Split(strings.TrimRight(script, "\n"), "\n")
	if last := lines[len(lines)-1]; last != `main "$@"` {
		t.Errorf("the last line of scripts/install.sh is %q: it must call main, so that a download cut short runs nothing", last)
	}
	if info, err := os.Stat(repoFile("scripts", "install.sh")); err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Error("scripts/install.sh must be executable")
	}

	quickstart := readRepoText(t, "docs", "quickstart.md")
	if !strings.Contains(quickstart, "\ncurl -fsSL https://certistack.dev/install.sh | bash\n") {
		t.Error("docs/quickstart.md step 1 does not give the one-line installer")
	}
}

// The installer ends by naming the next step: certistack setup on a first
// install, certistack check with the file when the setup directory already
// holds a controller.env (an upgrade, where setup is not what the reader needs).
// next_step is run on its own: the script with its last line, the call of main,
// taken off.
func TestInstallerNamesTheNextStepByWhetherThereIsAControllerEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the installer is a bash script for Linux")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	script := readRepoText(t, "scripts", "install.sh")
	body := strings.TrimSuffix(strings.TrimRight(script, "\n"), `main "$@"`)
	if body == script {
		t.Fatal("scripts/install.sh does not end with main \"$@\"")
	}
	functions := filepath.Join(t.TempDir(), "install-functions.sh")
	if err := os.WriteFile(functions, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	next := func(env ...string) string {
		t.Helper()
		cmd := exec.Command(bash, "-c", `source "$1"; next_step`, "bash", functions)
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("next_step: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}

	secure := t.TempDir()
	home := t.TempDir()
	const setupLine = "Installed. Next: certistack setup (https://certistack.dev/docs/quickstart/#2-run-the-setup)"
	if got := next("CERTISTACK_SECURE_DIR="+secure, "HOME="+home); got != setupLine {
		t.Errorf("a first install: %q, want %q", got, setupLine)
	}
	if err := os.WriteFile(filepath.Join(secure, "controller.env"), []byte("PVE_URL=https://pve.example:8006\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := "Installed. Next: certistack check --env-file " + filepath.Join(secure, "controller.env")
	if got := next("CERTISTACK_SECURE_DIR="+secure, "HOME="+home); got != want {
		t.Errorf("an upgrade: %q, want %q", got, want)
	}

	// Without sudo the setup directory is ~/certistack/secure, which setup
	// picks when /secure/certistack is not one it can write to.
	if _, err := os.Stat("/secure/certistack/controller.env"); err == nil {
		t.Skip("this machine has a /secure/certistack/controller.env, which the installer would name first")
	}
	homeSecure := filepath.Join(home, "certistack", "secure")
	if err := os.MkdirAll(homeSecure, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := next("HOME=" + home); got != setupLine {
		t.Errorf("a first install, without sudo: %q, want %q", got, setupLine)
	}
	if err := os.WriteFile(filepath.Join(homeSecure, "controller.env"), []byte("PVE_URL=https://pve.example:8006\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want = "Installed. Next: certistack check --env-file " + filepath.Join(homeSecure, "controller.env")
	if got := next("HOME=" + home); got != want {
		t.Errorf("an upgrade, without sudo: %q, want %q", got, want)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const podmanStub = `#!/bin/sh
for arg in "$@"; do printf '%s\n' "$arg"; done >> "$STUB_LOG"
`

// idStub answers `id -u` with STUB_UID, root by default: the wrapper only
// runs as root, and the tests are not.
const idStub = `#!/bin/sh
[ "$1" = -u ] || exit 64
printf '%s\n' "${STUB_UID:-0}"
`

const applianceTestImage = "registry.example.invalid/certistack-controller@sha256:0000000000000000000000000000000000000000000000000000000000000000"

// applianceWrapperSetup copies deploy/appliance/files/certistack-controller
// into a temp directory, pointed at a recording podman and a temp image
// reference file, and returns the script, the stub directory, the temp root
// and podman's argument log.
func applianceWrapperSetup(t *testing.T) (wrapper, stubs, root, logPath string) {
	t.Helper()
	needTools(t, "sh")
	original, err := os.ReadFile(repoFile("deploy", "appliance", "files", "certistack-controller"))
	if err != nil {
		t.Fatal(err)
	}
	root = t.TempDir()
	stubs = filepath.Join(root, "stubs")
	if err := os.MkdirAll(stubs, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(stubs, "podman"), podmanStub)
	writeExecutable(t, filepath.Join(stubs, "id"), idStub)
	imageFile := filepath.Join(root, "controller-image")
	if err := os.WriteFile(imageFile, []byte(applianceTestImage+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := string(original)
	for old, replacement := range map[string]string{
		"/usr/bin/podman": filepath.Join(stubs, "podman"),
		"image_file=/etc/certistack/controller-image": "image_file=" + imageFile,
	} {
		if strings.Count(script, old) != 1 {
			t.Fatalf("the wrapper no longer has exactly one %q to point at the test", old)
		}
		script = strings.Replace(script, old, replacement, 1)
	}
	wrapper = filepath.Join(root, "certistack-controller")
	writeExecutable(t, wrapper, script)
	return wrapper, stubs, root, filepath.Join(root, "podman.args")
}

// applianceWrapper runs deploy/appliance/files/certistack-controller as root
// with a recording podman in place of the real one and the image reference
// file in a temp directory, and returns podman's arguments split at the image.
func applianceWrapper(t *testing.T, args ...string) (before, after []string) {
	t.Helper()
	wrapper, stubs, root, logPath := applianceWrapperSetup(t)
	cmd := exec.Command("sh", append([]string{wrapper}, args...)...)
	cmd.Env = shellEnv(t, stubs, root, map[string]string{"STUB_LOG": logPath})
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wrapper %q: %v\n%s", args, err, out)
	}
	podmanArgs := readLog(t, logPath)
	for i, arg := range podmanArgs {
		if arg == applianceTestImage {
			return podmanArgs[:i], podmanArgs[i+1:]
		}
	}
	t.Fatalf("the image reference is not among podman's arguments: %q", podmanArgs)
	return nil, nil
}

// The wrapper runs a root-pulled image with root-only secrets, so any
// other caller got a rootless Podman with no image and no way to pull one
// ("image not known"). It now refuses, before it starts podman, and says what
// to do.
func TestApplianceWrapperRefusesANonRootCaller(t *testing.T) {
	wrapper, stubs, root, logPath := applianceWrapperSetup(t)
	for _, uid := range []string{"1000", "65532"} {
		cmd := exec.Command("sh", wrapper, "run", "/var/lib/certistack/plans/nightly.yaml")
		cmd.Env = shellEnv(t, stubs, root, map[string]string{"STUB_LOG": logPath, "STUB_UID": uid})
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "must run as root") || !strings.Contains(string(out), "sudo") {
			t.Errorf("uid %s: err=%v, output %q; want a refusal that says to use sudo", uid, err, out)
		}
		if calls := readLog(t, logPath); len(calls) != 0 {
			t.Errorf("uid %s: podman was started anyway: %q", uid, calls)
		}
	}
}

// mountedEnvironment returns the controller.env path the wrapper's mount
// makes visible in the container, from podman's own arguments.
func mountedEnvironment(t *testing.T, before []string) string {
	t.Helper()
	for i, arg := range before {
		if arg != "--volume" || i+1 >= len(before) {
			continue
		}
		parts := strings.Split(before[i+1], ":")
		if len(parts) == 3 && parts[0] == "/etc/certistack/secrets" && parts[2] == "ro" {
			return parts[1] + "/controller.env"
		}
	}
	t.Fatalf("the wrapper does not mount /etc/certistack/secrets read-only: %q", before)
	return ""
}

// The appliance mounted controller.env but never loaded it, so a
// first-boot `run` found an empty environment ("controller secret
// environment variable PVE_URL is required"). The controller reads an
// environment file only when given --env-file, so the wrapper passes the
// mounted file to every command that takes one, and only to those.
func TestApplianceWrapperLoadsTheMountedControllerEnvironment(t *testing.T) {
	before, _ := applianceWrapper(t, "version")
	envFile := mountedEnvironment(t, before)

	// The container's own environment stays empty of secrets: only TMPDIR and
	// the per-user configuration directory (inside the writable state mount,
	// for the usage statistics' install) go in, and no environment file is
	// handed to podman itself.
	var envs []string
	for i, arg := range before {
		switch {
		case arg == "--env-file" || strings.HasPrefix(arg, "--env-file="):
			t.Errorf("podman is given an environment file %q, which would put the secrets in the container's environment", arg)
		case arg == "--env" && i+1 < len(before):
			envs = append(envs, before[i+1])
		}
	}
	if strings.Join(envs, " ") != "TMPDIR=/tmp/certistack XDG_CONFIG_HOME=/var/lib/certistack/.config" {
		t.Errorf("podman environment = %q, want only TMPDIR and XDG_CONFIG_HOME", envs)
	}

	for _, c := range []struct {
		args, want []string
	}{
		{[]string{"run", "/var/lib/certistack/plans/nightly.yaml", "--node", "pve-01"},
			[]string{"run", "--env-file", envFile, "/var/lib/certistack/plans/nightly.yaml", "--node", "pve-01"}},
		{[]string{"plan", "p.yaml"}, []string{"plan", "--env-file", envFile, "p.yaml"}},
		{[]string{"doctor", "--json", "p.yaml"}, []string{"doctor", "--env-file", envFile, "--json", "p.yaml"}},
		{[]string{"init", "--all"}, []string{"init", "--env-file", envFile, "--all"}},
		{[]string{"check", "p.yaml"}, []string{"check", "--env-file", envFile, "p.yaml"}},
		// An --env-file of the operator's own comes later and so wins.
		{[]string{"run", "--env-file", "/other.env", "p.yaml"},
			[]string{"run", "--env-file", envFile, "--env-file", "/other.env", "p.yaml"}},
		// Commands that take no environment file are passed through as given.
		{[]string{"version"}, []string{"version"}},
		{[]string{"verify-report", "report.json"}, []string{"verify-report", "report.json"}},
		{[]string{"report", "show", "r.json"}, []string{"report", "show", "r.json"}},
		{nil, nil},
	} {
		_, got := applianceWrapper(t, c.args...)
		if strings.Join(got, "\x00") != strings.Join(c.want, "\x00") {
			t.Errorf("wrapper %q: the container's command is %q, want %q", c.args, got, c.want)
		}
	}

	// The documented first-boot invocation, exactly as the README gives it.
	var invocation []string
	for _, block := range codeBlocks(t, repoFile("deploy", "appliance", "README.md")) {
		if block.heading != "First boot" {
			continue
		}
		for _, command := range block.commands() {
			if fields := strings.Fields(command); len(fields) > 2 && fields[0] == "sudo" && fields[1] == "certistack-controller" {
				invocation = fields[2:]
			}
		}
	}
	if len(invocation) == 0 {
		t.Fatal("the appliance README's First boot section has no certistack-controller invocation")
	}
	_, got := applianceWrapper(t, invocation...)
	if len(got) < 3 || got[0] != invocation[0] || got[1] != "--env-file" || got[2] != envFile || strings.Join(got[3:], " ") != strings.Join(invocation[1:], " ") {
		t.Errorf("the README's invocation %q reaches the container as %q", invocation, got)
	}
}

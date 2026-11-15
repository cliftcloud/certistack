// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The section "Run doctor on the node" of docs/manual-setup.md (formerly in
// docs/getting-started.md) shows how to build the node's /root/doctor.env from
// the controller without an editor (CR2-10): a root-only file made first, then
// the lines doctor needs piped from controller.env through ssh. The commands
// must do what the text says. Only the named variables travel, the CA line is
// the node's path, and no secret reaches the screen.
func TestGettingStartedDoctorEnvironmentIsBuiltFromTheControllerWithoutPrintingSecrets(t *testing.T) {
	needTools(t, "grep", "cat")
	const secretToken, secretPBS = "00000000-aaaa-bbbb-cccc-token-secret-value", "pbs-token-secret-value-1234"
	var block string
	for _, candidate := range indentedFences(readRepoText(t, "docs", "manual-setup.md")) {
		if strings.Contains(candidate, "cat >> /root/doctor.env") {
			block = candidate
		}
	}
	if block == "" {
		t.Fatal("manual-setup.md has no block that appends to /root/doctor.env over ssh")
	}

	dir := t.TempDir()
	stubs := filepath.Join(dir, "stubs")
	if err := os.MkdirAll(stubs, 0o755); err != nil {
		t.Fatal(err)
	}
	controllerEnv := filepath.Join(dir, "controller.env")
	environment := strings.Join([]string{
		"PVE_URL=https://pve-node-01.example.com:8006",
		"PVE_TOKEN_ID=certistack-svc@pve!automation",
		"PVE_TOKEN_SECRET=" + secretToken,
		"PBS_REPOSITORY=certistack-ro@pbs!ro@pbs.example.com:8007:datastore1",
		"PBS_PASSWORD=" + secretPBS,
		"PBS_FINGERPRINT=ab:cd:ef",
		"CERTISTACK_NODE=pve-node-01",
		"CERTISTACK_SSH_HOST=pve-node-01.example.com",
		"CERTISTACK_SSH_USER=root",
		"CERTISTACK_SSH_IDENTITY=/secure/certistack/id_ed25519",
		"CERTISTACK_PVE_CA_SOURCE=/secure/certistack/pve-root-ca.pem",
		"",
	}, "\n")
	if err := os.WriteFile(controllerEnv, []byte(environment), 0o600); err != nil {
		t.Fatal(err)
	}
	log, stdin := filepath.Join(dir, "ssh.log"), filepath.Join(dir, "ssh.stdin")
	writeExecutable(t, filepath.Join(stubs, "ssh"), "#!/bin/sh\nfor a in \"$@\"; do last=$a; done\nprintf '%s\\n' \"$*\" >> \"$STUB_LOG\"\nif [ \"$last\" = 'cat >> /root/doctor.env' ]; then cat > \"$STUB_STDIN\"; fi\n")

	script := strings.ReplaceAll(block, "/secure/certistack/controller.env", controllerEnv)
	out, err := runStep(t, dir, shellEnv(t, stubs, dir, map[string]string{"STUB_LOG": log, "STUB_STDIN": stdin}), script)
	if err != nil {
		t.Fatalf("the block failed: %v\n%s", err, out)
	}
	for _, secret := range []string{secretToken, secretPBS} {
		if strings.Contains(out, secret) {
			t.Errorf("a secret reached the screen:\n%s", out)
		}
		for _, line := range readLog(t, log) {
			if strings.Contains(line, secret) {
				t.Errorf("a secret is on an ssh command line, where ps shows it: %s", line)
			}
		}
	}

	sent, err := os.ReadFile(stdin)
	if err != nil {
		t.Fatalf("nothing was sent to the node: %v", err)
	}
	want := strings.Join([]string{
		"PVE_URL=https://pve-node-01.example.com:8006",
		"PVE_TOKEN_ID=certistack-svc@pve!automation",
		"PVE_TOKEN_SECRET=" + secretToken,
		"PBS_REPOSITORY=certistack-ro@pbs!ro@pbs.example.com:8007:datastore1",
		"PBS_PASSWORD=" + secretPBS,
		"PBS_FINGERPRINT=ab:cd:ef",
		"CERTISTACK_PVE_CA_SOURCE=/etc/pve/pve-root-ca.pem",
		"",
	}, "\n")
	if string(sent) != want {
		t.Errorf("the node received\n%s\nwant (the doctor lines, and the node's own CA path instead of the controller's)\n%s", sent, want)
	}

	calls := readLog(t, log)
	if len(calls) != 2 || !strings.HasSuffix(calls[0], " install -m 0600 /dev/null /root/doctor.env") {
		t.Fatalf("ssh calls = %q, want the root-only file created first, then the lines appended", calls)
	}
	for _, call := range calls {
		if !strings.Contains(call, "StrictHostKeyChecking=yes") || !strings.Contains(call, "root@pve-node-01.example.com") {
			t.Errorf("the call does not pin the host key as the rest of the guide does: %s", call)
		}
	}
}

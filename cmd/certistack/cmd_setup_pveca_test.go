// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/controller"
)

// pveTestCA is a deterministic PVE-style cluster CA: an Ed25519 key, a fixed
// serial and fixed times, so its fingerprint is the same on every run.
func pveTestCA(t *testing.T, notAfter time.Time, isCA bool) []byte {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Proxmox Virtual Environment", OrganizationalUnit: []string{"0c7e3d1a-5b2f-4e6a-9d84-2f1b6c0a9e37"}, Organization: []string{"PVE Cluster Manager CA"}},
		NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// controllerDir is a directory with a mode-0600 environment file, a known_hosts
// file and an identity file, as the quickstart leaves them.
type controllerDir struct {
	dir, env, knownHosts, identity string
}

func newControllerDir(t *testing.T, extraEnv ...string) controllerDir {
	t.Helper()
	dir := t.TempDir()
	c := controllerDir{dir: dir, env: filepath.Join(dir, "controller.env"), knownHosts: filepath.Join(dir, "known_hosts"), identity: filepath.Join(dir, "id_ed25519")}
	for _, file := range []string{c.knownHosts, c.identity} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lines := []string{
		"PVE_URL=https://pve-node-01.example.com:8006",
		"PVE_TOKEN_ID=certistack-svc@pve!automation",
		"PVE_TOKEN_SECRET=super-secret-token-value",
		"PBS_REPOSITORY=certistack-ro@pbs!ro@pbs.example.com:8007:datastore",
		"PBS_PASSWORD=super-secret-pbs-value",
		"CERTISTACK_NODE=pve-node-01",
		"CERTISTACK_SSH_HOST=pve-node-01.example.com",
		"CERTISTACK_SSH_USER=root",
		"CERTISTACK_SSH_PORT=2222",
		"CERTISTACK_SSH_IDENTITY=" + c.identity,
		"CERTISTACK_SSH_KNOWN_HOSTS=" + c.knownHosts,
	}
	lines = append(lines, extraEnv...)
	if err := os.WriteFile(c.env, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// withNodeCA makes `setup pve-ca` read data from the node, and records the SSH
// access it used.
func withNodeCA(t *testing.T, data []byte, err error) *[]controller.SSHConfig {
	t.Helper()
	previous := fetchPVECA
	t.Cleanup(func() { fetchPVECA = previous })
	var used []controller.SSHConfig
	fetchPVECA = func(_ context.Context, cfg controller.SSHConfig) ([]byte, error) {
		used = append(used, cfg)
		return data, err
	}
	return &used
}

func TestSetupPVECAWritesTheCANextToTheEnvironmentFile(t *testing.T) {
	c := newControllerDir(t)
	ca := pveTestCA(t, time.Date(2035, 10, 1, 0, 0, 0, 0, time.UTC), true)
	used := withNodeCA(t, append([]byte("junk before\n"), ca...), nil)
	envBefore, _ := os.ReadFile(c.env)

	out, err := runRootWithInput(t, "", "setup", "pve-ca", "--env-file", c.env)
	if err != nil {
		t.Fatalf("pve-ca: %v\n%s", err, out)
	}
	want := controller.SSHConfig{Host: "pve-node-01.example.com", User: "root", Port: 2222, IdentityFile: c.identity, KnownHostsFile: c.knownHosts}
	if len(*used) != 1 || (*used)[0] != want {
		t.Errorf("SSH access used = %+v, want %+v", *used, want)
	}
	target := filepath.Join(c.dir, "pve-root-ca.pem")
	if got, _ := os.ReadFile(target); string(got) != string(ca) {
		t.Errorf("CA file = %q", got)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(target); info.Mode().Perm() != 0o644 {
			t.Errorf("mode %04o, want 0644", info.Mode().Perm())
		}
	}
	if after, _ := os.ReadFile(c.env); !bytes.Equal(after, envBefore) {
		t.Error("the environment file was edited")
	}
	if strings.Contains(out, "super-secret") {
		t.Errorf("a secret was printed:\n%s", out)
	}
	assertGolden(t, "setup_pve_ca.golden", maskDir(out, c.dir))
}

func TestSetupPVECAOutAndEnvironmentNotes(t *testing.T) {
	ca := pveTestCA(t, time.Date(2035, 10, 1, 0, 0, 0, 0, time.UTC), true)

	// --out, and a line in the environment file that names another file.
	other := filepath.Join(t.TempDir(), "old-ca.pem")
	c := newControllerDir(t, "CERTISTACK_PVE_CA_SOURCE="+other)
	withNodeCA(t, ca, nil)
	target := filepath.Join(t.TempDir(), "ca", "pve.pem")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := runRootWithInput(t, "", "setup", "pve-ca", "--env-file", c.env, "--out", target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "sets CERTISTACK_PVE_CA_SOURCE to "+other+", not to this file") || !strings.Contains(out, "CERTISTACK_PVE_CA_SOURCE="+target) {
		t.Errorf("output:\n%s", out)
	}

	// The environment file already names the file: nothing to add, and the file
	// is not rewritten.
	c = newControllerDir(t, "CERTISTACK_PVE_CA_SOURCE="+target)
	out, err = runRootWithInput(t, "", "setup", "pve-ca", "--env-file", c.env, "--out", target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "already holds this CA: nothing to write") || !strings.Contains(out, "already sets CERTISTACK_PVE_CA_SOURCE to this file") || strings.Contains(out, "Add this line") {
		t.Errorf("output:\n%s", out)
	}
}

func TestSetupPVECAWritesNothingForAFileThatIsNotACA(t *testing.T) {
	future := time.Date(2035, 10, 1, 0, 0, 0, 0, time.UTC)
	ca := pveTestCA(t, future, true)
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")})
	for name, c := range map[string]struct {
		data []byte
		want string
	}{
		"not PEM":       {[]byte("<html>login</html>"), "not PEM"},
		"a leaf":        {pveTestCA(t, future, false), "no CA certificate"},
		"expired":       {pveTestCA(t, time.Now().Add(-time.Hour), true), "expired on"},
		"a private key": {append(append([]byte(nil), ca...), key...), "contains a private key"},
	} {
		dir := newControllerDir(t)
		withNodeCA(t, c.data, nil)
		_, err := runRootWithInput(t, "", "setup", "pve-ca", "--env-file", dir.env)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "was not written") {
			t.Errorf("%s: error = %v", name, err)
		}
		if _, statErr := os.Stat(filepath.Join(dir.dir, "pve-root-ca.pem")); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s: a CA file exists", name)
		}
	}
}

func TestSetupPVECANeverReplacesTheEnvironmentFileOrOtherFiles(t *testing.T) {
	ca := pveTestCA(t, time.Date(2035, 10, 1, 0, 0, 0, 0, time.UTC), true)
	c := newControllerDir(t)
	withNodeCA(t, ca, nil)
	before, _ := os.ReadFile(c.env)
	if _, err := runRootWithInput(t, "", "setup", "pve-ca", "--env-file", c.env, "--out", c.env); err == nil || !strings.Contains(err.Error(), "the environment file itself") {
		t.Errorf("--out the environment file: %v", err)
	}
	if _, err := runRootWithInput(t, "", "setup", "pve-ca", "--env-file", c.env, "--out", c.identity); err == nil || !strings.Contains(err.Error(), "not a PEM certificate file") {
		t.Errorf("--out the identity: %v", err)
	}
	if after, _ := os.ReadFile(c.env); !bytes.Equal(after, before) {
		t.Error("the environment file changed")
	}
	if got, _ := os.ReadFile(c.identity); string(got) != "x\n" {
		t.Error("the identity file changed")
	}
}

func TestSetupPVECAExplainsAHostKeyThatIsNotRecorded(t *testing.T) {
	c := newControllerDir(t)
	withNodeCA(t, nil, errors.New("SSH command on pve-node-01.example.com: ssh failed: exit status 255: No ED25519 host key is known for [pve-node-01.example.com]:2222 and you have requested strict checking.\nHost key verification failed."))
	_, err := runRootWithInput(t, "", "setup", "pve-ca", "--env-file", c.env)
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"Host key verification failed", "certistack setup trust-node --host pve-node-01.example.com --port 2222 --known-hosts " + quotedPath(c.knownHosts)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestSetupPVECAExplainsAnUnreadableClusterFile(t *testing.T) {
	c := newControllerDir(t)
	env, _ := os.ReadFile(c.env)
	if err := os.WriteFile(c.env, bytes.Replace(env, []byte("CERTISTACK_SSH_USER=root"), []byte("CERTISTACK_SSH_USER=certistack"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	withNodeCA(t, nil, errors.New("ssh failed: exit status 1: /usr/bin/cat: /etc/pve/pve-root-ca.pem: Permission denied"))
	_, err := runRootWithInput(t, "", "setup", "pve-ca", "--env-file", c.env)
	if err == nil || !strings.Contains(err.Error(), "CERTISTACK_SSH_SUDO=true") {
		t.Fatalf("error = %v", err)
	}
}

func TestSetupPVECAStopsBeforeSSHWhenTheEnvironmentIsIncomplete(t *testing.T) {
	// No SSH host.
	dir := t.TempDir()
	env := filepath.Join(dir, "controller.env")
	if err := os.WriteFile(env, []byte("PVE_URL=https://pve.example:8006\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	used := withNodeCA(t, nil, nil)
	if _, err := runRootWithInput(t, "", "setup", "pve-ca", "--env-file", env); err == nil || !strings.Contains(err.Error(), "CERTISTACK_SSH_HOST is not set") {
		t.Errorf("no host: %v", err)
	}
	// known_hosts missing: the fix is trust-node.
	c := newControllerDir(t)
	if err := os.Remove(c.knownHosts); err != nil {
		t.Fatal(err)
	}
	if _, err := runRootWithInput(t, "", "setup", "pve-ca", "--env-file", c.env); err == nil || !strings.Contains(err.Error(), "certistack setup trust-node --host pve-node-01.example.com") {
		t.Errorf("no known_hosts: %v", err)
	}
	// The environment file is required.
	if _, err := runRootWithInput(t, "", "setup", "pve-ca"); err == nil || !strings.Contains(err.Error(), "env-file") {
		t.Errorf("no --env-file: %v", err)
	}
	if len(*used) != 0 {
		t.Errorf("SSH was used: %+v", *used)
	}
}

func TestSetupPVECARefusesAnEnvironmentFileOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes")
	}
	c := newControllerDir(t)
	if err := os.Chmod(c.env, 0o644); err != nil {
		t.Fatal(err)
	}
	used := withNodeCA(t, nil, nil)
	if _, err := runRootWithInput(t, "", "setup", "pve-ca", "--env-file", c.env); err == nil || !strings.Contains(err.Error(), "must not be accessible by group or other users") {
		t.Errorf("error = %v", err)
	}
	if len(*used) != 0 {
		t.Errorf("SSH was used")
	}
}

func TestSetupPVECAHelp(t *testing.T) {
	help, err := runRootWithInput(t, "", "setup", "pve-ca", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--env-file", "--out", "/etc/pve/pve-root-ca.pem", "CERTISTACK_PVE_CA_SOURCE", "does not edit the environment file"} {
		if !strings.Contains(help, want) {
			t.Errorf("setup pve-ca --help does not mention %q", want)
		}
	}
}

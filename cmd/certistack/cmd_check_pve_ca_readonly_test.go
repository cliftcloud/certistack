// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/nodecheck"
)

// readOnly makes dir a directory this process cannot create files in, as the
// controller container's secrets mount is, and skips the test where that cannot
// be made so: root, and Windows, ignore the permission bits. The condition is
// the one the hint tests, not a guess from the mode.
func readOnly(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if directoryWritable(dir) {
		t.Skip("this user can write to a directory it has no write permission on (root, or Windows)")
	}
}

func untrustedPVECA() nodecheck.Report {
	return nodecheck.Report{Layers: []nodecheck.Layer{
		{Name: nodecheck.LayerTools, Status: nodecheck.StatusPassed, Detail: "found on the node: qemu-img, proxmox-backup-client, guestfish, ip, nft"},
		{Name: nodecheck.LayerPVE, Status: nodecheck.StatusFailed, Code: nodecheck.CodePVECAUntrusted,
			Detail: "the node does not trust the certificate authority that signed the PVE API certificate (x509: certificate signed by unknown authority)"},
	}}
}

// hostFix is what the hint says when setup pve-ca has nowhere to write the CA:
// the host's way, as deploy/controller/README.md gives it.
var hostFix = []string{
	"This process cannot write to ",
	"certistack setup pve-ca cannot put the CA there",
	"copy /etc/pve/pve-root-ca.pem from the node",
	"sudo install -m 0600 -o 65532 -g 65532 pve-root-ca.pem deploy/controller/secrets/pve-ca.pem",
	"(https://github.com/cliftcloud/certistack/blob/main/deploy/controller/README.md#prepare-controller-secrets;",
}

func assertHostFix(t *testing.T, out, dir string) {
	t.Helper()
	for _, want := range append([]string{"cannot write to " + dir + ","}, hostFix...) {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// The command that would write next to the read-only mount is not offered.
	if strings.Contains(out, "certistack setup pve-ca --env-file") {
		t.Errorf("the hint still offers setup pve-ca --env-file, which cannot write here:\n%s", out)
	}
}

// In the controller container the environment file sits in a read-only mount,
// where setup pve-ca would write the CA: the hint says to fetch it on the host
// and install it, as the README does, and keeps the current hint wherever the
// directory can be written.
func TestCheckLayer5SendsAReadOnlyEnvironmentDirectoryToTheHost(t *testing.T) {
	t.Run("a stock node, no CA named", func(t *testing.T) {
		c := readyController(t)
		readOnly(t, c.dir)
		withNode(t, &nodeStub{report: untrustedPVECA()})
		out, _ := failsAt(t, c)
		if !strings.Contains(out, "✗ 5. PVE API") || !strings.Contains(out, "signs its API certificate with the cluster's own CA") {
			t.Fatalf("layer 5 did not fail on the CA:\n%s", out)
		}
		assertHostFix(t, out, c.dir)
	})

	t.Run("a CA that does not sign the certificate, in a read-only directory", func(t *testing.T) {
		caDir := t.TempDir()
		named := filepath.Join(caDir, "pve-ca.pem")
		if err := os.WriteFile(named, []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
		c := readyController(t, "CERTISTACK_PVE_CA_SOURCE="+named)
		readOnly(t, caDir)
		withNode(t, &nodeStub{report: untrustedPVECA()})
		out, _ := failsAt(t, c)
		if !strings.Contains(out, "CERTISTACK_PVE_CA_SOURCE is set ("+named+")") {
			t.Fatalf("the named CA was not reported:\n%s", out)
		}
		assertHostFix(t, out, caDir)
		if strings.Contains(out, "--out "+named) {
			t.Errorf("the hint offers --out into the read-only directory:\n%s", out)
		}
	})

	// --out writes the CA file itself, so it is the directory of that file that
	// decides: a read-only environment directory does not matter to it.
	t.Run("a named CA in a writable directory keeps the current hint", func(t *testing.T) {
		named := filepath.Join(t.TempDir(), "pve-ca.pem")
		if err := os.WriteFile(named, []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
		c := readyController(t, "CERTISTACK_PVE_CA_SOURCE="+named)
		readOnly(t, c.dir)
		withNode(t, &nodeStub{report: untrustedPVECA()})
		out, _ := failsAt(t, c)
		if !strings.Contains(out, "certistack setup pve-ca --env-file "+c.env+" --out "+named) {
			t.Errorf("a writable CA directory lost the current hint:\n%s", out)
		}
		if strings.Contains(out, "cannot write to") {
			t.Errorf("the hint says the process cannot write, but it can write the CA's directory:\n%s", out)
		}
	})

	t.Run("a CA file the worker could not be given", func(t *testing.T) {
		c := readyController(t)
		readOnly(t, c.dir)
		withNode(t, &nodeStub{stagingError: errors.New("stage PVE CA file: read PVE TLS CA file: no such file")})
		out, _ := failsAt(t, c)
		if !strings.Contains(out, "CERTISTACK_PVE_CA_SOURCE names a file this controller cannot read as a CA.") {
			t.Fatalf("the staging failure was not reported:\n%s", out)
		}
		assertHostFix(t, out, c.dir)
	})

	t.Run("a writable directory keeps the current hint", func(t *testing.T) {
		c := readyController(t)
		withNode(t, &nodeStub{report: untrustedPVECA()})
		out, _ := failsAt(t, c)
		if !strings.Contains(out, "certistack setup pve-ca --env-file "+c.env+"\n") || strings.Contains(out, "cannot write to") {
			t.Errorf("a writable directory got the host hint:\n%s", out)
		}
	})
}

// The probe creates a file and removes it again, and answers for the process
// that asks.
func TestDirectoryWritableTriesToWrite(t *testing.T) {
	dir := t.TempDir()
	if !directoryWritable(dir) {
		t.Error("a directory this process owns was reported as not writable")
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the probe left %v in the directory (%v)", entries, err)
	}
	if directoryWritable(filepath.Join(dir, "no-such-directory")) {
		t.Error("a directory that does not exist was reported as writable")
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if directoryWritable(file) {
		t.Error("a file was reported as a writable directory")
	}
	t.Run("a directory without write permission", func(t *testing.T) {
		readOnly(t, dir)
	})
}

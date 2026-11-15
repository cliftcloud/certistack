// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build linux

package nodeidentity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// local reads /etc/pve/local, PVE's own link to this node's directory in its
// cluster file system: its target is nodes/<name>. Where it does not exist
// (not a PVE host, a test) the short host name is the name.
func TestLocalReadsTheLinkPVEKeepsForThisNode(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "local")
	if err := os.Symlink("nodes/pve-node-01", link); err != nil {
		t.Fatal(err)
	}
	previousLink, previousHost := pveLocalLink, hostname
	t.Cleanup(func() { pveLocalLink, hostname = previousLink, previousHost })
	pveLocalLink = link
	hostname = func() (string, error) { return "some-other-name.example.com", nil }

	got, err := Local()
	if err != nil || got != "pve-node-01" {
		t.Fatalf("Local() = %q, %v; want the link's node, not the host name", got, err)
	}
}

func TestLocalFallsBackToTheShortHostNameWithoutAPVELink(t *testing.T) {
	previousLink, previousHost := pveLocalLink, hostname
	t.Cleanup(func() { pveLocalLink, hostname = previousLink, previousHost })
	pveLocalLink = filepath.Join(t.TempDir(), "local")
	hostname = func() (string, error) { return "pve1.example.com", nil }

	got, err := Local()
	if err != nil || got != "pve1" {
		t.Fatalf("Local() = %q, %v; want the short host name", got, err)
	}
}

func TestLocalFailsClosedForALinkThatIsNotOne(t *testing.T) {
	file := filepath.Join(t.TempDir(), "local")
	if err := os.WriteFile(file, []byte("not a link"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousLink := pveLocalLink
	t.Cleanup(func() { pveLocalLink = previousLink })
	pveLocalLink = file

	if name, err := Local(); err == nil || !strings.Contains(err.Error(), file) {
		t.Fatalf("Local() = %q, %v; want an error that names the path", name, err)
	}
}

func TestLocalFailsClosedWhenNeitherSourceGivesAName(t *testing.T) {
	previousLink, previousHost := pveLocalLink, hostname
	t.Cleanup(func() { pveLocalLink, hostname = previousLink, previousHost })
	pveLocalLink = filepath.Join(t.TempDir(), "local")
	hostname = func() (string, error) { return "", os.ErrPermission }

	if name, err := Local(); err == nil {
		t.Fatalf("Local() = %q with no source of a name", name)
	}
}

// A host is a PVE node when PVE's cluster file system directory is there, or
// PVE's own tools are on the PATH. A controller (a management VM, a laptop) has
// none of them. Any one is enough, so the legitimate use of plan and init as
// root on the node is never mistaken for a controller.
func TestOnPVENodeNeedsADirectoryOrATool(t *testing.T) {
	previousDir, previousLookPath := pveDir, lookPath
	t.Cleanup(func() { pveDir, lookPath = previousDir, previousLookPath })
	file := filepath.Join(t.TempDir(), "pve")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tools := func(names ...string) func(string) (string, error) {
		return func(name string) (string, error) {
			for _, have := range names {
				if name == have {
					return "/usr/sbin/" + name, nil
				}
			}
			return "", os.ErrNotExist
		}
	}
	for name, tc := range map[string]struct {
		dir   string
		tools func(string) (string, error)
		want  bool
	}{
		"nothing of PVE":            {filepath.Join(t.TempDir(), "absent"), tools(), false},
		"the directory":             {t.TempDir(), tools(), true},
		"a file, not the directory": {file, tools(), false},
		"pveversion only":           {filepath.Join(t.TempDir(), "absent"), tools("pveversion"), true},
		"qm only":                   {filepath.Join(t.TempDir(), "absent"), tools("qm"), true},
		"an unrelated tool":         {filepath.Join(t.TempDir(), "absent"), tools("ip", "ssh"), false},
	} {
		pveDir, lookPath = tc.dir, tc.tools
		if got := OnPVENode(); got != tc.want {
			t.Errorf("%s: OnPVENode() = %v, want %v", name, got, tc.want)
		}
	}
}

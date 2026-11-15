// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The directory given to setup (--dir, or the answer to its first question)
// was made private with a chmod whatever it held: a shared /tmp, a home, /etc
// or / given by mistake lost its mode (and /tmp its sticky bit), which is a
// change to something that is not setup's own. A directory that already holds
// anything but setup's own files is left as it is, and setup asks for one of
// its own, before it changes anything.
func TestTheWizardNeverChmodsADirectoryThatHoldsOtherFiles(t *testing.T) {
	f, _ := newWizardWorld(t)
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "someone-elses.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runWizard(t, f, shared, setupWizardOptions{Dir: shared, NodeHost: "pve1.example.com", Fingerprint: fixedHostKey(t, 7).Fingerprint, Yes: true})
	info, statErr := os.Stat(shared)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode()&(os.ModePerm|os.ModeSticky) != 0o777|os.ModeSticky {
		t.Fatalf("setup changed the mode of a shared directory it was given to %v:\n%s", info.Mode(), out)
	}
	if err == nil || !strings.Contains(err.Error(), shared) || !strings.Contains(err.Error(), "someone-elses.txt") {
		t.Fatalf("setup went on in a shared directory, or did not say why it stopped: %v\n%s", err, out)
	}
	if len(f.changes) != 0 {
		t.Fatalf("setup changed %v before it refused the directory", f.changes)
	}
}

// A directory that holds only what setup writes (an earlier setup's files) or
// nothing at all is setup's own: one open to other users is still made private,
// as before.
func TestTheWizardStillMakesItsOwnDirectoryPrivate(t *testing.T) {
	for name, files := range map[string][]string{"empty": nil, "an earlier setup's": {"controller.env.bak-20261101T000000Z", "known_hosts", "id_ed25519", "id_ed25519.pub"}} {
		t.Run(name, func(t *testing.T) {
			f, _ := newWizardWorld(t)
			own := filepath.Join(t.TempDir(), "secure")
			if err := os.Mkdir(own, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				if err := os.WriteFile(filepath.Join(own, file), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out, _ := runWizard(t, f, own, setupWizardOptions{Dir: own, NodeHost: "pve1.example.com", Fingerprint: fixedHostKey(t, 7).Fingerprint, Yes: true})
			if info, err := os.Stat(own); err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("setup's own directory was not made private: %v %v\n%s", info.Mode(), err, out)
			}
			if !strings.Contains(out, "Made "+own+" private (mode 0700)") {
				t.Fatalf("setup did not say it made the directory private:\n%s", out)
			}
		})
	}
}

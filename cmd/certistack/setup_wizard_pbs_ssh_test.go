// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"
)

// --pbs-ssh is handed to ssh as its destination. A value that starts with "-"
// was read by ssh as an option ("-oProxyCommand=...", which runs a command on
// the controller, or "-p 2222 root@pbs", which fails late as a bad port), and
// one with white space never named a host; both were found only at step 7,
// after the node had been changed. They are refused with the other flags,
// before anything is asked or changed.
func TestTheWizardRefusesAPBSSSHThatIsNoDestination(t *testing.T) {
	for _, value := range []string{"-oProxyCommand=touch /tmp/x", "-p 2222 root@pbs", "root@pbs -p 2222", "root@pbs\n", "\troot@pbs"} {
		f, dir := newWizardWorld(t)
		_, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", Fingerprint: fixedHostKey(t, 7).Fingerprint, Yes: true, PBSSSH: value, PBSNamespace: "/"})
		if err == nil || !strings.Contains(err.Error(), "--pbs-ssh") {
			t.Errorf("--pbs-ssh %q: %v, want it refused by name", value, err)
		}
		if len(f.changes) != 0 {
			t.Errorf("--pbs-ssh %q: setup changed %v before it refused it", value, f.changes)
		}
	}
	// A destination ssh reads as one: user@host, a host, or a Host alias.
	for _, value := range []string{"root@pbs.example.com", "pbs-backup", "root@192.0.2.20", "my_pbs_alias"} {
		if err := checkWizardFlags(setupWizardOptions{PBSSSH: value}); err != nil {
			t.Errorf("--pbs-ssh %q was refused: %v", value, err)
		}
	}
}

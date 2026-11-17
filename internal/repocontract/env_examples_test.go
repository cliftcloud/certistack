// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// activeEnvironment returns an environment example's uncommented NAME=value
// lines, in order, and its commented-out NAME=value lines.
func activeEnvironment(t *testing.T, path string) (active, commented map[string]string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	active, commented = map[string]string{}, map[string]string{}
	assignment := regexp.MustCompile(`^(#?)([A-Z][A-Z0-9_]*)=(.*)$`)
	for _, line := range strings.Split(string(data), "\n") {
		if m := assignment.FindStringSubmatch(line); m != nil {
			if m[1] == "#" {
				commented[m[2]] = m[3]
			} else {
				active[m[2]] = m[3]
			}
		}
	}
	return active, commented
}

// Neither shipped controller.env example names a report-signing key (the
// Community Edition writes its reports unsigned and the controller refuses
// CERTISTACK_SIGN_KEY, so a copied example must not carry one), and both leave
// the PVE CA line commented out: the CA is conditional, and an active line makes
// a missing pve-ca.pem stop every run.
func TestShippedEnvironmentExamplesNameNoSigningKeyAndLeaveTheCAOptional(t *testing.T) {
	for _, c := range []struct {
		name, example, readme, installed string
	}{
		{"appliance", repoFile("deploy", "appliance", "files", "controller.env.example"), repoFile("deploy", "appliance", "README.md"), "/etc/certistack/secrets/"},
		{"container", repoFile("deploy", "controller", "secrets", "controller.env.example"), repoFile("deploy", "controller", "README.md"), "deploy/controller/secrets/"},
	} {
		t.Run(c.name, func(t *testing.T) {
			active, commented := activeEnvironment(t, c.example)
			for _, set := range []map[string]string{active, commented} {
				if got, named := set["CERTISTACK_SIGN_KEY"]; named {
					t.Errorf("CERTISTACK_SIGN_KEY=%s is in the example, and the controller refuses that variable", got)
				}
			}
			if example, err := os.ReadFile(c.example); err != nil {
				t.Fatal(err)
			} else if strings.Contains(string(example), "certistack keygen") || strings.Contains(string(example), "signing key") {
				t.Error("the example still talks of a signing key")
			}
			if got, ok := active["CERTISTACK_PVE_CA_SOURCE"]; ok {
				t.Errorf("CERTISTACK_PVE_CA_SOURCE=%s is active, so every run needs a pve-ca.pem the guide calls optional", got)
			}
			if got := commented["CERTISTACK_PVE_CA_SOURCE"]; got != "/run/certistack-secrets/pve-ca.pem" {
				t.Errorf("the commented CA line is %q, so uncommenting it would not name the file the guide installs", got)
			}

			// Every secret file an active line names is installed by the guide.
			readme, err := os.ReadFile(c.readme)
			if err != nil {
				t.Fatal(err)
			}
			for name, value := range active {
				file, ok := strings.CutPrefix(value, "/run/certistack-secrets/")
				if !ok {
					continue
				}
				if !strings.Contains(string(readme), c.installed+file) && !strings.Contains(string(readme), " "+file+" ") {
					t.Errorf("%s=%s names a file the guide never installs", name, value)
				}
			}
			for _, stale := range []string{"controller-signing", "certistack keygen", "Create the report-signing key"} {
				if strings.Contains(string(readme), stale) {
					t.Errorf("the guide still mentions %q: the controller signs nothing", stale)
				}
			}
		})
	}
}

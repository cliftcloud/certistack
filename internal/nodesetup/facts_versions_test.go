// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The facts carry what setup holds a node to before its first change: the
// client's own version, the PVE release in pveversion's line, and pvesh's
// read of the SDN zones. Only pvesh's "No 'get' handler" is a missing SDN API;
// a read that failed otherwise, or was not made, says nothing.
func TestNodeFactsCarryTheVersionsAndTheSDNRead(t *testing.T) {
	facts, err := ParseNodeFacts(factsOutput("", "pbs_client_out=client version: 2.99.0", "sdn_zones=read"))
	if err != nil {
		t.Fatal(err)
	}
	if facts.ClientVersion != "2.99.0" || facts.PVERelease() != "9.2.2" || !facts.SDNRead || facts.SDNMissing() != nil {
		t.Errorf("facts: client %q, release %q, SDN read %v, missing %v", facts.ClientVersion, facts.PVERelease(), facts.SDNRead, facts.SDNMissing())
	}
	facts, _ = ParseNodeFacts(factsOutput("", "sdn_zones_error=No 'get' handler defined for '/cluster/sdn/zones'"))
	if missing := facts.SDNMissing(); missing == nil || !strings.Contains(missing.Problem(), "no SDN API (pvesh get /cluster/sdn/zones on the node: No 'get' handler defined)") {
		t.Errorf("a node without the SDN API: %v", missing)
	}
	for _, other := range []string{"", "sdn_zones_error=ipcc_send_rec[1] failed: Connection refused", "sdn_zones_error="} {
		facts, _ := ParseNodeFacts(factsOutput("", other))
		if facts.SDNRead || facts.SDNMissing() != nil || facts.ClientVersion != "" {
			t.Errorf("%q: SDN read %v, missing %v, client %q", other, facts.SDNRead, facts.SDNMissing(), facts.ClientVersion)
		}
	}
	for line, want := range map[string]string{
		"pve-manager/8.0.3/bbf3993334bfa916 (running kernel: 6.2.16-3-pve)": "8.0.3",
		"pve-manager/7.4-3/9002ab8a (running kernel: 5.15.102-1-pve)":       "7.4-3",
		"":               "",
		"not pveversion": "",
	} {
		if got := (NodeFacts{PVEVersion: line}).PVERelease(); got != want {
			t.Errorf("PVERelease of %q = %q, want %q", line, got, want)
		}
	}
}

// The script's two reads, run by a real shell against a fake client and pvesh:
// the client is asked with an empty environment (no repository, so no server),
// pvesh reads the zones and nothing else, and neither one's error output
// reaches the operator.
func TestTheFactsScriptReadsTheClientAndTheSDNZones(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the facts script is POSIX shell")
	}
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("no timeout command here")
	}
	var lines []string
	for _, l := range strings.Split(NodeFactsScript, "\n") {
		if strings.HasPrefix(l, "if command -v proxmox-backup-client ") || strings.HasPrefix(l, "if command -v pvesh ") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("the facts script has %d of its two version and SDN lines", len(lines))
	}
	for name, tc := range map[string]struct {
		pvesh   string
		missing bool
	}{
		"SDN":    {pvesh: `echo '[{"zone":"lab"}]'`},
		"no SDN": {pvesh: `echo "No 'get' handler defined for '/cluster/sdn/zones'" >&2; exit 255`, missing: true},
	} {
		t.Run(name, func(t *testing.T) {
			bin := t.TempDir()
			seen := filepath.Join(t.TempDir(), "seen")
			write := func(name, body string) {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			write("proxmox-backup-client", `echo "client $* PBS_REPOSITORY=${PBS_REPOSITORY:-unset}" >>`+seen+`; echo 'client version: 2.99.0'; echo 'warning on stderr' >&2`)
			write("pvesh", `echo "pvesh $*" >>`+seen+`; `+tc.pvesh)
			cmd := exec.Command("/bin/sh", "-c", strings.Join(lines, "\n"))
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "PBS_REPOSITORY=certistack@pbs!x@pbs.example:store"}
			var stderr strings.Builder
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil || stderr.Len() != 0 {
				t.Fatalf("the lines: %v, stderr %q", err, stderr.String())
			}
			facts, err := ParseNodeFacts(factsOutput("", strings.Split(strings.TrimSpace(string(out)), "\n")...))
			if err != nil {
				t.Fatal(err)
			}
			if facts.ClientVersion != "2.99.0" || (facts.SDNMissing() != nil) != tc.missing || facts.SDNRead == tc.missing {
				t.Errorf("output %q: client %q, SDN read %v, missing %v", out, facts.ClientVersion, facts.SDNRead, facts.SDNMissing())
			}
			calls, _ := os.ReadFile(seen)
			if got, want := string(calls), "client version PBS_REPOSITORY=unset\npvesh get /cluster/sdn/zones --output-format json\n"; got != want {
				t.Errorf("the node was asked\n%s\nwant\n%s", got, want)
			}
		})
	}
}

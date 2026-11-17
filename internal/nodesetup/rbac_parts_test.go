// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// skipIfPBSHere skips a test that needs a host without proxmox-backup-manager
// when the machine running the tests is itself a Proxmox Backup Server.
func skipIfPBSHere(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("proxmox-backup-manager"); err == nil {
		t.Skip("this machine has a real proxmox-backup-manager")
	}
}

// The whole script, copied to a PVE node and run there, does all of part 1;
// part 2 must then say plainly that it belongs to the Proxmox Backup Server,
// and end well: not an error, and not an error that blames a step that had
// succeeded.
func TestRBACWholeScriptOnAPVENodeEndsWellAtPart2(t *testing.T) {
	skipIfPBSHere(t)
	s := newRBACSandboxWith(t, rbacWithPBS, "pveum")
	for run := 1; run <= 2; run++ {
		stdout, stderr, code := s.run()
		if code != 0 {
			t.Fatalf("run %d: exit %d, want 0\nstdout:\n%s\nstderr:\n%s", run, code, stdout, stderr)
		}
		if strings.Contains(stderr, "stopped while") || strings.Contains(stderr, "proxmox-backup-manager not found") {
			t.Errorf("run %d: part 2 reported an error on a PVE node:\n%s", run, stderr)
		}
		for _, want := range []string{"Part 1 is done", "run part 2 on the Proxmox Backup Server"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("run %d: stdout lacks %q:\n%s", run, want, stdout)
			}
		}
	}
	if s.secrets() != 1 {
		t.Errorf("%d token secrets in all, want 1 (the PVE token, once)", s.secrets())
	}
	if n := s.called("pveum acl modify "); n == 0 {
		t.Error("part 1 did not run")
	}
}

// A failing check in part 2 must not name the step part 1 ended with: the step
// is set before the check.
func TestRBACPart2SetsItsStepBeforeItsToolCheck(t *testing.T) {
	script := scriptFor(t, rbacWithPBS)
	part2 := script[strings.Index(script, "# PART 2 of 2"):]
	step := strings.Index(part2, "\nSTEP=")
	check := strings.Index(part2, "command -v proxmox-backup-manager")
	if step < 0 || check < 0 {
		t.Fatalf("part 2 has no STEP assignment (%d) or no tool check (%d):\n%s", step, check, part2)
	}
	if step > check {
		t.Errorf("part 2 checks for proxmox-backup-manager before it sets STEP, so a failure blames the last step of part 1:\n%s", part2)
	}
}

// --part prints one part as a script of its own.
func TestRBACPartIsACompleteScriptOfItsOwn(t *testing.T) {
	onlyPVE, onlyPBS := rbacWithPBS, rbacWithPBS
	onlyPVE.Part, onlyPBS.Part = PartPVE, PartPBS
	pve := scriptFor(t, onlyPVE)
	pbs := scriptFor(t, onlyPBS)
	for name, script := range map[string]string{"pve": pve, "pbs": pbs} {
		if !strings.HasPrefix(script, "#!/bin/sh\n") {
			t.Errorf("--part %s does not start as a script", name)
		}
		for _, want := range []string{"\nset -eu\n", "\nSTEP='", "\ntrap '"} {
			if !strings.Contains(script, want) {
				t.Errorf("--part %s lacks %q", name, strings.TrimSpace(want))
			}
		}
	}
	if strings.Contains(pve, "proxmox-backup-manager") && strings.Contains(strings.Join(commandsOf(pve), "\n"), "proxmox-backup-manager") {
		t.Errorf("--part pve runs a PBS command")
	}
	if strings.Contains(strings.Join(commandsOf(pbs), "\n"), "pveum") {
		t.Errorf("--part pbs runs a PVE command")
	}
	whole := scriptFor(t, rbacWithPBS)
	for _, command := range commandsOf(pve) {
		if !strings.Contains(whole, command+"\n") {
			t.Errorf("--part pve has a command the whole script lacks: %s", command)
		}
	}
	for _, command := range commandsOf(pbs) {
		if !strings.Contains(whole, command+"\n") && !strings.Contains(command, "run this script as root") {
			t.Errorf("--part pbs has a command the whole script lacks: %s", command)
		}
	}
	// --part pve needs no datastore: it is the script for a PVE node as ever.
	alone := scriptFor(t, RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch", Part: PartPVE})
	if !strings.Contains(alone, "pveum role") || strings.Contains(alone, "PART 2") {
		t.Errorf("--part pve without a datastore:\n%s", alone)
	}
}

func TestRBACPartRefusesWhatIsNotAPart(t *testing.T) {
	good := RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch", PBSDatastore: "datastore1"}
	for _, part := range []string{"PVE", "Pbs", "1", "2", "both", "all", "pve;id", "pve ", " pve", "pve\npbs", "$(id)"} {
		p := good
		p.Part = part
		if script, err := RBACScript(p); err == nil || script != "" {
			t.Errorf("--part %q was accepted", part)
		}
	}
	p := RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch", Part: PartPBS}
	if _, err := RBACScript(p); err == nil || !strings.Contains(err.Error(), "--part pbs needs --pbs-datastore") {
		t.Errorf("--part pbs without a datastore: %v", err)
	}
}

// Each part, sent to its host as `... --part X | ssh root@HOST sh -s`, can be
// run twice, and creates its token once. The stdin of sh is the script itself.
func TestRBACEachPartCanBeRunAgain(t *testing.T) {
	skipIfPBSHere(t)
	for _, test := range []struct {
		part     string
		tools    []string
		secret   string
		wantAcls int
	}{
		{PartPVE, []string{"pveum"}, "STUB-SECRET-certistack-svc@pve!automation", 5},
		{PartPBS, []string{"proxmox-backup-manager"}, "STUB-SECRET-certistack-ro@pbs!ro", 2},
	} {
		t.Run(test.part, func(t *testing.T) {
			params := rbacWithPBS
			params.Part = test.part
			s := newRBACSandboxWith(t, params, test.tools...)
			stdout, stderr, code := s.run()
			if code != 0 {
				t.Fatalf("first run exited %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if !strings.Contains(stdout, test.secret) {
				t.Errorf("the first run did not show the token secret:\n%s", stdout)
			}
			if strings.Contains(stdout+stderr, "Part 1 is done") || strings.Contains(stderr, "stopped while") {
				t.Errorf("a single part ended with the whole file's message:\n%s\n%s", stdout, stderr)
			}
			acls := s.read("acl")
			if got := strings.Count(acls, "\n"); got != test.wantAcls {
				t.Errorf("%d ACLs after the first run, want %d:\n%s", got, test.wantAcls, acls)
			}
			stdout, stderr, code = s.run()
			if code != 0 {
				t.Fatalf("second run exited %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if s.secrets() != 1 {
				t.Errorf("%d token secrets in all, want 1", s.secrets())
			}
			if strings.Contains(stdout+stderr, "STUB-SECRET") {
				t.Errorf("the second run printed a token secret:\n%s\n%s", stdout, stderr)
			}
			if got := s.read("acl"); got != acls {
				t.Errorf("the second run changed the ACLs:\n%s\n%s", acls, got)
			}
		})
	}
}

// A part run on the wrong host says so and changes nothing.
func TestRBACPartOnTheWrongHostRefusesClearly(t *testing.T) {
	skipIfPBSHere(t)
	params := rbacWithPBS
	params.Part = PartPBS
	s := newRBACSandboxWith(t, params, "pveum")
	stdout, stderr, code := s.run()
	if code == 0 || !strings.Contains(stderr, "proxmox-backup-manager not found: run this script as root on the Proxmox Backup Server") {
		t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stderr, "stopped while reading") {
		t.Errorf("a stale step is named:\n%s", stderr)
	}
	if s.read("calls") != "" {
		t.Errorf("the script changed something on the wrong host:\n%s", s.read("calls"))
	}
}

// The point of --part is `certistack setup rbac ... --part pve | ssh root@HOST
// sh -s`: the shell reads the script from standard input, so no command in it may
// swallow the lines that follow, and the whole file run that way on a PVE node
// ends well too.
func TestRBACScriptRunsFromStandardInputAsShDashS(t *testing.T) {
	skipIfPBSHere(t)
	whole := rbacWithPBS
	onlyPVE, onlyPBS := rbacWithPBS, rbacWithPBS
	onlyPVE.Part, onlyPBS.Part = PartPVE, PartPBS
	for _, test := range []struct {
		name    string
		params  RBACParams
		tools   []string
		secrets int
		want    string
	}{
		{"part pve", onlyPVE, []string{"pveum"}, 1, "Role CertiStackRole created."},
		{"part pbs", onlyPBS, []string{"proxmox-backup-manager"}, 1, "PBS user certistack-ro@pbs created."},
		{"the whole file on a PVE node", whole, []string{"pveum"}, 1, "Part 1 is done"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newRBACSandboxWith(t, test.params, test.tools...)
			script := scriptFor(t, test.params)
			for run := 1; run <= 2; run++ {
				cmd := exec.Command(s.command, "-s")
				cmd.Stdin = strings.NewReader(script)
				cmd.Env = []string{"PATH=" + s.bin + string(os.PathListSeparator) + os.Getenv("PATH"), "STUB_STATE=" + s.state, "HOME=" + s.state, "LC_ALL=C"}
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				if err := cmd.Run(); err != nil {
					t.Fatalf("run %d: sh -s: %v\nstdout:\n%s\nstderr:\n%s", run, err, stdout.String(), stderr.String())
				}
				if run == 1 && !strings.Contains(stdout.String(), test.want) {
					t.Errorf("the first run's output lacks %q:\n%s", test.want, stdout.String())
				}
			}
			if s.secrets() != test.secrets {
				t.Errorf("%d token secrets in all, want %d", s.secrets(), test.secrets)
			}
			if !strings.Contains(s.read("acl"), "\n") {
				t.Error("the script stopped before the ACLs: it did not read the whole of its standard input")
			}
		})
	}
}

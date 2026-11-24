// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// runInitWithInput is runInit with standard input, for the question init asks.
func runInitWithInput(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Cleanup(func() { activeCommand.Store(""); remoteWorkerStaged.Store(false); localInspection.Store(false) })
	root := newRootCmd(nil)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err = root.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

// atATerminal makes init believe it is at one.
func atATerminal(t *testing.T) {
	t.Helper()
	previous := initIsTerminal
	t.Cleanup(func() { initIsTerminal = previous })
	initIsTerminal = func() bool { return true }
}

// withDiskSize gives every VM of initNode's discovery this much disk each.
func withDiskSize(t *testing.T, bytes int64) {
	t.Helper()
	discover := runnerDiscover
	t.Cleanup(func() { runnerDiscover = discover })
	runnerDiscover = func(ctx context.Context, req initplan.Request, scratch string) (*initplan.Discovery, error) {
		d, err := discover(ctx, req, scratch)
		for i := range d.VMs {
			d.VMs[i].DiskBytes = bytes
		}
		return d, err
	}
}

// init says what a run of its plan will read and hold, before it writes the
// plan: the disks, about how long they take, and the RAM. The three VMs of the
// test node have 20 GiB each and no memory in their backups, so a run reads 60
// GiB (about 23 minutes at 100 MB/s with 4 minutes of preparation per VM) and
// reserves 3 x (2048 + 256) MiB.
func TestInitSaysWhatARunOfThePlanReads(t *testing.T) {
	dir := initNode(t)
	stdout, stderr, err := runInit(t, context.Background(), initArgs(dir)...)
	if err != nil {
		t.Fatalf("init: %v\n%s", err, stderr)
	}
	for _, want := range []string{
		"The plan restores 3 VM(s). A run of it:\n",
		"  reads 60 GiB of backup disks, each in full\n",
		"  takes about 23 min (reading at 100 MB/s, a rate measured on older servers, plus 4 minutes to prepare each VM; a faster node takes less)\n",
		"  reserves 6.8 GiB of the node's RAM while it runs (each VM's memory plus 256 MiB)\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Index(stdout, "A run of it") > strings.Index(stdout, "Wrote ") {
		t.Errorf("the sizes come after the plan is written:\n%s", stdout)
	}
	// Without --vm or --all it lists backups, and says nothing of a plan.
	listing, _, err := runInit(t, context.Background(), "init", "--node", "pve1")
	if err == nil && strings.Contains(listing, "A run of it") {
		t.Errorf("the backup list carries the sizes of a plan:\n%s", listing)
	}
}

// A VM whose backup gives no disk size is left out of the total, and the account
// says so.
func TestInitSaysWhichVMsHaveNoDiskSize(t *testing.T) {
	dir := initNode(t)
	withDiskSize(t, 0)
	stdout, stderr, err := runInit(t, context.Background(), initArgs(dir)...)
	if err != nil {
		t.Fatalf("init: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "(3 VM(s) have no disk size in their backup, so the first two lines leave them out)") || !strings.Contains(stdout, "reads 0 MiB of backup disks") {
		t.Errorf("the output does not say the sizes are missing:\n%s", stdout)
	}
}

// At a terminal, init asks again for --all, and for a plan of more than 500 GiB,
// and writes nothing on any answer but yes. With --yes, and without a terminal,
// it asks nothing.
func TestInitAsksBeforeWritingALargePlan(t *testing.T) {
	type outcome struct {
		args     []string
		stdin    string
		terminal bool
		disk     int64 // GiB per VM
		asked    string
		written  bool
	}
	big := int64(200) // 600 GiB for the three VMs
	for name, tc := range map[string]outcome{
		"--all, answered yes":               {args: []string{"--all"}, stdin: "y\n", terminal: true, disk: 20, asked: "--all puts every VM that has a backup in the plan, 3 here. Write the plan? [y/N] ", written: true},
		"--all, answered with Enter":        {args: []string{"--all"}, stdin: "\n", terminal: true, disk: 20, asked: "Write the plan? [y/N] "},
		"--all, answered no":                {args: []string{"--all"}, stdin: "no\n", terminal: true, disk: 20, asked: "Write the plan? [y/N] "},
		"--all, the input ends":             {args: []string{"--all"}, stdin: "", terminal: true, disk: 20, asked: "Write the plan? [y/N] "},
		"--all, with --yes":                 {args: []string{"--all", "--yes"}, stdin: "", terminal: true, disk: 20, written: true},
		"--all, without a terminal":         {args: []string{"--all"}, stdin: "", terminal: false, disk: 20, written: true},
		"600 GiB named, answered yes":       {args: []string{"--vm", "100,101,102"}, stdin: "YES\n", terminal: true, disk: big, asked: "A run of this plan reads more than 500 GiB. Write the plan? [y/N] ", written: true},
		"600 GiB named, answered no":        {args: []string{"--vm", "100,101,102"}, stdin: "n\n", terminal: true, disk: big, asked: "A run of this plan reads more than 500 GiB."},
		"600 GiB named, without a terminal": {args: []string{"--vm", "100,101,102"}, stdin: "", terminal: false, disk: big, written: true},
		"600 GiB named, with --yes":         {args: []string{"--vm", "100,101,102", "--yes"}, stdin: "", terminal: true, disk: big, written: true},
		"60 GiB named, at a terminal":       {args: []string{"--vm", "100,101,102"}, stdin: "", terminal: true, disk: 20, written: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := initNode(t)
			withDiskSize(t, tc.disk<<30)
			if tc.terminal {
				atATerminal(t)
			}
			args := append([]string{"init", "--node", "pve1", "--output", filepath.Join(dir, "plan.yaml")}, tc.args...)
			stdout, stderr, err := runInitWithInput(t, tc.stdin, args...)
			if tc.asked == "" && strings.Contains(stderr, "Write the plan?") {
				t.Errorf("init asked when it should not:\n%s", stderr)
			}
			if tc.asked != "" && !strings.Contains(stderr, tc.asked) {
				t.Errorf("stderr lacks the question %q:\n%s", tc.asked, stderr)
			}
			_, statErr := os.Stat(filepath.Join(dir, "plan.yaml"))
			if written := statErr == nil; written != tc.written {
				t.Fatalf("plan written = %v, want %v (err %v)\n%s", written, tc.written, err, stdout)
			}
			if tc.written && err != nil {
				t.Fatalf("init: %v\n%s", err, stderr)
			}
			if !tc.written && (err == nil || !strings.Contains(err.Error(), "nothing was written") || !strings.Contains(err.Error(), "--vm") || !strings.Contains(err.Error(), "--yes")) {
				t.Fatalf("a plan that was not confirmed: err = %v, want it to say nothing was written and name --vm and --yes", err)
			}
		})
	}
}

// The plan init writes is valid as it stands: validate accepts it, with its
// frameworks as written, and the account does not tell the reader to set them.
func TestInitWritesAPlanThatValidatesAsWritten(t *testing.T) {
	dir := initNode(t)
	stdout, stderr, err := runInit(t, context.Background(), initArgs(dir)...)
	if err != nil {
		t.Fatalf("init: %v\n%s", err, stderr)
	}
	path := filepath.Join(dir, "plan.yaml")
	plan, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plan), "  frameworks: [NONE]\n") || strings.Contains(string(plan), "frameworks: [CHANGE]") {
		t.Errorf("the plan's frameworks are not NONE:\n%s", plan)
	}
	if out, err := runInitValidate(t, path); err != nil {
		t.Fatalf("validate refused the plan init wrote: %v\n%s", err, out)
	}
	for _, forbidden := range []string{"Set compliance.frameworks", "not valid until"} {
		if strings.Contains(stdout, forbidden) || strings.Contains(string(plan), forbidden) {
			t.Errorf("init still says %q", forbidden)
		}
	}
	if !strings.Contains(stdout, "The plan is valid as it stands") || !strings.Contains(stdout, "(compliance.frameworks is [NONE]") || !strings.Contains(stdout, "probes marked CHANGE") {
		t.Errorf("the account does not say what is left to do:\n%s", stdout)
	}
	if !strings.Contains(string(plan), "# CHANGE: check the service this VM is for") {
		t.Errorf("the probes lost their CHANGE comment:\n%s", plan)
	}
}

// runInitValidate runs validate on a plan init wrote.
func runInitValidate(t *testing.T, path string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runRoot(t, &out, "validate", path)
	return out.String(), err
}

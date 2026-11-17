// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/runner"
)

// initNode is a node for init: its discovery (two Linux VMs with nginx in
// their backups, Rocky 9 and Debian 12, and a Windows VM), and a fixed clock,
// so the plan is the same on every run.
func initNode(t *testing.T) string {
	t.Helper()
	for name := range controllerEnvironmentNames {
		t.Setenv(name, "")
	}
	backup := time.Date(2026, 10, 5, 2, 0, 0, 0, time.UTC)
	vm := func(id int, name, ostype string, agent bool) initplan.VM {
		return initplan.VM{SourceVMID: id, Snapshot: fmt.Sprintf("vm/%d/2026-10-05T02:00:00Z", id), BackupTime: backup, Name: name, OSType: ostype, BIOS: "seabios", Agent: agent, HasNIC: true, MAC: fmt.Sprintf("BC:24:11:00:01:%02X", id-100), DiskBytes: 20 << 30}
	}
	previousDiscover, previousClock := runnerDiscover, initClock
	t.Cleanup(func() { runnerDiscover, initClock = previousDiscover, previousClock })
	initClock = func() time.Time { return time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC) }
	runnerDiscover = func(context.Context, initplan.Request, string) (*initplan.Discovery, error) {
		return &initplan.Discovery{Node: "pve1", VMs: []initplan.VM{vm(100, "web-rocky", "l26", false), vm(101, "web-debian", "l26", true), vm(102, "dc-01", "win11", true)},
			Storages:     []pve.NodeStorage{{Storage: "local", NodeStorageStatus: pve.NodeStorageStatus{Type: "dir", Content: "images", Active: 1, Enabled: 1, Avail: 400 << 30}}},
			SandboxVMIDs: []int{9100, 9101, 9102}, ZoneID: "csZone1", VNetID: "csVnet1"}, nil
	}
	return t.TempDir()
}

// runInit runs init (or node-inspect) through the root command, with ctx,
// and returns its stdout, its stderr and its error.
func runInit(t *testing.T, ctx context.Context, args ...string) (string, string, error) {
	t.Helper()
	t.Cleanup(func() { activeCommand.Store(""); remoteWorkerStaged.Store(false); localInspection.Store(false) })
	root := newRootCmd(nil)
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	return stdout.String(), stderr.String(), err
}

func initArgs(dir string, extra ...string) []string {
	return append([]string{"init", "--node", "pve1", "--vm", "100,101,102", "--output", filepath.Join(dir, "plan.yaml")}, extra...)
}

// rockyAndDebian is what the node finds in the two Linux guests: nginx on
// port 80 in both (Rocky's nginx.conf, Debian's sites-enabled/default), sshd
// in both, and in the Debian guest MariaDB on localhost.
func rockyAndDebian(req initplan.InspectRequest) initplan.Inspection {
	nginx := func(file string) initplan.Service {
		return initplan.Service{Kind: initplan.ServiceNginx, Unit: "nginx.service", Config: "/etc/nginx/nginx.conf", Listeners: []initplan.Listener{
			{Port: 80, HTTP: true, File: file, Text: "listen 80"},
			{Address: "[::]", Port: 80, HTTP: true, File: file, Text: "listen [::]:80"},
		}}
	}
	ssh := func(unit string) initplan.Service {
		return initplan.Service{Kind: initplan.ServiceSSH, Unit: unit, Config: "/etc/ssh/sshd_config", Defaulted: true, Listeners: []initplan.Listener{{Port: 22, Text: "Port 22 (the default), no ListenAddress (every address)"}}}
	}
	in := initplan.Inspection{Journaled: true, CleanupVerified: true}
	for _, target := range req.Targets {
		vm := initplan.InspectedVM{SourceVMID: target.SourceVMID, Snapshot: target.Snapshot}
		switch target.SourceVMID {
		case 100:
			vm.OS = "Rocky Linux 9.4 (Blue Onyx)"
			vm.Services = []initplan.Service{nginx("/etc/nginx/nginx.conf"), ssh("sshd.service")}
			vm.Notes = []string{"/etc/nginx/nginx.conf includes /usr/share/nginx/modules/*.conf, outside the files inspected, which was not read"}
		case 101:
			vm.OS = "Debian GNU/Linux 12 (bookworm)"
			vm.Services = []initplan.Service{nginx("/etc/nginx/sites-enabled/default"), ssh("ssh.service"), {Kind: initplan.ServiceMariaDB, Unit: "mariadb.service", Config: "/etc/mysql/my.cnf", Listeners: []initplan.Listener{{Address: "127.0.0.1", Port: 3306, File: "/etc/mysql/mariadb.conf.d/50-server.cnf", Text: "bind-address = 127.0.0.1, port 3306 (the default)"}}}}
		}
		in.VMs = append(in.VMs, vm)
	}
	return in
}

// Without --inspect, init writes the plan it always wrote, and its account
// ends with a line on what --inspect does.
func TestInitWithoutInspectIsUnchangedAndOffersIt(t *testing.T) {
	dir := initNode(t)
	previous := nodeInspect
	t.Cleanup(func() { nodeInspect = previous })
	nodeInspect = func(context.Context, initplan.InspectRequest, runner.InspectOptions) initplan.Inspection {
		t.Fatal("init inspected without --inspect")
		return initplan.Inspection{}
	}
	stdout, stderr, err := runInit(t, context.Background(), initArgs(dir)...)
	if err != nil {
		t.Fatalf("init: %v\n%s", err, stderr)
	}
	assertGolden(t, "init_default.golden", maskDir(stdout, dir))
	plan, err := os.ReadFile(filepath.Join(dir, "plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "init_default_plan.golden", maskDir(string(plan), dir))
	if strings.Contains(stderr, "Inspecting") {
		t.Errorf("stderr: %s", stderr)
	}
}

// With --inspect, init on the node inspects the Linux VMs it gives a
// sandbox address, writes a probe for each service found, and says per VM
// what it did; the plan validates as written.
func TestInitInspectWritesServiceProbes(t *testing.T) {
	dir := initNode(t)
	previous := nodeInspect
	t.Cleanup(func() { nodeInspect = previous })
	var asked initplan.InspectRequest
	var options runner.InspectOptions
	nodeInspect = func(_ context.Context, req initplan.InspectRequest, opts runner.InspectOptions) initplan.Inspection {
		asked, options = req, opts
		if !interruptHasCleanup() {
			t.Error("an interrupt during the inspection would say there is nothing to clean up")
		}
		return rockyAndDebian(req)
	}
	stdout, stderr, err := runInit(t, context.Background(), initArgs(dir, "--inspect", "--state-dir", filepath.Join(dir, "state"))...)
	if err != nil {
		t.Fatalf("init: %v\n%s", err, stderr)
	}
	if fmt.Sprint(asked.Targets) != "[{100 vm/100/2026-10-05T02:00:00Z} {101 vm/101/2026-10-05T02:00:00Z}]" || asked.Node != "pve1" {
		t.Fatalf("inspected %+v", asked)
	}
	if options.StateDir != filepath.Join(dir, "state") || !strings.HasPrefix(options.RunID, "run-") || options.NodeName != "pve1" {
		t.Fatalf("options %+v", options)
	}
	if !strings.Contains(stderr, "Inspecting the newest backup of 2 Linux VM(s), one at a time and read-only") {
		t.Errorf("stderr: %s", stderr)
	}
	assertGolden(t, "init_inspect.golden", maskDir(stdout, dir))
	plan, err := os.ReadFile(filepath.Join(dir, "plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "init_inspect_plan.golden", maskDir(string(plan), dir))
	if _, err := config.LoadFromReader(bytes.NewReader(plan)); err != nil {
		t.Fatalf("the plan does not validate as written: %v", err)
	}
}

// What can go wrong with an inspection never stops init from writing its
// plan: each Linux VM it could not inspect keeps the SSH probe, and the
// account says why. Cleanup it could not verify writes the plan and fails
// the command (status 2); an interrupt writes nothing (status 130).
func TestInitInspectFailurePaths(t *testing.T) {
	type outcome struct {
		code    int    // the exit status
		written bool   // the plan was written
		says    string // in stdout, or the error
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, cancel context.CancelFunc)
		args  []string
		want  outcome
	}{
		{"the host lock is held", func(t *testing.T, _ context.CancelFunc) {
			lockedNode(t, fmt.Errorf("%s: %w", journal.LockHeldMessage, syscall.EWOULDBLOCK), nil)
		}, nil, outcome{0, true, "100 (web-rocky): not inspected: another CertiStack operation holds the node's host lock"}},
		{"guestfish is missing", func(t *testing.T, _ context.CancelFunc) {
			lockedNode(t, nil, errors.New(`start isolated guest network profile with guestfish: exec: "guestfish": executable file not found in $PATH`))
		}, nil, outcome{0, true, "not inspected: guestfish (libguestfs) does not run on the node"}},
		{"cleanup not verified on this node", func(t *testing.T, _ context.CancelFunc) {
			stubNodeInspect(t, func(req initplan.InspectRequest) initplan.Inspection {
				in := rockyAndDebian(req)
				in.CleanupVerified, in.CleanupErrors = false, []string{"PBS loop device /dev/loop7 remains mapped after cleanup"}
				return in
			})
		}, nil, outcome{2, true, "the plan was written to <dir>/plan.yaml, but the inspection's cleanup on the node could not be verified: PBS loop device /dev/loop7 remains mapped after cleanup; on this node, run this program's recover command, or let the node's next run recover (Troubleshooting, Issue 35)"}},
		{"interrupted", func(t *testing.T, cancel context.CancelFunc) {
			stubNodeInspect(t, func(req initplan.InspectRequest) initplan.Inspection {
				cancel()
				return initplan.Inspection{Journaled: true, CleanupVerified: true, Interrupted: "interrupted by SIGINT"}
			})
		}, nil, outcome{130, false, "context canceled"}},
		{"through a worker: cleanup not verified", func(t *testing.T, _ context.CancelFunc) {
			stubRemoteInspect(t, func(req initplan.InspectRequest) ([]byte, error) {
				data, _ := json.Marshal(rockyAndDebian(req))
				return data, fmt.Errorf("%w: the node's journal does not show the run clean", controller.ErrInspectionCleanupUnverified)
			})
		}, []string{"--ssh-host", "pve1.example"}, outcome{2, true, "the plan was written to <dir>/plan.yaml, but the inspection's cleanup on the node could not be verified"}},
		{"through a worker that could not start", func(t *testing.T, _ context.CancelFunc) {
			stubRemoteInspect(t, func(initplan.InspectRequest) ([]byte, error) {
				return nil, errors.New("SSH command on pve1.example: ssh failed: exit status 255: Connection refused")
			})
		}, []string{"--ssh-host", "pve1.example"}, outcome{0, true, "100 (web-rocky): not inspected: the inspection did not run: SSH command on pve1.example"}},
		{"through a worker whose answer names a VM not asked about", func(t *testing.T, _ context.CancelFunc) {
			stubRemoteInspect(t, func(initplan.InspectRequest) ([]byte, error) {
				return json.Marshal(initplan.Inspection{VMs: []initplan.InspectedVM{{SourceVMID: 999, Snapshot: "vm/999/2026-10-05T02:00:00Z"}}})
			})
		}, []string{"--ssh-host", "pve1.example"}, outcome{0, true, "100 (web-rocky): not inspected: the node's answer did not match the request"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := initNode(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tc.setup(t, cancel)
			args := initArgs(dir, append([]string{"--inspect", "--state-dir", filepath.Join(dir, "state")}, tc.args...)...)
			if len(tc.args) > 0 {
				args = append(args, "--ssh-known-hosts", filepath.Join(dir, "known_hosts"))
				previous := remoteDiscover
				t.Cleanup(func() { remoteDiscover = previous })
				remoteDiscover = func(ctx context.Context, opts controller.RunOptions, req initplan.Request) ([]byte, error) {
					d, err := runnerDiscover(ctx, req, "")
					if err != nil {
						return nil, err
					}
					return json.Marshal(d)
				}
			}
			stdout, stderr, err := runInit(t, ctx, args...)
			if code := exitCodeForError(err); code != tc.want.code {
				t.Fatalf("exit %d (%v), want %d\n%s\n%s", code, err, tc.want.code, stdout, stderr)
			}
			_, statErr := os.Stat(filepath.Join(dir, "plan.yaml"))
			if (statErr == nil) != tc.want.written {
				t.Fatalf("plan written %v, want %v", statErr == nil, tc.want.written)
			}
			said := maskDir(stdout, dir)
			if err != nil {
				said += "\n" + maskDir(err.Error(), dir)
			}
			if !strings.Contains(said, tc.want.says) {
				t.Fatalf("output lacks %q:\n%s\nstderr: %s", tc.want.says, said, stderr)
			}
			if tc.want.written && tc.want.code == 0 {
				plan, _ := os.ReadFile(filepath.Join(dir, "plan.yaml"))
				if !strings.Contains(string(plan), `description: "SSH answers on the sandbox address"`) {
					t.Fatalf("the Linux VMs did not keep the SSH probe:\n%s", plan)
				}
			}
		})
	}
}

// lockedNode is a node whose host lock answers lockErr (nil: taken) and
// whose guestfish check answers guestfishErr; nothing is inspected.
func lockedNode(t *testing.T, lockErr, guestfishErr error) {
	t.Helper()
	previousLock, previousCheck := acquireHostLock, checkGuestfish
	t.Cleanup(func() { acquireHostLock, checkGuestfish = previousLock, previousCheck })
	acquireHostLock = func() (*os.File, error) {
		if lockErr != nil {
			return nil, lockErr
		}
		return os.CreateTemp(t.TempDir(), "lock")
	}
	checkGuestfish = func(context.Context) error { return guestfishErr }
	if lockErr == nil && guestfishErr == nil {
		t.Fatal("lockedNode would inspect")
	}
}

func stubNodeInspect(t *testing.T, answer func(initplan.InspectRequest) initplan.Inspection) {
	t.Helper()
	previous := nodeInspect
	t.Cleanup(func() { nodeInspect = previous })
	nodeInspect = func(_ context.Context, req initplan.InspectRequest, _ runner.InspectOptions) initplan.Inspection {
		return answer(req)
	}
}

func stubRemoteInspect(t *testing.T, answer func(initplan.InspectRequest) ([]byte, error)) {
	t.Helper()
	previous := remoteInspect
	t.Cleanup(func() { remoteInspect = previous })
	remoteInspect = func(_ context.Context, _ controller.RunOptions, req initplan.InspectRequest) ([]byte, error) {
		return answer(req)
	}
}

// The worker's command reads its targets and prints the node's answer as
// JSON, whatever the answer says; a target it cannot read is an error.
func TestNodeInspectCommand(t *testing.T) {
	for name := range workerEnvironmentNames {
		t.Setenv(name, "")
	}
	envFile := writeEnvFile(t, "PBS_NAMESPACE=prod\n")
	root := t.TempDir()
	state, scratch := filepath.Join(root, "state"), filepath.Join(root, "scratch")
	var asked initplan.InspectRequest
	var options runner.InspectOptions
	previous := nodeInspect
	t.Cleanup(func() { nodeInspect = previous })
	nodeInspect = func(_ context.Context, req initplan.InspectRequest, opts runner.InspectOptions) initplan.Inspection {
		asked, options = req, opts
		return initplan.Inspection{Refused: "another CertiStack operation holds the node's host lock"}
	}
	stdout, _, err := runInit(t, context.Background(), "node-inspect", "--node", "pve1", "--namespace", "prod", "--target", "100=vm/100/2026-10-05T02:00:00Z", "--target", "101=vm/101/2026-10-05T02:00:00Z", "--scratch", scratch, "--state-dir", state, "--run-id", "run-0b8c5c43-6f1e-4b2a-9d6f-7f0f0a6c1d2e", "--env-file", envFile)
	if err != nil {
		t.Fatal(err)
	}
	var answer initplan.Inspection
	if err := json.Unmarshal([]byte(stdout), &answer); err != nil || !strings.Contains(answer.Refused, "host lock") {
		t.Fatalf("stdout %q (%v)", stdout, err)
	}
	if fmt.Sprint(asked.Targets) != "[{100 vm/100/2026-10-05T02:00:00Z} {101 vm/101/2026-10-05T02:00:00Z}]" || asked.Namespace != "prod" {
		t.Fatalf("asked %+v", asked)
	}
	if options.StateDir != state || options.ScratchDir != scratch || options.RunID != "run-0b8c5c43-6f1e-4b2a-9d6f-7f0f0a6c1d2e" || options.NodeName != "pve1" {
		t.Fatalf("options %+v", options)
	}
	for _, bad := range []string{"100", "abc=vm/100/2026-10-05T02:00:00Z", "100=vm/101/2026-10-05T02:00:00Z"} {
		if _, _, err := runInit(t, context.Background(), "node-inspect", "--node", "pve1", "--target", bad, "--scratch", scratch, "--state-dir", state, "--env-file", envFile); err == nil {
			t.Errorf("target %q was accepted", bad)
		}
	}
}

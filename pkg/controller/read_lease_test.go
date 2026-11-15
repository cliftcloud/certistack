// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// readOptions are the options of a plan or a discovery on a node whose files
// the test does not need.
func readOptions(t *testing.T) RunOptions {
	t.Helper()
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-super-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	absPlan, err := filepath.Abs(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return RunOptions{
		PlanPath: absPlan,
		NodeName: "pve-01",
		StateDir: "/var/lib/certistack",
		SSH:      SSHConfig{Host: "pve.example", User: "root", Port: 22, KnownHostsFile: knownHosts},
	}
}

// slowRead makes the read itself (node-plan or node-discover) last, outside the
// serialized runner, so that the lease renewals which run meanwhile can be
// counted.
type slowRead struct {
	*serialRunner
	delay                    time.Duration
	touchesAtTheEndOfTheRead int64
}

func (r *slowRead) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	if joined := strings.Join(args, " "); strings.Contains(joined, "'node-plan'") || strings.Contains(joined, "'node-discover'") {
		time.Sleep(r.delay)
		r.touchesAtTheEndOfTheRead = r.touches.Load()
	}
	return r.serialRunner.Run(ctx, name, args)
}

// A plan or a discovery stages the same credential-bearing workspace as a run
// (the PVE and PBS environment, the encryption key, the worker), and used to
// keep it only for as long as the controller lived to remove it: nothing
// renewed a lease the node could see, so a controller that died left the
// credentials until some later run's scrub, and a read that outlasted the
// scrub's idle window looked abandoned to another run. The workspace now has a
// lease from before the read starts, a watch on the node that removes it once
// the lease is not renewed, and renewals for as long as the read lasts.
func TestReadOnlyWorkspaceHasALeaseAWatchAndRenewals(t *testing.T) {
	interval, warnAfter := workerLeaseRenewInterval, leaseWarnAfter
	workerLeaseRenewInterval, leaseWarnAfter = 2*time.Millisecond, time.Hour
	defer func() { workerLeaseRenewInterval, leaseWarnAfter = interval, warnAfter }()

	for name, read := range map[string]func(*Executor, RunOptions) error{
		"plan": func(e *Executor, opts RunOptions) error {
			_, err := e.Plan(context.Background(), opts)
			return err
		},
		"discover": func(e *Executor, opts RunOptions) error {
			_, err := e.Discover(context.Background(), opts, initplan.Request{Node: "pve-01"})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			opts := readOptions(t)
			serial := &serialRunner{inner: &fakeCommandRunner{nodePlanOutput: `{"plan_id":"p","node":"pve-01","steps":[]}`}}
			serial.inner.hook = func(_, joined string) ([]byte, error, bool) {
				if strings.Contains(joined, "'node-discover'") {
					return []byte(`{"plan_id":"p","node":"pve-01","steps":[]}`), nil, true
				}
				return nil, nil, false
			}
			runner := &slowRead{serialRunner: serial, delay: 60 * time.Millisecond}
			if err := read(&Executor{runner: runner}, opts); err != nil {
				t.Fatal(err)
			}
			touchesDuringRead := runner.touchesAtTheEndOfTheRead
			serial.mu.Lock()
			defer serial.mu.Unlock()
			leaseAt, watchAt, readAt, removedAt := -1, -1, -1, -1
			var workspace, watch string
			for i, call := range serial.inner.calls {
				joined := strings.Join(call.args, " ")
				switch {
				case strings.Contains(joined, "'/usr/bin/install' '-m' '0600' '/dev/null' '/var/lib/certistack/workers/") && strings.HasSuffix(joined, "/controller.lease'"):
					leaseAt = i
					workspace = strings.TrimSuffix(strings.TrimPrefix(joined[strings.Index(joined, "'/var/lib/certistack/workers/"):], "'"), "/controller.lease'")
				case strings.Contains(joined, "'/usr/bin/systemd-run'"):
					watchAt, watch = i, joined
				case strings.Contains(joined, "'node-plan'") || strings.Contains(joined, "'node-discover'"):
					readAt = i
				case strings.Contains(joined, "'/usr/bin/rm' '-rf' '/var/lib/certistack/workers/"):
					removedAt = i
				}
			}
			if leaseAt < 0 || watchAt < 0 || readAt < 0 || removedAt < 0 || !(leaseAt < watchAt && watchAt < readAt && readAt < removedAt) {
				t.Fatalf("lease at %d, watch at %d, read at %d, removal at %d; want the lease made and watched before the read, and removal after it", leaseAt, watchAt, readAt, removedAt)
			}
			if !strings.Contains(watch, "certistack-read-watch-"+filepath.Base(workspace)) || !strings.Contains(watch, workspace+"/controller.lease") || !strings.Contains(watch, "/usr/bin/rm -rf") {
				t.Errorf("the watch does not name this workspace's unit, lease and removal: %s", watch)
			}
			if strings.Contains(watch, "super-secret") {
				t.Errorf("a secret reached the watch's command line: %s", watch)
			}
			if touchesDuringRead < 2 {
				t.Errorf("%d lease renewals were attempted during the read, want the lease kept renewed for as long as it lasts", touchesDuringRead)
			}
		})
	}
}

// The watch is launched by systemd-run, which substitutes variables in each
// word of the command it starts: the script reaches the shell as written, for
// a state directory with every character the controller accepts in a path,
// whoever runs it. The command is for an exact worker workspace only.
func TestReadLeaseWatchReachesTheShellUnalteredAndOnlyForAWorkspace(t *testing.T) {
	for _, stateDir := range []string{"/var/lib/certistack", "/var/lib/cert$tack", "/var/lib/${x##*/}/%h", "/var/lib/it's"} {
		for _, sudo := range []bool{false, true} {
			workspaceRoot := path.Join(stateDir, "workers")
			workspace := path.Join(workspaceRoot, uuid.NewString())
			lease := path.Join(workspace, "controller.lease")
			command := (&Executor{}).readLeaseWatchCommand(SSHConfig{UseSudo: sudo}, stateDir, workspaceRoot, workspace, lease)
			if command == nil {
				t.Fatalf("no watch command for the state directory %q", stateDir)
			}
			want := readLeaseWatchScript(workspaceShellVariables(lease, path.Join(workspace, "certistack-node"), stateDir, path.Join(workspace, "runtime.env"), path.Join(workspace, "worker-progress.log"), workspace), workerLeaseDurationSeconds, readLeaseWatchTick)
			if got := launchedScript(t, command); got != want {
				t.Errorf("state dir %q (sudo %v): the shell would not receive the watch script as written:\n--- received\n%s\n--- written\n%s", stateDir, sudo, got, want)
			}
			if (command[0] == "/usr/bin/sudo") != sudo {
				t.Errorf("state dir %q: command starts %q with sudo = %v", stateDir, command[:2], sudo)
			}
		}
	}
	root := "/var/lib/certistack/workers"
	for name, args := range map[string][3]string{
		"not a UUID":        {root, root + "/not-a-uuid", root + "/not-a-uuid/controller.lease"},
		"another directory": {root, "/tmp/" + uuid.NewString(), "/tmp/" + uuid.NewString() + "/controller.lease"},
		"a foreign lease":   {root, root + "/" + uuid.NewString(), "/etc/passwd"},
	} {
		if command := (&Executor{}).readLeaseWatchCommand(SSHConfig{}, "/var/lib/certistack", args[0], args[1], args[2]); command != nil {
			t.Errorf("%s: a watch command was built: %q", name, command)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// blockedRemoval answers everything as its runner does, except the removal of
// the node workspace: that waits for its context (a stalled SSH connection),
// or for the test to release it.
type blockedRemoval struct {
	inner   *serialRunner
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockedRemoval) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	if name == "ssh" && strings.Contains(strings.Join(args, " "), "'/usr/bin/rm' '-rf' '/var/lib/certistack/workers/") {
		r.once.Do(func() { close(r.started) })
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-r.release:
			return nil, errors.New("the test released the removal")
		}
	}
	return r.inner.Run(ctx, name, args)
}

func (r *blockedRemoval) RunWithStderr(ctx context.Context, name string, args []string, progress io.Writer) ([]byte, error) {
	return r.inner.RunWithStderr(ctx, name, args, progress)
}

// plan, check and init's discovery offer a second Ctrl-C that abandons their
// cleanup, and readOnNode removed the workspace under a background context of
// its own, which the second signal never reached: the removal went on until its
// own 30 s timeout. The cleanup context a caller gives is the parent of the
// removal, so an abandoned cleanup stops it; the workspace is then the node's
// lease watch's to remove, and the error says so.
func TestAbandonedCleanupStopsTheReadOnlyWorkspaceRemoval(t *testing.T) {
	for name, read := range map[string]func(*Executor, RunOptions) error{
		"plan": func(e *Executor, opts RunOptions) error {
			_, err := e.Plan(context.Background(), opts)
			return err
		},
		"discover": func(e *Executor, opts RunOptions) error {
			_, err := e.Discover(context.Background(), opts, initplan.Request{Node: "pve-01"})
			return err
		},
		"check": func(e *Executor, opts RunOptions) error {
			_, err := e.Check(context.Background(), opts, "")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			opts := readOptions(t)
			cleanup, abandon := context.WithCancel(context.Background())
			defer abandon()
			opts.CleanupContext = cleanup
			serial := &serialRunner{inner: &fakeCommandRunner{nodePlanOutput: `{"plan_id":"p","node":"pve-01","steps":[]}`}}
			runner := &blockedRemoval{inner: serial, started: make(chan struct{}), release: make(chan struct{})}
			t.Cleanup(func() { close(runner.release) })

			done := make(chan error, 1)
			go func() { done <- read(&Executor{runner: runner}, opts) }()
			select {
			case <-runner.started:
			case <-time.After(10 * time.Second):
				t.Fatal("the read never reached the removal of its workspace")
			}
			abandon()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error %v; want the removal stopped by the abandoned cleanup", err)
				}
				for _, want := range []string{"remove temporary node workspace", "removes the temporary workspace", "itself", "nothing to recover manually"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q lacks %q", err, want)
					}
				}
				if strings.Contains(err.Error(), "run certistack recover") {
					t.Errorf("error %q sends the operator to recover a read-only workspace", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("abandoning the cleanup did not stop the removal: it is still waiting on its own timeout")
			}
		})
	}
}

// Before the node's lease watch of the workspace is running nothing there
// removes an abandoned workspace, and the error says that, not that the node
// will.
func TestAbandonedCleanupBeforeTheLeaseWatchRunsSaysNothingRemovesTheWorkspace(t *testing.T) {
	opts := readOptions(t)
	cleanup, abandon := context.WithCancel(context.Background())
	defer abandon()
	opts.CleanupContext = cleanup
	serial := &serialRunner{inner: &fakeCommandRunner{}}
	serial.inner.hook = func(_, joined string) ([]byte, error, bool) {
		if strings.Contains(joined, "'/usr/bin/systemd-run'") {
			return nil, errors.New("systemd-run: connection refused"), true
		}
		return nil, nil, false
	}
	runner := &blockedRemoval{inner: serial, started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(runner.release) })

	done := make(chan error, 1)
	go func() {
		_, err := (&Executor{runner: runner}).Plan(context.Background(), opts)
		done <- err
	}()
	select {
	case <-runner.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the read never reached the removal of its workspace")
	}
	abandon()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "lease watch") || !strings.Contains(err.Error(), "nothing on the node removes it") || strings.Contains(err.Error(), "removes the temporary workspace") {
			t.Fatalf("error %v; want it to say that nothing on the node removes the workspace", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("abandoning the cleanup did not stop the removal")
	}
}

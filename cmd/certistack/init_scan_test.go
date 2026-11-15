// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
)

// paddedValidPlan is the repository's valid plan with a comment block that
// brings the file to size bytes: a plan every loader accepts, however large.
func paddedValidPlan(t *testing.T, path string, size int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var padded bytes.Buffer
	padded.Write(data)
	padded.WriteString("\n")
	line := "# " + strings.Repeat("x", 76) + "\n"
	for padded.Len()+len(line) <= size {
		padded.WriteString(line)
	}
	for padded.Len() < size {
		padded.WriteString("#")
	}
	if padded.Len() != size {
		t.Fatalf("padded to %d bytes, want %d", padded.Len(), size)
	}
	if err := os.WriteFile(path, padded.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The neighbour scan read at most 4 MiB of each plan and skipped a larger
// one in silence, so the sandbox VM IDs and SDN IDs of a valid 5 MiB plan
// beside the output were handed out again. It reads as much as a loader
// accepts, which is what makes a file a plan.
func TestSiblingScanReadsEveryPlanALoaderAccepts(t *testing.T) {
	const wantVMIDs = "[9001 9002 9003]"
	for name, size := range map[string]int{
		"5.28 MB, past the old 4 MiB limit": 5_280_000,
		"exactly the loader's limit":        config.MaxPlanBytes,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "nightly.yaml")
			paddedValidPlan(t, path, size)
			if _, err := config.LoadFromFile(path); err != nil {
				t.Fatalf("the padded plan is not one a loader accepts: %v", err)
			}
			vmids, sdnIDs, unread, err := siblingPlanIDs(context.Background(), filepath.Join(dir, "new.yaml"))
			if err != nil || len(unread) != 0 {
				t.Fatalf("scan: %v, unread %v", err, unread)
			}
			if fmt.Sprint(vmids) != wantVMIDs || fmt.Sprint(sdnIDs) != "[csSb01 csVn01]" {
				t.Fatalf("a valid plan of %d bytes reserved vmids %v, sdn %v; want %s and its zone and VNet", size, vmids, sdnIDs, wantVMIDs)
			}
		})
	}
	// One byte more is no plan any loader would accept, so there is nothing
	// to avoid, and nothing to warn about either.
	dir := t.TempDir()
	paddedValidPlan(t, filepath.Join(dir, "too-big.yaml"), config.MaxPlanBytes+1)
	if vmids, sdnIDs, unread, err := siblingPlanIDs(context.Background(), filepath.Join(dir, "new.yaml")); err != nil || len(vmids)+len(sdnIDs)+len(unread) != 0 {
		t.Fatalf("a file over the plan limit: reserved %v %v, unread %v, err %v", vmids, sdnIDs, unread, err)
	}
}

// A file that may be a plan and cannot be read was skipped in silence, so
// its IDs were handed out again with nothing to say why. It is now named, so
// that init can tell the operator; what cannot be a plan is still skipped
// without a word.
func TestSiblingScanNamesWhatItCouldNotRead(t *testing.T) {
	dir := t.TempDir()
	const plan = "tiers:\n  - vms:\n      - vmid: 9100\n"
	if err := os.WriteFile(filepath.Join(dir, "readable.yaml"), []byte(plan), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "no-such-target.yaml"), filepath.Join(dir, "dangling.yaml")); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	denied := filepath.Join(dir, "denied.yml")
	if err := os.WriteFile(denied, []byte(plan), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatal(err)
	}
	canReadDenied := false
	if f, err := os.Open(denied); err == nil {
		canReadDenied = true
		f.Close()
	}

	// What cannot be a plan, whatever it holds: no warning.
	if err := os.Mkdir(filepath.Join(dir, "a-directory.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"list.yaml": "- just\n- a list\n", "broken.yaml": "tiers: [\n", "notes.txt": plan} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	huge, err := os.Create(filepath.Join(dir, "huge.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := huge.Truncate(config.MaxPlanBytes + 1); err != nil {
		t.Fatal(err)
	}
	huge.Close()

	vmids, _, unread, err := siblingPlanIDs(context.Background(), filepath.Join(dir, "new.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprint(vmids), "9100") {
		t.Errorf("the readable plan reserved %v", vmids)
	}
	want := []string{"dangling.yaml"}
	if !canReadDenied {
		want = append(want, "denied.yml")
	}
	joined := strings.Join(unread, "\n")
	for _, name := range want {
		if !strings.Contains(joined, filepath.Join(dir, name)) {
			t.Errorf("unread %q does not name %s", unread, name)
		}
	}
	for _, name := range []string{"readable.yaml", "a-directory.yaml", "list.yaml", "broken.yaml", "notes.txt", "huge.yaml"} {
		if strings.Contains(joined, name) {
			t.Errorf("unread %q names %s, which is a plan that was read or a file that cannot be one", unread, name)
		}
	}
	if len(unread) != len(want) {
		t.Errorf("unread = %q, want only %v", unread, want)
	}
}

// init tells the operator, before it goes on, which neighbours it could not
// read: the one place the scan's answer reaches a person.
func TestInitSaysWhichNeighbouringPlansItCouldNotRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "gone.yaml"), filepath.Join(dir, "moved-plan.yaml")); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	t.Cleanup(func(previous func(context.Context, initplan.Request, string) (*initplan.Discovery, error)) func() {
		return func() { runnerDiscover = previous }
	}(runnerDiscover))
	var asked initplan.Request
	runnerDiscover = func(_ context.Context, req initplan.Request, _ string) (*initplan.Discovery, error) {
		asked = req
		return nil, errors.New("the node is not reachable in this test")
	}
	root := newRootCmd(nil)
	var stderr bytes.Buffer
	root.SetOut(io.Discard)
	root.SetErr(&stderr)
	root.SetArgs([]string{"init", "--node", "pve1", "--vm", "100", "--output", filepath.Join(dir, "new.yaml")})
	if err := root.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("init: %v", err)
	}
	if !strings.Contains(stderr.String(), "Warning: could not read "+filepath.Join(dir, "moved-plan.yaml")) || !strings.Contains(stderr.String(), "are not avoided") {
		t.Errorf("init did not say which neighbour it could not read:\n%s", stderr.String())
	}
	if asked.Node != "pve1" {
		t.Errorf("discovery was not asked for node pve1: %+v", asked)
	}
}

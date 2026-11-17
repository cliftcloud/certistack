// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
)

// errNotAPlanFile marks a candidate that cannot be a plan, whatever it
// holds: not a regular file, or larger than any loader accepts.
var errNotAPlanFile = errors.New("cannot be a plan")

// siblingPlanIDs are the sandbox VM IDs and SDN IDs of the plans next to
// output, which PVE does not know about between their runs. A file that is
// not a plan is skipped; output itself is left out, as it is replaced. A
// sandbox ID counts under either of its keys, vmid or its alias target_vmid.
//
// The directory is listed by entry name, not with a glob pattern, so a
// directory whose own name holds a glob character ("plans[") still reserves
// its neighbours' IDs. Each candidate is opened without waiting and
// read only if the open descriptor is a regular file, up to the size the plan
// loaders accept, so a FIFO planted beside the output cannot hold init, past
// its interrupts, in a wait for a writer, and a large plan is not
// mistaken for a file that is not one. A file that could be a plan and cannot
// be read is not skipped in silence: it is returned in unread, with why, for
// the caller to tell the operator that its IDs are not avoided. The scan stops
// when ctx does.
func siblingPlanIDs(ctx context.Context, output string) (vmids []int, sdnIDs []string, unread []string, err error) {
	parent := filepath.Dir(output)
	// Windows may report a non-directory parent as not found. Distinguish it
	// before ReadDir so init cannot silently skip conflicting sibling IDs.
	if info, statErr := os.Stat(parent); statErr == nil && !info.IsDir() {
		return nil, nil, nil, fmt.Errorf("the directory of %s is not a directory", output)
	}
	entries, err := os.ReadDir(parent)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, nil // writing the plan says so
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read the directory of %s for the plans beside it, whose sandbox IDs init must avoid: %w", output, err)
	}
	self, _ := filepath.Abs(output)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		if extension := strings.ToLower(filepath.Ext(entry.Name())); extension != ".yaml" && extension != ".yml" {
			continue
		}
		// A directory, FIFO, socket or device is not a plan. A symbolic link
		// is opened to see what it names.
		if entry.Type()&^fs.ModeSymlink != 0 {
			continue
		}
		path := filepath.Join(filepath.Dir(output), entry.Name())
		if abs, _ := filepath.Abs(path); abs == self {
			continue
		}
		data, err := readSiblingPlan(path)
		if errors.Is(err, errNotAPlanFile) {
			continue
		}
		if err != nil {
			unread = append(unread, fmt.Sprintf("%s (%v)", path, err))
			continue
		}
		var plan config.Plan
		if yaml.Unmarshal(data, &plan) != nil {
			continue
		}
		for _, id := range []string{plan.Network.ZoneID, plan.Network.VNetID} {
			if id != "" {
				sdnIDs = append(sdnIDs, id)
			}
		}
		for _, tier := range plan.Tiers {
			for _, vm := range tier.VMs {
				for _, id := range []int{vm.VMID, vm.TargetVMID} {
					if id > 0 {
						vmids = append(vmids, id)
					}
				}
			}
		}
	}
	return vmids, sdnIDs, unread, nil
}

// readSiblingPlan reads a regular file of at most config.MaxPlanBytes,
// without reading more of a larger one than that. What it opens is checked
// as a descriptor, after opening, and never waited for. A file that is not a
// regular file, or is larger than a plan can be, comes back as
// errNotAPlanFile; any other error is a read that failed.
func readSiblingPlan(path string) ([]byte, error) {
	file, err := openWithoutBlocking(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %w", errNotAPlanFile)
	}
	data, err := io.ReadAll(io.LimitReader(file, config.MaxPlanBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > config.MaxPlanBytes {
		return nil, fmt.Errorf("larger than the %d bytes of a plan: %w", config.MaxPlanBytes, errNotAPlanFile)
	}
	return data, nil
}

// checkPlanOutput refuses an output that exists and may not be replaced,
// before init reads anything. A dangling symbolic link exists, and an error
// other than "not there" is an error, not an absence.
func checkPlanOutput(path string, force bool) error {
	if force {
		return nil
	}
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return fmt.Errorf("%s exists; choose another --output, or pass --force to replace it", path)
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("check %s before writing it: %w", path, err)
	}
}

// planPublishHook, when set by a test, runs after the plan is staged and
// before it is published.
var planPublishHook func(path string)

// writePlanFile writes data to path through a temporary file, so a failure
// never leaves half a plan. It replaces an existing file only with force:
// without it the plan is published so that a file created at path after the
// check, by another process, is never replaced.
func writePlanFile(path string, data []byte, force bool) error {
	if err := checkPlanOutput(path, force); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return outputDirectoryError(filepath.Dir(path), err)
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if planPublishHook != nil {
		planPublishHook(path)
	}
	if force {
		if err := os.Rename(tmp.Name(), path); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		return nil
	}
	return publishWithoutReplacing(tmp.Name(), path)
}

// linkStagedPlan and renameStagedPlan are the two ways publishWithoutReplacing
// gives the staged plan its final name without replacing a file there; tests
// replace them to stand for file systems that refuse hard links or cannot
// rename without replacing.
var (
	linkStagedPlan   = os.Link
	renameStagedPlan = renameWithoutReplacing
)

// publishWithoutReplacing gives the staged file its final name only if that
// name is free at the moment it is taken: a hard link fails if the name
// exists, where a rename would replace whatever is there. On a file system
// without hard links it creates the final file exclusively and copies the
// plan into it, removing it again if that fails.
func publishWithoutReplacing(staged, path string) error {
	err := linkStagedPlan(staged, path)
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrExist) {
		return existsAfterCheck(path)
	}
	// No hard links here. Where the system can rename without replacing, the
	// staged file, already complete, takes the final name in one step; a
	// reader never sees half a plan under it.
	switch renameErr := renameStagedPlan(staged, path); {
	case renameErr == nil:
		return nil
	case errors.Is(renameErr, os.ErrExist):
		return existsAfterCheck(path)
	}
	// Only where that is unsupported is the final name created exclusively and
	// filled in place, which a reader can catch before it is complete.
	source, openErr := os.Open(staged)
	if openErr != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer source.Close()
	destination, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(createErr, os.ErrExist) {
		return existsAfterCheck(path)
	}
	if createErr != nil {
		return fmt.Errorf("write %s: %w", path, createErr)
	}
	if _, copyErr := io.Copy(destination, source); copyErr != nil {
		destination.Close()
		os.Remove(path)
		return fmt.Errorf("write %s: %w", path, copyErr)
	}
	if syncErr := destination.Sync(); syncErr != nil {
		destination.Close()
		os.Remove(path)
		return fmt.Errorf("write %s: %w", path, syncErr)
	}
	if closeErr := destination.Close(); closeErr != nil {
		os.Remove(path)
		return fmt.Errorf("write %s: %w", path, closeErr)
	}
	return nil
}

func existsAfterCheck(path string) error {
	return fmt.Errorf("%s appeared while the plan was being written, and CertiStack does not replace it; choose another --output, or pass --force to replace it", path)
}

// finishInit tells the operator what was written and what to do next. The
// plan file is already on disk; if the account of it cannot be written, the
// command fails and says so. Without --inspect, a plan that checks Linux VMs
// on SSH ends with one line on what --inspect does. withEnv is what the plan
// and run commands it prints add to name init's environment file: "" when
// they would use it without --env-file (controllerEnvFile.flag).
func finishInit(w io.Writer, output string, res *initplan.Result, node string, inspected bool, withEnv string) error {
	out := newCheckedOutput(w)
	fmt.Fprintf(out, "Wrote %s: %d VM(s) from node %s's backups.\n", output, res.VMs, node)
	for _, n := range res.Notes {
		fmt.Fprintf(out, "  - %s\n", n)
	}
	step := "Change each probe marked CHANGE to the service that VM provides"
	if inspected {
		step = "Check each probe marked CHANGE: confirm the probes init --inspect wrote, and change the SSH ones to the service that VM provides"
	}
	// The commands are printed as they must be typed: plan and run need the
	// environment file that init was given, unless it is the default.
	fmt.Fprintf(out, "\nNext:\n  1. %s. The plan is valid as it stands (compliance.frameworks is [NONE]: replace it only to name a standard).\n  2. certistack plan %s%s   (shows what a run would do; changes nothing)\n  3. certistack run %s%s\n", step, output, withEnv, output, withEnv)
	if res.InspectHint {
		fmt.Fprintf(out, "  Or run init again with --inspect: it looks inside each Linux VM's newest backup, read-only, and probes the services it finds instead of SSH.\n")
	}
	return out.deliver(nil, "the plan was written to "+output)
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// InspectOptions is where an inspection runs on this node.
type InspectOptions struct {
	NodeName   string
	ScratchDir string
	StateDir   string
	// RunID names the inspection in the recovery journal. A controller
	// derives it from the worker's workspace, as for a run, so it can verify
	// the journal afterwards; empty generates one.
	RunID string
}

// GuestReader reads a guest's services from its mapped disks, in the order
// the guest sees them, without writing to them: guestinspect.Detect over
// guestnet's ImageReader on a node.
type GuestReader func(ctx context.Context, devices []string) (initplan.GuestFindings, error)

// The limits an inspection is held to before each backup is mapped: those
// init writes into a plan's admission_control, checked once with no wait, and
// the memory of the libguestfs appliance that reads the disks (1280 MiB is
// libguestfs's default since 1.48; LIBGUESTFS_MEMSIZE changes it).
const (
	inspectionMaxRAMPercent    = 85.0
	inspectionMaxIOWaitPercent = 12.0
	inspectionApplianceMiB     = 1280
)

// inspectionAdmission is the admission check made before each backup is
// mapped. A variable so that a test does not read this host's load.
var inspectionAdmission = func(ctx context.Context) error {
	check := admission.New(admission.Config{MaxHostRAMPercent: inspectionMaxRAMPercent, MaxHostIOWaitPercent: inspectionMaxIOWaitPercent, DeferRetryIntervalSec: 1, MaxDeferRetries: 0})
	if err := check.CheckWithReservedMemory(ctx, inspectionApplianceMiB); err != nil {
		return fmt.Errorf("the node is busier than an inspection may load it (%s, with %d MiB for the libguestfs appliance): %w", admissionLimits(), inspectionApplianceMiB, err)
	}
	return nil
}

func admissionLimits() string {
	return fmt.Sprintf("RAM %.0f%%, I/O wait %.0f%%", inspectionMaxRAMPercent, inspectionMaxIOWaitPercent)
}

// inspectionBackups is what an inspection needs of PBS: each VM's backed-up
// configuration, for its disks. A variable so that a test needs no PBS.
var inspectionBackups = func(namespace string) (inspectionProfiles, *pbs.Client, error) {
	client, err := newPBSClient(config.Storage{}, namespace)
	if err != nil {
		return nil, nil, err
	}
	return client, client, nil
}

type inspectionProfiles interface {
	LoadVMProfile(ctx context.Context, snapshot, scratchDir string) (pbs.VMProfile, error)
}

// inspectBackups is the orchestrator's InspectBackups; tests replace it to
// see what the runner hands it without mapping anything.
var inspectBackups = func(ctx context.Context, o *orchestrator.Orchestrator, targets []orchestrator.InspectTarget, admit func(context.Context) error, read func(context.Context, orchestrator.InspectTarget, []string) error) ([]orchestrator.InspectOutcome, orchestrator.InspectCleanup, error) {
	return o.InspectBackups(ctx, targets, admit, read)
}

// InspectLocked looks inside the newest backup of each VM req names, on this
// node, while the caller holds the host lock (journal.Lock), as RunLocked
// runs a plan. It maps nothing while the node's journal records anything
// unfinished: that journal is the only record of what a run left, and the
// node's next run, or certistack recover, reconciles it first. It journals
// the inspection as a run journals itself, maps each VM's disks through the
// orchestrator (one VM at a time, read-only, released before the next), and
// has read look for the guest's services. It never fails as a whole: what
// went wrong is in the answer, for each VM.
func InspectLocked(ctx context.Context, req initplan.InspectRequest, opts InspectOptions, read GuestReader) initplan.Inspection {
	var in initplan.Inspection
	if ctx == nil {
		ctx = context.Background()
	}
	if err := initplan.ValidateInspectRequest(req); err != nil {
		in.Refused = err.Error()
		return in
	}
	if opts.RunID == "" {
		opts.RunID = fmt.Sprintf("run-%d", time.Now().UnixNano())
	}
	if !runIDExpr.MatchString(opts.RunID) {
		in.Refused = fmt.Sprintf("invalid run ID %q", opts.RunID)
		return in
	}
	if err := pve.ValidateNodeName(opts.NodeName); err != nil {
		in.Refused = "invalid node: " + err.Error()
		return in
	}
	if opts.StateDir == "" {
		opts.StateDir = "/var/lib/certistack"
	}
	if opts.ScratchDir == "" {
		opts.ScratchDir = sysutil.DefaultScratchDir
	}
	if err := sysutil.EnsurePrivateDirectory(opts.ScratchDir); err != nil {
		in.Refused = fmt.Sprintf("prepare scratch directory %s: %v", opts.ScratchDir, err)
		return in
	}
	if err := requireCleanJournal(filepath.Join(opts.StateDir, "active.json")); err != nil {
		in.Refused = "nothing was mapped: " + err.Error()
		return in
	}
	namespace := req.Namespace
	if namespace == "" {
		namespace = os.Getenv("PBS_NAMESPACE")
	}
	profiles, client, err := inspectionBackups(namespace)
	if err != nil {
		in.Refused = SafeFailureReason(err)
		return in
	}

	// Each VM's disks, from its backup's configuration, before anything is
	// mapped.
	var targets []orchestrator.InspectTarget
	index := map[int]int{}
	for _, target := range req.Targets {
		vm := initplan.InspectedVM{SourceVMID: target.SourceVMID, Snapshot: target.Snapshot}
		drives, why := inspectionDrives(ctx, profiles, target.Snapshot, opts.ScratchDir)
		if why != "" {
			vm.Skipped = why
		} else {
			targets = append(targets, orchestrator.InspectTarget{SourceVMID: target.SourceVMID, Snapshot: target.Snapshot, Drives: drives})
		}
		index[target.SourceVMID] = len(in.VMs)
		in.VMs = append(in.VMs, vm)
	}
	if len(targets) == 0 {
		in.CleanupVerified = true
		return in
	}

	if err := journal.Begin(opts.StateDir, journal.Record{RunID: opts.RunID, Phase: "running", UpdatedAt: time.Now().UTC(), Scratch: opts.ScratchDir}); err != nil {
		in.Refused = "start the recovery journal: " + SafeFailureReason(err)
		return in
	}
	in.Journaled = true
	orch := orchestrator.New(&config.Plan{}, orchestrator.Options{NodeName: opts.NodeName, ScratchDir: opts.ScratchDir, StateDir: opts.StateDir, RunID: opts.RunID}, client, nil)
	outcomes, cleanup, err := inspectBackups(ctx, orch, targets, inspectionAdmission, func(ctx context.Context, target orchestrator.InspectTarget, devices []string) error {
		findings, err := read(ctx, devices)
		in.VMs[index[target.SourceVMID]].GuestFindings = findings
		if err == nil {
			progress.Info("Inspect", "VM %d: %s.", target.SourceVMID, inspectionSummary(findings))
		}
		return err
	})
	for _, outcome := range outcomes {
		vm := &in.VMs[index[outcome.Target.SourceVMID]]
		switch {
		case outcome.Skipped != "":
			vm.Skipped = outcome.Skipped
		case outcome.Err != nil:
			vm.Failed = SafeFailureReason(outcome.Err)
		}
	}
	in.CleanupVerified, in.CleanupErrors = cleanup.Verified, cleanup.Errors
	if err != nil {
		var interrupted *orchestrator.InterruptedError
		if errors.As(err, &interrupted) || errors.Is(err, context.Canceled) {
			in.Interrupted = SafeFailureReason(err)
		} else {
			in.CleanupErrors = append(in.CleanupErrors, SafeFailureReason(err))
			in.CleanupVerified = false
		}
	}
	return in
}

// inspectionDrives are the disks of a VM's backup, read from its backed-up
// configuration into a private directory under scratch, or why it is not
// inspected.
func inspectionDrives(ctx context.Context, profiles inspectionProfiles, snapshot, scratch string) ([]config.SourceDrive, string) {
	dir, err := os.MkdirTemp(scratch, "certistack-inspect-")
	if err != nil {
		return nil, fmt.Sprintf("create a private scratch directory: %v", err)
	}
	defer os.RemoveAll(dir)
	profile, err := profiles.LoadVMProfile(ctx, snapshot, dir)
	if err != nil {
		return nil, "its backup's configuration could not be read: " + SafeFailureReason(err)
	}
	if profile.OSType != "l26" && profile.OSType != "l24" {
		return nil, fmt.Sprintf("its backup says guest OS type %q, and init --inspect reads Linux guests", profile.OSType)
	}
	if len(profile.Drives) == 0 {
		return nil, "its backup holds no disk"
	}
	drives := make([]config.SourceDrive, len(profile.Drives))
	for i, drive := range profile.Drives {
		drives[i] = config.SourceDrive{Slot: drive.Slot, Archive: drive.Archive}
	}
	return drives, ""
}

// inspectionSummary is a line of what a guest's findings say.
func inspectionSummary(findings initplan.GuestFindings) string {
	if len(findings.Services) == 0 {
		return "no service init knows of is enabled"
	}
	units := ""
	for i, service := range findings.Services {
		if i > 0 {
			units += ", "
		}
		units += service.Unit
	}
	return "enabled: " + units
}

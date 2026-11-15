// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/internal/recovery"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/runner"
)

// remotePlan is a controller's plan from a node (controller.Executor.Plan)
// and computeNodePlan this node's own. They are variables so that a test can
// give the command a node's answer, with or without a cleanup error, and see
// what the command hands to the plan.
var (
	remotePlan = func(ctx context.Context, opts controller.RunOptions) ([]byte, error) {
		return controller.NewExecutor().Plan(ctx, opts)
	}
	computeNodePlan = computePlan
	// runnerPlanRun works out the run's own plan on this node, after what a run
	// does before it (planBefore). A test gives computePlan a plan without a PVE.
	runnerPlanRun = runner.PlanRun
)

// planCmdWithCleanupContext is plan; cleanupContext, when set, is cancelled by
// the operator's second interrupt and abandons the removal of the temporary
// worker's workspace on the node.
func planCmdWithCleanupContext(cleanupContext context.Context) *cobra.Command {
	var (
		planPath       string
		envFile        string
		nodeName       string
		scratchDir     string
		stateDir       string
		overlayStorage string
		jsonOutput     bool
		sshHost        string
		sshUser        string
		sshPort        int
		sshIdentity    string
		sshKnownHosts  string
		sshSudo        bool
		unusedOutput   string
	)
	cmd := &cobra.Command{
		Use:   "plan [plan.yaml]",
		Short: "Show, step by step, what a run of the plan would do on this node, without doing it",
		Long: `Works out what "certistack run" would do with the plan on this PVE node,
changing nothing. It lists, in order:
  - what recovery of an earlier interrupted run would clean up first;
  - the checks;
  - every resource the run creates: the SDN sandbox, the probe address, each
    disk's read-only PBS map and its overlay or local copy, and each sandbox
    VM's exact PVE configuration;
  - the probes;
  - what teardown deletes, and the evidence that is kept.
The backups and source VMs are only read. It reads what a run reads before
creating anything, and exits non-zero when a run would refuse the plan.

With an SSH host (--ssh-host or CERTISTACK_SSH_HOST), it runs from the
controller as "run" does: a temporary worker, staged on the node the same
way, works out the plan there and is removed. Without one, it runs on the
node itself, as root, like doctor.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := onePlanPath(args, planPath); err != nil {
				return err
			}
			if envFile != "" {
				restoreEnvironment, err := useCommandEnvironment(envFile, false)
				if err != nil {
					return err
				}
				defer restoreEnvironment()
			}
			if err := applyControllerEnvironmentDefaults(cmd, &nodeName, &scratchDir, &unusedOutput, &stateDir, &sshHost, &sshUser, &sshPort, &sshIdentity, &sshKnownHosts, &sshSudo); err != nil {
				return err
			}
			if !cmd.Flags().Changed("overlay-storage") {
				if value := os.Getenv("CERTISTACK_OVERLAY_STORAGE"); value != "" {
					overlayStorage = value
				}
			}
			// On the node itself (no SSH host), the node name must be the node's
			// own, before anything else is read. Through an SSH host the
			// temporary worker checks it on the node, first thing.
			if sshHost == "" {
				if err := requirePVENodeWithoutSSHHost(envFile); err != nil {
					return err
				}
				if err := verifyNodeIdentity(nodeName); err != nil {
					return err
				}
			}
			if len(args) > 0 {
				planPath = args[0]
			}
			if planPath == "" {
				return errors.New("a plan is required: certistack plan <plan.yaml>")
			}
			// A plan that sets compliance.sign_key_path gets one line saying that
			// the Community Edition does not read it. It goes to standard error, so
			// --json's reader still gets nothing but the plan.
			if note := planSignKeyNote(planPath); note != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "note: "+note)
			}
			var (
				runPlan    *orchestrator.RunPlan
				cleanupErr error
			)
			if sshHost != "" {
				if sshKnownHosts == "" {
					sshKnownHosts = defaultKnownHostsPath()
				}
				noteWorkerStaged()
				output, err := remotePlan(cmd.Context(), controller.RunOptions{
					PlanPath:       planPath,
					NodeName:       nodeName,
					ScratchDir:     scratchDir,
					OverlayStorage: overlayStorage,
					StateDir:       stateDir,
					SSH: controller.SSHConfig{
						Host: sshHost, User: sshUser, Port: sshPort, IdentityFile: sshIdentity,
						KnownHostsFile: sshKnownHosts, UseSudo: sshSudo,
					},
					Writer:         cmd.ErrOrStderr(),
					CleanupContext: cleanupContext,
				})
				if len(output) == 0 {
					return withExitCode(err, exitCodeInfrastructure)
				}
				cleanupErr = err
				runPlan = &orchestrator.RunPlan{}
				if err := json.Unmarshal(output, runPlan); err != nil {
					return withExitCode(fmt.Errorf("read the node's plan: %w", err), exitCodeInfrastructure)
				}
				// The plan is the command's result, and --json's reader gets
				// nothing else of it: a cleanup that did not complete is told
				// in the document, as well as in the command's error.
				if cleanupErr != nil {
					runPlan.Warnings = append(runPlan.Warnings, "the temporary worker's cleanup on the node did not complete: "+strings.ReplaceAll(cleanupErr.Error(), "\n", "; "))
				}
			} else {
				plan, err := config.LoadFromFile(planPath)
				if err != nil {
					return fmt.Errorf("load plan: %w", err)
				}
				if nodeName == "" {
					// This host's PVE name, from PVE's own link as init and doctor
					// read it: a host renamed after install, or named in another
					// case, has a host name that is not its node's.
					if nodeName = localNodeName(); nodeName == "" {
						return errors.New("--node is required: this host's PVE node name could not be read, so say which node to plan for with --node NAME (the short name PVE shows)")
					}
				}
				// The flag or environment value, else the plan's own
				// storage.scratch_dir, else the default, as a run resolves it.
				scratchDir = config.EffectiveScratchDir(scratchDir, plan, sysutil.DefaultScratchDir)
				if runPlan, err = computeNodePlan(cmd, plan, nodeName, scratchDir, stateDir, overlayStorage, ""); err != nil {
					return err
				}
			}
			out := newCheckedOutput(cmd.OutOrStdout())
			if jsonOutput {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				// A document that could not be written fails the command
				// through deliver below, with the plan's own status kept.
				if err := enc.Encode(runPlan); err != nil && out.err == nil {
					return err
				}
			} else {
				writePlan(out, runPlan)
			}
			if cleanupErr != nil {
				return out.deliver(withExitCode(cleanupErr, exitCodeInfrastructure))
			}
			if len(runPlan.Refusals) > 0 {
				return out.deliver(withExitCode(errors.New("a run would refuse this plan"), exitCodeValidationFailed))
			}
			return out.deliver(nil)
		},
	}
	cmd.Flags().StringVarP(&planPath, "plan", "p", "", "path to the plan YAML")
	cmd.Flags().StringVar(&envFile, "env-file", "", "allowlisted controller environment file; values are parsed literally, never shell-sourced")
	cmd.Flags().StringVar(&nodeName, "node", "", "PVE node name (default on the node: this host's short name)")
	cmd.Flags().StringVar(&scratchDir, "scratch", "", "scratch directory a run would use (default: plan storage.scratch_dir, else /var/lib/certistack/scratch)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/certistack", "node state directory, whose journal a run would recover first")
	cmd.Flags().StringVar(&overlayStorage, "overlay-storage", "", "PVE storage for COW overlays, as for run (default: plan storage.overlay_storage)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print the plan as JSON")
	cmd.Flags().StringVar(&sshHost, "ssh-host", "", "PVE node SSH host: plan from the controller, as run does")
	cmd.Flags().StringVar(&sshUser, "ssh-user", "certistack", "SSH service account")
	cmd.Flags().IntVar(&sshPort, "ssh-port", 22, "SSH port")
	cmd.Flags().StringVar(&sshIdentity, "ssh-identity", "", "absolute SSH private-key path")
	cmd.Flags().StringVar(&sshKnownHosts, "ssh-known-hosts", "", "absolute known_hosts path; strict verification is always enabled")
	cmd.Flags().BoolVar(&sshSudo, "ssh-sudo", false, "explicitly permit passwordless sudo for the temporary node worker")
	return cmd
}

// planSignKeyNote is the note validate and plan print for a plan that sets
// compliance.sign_key_path, read from the plan file; "" when the plan does not set
// it, or cannot be read (what is wrong with it is told by the command itself).
func planSignKeyNote(planPath string) string {
	plan, err := config.LoadFromFile(planPath)
	if err != nil {
		return ""
	}
	return config.SignKeyPathNote(plan)
}

// nodePlanCmd is the temporary worker's side of a controller's plan: it
// prints the plan as JSON, and exits zero whenever it produced one.
func nodePlanCmd() *cobra.Command {
	var planPath, nodeName, scratchDir, stateDir, envFile, overlayStorage, sshClient string
	cmd := &cobra.Command{
		Use:    "node-plan",
		Short:  "Work out a run's plan on this node for a controller",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireNodeName("node-plan", nodeName); err != nil {
				return err
			}
			if err := verifyNodeIdentity(nodeName); err != nil {
				return err
			}
			if err := recordSSHClient(sshClient); err != nil {
				return err
			}
			restoreEnvironment, err := useCommandEnvironment(envFile, true)
			if err != nil {
				return err
			}
			defer restoreEnvironment()
			plan, err := config.LoadFromFileForWorker(planPath)
			if err != nil {
				return fmt.Errorf("load node worker plan: %w", err)
			}
			runPlan, err := computeNodePlan(cmd, plan, nodeName, scratchDir, stateDir, overlayStorage, filepath.Dir(envFile))
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(runPlan)
		},
	}
	cmd.Flags().StringVar(&planPath, "plan", "", "protected node-local plan path")
	cmd.Flags().StringVar(&nodeName, "node", "", "PVE node name")
	cmd.Flags().StringVar(&scratchDir, "scratch", sysutil.DefaultScratchDir, "scratch directory a run would use")
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/certistack", "node state directory")
	cmd.Flags().StringVar(&envFile, "env-file", "", "protected node-local controller environment file")
	cmd.Flags().StringVar(&overlayStorage, "overlay-storage", "", "PVE storage for COW overlays")
	addSSHClientFlag(cmd, &sshClient)
	for _, name := range []string{"plan", "node", "env-file"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

// computePlan is a run's plan on this node: what it would do before its
// own work, then orchestrator.Plan. When the plan can't be resolved as a
// run resolves it, that is the refusal the run would give. own is the
// workspace running the plan, which is never counted as retained. A plan
// that was cancelled is the context's error, not a refusal: an interrupted
// command is not a plan a run would refuse.
func computePlan(cmd *cobra.Command, plan *config.Plan, nodeName, scratchDir, stateDir, overlayStorage, own string) (*orchestrator.RunPlan, error) {
	before, recovered, stops := planBeforeChecked(stateDir, own, time.Now())
	runPlan, err := runnerPlanRun(cmd.Context(), plan, runner.Options{
		Recovered:      recovered,
		NodeName:       nodeName,
		ScratchDir:     scratchDir,
		OverlayStorage: overlayStorage,
		StateDir:       stateDir,
	})
	if err != nil {
		if ctxErr := cmd.Context().Err(); ctxErr != nil {
			if errors.Is(err, ctxErr) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: %s", ctxErr, runner.SafeFailureReason(err))
		}
		runPlan = &orchestrator.RunPlan{PlanID: plan.PlanID, Node: nodeName, Mode: "release", Refusals: []string{runner.SafeFailureReason(err)}}
	}
	if len(stops) > 0 {
		// A run recovers first, and stops where it cannot: nothing of its own
		// plan is reached, and what stops it is the first refusal. The run's
		// own refusals stay listed, as for any plan that stops early.
		for i := range runPlan.Steps {
			runPlan.Steps[i].Status = orchestrator.StatusNotReached
		}
		runPlan.Refusals = append(append([]string(nil), stops...), runPlan.Refusals...)
	}
	runPlan.Steps = append(before, runPlan.Steps...)
	return runPlan, nil
}

// planBefore is what a run does on the node before its own work: recover
// the journal of an earlier run that did not finish, and remove the
// credentials of retained worker workspaces. It also returns what that
// recovery deletes, which the run's own checks then find gone.
func planBefore(stateDir, own string, now time.Time) ([]orchestrator.PlanStep, orchestrator.Recovered) {
	steps, recovered, _ := planBeforeChecked(stateDir, own, now)
	return steps, recovered
}

// planBeforeChecked is planBefore with what stops a run before its own work:
// a journal recovery cannot read, and an allocation only an operator can
// settle. Each is a failed step, and a refusal here; the steps that follow
// recovery (removing the credentials of retained workspaces) are not reached.
func planBeforeChecked(stateDir, own string, now time.Time) ([]orchestrator.PlanStep, orchestrator.Recovered, []string) {
	const phase = "before the run"
	var steps []orchestrator.PlanStep
	var recovered orchestrator.Recovered
	var stops []string
	record, err := recovery.Inspect(stateDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		journalPath := filepath.Join(stateDir, "active.json")
		steps = append(steps, orchestrator.PlanStep{Phase: phase, Action: orchestrator.PlanCheck, Kind: "journal", Target: journalPath, Status: orchestrator.StatusFailed, Detail: "unreadable: " + err.Error() + "; a run would refuse to start"})
		stops = append(stops, fmt.Sprintf("the recovery journal %s cannot be read, so a run would refuse to start: recover previous node worker: %v", journalPath, err))
	case record.Phase != "cleaned":
		recoveryStepList, recoveryStops := recoverySteps(phase, record)
		steps = append(steps, recoveryStepList...)
		stops = append(stops, recoveryStops...)
		recovered.RunID = record.RunID
		for _, vm := range record.VMs {
			recovered.VMIDs = append(recovered.VMIDs, vm.VMID)
			if recovered.VMNodes == nil {
				recovered.VMNodes = map[int]string{}
			}
			recovered.VMNodes[vm.VMID] = vm.Node
		}
		// Recovery deletes a zone or VNet only where the journal names the
		// run's marker: one that names none leaves whatever PVE
		// lists, so the run's own availability check finds it there.
		if record.SDNOwner != "" {
			recovered.SDNZoneIDs, recovered.SDNVNetIDs = sdnObjectsOf(record)
			recovered.SDNIDs = append(append(recovered.SDNIDs, recovered.SDNZoneIDs...), recovered.SDNVNetIDs...)
			recovered.SDNOwner = record.SDNOwner
			recovered.SDNLockToken = record.SDNLockToken
		}
	}
	idle, _ := idleRetainedWorkspaces(filepath.Join(stateDir, "workers"), own, now)
	for _, workspace := range idle {
		step := orchestrator.PlanStep{Phase: phase, Action: orchestrator.PlanDelete, Kind: "workspace-credentials", Target: workspace.dir, Detail: "retained workspace idle since " + workspace.last.UTC().Format(time.RFC3339) + "; its logs are kept"}
		if len(stops) > 0 {
			// A run removes them once recovery has left the journal clean.
			step.Status = orchestrator.StatusNotReached
		}
		steps = append(steps, step)
	}
	return steps, recovered, stops
}

// recoverySteps are what recovery removes for an unfinished run's journal,
// and what it cannot settle, which stops a run (the second result).
func recoverySteps(phase string, r *journal.Record) ([]orchestrator.PlanStep, []string) {
	del := func(kind, target, detail string) orchestrator.PlanStep {
		return orchestrator.PlanStep{Phase: phase, Action: orchestrator.PlanDelete, Kind: kind, Target: target, Detail: detail}
	}
	from := fmt.Sprintf("left by run %s (%s)", r.RunID, r.Phase)
	var steps []orchestrator.PlanStep
	var stops []string
	for _, vm := range r.VMs {
		steps = append(steps, del("pve-vm", fmt.Sprintf("VM %d", vm.VMID), from+"; only while it still carries this run's ownership markers"))
	}
	for _, address := range r.HostAddresses {
		// Removing a probe address removes its containment table with it.
		if !address.ContainmentOnly {
			steps = append(steps, del("host-address", address.CIDR, "on "+address.Interface+", "+from))
		}
		steps = append(steps, del("nft-table", "inet "+sysutil.IsolationTableName(address.Interface, address.CIDR), "containment of "+address.CIDR+" on "+address.Interface+", "+from))
	}
	for _, loop := range r.Loops {
		if strings.TrimSpace(loop.Backing) != "" && !recovery.IsPBSMapBacking(loop.Backing) {
			// A run journals only its PBS maps' loops: recovery leaves this one
			// attached if it still backs that file, and a run then stops.
			steps = append(steps, orchestrator.PlanStep{Phase: phase, Action: orchestrator.PlanCheck, Kind: "journal", Target: loop.Device, Status: orchestrator.StatusWarning,
				Detail: from + "; recorded on " + loop.Backing + ", which is not a PBS map file, so recovery leaves it attached if it still backs that file, and a run stops there: check what uses it, and delete its entry in loops of the journal"})
			continue
		}
		steps = append(steps, del("pbs-map", loop.Device, from))
	}
	for _, intent := range r.UnresolvedMapIntents() {
		steps = append(steps, del("pbs-map", intent.Snapshot+"/"+intent.Archive, "begun but never recorded, if it exists; only the run's own map process and what leads to it are stopped or released, anything else that looks like it is reported; "+from))
	}
	for _, file := range r.DeltaFiles {
		if _, identified := r.DeltaIdentity(file); !identified && !recovery.DeltaRemovableByPath(file) {
			// Recovery leaves it, and the journal with it: a run stops there.
			steps = append(steps, orchestrator.PlanStep{Phase: phase, Action: orchestrator.PlanCheck, Kind: "journal", Target: file, Status: orchestrator.StatusFailed,
				Detail: from + "; the journal records no identity for it and it is not named as a disk file CertiStack makes, so recovery leaves it: check it, remove it if it is the run's, and delete its line in delta_files of the journal"})
			stops = append(stops, fmt.Sprintf("recovery would leave %s in place, as nothing shows it is run %s's: a run recovers that journal first and stops there", file, r.RunID))
			continue
		}
		steps = append(steps, del("overlay", file, from))
	}
	for _, file := range r.ScreenshotFiles {
		steps = append(steps, del("screenshot", file, from+"; a diagnostic console image, removed only if it is a plain file of that name in the run's scratch directory"))
	}
	zones, vnets := sdnObjectsOf(r)
	for _, vnet := range vnets {
		if r.SDNOwner == "" {
			steps = append(steps, sdnLeftInPlace(phase, "VNet", vnet, from))
			continue
		}
		steps = append(steps, del("sdn-vnet", vnet, from+"; only while PVE's VNet still carries the run's marker"))
	}
	for _, zone := range zones {
		if r.SDNOwner == "" {
			steps = append(steps, sdnLeftInPlace(phase, "zone", zone, from))
			continue
		}
		steps = append(steps, del("sdn-zone", zone, from+"; not while the run's VNet is left in place"))
	}
	if r.AllocationPending != "" && !r.SDNAllocationPending() {
		if iface, cidr, ok := r.PendingHostAddressAllocation(); ok {
			// Recovery reads the host for what the interrupted run's addition
			// made; what it removes is only what the containment
			// table the run installs first shows to be the run's.
			steps = append(steps, orchestrator.PlanStep{Phase: phase, Action: orchestrator.PlanCheck, Kind: "journal", Target: r.AllocationPending, Detail: fmt.Sprintf("a probe address whose addition was never recorded: recovery reads %s and nft table inet %s, removes them only if that table is there (the run installs it before it adds the address), and leaves an address that has no such table; %s", iface, sysutil.IsolationTableName(iface, cidr), from)})
		} else {
			steps = append(steps, orchestrator.PlanStep{Phase: phase, Action: orchestrator.PlanCheck, Kind: "journal", Target: r.AllocationPending, Status: orchestrator.StatusFailed, Detail: "an unconfirmed allocation: a run would stop for an operator to review it"})
			stops = append(stops, fmt.Sprintf("cannot safely reconcile unconfirmed allocation %q; review the named PVE resource before retrying: a run recovers run %s's journal first and stops there", r.AllocationPending, r.RunID))
		}
	}
	return steps, stops
}

// sdnObjectsOf are the zones and VNets recovery of r looks for in PVE: the
// journal's, and the one whose creation was sent and never confirmed.
func sdnObjectsOf(r *journal.Record) (zones, vnets []string) {
	zones, vnets = append(zones, r.SDNZones...), append(vnets, r.SDNVNets...)
	if id := r.PendingSDNZoneAllocation(); id != "" && !containsFold(zones, id) {
		zones = append(zones, id)
	}
	if id := r.PendingSDNVNetAllocation(); id != "" && !containsFold(vnets, id) {
		vnets = append(vnets, id)
	}
	return zones, vnets
}

func containsFold(ids []string, id string) bool {
	for _, known := range ids {
		if strings.EqualFold(known, id) {
			return true
		}
	}
	return false
}

// sdnLeftInPlace is the step for a zone or VNet of a journal that names no owner
// marker: nothing shows that such an object is the run's, so
// recovery deletes nothing PVE lists of it.
func sdnLeftInPlace(phase, kind, id, from string) orchestrator.PlanStep {
	return orchestrator.PlanStep{Phase: phase, Action: orchestrator.PlanCheck, Kind: "journal", Target: "SDN " + kind + " " + id, Status: orchestrator.StatusWarning,
		Detail: from + "; the journal names no ownership marker, so recovery deletes nothing PVE still lists of it: delete it in PVE (a VNet with its subnets first, then its zone), then " + recoverhint.Recover}
}

var planSymbols = map[string]string{
	orchestrator.PlanCheck:  "✓",
	orchestrator.PlanRead:   "<",
	orchestrator.PlanCreate: "+",
	orchestrator.PlanWrite:  "~",
	orchestrator.PlanStart:  ">",
	orchestrator.PlanRun:    ">",
	orchestrator.PlanDelete: "-",
	orchestrator.PlanKeep:   "=",
}

// writePlan prints a plan for an operator: phase by phase, one line per
// step, then the warnings, the refusals and a summary.
func writePlan(w io.Writer, p *orchestrator.RunPlan) {
	mode := p.Mode
	if mode == "test_skip_integrity" {
		mode = "lab-only test mode"
	}
	fmt.Fprintf(w, "CertiStack plan %q on node %s (%s)\n", p.PlanID, p.Node, mode)
	fmt.Fprintln(w, "Nothing has been changed. This is what a run would do, in order. File names carry the")
	fmt.Fprintln(w, "run's start time and the VM's tags its run ID; both are fixed when the run starts.")
	phase := ""
	counts := map[string]int{}
	for _, step := range p.Steps {
		if step.Phase != phase {
			phase = step.Phase
			fmt.Fprintf(w, "\n%s\n", titleCase(phase))
		}
		symbol := planSymbols[step.Action]
		switch step.Status {
		case orchestrator.StatusFailed:
			symbol = "✗"
		case orchestrator.StatusWarning:
			symbol = "!"
		case orchestrator.StatusNotReached:
			symbol = "·"
		}
		if step.Status != orchestrator.StatusNotReached {
			counts[step.Action]++
		}
		line := fmt.Sprintf("  %s %-7s %-20s %s", symbol, step.Action, step.Kind, step.Target)
		if step.Detail != "" {
			line += "  (" + step.Detail + ")"
		}
		if step.Status == orchestrator.StatusNotReached {
			line += "  [not reached]"
		}
		fmt.Fprintln(w, line)
		if len(step.Params) > 0 {
			keys := make([]string, 0, len(step.Params))
			for key := range step.Params {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				fmt.Fprintf(w, "        %s = %s\n", key, step.Params[key])
			}
		}
	}
	if len(p.Warnings) > 0 {
		fmt.Fprintf(w, "\nWarnings (%d)\n", len(p.Warnings))
		for _, warning := range p.Warnings {
			fmt.Fprintf(w, "  ! %s\n", warning)
		}
	}
	if len(p.Refusals) > 0 {
		fmt.Fprintf(w, "\nA run would refuse this plan (%d): it stops at the first ✗, and steps marked · are not reached\n", len(p.Refusals))
		for _, refusal := range p.Refusals {
			fmt.Fprintf(w, "  ✗ %s\n", refusal)
		}
	}
	fmt.Fprintf(w, "\nSummary: %d to create, %d to change inside the sandbox, %d to delete (at teardown or before the run). Backups are only read and no source VM is changed.\n",
		counts[orchestrator.PlanCreate], counts[orchestrator.PlanWrite], counts[orchestrator.PlanDelete])
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

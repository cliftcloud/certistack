// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/guestnet"
	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/runphase"
	"github.com/cliftcloud/certistack/pkg/sdn"
)

// Plan step actions.
const (
	PlanCheck  = "check"  // read-only verification
	PlanRead   = "read"   // reads the backup; never writes it
	PlanCreate = "create" // a resource the run owns and teardown deletes
	PlanWrite  = "write"  // changes a resource the run created
	PlanStart  = "start"
	PlanRun    = "run"
	PlanDelete = "delete" // at teardown
	PlanKeep   = "keep"   // evidence that outlives the run
)

// Plan step statuses. A step without one is something the run would do.
const (
	StatusOK         = "ok"          // a check that passes
	StatusWarning    = "warning"     // a check that passes with a warning
	StatusFailed     = "failed"      // the run would stop here
	StatusNotReached = "not-reached" // after the run would have stopped
)

// A PlanStep is one thing a run would do, in order.
type PlanStep struct {
	Phase  string `json:"phase"`
	Action string `json:"action"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Detail string `json:"detail,omitempty"`
	Status string `json:"status,omitempty"`
	// Params are a sandbox VM's PVE create parameters, exactly as sent.
	Params map[string]string `json:"params,omitempty"`
}

// RunPlan is what a run of the plan would do on this node, step by step.
// Refusals are everything that would stop it, even past the first;
// warnings are what the run would warn about.
type RunPlan struct {
	PlanID   string     `json:"plan_id"`
	Node     string     `json:"node"`
	Mode     string     `json:"mode"`
	Steps    []PlanStep `json:"steps"`
	Warnings []string   `json:"warnings,omitempty"`
	Refusals []string   `json:"refusals,omitempty"`
	// stopped is set once the whole run would have stopped.
	stopped bool
	// starts counts the sandbox VM starts planned so far.
	starts int
}

// add appends step, marking it not reached after the run would have stopped.
func (p *RunPlan) add(step PlanStep) {
	if p.stopped && step.Action != PlanDelete && step.Action != PlanKeep {
		step.Status = StatusNotReached
	}
	p.Steps = append(p.Steps, step)
}

// check appends a check step: ok, or failed with the refusal it causes. A
// failed global check stops the whole run; otherwise only the caller's
// scope stops. It reports whether the check passed.
func (p *RunPlan) check(step PlanStep, err error, global bool) bool {
	step.Action = PlanCheck
	if err == nil {
		if step.Status == "" {
			step.Status = StatusOK
		}
		p.add(step)
		return true
	}
	p.Refusals = append(p.Refusals, err.Error())
	step.Detail = err.Error()
	if !p.stopped {
		step.Status = StatusFailed
	}
	p.add(step)
	if global {
		p.stopped = true
	}
	return false
}

func (p *RunPlan) warn(format string, args ...any) {
	p.Warnings = append(p.Warnings, fmt.Sprintf(format, args...))
}

// Plan works out what Run would do, without doing any of it. It lists the
// checks, the resources it creates and the files it writes, in order. That
// includes each sandbox VM's exact PVE configuration, the probes, and what
// teardown deletes. It reads only what a run reads before creating
// anything: PVE's VM, SDN and storage status, the node's memory and disks,
// and the resolved plan.
//
// A check that would stop the run is marked failed, and what comes after it
// is marked not reached. A VM's failure stops that VM and the tiers after
// it, as Run does, but not the other VMs of its tier. Planning still
// evaluates every check, so Refusals lists every problem at once. The plan's
// backups must already be resolved, as the runner does before Run.
func (o *Orchestrator) Plan(ctx context.Context) (*RunPlan, error) {
	mode := "release"
	if o.opts.SkipIntegrity {
		mode = "test_skip_integrity"
	}
	p := &RunPlan{PlanID: o.plan.PlanID, Node: o.opts.NodeName, Mode: mode}
	// A node name PVE's paths and a zone's node list cannot carry stops the
	// run before it reads or changes anything.
	if err := pve.ValidateNodeName(o.opts.NodeName); err != nil {
		p.check(PlanStep{Phase: "checks", Kind: "node", Target: o.opts.NodeName}, fmt.Errorf("invalid node: %w", err), true)
		planTeardown(p)
		return p, nil
	}
	// The overlays' names carry the run's start time; this is a sample.
	timestamp := time.Now().UnixNano()

	// A plan that was cancelled is not a plan: its steps would be refusals
	// that cancellation caused, and a lookup it interrupted must not be taken
	// for an unknown answer.
	o.planChecks(ctx, p)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o.planNetwork(ctx, p)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	tiers := append([]config.Tier(nil), o.plan.Tiers...)
	sort.SliceStable(tiers, func(i, j int) bool { return tiers[i].Level < tiers[j].Level })
	for _, tier := range tiers {
		o.beginTierCache(tier)
		stopped := map[int]bool{}
		for _, vmCfg := range tier.VMs {
			if !o.planVM(ctx, p, tier, vmCfg, timestamp) {
				stopped[vmCfg.VMID] = true
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		phase := fmt.Sprintf("tier %d", tier.Level)
		if tier.StartupGracePeriodSec > 0 {
			p.add(PlanStep{Phase: phase, Action: PlanRun, Kind: "wait", Target: fmt.Sprintf("%d s", tier.StartupGracePeriodSec), Detail: "startup grace period before the probes"})
		}
		for _, vmCfg := range tier.VMs {
			for _, pr := range vmCfg.Probes {
				step := PlanStep{Phase: phase, Action: PlanRun, Kind: "probe", Target: fmt.Sprintf("VM %d %s", vmCfg.VMID, pr.Type), Detail: probeDetail(pr)}
				if stopped[vmCfg.VMID] {
					step.Status = StatusNotReached
				}
				p.add(step)
			}
		}
		if tier.SoakTimeSec > 0 {
			p.add(PlanStep{Phase: phase, Action: PlanRun, Kind: "wait", Target: fmt.Sprintf("%d s", tier.SoakTimeSec), Detail: fmt.Sprintf("soak before the next tier: the VMs are watched, and their service probes run again every %d s and when the soak ends (one failed check fails the tier)", soakIntervalSec())})
		}
		// A failed VM keeps the tiers that depend on this one from starting.
		if len(stopped) > 0 {
			p.stopped = true
		}
	}
	planTeardown(p)
	return p, nil
}

// Recovered is what recovery of an unfinished run's journal deletes before
// a run begins.
type Recovered struct {
	VMIDs  []int
	SDNIDs []string
	// RunID is the unfinished run's, and VMNodes the node each of VMIDs was
	// recorded on. Recovery stops and destroys a recorded VM only while it
	// carries this run's ownership markers, so the plan counts the VM as gone
	// only when it does.
	RunID   string
	VMNodes map[int]string
	// SDNZoneIDs, SDNVNetIDs and SDNOwner are the zones and VNets recovery
	// looks for in PVE and the marker it demands of the VNet. A journal that
	// names no marker has none of them: recovery deletes nothing it lists.
	SDNZoneIDs, SDNVNetIDs []string
	SDNOwner               string
	// SDNLockToken is the SDN lock the unfinished run still held, which
	// recovery takes over: a never-applied zone made under it is the run's.
	SDNLockToken string
}

func (r Recovered) hasVM(vmid int) bool {
	for _, id := range r.VMIDs {
		if id == vmid {
			return true
		}
	}
	return false
}

func (r Recovered) hasSDN(id string) bool {
	for _, known := range r.SDNIDs {
		if strings.EqualFold(known, id) {
			return true
		}
	}
	return false
}

// planChecks are Run's checks before it creates anything.
func (o *Orchestrator) planChecks(ctx context.Context, p *RunPlan) {
	const phase = "checks"
	o.planSandboxChecks(ctx, p)
	if enabled, err := o.networkRecoveryEnabled(); err != nil {
		p.check(PlanStep{Phase: phase, Kind: "guest-network-tools", Target: "network recovery"}, fmt.Errorf("guest network recovery: %w", err), true)
	} else if enabled {
		p.check(PlanStep{Phase: phase, Kind: "guest-network-tools", Target: "guestfish", Detail: "offline guest network recovery is available"}, guestnet.CheckDependency(ctx), true)
	}
	if storage := o.opts.OverlayStorage; storage != "" {
		step := PlanStep{Phase: phase, Kind: "overlay-storage", Target: storage, Detail: fmt.Sprintf("file-based, on node %s, with at least %d GiB free", o.opts.NodeName, minOverlayStorageFreeBytes>>30)}
		warning, err := o.checkOverlayStorage(ctx)
		if err != nil {
			err = fmt.Errorf("validate overlay storage: %w", err)
		} else {
			// The run warns when it creates the first overlay; the plan
			// warns here, from the storage's directory.
			warnings := []string{warning}
			if dir, dirErr := o.localOverlayStorageDir(ctx, storage); dirErr == nil {
				diskWarning, diskErr := o.overlayClusterDiskWarning(ctx, dir)
				if diskErr != nil {
					return // the context ended: Plan returns its error
				}
				warnings = append(warnings, diskWarning)
			}
			for _, w := range warnings {
				if w != "" {
					step.Status, step.Detail = StatusWarning, step.Detail+"; "+w
					p.warn("%s", w)
				}
			}
		}
		p.check(step, err, true)
	}
	p.check(PlanStep{Phase: phase, Kind: "probe-targets", Target: "wire probes", Detail: "no target is one of the node's own addresses"}, o.checkWireProbeTargetsNotLocal(), true)
	p.check(PlanStep{Phase: phase, Kind: "vm-identities", Target: "NICs and probe targets", Detail: "no two NICs share a MAC address and no two VMs share a wire-probe target"}, o.checkResolvedInputs(), true)
	o.planMachines(ctx, p)
	o.planPrivileges(ctx, p)
	reserved, vms, _, err := admission.RecoveryMemoryReservation(o.plan)
	if err != nil {
		p.check(PlanStep{Phase: phase, Kind: "admission", Target: "memory reservation"}, fmt.Errorf("calculate recovery memory reservation: %w", err), true)
		return
	}
	step := PlanStep{Phase: phase, Kind: "admission", Target: fmt.Sprintf("%d MiB for %d VM(s)", reserved, vms), Detail: "host memory and I/O wait within the plan's limits after reserving the sandbox VMs' memory"}
	if o.admission != nil {
		if err := o.admission.CheckWithReservedMemory(ctx, reserved); errors.Is(err, admission.ErrNeverAdmissible) {
			p.check(step, err, true)
			return
		} else if err != nil {
			step.Status, step.Detail = StatusWarning, "not admitted now; the run would wait and retry: "+err.Error()
			p.warn("Admission would defer the run and retry: %v", err)
		}
	}
	p.check(step, nil, true)
}

// planSandboxChecks lists the checks of the sandbox range against the node: the
// first thing a run does, because a range that holds the PVE API or the PBS
// server, or that overlaps a real network of the node, takes it over once the
// probe address is on the sandbox bridge. A check that could not be made is a
// warning, never a pass.
func (o *Orchestrator) planSandboxChecks(ctx context.Context, p *RunPlan) {
	const phase = "checks"
	checks := o.opts.Sandbox
	if checks == nil {
		return
	}
	target := o.plan.Network.IPRange
	if target == "" {
		target = o.plan.Network.SubnetCIDR
	}
	if checks.Range != nil {
		p.check(PlanStep{Phase: phase, Kind: "sandbox-range", Target: target, Detail: "holds neither the PVE API nor the PBS server"}, checks.Range(ctx), true)
	}
	if checks.Network != nil {
		step := PlanStep{Phase: phase, Kind: "sandbox-network", Target: target, Detail: "overlaps none of the node's real networks, and holds neither a gateway of its routes nor an address of the node"}
		warning, err := checks.Network(ctx)
		if err == nil && warning != "" {
			step.Status, step.Detail = StatusWarning, warning
			p.warn("%s", warning)
		}
		p.check(step, err, true)
	}
}

// planMachines is Run's machine-version check, shown only when a VM pins a
// versioned machine (otherwise the run has nothing to compare and reads no
// machine list).
func (o *Orchestrator) planMachines(ctx context.Context, p *RunPlan) {
	if len(o.pinnedMachines()) == 0 {
		return
	}
	step := PlanStep{Phase: "checks", Kind: "machine-versions", Target: "backup machine types", Detail: fmt.Sprintf("every versioned machine a backup pins is one node %s's QEMU offers", o.opts.NodeName)}
	warning, err := o.checkNodeMachines(ctx)
	if warning != "" {
		step.Status, step.Detail = StatusWarning, step.Detail+"; "+warning
		p.warn("%s", warning)
	}
	p.check(step, err, true)
}

// planPrivileges checks the token's privileges on every path the run
// touches, so all the missing ones show at once rather than one at a time
// as the run meets them.
func (o *Orchestrator) planPrivileges(ctx context.Context, p *RunPlan) {
	step := PlanStep{Phase: "checks", Kind: "token-privileges", Target: "PVE token", Detail: "holds the documented CertiStackRole on every VM, SDN and storage path the run uses"}
	missing, err := o.pveClient.MissingPrivileges(ctx, o.runPrivileges())
	if err != nil {
		step.Status, step.Detail = StatusWarning, "could not read the token's privileges: "+err.Error()
		p.warn("%s", step.Detail)
		p.check(step, nil, true)
		return
	}
	required, advisory := pve.DescribeMissingPrivileges(missing)
	if advisory != "" {
		step.Status, step.Detail = StatusWarning, "lacks (the run works around these): "+advisory
		p.warn("The PVE token lacks %s", advisory)
	}
	if required != "" {
		p.check(step, fmt.Errorf("the PVE token lacks %s", required), true)
		return
	}
	p.check(step, nil, true)
}

// runPrivileges are the privileges this run needs, per path.
func (o *Orchestrator) runPrivileges() []pve.PrivilegeRequirement {
	var vmids []int
	for _, tier := range o.plan.Tiers {
		for _, vm := range tier.VMs {
			vmids = append(vmids, vm.VMID)
		}
	}
	netCfg := o.plan.Network
	return pve.RunPrivileges(o.opts.NodeName, vmids, netCfg.ZoneID, netCfg.VNetID, netCfg.EffectiveLifecycle() != "preprovisioned", o.opts.OverlayStorage)
}

// planNetwork is setupNetwork's steps.
func (o *Orchestrator) planNetwork(ctx context.Context, p *RunPlan) {
	const phase = "sandbox network"
	netCfg := o.plan.Network
	switch netCfg.EffectiveLifecycle() {
	case "preprovisioned":
		var err error
		if err = o.sdnMgr.ValidatePreprovisionedSandbox(ctx, netCfg); err != nil {
			err = fmt.Errorf("validate preprovisioned sandbox: %w", err)
		} else if err = o.checkSandboxVNetHoldsOnlyTheRun(ctx); err != nil {
			err = fmt.Errorf("validate preprovisioned sandbox: %w", err)
		}
		p.check(PlanStep{Phase: phase, Kind: "sdn-sandbox", Target: netCfg.ZoneID + "/" + netCfg.VNetID, Detail: "pre-provisioned: validated read-only (subnet, no gateway, no SNAT, no other guest attached in PVE's list or on this node's bridge), never changed"}, err, true)
	default:
		detail := "neither exists yet, so the run owns what it creates"
		gone := o.opts.Recovered.hasSDN
		var refusals []*sdn.NotOwnedError
		var refusalNote string
		if o.opts.Recovered.hasSDN(netCfg.ZoneID) || o.opts.Recovered.hasSDN(netCfg.VNetID) {
			detail = "an unfinished run's zone or VNet exists now; recovery deletes it first, so the run owns what it creates"
			// Recovery deletes only what PVE shows is the unfinished run's: a
			// VNet that has another alias (a replacement) stays, and its zone
			// with it, and the run would meet them.
			var refusalErr error
			if refusals, refusalErr = o.recoveryRefusals(ctx); refusalErr != nil || len(refusals) > 0 {
				gone = func(string) bool { return false }
			}
			if refusalErr != nil {
				refusalNote = fmt.Sprintf("; whether the unfinished run's recovery would delete it first could not be read: %v", refusalErr)
			} else if len(refusals) > 0 {
				refusalNote = fmt.Sprintf("; the unfinished run's recovery would not delete it first: %v", refusals[0])
			}
		}
		var err error
		if err = o.sdnMgr.EnsureSandboxAvailableAfter(ctx, netCfg, gone); err != nil {
			err = fmt.Errorf("sandbox ownership check: %w%s", err, refusalNote)
		}
		p.check(PlanStep{Phase: phase, Kind: "sdn-available", Target: netCfg.ZoneID + "/" + netCfg.VNetID, Detail: detail}, err, true)
		// Applying SDN is cluster-wide, so a run applies under PVE's SDN lock,
		// which PVE refuses while changes are pending. Read-only here: the
		// zones, VNets and controllers with unapplied changes.
		lock := PlanStep{Phase: phase, Action: PlanRun, Kind: "sdn-lock", Target: "cluster SDN", Detail: "takes PVE's SDN lock for the zone, VNet and subnet and their apply, so the apply applies nothing else (PVE 8 has no SDN lock: the run then reads the cluster's pending SDN changes itself)"}
		if pending, pendingErr := o.sdnMgr.PendingChanges(ctx); pendingErr != nil {
			lock.Status, lock.Detail = StatusWarning, lock.Detail+"; could not read the cluster's pending SDN changes: "+pendingErr.Error()
			p.warn("%s", lock.Detail)
		} else if len(pending) > 0 {
			p.check(lock, fmt.Errorf("%w (%s): a run would be refused. "+sdn.PendingChangesAdvice, sdn.ErrPendingSDNChanges, strings.Join(pending, ", ")), true)
			return
		}
		p.add(lock)
		zone := netCfg.Mode + " zone"
		if netCfg.Mode == "vxlan" {
			peers, _ := netCfg.VXLANPeerAddresses()
			zone += ", peers " + strings.Join(peers, ",")
		} else if o.opts.NodeName != "" {
			zone += ", on node " + o.opts.NodeName + " only"
		}
		p.add(PlanStep{Phase: phase, Action: PlanCreate, Kind: "sdn-zone", Target: netCfg.ZoneID, Detail: zone})
		vnet := "on zone " + netCfg.ZoneID
		if tag := sdn.VNetTag(netCfg); tag > 0 {
			vnet += fmt.Sprintf(", tag %d", tag)
		}
		p.add(PlanStep{Phase: phase, Action: PlanCreate, Kind: "sdn-vnet", Target: netCfg.VNetID, Detail: vnet})
		p.add(PlanStep{Phase: phase, Action: PlanCreate, Kind: "sdn-subnet", Target: netCfg.IPRange, Detail: "on VNet " + netCfg.VNetID + "; no gateway, no SNAT"})
		reload := PlanStep{Phase: phase, Action: PlanRun, Kind: "sdn-reload", Target: "cluster SDN", Detail: "applies the new zone and VNet, then waits for this node's network reload to bring up the VNet's bridge"}
		// Every run applies SDN at its start and again at its end, and PVE's
		// apply makes each node of a cluster reload its network. A standalone
		// node reloads only itself, and a pre-provisioned sandbox is never applied.
		if nodes, ok := o.clusterNodes(ctx); ok && nodes > 1 && !p.stopped {
			note := fmt.Sprintf("This node is in a cluster of %d nodes: every run applies SDN twice, at its start and at its end, and PVE reloads the network on all %d nodes each time. network.lifecycle: preprovisioned avoids it (docs/plan-reference.md, \"Use a pre-provisioned sandbox\").", nodes, nodes)
			reload.Status, reload.Detail = StatusWarning, reload.Detail+"; "+note
			p.warn("%s", note)
		}
		p.add(reload)
		p.add(PlanStep{Phase: phase, Action: PlanRun, Kind: "bridge-forwarding", Target: netCfg.VNetID, Detail: "turns IPv4 and IPv6 forwarding off on the run's own bridge (PVE's ifupdown2 turns it on for every SDN bridge)"})
	}
	probeCIDR, err := netCfg.ProbeAddressCIDR()
	if err != nil {
		p.check(PlanStep{Phase: phase, Kind: "probe-address", Target: netCfg.ProbeIP}, fmt.Errorf("derive isolated host probe address: %w", err), true)
		return
	}
	p.add(PlanStep{Phase: phase, Action: PlanCreate, Kind: "host-address", Target: probeCIDR, Detail: "on the node's " + netCfg.VNetID + " interface, the source of the wire probes"})
	p.add(PlanStep{Phase: phase, Action: PlanCreate, Kind: "nft-table", Target: "inet " + sysutil.IsolationTableName(netCfg.VNetID, probeCIDR), Detail: "confines the probe address to the sandbox: no input from it and no forwarding through the node"})
}

// recoveryRefusals are the zone and VNet of the unfinished run's journal that
// recovery would leave in PVE because nothing shows they are the run's: what
// the plan's "recovery deletes it first" would otherwise promise falsely.
func (o *Orchestrator) recoveryRefusals(ctx context.Context) ([]*sdn.NotOwnedError, error) {
	recovered := o.opts.Recovered
	manager := sdn.NewManager(o.pveClient)
	manager.SetOwnerMarker(recovered.SDNOwner)
	if recovered.SDNLockToken != "" {
		manager.AdoptLock(recovered.SDNLockToken)
	}
	return manager.RecoveryRefusals(ctx, recovered.SDNZoneIDs, recovered.SDNVNetIDs)
}

// recordedVMOutcome is the VMID check for an ID that the unfinished run's
// journal records and PVE has a VM at now. Recovery stops and destroys a
// recorded VM only while its markers, read at that moment, say it is the
// unfinished run's (internal/recovery recordedVMOwnedNow): a VM at a reused ID,
// or one whose markers were removed, is left alone, and the run then meets it.
// The ID counts as freed by recovery on that evidence alone; otherwise the
// error says why recovery will not free it (or cannot be shown to).
func (o *Orchestrator) recordedVMOutcome(ctx context.Context, vmid int) (string, error) {
	recovered := o.opts.Recovered
	node := recovered.VMNodes[vmid]
	if recovered.RunID == "" || node == "" {
		return "", fmt.Errorf("VM %d already exists in the PVE cluster, and the unfinished run's journal does not name both the run and the node of its VM, so whether recovery would destroy it cannot be established", vmid)
	}
	owned, err := o.pveClient.IsCertiStackRunOwned(ctx, node, vmid, recovered.RunID)
	switch {
	case err == nil && owned:
		return "an unfinished run's sandbox VM has it now; recovery destroys that VM first", nil
	case err == nil:
		return "", fmt.Errorf("VM %d already exists in the PVE cluster and does not carry the unfinished run's (%s) ownership markers (a VM that reuses the ID, or one whose markers were removed): recovery refuses to destroy it and leaves it alone, so a run would stop here", vmid, recovered.RunID)
	case o.pveClient.VMNotFound(ctx, err, node, vmid):
		return "", fmt.Errorf("VM %d already exists in the PVE cluster, but not on node %s, where the unfinished run recorded its VM: recovery finds nothing there to destroy, so a run would stop here", vmid, node)
	default:
		return "", fmt.Errorf("VM %d already exists in the PVE cluster, and whether it carries the unfinished run's (%s) ownership markers could not be read (%v), so whether recovery would destroy it cannot be established", vmid, recovered.RunID, err)
	}
}

// vmPlan adds one VM's steps: after a failed check, the rest of the VM is
// not reached, as bootAndVerifyVM returns.
type vmPlan struct {
	p       *RunPlan
	phase   string
	stopped bool
}

func (v *vmPlan) add(step PlanStep) {
	step.Phase = v.phase
	if v.stopped && step.Status == "" {
		step.Status = StatusNotReached
	}
	v.p.add(step)
}

func (v *vmPlan) check(step PlanStep, err error) {
	step.Phase = v.phase
	if v.stopped && err == nil {
		step.Action, step.Status = PlanCheck, StatusNotReached
		v.p.add(step)
		return
	}
	if !v.p.check(step, err, false) {
		v.stopped = true
	}
}

// planVM is bootAndVerifyVM's steps for one VM, in its order. It reports
// whether the VM would get as far as starting.
func (o *Orchestrator) planVM(ctx context.Context, p *RunPlan, tier config.Tier, vmCfg config.VM, timestamp int64) bool {
	v := &vmPlan{p: p, phase: fmt.Sprintf("VM %d (%s)", vmCfg.VMID, vmCfg.Name)}
	target := fmt.Sprintf("VM %d", vmCfg.VMID)

	// 0: the VMID guard.
	var err error
	detail := "unused in the cluster"
	if inUse, lookupErr := o.pveClient.IsVMIDInUse(ctx, vmCfg.VMID); lookupErr != nil {
		err = fmt.Errorf("VM %d: cannot establish whether the VMID is in use: %w", vmCfg.VMID, lookupErr)
	} else if inUse && o.opts.Recovered.hasVM(vmCfg.VMID) {
		// Recovery destroys the unfinished run's sandbox before this run
		// creates its own, if it is the unfinished run's.
		detail, err = o.recordedVMOutcome(ctx, vmCfg.VMID)
	} else if inUse {
		err = fmt.Errorf("VM %d already exists in the PVE cluster", vmCfg.VMID)
	}
	v.check(PlanStep{Kind: "vmid-free", Target: target, Detail: detail}, err)

	source := vmCfg.SourcePBS.Snapshot
	var props []string
	if vmCfg.SourceCryptMode != "" {
		props = append(props, "crypt "+vmCfg.SourceCryptMode)
	}
	if vmCfg.SourceConsistency != "" {
		props = append(props, vmCfg.SourceConsistency)
	}
	v.add(PlanStep{Action: PlanRead, Kind: "pbs-snapshot", Target: source, Detail: strings.Join(props, ", ")})
	if vmCfg.SourceConsistency == pbs.ConsistencyCrash {
		p.warn("VM %d's backup is crash-consistent: %s", vmCfg.VMID, vmCfg.SourceConsistencyDetail)
	}
	if vmCfg.RequireQuiescedBackup {
		err = nil
		if reason := pbs.QuiescedRequirementUnmet(vmCfg.SourceConsistency, vmCfg.SourceConsistencyDetail); reason != "" {
			err = fmt.Errorf("VM %d: %s", vmCfg.VMID, reason)
		}
		v.check(PlanStep{Kind: "backup-consistency", Target: target, Detail: "quiesced or powered-off, as require_quiesced_backup asks"}, err)
	}
	if len(vmCfg.OmittedDisks) > 0 {
		p.warn("VM %d restores only some of its disks: the plan leaves out %s", vmCfg.VMID, strings.Join(vmCfg.OmittedDisks, ", "))
	}

	drives := vmCfg.SourcePBS.RestoreDrives()
	bootSlot, err := bootSlotFor(vmCfg, drives)
	if err != nil {
		v.check(PlanStep{Kind: "boot-disk", Target: target}, fmt.Errorf("VM %d: %w", vmCfg.VMID, err))
	}

	// A/B: each disk's map and overlay.
	pveDisks := make([]pve.DiskOverlay, 0, len(drives))
	vmBytes := int64(0)
	for i, drive := range drives {
		v.add(PlanStep{Action: PlanRead, Kind: "pbs-map", Target: source + "/" + drive.Archive, Detail: "mapped read-only to a loop device for " + drive.Slot})
		name := overlayFileName(vmCfg.VMID, drive.Slot, timestamp, i)
		overlay := pve.DiskOverlay{Slot: drive.Slot, Path: filepath.Join(o.opts.ScratchDir, name)}
		if o.opts.OverlayStorage != "" {
			overlay.Volume = overlayVolumeID(o.opts.OverlayStorage, vmCfg.VMID, name)
			overlay.Path = overlay.Volume
			if o.overlayVolumePathFn != nil {
				if resolved, err := o.overlayVolumePathFn(ctx, overlay.Volume); err == nil {
					overlay.Path = resolved
				}
			}
		}
		pveDisks = append(pveDisks, overlay)
		v.add(PlanStep{Action: PlanCreate, Kind: "overlay", Target: overlay.Path, Detail: "qcow2 over the map; the guest's writes go here only"})
		if n, ok := sourceDiskLength(vmCfg, drive.Slot); ok && vmBytes >= 0 {
			vmBytes += n
		} else {
			vmBytes = -1
		}
	}

	// Firmware state copies.
	firmwareVolumes := make([]pve.FirmwareVolume, 0, len(vmCfg.FirmwareDisks))
	for index, disk := range vmCfg.FirmwareDisks {
		name := firmwareFileName(vmCfg.VMID, disk.Slot, timestamp, index)
		volume := overlayVolumeID(o.opts.OverlayStorage, vmCfg.VMID, name)
		firmwareVolumes = append(firmwareVolumes, pve.FirmwareVolume{Slot: disk.Slot, Volume: volume, Options: disk.Options})
		v.add(PlanStep{Action: PlanCreate, Kind: "firmware-copy", Target: volume, Detail: disk.Slot + " restored whole from PBS as a disposable copy"})
	}

	// C: guest network recovery inside the disposable overlays of every
	// restored disk: the guest's root need not be on the boot disk.
	if address, configured, err := vmCfg.SandboxAddress(o.plan.Network); err != nil {
		v.check(PlanStep{Kind: "guest-network", Target: target}, fmt.Errorf("VM %d: network recovery: %w", vmCfg.VMID, err))
	} else if configured {
		if overlays, overlayErr := guestNetworkOverlays(pveDisks, bootSlot); overlayErr != nil {
			// With no boot disk the check above has already refused the VM.
			if bootSlot != "" {
				v.check(PlanStep{Kind: "guest-network", Target: target}, fmt.Errorf("VM %d: network recovery: %w", vmCfg.VMID, overlayErr))
			}
		} else {
			v.add(PlanStep{Action: PlanWrite, Kind: "guest-network", Target: guestNetworkTarget(overlays), Detail: fmt.Sprintf("%s recovery: sets the guest's address to %s (no gateway, no DNS); guestfish opens all %d restored disks' overlays together and writes inside them only", vmCfg.NetworkRecovery.EffectiveMode(), address, len(overlays))})
		}
	}

	// C2: copy-before-boot, as chooseCopyBeforeBoot decides it, then the scans.
	copyDisks := false
	if len(pveDisks) > 0 {
		// The run makes the VM's image directory before it decides; the
		// plan measures its nearest existing parent on the same storage.
		copyDir := plannedDir(filepath.Dir(pveDisks[0].Path), o.dirExistsFn)
		in := copyInputs{mode: vmCfg.CopyBeforeBoot, vmBytes: vmBytes, tierScanned: o.tierCache.scanned, tierBytes: o.tierCache.plannedBytes, budgetKnown: o.tierCache.budgetKnown, budget: o.tierCache.budgetBytes, freeBytes: -1,
			copied: o.copiedBytes, capBytes: o.copyCapBytes(), windows: windowsOSType(vmCfg.OSType)}
		if in.mode != config.CopyBeforeBootNever && (in.mode == config.CopyBeforeBootAlways || !o.opts.SkipIntegrity) {
			if o.freeBytesFn != nil {
				if free, err := o.freeBytesFn(copyDir); err == nil {
					// By this VM's decision, the run has written the earlier
					// VMs' copies to the same storage.
					in.freeBytes = max(0, free-o.copiedBytes)
				}
			}
			if o.sharedDisksFn != nil {
				if shared, err := o.sharedDisksFn(ctx, copyDir, sysutil.ClusterStateDir); err != nil {
					if ctx.Err() != nil {
						return false // cancelled: Plan returns the context's error
					}
					in.sharedUnknown = err.Error()
				} else if len(shared) > 0 {
					in.sharedDisk = true
				}
			}
			in.standalone = (in.sharedDisk || in.sharedUnknown != "") && o.standaloneNode(ctx)
			decided, warning, err := decideCopy(in)
			step := PlanStep{Kind: "copy-before-boot", Target: target, Detail: "not needed: the disks stay cached until boot"}
			switch {
			case err != nil:
				err = fmt.Errorf("VM %d: %w", vmCfg.VMID, err)
			case warning != "":
				step.Status, step.Detail = StatusWarning, warning
				p.warn("VM %d: %s", vmCfg.VMID, warning)
			case decided:
				step.Detail = "copies the disks to local storage and boots from them"
			}
			v.check(step, err)
			copyDisks = decided && err == nil
			if copyDisks {
				o.copiedBytes += vmBytes
			}
		}
	}
	for i, drive := range drives {
		size := "the whole disk"
		if n, ok := sourceDiskLength(vmCfg, drive.Slot); ok {
			size = "all " + runphase.FormatSize(n)
		}
		switch {
		case copyDisks:
			copyPath := filepath.Join(filepath.Dir(pveDisks[i].Path), copyFileName(vmCfg.VMID, drive.Slot, timestamp, i))
			v.add(PlanStep{Action: PlanRead, Kind: "integrity-scan", Target: drive.Slot, Detail: "reads " + size + " once (SHA-256) and copies it"})
			v.add(PlanStep{Action: PlanCreate, Kind: "copy", Target: copyPath, Detail: "sparse local copy of " + drive.Slot + "; the sandbox boots from it, as a restore does"})
			v.add(PlanStep{Action: PlanWrite, Kind: "overlay", Target: pveDisks[i].Path, Detail: "re-pointed at its copy (qemu-img rebase -u)"})
		case o.opts.SkipIntegrity:
			v.add(PlanStep{Action: PlanRead, Kind: "integrity-scan", Target: drive.Slot, Detail: "skipped (lab-only test mode)"})
		default:
			v.add(PlanStep{Action: PlanRead, Kind: "integrity-scan", Target: drive.Slot, Detail: "reads " + size + " once (SHA-256), filling the page cache the boot reads"})
		}
	}
	if !copyDisks && !o.opts.SkipIntegrity && vmBytes > 0 && !v.stopped {
		if msg := o.noteScannedDisks(vmCfg.VMID, vmBytes); msg != "" {
			p.warn("%s", msg)
		}
	}

	// D: the sandbox VM, exactly as CreateVM sends it, and its start.
	cfg := o.sandboxVMConfig(vmCfg, pveDisks, bootSlot, firmwareVolumes)
	o.pinWindowsMachine(ctx, vmCfg, &cfg)
	params, err := cfg.CreateParams()
	if err != nil {
		v.check(PlanStep{Kind: "pve-vm-config", Target: target}, fmt.Errorf("VM %d: sandbox VM configuration: %w", vmCfg.VMID, err))
	}
	step := PlanStep{Action: PlanCreate, Kind: "pve-vm", Target: target, Detail: vmCfg.Name + " on node " + o.opts.NodeName}
	if params != nil {
		step.Params = make(map[string]string, len(params))
		for key, value := range params {
			step.Params[key] = fmt.Sprint(value)
		}
	}
	v.add(step)
	timeout := tier.BootTimeoutSec
	if timeout <= 0 {
		timeout = int(bootTimeoutDuration(0) / time.Second)
	}
	if limit := o.plan.AdmissionControl.MaxConcurrentBoots; limit > 0 && p.starts >= limit {
		settle := o.plan.AdmissionControl.BootSettle()
		v.add(PlanStep{Action: PlanRun, Kind: "wait", Target: "boot slot", Detail: fmt.Sprintf("may hold the start, up to %s, until fewer than %d sandbox VMs started in the last %s (admission_control.max_concurrent_boots)", settle, limit, settle)})
	}
	v.add(PlanStep{Action: PlanStart, Kind: "pve-vm", Target: target, Detail: fmt.Sprintf("waits up to %d s for QEMU to run", timeout)})
	if !v.stopped && !p.stopped {
		p.starts++
	}
	return !v.stopped && !p.stopped
}

func probeDetail(pr config.Probe) string {
	var parts []string
	if pr.TargetIP != "" {
		target := pr.TargetIP
		if pr.Port > 0 {
			target = hostPort(pr.TargetIP, pr.Port)
		}
		parts = append(parts, target)
	}
	if pr.Command != "" {
		parts = append(parts, "runs "+pr.Command)
	}
	if pr.Description != "" {
		parts = append(parts, pr.Description)
	}
	if pr.TimeoutSec > 0 {
		parts = append(parts, fmt.Sprintf("within %d s", pr.TimeoutSec))
	}
	switch strings.ToLower(pr.Type) {
	case "qmp", "qmp_status", "screendump":
		parts = append(parts, "supporting evidence only: it does not verify the guest")
	case "qga", "qga_ping":
		if !pr.RequireQGA {
			parts = append(parts, "skipped, and not evidence, if the guest agent does not answer")
		}
	}
	return strings.Join(parts, "; ")
}

// planTeardown undoes, in reverse, what the run would have created before
// it finished or stopped, as its LIFO cleanup does, and lists the evidence
// that stays.
func planTeardown(p *RunPlan) {
	const phase = "teardown"
	reload, locked := false, false
	reached := append([]PlanStep(nil), p.Steps...)
	for i := len(reached) - 1; i >= 0; i-- {
		step := reached[i]
		if step.Status == StatusNotReached {
			continue
		}
		switch {
		case step.Action == PlanCreate:
			detail := ""
			switch step.Kind {
			case "pve-vm":
				detail = "stopped and destroyed, after checking its CertiStack ownership markers"
			case "sdn-zone", "sdn-vnet":
				reload = true
				if !locked {
					// As for the creates: the removals and their apply are this
					// run's alone.
					p.Steps = append(p.Steps, PlanStep{Phase: phase, Action: PlanRun, Kind: "sdn-lock", Target: "cluster SDN", Detail: "takes PVE's SDN lock again for the removals and their apply; if the cluster's SDN has changes pending by then, nothing is deleted: the zone and VNet stay in place, the run does not report clean, and " + recoverhint.Recovery + " removes them once the pending changes are settled (PVE 8 has no SDN lock: the run then reads the pending changes itself, and makes no removal over one that is not its own)"})
					locked = true
				}
			case "sdn-subnet":
				continue // removed with its VNet
			}
			p.Steps = append(p.Steps, PlanStep{Phase: phase, Action: PlanDelete, Kind: step.Kind, Target: step.Target, Detail: detail})
		case step.Action == PlanRead && step.Kind == "pbs-map":
			p.Steps = append(p.Steps, PlanStep{Phase: phase, Action: PlanDelete, Kind: "pbs-map", Target: step.Target, Detail: "unmapped"})
		}
	}
	if reload {
		p.Steps = append(p.Steps, PlanStep{Phase: phase, Action: PlanRun, Kind: "sdn-reload", Target: "cluster SDN", Detail: "applies the removals, then waits for this node's network reload to take the VNet's bridge down"})
	}
	p.Steps = append(p.Steps,
		PlanStep{Phase: phase, Action: PlanKeep, Kind: "report", Target: "JSON report (unsigned in the Community Edition)", Detail: "with each disk's digest, the probes' results and the teardown evidence"},
		PlanStep{Phase: phase, Action: PlanKeep, Kind: "failure-evidence", Target: "on failure only", Detail: "a screenshot and the guest network diagnostic of a failed VM"},
	)
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package orchestrator implements the Directed Acyclic Graph (DAG) dependency resolver,
// multi-tier boot sequencer, and timeout manager for CertiStack disaster recovery plans.
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/guestnet"
	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/internal/qgacommand"
	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/internal/recovery"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/cleanup"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/probe/qga"
	"github.com/cliftcloud/certistack/pkg/probe/qmp"
	"github.com/cliftcloud/certistack/pkg/probe/screendump"
	"github.com/cliftcloud/certistack/pkg/probe/synthetic"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/runphase"
	"github.com/cliftcloud/certistack/pkg/sdn"
)

// Options holds runtime options for orchestrator execution.
type Options struct {
	// Recovered is what recovery of an unfinished run deletes before this
	// run begins. Plan counts it as gone, as the run finds it.
	Recovered  Recovered
	NodeName   string // Proxmox VE hypervisor node name (e.g. "pve1")
	ScratchDir string // Private work directory (guestfs, screendumps; overlays when OverlayStorage is empty)
	// OverlayStorage is the PVE storage that holds COW overlays as VM-owned
	// volumes, attached by volume ID. Required on stock Proxmox VE, which
	// refuses disks outside a storage.
	OverlayStorage string
	DryRun         bool   // If true, validates DAG and stages without actual hypervisor mutations
	RunID          string // Unique DR validation run UUID (default auto-generated)
	StateDir       string // Directory for active.json state journaling (default "/var/lib/certistack")
	QMPSocketDir   string // Optional directory override for QMP sockets (default "/var/run/qemu-server")
	QGASocketDir   string // Optional directory override for QGA sockets (default "/var/run/qemu-server")
	SkipQMP        bool   // If true, skips Stage 1 QMP connection (e.g. in non-QEMU environments)
	// SkipIntegrity is an explicit test-only shortcut that omits the full read
	// and checksum verification of each mapped PBS image. The runner stamps the
	// resulting signed report as non-comprehensive test evidence.
	SkipIntegrity bool
	ChaosTrigger  string // Fault to inject in a chaos build ("panic", "kill-daemon")
	// Sandbox are the checks of the sandbox range against the node that Plan
	// lists first. Nil makes none: a caller that has no node to judge the range
	// against (a test) leaves it out.
	Sandbox *SandboxChecks
}

// SandboxChecks are the checks that keep the sandbox range from taking over
// part of the node's own network. Plan lists each as a check step, and a failed
// one stops the plan there, as it stops a run before anything exists. A nil
// function is not checked.
type SandboxChecks struct {
	// Range refuses a range that holds the PVE API or the PBS server.
	Range func(ctx context.Context) error
	// Network refuses a range that overlaps one of the node's real networks. A
	// warning without an error means the node's networks could not be read,
	// which is not a pass.
	Network func(ctx context.Context) (warning string, err error)
}

// ExecutionResult encapsulates the complete outcome of a test plan run.
type ExecutionResult struct {
	PlanID           string
	StartTime        time.Time
	EndTime          time.Time
	RTO              time.Duration
	AllPassed        bool
	VMRecords        []probe.VMValidationRecord
	PhaseTimings     *attest.PhaseTimings
	TeardownEvidence *attest.TeardownEvidence
	// Admission is the host admission policy and the last check's
	// measurements, once admission was evaluated; nil before.
	Admission       *attest.AdmissionEvidence
	FailureArtifact string
	Error           error
}

// Orchestrator coordinates the end-to-end execution of a declarative DR test plan.
type Orchestrator struct {
	plan               *config.Plan
	opts               Options
	runID              string
	cleanup            *cleanup.Stack
	admission          *admission.Controller
	pbsClient          *pbs.Client
	pveClient          *pve.Client
	sdnMgr             *sdn.Manager
	hostAddresses      hostAddressManager
	record             journal.Record
	networkDiagnostics map[int]string
	// networkDiagnosticRequested records a failed VM that needs the
	// COW-overlay fallback. Successful validations deliberately never read the
	// optional in-guest diagnostic during cleanup.
	networkDiagnosticRequested map[int]bool
	// networkDiagnosticPartial records a live diagnostic without listeners
	// or firewall: the guest agent allows no guest-exec.
	networkDiagnosticPartial map[int]bool

	// SDN cleanup is registered before resources are created so it runs last in
	// LIFO order. These fields make both the callback and its signed evidence
	// reflect only mutations this run actually made.
	sdnReloadRequired bool
	sdnTeardownReload bool
	// sdnTeardownBlocked is why teardown deleted the sandbox's SDN objects
	// without applying the deletion: PVE's SDN lock could not be taken.
	sdnTeardownBlocked error

	// sdnDeleted records that teardown deleted an SDN object, so there is a
	// change to apply.
	sdnDeleted bool
	// sdnZoneAbsent and sdnVNetAbsent record that teardown found PVE without
	// the zone or VNet whose creation was never confirmed: the request had no
	// effect, there was nothing to delete, and no apply is owed for it.
	sdnZoneAbsent, sdnVNetAbsent bool
	// sdnVNetNotOwned records that teardown refused to delete the VNet because
	// it is not provably the run's: its zone is then left as well, since a zone
	// has no marker of its own to tell it from a replacement.
	sdnVNetNotOwned   bool
	sdnPreprovisioned bool
	runQMFallbackFn   func(context.Context, []string) ([]byte, error)

	// vmTeardown holds each sandbox VM whose teardown is registered, and why
	// teardown has not confirmed it destroyed (nil once it has). A VM not
	// confirmed destroyed may still run, so teardown keeps what it uses: its
	// PBS maps, overlays and firmware copies, and the host probe address and
	// containment on the VNet it is attached to.
	vmTeardown map[int]error
	// preDestroy holds, by VM, what must run between the VM's stop and its
	// destroy: see beforeVMDestroy.
	preDestroy map[int]func(vmQuiescence, error)

	// overlayVolumePathFn resolves an overlay volume ID to its node path.
	overlayVolumePathFn func(context.Context, string) (string, error)
	// sharedDisksFn and clusterDiskChecked: see warnOverlaySharesClusterDisk.
	sharedDisksFn      func(context.Context, string, string) ([]string, error)
	clusterDiskChecked bool
	// clusterNodesFn replaces clusterNodes in tests.
	clusterNodesFn func(context.Context) (int, bool)
	// validateOverlayStorageFn replaces PVE's overlay storage check in tests.
	validateOverlayStorageFn func(context.Context) error
	// storageConfigFn and mountPointFn are what the node checks about a
	// storage whose PVE status did not answer: see confirmLocalOverlayStorage.
	storageConfigFn func(string) (localStorage, error)
	mountPointFn    func(string) (bool, error)
	// unmapLeakedMapsFn releases a failed map's loop device, if it made one.
	unmapLeakedMapsFn func([]*journal.MapIntent, map[string]bool, func() error) error
	// bridgePortsFn lists the ports the kernel has attached to a bridge of
	// this node (sysutil.BridgePorts); tests replace it.
	bridgePortsFn func(bridge string) ([]string, error)
	// createdVMs are the sandbox VMs whose creation PVE confirmed to this
	// run: with the journal's record, what makes a port on the sandbox
	// bridge the run's own.
	createdVMs map[int]bool
	// staleLoopDevicesFn lists the stale FUSE loops on the host, and
	// releaseStaleLoopsFn detaches the ones that appeared since a baseline: see
	// beginStaleLoopWatch.
	staleLoopDevicesFn  func() []string
	releaseStaleLoopsFn func(ctx context.Context, before []string, maps int) ([]string, []error)
	// staleLoopBaseline is what staleLoopDevicesFn said before this run's first map.
	staleLoopBaseline      []string
	staleLoopBaselineTaken bool
	// mayStopMapDaemonFn says whether the daemon of a map's loop may be stopped
	// (its pid file names none, or the run's own), stopMapDaemonFn stops it
	// through a pidfd of the process it verified (the note says why none was
	// signalled), and reusedLoopNoteFn what to say of a recorded loop device that
	// backs another file now: see unmapRecordedLoop.
	mayStopMapDaemonFn func(string, journal.MapIntent) (bool, error)
	stopMapDaemonFn    func(string, journal.MapIntent) (string, error)
	reusedLoopNoteFn   func(device, backing string) (string, error)
	// deviceBytesFn and freeBytesFn size a VM's disks and the space for
	// their copies: see chooseCopyBeforeBoot.
	deviceBytesFn func(string) (int64, error)
	freeBytesFn   func(string) (int64, error)
	// cacheMemoryFn and tierCache: see beginTierCache.
	cacheMemoryFn func() (float64, error)
	tierCache     tierCache
	// restoreImageFn restores one PBS image archive to a new file.
	restoreImageFn func(ctx context.Context, snapshot, archive, target string) error
	// verifyImageFn and copyImageFn are pbs.VerifyMappedImageWithProgress and
	// pbs.CopyMappedImageWithProgress when nil; tests replace them to see what
	// a run asks of them (verifyMappedDisk, copyMappedDisk).
	// applyGuestNetworkFn and readNetworkDiagnosticFn are guestnet's Apply and
	// ReadDiagnostics, which need guestfish; tests replace them.
	applyGuestNetworkFn     func(ctx context.Context, cfg guestnet.Config) (guestnet.Result, error)
	readNetworkDiagnosticFn func(ctx context.Context, overlays []string) (string, error)

	verifyImageFn func(ctx context.Context, snapshot, device string, want pbs.DiskSize, progress func(int64)) (*pbs.VerifySummary, string, error)
	copyImageFn   func(ctx context.Context, snapshot, device, fusePath, copyPath string, want pbs.DiskSize, progress func(int64)) (*pbs.VerifySummary, string, error)
	// preparedOverlayDirs are per-VM image directories already checked.
	preparedOverlayDirs map[string]bool
	// boots holds VM starts to admission_control.max_concurrent_boots.
	boots *bootGate
	// copiedBytes is what the run's copies before boot take so far.
	copiedBytes int64
	// dirExistsFn tells plan which directories the run has not made yet.
	dirExistsFn func(string) bool
	// bootVMFn is bootAndVerifyVM when nil; tests replace it to run the tiers'
	// probe and soak stages without restoring a VM.
	bootVMFn func(context.Context, config.VM, int, *attest.PhaseTimings) (*probe.VMValidationRecord, error)
	// phases numbers the run's phases for its progress (announcePhase); phaseFn
	// shows one when set, and scanClock is the clock of the scans' time left.
	// Tests replace them.
	phases    *runphase.Tracker
	phaseFn   func(stage, message string)
	scanClock func() time.Time

	// addrGuard watches the probe address from setupNetwork to teardown (see
	// addrguard.go); addrGuardEvery is its interval, 2 s when zero. cancelRun
	// stops the run when the guard cannot restore the sandbox's containment.
	addrGuard      *addrGuard
	addrGuardEvery time.Duration
	cancelRun      context.CancelCauseFunc
}

type hostAddressManager interface {
	Add(context.Context, string, string) error
	Remove(context.Context, string, string) error
	RemoveContainment(context.Context, string, string) error
	// Identify reads the kernel's identity of the interface and of the
	// containment table just installed for the address; zeros are
	// "could not be read".
	Identify(ctx context.Context, iface, cidr string) (ifindex int, tableHandle uint64, err error)
	// SettleBridge waits for this node's network reload after an SDN
	// apply: the bridge there (present) or gone, and ifupdown2 done.
	SettleBridge(ctx context.Context, bridge string, present bool, timeout time.Duration) error
	// DisableForwarding turns forwarding off on a bridge the run owns.
	DisableForwarding(ctx context.Context, bridge string) error
	// InspectHostAddress, RestoreAddress and RestoreContainment are the
	// address guard's (addrguard.go): a read-only look at the probe address,
	// its containment table and the bridge's forwarding, and the two repairs a
	// network reload on the node makes necessary. Neither repair journals
	// anything; DisableForwarding is the third.
	InspectHostAddress(ctx context.Context, iface, cidr string) (sysutil.HostAddressState, error)
	// HostAddressTaken names what is already on the host where the probe
	// address is about to be installed ("" when nothing is).
	HostAddressTaken(ctx context.Context, iface, cidr string) (string, error)
	RestoreAddress(ctx context.Context, iface, cidr string) error
	RestoreContainment(ctx context.Context, iface, cidr string) error
	// DisableForwardingOf turns off only the named families ("IPv4", "IPv6"):
	// the guard puts back what a reload turned on and nothing else.
	DisableForwardingOf(ctx context.Context, bridge string, families []string) error
}

// bridgeSettleTimeout bounds the wait for this node's network reload after
// an SDN apply, by the cluster's size.
func (o *Orchestrator) bridgeSettleTimeout(ctx context.Context) time.Duration {
	nodes, err := o.pveClient.NodeCount(ctx)
	if err != nil {
		slog.Warn("could not count the cluster's nodes; the network reload wait uses its minimum", "error", err)
	}
	return sysutil.SettleTimeout(nodes)
}

type localHostAddressManager struct{}

const defaultBootTimeout = 60 * time.Second

func bootTimeoutDuration(seconds int) time.Duration {
	if seconds <= 0 {
		return defaultBootTimeout
	}
	return time.Duration(seconds) * time.Second
}

// guestNetworkDiagnosticCommand is the failed-VM diagnostic run through the
// guest agent; the boot-time one in the COW overlay shares its body.
var guestNetworkDiagnosticCommand = guestnet.LiveDiagnosticCommand()

func (localHostAddressManager) Add(ctx context.Context, iface, cidr string) error {
	return sysutil.AddInterfaceAddress(ctx, iface, cidr)
}

func (localHostAddressManager) Remove(ctx context.Context, iface, cidr string) error {
	return sysutil.RemoveInterfaceAddress(ctx, iface, cidr)
}

func (localHostAddressManager) SettleBridge(ctx context.Context, bridge string, present bool, timeout time.Duration) error {
	return sysutil.SettleBridge(ctx, bridge, present, timeout)
}

func (localHostAddressManager) DisableForwarding(_ context.Context, bridge string) error {
	return sysutil.DisableBridgeForwarding(bridge)
}

func (localHostAddressManager) DisableForwardingOf(_ context.Context, bridge string, families []string) error {
	return sysutil.DisableBridgeForwardingOf(bridge, families...)
}

func (localHostAddressManager) RemoveContainment(ctx context.Context, iface, cidr string) error {
	return sysutil.RemoveInterfaceContainment(ctx, iface, cidr)
}

func (localHostAddressManager) Identify(ctx context.Context, iface, cidr string) (int, uint64, error) {
	return sysutil.HostAddressIdentity(ctx, iface, cidr)
}

// New creates a new test plan orchestrator.
func New(plan *config.Plan, opts Options, pbsClient *pbs.Client, pveClient *pve.Client) *Orchestrator {
	if opts.ScratchDir == "" {
		opts.ScratchDir = sysutil.DefaultScratchDir
	}
	if opts.NodeName == "" {
		opts.NodeName = "localhost"
	}
	if opts.StateDir == "" {
		opts.StateDir = "/var/lib/certistack"
	}

	runID := opts.RunID
	if runID == "" {
		runID = fmt.Sprintf("run-%d", time.Now().UnixNano())
	}

	admissCfg := admission.Config{
		MaxHostRAMPercent:     plan.AdmissionControl.MaxHostRAMPercent,
		MaxHostIOWaitPercent:  plan.AdmissionControl.MaxHostIOWaitPercent,
		DeferRetryIntervalSec: plan.AdmissionControl.DeferRetryIntervalSec,
		MaxDeferRetries:       plan.AdmissionControl.MaxDeferRetries,
	}

	rec := journal.Record{
		RunID:     runID,
		Phase:     "initializing",
		UpdatedAt: time.Now().UTC(),
		Scratch:   opts.ScratchDir,
	}

	o := &Orchestrator{
		plan:                       plan,
		opts:                       opts,
		runID:                      runID,
		cleanup:                    cleanup.New(),
		admission:                  admission.New(admissCfg),
		pbsClient:                  pbsClient,
		pveClient:                  pveClient,
		sdnMgr:                     sdn.NewManager(pveClient),
		hostAddresses:              localHostAddressManager{},
		record:                     rec,
		networkDiagnostics:         make(map[int]string),
		networkDiagnosticRequested: make(map[int]bool),
		networkDiagnosticPartial:   make(map[int]bool),
		overlayVolumePathFn:        pvesmVolumePath,
		sharedDisksFn:              sysutil.SharedDisks,
		storageConfigFn:            readStorageConfig,
		mountPointFn:               sysutil.IsMountPoint,
		cacheMemoryFn:              scanCacheMB,
		deviceBytesFn:              sysutil.BlockDeviceBytes,
		freeBytesFn:                sysutil.FilesystemFreeBytes,
		unmapLeakedMapsFn:          recovery.UnmapLeakedMaps,
		bridgePortsFn:              sysutil.BridgePorts,
		staleLoopDevicesFn:         sysutil.StaleFUSELoopDevices,
		releaseStaleLoopsFn:        sysutil.ReleaseStaleFUSELoopsSince,
		mayStopMapDaemonFn:         recovery.MayStopMapDaemon,
		stopMapDaemonFn:            recovery.StopMapDaemon,
		reusedLoopNoteFn:           recovery.ReusedLoopNote,
		preparedOverlayDirs:        make(map[string]bool),
		dirExistsFn:                dirExists,
	}
	if plan != nil {
		o.boots = newBootGate(plan.AdmissionControl)
	}
	if pbsClient != nil {
		o.restoreImageFn = pbsClient.RestoreImage
	}
	return o
}

func (o *Orchestrator) flushJournal() error {
	if o.opts.StateDir == "" {
		return errors.New("recovery journal state directory is required")
	}
	o.record.UpdatedAt = time.Now().UTC()
	path := filepath.Join(o.opts.StateDir, "active.json")
	if err := journal.Write(path, o.record); err != nil {
		return fmt.Errorf("persist recovery journal: %w", err)
	}
	return nil
}

// persistSDNLock journals the state of PVE's SDN lock (sdn.Manager's
// SetPersist): a lock request before it is sent, the token as it arrives
// and goes, and the last apply's task. Recovery then releases or finishes
// what a dead run left, and knows a request whose answer was lost.
func (o *Orchestrator) persistSDNLock(state sdn.LockState) error {
	before := [4]string{o.record.SDNLockToken, o.record.SDNLockRequested, o.record.SDNApplyTask, o.record.SDNApplyUnknown}
	o.record.NoteSDNLock(state.Token, state.Requested, state.ApplyTask, state.ApplyUnknown, time.Now())
	if before == [4]string{o.record.SDNLockToken, o.record.SDNLockRequested, o.record.SDNApplyTask, o.record.SDNApplyUnknown} {
		return nil
	}
	return o.flushJournal()
}

// verifySDNGone asks PVE whether the run's zone and VNet are gone: neither
// configured nor running. Only what the run tracks is asked about ("" is
// untracked): an object of the plan's name that the run never created is not the
// run's to report on. A read that fails is an error, never "gone".
func (o *Orchestrator) verifySDNGone(zone, vnet string) (zoneLeft, vnetLeft bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var zoneIDs, vnetIDs []string
	if zone != "" {
		zoneIDs = []string{zone}
	}
	if vnet != "" {
		vnetIDs = []string{vnet}
	}
	zones, vnets, err := o.sdnMgr.ObjectStates(ctx, zoneIDs, vnetIDs)
	if err != nil {
		return false, false, fmt.Errorf("could not confirm the sandbox's SDN %s are gone: %w", strings.Join(sdnNames(zone, vnet), " and "), err)
	}
	zoneLeft, vnetLeft = zone != "" && zones[zone] != sdn.Absent, vnet != "" && vnets[vnet] != sdn.Absent
	var left []string
	if zoneLeft {
		left = append(left, "zone "+zone)
	}
	if vnetLeft {
		left = append(left, "VNet "+vnet)
	}
	if len(left) > 0 {
		return zoneLeft, vnetLeft, fmt.Errorf("PVE still lists the sandbox's SDN %s (a delete's reply is not proof it is gone)", strings.Join(left, " and "))
	}
	return false, false, nil
}

// sdnNames names the tracked zone and VNet ("" is untracked).
func sdnNames(zone, vnet string) []string {
	var names []string
	if zone != "" {
		names = append(names, "zone "+zone)
	}
	if vnet != "" {
		names = append(names, "VNet "+vnet)
	}
	return names
}

// createUnconfirmed reports whether the creation of the zone or VNet (kind
// "zone" or "VNet") was sent and never confirmed, which teardown then resolves
// from PVE's own lists.
func (o *Orchestrator) createUnconfirmed(kind, id string) bool {
	if id == "" {
		return false
	}
	switch kind {
	case "zone":
		return o.record.PendingSDNZoneAllocation() == id
	default:
		return o.record.PendingSDNVNetAllocation() == id
	}
}

// settleSDNAllocation clears the pending allocation of the zone or VNet whose
// creation was never confirmed. It is called only once verifySDNGone has read
// PVE's lists and found neither object in them: whatever the request did, it
// left nothing. A pending allocation of anything else stays.
func (o *Orchestrator) settleSDNAllocation(zone, vnet string) {
	if o.createUnconfirmed("zone", zone) || o.createUnconfirmed("VNet", vnet) {
		o.record.AllocationPending = ""
	}
}

// deletesBlocked is the error of an SDN delete teardown does not make: PVE's
// lock could not be taken, so nothing is written to SDN at all. A deletion
// made without the lock would mix with whatever an administrator has pending
// or, with no apply coming, block every SDN lock in the cluster: the object
// stays for certistack recover, which deletes and applies it under a lock.
func (o *Orchestrator) deletesBlocked(what string) error {
	if o.sdnTeardownBlocked != nil {
		return fmt.Errorf("%s was left in place: PVE's SDN lock could not be taken, and "+recoverhint.Recovery+" deletes it under a lock", what)
	}
	return nil
}

// noteVNetNotOwned records a VNet deletion refused because the VNet is not
// provably the run's, which keeps the zone deletion from following it.
func (o *Orchestrator) noteVNetNotOwned(err error) {
	var notOwned *sdn.NotOwnedError
	if errors.As(err, &notOwned) {
		o.sdnVNetNotOwned = true
	}
}

// Run executes the full disaster recovery validation workflow.
// Guarantees fail-safe LIFO resource teardown upon completion or error.
//
// Signal cancellation is handled in this goroutine rather than by a
// concurrent cleanup goroutine. That guarantees any interrupted operation
// returns before the LIFO stack unmaps its resources, and that the caller
// waits for every teardown step (including SDN deletion) before exit. A run
// a signal stopped says which, and whether the node was shutting down.
func (o *Orchestrator) Run(ctx context.Context) (*ExecutionResult, error) {
	ctx, stopSignals, interruptedBy := interruptContext(ctx)
	defer stopSignals()
	res, err := o.run(ctx)
	if interrupted := interruptedBy(); interrupted != nil {
		if res != nil {
			res.Error = withInterruption(res.Error, interrupted)
		}
		err = withInterruption(err, interrupted)
	}
	// A run the address guard stopped because the sandbox's containment could
	// not be restored does not read as complete or as merely cancelled.
	if failure := o.isolationFailure(); failure != nil {
		if res != nil {
			res.AllPassed = false
			res.Error = withIsolationFailure(res.Error, failure)
		}
		err = withIsolationFailure(err, failure)
	}
	return res, err
}

func (o *Orchestrator) run(ctx context.Context) (*ExecutionResult, error) {
	// The address guard stops the run through this when it cannot restore the
	// sandbox's containment. It is deferred first so that it runs last, after
	// the teardown, whose steps may hold ctx.
	ctx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)
	o.cancelRun = cancelRun
	defer o.cleanup.Unwind()

	startTime := time.Now()
	timings := &attest.PhaseTimings{}
	var lastSuccessTime time.Time
	o.beginPhases()
	res := &ExecutionResult{
		PlanID:       o.plan.PlanID,
		StartTime:    startTime,
		AllPassed:    true,
		PhaseTimings: timings,
	}
	defer func() {
		finalizeResultTiming(res, timings, startTime, lastSuccessTime)
	}()

	// A node name PVE's paths and a zone's node list cannot carry is refused
	// before the journal, PVE or PBS is touched.
	if err := pve.ValidateNodeName(o.opts.NodeName); err != nil {
		res.AllPassed = false
		res.Error = fmt.Errorf("invalid node: %w", err)
		return res, res.Error
	}

	teardownPerformed := false
	performTeardown := func() {
		if teardownPerformed {
			return
		}
		teardownPerformed = true
		o.announcePhase(runphase.Teardown, 0, "")
		hadCleanupSteps := o.cleanup.Len() > 0
		if hadCleanupSteps {
			progress.Info("Cleanup", "Unwinding LIFO cleanup stack: sandbox VM, volatile overlays, loop mappings, and SDN resources.")
		} else {
			progress.Info("Cleanup", "No CertiStack-owned PVE resources were allocated; recording clean teardown evidence.")
		}
		tTeardown := time.Now()
		cleanupFailures := o.cleanup.Unwind()
		o.recordNetworkDiagnostics(res.VMRecords)
		timings.TeardownSec = time.Since(tTeardown).Seconds()

		evidence := &attest.TeardownEvidence{SDNProvisioning: o.plan.Network.EffectiveLifecycle()}
		if o.sdnPreprovisioned {
			evidence.SDNZoneValidated = o.plan.Network.ZoneID
			evidence.SDNVNetValidated = o.plan.Network.VNetID
		}
		zoneTracked := containsString(o.record.SDNZones, o.plan.Network.ZoneID)
		vnetTracked := containsString(o.record.SDNVNets, o.plan.Network.VNetID)
		// An object whose creation PVE never made (found absent when teardown came
		// to delete it) was not removed: the report says so, by leaving it out.
		if zoneTracked && !o.sdnZoneAbsent && !cleanupStepFailed(cleanupFailures, fmt.Sprintf("delete SDN zone %s", o.plan.Network.ZoneID)) {
			evidence.SDNZoneRemoved = o.plan.Network.ZoneID
		}
		if vnetTracked && !o.sdnVNetAbsent && !cleanupStepFailed(cleanupFailures, fmt.Sprintf("delete SDN VNet %s", o.plan.Network.VNetID)) {
			evidence.SDNVNetRemoved = o.plan.Network.VNetID
		}
		zoneUnverified, vnetUnverified := false, false

		// Cleanup callbacks succeeding is not teardown proof. The VM API, local
		// filesystem, and kernel loop table are queried after the whole LIFO
		// stack drains so a transient PVE response or a silently retained file
		// cannot be represented as a clean validation.
		vmVerifyErr := o.verifyTrackedVMsAbsent()
		evidence.VMStoppedAndDestroyed = vmVerifyErr == nil
		if vmVerifyErr != nil {
			evidence.CleanupErrors = append(evidence.CleanupErrors, vmVerifyErr.Error())
		}

		overlaysRemoved, removedOverlays, overlayVerifyErrors := o.verifyTrackedOverlaysRemoved()
		evidence.OverlayFilesRemoved = append(evidence.OverlayFilesRemoved, removedOverlays...)
		for _, verifyErr := range overlayVerifyErrors {
			evidence.CleanupErrors = append(evidence.CleanupErrors, verifyErr.Error())
		}

		loopsUnmapped, unmappedLoops, loopVerifyErrors := o.verifyTrackedLoopsUnmapped()
		evidence.LoopDevicesUnmapped = append(evidence.LoopDevicesUnmapped, unmappedLoops...)
		for _, verifyErr := range loopVerifyErrors {
			evidence.CleanupErrors = append(evidence.CleanupErrors, verifyErr.Error())
		}

		for _, failure := range cleanupFailures {
			evidence.CleanupErrors = append(evidence.CleanupErrors, fmt.Sprintf("%s: %v", failure.Step, failure.Err))
		}
		// A lock the run may hold is not cleaned up.
		if o.record.SDNLockRequested != "" {
			evidence.CleanupErrors = append(evidence.CleanupErrors, fmt.Sprintf("a request for PVE's SDN configuration lock (at %s) got no definite answer, so PVE may hold the lock for this run with a token CertiStack never received; "+recoverhint.Recovery+" checks, and says what to do", o.record.SDNLockRequested))
		}
		if o.record.SDNLockToken != "" {
			evidence.CleanupErrors = append(evidence.CleanupErrors, "this run may still hold PVE's SDN configuration lock; "+recoverhint.Recovery+" releases it, or applies the run's SDN change under it")
		}
		if o.record.SDNApplyUnknown != "" {
			evidence.CleanupErrors = append(evidence.CleanupErrors, fmt.Sprintf("an SDN apply's outcome is unknown (its reply was lost, at %s), and it may still be reloading the nodes; "+recoverhint.Recovery+" waits for it and finishes", o.record.SDNApplyUnknown))
		}
		sdnLockSettled := o.record.SDNLockRequested == "" && o.record.SDNLockToken == "" && o.record.SDNApplyUnknown == ""
		// A delete's success reply is not proof: PVE's own lists say whether the
		// zone and VNet are gone.
		if (zoneTracked || vnetTracked) && !o.sdnPreprovisioned {
			var trackedZone, trackedVNet string
			if zoneTracked {
				trackedZone = o.plan.Network.ZoneID
			}
			if vnetTracked {
				trackedVNet = o.plan.Network.VNetID
			}
			leftZone, leftVNet, verifyErr := o.verifySDNGone(trackedZone, trackedVNet)
			if verifyErr != nil {
				evidence.CleanupErrors = append(evidence.CleanupErrors, verifyErr.Error())
			} else {
				// PVE's lists say the creation whose answer never came made
				// nothing that is left: the allocation is settled.
				o.settleSDNAllocation(trackedZone, trackedVNet)
			}
			if leftZone || verifyErr != nil {
				evidence.SDNZoneRemoved, zoneUnverified = "", true
			}
			if leftVNet || verifyErr != nil {
				evidence.SDNVNetRemoved, vnetUnverified = "", true
			}
		}
		pendingAllocation := o.record.AllocationPending != ""
		if pendingAllocation {
			evidence.CleanupErrors = append(evidence.CleanupErrors, "unresolved allocation pending: "+o.record.AllocationPending)
		}
		sdnResourcesRemoved := (!zoneTracked || (!zoneUnverified && (o.sdnZoneAbsent || evidence.SDNZoneRemoved == o.plan.Network.ZoneID))) &&
			(!vnetTracked || (!vnetUnverified && (o.sdnVNetAbsent || evidence.SDNVNetRemoved == o.plan.Network.VNetID)))
		sdnReloaded := !o.sdnReloadRequired || o.sdnTeardownReload
		evidence.SDNClusterReloaded = o.sdnReloadRequired && o.sdnTeardownReload
		evidence.OrphanSweepClean = len(cleanupFailures) == 0 && !pendingAllocation && sdnLockSettled && evidence.VMStoppedAndDestroyed && overlaysRemoved && loopsUnmapped && sdnResourcesRemoved && sdnReloaded
		evidence.AllCleaned = evidence.OrphanSweepClean
		evidence.VerifiedAt = time.Now().UTC().Format(time.RFC3339)
		res.TeardownEvidence = evidence
		if evidence.AllCleaned {
			// A normal run must not look like an interrupted run on the next
			// controller invocation. Keep the journal as an auditable terminal
			// record, but mark it clean only after every owned resource has been
			// checked absent. Crash recovery intentionally leaves other phases
			// untouched so it can retry safely.
			o.record.Phase = "cleaned"
			o.record.CleanupErrors = nil
			if err := o.flushJournal(); err != nil {
				evidence.CleanupErrors = append(evidence.CleanupErrors, err.Error())
				evidence.OrphanSweepClean = false
				evidence.AllCleaned = false
				res.AllPassed = false
				res.Error = err
			}
			if zoneTracked || vnetTracked {
				progress.Info("Cleanup", "Cleanup verified: sandbox VM destroyed, overlays removed, loop mappings released, and owned SDN resources purged.")
			} else {
				progress.Info("Cleanup", "Cleanup verified: no CertiStack-owned PVE SDN resources were allocated.")
			}
		} else {
			o.record.Phase = "cleanup_failed"
			o.record.CleanupErrors = append(o.record.CleanupErrors[:0], evidence.CleanupErrors...)
			if err := o.flushJournal(); err != nil {
				evidence.CleanupErrors = append(evidence.CleanupErrors, err.Error())
				res.AllPassed = false
				res.Error = err
			}
			progress.Error("Cleanup", "Cleanup could not be fully verified (%d issue(s)); recovery evidence was retained for review.", len(evidence.CleanupErrors))
		}
	}

	defer performTeardown()

	o.record.Phase = "running"
	if err := o.flushJournal(); err != nil {
		res.AllPassed = false
		res.Error = err
		return res, err
	}

	slog.Info("starting CertiStack DR validation plan", "plan_id", o.plan.PlanID, "tiers", len(o.plan.Tiers))
	progress.Info("", "Starting DR validation plan %q with %d recovery tier(s).", o.plan.PlanID, len(o.plan.Tiers))
	o.announcePhase(runphase.Admission, 0, "")
	if enabled, err := o.networkRecoveryEnabled(); err != nil {
		res.AllPassed = false
		res.Error = fmt.Errorf("validate COW-only network recovery: %w", err)
		return res, res.Error
	} else if enabled {
		progress.Info("Sandbox", "Checking COW-only guest network recovery support on the node worker.")
		if err := guestnet.CheckDependency(ctx); err != nil {
			res.AllPassed = false
			res.Error = err
			return res, res.Error
		}
	}

	if storage := o.opts.OverlayStorage; storage != "" {
		progress.Info("Storage", "Validating overlay storage %q on node %s.", storage, o.opts.NodeName)
		warning, err := o.checkOverlayStorage(ctx)
		if err != nil {
			res.AllPassed = false
			res.Error = fmt.Errorf("validate overlay storage: %w", err)
			return res, res.Error
		}
		if warning != "" {
			progress.Warn("Storage", "%s", warning)
		}
	}

	// A wire probe target that is one of the worker's own addresses would be
	// answered by the host, not the restored guest, even from a socket bound
	// to the sandbox interface. Refuse the plan before anything is created.
	if err := o.checkWireProbeTargetsNotLocal(); err != nil {
		res.AllPassed = false
		res.Error = err
		return res, res.Error
	}
	// The resolved plan's NICs and probe targets each belong to one VM.
	if err := o.checkResolvedInputs(); err != nil {
		res.AllPassed = false
		res.Error = err
		return res, res.Error
	}
	// A backup that pins a QEMU machine version newer than the node's QEMU
	// is refused here, not at the VM's start after minutes of guest
	// preparation. A machine list that cannot be read is a warning.
	machineWarning, machineErr := o.checkNodeMachines(ctx)
	if machineWarning != "" {
		progress.Warn("Sandbox", "%s", machineWarning)
	}
	if machineErr != nil {
		res.AllPassed = false
		res.Error = machineErr
		return res, res.Error
	}

	// 1. Admission Control Guardrails
	slog.Info("evaluating host admission control thresholds...")
	progress.Info("Admission", "Evaluating host admission control thresholds.")
	admissionTime := startPhase(&timings.AdmissionCheckSec)
	reservedMemoryMB, concurrentVMs, reservationTier, reservationErr := admission.RecoveryMemoryReservation(o.plan)
	if reservationErr != nil {
		admissionTime.stop()
		res.AllPassed = false
		res.Error = fmt.Errorf("calculate recovery resource reservation: %w", reservationErr)
		performTeardown()
		return res, res.Error
	}
	if concurrentVMs > 0 {
		progress.Info("Admission", "Reserving %d MiB for %d concurrent sandbox VM(s) through recovery tier %d before boot.", reservedMemoryMB, concurrentVMs, reservationTier)
	}
	admitErr := o.admission.WaitForAdmissionWithReservedMemory(ctx, reservedMemoryMB)
	// The time admission took counts whether it granted the run or refused it.
	admissionTime.stop()
	// The report states the limits the run was held to and what the last check
	// measured, whether it granted the run or refused it.
	res.Admission = attest.NewAdmissionEvidence(o.plan).WithEvaluation(o.admission.Evaluation())
	if err := admitErr; err != nil {
		res.AllPassed = false
		res.Error = fmt.Errorf("admission control guardrail triggered: %w", err)
		performTeardown()
		return res, res.Error
	}

	// 2. Set up the isolated SDN sandbox.
	o.announcePhase(runphase.Network, 0, "")
	slog.Info("setting up isolated SDN sandbox...", "mode", o.plan.Network.Mode, "lifecycle", o.plan.Network.EffectiveLifecycle(), "zone", o.plan.Network.ZoneID)
	if o.plan.Network.EffectiveLifecycle() == "preprovisioned" {
		progress.Info("Sandbox", "Validating pre-provisioned isolated SDN zone %s / VNet %s (no gateway, no SNAT).", o.plan.Network.ZoneID, o.plan.Network.VNetID)
	} else {
		progress.Info("Sandbox", "Provisioning isolated SDN zone %s / VNet %s (no gateway, no SNAT).", o.plan.Network.ZoneID, o.plan.Network.VNetID)
	}
	sdnTime := startPhase(&timings.SDNProvisioningSec)
	setupErr := o.setupNetwork(ctx)
	sdnTime.stop()
	if err := setupErr; err != nil {
		res.AllPassed = false
		res.Error = fmt.Errorf("SDN sandbox setup failed: %w", err)
		performTeardown()
		return res, res.Error
	}

	// 3. Multi-Tier Sequential Execution
	tiers := make([]config.Tier, len(o.plan.Tiers))
	copy(tiers, o.plan.Tiers)
	sort.SliceStable(tiers, func(i, j int) bool {
		return tiers[i].Level < tiers[j].Level
	})

	for _, tier := range tiers {
		slog.Info("=== executing tier ===", "level", tier.Level, "name", tier.Name, "vms", len(tier.VMs))
		progress.Info("", "Recovery tier %d: %s (%d VM(s)).", tier.Level, tier.Name, len(tier.VMs))
		o.beginTierCache(tier)

		// A tier represents services that can recover independently. Always
		// collect every outcome in the current tier so the signed report remains
		// actionable; a failure still prevents dependent tiers from starting.
		runnable := make([]tierVMRun, 0, len(tier.VMs))
		failures := make([]error, 0)

		// Boot all VMs in this dependency tier. One broken restore must not hide
		// whether its independent peers could be recovered.
		for vmIndex, vmCfg := range tier.VMs {
			progress.Info("Sandbox", "Tier %d progress: preparing sandbox VM %d/%d (%s).", tier.Level, vmIndex+1, len(tier.VMs), vmCfg.Name)
			boot := o.bootAndVerifyVM
			if o.bootVMFn != nil {
				boot = o.bootVMFn
			}
			vmRecord, err := boot(ctx, vmCfg, tier.BootTimeoutSec, timings)
			recordIndex := len(res.VMRecords)
			res.VMRecords = append(res.VMRecords, *vmRecord)

			if err != nil || !vmRecord.AllPassed {
				res.AllPassed = false
				if err == nil {
					err = errors.New("VM recovery did not reach a verifiable running state")
				}
				markVMRecordFailed(&res.VMRecords[recordIndex], err)
				failures = append(failures, fmt.Errorf("VM %d (%s) restore: %w", vmCfg.VMID, vmCfg.Name, err))
				if vmRecord.FailureArtifact != "" {
					res.FailureArtifact = vmRecord.FailureArtifact
				} else if artifact := o.captureFailureArtifact(ctx, vmCfg.VMID); artifact != nil {
					o.trackFailureArtifact(artifact)
					res.VMRecords[recordIndex].FailureArtifact = artifact.Base64
					if res.FailureArtifact == "" {
						res.FailureArtifact = artifact.Base64
					}
				}
				continue
			}
			runnable = append(runnable, tierVMRun{config: vmCfg, recordIndex: recordIndex})
		}

		// Soak time grace period before evaluating probes if configured
		if len(runnable) > 0 && tier.StartupGracePeriodSec > 0 {
			slog.Info("waiting startup grace period soak time", "seconds", tier.StartupGracePeriodSec)
			o.announcePhase(runphase.Grace, tier.Level, "")
			progress.Info("", "Waiting %ds for guest services to stabilize.", tier.StartupGracePeriodSec)
			tSoak := time.Now()
			vmids := make([]int, len(runnable))
			for i, run := range runnable {
				vmids[i] = run.config.VMID
			}
			// A guest that stops for good while the tier waits (a full
			// overlay storage stops it on its first failed write) fails now,
			// with the reason, instead of at its probes' timeouts.
			halted, err := o.waitWatchingVMs(ctx, time.Duration(tier.StartupGracePeriodSec)*time.Second, vmids)
			timings.StartupGracePeriodSec += time.Since(tSoak).Seconds()
			if err != nil {
				for _, run := range runnable {
					markVMRecordIncomplete(&res.VMRecords[run.recordIndex], err)
				}
				res.AllPassed = false
				res.Error = err
				performTeardown()
				return res, err
			}
			still := runnable[:0]
			for _, run := range runnable {
				haltErr, stopped := halted[run.config.VMID]
				if !stopped {
					still = append(still, run)
					continue
				}
				res.AllPassed = false
				markVMRecordFailed(&res.VMRecords[run.recordIndex], haltErr)
				failures = append(failures, fmt.Errorf("VM %d (%s): %w", run.config.VMID, run.config.Name, haltErr))
				if artifact := o.captureFailureArtifact(ctx, run.config.VMID); artifact != nil {
					o.trackFailureArtifact(artifact)
					res.VMRecords[run.recordIndex].FailureArtifact = artifact.Base64
					if res.FailureArtifact == "" {
						res.FailureArtifact = artifact.Base64
					}
				}
			}
			runnable = still
		}

		// Execute Stage 2 (synthetic wire-level) & Stage 3 (in-guest QGA) probes
		for runIndex := range runnable {
			vmCfg := runnable[runIndex].config
			recordIndex := runnable[runIndex].recordIndex
			o.announcePhase(runphase.Probes, vmCfg.VMID, "")
			tProbes := time.Now()
			probeResults, pass, err := o.runProbes(ctx, vmCfg)
			runnable[runIndex].results = probeResults
			timings.ProbesExecutionSec += time.Since(tProbes).Seconds()
			res.VMRecords[recordIndex].ProbeResults = append(res.VMRecords[recordIndex].ProbeResults, probeResults...)

			if !pass || err != nil {
				res.AllPassed = false
				if err == nil {
					err = errors.New("one or more probes failed")
				}
				markVMRecordProbeFailure(&res.VMRecords[recordIndex], err)
				failures = append(failures, fmt.Errorf("VM %d (%s) probes: %w", vmCfg.VMID, vmCfg.Name, err))

				if vmCfg.NetworkRecovery.CaptureDiagnostics {
					o.networkDiagnosticRequested[vmCfg.VMID] = true
					recoveredMAC := ""
					if hw := res.VMRecords[recordIndex].RestoredHardware; hw != nil {
						recoveredMAC = hw.MAC
					}
					diagnostic, diagnosis, complete, diagnosticErr := o.captureLiveNetworkDiagnostic(ctx, vmCfg.VMID, recoveredMAC, res.VMRecords[recordIndex].NetworkRecoveryAddress)
					if diagnosis != "" {
						progress.Warn("Diagnosis", "VM %d: %s", vmCfg.VMID, diagnosis)
					}
					if diagnosticErr != nil {
						// QGA is deliberately optional here. A missing or policy-disabled
						// agent is common in recovery testing, so it cannot mask the
						// original probe result or make teardown fail.
						progress.Warn("Sandbox", "Live guest network diagnostic unavailable for VM %d; using COW-overlay fallback (%v).", vmCfg.VMID, diagnosticErr)
					} else if !complete {
						// Hardened agents (EL7's among them) disable guest-exec: the
						// interfaces were read, but not listeners or firewall.
						o.networkDiagnostics[vmCfg.VMID] = diagnostic
						o.networkDiagnosticPartial[vmCfg.VMID] = true
						progress.Warn("Sandbox", "VM %d's guest agent allows no guest-exec, so its listeners and firewall could not be read live; only its interfaces were. The run adds the boot-time diagnostic from its COW overlay when network recovery installed one.", vmCfg.VMID)
					} else {
						o.networkDiagnostics[vmCfg.VMID] = diagnostic
						progress.Info("Sandbox", "Captured live guest network diagnostic for VM %d through QGA.", vmCfg.VMID)
					}
				}

				// Diagnostic Fallback: Trigger forensic screendump
				artifact := o.captureFailureArtifact(ctx, vmCfg.VMID)
				if artifact != nil {
					o.trackFailureArtifact(artifact)
					res.VMRecords[recordIndex].FailureArtifact = artifact.Base64
					if res.FailureArtifact == "" {
						res.FailureArtifact = artifact.Base64
					}
				}
				continue
			}
			res.VMRecords[recordIndex].VerificationStatus = "verified"
			lastSuccessTime = time.Now()
		}
		// A guest attached to a pre-provisioned VNet since the run checked it
		// could have answered a probe in a restored VM's place: then no probe
		// of this tier is evidence.
		if err := o.checkSandboxVNetStillHoldsOnlyTheRun(ctx); err != nil {
			for _, run := range runnable {
				res.VMRecords[run.recordIndex].VerificationStatus = ""
				markVMRecordFailed(&res.VMRecords[run.recordIndex], err)
				failures = append(failures, fmt.Errorf("VM %d (%s) probes: %w", run.config.VMID, run.config.Name, err))
			}
			runnable = nil
		}

		if len(failures) > 0 {
			res.AllPassed = false
			res.Error = fmt.Errorf("recovery tier %d (%s) failed: %w", tier.Level, tier.Name, errors.Join(failures...))
			performTeardown()
			return res, res.Error
		}

		// tiers[].soak_time_sec: hold this tier's already-passing VMs
		// running for an additional settle period before moving on, distinct
		// from startup_grace_period_sec's pre-probe wait. The soak watches
		// whether QEMU keeps each VM running and, from schema 1.7, repeats each
		// VM's service probes every soakSampleInterval and once more when the
		// period is over, so it shows that the service that answered once
		// still does (soakTier). A VM that stopped or that failed a
		// check fails the tier.
		if len(runnable) > 0 && tier.SoakTimeSec > 0 {
			slog.Info("holding tier for soak time before continuing", "level", tier.Level, "seconds", tier.SoakTimeSec)
			o.announcePhase(runphase.Soak, tier.Level, "")
			progress.Info("", "Holding tier %d for a %ds soak period, checking its services every %ds and when it ends, before continuing.", tier.Level, tier.SoakTimeSec, soakIntervalSec())
			tSoakEnd := time.Now()
			halted, soakEvidence, err := o.soakTier(ctx, tier, runnable)
			for _, run := range runnable {
				res.VMRecords[run.recordIndex].Soak = soakEvidence[run.config.VMID]
			}
			timings.SoakTimeSec += time.Since(tSoakEnd).Seconds()
			if err != nil {
				for _, run := range runnable {
					markVMRecordIncomplete(&res.VMRecords[run.recordIndex], err)
				}
				res.AllPassed = false
				res.Error = err
				performTeardown()
				return res, err
			}
			// A VM that stopped during the soak, or whose service stopped
			// answering, fails the tier, and so does a guest attached to a
			// pre-provisioned VNet meanwhile.
			var soakFailures []error
			vnetErr := o.checkSandboxVNetStillHoldsOnlyTheRun(ctx)
			for _, run := range runnable {
				if haltErr, stopped := halted[run.config.VMID]; stopped {
					markVMRecordFailed(&res.VMRecords[run.recordIndex], haltErr)
					soakFailures = append(soakFailures, fmt.Errorf("VM %d (%s) during the soak: %w", run.config.VMID, run.config.Name, haltErr))
				} else if vnetErr != nil {
					markVMRecordFailed(&res.VMRecords[run.recordIndex], vnetErr)
					soakFailures = append(soakFailures, fmt.Errorf("VM %d (%s) during the soak: %w", run.config.VMID, run.config.Name, vnetErr))
				}
			}
			if len(soakFailures) > 0 {
				res.AllPassed = false
				res.Error = fmt.Errorf("recovery tier %d (%s) failed: %w", tier.Level, tier.Name, errors.Join(soakFailures...))
				performTeardown()
				return res, res.Error
			}
		}
	}

	finalizeResultTiming(res, timings, startTime, lastSuccessTime)

	performTeardown()

	// all_passed here is the whole verdict: a validation that passed but
	// could not verify its cleanup did not pass, so the node log and the
	// report agree.
	cleaned := res.TeardownEvidence != nil && res.TeardownEvidence.AllCleaned
	if cleaned {
		slog.Info("CertiStack DR validation plan completed",
			"plan_id", o.plan.PlanID, "all_passed", res.AllPassed, "validation_passed", res.AllPassed, "cleanup_verified", true, "rto", res.RTO)
	} else {
		slog.Warn("CertiStack DR validation plan completed, but its temporary resource cleanup could not be verified",
			"plan_id", o.plan.PlanID, "all_passed", false, "validation_passed", res.AllPassed, "cleanup_verified", false, "rto", res.RTO)
	}

	return res, nil
}

func markVMRecordFailed(record *probe.VMValidationRecord, failure error) {
	if record == nil {
		return
	}
	record.AllPassed = false
	record.VerificationStatus = "failed"
	if failure == nil || len(record.ProbeResults) != 0 {
		return
	}
	record.ProbeResults = append(record.ProbeResults, probe.Result{
		Type:        "recovery",
		Target:      fmt.Sprintf("vm/%d", record.VMID),
		Description: "Recovery bootstrap and Stage 1 verification",
		Passed:      false,
		Error:       failure.Error(),
	})
}

// markVMRecordProbeFailure records why a VM's probe stage did not pass: a
// VM whose probes passed but asserted nothing in the guest is "unverified",
// never "verified" and not a pass; any other failure is "failed".
func markVMRecordProbeFailure(record *probe.VMValidationRecord, failure error) {
	var unverified *vmUnverifiedError
	if !errors.As(failure, &unverified) {
		markVMRecordFailed(record, failure)
		return
	}
	if record == nil {
		return
	}
	record.AllPassed = false
	record.VerificationStatus = "unverified"
}

func markVMRecordIncomplete(record *probe.VMValidationRecord, interruption error) {
	if record == nil {
		return
	}
	record.AllPassed = false
	record.VerificationStatus = "incomplete"
	if interruption == nil || len(record.ProbeResults) != 0 {
		return
	}
	record.ProbeResults = append(record.ProbeResults, probe.Result{
		Type:        "validation",
		Target:      fmt.Sprintf("vm/%d", record.VMID),
		Description: "Deterministic probes were not completed",
		Passed:      false,
		Error:       "validation interrupted before probes were run: " + interruption.Error(),
	})
}

func (o *Orchestrator) networkRecoveryEnabled() (bool, error) {
	for _, tier := range o.plan.Tiers {
		for _, vm := range tier.VMs {
			if vm.NetworkRecovery.EffectiveMode() == "preserve" {
				continue
			}
			_, configured, err := vm.SandboxAddress(o.plan.Network)
			if err != nil {
				return false, fmt.Errorf("VM %d: %w", vm.VMID, err)
			}
			if configured {
				return true, nil
			}
		}
	}
	return false, nil
}

// finalizeResultTiming makes every terminal result auditable. A successful
// validation records time to its last verified recovery point and excludes
// teardown; a negative validation has no recovery point, so it records elapsed
// time to terminal failure, which includes teardown because deferred timing
// runs after cleanup. TeardownSec remains available in both cases.
func finalizeResultTiming(res *ExecutionResult, timings *attest.PhaseTimings, start, lastSuccess time.Time) {
	if res == nil || !res.EndTime.IsZero() {
		return
	}
	res.EndTime = time.Now()
	if res.AllPassed && !lastSuccess.IsZero() {
		res.RTO = lastSuccess.Sub(start)
	} else {
		res.RTO = res.EndTime.Sub(start)
	}
	if timings != nil {
		timings.TotalRTOSec = res.RTO.Seconds()
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func cleanupStepFailed(failures []cleanup.StepError, step string) bool {
	for _, failure := range failures {
		if failure.Step == step {
			return true
		}
	}
	return false
}

// checkSandboxVNetHoldsOnlyTheRun refuses a pre-provisioned VNet that a guest
// other than the run's own sandbox VMs is attached to, now or once a pending
// change is applied: such a guest could answer a probe in a restored VM's
// place. A simple zone's VNet is a bridge of each node of its own, so only
// this node's guests are read; a VXLAN VNet spans its peers, so every node's
// are.
//
// PVE's list shows only the guests the token may audit, and only what their
// configuration says, so the bridge on this node is read as well
// (checkSandboxBridgePorts): what the kernel has attached to it.
func (o *Orchestrator) checkSandboxVNetHoldsOnlyTheRun(ctx context.Context) error {
	netCfg := o.plan.Network
	node := ""
	if netCfg.Mode == "simple" && o.opts.NodeName != "localhost" {
		node = o.opts.NodeName
	}
	own := map[int]bool{}
	for _, vm := range o.record.VMs {
		own[vm.VMID] = true
	}
	guests, err := o.pveClient.GuestsOnBridge(ctx, netCfg.VNetID, node, own, o.record.RunID)
	if err != nil {
		return fmt.Errorf("check which guests are attached to sandbox VNet %s: %w", netCfg.VNetID, err)
	}
	if len(guests) == 0 {
		return o.checkSandboxBridgePorts()
	}
	const shown = 5
	var names []string
	tagged := false
	for i, guest := range guests {
		tagged = tagged || guest.CertiStack
		if i == shown {
			names = append(names, fmt.Sprintf("%d more", len(guests)-shown))
			break
		}
		names = append(names, guest.String())
	}
	for _, guest := range guests[min(shown, len(guests)):] {
		tagged = tagged || guest.CertiStack
	}
	next := "A pre-provisioned VNet must hold only CertiStack's sandbox VMs: move those devices to another bridge, or use network.lifecycle: ephemeral"
	if tagged {
		next = "A VM tagged certistack is another CertiStack run's sandbox VM, or one a crashed run left. Two CertiStack runs must not share a pre-provisioned VNet at once: run them one after the other, or give each its own VNet. To remove a leftover, " + recoverhint.Recover + ". " + next
	}
	return fmt.Errorf("sandbox VNet %s is also attached to %s: one of them could answer a probe in a restored VM's place. %s", netCfg.VNetID, strings.Join(names, "; "), next)
}

// noteVMCreated records that PVE confirmed the creation of sandbox VM vmid
// to this run.
func (o *Orchestrator) noteVMCreated(vmid int) {
	if o.createdVMs == nil {
		o.createdVMs = map[int]bool{}
	}
	o.createdVMs[vmid] = true
}

// Port names PVE gives a guest's network device on a bridge: a VM's tap
// device, the veth pair of the iptables firewall's bridge (fwpr on the VNet's
// bridge, fwln on the firewall bridge), and a container's veth device.
var (
	vmPortName        = regexp.MustCompile(`^(?:tap([1-9][0-9]{0,8})i|fwpr([1-9][0-9]{0,8})p|fwln([1-9][0-9]{0,8})i)[0-9]{1,2}$`)
	containerPortName = regexp.MustCompile(`^veth([1-9][0-9]{0,8})i[0-9]{1,2}$`)
)

// checkSandboxBridgePorts refuses a sandbox VNet whose bridge on this node has
// a port that is not the run's own: the tap device (or firewall port) of a VM
// this run journaled and whose creation PVE confirmed to it, or, in a VXLAN
// zone, the VNet's tunnel (vxlan_<vnet>, as PVE names it). Any other port is a
// guest the token's guest list did not show (one the token may not audit, or
// one attached outside its configuration), or something else on the
// sandbox's network. A bridge that is not on this node, or whose ports cannot
// be read, is refused too: it is not an empty one.
func (o *Orchestrator) checkSandboxBridgePorts() error {
	netCfg := o.plan.Network
	ports, err := o.bridgePortsFn(netCfg.VNetID)
	if err != nil {
		return fmt.Errorf("check which guests are attached to sandbox VNet %s on this node: %w. The VNet's zone must include this node, and its configuration be applied", netCfg.VNetID, err)
	}
	own := map[int]bool{}
	for _, vm := range o.record.VMs {
		if o.createdVMs[vm.VMID] {
			own[vm.VMID] = true
		}
	}
	var foreign []string
	for _, port := range ports {
		if netCfg.Mode == "vxlan" && port == "vxlan_"+netCfg.VNetID {
			continue
		}
		if m := vmPortName.FindStringSubmatch(port); m != nil {
			vmid, _ := strconv.Atoi(m[1] + m[2] + m[3])
			if own[vmid] {
				continue
			}
			foreign = append(foreign, fmt.Sprintf("%s (VM %d)", port, vmid))
			continue
		}
		if m := containerPortName.FindStringSubmatch(port); m != nil {
			foreign = append(foreign, fmt.Sprintf("%s (container %s)", port, m[1]))
			continue
		}
		foreign = append(foreign, fmt.Sprintf("%q", port))
	}
	if len(foreign) == 0 {
		return nil
	}
	const shown = 5
	if len(foreign) > shown {
		foreign = append(foreign[:shown], fmt.Sprintf("%d more", len(foreign)-shown))
	}
	return fmt.Errorf("sandbox VNet %s's bridge on this node (%s) also has %s attached, which PVE's guest list for this token does not show: a guest the token may not audit, or one attached outside its configuration, could answer a probe in a restored VM's place. A pre-provisioned VNet must hold only CertiStack's sandbox VMs: detach it, or use network.lifecycle: ephemeral", netCfg.VNetID, o.opts.NodeName, strings.Join(foreign, "; "))
}

// checkSandboxVNetStillHoldsOnlyTheRun checks a pre-provisioned VNet again
// during the run; an ephemeral VNet is the run's own and needs no check.
func (o *Orchestrator) checkSandboxVNetStillHoldsOnlyTheRun(ctx context.Context) error {
	if !o.sdnPreprovisioned {
		return nil
	}
	return o.checkSandboxVNetHoldsOnlyTheRun(ctx)
}

// setupNetwork provisions the isolated SDN zone and VNet, registering cleanup handlers.
func (o *Orchestrator) setupNetwork(ctx context.Context) error {
	netCfg := o.plan.Network
	switch netCfg.EffectiveLifecycle() {
	case "preprovisioned":
		if err := o.sdnMgr.ValidatePreprovisionedSandbox(ctx, netCfg); err != nil {
			return fmt.Errorf("validate preprovisioned sandbox: %w", err)
		}
		if err := o.checkSandboxVNetHoldsOnlyTheRun(ctx); err != nil {
			return fmt.Errorf("validate preprovisioned sandbox: %w", err)
		}
		o.sdnPreprovisioned = true
	case "ephemeral":
		if err := o.sdnMgr.EnsureSandboxAvailable(ctx, netCfg); err != nil {
			return fmt.Errorf("sandbox ownership check: %w", err)
		}

		// Applying SDN is all or nothing, on every node. PVE's SDN lock,
		// held from the first write to the apply, makes the apply this
		// run's change alone: PVE refuses it while an administrator's
		// changes are pending, and holds off other writers meanwhile. The
		// journal has the request before it is sent and the token as it
		// arrives, so recovery can release a lock a dead run left.
		o.sdnMgr.SetPersist(o.persistSDNLock)
		o.sdnMgr.SetOwnObjects([]string{netCfg.ZoneID}, []string{netCfg.VNetID})
		if err := o.sdnMgr.Lock(ctx); err != nil {
			return fmt.Errorf("sandbox network: %w", err)
		}
		if o.sdnMgr.NoLockAPI() {
			// PVE 8 has no SDN lock: the run goes on without one, once PVE has
			// said so, and says so (the manager reads the pending changes itself;
			// PVE holds no other client off).
			progress.Warn("Network", "This PVE has no SDN configuration lock (PVE 8): CertiStack changes the sandbox network without one and checks the cluster's pending SDN changes itself; PVE does not hold other SDN changes off meanwhile.")
		}

		// Register SDN reload to execute last during teardown (first pushed = last executed in LIFO).
		o.cleanup.Push("reload SDN after teardown", func() error {
			if !o.sdnReloadRequired {
				// Nothing was created: release the lock, if still held.
				return o.sdnMgr.Unlock(context.Background())
			}
			if o.sdnTeardownBlocked != nil {
				return o.sdnTeardownBlocked
			}
			if !o.sdnDeleted && !o.sdnMgr.Mutated() {
				// Nothing could be deleted (the deletions' errors are the
				// teardown's). Applying the unchanged configuration would only
				// reload every node's network, and turn forwarding back on for
				// the sandbox's bridge: release the lock instead.
				if err := o.sdnMgr.Unlock(context.Background()); err != nil {
					return err
				}
				// A creation whose answer never came and that PVE does not
				// have made nothing: there is no change to apply.
				if (!containsString(o.record.SDNZones, netCfg.ZoneID) || o.sdnZoneAbsent) &&
					(!containsString(o.record.SDNVNets, netCfg.VNetID) || o.sdnVNetAbsent) {
					o.sdnReloadRequired = false
				}
				return nil
			}
			if err := o.sdnMgr.Reload(context.Background()); err != nil {
				return err
			}
			if !o.sdnDeleted {
				// Only part of the sandbox's SDN was deleted (a subnet, with
				// the VNet's own deletion refused), and applied: the lock is
				// not released over a pending deletion, which would block every
				// SDN lock in the cluster. The bridge stays until recovery
				// deletes the VNet and zone.
				o.sdnTeardownReload = true
				return nil
			}
			// PVE's apply returns before the nodes reload their networks:
			// the removal is applied here once this node's bridge is gone.
			if err := o.hostAddresses.SettleBridge(context.Background(), netCfg.VNetID, false, o.bridgeSettleTimeout(context.Background())); err != nil {
				return fmt.Errorf("confirm the sandbox VNet's removal on this node: %w", errors.Join(err, o.sdnMgr.ReloadFailed(context.Background())))
			}
			o.sdnTeardownReload = true
			return nil
		})

		// The zone and the VNet are journaled, and their deletions registered,
		// BEFORE their creations are sent. A creation whose reply is lost (or
		// that PVE refuses, or a crash in between) may still have made the
		// object, pending under the lock this run holds; teardown and recovery
		// know its name, and delete whatever they find there that is provably
		// the run's, instead of leaving a pending object that blocks every SDN
		// lock in the cluster and that nothing could tell from an
		// administrator's change. AllocationPending says the creation
		// is unconfirmed until PVE's lists show nothing of it is left. On a PVE
		// without the lock (PVE 8) a zone that is only new is not shown to be
		// the run's (DestroyUnconfirmedZone leaves it and reports it).
		//
		// The VNet carries a marker of this run (its alias), journaled with the
		// first object: recovery deletes a recorded VNet only while it still
		// has it, so a VNet another run or an administrator creates later
		// under the same name is never deleted as this run's.
		o.sdnMgr.SetOwnerMarker(sdn.OwnerMarker(o.record.RunID))
		o.record.SDNOwner = sdn.OwnerMarker(o.record.RunID)

		// Create Zone.
		o.sdnReloadRequired = true
		o.record.AddSDNZone(netCfg.ZoneID)
		o.record.AllocationPending = journal.SDNZonePending(netCfg.ZoneID)
		o.cleanup.Push(fmt.Sprintf("delete SDN zone %s", netCfg.ZoneID), func() error {
			if err := o.deletesBlocked("SDN zone " + netCfg.ZoneID); err != nil {
				return err
			}
			if o.sdnVNetNotOwned {
				return fmt.Errorf("SDN zone %s was left in place: the VNet in it is not provably the run's, and a zone has no marker of its own to tell it from a replacement", netCfg.ZoneID)
			}
			if o.createUnconfirmed("zone", netCfg.ZoneID) {
				created, err := o.sdnMgr.DestroyUnconfirmedZone(context.Background(), netCfg.ZoneID)
				if err != nil {
					return err
				}
				if !created {
					o.sdnZoneAbsent = true
					return nil
				}
			} else if err := o.sdnMgr.DestroyZone(context.Background(), netCfg.ZoneID); err != nil {
				return err
			}
			o.sdnDeleted = true
			return nil
		})
		if err := o.flushJournal(); err != nil {
			return err
		}
		if err := o.sdnMgr.CreateZone(ctx, netCfg, o.opts.NodeName); err != nil {
			return err
		}
		o.record.AllocationPending = ""
		if err := o.flushJournal(); err != nil {
			return err
		}

		// Create VNet.
		o.record.AddSDNVNet(netCfg.VNetID)
		o.record.AllocationPending = journal.SDNVNetPending(netCfg.VNetID)
		o.cleanup.Push(fmt.Sprintf("delete SDN VNet %s", netCfg.VNetID), func() error {
			if err := o.deletesBlocked("SDN VNet " + netCfg.VNetID); err != nil {
				return err
			}
			if o.createUnconfirmed("VNet", netCfg.VNetID) {
				created, err := o.sdnMgr.DestroyUnconfirmedVNet(context.Background(), netCfg.VNetID)
				o.noteVNetNotOwned(err)
				if err != nil {
					return err
				}
				if !created {
					o.sdnVNetAbsent = true
					return nil
				}
			} else {
				err := o.sdnMgr.DestroyVNet(context.Background(), netCfg.VNetID)
				o.noteVNetNotOwned(err)
				if err != nil {
					return err
				}
			}
			o.sdnDeleted = true
			return nil
		})
		if err := o.flushJournal(); err != nil {
			return err
		}
		if err := o.sdnMgr.CreateVNet(ctx, netCfg); err != nil {
			return err
		}
		o.record.AllocationPending = ""
		if err := o.flushJournal(); err != nil {
			return err
		}

		// The VNet is now journaled and cleanup-registered. If subnet creation
		// fails or the worker is interrupted, DestroyVNet can still remove the
		// exact parent and all of its child subnets during recovery.
		if err := o.sdnMgr.CreateSubnet(ctx, netCfg); err != nil {
			return err
		}

		// Teardown takes the lock again, right before it deletes the VNet and
		// zone (pushed after their deletions, so it runs before them). It is
		// pushed before the apply below releases the lock, so a failure
		// anywhere after, the apply's own included, still deletes and
		// applies under a lock. A lock the manager still holds, as
		// when the apply was refused, is kept; one the apply may have spent
		// is used only while a lock stands (EnsureLock).
		o.cleanup.Push("lock SDN for teardown", func() error {
			if err := o.sdnMgr.EnsureLock(context.Background()); err != nil {
				// Nothing is written to SDN without the lock: a deletion made
				// over an administrator's pending changes would mix with them, and one with
				// no apply coming would block every SDN lock in the cluster. The objects
				// stay for certistack recover, once the pending changes are applied or
				// discarded.
				o.sdnTeardownBlocked = fmt.Errorf("the sandbox's SDN zone %s and VNet %s were left in place, since PVE's SDN lock could not be taken; "+recoverhint.Recovery+" deletes and applies them under a lock, after the pending SDN changes (if any) are applied or discarded: %w", netCfg.ZoneID, netCfg.VNetID, err)
				progress.Warn("Cleanup", "%v", o.sdnTeardownBlocked)
			}
			return nil
		})

		// Apply SDN changes cluster-wide. The reload cleanup hook was registered
		// before every SDN resource, so LIFO ordering executes it after the VNet
		// and zone have been removed.
		if err := o.sdnMgr.Reload(ctx); err != nil {
			return err
		}
		// PVE's apply returns once it has forked each node's network reload,
		// not when this node has the bridge.
		if err := o.hostAddresses.SettleBridge(ctx, netCfg.VNetID, true, o.bridgeSettleTimeout(ctx)); err != nil {
			return fmt.Errorf("sandbox network: %w", errors.Join(err, o.sdnMgr.ReloadFailed(ctx)))
		}
		// ifupdown2 turns IPv4 forwarding on for every SDN bridge. This one
		// is the run's own, so the run turns it off; the containment table
		// the probe address brings drops forwarded packets as well.
		if err := o.hostAddresses.DisableForwarding(ctx, netCfg.VNetID); err != nil {
			return fmt.Errorf("sandbox network: %w", err)
		}
	default:
		return fmt.Errorf("unsupported sandbox lifecycle %q", netCfg.EffectiveLifecycle())
	}

	probeCIDR, err := netCfg.ProbeAddressCIDR()
	if err != nil {
		return fmt.Errorf("derive isolated host probe address: %w", err)
	}
	// Nothing of this run's may be there yet. Recovery settles an interrupted
	// allocation by what it finds on the host, so an address or containment
	// table that was there first must stop the run here, before the journal
	// says "pending", and never be mistaken for this run's later.
	taken, err := o.hostAddresses.HostAddressTaken(ctx, netCfg.VNetID, probeCIDR)
	if err != nil {
		return fmt.Errorf("sandbox network: cannot tell whether the isolated host probe address %s is already on %s: %w", probeCIDR, netCfg.VNetID, err)
	}
	if taken != "" {
		return fmt.Errorf("sandbox network: %s, and this run did not put it there: it will not be touched. If an earlier run left it, "+recoverhint.Recover+"; otherwise remove it yourself or use another sandbox network", taken)
	}
	slog.Info("assigning isolated host probe address", "interface", netCfg.VNetID, "cidr", probeCIDR)
	// Journal the intent before the host is touched: a crash between adding
	// the address (and its nft containment table) and journaling it would
	// otherwise leave both unrecorded, which on a preprovisioned VNet nothing
	// else removes. Recovery settles a pending allocation from the host
	// (sysutil.SettleUnconfirmedHostAddress): it removes the
	// address and its containment table only where the host shows them to be
	// this run's addition, leaves an address that has no table of this run's
	// alone and says so, and keeps the allocation in the journal when the host
	// cannot be read or a removal fails.
	o.record.AllocationPending = journal.HostAddressPending(probeCIDR, netCfg.VNetID)
	if err := o.flushJournal(); err != nil {
		return err
	}
	if err := o.hostAddresses.Add(ctx, netCfg.VNetID, probeCIDR); err != nil {
		// Add rolls back what it created. When the rollback itself failed,
		// the error says what this run still owns: record exactly that and
		// register its removal, so the teardown evidence and the journal stay
		// unclean until removal succeeds. Otherwise nothing of this run's is
		// left (an address that was already on the interface, a reason Add
		// fails, is never removed).
		switch {
		case errors.Is(err, sysutil.ErrAddressLeft):
			o.cleanup.Push(fmt.Sprintf("remove host probe address %s from %s", probeCIDR, netCfg.VNetID), func() error {
				return o.removeHostAddress(netCfg.VNetID, probeCIDR)
			})
			o.record.AddHostAddress(netCfg.VNetID, probeCIDR)
			o.recordHostAddressIdentity(ctx, netCfg.VNetID, probeCIDR)
		case errors.Is(err, sysutil.ErrContainmentLeft):
			o.cleanup.Push(fmt.Sprintf("remove host probe containment for %s on %s", probeCIDR, netCfg.VNetID), func() error {
				return o.removeHostContainment(netCfg.VNetID, probeCIDR)
			})
			o.record.AddHostContainment(netCfg.VNetID, probeCIDR)
			o.recordHostAddressIdentity(ctx, netCfg.VNetID, probeCIDR)
		}
		o.record.AllocationPending = ""
		if flushErr := o.flushJournal(); flushErr != nil {
			return errors.Join(err, flushErr)
		}
		return err
	}
	// Register removal as soon as the address exists, before the journal
	// write that can still fail, so teardown removes it on every path.
	o.cleanup.Push(fmt.Sprintf("remove host probe address %s from %s", probeCIDR, netCfg.VNetID), func() error {
		return o.removeHostAddress(netCfg.VNetID, probeCIDR)
	})
	// The address and the bridge's forwarding do not survive a network reload
	// on the node, which PVE makes at every SDN apply in the cluster: the guard
	// puts them back. Its stop is pushed right after the address's removal, so
	// the LIFO cleanup stops it before the address and the table are removed.
	o.startAddrGuard(netCfg.VNetID, probeCIDR)
	o.record.AddHostAddress(netCfg.VNetID, probeCIDR)
	o.recordHostAddressIdentity(ctx, netCfg.VNetID, probeCIDR)
	o.record.AllocationPending = ""
	if err := o.flushJournal(); err != nil {
		return err
	}
	o.watchAddrGuard(ctx)

	return nil
}

// hostBootID is this boot's identity (the kernel's boot_id); tests replace it.
var hostBootID = process.CurrentBootID

// recordHostAddressIdentity journals the kernel's identity of the interface the
// probe address is on and of its containment table, so a later recovery
// removes only what still carries them. An identity that cannot be
// read is recorded as absent, and recovery then removes nothing of it: it leaves
// the address and table for the operator, since nothing shows a replacement from
// the run's own (the run's own teardown, which knows what it added, still removes them).
//
// The numbers name the run's own interface and table only within this boot (an
// index and a handle are issued again after a reboot), so the boot is journaled
// beside them. Numbers that no boot can be named for are not recorded: a
// recovery after a reboot could not tell the run's own from a replacement that
// carries them, so it leaves them for the operator, as for numbers that could
// not be read. The boot is recorded even when the numbers could not be read.
func (o *Orchestrator) recordHostAddressIdentity(ctx context.Context, iface, cidr string) {
	boot, bootErr := hostBootID()
	ifindex, handle, err := o.hostAddresses.Identify(ctx, iface, cidr)
	if err != nil {
		slog.Warn("could not record the identity of the probe address's interface or containment table; a recovery after a crash would leave them for the operator to remove", "interface", iface, "error", err)
	}
	if bootErr != nil {
		slog.Warn("could not read this boot's identity, so the probe address's interface index and containment table handle are not recorded; a recovery after a crash would leave them for the operator to remove", "interface", iface, "error", bootErr)
		ifindex, handle = 0, 0
	}
	o.record.SetHostAddressIdentity(iface, cidr, ifindex, handle)
	o.record.SetHostAddressBoot(iface, cidr, boot)
}

// bootAndVerifyVM provisions block mapping, delta overlay, and boots the VM.
func (o *Orchestrator) bootAndVerifyVM(ctx context.Context, vmCfg config.VM, bootTimeoutSec int, timings *attest.PhaseTimings) (*probe.VMValidationRecord, error) {
	// The record starts with everything already known of the backup, so a
	// restore that stops at its first guard still signs which backup it was.
	record := newVMRecord(vmCfg)
	if timings == nil {
		timings = &attest.PhaseTimings{} // a caller that keeps no timings
	}
	if vmCfg.SourceConsistency == pbs.ConsistencyCrash {
		progress.Warn("Source", "VM %d's backup is crash-consistent: %s.", vmCfg.VMID, vmCfg.SourceConsistencyDetail)
	}
	if vmCfg.RequireQuiescedBackup {
		if reason := pbs.QuiescedRequirementUnmet(vmCfg.SourceConsistency, vmCfg.SourceConsistencyDetail); reason != "" {
			return record, errors.New(reason)
		}
	}

	// 0. Preexisting VM Guard: Fail-closed before making any mutations. VMIDs
	// are cluster-wide, so check cluster resources before the node-local status.
	clusterVMInUse, err := o.pveClient.IsVMIDInUse(ctx, vmCfg.VMID)
	if err != nil {
		record.AllPassed = false
		return record, fmt.Errorf("cannot establish whether VM %d is already used in the cluster; refusing to continue: %w", vmCfg.VMID, err)
	}
	if clusterVMInUse {
		record.AllPassed = false
		return record, fmt.Errorf("preexisting VM guard triggered: VM %d already exists in the PVE cluster", vmCfg.VMID)
	}

	existingStatus, err := o.pveClient.GetVMStatus(ctx, o.opts.NodeName, vmCfg.VMID)
	if err != nil && !o.pveClient.VMNotFound(ctx, err, o.opts.NodeName, vmCfg.VMID) {
		record.AllPassed = false
		return record, fmt.Errorf("cannot establish whether VM %d already exists; refusing to continue: %w", vmCfg.VMID, err)
	}
	if existingStatus != nil {
		record.AllPassed = false
		return record, fmt.Errorf("preexisting VM guard triggered: VM %d already exists on node %s (status: %s)", vmCfg.VMID, o.opts.NodeName, existingStatus.Status)
	}

	drives := vmCfg.SourcePBS.RestoreDrives()
	if len(drives) == 0 {
		return record, fmt.Errorf("VM %d has no backed-up source disks", vmCfg.VMID)
	}
	bootSlot, err := bootSlotFor(vmCfg, drives)
	if err != nil {
		return record, err
	}
	if len(vmCfg.OmittedDisks) > 0 {
		progress.Warn("Storage", "VM %d restores only some of its backed-up disks: the plan leaves out %s. The report records them as omitted.", vmCfg.VMID, strings.Join(vmCfg.OmittedDisks, ", "))
	}
	o.announcePhase(runphase.Restore, vmCfg.VMID, "")
	slog.Info("mapping PBS backup disks", "vmid", vmCfg.VMID, "snapshot", vmCfg.SourcePBS.Snapshot, "disks", len(drives))

	// A/B. Map every backed-up PBS archive and create one ephemeral COW overlay
	// per source SCSI slot. A source map is never attached directly to PVE.
	timestamp := time.Now().UnixNano()
	pveDisks := make([]pve.DiskOverlay, 0, len(drives))
	type mappedSourceDisk struct {
		drive  config.SourceDrive
		device string
	}
	mappedDisks := make([]mappedSourceDisk, 0, len(drives))
	for diskIndex, sourceDrive := range drives {
		loopDevice, err := o.mapSourceDrive(ctx, vmCfg.VMID, vmCfg.SourcePBS.Snapshot, sourceDrive, timings, func(mapped bool) {
			if mapped {
				setSourceDiskStatus(record, sourceDrive.Slot, probe.DiskMapped)
			} else {
				setSourceDiskStatus(record, sourceDrive.Slot, probe.DiskMapFailed)
			}
		})
		if err != nil {
			return record, err
		}

		overlayName := overlayFileName(vmCfg.VMID, sourceDrive.Slot, timestamp, diskIndex)
		deltaPath := filepath.Join(o.opts.ScratchDir, overlayName)
		overlayVolume := ""
		if o.opts.OverlayStorage != "" {
			overlayVolume = overlayVolumeID(o.opts.OverlayStorage, vmCfg.VMID, overlayName)
			volumePath, pathErr := o.overlayVolumePathFn(ctx, overlayVolume)
			if pathErr != nil {
				return record, fmt.Errorf("resolve overlay volume for %s: %w", sourceDrive.Slot, pathErr)
			}
			if pathErr := checkOverlayPath(volumePath, vmCfg.VMID, overlayName); pathErr != nil {
				return record, pathErr
			}
			if err := o.prepareOverlayDirOnce(filepath.Dir(volumePath), vmCfg.VMID); err != nil {
				return record, err
			}
			if err := o.warnOverlaySharesClusterDisk(ctx, filepath.Dir(volumePath)); err != nil {
				return record, err
			}
			deltaPath = volumePath
		}
		// qemu-img writes a staging file this run named, journaled before it
		// starts (it can leave a partial qcow2 behind when it fails or the
		// worker is interrupted), and the finished file is published at the
		// generated path without replacing anything: a file another tool put
		// there is never this run's to remove.
		slog.Info("creating ephemeral delta overlay", "vmid", vmCfg.VMID, "slot", sourceDrive.Slot, "delta_path", deltaPath, "backing", loopDevice)
		overlayTime := startPhase(&timings.OverlayCreationSec)
		overlayErr := o.createTracked(vmCfg.VMID, deltaPath, func(staging string) error {
			return sysutil.CreateDeltaOverlay(ctx, loopDevice, staging)
		})
		overlayTime.stop()
		if overlayErr != nil {
			return record, fmt.Errorf("delta overlay error for %s: %w", sourceDrive.Slot, overlayErr)
		}
		progress.Info("Storage", "Created volatile COW delta for VM %d %s; base snapshot remains read-only.", vmCfg.VMID, sourceDrive.Slot)
		pveDisks = append(pveDisks, pve.DiskOverlay{Slot: sourceDrive.Slot, Path: deltaPath, Volume: overlayVolume})
		mappedDisks = append(mappedDisks, mappedSourceDisk{drive: sourceDrive, device: loopDevice})
	}

	// A UEFI source VM also needs its firmware state: its variable store
	// and TPM state, restored as disposable copies.
	firmwareVolumes, _, err := o.restoreFirmwareDisks(ctx, vmCfg, timestamp, timings, record)
	if err != nil {
		return record, err
	}
	for _, firmware := range firmwareVolumes {
		progress.Info("Storage", "Restored the source %s of VM %d from PBS as a disposable copy; the backup remains read-only.", firmware.Slot, vmCfg.VMID)
	}

	// C. Adapt the isolated sandbox network inside the disposable overlays. The
	// guest's root filesystem need not be on the boot disk, so guestfish is
	// given the overlay of every restored disk. The PBS map remains
	// read-only and every generated profile is reported as evidence. A recovery
	// plan can opt out with mode: preserve.
	var diagnosticOverlays []string
	if address, configured, addressErr := vmCfg.SandboxAddress(o.plan.Network); addressErr != nil {
		return record, fmt.Errorf("resolve overlay network recovery for VM %d: %w", vmCfg.VMID, addressErr)
	} else if configured {
		overlays, overlayErr := guestNetworkOverlays(pveDisks, bootSlot)
		if overlayErr != nil {
			return record, fmt.Errorf("apply COW-only network recovery for VM %d: %w", vmCfg.VMID, overlayErr)
		}
		o.announcePhase(runphase.GuestNetwork, vmCfg.VMID, "")
		progress.Info("Sandbox", "Inspecting guest networking and preparing a COW-only recovery profile for VM %d; offline image work can take several minutes.", vmCfg.VMID)
		tNetworkRecovery := time.Now()
		adaptation, adaptErr := o.applyGuestNetwork(ctx, o.guestNetworkConfig(vmCfg, address, overlays, func(message string) {
			progress.Info("Sandbox", "VM %d: %s.", vmCfg.VMID, message)
		}))
		networkRecoverySeconds := time.Since(tNetworkRecovery).Seconds()
		record.NetworkRecoverySeconds = networkRecoverySeconds
		if timings != nil {
			timings.COWGuestNetworkRecoverySec += networkRecoverySeconds
		}
		if adaptErr != nil {
			return record, fmt.Errorf("apply COW-only network recovery for VM %d: %w", vmCfg.VMID, adaptErr)
		}
		record.NetworkRecoveryStrategy = adaptation.Strategy
		record.NetworkRecoveryAddress = adaptation.Address
		record.NetworkRecoveryFiles = append([]string(nil), adaptation.Files...)
		if vmCfg.NetworkRecovery.CaptureDiagnostics {
			diagnosticOverlays = overlays
		}
		progress.Info("Sandbox", "Applied %s network recovery profile for VM %d to its disposable COW overlays (%s; no gateway, no DNS).", adaptation.Strategy, vmCfg.VMID, adaptation.Address)
	}

	// C2. Verify every mapped source image and retain disk-specific evidence,
	// before the VM starts. The scan reads every byte of every disk through
	// the same PBS map the guest boots from; run alongside the boot it
	// starves the guest's first reads (Windows services time out at start),
	// and a restore, too, has all its data before it boots. A damaged
	// backup fails before anything boots from it.
	if vmCfg.SourcePBS.Snapshot == "" {
		return record, fmt.Errorf("PBS integrity verification is unavailable for VM %d", vmCfg.VMID)
	}
	if !o.opts.SkipIntegrity && o.pbsClient == nil {
		return record, fmt.Errorf("PBS integrity verification is unavailable for VM %d", vmCfg.VMID)
	}
	if o.opts.SkipIntegrity {
		progress.Warn("Storage", "Full mapped-image integrity scan skipped by explicit test-only flag.")
	}
	slots := make([]string, len(mappedDisks))
	for i, mapped := range mappedDisks {
		slots[i] = mapped.drive.Slot
	}
	var warmedDisks int
	var warmedBytes int64
	var scannedBytes int64
	// Copy-before-boot: when the VM's disks would not all stay cached until
	// it boots, the scan also copies them beside their overlays and the
	// overlays boot from the copies.
	devices := make([]string, len(mappedDisks))
	for i, mapped := range mappedDisks {
		devices[i] = mapped.device
	}
	copyDisks := false
	if len(pveDisks) > 0 {
		if copyDisks, err = o.chooseCopyBeforeBoot(ctx, vmCfg, devices, filepath.Dir(pveDisks[0].Path)); err != nil {
			return record, err
		}
	}
	if !o.opts.SkipIntegrity || copyDisks {
		o.announcePhase(runphase.Integrity, vmCfg.VMID, scanSizeNote(vmCfg, slots))
	}
	for _, i := range scanOrder(slots, bootSlot) {
		mapped := mappedDisks[i]
		manifestRef := manifestReference(mapped.drive.Archive)

		diskEvidence := probe.SourceDiskEvidence{
			Slot:              mapped.drive.Slot,
			Archive:           mapped.drive.Archive,
			ManifestReference: manifestRef,
		}
		verifyStatus := "SKIPPED: full mapped-image integrity verification disabled by --skip-integrity test mode"
		switch {
		case copyDisks:
			tIntegrity := time.Now()
			copyPath := filepath.Join(filepath.Dir(pveDisks[i].Path), copyFileName(vmCfg.VMID, mapped.drive.Slot, timestamp, i))
			fusePath, _ := sysutil.LoopBacking(mapped.device)
			var summary *pbs.VerifySummary
			var digest string
			// The copy is written to a staging file and published without
			// replacing anything, like an overlay.
			cErr := o.createTracked(vmCfg.VMID, copyPath, func(staging string) error {
				var err error
				summary, digest, err = o.copyMappedDisk(ctx, vmCfg, mapped.drive.Slot, mapped.device, strings.TrimSuffix(fusePath, " (deleted)"), staging, o.scanReporter(vmCfg, mapped.drive.Slot, true))
				return err
			})
			if timings != nil {
				timings.IntegrityVerificationSec += time.Since(tIntegrity).Seconds()
			}
			if cErr != nil {
				setSourceDiskStatus(record, mapped.drive.Slot, probe.DiskVerificationFailed)
				return record, fmt.Errorf("PBS mapped-image integrity verification and copy failed for %s: %w", mapped.drive.Slot, cErr)
			}
			if err := sysutil.RebaseDeltaOverlay(ctx, pveDisks[i].Path, copyPath); err != nil {
				setSourceDiskStatus(record, mapped.drive.Slot, probe.DiskVerificationFailed)
				return record, fmt.Errorf("boot %s from its local copy: %w", mapped.drive.Slot, err)
			}
			diskEvidence.IntegrityStatus = "verified"
			diskEvidence.ImageDigest = digest
			diskEvidence.BootSource = "local-copy"
			verifyStatus = summary.Detail
		case o.opts.SkipIntegrity:
			diskEvidence.IntegrityStatus = "skipped_test_mode"
			slog.Warn("skipping full mapped-image integrity verification in test mode", "vmid", vmCfg.VMID, "slot", mapped.drive.Slot)
			if read, err := warmDiskLabels(ctx, "/sys/class/block", mapped.device); err != nil {
				progress.Warn("Storage", "VM %d: test mode could not read %s's partition tables and labels ahead of boot: %v", vmCfg.VMID, mapped.drive.Slot, err)
			} else {
				warmedDisks++
				warmedBytes += read
			}
		default:
			tIntegrity := time.Now()
			summary, digest, vErr := o.verifyMappedDisk(ctx, vmCfg, mapped.drive.Slot, mapped.device, o.scanReporter(vmCfg, mapped.drive.Slot, false))
			if timings != nil {
				timings.IntegrityVerificationSec += time.Since(tIntegrity).Seconds()
			}
			if vErr != nil {
				setSourceDiskStatus(record, mapped.drive.Slot, probe.DiskVerificationFailed)
				return record, fmt.Errorf("PBS mapped-image integrity verification failed for %s: %w", mapped.drive.Slot, vErr)
			}
			diskEvidence.IntegrityStatus = "verified"
			diskEvidence.ImageDigest = digest
			verifyStatus = summary.Detail
			scannedBytes += summary.BytesRead
		}
		// Each disk's evidence is recorded as its scan ends, so a failure of
		// a later disk keeps what the earlier ones established.
		setSourceDisk(record, diskEvidence)
		if mapped.drive.Slot == bootSlot {
			record.SourceDrive = mapped.drive.Archive
			record.SourceManifestReference = manifestRef
			record.SourceImageDigest = diskEvidence.ImageDigest
			record.PBSVerifyStatus = verifyStatus
		}
	}
	// Firmware images were restored whole, with every chunk checked, whatever
	// the integrity mode; each was recorded when it was restored.
	record.CopiedBeforeBoot = copyDisks
	if copyDisks {
		progress.Info("Storage", "Full mapped-image integrity verification passed for %d restored disk(s); the sandbox boots from their local copies.", len(mappedDisks))
	} else if !o.opts.SkipIntegrity {
		progress.Info("Storage", "Full mapped-image integrity verification passed for %d restored disk(s).", len(mappedDisks))
		o.noteScannedDisks(vmCfg.VMID, scannedBytes)
	} else if warmedDisks > 0 {
		progress.Info("Storage", "VM %d: test mode read the partition tables and labels of %d disk(s) (%d MiB) ahead of boot.", vmCfg.VMID, warmedDisks, warmedBytes>>20)
	}

	// D. Register Ephemeral PVE VM Configuration with ownership markers.
	o.announcePhase(runphase.Boot, vmCfg.VMID, "")
	pveVMConfig := o.sandboxVMWithEvidence(ctx, vmCfg, pveDisks, bootSlot, firmwareVolumes, record)
	cpuWeight := pveVMConfig.CPUWeight

	// Persist the intended VM identity and register its ownership-checked
	// teardown before the create request. PVE can accept a create request while
	// its task lookup or HTTP response times out. In that case a normal failed
	// run still destroys the exact owned VM immediately; a crash has the same
	// identity available to recovery. Recording first is safe when the request
	// never reaches PVE: a missing VM is a no-op and an unrelated VM is never
	// removed.
	//
	// The overlay diagnostic is read in the VM's teardown, between its stop and
	// its destroy: once QEMU has stopped, as ReadDiagnostics requires,
	// and before PVE's destroy frees the overlay, which is a volume of the
	// sandbox VM.
	if len(diagnosticOverlays) > 0 {
		o.captureNetworkDiagnosticBeforeDestroy(vmCfg.VMID, diagnosticOverlays)
	}
	if err := o.trackOwnedVM(vmCfg.VMID); err != nil {
		return record, err
	}

	slog.Info("registering ephemeral VM configuration with hypervisor", "vmid", vmCfg.VMID, "run_id", o.runID)
	progress.Info("Sandbox", "Registering ephemeral sandbox VM %d (%s).", vmCfg.VMID, vmCfg.Name)
	registrationTime := startPhase(&timings.VMRegistrationSec)
	defer registrationTime.stop() // covers every return before the registration ends
	upid, err := o.pveClient.CreateVM(ctx, o.opts.NodeName, pveVMConfig)
	if err != nil {
		return record, fmt.Errorf("PVE CreateVM error: %w", err)
	}
	if err := o.pveClient.WaitForTask(ctx, o.opts.NodeName, upid, time.Second, 2*time.Minute); err != nil {
		return record, fmt.Errorf("PVE CreateVM task failed: %w", err)
	}
	o.noteVMCreated(vmCfg.VMID)
	// PVE pins a new Windows guest's machine version on create; a restore
	// keeps the backup's setting, which PVE resolves at every start. Undo the
	// pin so the sandbox VM runs the machine the restored VM would; the
	// record's running_machine shows which one it was.
	if pinned, err := o.pveClient.KeepRequestedMachine(ctx, o.opts.NodeName, vmCfg.VMID, pveVMConfig.Machine); err != nil {
		progress.Warn("Sandbox", "Could not keep the backup's machine setting for VM %d; it runs the version PVE pinned on create: %v", vmCfg.VMID, err)
	} else if pinned != "" {
		requested := pveVMConfig.Machine
		if requested == "" {
			requested = "PVE's default"
		}
		progress.Info("Sandbox", "PVE pinned VM %d's machine to %s on create; restored the backup's setting (%s), as a restore would.", vmCfg.VMID, pinned, requested)
	}
	if len(vmCfg.SourceCDROMs) > 0 {
		o.recordEmptyCDROMs(ctx, record, vmCfg)
	}
	registrationTime.stop()

	// D. Start VM, once fewer than max_concurrent_boots sandbox VMs are
	// still booting.
	waited, err := o.boots.wait(ctx, vmCfg.VMID)
	if timings != nil {
		timings.AdmissionCheckSec += waited.Seconds()
	}
	if err != nil {
		return record, fmt.Errorf("wait to start VM %d: %w", vmCfg.VMID, err)
	}
	slog.Info("starting VM execution", "vmid", vmCfg.VMID)
	progress.Info("Sandbox", "Launching ephemeral sandbox VM %d (PVE cpuunits=%d).", vmCfg.VMID, cpuWeight)
	bootTimeout := bootTimeoutDuration(bootTimeoutSec)
	tStart := time.Now()
	startTime := startPhase(&timings.VMStartSec)
	defer startTime.stop() // covers every return before the start ends
	recordBootDuration := func() {
		// This is intentionally measured from the PVE start request through
		// Stage 1 readiness. PBS mapping, COW guestfs work, and image integrity
		// each have separate timing evidence and must not be misrepresented as
		// guest boot time in a customer-facing certificate.
		if record.BootDuration == 0 {
			record.BootDuration = time.Since(tStart)
			record.BootDurationSeconds = record.BootDuration.Seconds()
		}
	}
	startUpid, err := o.pveClient.StartVM(ctx, o.opts.NodeName, vmCfg.VMID)
	if err != nil {
		recordBootDuration()
		return record, fmt.Errorf("PVE StartVM error: %w", err)
	}
	if err := o.pveClient.WaitForTask(ctx, o.opts.NodeName, startUpid, time.Second, bootTimeout); err != nil {
		recordBootDuration()
		return record, fmt.Errorf("PVE StartVM task failed: %w", err)
	}
	o.boots.started(tStart)
	startTime.stop()

	// E. Record VM PID in runner state journal
	vmPID := 0
	if vmStatus, err := o.pveClient.GetVMStatus(ctx, o.opts.NodeName, vmCfg.VMID); err == nil && vmStatus != nil && vmStatus.PID > 0 {
		vmPID = vmStatus.PID
		if record.RestoredHardware != nil {
			record.RestoredHardware.RunningMachine = vmStatus.RunningMachine
		}
	} else {
		slog.Warn("VM PID unavailable; process identity tracking skipped", "vmid", vmCfg.VMID)
	}
	vmProcess := journal.Process{PID: vmPID}
	if vmPID > 0 {
		identity, identityErr := process.ProcessIdentity(vmPID)
		if identityErr != nil {
			return record, fmt.Errorf("record QEMU process identity for VM %d: %w", vmCfg.VMID, identityErr)
		}
		// A PID and start ticks name a process only within this boot: record
		// the boot too, so recovery after a reboot does not take a process of
		// the later boot for this one.
		bootID, bootErr := process.CurrentBootID()
		if bootErr != nil {
			return record, fmt.Errorf("record the boot of QEMU process %d for VM %d: %w", vmPID, vmCfg.VMID, bootErr)
		}
		vmProcess = journal.Process{PID: vmPID, StartTicks: identity.StartTicks, BootID: bootID}
	}
	o.record.AddVMProcess(vmCfg.VMID, o.opts.NodeName, vmProcess)
	if err := o.flushJournal(); err != nil {
		return record, err
	}

	// F. Stage 1: QMP Hypervisor Status Verification (Fail-Closed)
	if !o.opts.SkipQMP {
		qmpSocket := qmp.DefaultSocketPath(vmCfg.VMID)
		if o.opts.QMPSocketDir != "" {
			qmpSocket = filepath.Join(o.opts.QMPSocketDir, fmt.Sprintf("%d.qmp", vmCfg.VMID))
		}
		slog.Info("verifying hypervisor execution state via QMP...", "vmid", vmCfg.VMID, "socket", qmpSocket)
		qmpTime := startPhase(&timings.QMPRunningWaitSec)
		defer qmpTime.stop() // covers every return before the wait ends
		qmpClient, err := qmp.DialContext(ctx, qmpSocket, 10*time.Second)
		if err != nil {
			record.AllPassed = false
			recordBootDuration()
			return record, fmt.Errorf("Stage 1 QMP connection failed for VM %d: %w", vmCfg.VMID, err)
		}
		defer qmpClient.Close()
		if err := qmpClient.WaitForRunning(ctx, 500*time.Millisecond, bootTimeout); err != nil {
			record.AllPassed = false
			recordBootDuration()
			return record, fmt.Errorf("Stage 1 verification failed for VM %d: %w", vmCfg.VMID, err)
		}
		qmpTime.stop()
		progress.Info("Stage 1", "QMP hypervisor handshake established → VM RUNNING.")
	} else {
		slog.Warn("skipping Stage 1 QMP verification as configured", "vmid", vmCfg.VMID)
	}
	recordBootDuration()
	record.VerificationStatus = "booted"

	slog.Info("VM booted successfully", "vmid", vmCfg.VMID, "duration", record.BootDuration)
	return record, nil
}

// trackDeltaOverlay makes a staging path of VM vmid (see createTracked)
// recoverable before an external creator receives it. The creator can leave a
// partial file if it fails or the node is interrupted; an absent file is the
// successful idempotent cleanup result. The file stays while the VM may still
// run. It removes by path, so it is only for a path whose name carries this
// run's unguessable token: a file at a predictable path is tracked by its
// identity instead.
func (o *Orchestrator) trackDeltaOverlay(vmid int, path string) error {
	o.record.AddDeltaFile(path)
	if err := o.flushJournal(); err != nil {
		return err
	}
	o.cleanup.Push(fmt.Sprintf("remove delta overlay %s", path), func() error {
		if err := o.keptForVM(vmid, "overlay "+path); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
	return nil
}

// prepareOverlayDirOnce checks (and if needed creates) a VM image directory
// the first time one of the VM's disks uses it. A directory this run created
// is removed during cleanup once its overlays are gone; it is registered
// before the overlays so LIFO cleanup removes the files first.
func (o *Orchestrator) prepareOverlayDirOnce(dir string, vmid int) error {
	if o.preparedOverlayDirs[dir] {
		return nil
	}
	created, err := prepareOverlayDir(dir, vmid)
	if err != nil {
		return err
	}
	o.preparedOverlayDirs[dir] = true
	if created {
		o.cleanup.Push(fmt.Sprintf("remove overlay directory %s", dir), func() error {
			if err := o.keptForVM(vmid, "overlay directory "+dir); err != nil {
				return err
			}
			return removeEmptyOverlayDir(dir)
		})
	}
	return nil
}

// trackOwnedVM makes an exact ephemeral VM eligible for normal teardown and
// crash recovery before PVE receives its create request. The teardown verifies
// CertiStack ownership and treats definite non-existence as success, so an
// unsent or rejected request can never remove somebody else's VM. Until the
// teardown confirms the VM destroyed, what it uses is kept (vmTeardown).
func (o *Orchestrator) trackOwnedVM(vmid int) error {
	o.record.AddVM(vmid, o.opts.NodeName, 0, "")
	if err := o.flushJournal(); err != nil {
		return err
	}
	if o.vmTeardown == nil {
		o.vmTeardown = make(map[int]error)
	}
	o.vmTeardown[vmid] = errVMTeardownNotRun
	o.cleanup.Push(fmt.Sprintf("destroy VM %d", vmid), func() error {
		err := o.destroyOwnedVM(vmid, o.runID)
		o.vmTeardown[vmid] = err
		return err
	})
	return nil
}

// errVMTeardownNotRun is a registered VM teardown that has not run yet.
var errVMTeardownNotRun = errors.New("its teardown did not run")

// vmMayRemain says why sandbox VM vmid may still exist, or nil: the VM's
// teardown is registered and has not confirmed it destroyed (that step's
// own error says why). A VM whose create request was never sent has no
// teardown, and nothing of it remains.
func (o *Orchestrator) vmMayRemain(vmid int) error {
	switch reason, registered := o.vmTeardown[vmid]; {
	case !registered || reason == nil:
		return nil
	case errors.Is(reason, errVMTeardownNotRun):
		return fmt.Errorf("sandbox VM %d was not confirmed destroyed: %w", vmid, reason)
	}
	return fmt.Errorf("sandbox VM %d was not confirmed destroyed", vmid)
}

// sandboxVMsMayRemain says why a sandbox VM of this run may still exist, or
// nil once teardown has confirmed every one destroyed. While it is non-nil,
// what the VMs share on the host stays: the host probe address and its
// containment table.
//
// The SDN zone and VNet are not held back: their deletion callbacks do not
// consult this, and recovery deletes them before it decides whether a VM
// remains. When the VNet goes, its bridge goes, and the kept probe address
// with it; the surviving VM's NIC is then on no bridge, so the guest has no
// network at all, and the containment table, which is removed only once the
// address is confirmed gone, is what recovery removes later (an address that
// is gone with its bridge counts as gone). Holding the deletion back instead
// would keep a live segment around a guest teardown could not stop, and would
// leave the SDN lock and a pending apply to settle around it; cutting the
// guest off is the stricter isolation, and recovery still retries the VM.
func (o *Orchestrator) sandboxVMsMayRemain() error {
	vmids := make([]int, 0, len(o.vmTeardown))
	for vmid := range o.vmTeardown {
		vmids = append(vmids, vmid)
	}
	sort.Ints(vmids)
	var reasons []string
	for _, vmid := range vmids {
		if err := o.vmMayRemain(vmid); err != nil {
			reasons = append(reasons, err.Error())
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	return errors.New(strings.Join(reasons, "; "))
}

// keptForVM refuses to release what VM vmid uses (a disk or a PBS map)
// while the VM may still run. The journal keeps it, and recovery releases it
// once the VM is destroyed.
func (o *Orchestrator) keptForVM(vmid int, what string) error {
	if err := o.vmMayRemain(vmid); err != nil {
		return fmt.Errorf("kept %s in place: %w, and may still use it; recovery releases it once the VM is destroyed", what, err)
	}
	return nil
}

// removeHostAddress removes the host probe address and its containment
// once no sandbox VM of this run may still be on the VNet. The VNet's own
// deletion does not wait for the VMs (see sandboxVMsMayRemain), and the
// message says so.
func (o *Orchestrator) removeHostAddress(iface, cidr string) error {
	if err := o.sandboxVMsMayRemain(); err != nil {
		return fmt.Errorf("kept host probe address %s on %s and its containment in place: %w; the VNet's deletion does not wait for the VMs: when it goes through, the bridge and this address go with it and the guest is left on no network, and recovery removes the containment once the VMs are destroyed", cidr, iface, err)
	}
	if err := o.hostAddresses.Remove(context.Background(), iface, cidr); err != nil {
		if errors.Is(err, sysutil.ErrContainmentLeft) {
			// The address is gone and only its containment table is left: the
			// record says so, so that the retry (recovery) removes the table
			// and does not delete the address again, which an address of the
			// same CIDR on the same interface since is not this run's to lose.
			o.record.SetHostContainmentOnly(iface, cidr)
			if flushErr := o.flushJournal(); flushErr != nil {
				err = errors.Join(err, flushErr)
			}
		}
		return err
	}
	return o.forgetHostAddress(iface, cidr)
}

// forgetHostAddress drops a host address record whose removal is confirmed. A
// journal kept for another resource's failure must not later remove a
// replacement that reuses the interface and CIDR.
func (o *Orchestrator) forgetHostAddress(iface, cidr string) error {
	o.record.DropHostAddress(iface, cidr)
	return o.flushJournal()
}

// removeHostContainment removes a failed address assignment's containment
// once no sandbox VM of this run may still be on the VNet.
func (o *Orchestrator) removeHostContainment(iface, cidr string) error {
	if err := o.sandboxVMsMayRemain(); err != nil {
		return fmt.Errorf("kept the containment for %s on %s in place: %w; recovery removes it once the VMs are destroyed", cidr, iface, err)
	}
	if err := o.hostAddresses.RemoveContainment(context.Background(), iface, cidr); err != nil {
		return err
	}
	return o.forgetHostAddress(iface, cidr)
}

// verifyTrackedVMsAbsent verifies only exact VM identities that this run
// durably registered before attempting creation. Planned VMs in later tiers
// may never have been allocated after an earlier failure, and must not be
// mistaken for CertiStack-owned resources during teardown proof.
func (o *Orchestrator) verifyTrackedVMsAbsent() error {
	for _, tracked := range o.record.VMs {
		if tracked.VMID <= 0 || strings.TrimSpace(tracked.Node) == "" {
			return fmt.Errorf("cannot verify a malformed tracked sandbox VM identity")
		}
		if o.pveClient == nil {
			return fmt.Errorf("cannot verify sandbox VM %d is absent: PVE client is unavailable", tracked.VMID)
		}
		status, err := o.pveClient.GetVMStatus(context.Background(), tracked.Node, tracked.VMID)
		if o.pveClient.VMNotFound(context.Background(), err, tracked.Node, tracked.VMID) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot verify sandbox VM %d is absent on node %s: %w", tracked.VMID, tracked.Node, err)
		}
		if status != nil {
			return fmt.Errorf("sandbox VM %d remains on node %s (status: %s)", tracked.VMID, tracked.Node, status.Status)
		}
	}
	return nil
}

// verifyTrackedOverlaysRemoved proves that each exact, journaled COW file is
// absent. A non-not-found stat error is not a pass: permission and I/O errors
// are explicitly surfaced because they leave cleanup indeterminate.
func (o *Orchestrator) verifyTrackedOverlaysRemoved() (allRemoved bool, removed []string, errs []error) {
	allRemoved = true
	for _, overlay := range o.record.DeltaFiles {
		if strings.TrimSpace(overlay) == "" {
			allRemoved = false
			errs = append(errs, errors.New("cannot verify an empty tracked COW overlay path"))
			continue
		}
		if identity, ok := o.record.DeltaIdentity(overlay); ok {
			// A file this run created there: what is at the path now is
			// judged against it, never by the path alone.
			state, err := sysutil.CheckFileIdentity(overlay, identity)
			switch {
			case err != nil:
				allRemoved = false
				errs = append(errs, fmt.Errorf("cannot verify COW overlay %s is absent: %w", overlay, err))
			case state == sysutil.FileAbsent:
				removed = append(removed, filepath.Base(overlay))
			case state == sysutil.FileOther:
				allRemoved = false
				errs = append(errs, fmt.Errorf("COW overlay %s now holds a file this run did not create; it was left alone. Whether this run's own file is elsewhere cannot be established: inspect it, then remove it or this journal entry by hand", overlay))
			default:
				allRemoved = false
				errs = append(errs, fmt.Errorf("COW overlay %s remains after cleanup", overlay))
			}
			continue
		}
		_, err := os.Stat(overlay)
		switch {
		case errors.Is(err, os.ErrNotExist):
			removed = append(removed, filepath.Base(overlay))
		case err != nil:
			allRemoved = false
			errs = append(errs, fmt.Errorf("cannot verify COW overlay %s is absent: %w", overlay, err))
		default:
			allRemoved = false
			errs = append(errs, fmt.Errorf("COW overlay %s remains after cleanup", overlay))
		}
	}
	return allRemoved, removed, errs
}

// verifyTrackedLoopsUnmapped proves every journaled PBS loop map is absent.
// The backing-file identity is checked when a device is still present so an
// unexpected device reuse is called out rather than being silently accepted.
func (o *Orchestrator) verifyTrackedLoopsUnmapped() (allUnmapped bool, unmapped []string, errs []error) {
	allUnmapped = true
	loops := append([]journal.TrackedLoop(nil), o.record.Loops...)
	if o.record.LoopDevice != "" && !containsTrackedLoop(loops, o.record.LoopDevice) {
		loops = append(loops, journal.TrackedLoop{Device: o.record.LoopDevice, Backing: o.record.LoopBacking})
	}
	for _, loop := range loops {
		if strings.TrimSpace(loop.Device) == "" {
			allUnmapped = false
			errs = append(errs, errors.New("cannot verify an empty tracked PBS loop device"))
			continue
		}
		state, err := sysutil.CheckLoop(loop.Device, loop.Backing)
		switch {
		case err != nil:
			allUnmapped = false
			if holders, held := sysutil.HeldAfterUnmap(loop.Device); held {
				errs = append(errs, sysutil.LoopHeldError(loop.Device, holders))
				continue
			}
			errs = append(errs, fmt.Errorf("cannot verify PBS loop device %s is unmapped: %w", loop.Device, err))
		case state == sysutil.LoopGone:
			unmapped = append(unmapped, loop.Device)
		case state == sysutil.LoopReused:
			// Stale backing is not proof of a real replacement map. A mount or
			// open descriptor can retain it without any listed block holder;
			// the attachment's disk sequence number, when recorded, tells.
			if err := sysutil.AwaitLoopReleased(loop, 1, 0); err != nil {
				allUnmapped = false
				errs = append(errs, err)
				continue
			}
			// The device number is another file's now: the run's map is not on
			// it, and it is not the run's to detach. Clean only if nothing of the
			// run's map remains.
			note, noteErr := o.reusedLoopNoteFn(loop.Device, loop.Backing)
			if noteErr != nil {
				allUnmapped = false
				errs = append(errs, noteErr)
				continue
			}
			progress.Warn("Cleanup", "%s", note)
			unmapped = append(unmapped, loop.Device)
		default:
			allUnmapped = false
			errs = append(errs, sysutil.LoopRemainsError(loop.Device))
		}
	}
	return allUnmapped, unmapped, errs
}

func containsTrackedLoop(loops []journal.TrackedLoop, device string) bool {
	for _, loop := range loops {
		if loop.Device == device {
			return true
		}
	}
	return false
}

// destroyOwnedVM removes one exact CertiStack VM during teardown. A confirmed
// PVE not-found response is success: another teardown/recovery path already
// reached the intended absent state. Transport, authorization, and ownership
// failures remain fail-closed and preserve the durable journal for retry.
//
// Success is established from the VM, never from a task or a command: after
// the destroy (PVE's task, or the local qm fallback) PVE must answer that the
// exact VM does not exist, and a VM still there or an unreadable answer is a
// failure. What the VM uses is released on this result alone
// (vmTeardown), so a task that succeeded for another object cannot release it.
// The stop is not taken on a task's word either: its task's outcome is
// discarded, the VM's status is polled for "stopped", and the destroy that
// follows is refused by PVE for a VM that still runs.
//
// What was registered for the VM with beforeVMDestroy runs once the status says
// "stopped" (or that the VM does not exist) and before the first destroy, which
// frees the VM's volumes. A teardown that ends before that point (the VM is
// already gone, or its ownership or stop cannot be established) runs it on the
// way out, told which of those it was.
func (o *Orchestrator) destroyOwnedVM(vmid int, runID string) (cleanupErr error) {
	progress.Info("Cleanup", "Stopping and removing sandbox VM %d; this can take a few minutes on a busy node.", vmid)
	defer func() {
		if cleanupErr != nil {
			progress.Error("Cleanup", "Sandbox VM %d could not be confirmed absent: %v", vmid, cleanupErr)
			return
		}
		progress.Info("Cleanup", "Sandbox VM %d is confirmed absent.", vmid)
	}()
	defer func() {
		if cleanupErr == nil {
			o.runBeforeVMDestroy(vmid, vmAbsent, nil)
		} else {
			o.runBeforeVMDestroy(vmid, vmNotConfirmedStopped, cleanupErr)
		}
	}()

	ctx := context.Background()
	if gone, err := o.vmOwnedNow(ctx, vmid, runID); err != nil || gone {
		return err
	}

	stopUpid, stopErr := o.pveClient.StopVM(ctx, o.opts.NodeName, vmid)
	if o.vmGoneAfter(ctx, stopErr, vmid) {
		return nil
	}
	if stopErr != nil {
		slog.Warn("StopVM API call returned error, issuing fallback stop", "vmid", vmid, "error", stopErr)
		owned, ownershipErr := o.confirmOwnedBeforeQMFallback(ctx, vmid, runID)
		if ownershipErr != nil {
			return ownershipErr
		}
		if !owned {
			return nil
		}
		fallbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = o.runQMFallback(fallbackCtx, []string{"stop", fmt.Sprintf("%d", vmid), "--skiplock", "1"})
		cancel()
	} else {
		_ = o.pveClient.WaitForTask(ctx, o.opts.NodeName, stopUpid, time.Second, 30*time.Second)
	}

	// Wait for hypervisor to report VM state as stopped (up to 15 seconds).
	// A definite missing configuration is already the desired final state.
	quiescence, notConfirmed := vmNotConfirmedStopped, fmt.Errorf("PVE did not report sandbox VM %d stopped within 15 seconds", vmid)
	for i := 0; i < 30; i++ {
		status, statusErr := o.pveClient.GetVMStatus(ctx, o.opts.NodeName, vmid)
		if o.pveClient.VMNotFound(ctx, statusErr, o.opts.NodeName, vmid) {
			quiescence = vmAbsent
			break
		}
		if status == nil {
			if statusErr != nil {
				notConfirmed = fmt.Errorf("sandbox VM %d's state cannot be read: %w", vmid, statusErr)
			} else {
				notConfirmed = fmt.Errorf("PVE returned an empty status for sandbox VM %d", vmid)
			}
			break
		}
		if status.Status == "stopped" {
			quiescence = vmStopped
			break
		}
		if statusErr != nil {
			// Do not hide an indeterminate status read. Destroy will retry or
			// fail closed below with its own authenticated result.
			slog.Warn("could not confirm VM stop state before destroy", "vmid", vmid, "error", statusErr)
			notConfirmed = statusErr
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	// QEMU no longer writes to the VM's disks, and PVE has not yet freed them.
	o.runBeforeVMDestroy(vmid, quiescence, notConfirmed)

	var destroyUpid string
	var destroyErr error
	for attempt := 1; attempt <= 5; attempt++ {
		// The stop and the waits since the ownership was read gave the ID time
		// to be reused: the markers are read again before each destroy, and
		// only the run's own VM is ever sent one.
		if gone, err := o.vmOwnedNow(ctx, vmid, runID); err != nil || gone {
			return err
		}
		destroyUpid, destroyErr = o.pveClient.DestroyVM(ctx, o.opts.NodeName, vmid)
		if o.vmGoneAfter(ctx, destroyErr, vmid) {
			return nil
		}
		if destroyErr == nil {
			break
		}
		errLower := strings.ToLower(destroyErr.Error())
		if strings.Contains(errLower, "running") || strings.Contains(errLower, "locked") || strings.Contains(errLower, "lock") {
			slog.Warn("VM still stopping/locked, waiting before destroy retry...", "vmid", vmid, "attempt", attempt, "error", destroyErr)
			owned, ownershipErr := o.confirmOwnedBeforeQMFallback(ctx, vmid, runID)
			if ownershipErr != nil {
				return ownershipErr
			}
			if !owned {
				return nil
			}
			fallbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, _ = o.runQMFallback(fallbackCtx, []string{"stop", fmt.Sprintf("%d", vmid), "--skiplock", "1"})
			cancel()
			time.Sleep(time.Duration(attempt) * 750 * time.Millisecond)
			continue
		}
		break
	}
	if destroyErr != nil {
		slog.Warn("DestroyVM API failed, issuing fallback CLI destroy", "vmid", vmid, "error", destroyErr)
		owned, ownershipErr := o.confirmOwnedBeforeQMFallback(ctx, vmid, runID)
		if ownershipErr != nil {
			return ownershipErr
		}
		if !owned {
			return nil
		}
		fallbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		out, cmdErr := o.runQMFallback(fallbackCtx, []string{"destroy", fmt.Sprintf("%d", vmid)})
		cancel()
		// A command that exited 0 is no more proof than a task that succeeded.
		remains := o.vmMayStillExist(vmid)
		switch {
		case remains == nil:
			return nil
		case cmdErr == nil:
			return fmt.Errorf("qm destroy of VM %d reported success (the API said: %v), but %w", vmid, destroyErr, remains)
		}
		return fmt.Errorf("failed to destroy VM %d (API: %v, CLI: %v, out: %s; %v)", vmid, destroyErr, cmdErr, string(out), remains)
	}
	// Neither the task's success nor its failure or a timeout in reading it
	// says whether the VM is gone: PVE's answer for the exact VM does.
	waitErr := o.pveClient.WaitForTask(ctx, o.opts.NodeName, destroyUpid, time.Second, 30*time.Second)
	remains := o.vmMayStillExist(vmid)
	switch {
	case remains == nil:
		return nil
	case waitErr != nil:
		return fmt.Errorf("%w (%v)", waitErr, remains)
	}
	return fmt.Errorf("the destroy task of VM %d reported success, but %w", vmid, remains)
}

// vmGoneAfter reports whether err, PVE's answer to a stop or a destroy of VM
// vmid, says the VM does not exist and PVE says so again when the VM is read:
// "no such VM" returned by a request that was to act on it is not taken as the
// end of the VM on its own. An answer that PVE's own status read of the VM then
// contradicts (a 404 for a VM that still runs, a proxy's answer) leaves the
// teardown on its way to the stop or destroy that did not happen, and the
// resources the VM uses stay (its overlay, its probe address) until the VM is
// confirmed gone.
func (o *Orchestrator) vmGoneAfter(ctx context.Context, err error, vmid int) bool {
	return o.pveClient.VMNotFound(ctx, err, o.opts.NodeName, vmid) && o.vmMayStillExist(vmid) == nil
}

// vmOwnedNow reads the VM's own configuration and requires the exact markers of
// this run. It reports gone when PVE says the VM does not exist. A VM that is
// there without the run's markers is not the run's (a replacement at a reused
// ID, or a VM whose markers were removed): it is never stopped or destroyed,
// and the error says so.
func (o *Orchestrator) vmOwnedNow(ctx context.Context, vmid int, runID string) (gone bool, err error) {
	owned, err := o.pveClient.IsCertiStackRunOwned(ctx, o.opts.NodeName, vmid, runID)
	switch {
	case o.pveClient.VMNotFound(ctx, err, o.opts.NodeName, vmid):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("refusing to destroy VM %d: cannot verify CertiStack ownership: %w", vmid, err)
	case !owned:
		return false, fmt.Errorf("refusing to destroy VM %d: it does not carry this run's CertiStack ownership markers (a VM that reuses the ID, or one whose markers were removed); it was left alone", vmid)
	}
	return false, nil
}

func (o *Orchestrator) confirmOwnedBeforeQMFallback(ctx context.Context, vmid int, runID string) (bool, error) {
	owned, err := o.pveClient.IsCertiStackRunOwned(ctx, o.opts.NodeName, vmid, runID)
	if o.pveClient.VMNotFound(ctx, err, o.opts.NodeName, vmid) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("refusing local qm fallback for VM %d: cannot verify CertiStack ownership: %w", vmid, err)
	}
	if !owned {
		return false, fmt.Errorf("refusing local qm fallback for VM %d: ownership changed", vmid)
	}
	return true, nil
}

func (o *Orchestrator) runQMFallback(ctx context.Context, args []string) ([]byte, error) {
	if o.runQMFallbackFn != nil {
		return o.runQMFallbackFn(ctx, args)
	}
	return process.CombinedOutput(process.CommandContext(ctx, "qm", args, false))
}

// vmMayStillExist asks PVE about the exact VM and returns nil only when PVE
// answers that it does not exist. A VM that is still there, an unreadable
// answer and an empty one are all "may still exist".
func (o *Orchestrator) vmMayStillExist(vmid int) error {
	ctx := context.Background()
	status, err := o.pveClient.GetVMStatus(ctx, o.opts.NodeName, vmid)
	switch {
	case o.pveClient.VMNotFound(ctx, err, o.opts.NodeName, vmid):
		return nil
	case err != nil:
		return fmt.Errorf("sandbox VM %d cannot be confirmed gone (%v)", vmid, err)
	case status == nil:
		return fmt.Errorf("sandbox VM %d cannot be confirmed gone (PVE returned an empty status)", vmid)
	}
	return fmt.Errorf("sandbox VM %d still exists (status: %s)", vmid, status.Status)
}

func firewallPorts(probes []config.Probe) []guestnet.FirewallPort {
	seen := make(map[string]bool)
	var ports []guestnet.FirewallPort
	add := func(protocol string, port int) {
		key := fmt.Sprintf("%s/%d", protocol, port)
		if port > 0 && !seen[key] {
			seen[key] = true
			ports = append(ports, guestnet.FirewallPort{Protocol: protocol, Port: port})
		}
	}
	for _, probe := range probes {
		switch strings.ToLower(probe.Type) {
		case "http", "http_get", "tcp", "tcp_handshake", "ldap", "mssql", "smb":
			add("tcp", probe.Port)
		case "dns":
			if probe.Transport == "tcp" {
				add("tcp", probe.Port)
			} else if probe.Transport == "udp" {
				add("udp", probe.Port)
			} else {
				add("udp", probe.Port)
				add("tcp", probe.Port)
			}
		}
	}
	return ports
}

// runProbes executes all configured Stage 2 and Stage 3 probes for a VM.
// checkWireProbeTargetsNotLocal refuses a plan whose wire probes target an
// address of the worker host. Each dial checks again (synthetic.Source).
func (o *Orchestrator) checkWireProbeTargetsNotLocal() error {
	for _, tier := range o.plan.Tiers {
		for _, vm := range tier.VMs {
			for _, p := range vm.Probes {
				if !config.IsWireProbe(p.Type) || strings.TrimSpace(p.TargetIP) == "" {
					continue
				}
				if err := synthetic.CheckTargetNotLocal(p.TargetIP); err != nil {
					return fmt.Errorf("VM %d probe %q: %w", vm.VMID, p.Description, err)
				}
			}
		}
	}
	return nil
}

// wireProbeSource pins wire probes to the sandbox VNet interface and the host
// probe address setupNetwork assigned to it, so only the isolated network can
// answer them. If that address is not assigned the dial fails rather than
// falling back to the host routing table. Only unit tests, which construct an
// Orchestrator without a plan to probe local listeners, get an unbound source.
func (o *Orchestrator) wireProbeSource() synthetic.Source {
	if o.plan == nil {
		return synthetic.Source{}
	}
	return synthetic.Source{
		Interface: o.plan.Network.VNetID,
		Address:   strings.TrimSpace(o.plan.Network.ProbeIP),
	}
}

func (o *Orchestrator) runProbes(ctx context.Context, vmCfg config.VM) ([]probe.Result, bool, error) {
	return o.runProbeSet(ctx, vmCfg, false)
}

// runProbeSet runs the VM's probes in order. quiet is the soak's repeat of the
// service probes: the same probes under the same policy, but a pass
// and a skip are not announced each time, since a long soak would otherwise
// print them every few seconds; a failure is announced as ever.
func (o *Orchestrator) runProbeSet(ctx context.Context, vmCfg config.VM, quiet bool) ([]probe.Result, bool, error) {
	say := func(info func(string, string, ...any), stage, format string, args ...any) {
		if !quiet {
			info(stage, format, args...)
		}
	}
	if len(vmCfg.Probes) == 0 {
		return nil, false, fmt.Errorf("VM %d has no probes configured (at least one Stage 2/3 probe is required)", vmCfg.VMID)
	}
	// A result is credited to the VM whose probes ran, so a target another VM
	// of the plan names too is never probed on this VM's behalf.
	if err := o.checkWireTargetsOwned(vmCfg); err != nil {
		return nil, false, fmt.Errorf("VM %d: %w", vmCfg.VMID, err)
	}

	// Fault injection for chaos testing (only in a -tags=chaos build).
	if chaosEnabled && o.opts.ChaosTrigger != "" {
		switch o.opts.ChaosTrigger {
		case "panic":
			slog.Warn("CHAOS INJECTION: triggering unhandled runtime panic during probes")
			panic("CertiStack Gate 3 chaos test injection: unhandled panic")
		case "kill-daemon":
			slog.Warn("CHAOS INJECTION: violently terminating process with SIGKILL (code 137)")
			os.Exit(137)
		}
	}

	var results []probe.Result
	allPassed := true
	failures := make([]error, 0)

	// A guest that stops for good while it is probed fails at once, with
	// the reason, not at its probes' timeouts as a network error.
	ctx, cancelProbes := context.WithCancelCause(ctx)
	defer cancelProbes(nil)
	go o.watchHalt(ctx, vmCfg.VMID, cancelProbes, haltPollInterval)
	haltedCause := func() error {
		return vmStopCause(context.Cause(ctx))
	}

	haltReported := false
	for _, p := range vmCfg.Probes {
		if halt := haltedCause(); halt != nil {
			if !haltReported {
				failures = append(failures, halt)
			}
			allPassed = false
			break
		}
		slog.Info("executing probe", "vmid", vmCfg.VMID, "type", p.Type, "target", p.TargetIP, "desc", p.Description)
		stage := progressStageForProbe(p.Type)
		label := progressProbeLabel(p)
		say(progress.Info, stage, "Running %s.", label)

		timeout := time.Duration(p.TimeoutSec) * time.Second
		if timeout <= 0 {
			timeout = 15 * time.Second
		}
		var prober probe.Prober
		qgaSocket := qga.DefaultSocketPath(vmCfg.VMID)
		if o.opts.QGASocketDir != "" {
			qgaSocket = filepath.Join(o.opts.QGASocketDir, fmt.Sprintf("%d.qga", vmCfg.VMID))
		}

		switch p.Type {
		case "tcp", "tcp_handshake":
			tcp := synthetic.NewTCPProber(p.TargetIP, p.Port, timeout, p.Description)
			tcp.Source = o.wireProbeSource()
			prober = tcp
		case "http", "http_get":
			httpProber := synthetic.NewHTTPProber(p.TargetIP, p.Port, p.Path, p.TLS, p.InsecureSkipVerify, p.ExpectedStatus, timeout, p.Description, p.ServerName)
			httpProber.Source = o.wireProbeSource()
			prober = httpProber
		case "dns":
			// No domain means a listener check, not a lookup of "localhost",
			// which the worker would answer from its own /etc/hosts.
			domain := p.Domain
			if domain == "" {
				domain = p.Path
			}
			dns := synthetic.NewDNSProber(p.TargetIP, p.Port, domain, p.Transport, timeout, p.Description)
			dns.RecordType = p.RecordType
			dns.Source = o.wireProbeSource()
			prober = dns
		case "ldap":
			ldap := synthetic.NewLDAPProber(p.TargetIP, p.Port, p.BaseDN, timeout, p.Description)
			ldap.NamingContext = p.NamingContext
			ldap.Source = o.wireProbeSource()
			prober = ldap
		case "mssql":
			mssql := synthetic.NewMSSQLProber(p.TargetIP, p.Port, timeout, p.Description)
			mssql.ServerName = p.ServerName
			mssql.Source = o.wireProbeSource()
			prober = mssql
		case "smb":
			smb := synthetic.NewSMBProber(p.TargetIP, p.Port, timeout, p.Description)
			smb.Source = o.wireProbeSource()
			prober = smb
		case "qga", "qga_ping":
			cmd := p.Command
			if cmd == "" && p.Type == "qga_ping" {
				cmd = "ping"
			}
			// The agent runs a command outside its fast paths as "/bin/sh -c" in
			// the guest, and a plan handed to a run directly may not have been
			// validated under either spelling. Only the allowlist's commands
			// reach the agent, and a refused one fails the probe at once, not
			// after polling to its timeout.
			if !qgacommand.Allowed(cmd) {
				failure := fmt.Errorf("the guest command %q is not one a probe may run: it must be %s; arbitrary guest shell commands are not permitted", cmd, qgacommand.Description)
				results = append(results, probe.Result{
					Type:        "qga",
					Target:      cmd,
					Description: p.Description,
					Passed:      false,
					Error:       failure.Error(),
				})
				allPassed = false
				failures = append(failures, failure)
				progress.Error(stage, "%s → FAILED: %s", label, failure)
				continue
			}
			prober = qga.NewQGAProber(qgaSocket, cmd, p.ExpectedOutput, p.RequireQGA, timeout, p.Description)
		case "qmp", "qmp_status":
			qmpSocket := qmp.DefaultSocketPath(vmCfg.VMID)
			if o.opts.QMPSocketDir != "" {
				qmpSocket = filepath.Join(o.opts.QMPSocketDir, fmt.Sprintf("%d.qmp", vmCfg.VMID))
			}
			prober = probe.ProberFunc(func(pctx context.Context) probe.Result {
				start := time.Now()
				client, err := qmp.DialContext(pctx, qmpSocket, timeout)
				if err != nil {
					return probe.Result{
						Type:        "qmp",
						Target:      qmpSocket,
						Description: p.Description,
						Passed:      false,
						Duration:    time.Since(start),
						Error:       err.Error(),
					}
				}
				defer client.Close()
				status, err := client.QueryStatusContext(pctx)
				if err != nil {
					return probe.Result{
						Type:        "qmp",
						Target:      qmpSocket,
						Description: p.Description,
						Passed:      false,
						Duration:    time.Since(start),
						Error:       err.Error(),
					}
				}
				passed := status.Running && status.Status == "running"
				result := probe.Result{
					Type:        "qmp",
					Target:      qmpSocket,
					Description: p.Description,
					Passed:      passed,
					Duration:    time.Since(start),
					Detail:      fmt.Sprintf("status=%s running=%v", status.Status, status.Running),
				}
				if !passed {
					result.Error = fmt.Sprintf("QMP reports VM is not running (status=%s running=%v)", status.Status, status.Running)
				}
				return result
			})
		case "screendump":
			qmpSocket := qmp.DefaultSocketPath(vmCfg.VMID)
			if o.opts.QMPSocketDir != "" {
				qmpSocket = filepath.Join(o.opts.QMPSocketDir, fmt.Sprintf("%d.qmp", vmCfg.VMID))
			}
			prober = probe.ProberFunc(func(pctx context.Context) probe.Result {
				start := time.Now()
				client, err := qmp.DialContext(pctx, qmpSocket, timeout)
				if err != nil {
					return probe.Result{
						Type:        "screendump",
						Target:      qmpSocket,
						Description: p.Description,
						Passed:      false,
						Duration:    time.Since(start),
						Error:       err.Error(),
					}
				}
				defer client.Close()
				artifact, err := screendump.Capture(pctx, client, vmCfg.VMID, o.opts.ScratchDir, o.screenshotOptions()...)
				if err != nil {
					return probe.Result{
						Type:        "screendump",
						Target:      qmpSocket,
						Description: p.Description,
						Passed:      false,
						Duration:    time.Since(start),
						Error:       err.Error(),
					}
				}
				// The result keeps the image's digest, not the image: nothing
				// retains a successful capture, so its scratch copy goes now.
				o.discardScreendump(artifact)
				return probe.Result{
					Type:        "screendump",
					Target:      qmpSocket,
					Description: p.Description,
					Passed:      true,
					Duration:    time.Since(start),
					Detail:      fmt.Sprintf("captured a %dx%d console image (%d bytes as PNG); only its SHA-256 is recorded, the image is not kept", artifact.Width, artifact.Height, artifact.PNGSize),
					ImageSHA256: artifact.SHA256,
				}
			})
		default:
			failure := fmt.Errorf("unknown probe type: %s", p.Type)
			results = append(results, probe.Result{
				Type:        p.Type,
				Target:      p.TargetIP,
				Description: p.Description,
				Passed:      false,
				Error:       failure.Error(),
			})
			allPassed = false
			failures = append(failures, failure)
			progress.Error(stage, "%s → FAILED: %s", label, failure)
			continue
		}

		// Wire and hypervisor polling with backoff. A positive retries value
		// caps the number of additional executions; zero keeps the automatic
		// readiness polling.
		if config.IsWireProbe(p.Type) {
			prober = o.withAddressCheck(prober)
		}
		res, attempts := runProberWithRetry(ctx, prober, timeout, p.Retries)
		if attempts > 1 {
			if p.Retries > 0 {
				say(progress.Info, stage, "%s required %d of %d allowed probe attempts.", label, attempts, p.Retries+1)
			} else {
				say(progress.Info, stage, "%s required %d automatic probe attempts before its timeout.", label, attempts)
			}
		}

		res.Origin = probeOrigin(p.Type)
		recordProbePolicy(&res, p, timeout, attempts)
		source := o.wireProbeSource()
		addressUnavailableHint(&res, p.Type, source.Interface, source.Address)
		if halt := haltedCause(); halt != nil && !res.Passed {
			res.Error = halt.Error()
			haltReported = true
		}
		results = append(results, res)

		if !res.Passed {
			annotateReachableTargetRejection(&results[len(results)-1], vmCfg.OmittedNICs)
			res = results[len(results)-1]
			allPassed = false
			slog.Error("probe FAILED", "vmid", vmCfg.VMID, "type", p.Type, "error", res.Error)
			progress.Error(stage, "%s → FAILED: %s", label, res.Error)
			if res.Detail != "" {
				progress.Warn("Diagnosis", "VM %d: %s", vmCfg.VMID, res.Detail)
			}
			name := p.Description
			if name == "" {
				name = p.Type
			}
			failures = append(failures, fmt.Errorf("probe %q failed: %s", name, res.Error))
			continue
		}

		slog.Info("probe passed", "vmid", vmCfg.VMID, "type", p.Type, "duration", res.Duration)
		slog.Info("probe passed deterministically", "vmid", vmCfg.VMID, "type", p.Type, "duration", res.Duration)
		if res.Skipped {
			say(progress.Warn, stage, "%s → SKIPPED: %s", label, res.Detail)
		} else if res.Detail != "" {
			say(progress.Info, stage, "%s → PASSED (%s; %s).", label, res.Duration.Round(time.Millisecond), res.Detail)
		} else {
			say(progress.Info, stage, "%s → PASSED (%s).", label, res.Duration.Round(time.Millisecond))
		}
	}

	if len(failures) > 0 {
		return results, false, errors.Join(failures...)
	}
	// A VM is verified only by a guest-level assertion that ran and passed:
	// a wire probe, or a guest-agent probe that was not skipped. Optional QGA
	// probes whose guest agent did not answer are skipped, and qmp and
	// screendump probes show only that QEMU runs the VM (a guest in a boot
	// loop or at a kernel panic passes both), so a stage whose passes are all
	// of those checked nothing in the guest. Plan validation
	// refuses such a probe set; this holds for any plan that reaches the
	// stage anyway. The results stay as they are, and one failed result says
	// why the VM is unverified.
	if reason := noGuestAssertion(results); reason != "" {
		err := &vmUnverifiedError{fmt.Sprintf("VM %d is unverified: %s", vmCfg.VMID, reason)}
		results = append(results, probe.Result{
			Type:        "probe_stage",
			Target:      fmt.Sprintf("vm/%d", vmCfg.VMID),
			Description: "At least one guest-level assertion ran and passed",
			Error:       err.Error(),
		})
		progress.Error("Stage 3", "%s", err)
		return results, false, err
	}
	return results, allPassed, nil
}

// vmUnverifiedError says a VM's probes passed but none asserted anything in
// the guest, so the VM is unverified, not failed: a fault drill's injected
// failure is a failed probe, and this is the absence of any evidence.
type vmUnverifiedError struct{ message string }

func (e *vmUnverifiedError) Error() string { return e.message }

// noGuestAssertion is why no result is a guest-level assertion that ran and
// passed, or "" when one is. The verdict on a signed report applies the same
// rule (cmd/certistack verify_acceptance.go, probeIsGuestLevel).
func noGuestAssertion(results []probe.Result) string {
	skipped, hypervisor := 0, 0
	for _, res := range results {
		switch {
		case res.Skipped:
			skipped++
		case res.Passed && config.IsGuestLevelProbe(res.Type):
			return ""
		case res.Passed:
			hypervisor++
		}
	}
	switch {
	case hypervisor == 0:
		return fmt.Sprintf("all %d probes were skipped because the guest agent did not answer, so nothing was checked; set require_qga: true, or add a wire probe (tcp, http, dns, ldap, mssql or smb)", len(results))
	case skipped == 0:
		return "only its qmp or screendump probes ran, which show that QEMU runs the VM, not that the guest booted or that a service in it works; add a wire probe (tcp, http, dns, ldap, mssql or smb) or a qga probe with require_qga: true"
	default:
		return "its guest-agent probes were skipped because the agent did not answer, and its qmp or screendump probes show only that QEMU runs the VM; set require_qga: true, or add a wire probe (tcp, http, dns, ldap, mssql or smb)"
	}
}

// restoredHardware is the hardware evidence of a sandbox VM created with hw:
// every setting CreateVM sends that shapes how the guest runs, so two
// configurations that request different hardware never sign the same record. A
// test keeps it in step with pve.Hardware.
func restoredHardware(hw pve.Hardware, fromBackupConfig bool, bootSlot, smbios1 string) *probe.RestoredHardware {
	return &probe.RestoredHardware{
		FromBackupConfig: fromBackupConfig,
		Cores:            hw.Cores, Sockets: hw.Sockets, MemoryMB: hw.MemoryMB, BalloonMB: hw.BalloonMB, NoBalloon: hw.NoBalloon,
		CPU: hw.CPU, CPUWeight: hw.CPUWeight, Machine: hw.Machine, BIOS: hw.BIOS, SCSIHW: hw.SCSIHW, OSType: hw.OSType,
		NICModel: hw.NICModel, MAC: hw.MAC, BootDisk: bootSlot, BootOrder: hw.BootOrder, SMBIOSUUID: pbs.SMBIOSUUID(smbios1),
	}
}

// recordProbePolicy writes into a result the policy its probe ran under and
// its attempt history, which the signed report would otherwise leave out: two
// runs that passed under a one-second and a three-minute budget, on the first
// attempt and on the ninth, or with the guest agent required and optional,
// would sign the same result. The policy is what the
// plan asked for, and what the probe was actually given: the timeout is the
// budget runProberWithRetry enforced.
func recordProbePolicy(res *probe.Result, p config.Probe, timeout time.Duration, attempts int) {
	res.TimeoutSec = int(timeout / time.Second)
	if p.Retries > 0 {
		res.Retries = p.Retries
	}
	res.Attempts = attempts
	if p.Type == "qga" || p.Type == "qga_ping" {
		res.RequireQGA = p.RequireQGA
	}
}

// discardScreendump removes a successful screendump probe's scratch PNG. If
// it cannot be removed now, teardown tries again and reports the failure, so
// a private console image never outlives the run unnoticed.
func (o *Orchestrator) discardScreendump(artifact *screendump.Artifact) {
	if artifact == nil || artifact.PNGPath == "" {
		return
	}
	if err := os.Remove(artifact.PNGPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("could not remove the screendump probe's scratch image; teardown will retry", "path", artifact.PNGPath, "error", err)
		o.trackFailureArtifact(artifact)
		return
	}
	o.releaseScreenshotFiles(artifact.PNGPath)
}

// screenshotOptions make a capture record its files in the journal before QEMU
// writes them, and drop them from it once removed. A worker killed while a frame
// exists then leaves a record that recovery removes it by, and teardown removes
// what is still recorded when it unwinds.
func (o *Orchestrator) screenshotOptions() []screendump.Option {
	return []screendump.Option{
		screendump.WithRegister(o.registerScreenshotFiles),
		screendump.WithRemoved(o.releaseScreenshotFiles),
	}
}

// registerScreenshotFiles journals the diagnostic screenshot files about to be
// made and registers their removal at teardown.
func (o *Orchestrator) registerScreenshotFiles(paths ...string) error {
	// An orchestrator with no state directory has no journal to record in (a run
	// cannot start without one; this is the probes alone, in a test).
	if o.opts.StateDir != "" {
		o.record.AddScreenshotFiles(paths...)
		if err := o.flushJournal(); err != nil {
			o.record.DropScreenshotFiles(paths...)
			return err
		}
	}
	if o.cleanup != nil {
		o.cleanup.Push(fmt.Sprintf("remove diagnostic screenshot files %s", strings.Join(paths, ", ")), func() error {
			var errs []error
			for _, path := range paths {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, fmt.Errorf("remove diagnostic screenshot %s: %w", path, err))
				}
			}
			if len(errs) > 0 {
				return errors.Join(errs...)
			}
			o.releaseScreenshotFiles(paths...)
			return nil
		})
	}
	return nil
}

// releaseScreenshotFiles drops files that are gone from the journal. A journal
// that cannot be written leaves them recorded, which is harmless: recovery
// finds them already removed and drops them.
func (o *Orchestrator) releaseScreenshotFiles(paths ...string) {
	o.record.DropScreenshotFiles(paths...)
	if o.opts.StateDir == "" {
		return
	}
	if err := o.flushJournal(); err != nil {
		slog.Warn("could not journal the removal of screenshot files", "error", err)
	}
}

func probeOrigin(probeType string) string {
	if config.IsWireProbe(probeType) {
		return "worker_host"
	}
	switch strings.ToLower(probeType) {
	case "qga", "qga_ping":
		return "guest_qga"
	case "qmp", "qmp_status", "screendump":
		return "hypervisor_qmp"
	default:
		return "unknown"
	}
}

// runProberWithRetry runs a probe under one absolute timeout budget. A zero
// retry value preserves automatic readiness polling until that budget expires.
// A positive value is an operator-selected cap on additional executions, so
// retries: 2 permits at most three attempts. The wait is context-aware: a
// cancellation never waits for the next backoff tick.
//
// The budget is a hard acceptance boundary: a pass that a probe returns
// after the budget ran out, or after the run was interrupted, is a failure.
// A skip (an optional QGA probe whose agent did not answer in the budget)
// stays a skip unless the run was interrupted.
func runProberWithRetry(ctx context.Context, prober probe.Prober, timeout time.Duration, retries int) (probe.Result, int) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return probe.Result{Passed: false, Error: err.Error()}, 0
	}
	deadline := time.Now().Add(timeout)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}

	maxAttempts := 0 // zero means automatic attempts until the deadline.
	if retries > 0 {
		maxAttempts = retries + 1
	}
	pollInterval := 500 * time.Millisecond
	var result, completed probe.Result
	haveCompleted := false
	for attempts := 1; ; attempts++ {
		attemptCtx, cancel := context.WithDeadline(ctx, deadline)
		result = prober.Probe(attemptCtx)
		late := probe.Expired(attemptCtx)
		interrupted := late != nil
		cancel()
		if result.Passed && interrupted && (!result.Skipped || ctx.Err() != nil) {
			return latePass(ctx, result, timeout), attempts
		}
		if !interrupted {
			completed, haveCompleted = result, true
		}
		if result.Passed || ctx.Err() != nil || time.Until(deadline) <= 0 || (maxAttempts > 0 && attempts >= maxAttempts) {
			if !result.Passed && interrupted && haveCompleted && completed.Error != "" {
				// The budget expired mid-attempt, so this attempt's error is
				// only "deadline exceeded". Report what the guest actually
				// answered on the last attempt that ran to completion.
				completed.Error += " (last completed attempt; the final attempt was cut off by the probe timeout)"
				return completed, attempts
			}
			return result, attempts
		}

		wait := pollInterval
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return result, attempts
		case <-timer.C:
		}
		if pollInterval < 2*time.Second {
			pollInterval += 250 * time.Millisecond
		}
	}
}

// latePass turns a pass that came after the probe's budget ran out, or after
// the run was interrupted, into the failure it is: the answer may be true
// now, but it was not established in time.
func latePass(ctx context.Context, result probe.Result, timeout time.Duration) probe.Result {
	result.Passed, result.Skipped = false, false
	if ctx.Err() != nil {
		result.Error = fmt.Sprintf("probe result arrived after the run was interrupted (%v), so it does not count", context.Cause(ctx))
	} else {
		result.Error = fmt.Sprintf("probe result arrived after its %s budget ran out, so it does not count", timeout)
	}
	return result
}

// annotateReachableTargetRejection makes a common recovery failure actionable
// without turning a transport symptom into an unsupported claim about the
// application. A connection refusal proves that the isolated target answered;
// it does not prove whether the guest process is absent or a guest-local
// firewall rejected the port. The signed result and terminal output therefore
// direct the operator to the captured listener/firewall evidence.
func annotateReachableTargetRejection(result *probe.Result, omittedNICs []string) {
	if result == nil || result.Passed || !strings.Contains(strings.ToLower(result.Error), "connection refused") {
		return
	}
	result.Detail = "The isolated target actively rejected this port, so recovery addressing is reachable: the service is not listening, or a guest firewall rejects the port. The report's network diagnostic shows the guest's listeners and firewall when they could be read."
	if len(omittedNICs) > 0 {
		// A service that also listens on an omitted NIC's own address cannot
		// bind it, and may exit, taking its other listeners with it.
		result.Detail += fmt.Sprintf(" The sandbox VM lacks its source NIC(s) %s: a service that listens on an address of a missing NIC can fail to start and stop answering on every port. Set network_recovery.attach_all_nics to validate with all NICs.", strings.Join(omittedNICs, ", "))
	}
}

// shouldReadNetworkDiagnostic keeps the offline guestfs fallback scoped to a
// failed validation. Diagnostics are supporting evidence, never a normal
// success-path teardown operation.
func (o *Orchestrator) shouldReadNetworkDiagnostic(vmid int) bool {
	if o == nil || !o.networkDiagnosticRequested[vmid] {
		return false
	}
	// A live read without guest-exec has no listeners: the overlay's boot
	// record adds them.
	_, capturedLive := o.networkDiagnostics[vmid]
	return !capturedLive || o.networkDiagnosticPartial[vmid]
}

// ownsVMForCapture says whether the console at vmid may be photographed as the
// restored VM's: this run created a VM at that ID (it is in the journal) and
// PVE still shows the run's own markers on it. A restore that was refused
// because the ID was occupied, a VM replaced since, or one whose ownership
// cannot be read is somebody else's console, and its screenshot would put an
// unrelated guest's screen into signed evidence as the backup's.
// captureVMNeverCreated is ownsVMForCapture's reason when the run made no VM
// at the ID and PVE shows none there either.
const captureVMNeverCreated = "the run stopped before it created the VM"

func (o *Orchestrator) ownsVMForCapture(ctx context.Context, vmid int) (bool, string) {
	tracked := false
	for _, vm := range o.record.VMs {
		if vm.VMID == vmid {
			tracked = true
			break
		}
	}
	if !tracked {
		// With no VM at that ID at all, the run never made one: it stopped
		// before it got that far. A VM there, or an answer that does not say, is
		// somebody else's console or not known to be gone.
		if o.pveClient != nil {
			if _, err := o.pveClient.GetVMConfig(ctx, o.opts.NodeName, vmid); err != nil && o.pveClient.VMNotFound(ctx, err, o.opts.NodeName, vmid) {
				return false, captureVMNeverCreated
			}
		}
		return false, "this run did not create a VM with that ID"
	}
	if o.pveClient == nil {
		return false, "its ownership cannot be checked"
	}
	owned, err := o.pveClient.IsCertiStackRunOwned(ctx, o.opts.NodeName, vmid, o.runID)
	switch {
	case err != nil:
		return false, fmt.Sprintf("its ownership cannot be read (%v)", err)
	case !owned:
		return false, "it does not carry this run's CertiStack markers"
	}
	return true, ""
}

// captureFailureArtifact takes a forensic screenshot via QMP upon verification
// failure, of a VM this run created and still owns (ownsVMForCapture), and of no
// other.
func (o *Orchestrator) captureFailureArtifact(ctx context.Context, vmid int) *screendump.Artifact {
	if owned, why := o.ownsVMForCapture(ctx, vmid); !owned {
		slog.Warn("no forensic screendump of this VM: it is not shown to be the run's", "vmid", vmid, "reason", why)
		if why == captureVMNeverCreated {
			progress.Warn("Stage 4", "No console image for VM %d: %s.", vmid, why)
		} else {
			progress.Warn("Stage 4", "No console image was taken for VM %d: %s, so whatever runs under that ID is not photographed as the restored VM's.", vmid, why)
		}
		return nil
	}
	qmpSocket := qmp.DefaultSocketPath(vmid)
	if o.opts.QMPSocketDir != "" {
		qmpSocket = filepath.Join(o.opts.QMPSocketDir, fmt.Sprintf("%d.qmp", vmid))
	}
	// Within ctx, as the capture is: an interrupted run does not wait on QEMU.
	client, err := qmp.DialContext(ctx, qmpSocket, 5*time.Second)
	if err != nil {
		slog.Warn("could not connect to QMP for forensic screendump", "vmid", vmid, "error", err)
		return nil
	}
	defer client.Close()

	artifact, err := screendump.Capture(ctx, client, vmid, o.opts.ScratchDir, o.screenshotOptions()...)
	if err != nil {
		slog.Warn("failed to capture forensic screendump", "vmid", vmid, "error", err)
		return nil
	}
	progress.Info("Stage 4", "Forensic framebuffer capture completed for VM %d (%dx%d).", vmid, artifact.Width, artifact.Height)

	return artifact
}

// recordEmptyCDROMs records the empty CD-ROM drives the sandbox VM actually
// has, read back from PVE, and says which of the source's it lacks (a token
// without VM.Config.CDROM on a node where local qm is unavailable).
func (o *Orchestrator) recordEmptyCDROMs(ctx context.Context, record *probe.VMValidationRecord, vmCfg config.VM) {
	cfg, err := o.pveClient.GetVMConfig(ctx, o.opts.NodeName, vmCfg.VMID)
	if err != nil {
		progress.Warn("Sandbox", "Could not read back VM %d's CD-ROM drives: %v", vmCfg.VMID, err)
		return
	}
	var missing []string
	for _, slot := range vmCfg.SourceCDROMs {
		if value, _ := cfg[slot].(string); strings.Contains(value, "media=cdrom") {
			if record.RestoredHardware != nil {
				record.RestoredHardware.EmptyCDROMs = append(record.RestoredHardware.EmptyCDROMs, slot)
			}
		} else {
			missing = append(missing, slot)
		}
	}
	if len(missing) > 0 {
		progress.Warn("Sandbox", "VM %d lacks the source's CD-ROM drive(s) %s, so its guest sees a controller missing that a restore would keep; grant VM.Config.CDROM to the API token.", vmCfg.VMID, strings.Join(missing, ", "))
	}
}

// captureLiveNetworkDiagnostic requests narrow network state through QGA while
// a failed sandbox is still running. It is diagnostic-only: agent
// unavailability remains non-fatal and is handled by the caller. The second
// result names a recovery address that never reached the recovered NIC.
func (o *Orchestrator) captureLiveNetworkDiagnostic(ctx context.Context, vmid int, recoveredMAC, recoveryAddress string) (diagnostic, diagnosis string, complete bool, err error) {
	socket := qga.DefaultSocketPath(vmid)
	if o.opts.QGASocketDir != "" {
		socket = filepath.Join(o.opts.QGASocketDir, fmt.Sprintf("%d.qga", vmid))
	}
	// Within ctx: an interrupted run does not wait on a guest agent that has
	// nothing to say.
	client, err := qga.DialContext(ctx, socket, 5*time.Second)
	if err != nil {
		return "", "", false, err
	}
	defer client.Close()

	interfaces, interfaceErr := client.GetNetworkInterfacesContext(ctx, 5*time.Second)
	if interfaceErr != nil {
		return "", "", false, interfaceErr
	}
	diagnostic = formatGuestInterfaces(interfaces)
	diagnosis = qga.CleanGuestText(recoveryAddressDiagnosis(interfaces, recoveredMAC, recoveryAddress))
	if diagnosis != "" {
		diagnostic = "[diagnosis] " + diagnosis + "\n" + diagnostic
	}
	execution, execErr := client.Exec(ctx, guestNetworkDiagnosticCommand, 250*time.Millisecond, 10*time.Second)
	if execErr != nil {
		// Hardened images often expose the safe inventory RPC while explicitly
		// disabling guest-exec. The inventory is still decisive evidence that
		// does not require any in-guest change, but it holds no listeners.
		return normalizeNetworkDiagnostic(diagnostic + "\n[guest-exec unavailable: " + execErr.Error() + "]"), diagnosis, false, nil
	}
	if !execution.Succeeded() {
		return normalizeNetworkDiagnostic(diagnostic + "\n[guest diagnostic command " + execution.Outcome() + ": " + strings.TrimSpace(execution.Stderr) + "]"), diagnosis, false, nil
	}
	return normalizeNetworkDiagnostic(diagnostic + "\n" + execution.Stdout), diagnosis, true, nil
}

// recoveryAddressDiagnosis explains a failure whose cause is that the guest
// never took its recovery address: the recovered NIC answers the agent but
// carries other IPv4 addresses, typically its own original configuration.
func recoveryAddressDiagnosis(interfaces []qga.NetworkInterface, mac, want string) string {
	if mac == "" || want == "" {
		return ""
	}
	for _, iface := range interfaces {
		if !strings.EqualFold(iface.HardwareAddress, mac) {
			continue
		}
		var have []string
		for _, address := range iface.IPAddresses {
			if ip := net.ParseIP(address.IPAddress); ip == nil || ip.To4() == nil {
				continue
			}
			if address.IPAddress == want {
				return ""
			}
			have = append(have, fmt.Sprintf("%s/%d", address.IPAddress, address.Prefix))
		}
		if len(have) == 0 {
			return fmt.Sprintf("guest NIC %s (%s) has no IPv4 address; the recovery address %s was not applied", iface.Name, mac, want)
		}
		return fmt.Sprintf("network recovery did not take effect: guest NIC %s (%s) has %s, not the recovery address %s, so the guest's own network configuration won", iface.Name, mac, strings.Join(have, ", "), want)
	}
	return ""
}

func formatGuestInterfaces(interfaces []qga.NetworkInterface) string {
	var b strings.Builder
	b.WriteString("[interfaces via QGA]\n")
	for _, iface := range interfaces {
		fmt.Fprintf(&b, "%s %s", iface.Name, iface.HardwareAddress)
		for _, address := range iface.IPAddresses {
			fmt.Fprintf(&b, " %s/%d", address.IPAddress, address.Prefix)
		}
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String())
}

// recordNetworkDiagnostics puts each VM's captured network diagnostic into its
// record. Whichever way it was captured (live through the agent, or read back
// from the file the guest wrote into the overlay), it is the guest's text, so
// it is cleaned and bounded here, once, on its way into the signed report.
func (o *Orchestrator) recordNetworkDiagnostics(records []probe.VMValidationRecord) {
	for i := range records {
		if diagnostic, ok := o.networkDiagnostics[records[i].VMID]; ok {
			records[i].NetworkRecoveryDiagnostic = normalizeNetworkDiagnostic(diagnostic)
		}
	}
}

// normalizeNetworkDiagnostic bounds a guest diagnostic, live or read back from
// the overlay, and strips what could hide or reorder text in it. Everything in
// it is text the guest chose (interface names, command output, the agent's own
// error messages, a file its boot script wrote), and it is printed and kept, so
// it never leaves here with a terminal escape sequence or a bidirectional
// control, or longer than 16 KiB.
func normalizeNetworkDiagnostic(output string) string {
	const maximum = 16 << 10
	output = strings.TrimSpace(qga.CleanGuestText(output))
	if len(output) > maximum {
		// The cut may fall inside a character; what is left of it goes.
		return strings.ToValidUTF8(output[:maximum], "") + "\n[truncated]"
	}
	return output
}

func progressStageForProbe(probeType string) string {
	switch strings.ToLower(probeType) {
	case "qga", "qga_ping":
		return "Stage 3"
	case "screendump":
		return "Stage 4"
	default:
		return "Stage 2"
	}
}

func progressProbeLabel(p config.Probe) string {
	typeName := strings.ToUpper(p.Type)
	if p.Type == "http" || p.Type == "http_get" {
		scheme := "http"
		if p.TLS {
			scheme = "https"
		}
		path := p.Path
		if path == "" {
			path = "/"
		}
		return fmt.Sprintf("%s GET %s://%s:%d%s", strings.ToUpper(scheme), scheme, p.TargetIP, p.Port, path)
	}
	if p.Description != "" {
		return fmt.Sprintf("%s probe: %s", typeName, p.Description)
	}
	if p.TargetIP != "" {
		return fmt.Sprintf("%s probe: %s:%d", typeName, p.TargetIP, p.Port)
	}
	return typeName + " probe"
}

// trackFailureArtifact removes the transient scratch PNG during the normal
// LIFO unwind. The report stores the encoded image, so the scratch copy is not
// needed after report generation and must not accumulate across failed runs.
func (o *Orchestrator) trackFailureArtifact(artifact *screendump.Artifact) {
	if artifact == nil || artifact.PNGPath == "" || o.cleanup == nil {
		return
	}
	path := artifact.PNGPath
	o.cleanup.Push(fmt.Sprintf("remove forensic screenshot %s", path), func() error {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove forensic screenshot %s: %w", path, err)
		}
		return nil
	})
}

// sandboxVMConfig is the sandbox VM a run creates for vmCfg: the resolved
// plan's hardware, the overlays and firmware copies, the ownership markers,
// and NICs only on the sandbox VNet. The plan command shows the same
// configuration (CreateParams).
func (o *Orchestrator) sandboxVMConfig(vmCfg config.VM, pveDisks []pve.DiskOverlay, bootSlot string, firmwareVolumes []pve.FirmwareVolume) pve.VMConfig {
	cpuWeight := vmCfg.HardwareOverrides.CPUWeight
	if cpuWeight <= 0 {
		cpuWeight = 50
	}
	return pve.VMConfig{
		VMID:            vmCfg.VMID,
		Name:            vmCfg.Name,
		RunID:           o.runID,
		Cores:           vmCfg.HardwareOverrides.Cores,
		Sockets:         vmCfg.HardwareOverrides.Sockets,
		MemoryMB:        vmCfg.HardwareOverrides.MemoryMB,
		BalloonMB:       vmCfg.HardwareOverrides.BalloonMB,
		NoBalloon:       vmCfg.NoBalloon,
		SMBIOS1:         vmCfg.SMBIOS1,
		EmptyCDROMs:     vmCfg.SourceCDROMs,
		CPUWeight:       cpuWeight,
		DiskOverlays:    pveDisks,
		BootDisk:        bootSlot,
		BootOrder:       vmCfg.BootOrder,
		AdditionalNICs:  pveNICs(vmCfg.AdditionalNICs),
		FirmwareVolumes: firmwareVolumes,
		Bridge:          o.plan.Network.VNetID,
		MAC:             vmCfg.MAC,
		NICModel:        vmCfg.NICModel,
		Machine:         vmCfg.Machine,
		OSType:          vmCfg.OSType,
		BIOS:            vmCfg.BIOS,
		SCSIHW:          vmCfg.SCSIHW,
	}
}

// sandboxVMWithEvidence is the configuration CreateVM sends PVE for vmCfg's
// sandbox VM, with the hardware it requests recorded in the VM's evidence from
// that same configuration: what the signed report says the guest ran with is
// what was asked of PVE, the CPU weight included. bootAndVerifyVM
// creates the VM from the configuration returned, so there is no second place
// for the request and the record to disagree.
func (o *Orchestrator) sandboxVMWithEvidence(ctx context.Context, vmCfg config.VM, pveDisks []pve.DiskOverlay, bootSlot string, firmwareVolumes []pve.FirmwareVolume, record *probe.VMValidationRecord) pve.VMConfig {
	pveVMConfig := o.sandboxVMConfig(vmCfg, pveDisks, bootSlot, firmwareVolumes)
	o.pinWindowsMachine(ctx, vmCfg, &pveVMConfig)
	hw := pveVMConfig.EffectiveHardware()
	record.RestoredHardware = restoredHardware(hw, o.plan.UseBackupConfig, bootSlot, vmCfg.SMBIOS1)
	for _, nic := range vmCfg.AdditionalNICs {
		record.RestoredHardware.AdditionalNICs = append(record.RestoredHardware.AdditionalNICs, nic.Slot+" "+nic.Model+" "+nic.MAC)
	}
	record.OmittedNICs = append([]string(nil), vmCfg.OmittedNICs...)
	for _, firmware := range firmwareVolumes {
		record.RestoredHardware.FirmwareDisks = append(record.RestoredHardware.FirmwareDisks, strings.TrimSpace(firmware.Slot+" "+firmware.Options))
	}
	return pveVMConfig
}

// pinWindowsMachine pins a Windows sandbox VM with an unversioned machine
// type to the machine version a restore of its backup starts it on.
func (o *Orchestrator) pinWindowsMachine(ctx context.Context, vmCfg config.VM, pveVMConfig *pve.VMConfig) {
	// A restore starts a Windows guest with an unversioned machine type on
	// the machine version of the QEMU that created it; the sandbox VM, whose
	// meta line PVE writes itself, is pinned to that version where it differs.
	if windowsOSType(pveVMConfig.EffectiveHardware().OSType) && unversionedMachine(pveVMConfig.Machine) {
		if machines, err := o.pveClient.QEMUMachines(ctx, o.opts.NodeName); err != nil {
			progress.Warn("Sandbox", "Could not read node %s's QEMU machine versions, so VM %d starts on the node's latest one, which a restore of its backup may not: %v", o.opts.NodeName, vmCfg.VMID, err)
		} else if pinned, ok := windowsRestoreMachine(pveVMConfig.Machine, vmCfg.SourceMeta, machines); ok {
			progress.Info("Sandbox", "VM %d runs %s, the machine a restore of its backup starts it on (%s).", vmCfg.VMID, pinned, orNone(vmCfg.SourceMeta))
			pveVMConfig.Machine = pinned
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package recovery provides safe crash recovery and reconciliation of orphaned
// loop devices, scratch overlays, and processes after abnormal terminations.
package recovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/sdn"
)

// LoopBacking returns the kernel-backed identity for a loop device. It remains
// exported here for recovery callers while the shared implementation also lets
// the orchestrator persist the same identity at map time.
func LoopBacking(device string) (string, error) {
	return sysutil.LoopBacking(device)
}

// Inspect loads the current active journal record from stateDir.
func Inspect(stateDir string) (*journal.Record, error) {
	path := filepath.Join(stateDir, "active.json")
	r, err := journal.Load(path)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// Recover inspects and safely reconciles recorded loop devices, processes, and scratch overlays.
// It explicitly verifies identities before taking any destructive action to prevent collateral damage.
// It cannot be interrupted: a caller that can be (the certistack recover
// command) uses RecoverContext.
func Recover(stateDir string) error {
	return RecoverContext(context.Background(), context.Background(), stateDir)
}

// RecoverContext is Recover for a caller that can be interrupted; see
// RecoverLockedContext for what ctx and abandon do.
func RecoverContext(ctx, abandon context.Context, stateDir string) error {
	if stateDir == "" {
		stateDir = "/var/lib/certistack"
	}

	lock, err := journal.Lock()
	if err != nil {
		return fmt.Errorf("cannot acquire host lock for recovery: %w", err)
	}
	defer lock.Close()
	return RecoverLockedContext(ctx, abandon, stateDir)
}

// RecoverLocked reconciles an interrupted validation while the caller owns
// the host execution lock from journal.Lock. It exists so a node worker can
// keep recovery, preflight, and a replacement validation mutually exclusive.
// Callers that do not already hold that lock must use Recover.
func RecoverLocked(stateDir string) error {
	return RecoverLockedContext(context.Background(), context.Background(), stateDir)
}

// RecoverLockedContext is RecoverLocked for a caller that can be interrupted.
// The two contexts are the two interrupts an operator can give.
//
// ctx is the first: recovery starts no further step, and ends the waits it
// can end: its PVE work (a stop or destroy task PVE already runs goes on
// there, and an SDN lock or apply it had begun stays journaled for the next
// recovery), its read of what PVE says remains, the stop of what holds a PBS
// map's loop, the wait for a loop detach to finish (the detach already issued
// goes on in the kernel) and the wait for the loop to leave it, and the release
// of an interrupted map's stale loop. It reports every step it did not start.
// What is already running and cannot be ended safely is not cut short: one
// host probe address's removal (the address, then its table), the kill of a
// recorded QEMU or mapper process and the wait for it to exit (at most thirty
// seconds), the stop of a map's daemon, and the unmap of a map a killed worker
// began but never recorded. Each ends on its own bound.
// abandon is the second interrupt: it also cuts short the kernel commands of
// a host probe address's removal that are running; the others above continue.
// What is interrupted leaves the journal unresolved (cleanup_failed, with the
// reasons), never cleaned, and the error wraps the interrupt, so a command
// that returns it ends as an interrupted one. A recovery that finished every
// step before the interrupt is complete, its journal is cleaned, and it
// returns nil.
func RecoverLockedContext(ctx, abandon context.Context, stateDir string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if abandon == nil {
		abandon = context.Background()
	}
	if stateDir == "" {
		stateDir = "/var/lib/certistack"
	}

	path := filepath.Join(stateDir, "active.json")
	r, err := journal.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		slog.Info("no active journal found to recover", "path", path)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to load journal from %s: %w", path, err)
	}

	if r.Phase == "cleaned" {
		slog.Info("recorded run is already marked cleaned", "run_id", r.RunID)
		return nil
	}

	slog.Info("initiating crash recovery reconciliation", "run_id", r.RunID, "phase", r.Phase)
	defer keepLog(stateDir, r.RunID)()
	say("INFO", "Recovering what run %s left (its journal stopped at %q).", r.RunID, r.Phase)

	var errs []error

	// An interrupt (ctx, or abandon for the second) starts no further step: a
	// step it keeps from starting is reported and left to the next recovery.
	// Steps are never skipped past one another's dependencies: what was not
	// stopped stays in running, and what the VMs may use is then kept.
	interrupted := func() error {
		if cause := ctx.Err(); cause != nil {
			return cause
		}
		return abandon.Err()
	}
	notStarted := func(step string) bool {
		cause := interrupted()
		if cause == nil {
			return false
		}
		errs = append(errs, fmt.Errorf("not started: %s: recovery was interrupted: %w", step, cause))
		return true
	}

	// 1. Use PVE's lifecycle API to stop and destroy the exact VMs recorded by
	// this run before touching node-local processes. A valid controller worker
	// environment is required when a journal contains PVE resources; recovery
	// refuses to guess a node or operate on an unverified VM.
	if err := recoverPVEResources(ctx, &r, path); err != nil {
		errs = append(errs, err)
	}

	// 2. Terminate QEMU processes (legacy single QEMU + multi-VM records).
	// The process identity check remains a last-resort local safeguard if an API
	// task was interrupted between PVE state changes.
	var running []string // recorded QEMU processes not confirmed stopped
	if r.QEMU.PID > 0 {
		if notStarted(fmt.Sprintf("stopping recorded QEMU process %d", r.QEMU.PID)) {
			running = append(running, fmt.Sprintf("QEMU process %d was not stopped (recovery was interrupted)", r.QEMU.PID))
		} else {
			slog.Info("reconciling recorded legacy QEMU process", "pid", r.QEMU.PID)
			if err := process.StopRecorded(r.QEMU); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop recorded QEMU process %d: %w", r.QEMU.PID, err))
				if !errors.Is(err, process.ErrPIDReused) {
					running = append(running, fmt.Sprintf("QEMU process %d was not confirmed stopped", r.QEMU.PID))
				}
			}
		}
	}
	for _, vm := range r.VMs {
		if vm.Process.PID > 0 && vm.Process.PID != r.QEMU.PID {
			if notStarted(fmt.Sprintf("stopping QEMU process %d of VM %d", vm.Process.PID, vm.VMID)) {
				running = append(running, fmt.Sprintf("VM %d's QEMU process %d was not stopped (recovery was interrupted)", vm.VMID, vm.Process.PID))
				continue
			}
			slog.Info("reconciling recorded VM QEMU process", "vmid", vm.VMID, "pid", vm.Process.PID)
			if err := process.StopRecorded(vm.Process); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop QEMU process for VM %d (pid %d): %w", vm.VMID, vm.Process.PID, err))
				if !errors.Is(err, process.ErrPIDReused) {
					running = append(running, fmt.Sprintf("VM %d's QEMU process %d was not confirmed stopped", vm.VMID, vm.Process.PID))
				}
			}
		}
	}

	// What the sandbox VMs use (the host probe addresses and containment on
	// their VNet, the PBS maps, the map process, and the overlays) goes in
	// steps 3 to 6 only once every VM and QEMU process is confirmed gone: one
	// that is not may still run and use it. Otherwise it stays in place, and
	// in the journal for the next attempt. released is what this attempt
	// releases; the journal record r keeps everything.
	released := r
	remain := vmsMayRemain(ctx, &r, running)
	if remain != nil {
		switch kept := vmDependencies(&r); {
		case kept != "":
			errs = append(errs, fmt.Errorf("kept %s in place: %w; the next recovery releases them once the VMs are gone%s", kept, remain, vnetDeletionNote(&r)))
			say("WARN", "Kept %s in place: %v.", kept, remain)
		case len(errs) == 0:
			// Steps 1 and 2 normally say so already; either way the
			// journal is not clean while a VM may remain.
			errs = append(errs, remain)
		}
		released.HostAddresses, released.Loops, released.LoopDevice, released.Mapper, released.DeltaFiles = nil, nil, "", journal.Process{}, nil
	}

	// 3. Remove only host probe addresses durably registered to this run.
	// Recovery never guesses a bridge or subnet from a filename or plan ID.
	pendingIface, pendingCIDR, pendingHost := r.PendingHostAddressAllocation()
	pendingWasRecorded := pendingHost && hasHostAddress(r.HostAddresses, pendingIface, pendingCIDR)
	for _, address := range released.HostAddresses {
		if notStarted(fmt.Sprintf("removing host probe address %s on %s", address.CIDR, address.Interface)) {
			continue
		}
		// The kernel commands of one address's removal (the address, then its
		// table) run under abandon, not ctx: a first interrupt does not stop
		// them half way, since the table must follow the address it was
		// installed for, and the second one does.
		opCtx, cancel := context.WithTimeout(abandon, 15*time.Second)
		// The interface index and the table handle are numbers of one boot's
		// kernel: a record of another boot is of objects that went with that
		// boot, and an interface or table of that name now is a replacement
		// that happens to carry the same numbers. Nothing is read or removed for
		// it: the record is settled. A boot that cannot be compared with this
		// one (this boot's identity cannot be read) leaves it unresolved.
		// A record without a boot is reconciled by the numbers alone.
		other, bootErr := hostAddressOfAnotherBoot(address)
		switch {
		case bootErr != nil:
			errs = append(errs, bootErr)
			cancel()
			continue
		case other:
			say("WARN", "%s.", settledWithItsBoot(address))
			r.DropHostAddress(address.Interface, address.CIDR)
			cancel()
			continue
		}
		// A record with the kernel's identities removes only what still
		// carries them. One without them (the identity could not be read when
		// the address was added, or the journal is from a version that did not
		// record it) cannot be told from an interface or table of the same name
		// that someone else made, so nothing is deleted: the journal stays
		// unresolved and the operator is told what to check and remove. What
		// carries other identities is left and reported, and is not a failure:
		// nothing of the run's is left there.
		if missing := missingHostIdentity(address); missing != "" {
			slog.Warn("recorded host probe address has no recorded identity; leaving it", "interface", address.Interface, "cidr", address.CIDR, "missing", missing)
			errs = append(errs, noHostIdentityError(address, missing))
			cancel()
			continue
		}
		if address.ContainmentOnly {
			slog.Info("reconciling recorded host probe containment", "interface", address.Interface, "cidr", address.CIDR)
			notes, err := sysutil.RemoveRecordedContainment(opCtx, address.Interface, address.CIDR, address.TableHandle)
			for _, note := range notes {
				say("WARN", "%s.", note)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to remove host probe containment for %s on %s: %w", address.CIDR, address.Interface, err))
			} else {
				r.DropHostAddress(address.Interface, address.CIDR)
			}
		} else {
			slog.Info("reconciling recorded host probe address", "interface", address.Interface, "cidr", address.CIDR)
			notes, err := sysutil.RemoveRecordedHostAddress(opCtx, address.Interface, address.CIDR, address.IfIndex, address.TableHandle)
			for _, note := range notes {
				say("WARN", "%s.", note)
			}
			switch {
			case errors.Is(err, sysutil.ErrContainmentLeft):
				// The address is gone and only the table is left: the journal
				// kept for the next attempt must not delete the address again,
				// which another address of the same CIDR on the same interface
				// since is not the run's to lose.
				r.SetHostContainmentOnly(address.Interface, address.CIDR)
				errs = append(errs, fmt.Errorf("failed to remove host probe address %s from %s: %w", address.CIDR, address.Interface, err))
			case err != nil:
				errs = append(errs, fmt.Errorf("failed to remove host probe address %s from %s: %w", address.CIDR, address.Interface, err))
			default:
				say("INFO", "Removed probe address %s from %s.", address.CIDR, address.Interface)
				r.DropHostAddress(address.Interface, address.CIDR)
			}
		}
		cancel()
	}

	// 3b. A host probe address whose addition was started and never recorded
	// (allocation_pending): a crash between the journal write that
	// precedes the addition and the one that records it. If the journal also
	// recorded the address, step 3 has settled it (or failed, and the
	// allocation stays with the record). Otherwise the host is read, and what
	// the run's addition made is removed only when it is shown to be the run's
	// (sysutil.SettleUnconfirmedHostAddress). While a VM may still use the
	// sandbox network nothing is touched, as for a recorded address.
	if pendingHost && remain == nil {
		switch {
		case pendingWasRecorded && hasHostAddress(r.HostAddresses, pendingIface, pendingCIDR):
			// Step 3 could not remove it: the record keeps it, and the
			// allocation with it.
		case pendingWasRecorded:
			r.AllocationPending = ""
		case notStarted(fmt.Sprintf("settling the host probe address %s on %s that the interrupted run was adding", pendingCIDR, pendingIface)):
			// The allocation stays pending in the journal.
		default:
			opCtx, cancel := context.WithTimeout(abandon, 30*time.Second)
			slog.Info("settling an unconfirmed host probe address", "interface", pendingIface, "cidr", pendingCIDR)
			notes, err := sysutil.SettleUnconfirmedHostAddress(opCtx, pendingIface, pendingCIDR)
			cancel()
			for _, note := range notes {
				say("INFO", "%s.", note)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("could not settle the host probe address %s on %s that the interrupted run was adding: %w", pendingCIDR, pendingIface, err))
			} else {
				r.AllocationPending = ""
			}
		}
		if r.AllocationPending == "" {
			r.UpdatedAt = time.Now().UTC()
			if err := journal.Write(path, r); err != nil {
				errs = append(errs, fmt.Errorf("journal that the host probe address allocation is settled: %w", err))
				r.AllocationPending = journal.HostAddressPending(pendingCIDR, pendingIface)
			}
		}
	}

	// 4. Unmap loop devices (legacy single device + multi-loop records)
	allLoops := released.Loops
	if released.LoopDevice != "" {
		hasSingle := false
		for _, l := range allLoops {
			if l.Device == released.LoopDevice {
				hasSingle = true
				break
			}
		}
		if !hasSingle {
			allLoops = append(allLoops, journal.TrackedLoop{Device: released.LoopDevice, Backing: released.LoopBacking})
		}
	}

	owned := make([]sysutil.LoopIdentity, 0, len(allLoops))
	for _, loop := range allLoops {
		owned = append(owned, sysutil.LoopIdentity{Device: loop.Device, Backing: loop.Backing})
	}
	for _, loop := range allLoops {
		if notStarted(fmt.Sprintf("releasing loop device %s", loop.Device)) {
			continue
		}
		// A PBS map's backing file is named after its repository, whose user
		// part can name an API token: it is compared, never printed.
		slog.Info("reconciling recorded loop device", "device", loop.Device)
		if err := releaseRecordedLoop(ctx, r.MapIntentOfLoop(loop.Device), loop, owned); err != nil {
			errs = append(errs, err)
		}
	}

	// 4b. Unmap maps a killed worker began but never recorded.
	// What recovery learns about their processes is journaled before it
	// signals them, for a later attempt.
	persist := func() error {
		r.UpdatedAt = time.Now().UTC()
		return journal.Write(path, r)
	}
	if open := r.OpenMapIntents(); len(open) > 0 && !notStarted("unmapping the PBS maps a killed worker began") {
		if err := UnmapLeakedMaps(open, trackedLoops(r), persist); err != nil {
			errs = append(errs, err)
		}
	}

	// 4c. A map killed while its daemon started can leave a loop the daemon
	// attached and then died without detaching, after which the file behind it is
	// gone and nothing names it. A stale FUSE loop that was not stale when the
	// run's first map began, and no more of them than the run has maps that never
	// reported a loop, is that: it is detached.
	if err := releaseStaleLoopsOf(ctx, &r); err != nil {
		errs = append(errs, err)
	}

	// 5. Terminate mapper process if recorded
	if released.Mapper.PID > 0 && !notStarted(fmt.Sprintf("stopping recorded mapper process %d", released.Mapper.PID)) {
		slog.Info("reconciling recorded mapper process", "pid", released.Mapper.PID)
		if err := process.StopRecorded(released.Mapper); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop recorded mapper process %d: %w", released.Mapper.PID, err))
		}
	}

	// 6. Remove recorded delta overlay files. One with a recorded identity is
	// removed only while it is still the file the run created there: what
	// else is at the path is not this run's, and is left and reported. A path
	// without one (an entry journaled without an identity, or a staging file
	// named with the run's unguessable token) is removed by path, and only when
	// it is named as the run's disk files are (removeUnidentifiedDelta).
	for _, delta := range released.DeltaFiles {
		if delta != "" && notStarted(fmt.Sprintf("removing recorded delta overlay %s", delta)) {
			continue
		}
		if identity, ok := released.DeltaIdentity(delta); ok && delta != "" {
			slog.Info("unlinking recorded ephemeral delta overlay after checking its identity", "path", delta)
			switch err := sysutil.RemoveIfSame(delta, identity); {
			case errors.Is(err, sysutil.ErrNotOurs):
				errs = append(errs, fmt.Errorf("left %s in place: it is not the file the interrupted run created there, so it is not removed; inspect it, then remove it or its entry in the journal by hand", delta))
			case err != nil:
				errs = append(errs, fmt.Errorf("failed to remove recorded delta overlay %s: %w", delta, err))
			default:
				say("INFO", "Removed %s.", delta)
			}
			continue
		}
		if delta != "" {
			if err := removeUnidentifiedDelta(delta); err != nil {
				errs = append(errs, err)
			}
		}
	}

	// 6b. Remove the diagnostic screenshot files the run journaled before it
	// asked QEMU to write them. Only a file recorded in this journal, in the
	// run's scratch directory and named as a screenshot of CertiStack's is
	// removed, and only when it is a regular file: nothing is swept by name.
	for _, shot := range append([]string(nil), r.ScreenshotFiles...) {
		if notStarted(fmt.Sprintf("removing recorded screenshot file %s", shot)) {
			continue
		}
		switch err := removeScreenshotFile(r.Scratch, shot); {
		case err != nil:
			errs = append(errs, err)
		default:
			r.DropScreenshotFiles(shot)
		}
	}

	// Never infer ownership from a filename, backing path, or a broad /tmp
	// sweep. A crash can only clean resources durably registered to this run.
	// A request that may have reached PVE but was not durably confirmed has the
	// opposite problem: deleting it would risk removing somebody else's object.
	// Preserve the exact pending identity for an operator to reconcile instead
	// of treating an inconclusive allocation as clean.
	if r.AllocationPending != "" {
		errs = append(errs, fmt.Errorf("cannot safely reconcile unconfirmed allocation %q; review the named PVE resource before retrying", r.AllocationPending))
	}

	if len(errs) > 0 {
		if cause := interrupted(); cause != nil {
			// What is not done stays journaled: the error says so, and wraps the
			// interrupt, so the command ends as an interrupted one.
			say("WARN", "Recovery was interrupted: what it had not finished stays in the journal; "+recoverhint.Again+".")
			errs = append(errs, fmt.Errorf("recovery was interrupted: %w; the journal keeps what is left, "+recoverhint.Again, cause))
		}
		// Preserve a non-cleaned phase and every durable resource identity so a
		// later controller worker can retry reconciliation. Marking this record
		// cleaned here would turn a transient API or credential error into an
		// orphaned VM, VNet, loop device, or overlay.
		r.Phase = "cleanup_failed"
		r.UpdatedAt = time.Now().UTC()
		for _, e := range errs {
			r.CleanupErrors = append(r.CleanupErrors, e.Error())
		}
		if writeErr := journal.Write(path, r); writeErr != nil {
			errs = append(errs, fmt.Errorf("persist failed recovery journal: %w", writeErr))
		}
		say("ERROR", "Recovery of run %s is incomplete (%d problem(s)); the journal keeps what is left for the next attempt.", r.RunID, len(errs))
		for _, e := range errs {
			logLine("ERROR", "  %v", e)
		}
		return errors.Join(errs...)
	}

	r.Phase = "cleaned"
	r.UpdatedAt = time.Now().UTC()
	r.CleanupErrors = nil
	if err := journal.Write(path, r); err != nil {
		return fmt.Errorf("persist completed recovery journal: %w", err)
	}
	slog.Info("crash recovery reconciliation completed successfully", "run_id", r.RunID)
	say("INFO", "Recovered run %s: its journal is clean.", r.RunID)
	return nil
}

// releaseRecordedLoop releases the loop device the journal recorded for one
// of the run's maps, intent being the map's intent (zero when the journal has
// none), and only while the device still backs the recorded file: a loop
// number is reused once the run's map is gone, and then belongs to another
// operation's map or an ordinary loop, which is left alone.
//   - A device that is gone is the desired end state.
//   - One that backs another file is no longer the run's: it is left, and that
//     is the end state too, unless something of the run's map remains (its
//     daemon or its FUSE mount), which is an error.
//   - One whose backing cannot be read, or that has no recorded identity, is
//     an error: nothing is done to it.
//   - One that still backs a recorded file outside the map run directory is
//     not a loop a run made (a run journals only its PBS maps' loops): it is
//     left attached, with what the host assembled on it, and is an error.
//   - One that is released also has the map's FUSE mount detached and its map
//     file and pid file removed (removeReleasedMapFiles), as a map found through
//     its intent has: a daemon that was killed leaves them. Not when the pid
//     file named a process that is not the run's map: the loop is only detached.
//   - One that is gone gets the same removal, so that one that failed when the
//     loop was released is retried by the next recovery; it is a no-op when
//     nothing is left.
//
// owned is every loop the journal records: devices the host assembled from the
// partitions of these (see sysutil.ReleaseLoopHolders) are stopped before the
// unmap, and only when all their members are among them.
func releaseRecordedLoop(ctx context.Context, intent journal.MapIntent, loop journal.TrackedLoop, owned []sysutil.LoopIdentity) error {
	state, err := sysutil.CheckLoop(loop.Device, loop.Backing)
	switch {
	case err != nil:
		return fmt.Errorf("inspect recorded loop device %s: %w", loop.Device, err)
	case state == sysutil.LoopGone:
		// The prior worker may have detached it just before it was interrupted,
		// or an earlier recovery released it and could not remove the map's
		// mount and files: they are still the run's to remove, and nothing is
		// done when nothing is left.
		return removeReleasedMapFiles(intent, loop.Device, loop.Backing)
	case state == sysutil.LoopReused:
		return settleReusedLoop(ctx, loop)
	case !IsPBSMapBacking(loop.Backing):
		// A run journals a loop only for a PBS map, whose file is in the map run
		// directory: one on another file (a corrupt or hand-edited journal) is
		// not the run's, and neither it nor what is assembled on it is touched.
		return fmt.Errorf("left %s attached: the journal records it on %s, which is not a PBS map file in %s, and a run journals only the loops of its PBS maps, so nothing shows it is the interrupted run's; check what uses it, detach it yourself only if it is the run's, delete its entry in loops of the journal, and "+recoverhint.Again, loop.Device, loop.Backing, hostLeakFinder.runDir)
	}
	// The map's daemon is stopped only when the pid file shows it is the run's
	// own (or names no live process): what else the pid file names is not
	// signalled.
	guard, why := hostMapReaper.unmapGuardFor(loop.Backing, intent)
	var stopDaemon func() error
	switch guard {
	case unmapUnknown:
		return fmt.Errorf("left %s attached: %s; "+recoverhint.Again, loop.Device, why)
	case unmapDetachOnly:
		slog.Warn("not stopping the map's daemon: the pid file names a process that is not the run's map", "device", loop.Device, "reason", why)
		say("WARN", "Detaching %s without stopping a map daemon: %s.", loop.Device, why)
	default:
		stopDaemon = func() error {
			note, err := hostMapReaper.stopMapDaemon(loop.Backing, intent)
			if err != nil {
				return fmt.Errorf("left %s attached: %w; "+recoverhint.Again, loop.Device, err)
			}
			if note != "" {
				slog.Warn("signalled no map daemon", "device", loop.Device, "reason", note)
				say("WARN", "Detaching %s without stopping a map daemon: %s.", loop.Device, note)
			}
			return nil
		}
	}
	err = releaseLoopContext(ctx, loop, stopDaemon, owned)
	switch {
	case errors.Is(err, sysutil.ErrLoopReused):
		return settleReusedLoop(ctx, loop)
	case err != nil:
		return err
	}
	say("INFO", "Released PBS map %s.", loop.Device)
	if stopDaemon == nil {
		// The pid file names a process that is not the run's map: the map file
		// and the pid file may belong to that process, and are not touched.
		return nil
	}
	return removeReleasedMapFiles(intent, loop.Device, loop.Backing)
}

// removeReleasedMapFiles removes what the PBS map of a loop that is released
// left behind, once its daemon is gone or was stopped: a daemon that was killed
// leaves its FUSE mount (dead) and its map file and pid file, which only
// removeMapFiles clears. It is called when the loop was just released, and
// again for a loop that is already gone, so that a removal that failed is
// retried by the next recovery; with nothing left it does nothing. recorded is
// the map file the journal recorded for the loop; a path outside the map run
// directory is no PBS map's, and nothing is touched.
//
// The files are removed only when the pid file shows they are the run's own
// map's, now dead (unmapGuardFor and mapDaemonState): when it names another
// process, a proxmox-backup-client runs under it (another operation's map of
// the same snapshot, or the run's own daemon, which still runs), or it cannot be
// read, they are left, and that alone does not make the recovery incomplete.
// Only a removal that fails is an error.
func removeReleasedMapFiles(intent journal.MapIntent, device, recorded string) error {
	backing := strings.TrimSuffix(recorded, " (deleted)")
	if filepath.Dir(backing) != hostLeakFinder.runDir {
		return nil
	}
	why := ""
	if guard, reason := hostMapReaper.unmapGuardFor(backing, intent); guard != unmapStopDaemon {
		why = reason
	} else if alive, unknown := mapDaemonState(backing); alive {
		why = "a proxmox-backup-client still runs under its pid file"
	} else if unknown != "" {
		why = unknown
	}
	if why != "" {
		slog.Warn("leaving the files of a released PBS map in place", "device", device, "reason", why)
		say("WARN", "Left the FUSE mount and files of %s's PBS map in place: %s.", device, why)
		return nil
	}
	if err := removeMapFiles(hostLeakFinder, intent, backing); err != nil {
		return fmt.Errorf("released %s, but its PBS map's FUSE mount or files could not be removed: %w", device, err)
	}
	slog.Info("removed the FUSE mount and files of a released PBS map", "device", device)
	return nil
}

// settleReusedLoop is the answer for a recorded loop device that backs
// another file now: nothing was done to it. It is an error only when
// something of the run's map remains.
func settleReusedLoop(ctx context.Context, loop journal.TrackedLoop) error {
	device, backing := loop.Device, loop.Backing
	// A stale attachment is not proven released even without a listed block
	// holder; the attachment's disk sequence number, when the run recorded it,
	// tells the run's from another. Nothing whose ownership is no longer
	// established is stopped. The run's own attachment can be on its way out
	// of the kernel (autoclear; whatever had it open lets go within seconds),
	// so it is given the wait an unmapped loop gets.
	if err := awaitLoopReleased(ctx, loop); err != nil {
		return err
	}
	note, err := ReusedLoopNote(device, backing)
	if err != nil {
		return err
	}
	slog.Warn("a recorded loop device backs another file now and was left alone", "device", device)
	say("WARN", "%s", note)
	return nil
}

// ReusedLoopNote says, for a loop device the run recorded that backs another
// file now, that it was left alone and nothing of the run's map remains. It
// errs when something of the map remains (its FUSE mount is still there, or a
// proxmox-backup-client still runs under its pid file), or when that cannot
// be established: the map's own leftovers are then not gone, and cleanup is
// not clean.
func ReusedLoopNote(device, backing string) (string, error) {
	remnant, err := mapRemnant(backing)
	switch {
	case err != nil:
		return "", fmt.Errorf("%s backs another file now, so it was left alone, but recovery cannot tell whether the run's PBS map is gone: %w", device, err)
	case remnant != "":
		return "", fmt.Errorf("%s backs another file now, so it was left alone, but the run's PBS map is not gone: %s; stop or unmap it by hand (its process, or umount -l its mount under %s), and "+recoverhint.Again, device, remnant, pbsMapRunDir)
	}
	return fmt.Sprintf("Left %s alone: it backs another file now, not the PBS map the run recorded, and nothing of that map remains.", device), nil
}

// mapRemnant says what of the PBS map served through the map file backing is
// still there: its FUSE mount, or a live proxmox-backup-client under its pid
// file. "" is nothing (a backing outside the map run directory is no PBS
// map's); an error means it is not known.
func mapRemnant(backing string) (string, error) {
	backing = strings.TrimSuffix(backing, " (deleted)")
	if filepath.Dir(backing) != hostLeakFinder.runDir {
		return "", nil
	}
	mounted, err := hostLeakFinder.mounted(backing)
	if err != nil {
		return "", fmt.Errorf("the mount table cannot be read: %w", err)
	}
	if mounted {
		return "its FUSE mount is still there", nil
	}
	data, err := os.ReadFile(strings.TrimSuffix(backing, ".img") + ".pid")
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("its pid file cannot be read: %s", pathless(err))
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 1 && hostMapReaper.daemonAlive(pid) {
		return fmt.Sprintf("a proxmox-backup-client (PID %d) still runs under its pid file", pid), nil
	}
	return "", nil
}

// MayStopMapDaemon says whether the daemon of the map served through the map
// file backing (recorded for the map intent) may be stopped (StopMapDaemon):
// the pid file names no live process, or the run's own map daemon. When it
// names something else the caller only detaches the loop, signalling nothing.
// An error means it cannot be established: nothing is to be done to the map.
func MayStopMapDaemon(backing string, intent journal.MapIntent) (bool, error) {
	guard, why := hostMapReaper.unmapGuardFor(backing, intent)
	switch guard {
	case unmapStopDaemon:
		return true, nil
	case unmapDetachOnly:
		slog.Warn("not stopping the map's daemon: the pid file names a process that is not the run's map", "reason", why)
		return false, nil
	}
	return false, fmt.Errorf("the PBS map was left alone: %s", why)
}

// StopMapDaemon stops the daemon of the PBS map served through the map file
// backing, as proxmox-backup-client unmap did, but through a pidfd opened for
// the process that was verified to be the run's own map daemon (see
// mapReaper.stopMapDaemon): the client rereads the pid file and signals that
// bare PID, and the PID can have been reused in between. It signals nothing
// that is not the run's daemon: the note then says why, and the caller detaches
// the loop alone. An error means the daemon could not be stopped, or what runs
// could not be established: the map is to be left as it is.
func StopMapDaemon(backing string, intent journal.MapIntent) (note string, err error) {
	return hostMapReaper.stopMapDaemon(backing, intent)
}

// releaseLoop releases a PBS map's loop device, which the run recorded as
// backed by recorded, and only while it still is: the map's daemon is stopped
// first (stopDaemon, when not nil; it exits having released the loop itself),
// then the loop is detached with losetup -d if it is still attached. A device
// that is already gone counts as released. One that backs another file than the
// recorded one, whether at the start, before the daemon is stopped or before
// the detach, is not touched, and the answer is sysutil.ErrLoopReused: a failed
// first step never widens what the second may detach.
//
// A map whose daemon is gone has its FUSE connection aborted first: a
// thread of a killed daemon can wait on its own file for ever, and every
// open of the loop then hangs. The detach runs under a watchdog, because a
// command stuck in the kernel cannot be killed: when losetup -d hangs, the
// connection is aborted, and a detach still stuck after that is reported
// instead of waited for.
//
// stopDaemon signals the process the map's pid file names, so the caller gives
// one only when unmapGuardFor allows (the pid file names no live process, or
// the run's own daemon), and it is bound to what it verified (stopMapDaemon).
// A daemon that cannot be stopped leaves the map as it is: nothing is
// detached, because a detached loop would leave the daemon, and its mount,
// that nothing names any more.
//
// Before either runs, the md arrays and device-mapper devices the host
// assembled from the loop's partitions are stopped, when every member of
// theirs is a loop in owned (sysutil.ReleaseLoopHolders): a loop that is held
// stays after the unmap. The loop is then waited for until it is gone, and one
// that stays is an error naming what holds it.
func releaseLoop(loop journal.TrackedLoop, stopDaemon func() error, owned []sysutil.LoopIdentity) error {
	return releaseLoopContext(context.Background(), loop, stopDaemon, owned)
}

// releaseLoopContext is releaseLoop whose waits end when ctx does: the stop of
// what holds the loop, the wait for the detach to finish and the wait for the
// loop to leave the kernel. A step already issued (the map daemon's stop, a
// detach) is not undone and not waited for further: the loop stays recorded,
// and the next recovery finds it released or still the run's.
func releaseLoopContext(ctx context.Context, loop journal.TrackedLoop, stopDaemon func() error, owned []sysutil.LoopIdentity) error {
	if err := releaseLoopOnce(ctx, loop.Device, loop.Backing, stopDaemon, owned); err != nil {
		return err
	}
	return awaitLoopReleased(ctx, loop)
}

// awaitLoopReleased waits for the unmapped loop to leave the kernel, or for ctx
// to end: the wait is a read of the loop only, so it is simply not continued.
func awaitLoopReleased(ctx context.Context, loop journal.TrackedLoop) error {
	attempts, interval := loopReleaseAttempts, loopReleaseInterval
	if ctx.Done() == nil {
		return sysutil.AwaitLoopReleased(loop, attempts, interval)
	}
	done := runWatched(func() error { return sysutil.AwaitLoopReleased(loop, attempts, interval) })
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("%s was unmapped but is not yet confirmed released: recovery was interrupted while it waited: %w", loop.Device, ctx.Err())
	}
}

// releaseLoopHolders and the wait for a released loop to leave the kernel are
// replaced by tests.
var (
	releaseLoopHolders  = sysutil.ReleaseLoopHolders
	loopReleaseAttempts = 10
	loopReleaseInterval = time.Second
)

// holderReleaseTimeout bounds stopping the devices that hold one loop.
const holderReleaseTimeout = 3 * time.Minute

func releaseLoopOnce(ctx context.Context, device, recorded string, stopDaemon func() error, owned []sysutil.LoopIdentity) error {
	stillOurs := func() (bool, error) {
		state, err := sysutil.CheckLoop(device, recorded)
		switch {
		case err != nil:
			return false, fmt.Errorf("cannot establish that %s is still the run's PBS map, so it is left alone: %w", device, err)
		case state == sysutil.LoopReused:
			return false, fmt.Errorf("%s: %w", device, sysutil.ErrLoopReused)
		}
		return state == sysutil.LoopRecorded, nil
	}
	if ok, err := stillOurs(); !ok {
		return err
	}
	backing, _ := LoopBacking(device)
	backing = strings.TrimSuffix(backing, " (deleted)")
	aborted := false
	abort := func(why string) {
		if aborted || backing == "" {
			return
		}
		// The connection is found by the map file's path. A live daemon at
		// that path (another map of the same snapshot and archive, mounted
		// since) is never aborted; a wedged one is a zombie, not live.
		if mapDaemonAlive(backing) {
			slog.Warn("not aborting a PBS map's FUSE connection: a live daemon serves its file", "device", device, "reason", why)
			return
		}
		ok, err := hostLeakFinder.abortMapConnection(backing)
		if err != nil {
			slog.Warn("could not abort a PBS map's FUSE connection", "device", device, "error", err)
			return
		}
		if ok {
			aborted = true
			slog.Warn("aborted a PBS map's FUSE connection", "device", device, "reason", why)
			say("WARN", "Aborted the FUSE connection of %s's PBS map (%s), so reads stuck on it fail instead of hanging the node.", device, why)
		}
	}
	if backing != "" && !mapDaemonAlive(backing) {
		abort("its process is gone")
	}

	// The devices on the loop's partitions are stopped after a dead map's
	// connection is aborted, which keeps what they read from hanging.
	// A command stuck in the kernel cannot be killed: it is waited for only so long.
	holdersCtx, cancel := context.WithTimeout(ctx, holderReleaseTimeout)
	defer cancel()
	type released struct {
		stopped []sysutil.LoopHolder
		err     error
	}
	done := make(chan released, 1)
	go func() {
		stopped, err := releaseLoopHolders(holdersCtx, device, owned)
		done <- released{stopped, err}
	}()
	var stopped []sysutil.LoopHolder
	var holdersErr error
	stuck := time.NewTimer(holderReleaseTimeout + mapCommandWatchdog)
	select {
	case r := <-done:
		stopped, holdersErr = r.stopped, r.err
	case <-stuck.C:
		holdersErr = fmt.Errorf("stopping what holds %s is stuck in the kernel", device)
	case <-ctx.Done():
		// The commands that stop the holders end with holdersCtx, which is
		// derived from ctx; what they already stopped stays stopped.
		holdersErr = fmt.Errorf("stopping what holds %s was interrupted: %w", device, ctx.Err())
	}
	stuck.Stop()
	if len(stopped) > 0 {
		slog.Info("stopped the devices the host assembled from a PBS map's partitions", "device", device, "holders", sysutil.HolderLabels(stopped))
		say("INFO", "Stopped %s, which the host assembled from the partitions of %s, before releasing it.", sysutil.HolderLabels(stopped), device)
	}
	if holdersErr != nil {
		return fmt.Errorf("release %s: %w", device, holdersErr)
	}

	if stopDaemon != nil {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("left %s attached: recovery was interrupted before it stopped the map's daemon: %w; "+recoverhint.Again, device, err)
		}
		if ok, err := stillOurs(); !ok {
			return err
		}
		if err := stopDaemon(); err != nil {
			return err
		}
	}
	// The device can be gone (the daemon released it as it exited) or reused
	// since: only the run's own loop is detached.
	if ok, err := stillOurs(); !ok {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("left %s attached: recovery was interrupted before it detached it: %w; "+recoverhint.Again, device, err)
	}
	detach := runWatched(func() error { return sysutil.DetachLoop(context.Background(), device) })
	// An interrupt ends the wait for the detach and is not a hung one: the
	// FUSE connection is aborted only for a detach that hung. The detach that
	// was issued goes on in the kernel; the next recovery finds the loop
	// released, or still the run's.
	interruptedDetach := func() error {
		return fmt.Errorf("left %s: recovery was interrupted while it waited for losetup -d to finish: %w; the detach already issued goes on, and "+recoverhint.Recovery+" confirms it", device, ctx.Err())
	}
	finished, ended, detachErr := waitWatchedContext(ctx, detach, mapCommandWatchdog)
	if ended {
		return interruptedDetach()
	}
	if !finished {
		abort("losetup -d hung")
		finished, ended, detachErr = waitWatchedContext(ctx, detach, mapCommandWatchdog)
		if ended {
			return interruptedDetach()
		}
	}
	if !finished {
		return fmt.Errorf("losetup -d %s is stuck in the kernel: the loop's backing I/O never completes. Find the FUSE connection with waiting requests and no mount under /sys/fs/fuse/connections, and abort it (echo 1 > .../abort)", device)
	}
	if detachErr != nil {
		if _, inspectErr := LoopBacking(device); errors.Is(inspectErr, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to unmap %s: %w", device, detachErr)
	}
	return nil
}

// mapCommandWatchdog is how long recovery waits for a map's daemon to exit
// after SIGINT, or for one detach command, before it treats it as stuck.
const mapCommandWatchdog = 20 * time.Second

// runWatched runs fn in the background; waitWatched waits for it.
func runWatched(fn func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	return done
}

// waitWatched waits at most d for a runWatched call, and reports whether
// it finished. One that has not is left to finish on its own: a process in
// uninterruptible sleep cannot be killed, and recovery must not hang with
// it.
func waitWatched(done <-chan error, d time.Duration) (bool, error) {
	finished, _, err := waitWatchedContext(context.Background(), done, d)
	return finished, err
}

// waitWatchedContext is waitWatched that also ends when ctx does: interrupted
// is then true, and the call is left to finish on its own as for a watchdog.
func waitWatchedContext(ctx context.Context, done <-chan error, d time.Duration) (finished, interrupted bool, err error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case err := <-done:
		return true, false, err
	case <-timer.C:
		return false, false, nil
	case <-ctx.Done():
		return false, true, nil
	}
}

// mapDaemonAlive reports whether the daemon named by a PBS map file's pid
// file may still run. Only a pid file that is not there, or names a process
// that is gone, says it does not: a pid file that cannot be read or holds no
// usable PID is not evidence of a dead daemon, so it counts as running and
// nothing the daemon serves is aborted or detached on the strength of it.
func mapDaemonAlive(backing string) bool {
	alive, unknown := mapDaemonState(backing)
	return alive || unknown != ""
}

// mapDaemonState is mapDaemonAlive with the reason a daemon cannot be called
// dead: unknown is set when the pid file exists and cannot be read or holds
// no usable PID.
func mapDaemonState(backing string) (alive bool, unknown string) {
	data, err := os.ReadFile(strings.TrimSuffix(backing, ".img") + ".pid")
	switch {
	case errors.Is(err, os.ErrNotExist):
		return false, ""
	case err != nil:
		return false, "its pid file cannot be read: " + pathless(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return false, "its pid file names no process"
	}
	return hostMapReaper.daemonAlive(pid), ""
}

// UnmapLeakedMaps releases what maps begun under intents left behind
// without a journal entry: a worker killed while it mapped, or a map that
// timed out after its loop device existed. tracked names the devices a
// journal already owns. persist journals the intents, which point into the
// caller's record; nil journals nothing.
//
// In order, per intent:
//  1. It stops the map's own processes (mapReaper.stop), journaled first.
//     The daemon a killed worker's client forked can still be fetching,
//     and would create its loop device after this ran.
//  2. It releases the loop devices the map created (leakFinder.find).
//  3. It removes the map files a stopped daemon left behind, including a
//     FUSE mount whose daemon was stopped before it wrote its pid file
//     (leakFinder.orphans).
//
// A loop device or map file is the map's only when its pid file leads to
// one of the map's own processes, now gone, or in the two cases
// settlePidless (no pid file) and settleDeadUnknown (a pid file written in the
// intent's window that names a process now gone, which recovery never saw:
// the map's daemon died with the worker) allow. Both release a leftover by the
// same path as a proven one: its loop is detached, its FUSE connection aborted
// and its mount detached, and its map file and pid file removed. Anything that
// looks like the map's but is not proved to be is left and reported, as is a
// map process that does not stop and a map file recovery cannot remove:
// recovery is then incomplete, and the journal keeps the intent for the next
// attempt.
func UnmapLeakedMaps(intents []*journal.MapIntent, tracked map[string]bool, persist func() error) error {
	var errs []error
	for _, intent := range intents {
		if err := hostMapReaper.stop(intent, persist); err != nil {
			errs = append(errs, err)
		}
		running, err := hostMapReaper.mapRunning(*intent)
		mapRunErr := err != nil
		if err != nil {
			errs = append(errs, err)
			running = true // not known: nothing without a pid file is the map's
		}
		evidence := hostMapReaper.evidence(*intent, running)
		leaks, unproven := hostLeakFinder.find(*intent, tracked, evidence)
		errs = append(errs, unproven...)
		// What the host assembled from these loops' partitions is stopped only
		// when every member is one of them: the interrupted run's own map.
		owned := make([]sysutil.LoopIdentity, 0, len(leaks))
		for _, leak := range leaks {
			owned = append(owned, sysutil.LoopIdentity{Device: leak.Device, Backing: leak.Backing})
		}
		for _, leak := range leaks {
			// Released only while it is still that map's loop.
			current, err := LoopBacking(leak.Device)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || strings.TrimSuffix(current, " (deleted)") != leak.Backing {
				errs = append(errs, fmt.Errorf("%s changed while recovery looked at it and was left; "+recoverhint.Again, leak.Device))
				continue
			}
			slog.Warn("unmapping a PBS map a previous worker began but never recorded", "device", leak.Device, "snapshot", intent.Snapshot, "archive", intent.Archive)
			say("WARN", "Releasing %s, a PBS map of %s %s the interrupted run began but never recorded.", leak.Device, intent.Snapshot, intent.Archive)
			// The map's daemon is gone: none is stopped.
			switch err := releaseLoop(journal.TrackedLoop{Device: leak.Device, Backing: leak.Backing}, nil, owned); {
			case errors.Is(err, sysutil.ErrLoopReused):
				slog.Warn("a leftover loop device backs another file now and was left alone", "device", leak.Device)
			case err != nil:
				errs = append(errs, err)
			}
		}
		// Releasing a loop can take 20 s and more: whether a map still runs is
		// looked at again before the map files are.
		if len(leaks) > 0 {
			again, err := hostMapReaper.mapRunning(*intent)
			if err != nil {
				if !mapRunErr {
					errs = append(errs, err)
				}
				again = true
			}
			evidence = hostMapReaper.evidence(*intent, again)
		}
		orphans, unproven := hostLeakFinder.orphans(*intent, evidence)
		errs = append(errs, unproven...)
		for _, backing := range orphans {
			slog.Warn("removing the files of a PBS map whose daemon was killed", "snapshot", intent.Snapshot, "archive", intent.Archive)
			say("WARN", "Removing the leftover files of a PBS map of %s %s whose process was killed.", intent.Snapshot, intent.Archive)
			if err := removeMapFiles(hostLeakFinder, *intent, backing); err != nil {
				errs = append(errs, fmt.Errorf("PBS map of %s %s: %w", intent.Snapshot, intent.Archive, err))
			}
		}
	}
	return errors.Join(errs...)
}

// detachMount lazily detaches the mount at path (umount2 MNT_DETACH). It is a
// variable so that tests, which run without privileges, need no mount.
var detachMount = func(path string) error { return syscall.Unmount(path, syscall.MNT_DETACH) }

// maxMountDetaches bounds how many mounts removeMapFiles takes off one map file.
const maxMountDetaches = 8

// removeMapFiles detaches a dead map's FUSE mount lazily and removes its map
// file and pid file. It unmounts with umount2(MNT_DETACH) itself: umount(8)
// resolves the path first, which a dead FUSE mount answers with ENOTCONN.
// It names the files without the repository their names start with.
func removeMapFiles(f leakFinder, intent journal.MapIntent, backing string) error {
	label := f.mapLabel(intent)
	// Its FUSE connection is aborted and its mount detached below: never for
	// a map a live proxmox-backup-client serves (its pid file, or one that
	// cannot be read, names one).
	if alive, unknown := mapDaemonState(backing); unknown != "" {
		return fmt.Errorf("the PBS map file %s was left alone: it cannot be shown that no proxmox-backup-client serves it (%s)", label, unknown)
	} else if alive {
		return fmt.Errorf("the PBS map file %s is served by a live proxmox-backup-client, so it was left alone", label)
	}
	// A daemon thread waiting on its own file keeps the connection open;
	// abort it so those threads can exit.
	if aborted, err := f.abortMapConnection(backing); err != nil {
		slog.Warn("could not abort a dead PBS map's FUSE connection", "error", pathless(err))
	} else if aborted {
		say("WARN", "Aborted the FUSE connection of the dead PBS map %s.", label)
	}
	// Maps made over a dead one stack their mounts on the one path, and a detach
	// takes off the top one only: it is repeated while the path is still mounted,
	// a bounded number of times.
	for attempt := 1; ; attempt++ {
		if err := detachMount(backing); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("detach the stale FUSE mount %s: %w", label, err)
		}
		mounted, err := f.mounted(backing)
		if err != nil {
			return fmt.Errorf("cannot read the mount table to confirm the stale FUSE mount %s is detached: %v", label, err)
		}
		if !mounted {
			break
		}
		if attempt == maxMountDetaches {
			return fmt.Errorf("the stale FUSE mount %s is still mounted; detach it with umount -l", label)
		}
	}
	var errs []error
	for _, p := range []string{backing, strings.TrimSuffix(backing, ".img") + ".pid"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove the stale PBS map file %s: %s", label, pathless(err)))
		}
	}
	return errors.Join(errs...)
}

// say records a recovery action as a progress event, which the controller
// shows the operator when the controller is attached, besides the log. After
// a crash, what recovery did is otherwise only in a file removed with the
// worker's workspace.
func say(level, format string, args ...any) {
	progress.Emit(level, "Recovery", format, args...)
	logLine(level, format, args...)
}

// While a recovery runs, recoveryLog keeps its actions in the state
// directory's logs, whoever started it: the supervisor after a worker
// crash, the controller after it lost the node (only the controller
// saw what that recovery did), a node-run before it starts, or an operator.
// It is the file the supervisor keeps the run's progress in.
var (
	recoveryLogMu sync.Mutex
	recoveryLog   io.WriteCloser
)

var logNameExpr = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// keepLog starts recording to <stateDir>/logs/<run>.log, the run ID
// without its "run-" prefix, and returns what stops it. A log that cannot
// be opened is reported, and never stops recovery.
func keepLog(stateDir, runID string) func() {
	name := strings.TrimPrefix(runID, "run-")
	if !logNameExpr.MatchString(name) {
		name = "unnamed-run"
	}
	dir := filepath.Join(stateDir, "logs")
	f, err := func() (*os.File, error) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		return os.OpenFile(filepath.Join(dir, name+".log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	}()
	if err != nil {
		slog.Warn("cannot keep a recovery log", "dir", dir, "error", err)
		return func() {}
	}
	recoveryLogMu.Lock()
	recoveryLog = f
	recoveryLogMu.Unlock()
	return func() {
		recoveryLogMu.Lock()
		recoveryLog = nil
		recoveryLogMu.Unlock()
		_ = f.Close()
	}
}

// logLine adds one line to the recovery log, if one is kept.
func logLine(level, format string, args ...any) {
	recoveryLogMu.Lock()
	defer recoveryLogMu.Unlock()
	if recoveryLog == nil {
		return
	}
	message := strings.NewReplacer("\r", " ", "\n", " ").Replace(fmt.Sprintf(format, args...))
	_, _ = fmt.Fprintf(recoveryLog, "%s %s %s\n", time.Now().UTC().Format(time.RFC3339), level, message)
}

func withheldClientOutputDetail(output []byte) string {
	return fmt.Sprintf("withheld (%d bytes)", len(output))
}

// settleBridge is sysutil.SettleBridge; tests replace it.
var settleBridge = sysutil.SettleBridge

// sdnLockWait bounds recovery's wait for an SDN lock another client holds;
// zero is the SDN manager's default. Tests shorten it.
var sdnLockWait time.Duration

// sdnApplyWait bounds recovery's wait for a running SDN apply; zero is the SDN
// manager's default. Tests shorten it.
var sdnApplyWait time.Duration

// pveRecoveryTimeout bounds recovery's PVE work: VMs, SDN objects and lock.
var pveRecoveryTimeout = 5 * time.Minute

// recoverPVEResources destroys the run's sandbox VMs and SDN objects, and
// settles PVE's SDN lock. Its SDN lock state is journaled at path as it
// changes, before a new token is used.
//
// parent is the operator's interrupt: it ends the work and the waits on PVE,
// with the budget below counted inside it. A VM or SDN task PVE already runs
// goes on there; the journal keeps the VMs, the objects and the SDN lock state
// (journaled before it is used), so the next recovery finds out what is left.
func recoverPVEResources(parent context.Context, r *journal.Record, path string) error {
	if len(r.VMs) == 0 && len(r.SDNVNets) == 0 && len(r.SDNZones) == 0 && !r.SDNAllocationPending() && r.SDNLockToken == "" && r.SDNLockRequested == "" && r.SDNApplyUnknown == "" {
		return nil
	}
	if err := parent.Err(); err != nil {
		return fmt.Errorf("not started: recovery of the run's PVE resources: recovery was interrupted: %w", err)
	}

	client, err := recoveryPVEClientFromEnv()
	if err != nil {
		return fmt.Errorf("PVE resource recovery requires controller-provided PVE credentials: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, pveRecoveryTimeout)
	defer cancel()
	var errs []error

	for _, vm := range r.VMs {
		if vm.VMID <= 0 || strings.TrimSpace(vm.Node) == "" {
			errs = append(errs, fmt.Errorf("refusing to recover invalid recorded VM identity vmid=%d node=%q", vm.VMID, vm.Node))
			continue
		}
		status, statusErr := client.GetVMStatus(ctx, vm.Node, vm.VMID)
		if client.VMNotFound(ctx, statusErr, vm.Node, vm.VMID) {
			continue
		}
		if statusErr != nil {
			errs = append(errs, fmt.Errorf("read recorded VM %d on %s: %w", vm.VMID, vm.Node, statusErr))
			continue
		}
		if status == nil {
			errs = append(errs, fmt.Errorf("read recorded VM %d on %s: PVE returned an empty status", vm.VMID, vm.Node))
			continue
		}
		// A VM is stopped or destroyed only while its own markers say it is
		// this run's, read immediately before each of those calls: the ID is a
		// number PVE reuses, and what was verified earlier can be a VM that
		// is gone. "Does not exist" from any call ends the VM's
		// recovery: it never authorizes a destroy of whatever is at the ID.
		if gone, ownedErr := recordedVMOwnedNow(ctx, client, vm, r.RunID); ownedErr != nil {
			errs = append(errs, ownedErr)
			continue
		} else if gone {
			continue
		}
		if status.Status != "stopped" {
			upid, stopErr := client.StopVM(ctx, vm.Node, vm.VMID)
			if client.VMNotFound(ctx, stopErr, vm.Node, vm.VMID) {
				continue
			}
			if stopErr != nil {
				errs = append(errs, unbackedNotFound(ctx, client, vm, r.RunID, fmt.Errorf("stop recorded VM %d: %w", vm.VMID, stopErr)))
				continue
			}
			if waitErr := client.WaitForTask(ctx, vm.Node, upid, time.Second, 45*time.Second); waitErr != nil {
				errs = append(errs, fmt.Errorf("wait for recorded VM %d stop: %w", vm.VMID, waitErr))
				continue
			}
			// A task that succeeded is not proof that this VM stopped: it
			// can be another task's, or PVE's account of it wrong.
			// Only the VM's own status is.
			gone, stoppedErr := vmStoppedAfterTask(ctx, client, vm)
			if stoppedErr != nil {
				errs = append(errs, stoppedErr)
				continue
			}
			if gone {
				continue
			}
		}
		// The stop, and any wait for it, gave the ID time to be reused: the
		// markers are read again right before the destroy.
		if gone, ownedErr := recordedVMOwnedNow(ctx, client, vm, r.RunID); ownedErr != nil {
			errs = append(errs, ownedErr)
			continue
		} else if gone {
			continue
		}
		upid, destroyErr := client.DestroyVM(ctx, vm.Node, vm.VMID)
		if client.VMNotFound(ctx, destroyErr, vm.Node, vm.VMID) {
			continue
		}
		if destroyErr != nil {
			errs = append(errs, unbackedNotFound(ctx, client, vm, r.RunID, fmt.Errorf("destroy recorded VM %d: %w", vm.VMID, destroyErr)))
			continue
		}
		// Neither a destroy task's success nor its failure or a timeout in
		// reading it says whether the VM is gone. PVE's answer for the exact
		// node and VM ID does, and only "does not exist" counts.
		waitErr := client.WaitForTask(ctx, vm.Node, upid, time.Second, 45*time.Second)
		if remains := vmMayStillExist(ctx, client, vm, r.RunID); remains != nil {
			if waitErr != nil {
				errs = append(errs, fmt.Errorf("wait for recorded VM %d destroy: %w (%v)", vm.VMID, waitErr, remains))
			} else {
				errs = append(errs, fmt.Errorf("the destroy task of recorded VM %d reported success, but %w", vm.VMID, remains))
			}
			continue
		}
		if waitErr != nil {
			slog.Warn("a recorded VM's destroy task could not be followed, but PVE reports the VM gone", "vmid", vm.VMID, "error", waitErr)
		}
		say("INFO", "Destroyed sandbox VM %d on %s.", vm.VMID, vm.Node)
	}

	if err := recoverSDN(ctx, client, r, path); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// recoverSDN removes the interrupted run's SDN zone and VNet, applies their
// removal, and settles PVE's SDN lock, as a run's teardown does. An apply
// commits every pending change on every node, so recovery applies only
// under a lock it holds, journaled before use, when the change it
// applies is the run's alone, and nothing at all when PVE has neither the
// objects nor their unapplied deletion. A token the run journaled
// is used only while a lock stands, and stays journaled until its release
// is established. A lock request whose answer never came is
// resolved only by PVE's answer to a new one; the run's last apply
// must have ended before another starts.
//
// A zone or VNet whose creation was sent and never confirmed
// (allocation_pending) is one of the run's objects too, found by name: it is
// deleted when PVE shows it to be the run's never-applied creation, and the
// allocation is settled once PVE's lists show nothing of it is left.
// No object is deleted that the journal cannot show is the run's: a VNet
// only while it carries the journaled marker, a zone only with that marker
// journaled and its VNet not refused, and nothing at all for a journal that
// names no marker.
func recoverSDN(ctx context.Context, client *pve.Client, r *journal.Record, path string) error {
	zones, vnets := nonEmpty(r.SDNZones), nonEmpty(r.SDNVNets)
	unconfirmedZone := r.PendingSDNZoneAllocation()
	if unconfirmedZone != "" {
		zones = appendMissing(zones, unconfirmedZone)
	}
	if id := r.PendingSDNVNetAllocation(); id != "" {
		vnets = appendMissing(vnets, id)
	}
	if len(zones)+len(vnets) == 0 && r.SDNLockToken == "" && r.SDNLockRequested == "" && r.SDNApplyUnknown == "" {
		return nil
	}
	manager := sdn.NewManager(client)
	manager.SetLockWait(sdnLockWait)
	manager.SetApplyWait(sdnApplyWait)
	manager.AdoptLock(r.SDNLockToken)
	if r.SDNLockRequested != "" {
		manager.AdoptLockRequest()
	}
	if r.SDNApplyUnknown != "" {
		manager.AdoptApplyUnknown()
	}
	manager.SetOwnObjects(zones, vnets)
	manager.SetOwnerMarker(r.SDNOwner)
	if r.SDNApplyTask != "" {
		if err := manager.AdoptApplyTask(r.SDNApplyTask); err != nil {
			return fmt.Errorf("the interrupted run's journal names an SDN apply task CertiStack cannot follow: %w", err)
		}
	}
	manager.SetPersist(func(state sdn.LockState) error {
		r.NoteSDNLock(state.Token, state.Requested, state.ApplyTask, state.ApplyUnknown, time.Now())
		r.UpdatedAt = time.Now().UTC()
		return journal.Write(path, *r)
	})
	// settled is called once PVE's lists show nothing of the objects is left:
	// an unconfirmed creation then made nothing that remains, and its
	// allocation is cleared (and journaled now, for a later step's failure).
	settled := func() error {
		if !r.SDNAllocationPending() {
			return nil
		}
		r.AllocationPending = ""
		r.UpdatedAt = time.Now().UTC()
		if err := journal.Write(path, *r); err != nil {
			return fmt.Errorf("journal that the SDN allocation is settled: %w", err)
		}
		return nil
	}
	// An apply is waited for where one is made (Manager.Reload): a recovery
	// that applies nothing does not wait for the run's last apply, whose
	// task may not be readable from here.

	zoneStates, vnetStates, stateErr := manager.ObjectStates(ctx, zones, vnets)
	if len(zones)+len(vnets) == 0 || (stateErr == nil && allAbsent(zoneStates) && allAbsent(vnetStates)) {
		// Nothing is left to delete or apply, so no apply that would commit
		// what an administrator left pending: only the lock is settled.
		if err := settleSDNLock(ctx, manager, r); err != nil {
			return err
		}
		// No apply follows from this journal, so an apply whose outcome was
		// lost no longer matters to it.
		if err := manager.ClearApplyUnknown(); err != nil {
			return err
		}
		if err := settled(); err != nil {
			return err
		}
		return confirmBridgesGone(ctx, client, vnets)
	}
	// An apply is about to be made or may be (an object PVE runs, a deletion
	// not applied, or a state that cannot be read): the run's last apply must
	// have ended first, before anything is deleted under the lock.
	if stateErr != nil || anyState(zoneStates, sdn.Applied, sdn.Deleted) || anyState(vnetStates, sdn.Applied, sdn.Deleted) {
		if err := manager.WaitForApply(ctx); err != nil {
			return err
		}
	}
	// Anything else, or a state that cannot be read, is settled under the
	// lock: taken, or the journaled one confirmed standing.
	adopted := manager.LockToken()
	wrote := false // whether the lock-less exception below wrote anything
	if err := manager.EnsureLock(ctx); err != nil {
		if errors.Is(err, sdn.ErrPendingSDNChanges) {
			// PVE refuses the lock over pending changes. When every one of
			// them is the run's own never-applied creation, nothing of an
			// administrator's is at stake: removing them leaves nothing
			// pending. Otherwise nothing is written.
			removed, rerr := removeOwnUnappliedObjects(ctx, manager, zones, vnets, zoneStates, vnetStates)
			if rerr != nil {
				return rerr
			}
			if removed {
				wrote = true
				if zoneStates, vnetStates, stateErr = manager.ObjectStates(ctx, zones, vnets); stateErr != nil {
					return stateErr
				}
				if allAbsent(zoneStates) && allAbsent(vnetStates) {
					if err := verifySDNGone(ctx, manager, zones, vnets); err != nil {
						return err
					}
					// No apply follows from this journal.
					if err := manager.ClearApplyUnknown(); err != nil {
						return err
					}
					if err := settled(); err != nil {
						return err
					}
					return confirmBridgesGone(ctx, client, vnets)
				}
				err = manager.EnsureLock(ctx)
			}
		}
		if err != nil {
			return sdnLockRefused(ctx, manager, r, zones, vnets, err, wrote)
		}
	}
	if manager.NoLockAPI() {
		say("WARN", "This PVE has no SDN configuration lock (PVE 8): recovery changes the run's SDN objects without one, after reading that the cluster's pending SDN changes are only the run's own; PVE does not hold other SDN changes off meanwhile.")
	}
	// Under the lock, the configuration changes only by recovery's hand.
	zoneStates, vnetStates, stateErr = manager.ObjectStates(ctx, zones, vnets)
	if stateErr != nil {
		if adopted != "" && manager.LockToken() == adopted {
			// The run's own lock stands over its own pending deletion: keep
			// it, journaled. Releasing it here would leave that deletion
			// pending with no lock, which blocks every SDN lock in the
			// cluster.
			return stateErr
		}
		return errors.Join(stateErr, manager.Unlock(ctx))
	}
	var errs []error
	// A zone has no marker of its own: read which of the run's zones a VNet
	// carrying the run's marker still shows to be the run's, before those
	// VNets are deleted (a zone shown by nothing is left and reported).
	if err := manager.ProveZones(ctx, zones); err != nil {
		errs = append(errs, err)
	}
	apply := false
	vnetRefused := false // a VNet was left in place: its zone is left too
	remove := func(kind, id string, state sdn.ObjectState, destroy func(context.Context, string) error) {
		switch state {
		case sdn.Deleted:
			// Deleted, but not applied: the run's own pending change.
			apply = true
		case sdn.Applied, sdn.New:
			before := manager.Mutations()
			if err := destroy(ctx, id); err != nil {
				// The manager already treats an exact "this object does not
				// exist" as absence; no other message is.
				errs = append(errs, err)
				var notOwned *sdn.NotOwnedError
				if kind == "VNet" && errors.As(err, &notOwned) {
					vnetRefused = true
				}
				// A subnet deleted before the VNet's own deletion failed is a
				// change of a running VNet, pending until it is applied.
				if manager.Mutations() > before && state == sdn.Applied {
					apply = true
				}
				return
			}
			say("INFO", "Deleted sandbox %s %s.", kind, id)
			// A never-applied object leaves nothing to apply once deleted.
			apply = apply || state == sdn.Applied
		}
	}
	// VNets must be removed before their zones. The manager removes only the
	// exact journaled ID and handles PVE's child-subnet deletion requirement.
	for i := len(vnets) - 1; i >= 0; i-- {
		remove("VNet", vnets[i], vnetStates[vnets[i]], manager.DestroyVNet)
	}
	for i := len(zones) - 1; i >= 0; i-- {
		if vnetRefused && zoneStates[zones[i]] != sdn.Absent {
			// A zone has no marker to tell it from a replacement; the VNet in
			// it was not shown to be the run's, so neither is the zone.
			errs = append(errs, fmt.Errorf("left SDN zone %s in place: a VNet of the run was left in place as not provably the run's, and a zone has no marker of its own to tell it from a replacement", zones[i]))
			continue
		}
		destroy := manager.DestroyZone
		if zones[i] == unconfirmedZone {
			// The creation's answer never came: only a zone PVE shows as the
			// run's never-applied creation is deleted, and on a PVE without an
			// SDN lock (PVE 8) a never-applied zone is not shown to be the
			// run's, so it is left and reported.
			destroy = func(ctx context.Context, id string) error {
				_, err := manager.DestroyUnconfirmedZone(ctx, id)
				return err
			}
		}
		remove("SDN zone", zones[i], zoneStates[zones[i]], destroy)
	}
	if !apply {
		// Nothing of the run's is running: release the lock rather than
		// reload every node's network for nothing.
		if err := manager.Unlock(ctx); err != nil {
			errs = append(errs, err)
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		if err := verifySDNGone(ctx, manager, zones, vnets); err != nil {
			return err
		}
		// No apply follows from this journal.
		if err := manager.ClearApplyUnknown(); err != nil {
			return err
		}
		if err := settled(); err != nil {
			return err
		}
		return confirmBridgesGone(ctx, client, vnets)
	}
	if err := manager.Reload(ctx); err != nil {
		// A lock that may still be held stays journaled, for the next
		// attempt to apply under.
		return errors.Join(append(errs, err)...)
	}
	// PVE's apply returns before the nodes reload their networks.
	nodes, _ := client.NodeCount(ctx)
	for _, vnet := range vnets {
		if err := settleBridge(ctx, vnet, false, sysutil.SettleTimeout(nodes)); err != nil {
			errs = append(errs, fmt.Errorf("confirm the interrupted run's VNet %s is gone on this node: %w", vnet, errors.Join(err, manager.ReloadFailed(ctx))))
		}
	}
	if len(errs) == 0 {
		if err := verifySDNGone(ctx, manager, zones, vnets); err != nil {
			errs = append(errs, err)
		} else if err := settled(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// verifySDNGone reads PVE's lists once more: a delete's success reply is not
// proof that the object is gone, and the journal is not cleaned on it. An
// object still configured or running is an error; so is a read that fails.
func verifySDNGone(ctx context.Context, manager *sdn.Manager, zones, vnets []string) error {
	zoneStates, vnetStates, err := manager.ObjectStates(ctx, zones, vnets)
	if err != nil {
		return fmt.Errorf("could not confirm that the interrupted run's SDN zone and VNet are gone: %w", err)
	}
	var left []string
	for _, id := range vnets {
		if vnetStates[id] != sdn.Absent {
			left = append(left, "VNet "+id)
		}
	}
	for _, id := range zones {
		if zoneStates[id] != sdn.Absent {
			left = append(left, "zone "+id)
		}
	}
	if len(left) > 0 {
		return fmt.Errorf("PVE still lists the interrupted run's %s after their deletion, so the journal keeps them for the next recovery (a delete's reply is not proof)", strings.Join(left, " and "))
	}
	return nil
}

// removeOwnUnappliedObjects deletes the run's never-applied zone and VNet when
// they are the ONLY pending changes: PVE refuses its lock over them, and
// nothing of an administrator's is mixed in. It reports whether it removed
// any. With a foreign pending change, or a pending list it cannot read,
// nothing is written.
func removeOwnUnappliedObjects(ctx context.Context, manager *sdn.Manager, zones, vnets []string, zoneStates, vnetStates map[string]sdn.ObjectState) (bool, error) {
	var newZones, newVNets []string
	for _, id := range zones {
		if zoneStates[id] == sdn.New {
			newZones = append(newZones, id)
		}
	}
	for _, id := range vnets {
		if vnetStates[id] == sdn.New {
			newVNets = append(newVNets, id)
		}
	}
	if len(newZones)+len(newVNets) == 0 {
		return false, nil
	}
	// Decided on a fresh read of what is pending, not on the states read
	// before the lock was asked for: an apply in between (an administrator's)
	// would have made the run's objects running, and deleting those without
	// the lock would leave a deletion pending that nobody applies.
	if ok, err := manager.OwnUnappliedOnly(ctx, newZones, newVNets); err != nil || !ok {
		return false, nil
	}
	var errs []error
	// The read above shows these never-applied zones to be the run's own:
	// nothing else is pending in the cluster.
	manager.NoteOwnUnapplied(newZones)
	removed := false
	vnetRefused := false
	for i := len(vnets) - 1; i >= 0; i-- {
		if vnetStates[vnets[i]] == sdn.New {
			if err := manager.DestroyVNet(ctx, vnets[i]); err != nil {
				errs = append(errs, err)
				var notOwned *sdn.NotOwnedError
				if errors.As(err, &notOwned) {
					vnetRefused = true
				}
				continue
			}
			say("INFO", "Deleted sandbox VNet %s (never applied).", vnets[i])
			removed = true
		}
	}
	for i := len(zones) - 1; i >= 0; i-- {
		if zoneStates[zones[i]] == sdn.New {
			if vnetRefused {
				errs = append(errs, fmt.Errorf("left SDN zone %s in place: a VNet of the run was left in place as not provably the run's, and a zone has no marker of its own to tell it from a replacement", zones[i]))
				continue
			}
			if err := manager.DestroyZone(ctx, zones[i]); err != nil {
				errs = append(errs, err)
				continue
			}
			say("INFO", "Deleted sandbox SDN zone %s (never applied).", zones[i])
			removed = true
		}
	}
	return removed, errors.Join(errs...)
}

// sdnLockRefused says why recovery could not settle PVE's SDN lock, and what
// is left to do. It writes nothing: a lock refusal is a barrier for every SDN
// change. Recovery does not delete over an administrator's pending changes (a
// deletion made without the lock would mix with them, and a later apply of
// theirs would enact it); it leaves the run's zone and VNet as they
// are, and its journal unclean, until those changes are applied or discarded.
func sdnLockRefused(ctx context.Context, manager *sdn.Manager, r *journal.Record, zones, vnets []string, lockErr error, wrote bool) error {
	names := strings.Join(append(append([]string(nil), zones...), vnets...), ", ")
	switch {
	case errors.Is(lockErr, sdn.ErrPendingSDNChanges):
		stopped := "so CertiStack changed nothing: the run's zone and VNet (" + names + ") are left as they are"
		if wrote {
			stopped = "so CertiStack stopped after it removed the run's never-applied objects"
		}
		foreign, foreignErr := manager.ForeignPending(ctx)
		switch {
		case foreignErr != nil:
			return fmt.Errorf("PVE refuses its SDN configuration lock over pending changes, and CertiStack could not read which (%v), %s. Ask whoever changed SDN to apply or discard the change (Datacenter > SDN); do not apply someone else's change yourself. Then "+recoverhint.Again+": %w", foreignErr, stopped, lockErr)
		case len(foreign) == 0 && pendingGone(ctx, manager):
			return fmt.Errorf("PVE refused its SDN configuration lock over pending changes that are gone now (someone applied them), %s; "+recoverhint.Again+": %w", stopped, lockErr)
		case len(foreign) == 0:
			return fmt.Errorf("the only pending SDN changes are the interrupted run's own (its deletions were made and never applied), and PVE refuses its lock while they are pending, %s. When no one else has an SDN change pending, apply them in PVE (Datacenter > SDN > Apply), then "+recoverhint.Again+": %w", stopped, lockErr)
		}
		return fmt.Errorf("PVE's SDN configuration has changes that are not the interrupted run's, %s. Ask whoever changed SDN to apply or discard the change (Datacenter > SDN); do not apply someone else's change yourself. Then "+recoverhint.Again+": %w", stopped, lockErr)
	case errors.Is(lockErr, sdn.ErrSDNLockHeld) && manager.LockRequestUnresolved():
		return fmt.Errorf("PVE's SDN configuration lock stands, and it may be the one the interrupted run requested at %s, whose answer never came: PVE's lock has no owner but its token, which CertiStack never received. If no one else is changing the cluster's SDN, release it (pvesh delete /cluster/sdn/lock --force 1), then "+recoverhint.Again+": %w", r.SDNLockRequested, lockErr)
	default:
		return fmt.Errorf("recovery takes PVE's SDN configuration lock to remove the interrupted run's SDN zone and VNet (%s), and could not; it changed nothing; "+recoverhint.Again+": %w", names, lockErr)
	}
}

// pendingGone reports that PVE has no pending SDN change now.
func pendingGone(ctx context.Context, manager *sdn.Manager) bool {
	pending, err := manager.PendingChanges(ctx)
	return err == nil && len(pending) == 0
}

// settleSDNLock releases the lock the interrupted run journaled, and finds
// out whether PVE holds one for a request of the run's whose answer never
// came. A release that fails leaves the token journaled; a lock
// that stands after a lost request may be the run's, and is left for an
// operator.
func settleSDNLock(ctx context.Context, manager *sdn.Manager, r *journal.Record) error {
	if manager.LockToken() != "" {
		noLockAPI, err := manager.ReleaseAdoptedToken(ctx)
		if err != nil {
			return err
		}
		switch {
		case noLockAPI:
			// A journal written on a PVE with an SDN lock, recovered against one
			// without (PVE 8): the token is held by nothing, and neither was
			// there a lock to wait for. The objects the run made are deleted
			// without one, as on any PVE 8.
			say("INFO", "This PVE has no SDN configuration lock (PVE 8), so the lock token the interrupted run journaled (from a PVE that has one) is held by nothing and was dropped from the journal.")
		case manager.UnlockedForeign():
			say("INFO", "PVE's SDN configuration lock is another client's: the lock the interrupted run held was released already.")
		default:
			say("INFO", "Released the SDN configuration lock the interrupted run held.")
		}
	}
	if !manager.LockRequestUnresolved() {
		return nil
	}
	err := manager.Lock(ctx)
	switch {
	case err == nil:
		// PVE granted a lock: none stood, so the request's was never made or
		// is gone. The probe's own lock is released again.
		return manager.Unlock(ctx)
	case errors.Is(err, sdn.ErrPendingSDNChanges):
		// PVE refuses the lock over pending changes only while none stands.
		return nil
	case errors.Is(err, sdn.ErrSDNLockHeld):
		return fmt.Errorf("PVE's SDN configuration lock stands, and it may be the one the interrupted run requested at %s, whose answer never came: PVE's lock has no owner but its token, which CertiStack never received. If no one else is changing the cluster's SDN, release it (pvesh delete /cluster/sdn/lock --force 1), then "+recoverhint.Again+": %w", r.SDNLockRequested, err)
	default:
		return fmt.Errorf("CertiStack could not find out whether PVE holds an SDN configuration lock for the interrupted run's lost request; "+recoverhint.Again+": %w", err)
	}
}

func nonEmpty(ids []string) []string {
	var out []string
	for _, id := range ids {
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

// appendMissing adds id to ids unless it is there (an ID is compared as PVE
// compares it, without regard to case).
func appendMissing(ids []string, id string) []string {
	for _, known := range ids {
		if strings.EqualFold(known, id) {
			return ids
		}
	}
	return append(ids, id)
}

func anyState(states map[string]sdn.ObjectState, want ...sdn.ObjectState) bool {
	for _, state := range states {
		for _, w := range want {
			if state == w {
				return true
			}
		}
	}
	return false
}

func allAbsent(states map[string]sdn.ObjectState) bool {
	for _, state := range states {
		if state != sdn.Absent {
			return false
		}
	}
	return true
}

// confirmBridgesGone checks that the interrupted run's VNet bridges are gone
// from this node: PVE's configuration no longer having a VNet does not prove
// that the node's network reload removed its bridge.
func confirmBridgesGone(ctx context.Context, client *pve.Client, vnets []string) error {
	if len(vnets) == 0 {
		return nil
	}
	nodes, _ := client.NodeCount(ctx)
	var errs []error
	for _, vnet := range vnets {
		if err := settleBridge(ctx, vnet, false, sysutil.SettleTimeout(nodes)); err != nil {
			errs = append(errs, fmt.Errorf("the interrupted run's VNet %s is gone from PVE's SDN configuration, but its bridge is still on this node; reload the node's network (ifreload -a), then "+recoverhint.Again+": %w", vnet, err))
		}
	}
	return errors.Join(errs...)
}

func recoveryPVEClientFromEnv() (*pve.Client, error) {
	baseURL := strings.TrimSpace(os.Getenv("PVE_URL"))
	tokenID := strings.TrimSpace(os.Getenv("PVE_TOKEN_ID"))
	tokenSecret := strings.TrimSpace(os.Getenv("PVE_TOKEN_SECRET"))
	if baseURL == "" || tokenID == "" || tokenSecret == "" {
		return nil, errors.New("PVE_URL, PVE_TOKEN_ID, and PVE_TOKEN_SECRET must all be set")
	}
	insecureValue := strings.ToLower(strings.TrimSpace(os.Getenv("PVE_TLS_INSECURE")))
	insecure := insecureValue == "true" || insecureValue == "1"
	// NewClient refuses TLSInsecure without the lab opt-in, so recovery (which
	// node-run performs before preflight) never sends the token unverified.
	return pve.NewClient(pve.Config{
		BaseURL:     baseURL,
		TokenID:     tokenID,
		TokenSecret: tokenSecret,
		TLSInsecure: insecure,
		TLSCAFile:   strings.TrimSpace(os.Getenv("CERTISTACK_PVE_CA_SOURCE")),
	}), nil
}

// hostBootID is this boot's identity (the kernel's boot_id); tests replace it.
var hostBootID = process.CurrentBootID

// hostAddressOfAnotherBoot reports whether the host probe address record was
// captured in a boot other than this one. A record without a boot is not: it
// is reconciled by its interface index and table handle alone. When this boot's
// identity cannot be read, the record can be neither compared nor settled, and
// the error says what to check and remove; nothing is removed.
func hostAddressOfAnotherBoot(address journal.TrackedHostAddress) (bool, error) {
	if address.BootID == "" {
		return false, nil
	}
	boot, err := hostBootID()
	if err != nil {
		table := sysutil.IsolationTableName(address.Interface, address.CIDR)
		return false, fmt.Errorf("not removing host probe address %s on interface %s or containment table %s: the journal recorded them in a boot, and this boot's identity cannot be read (%v), so they cannot be told from ones of this boot. Check that they are the interrupted run's (`ip address show dev %s`, `nft list table inet %s`), remove them yourself (`ip address delete %s dev %s`, `nft delete table inet %s`), then "+recoverhint.Again, address.CIDR, address.Interface, table, err, address.Interface, table, address.CIDR, address.Interface, table)
	}
	return boot != address.BootID, nil
}

// settledWithItsBoot says why a host probe address record of another boot is
// dropped without anything being read or removed.
func settledWithItsBoot(address journal.TrackedHostAddress) string {
	table := sysutil.IsolationTableName(address.Interface, address.CIDR)
	what := "probe address " + address.CIDR + " on interface " + address.Interface + " and its containment table " + table
	if address.ContainmentOnly {
		what = "containment table " + table + " for " + address.CIDR + " on interface " + address.Interface
	}
	return "Settled the journal's record of " + what + ": it was made in boot " + address.BootID + ", which has ended, and they went with it. Anything of that name there now was not made by that run, and was left alone"
}

// hasHostAddress reports whether the journal records the host probe address
// cidr on iface.
func hasHostAddress(addresses []journal.TrackedHostAddress, iface, cidr string) bool {
	for _, address := range addresses {
		if address.Interface == iface && address.CIDR == cidr {
			return true
		}
	}
	return false
}

// missingHostIdentity names the identity a recorded host probe address lacks,
// or "" when it has what recovery needs to tell the run's own from a
// replacement: the interface index and the table handle for an address, the
// table handle for a containment table left alone.
func missingHostIdentity(address journal.TrackedHostAddress) string {
	switch {
	case address.TableHandle == 0 && !address.ContainmentOnly && address.IfIndex == 0:
		return "the interface index and the containment table handle"
	case address.TableHandle == 0:
		return "the containment table handle"
	case !address.ContainmentOnly && address.IfIndex == 0:
		return "the interface index"
	}
	return ""
}

func noHostIdentityError(address journal.TrackedHostAddress, missing string) error {
	table := sysutil.IsolationTableName(address.Interface, address.CIDR)
	what := "address " + address.CIDR + " on interface " + address.Interface + " and containment table " + table
	if address.ContainmentOnly {
		what = "containment table " + table + " for " + address.CIDR + " on interface " + address.Interface
	}
	return fmt.Errorf("not removing %s: the journal does not record %s, so they cannot be told from ones someone else made. Check that they are the interrupted run's (`ip address show dev %s`, `nft list table inet %s`), remove them yourself (`ip address delete %s dev %s`, `nft delete table inet %s`), then "+recoverhint.Again, what, missing, address.Interface, table, address.CIDR, address.Interface, table)
}

// screenshotName is the form of a diagnostic screenshot file the screendump
// probe makes: certistack-failure-vm<id>-<unix time>-<8 hex digits>.ppm|png.
var screenshotName = regexp.MustCompile(`^certistack-failure-vm[0-9]+-[0-9]+-[0-9a-f]{8}\.(ppm|png)$`)

// removeScreenshotFile removes one journaled screenshot file. A file that is
// already gone is done. Anything else that is not a plain file of that name
// directly in the run's scratch directory is refused and left, with the reason.
func removeScreenshotFile(scratch, path string) error {
	if scratch == "" {
		scratch = sysutil.DefaultScratchDir
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != filepath.Clean(scratch) || !screenshotName.MatchString(filepath.Base(path)) {
		return fmt.Errorf("left %s in place: it is not a screenshot file of the run's scratch directory %s, so it is not removed; inspect it, then remove it or its entry in the journal by hand", path, scratch)
	}
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("cannot look at the recorded screenshot file %s: %w", path, err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("left %s in place: it is not a regular file, so it is not removed", path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove the recorded screenshot file %s: %w", path, err)
	}
	say("INFO", "Removed %s.", path)
	return nil
}

// releaseStaleLoops is sysutil.ReleaseStaleFUSELoopsSince; tests replace it.
var releaseStaleLoops = sysutil.ReleaseStaleFUSELoopsSince

// removeUnidentifiedDelta removes a journaled disk file that has no recorded
// identity (a staging file, named with the run's token, or an entry journaled
// without one) by its path: only a plain file that DeltaRemovableByPath allows
// is removed, and anything else is left in place, with the reason. A file that
// is already gone is done.
func removeUnidentifiedDelta(path string) error {
	if !DeltaRemovableByPath(path) {
		return fmt.Errorf("left %s in place: the journal records no identity for it and it is not named as a disk file CertiStack makes (certistack-delta-... or certistack-copy-...), so nothing shows it is the interrupted run's; inspect it, then remove it or its line in delta_files of the journal by hand", path)
	}
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("cannot look at the recorded delta overlay %s: %w", path, err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("left %s in place: it is not a regular file, so it is not the disk file the interrupted run created; inspect it, then remove it or its line in delta_files of the journal by hand", path)
	}
	slog.Info("unlinking recorded ephemeral delta overlay", "path", path)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove recorded delta overlay %s: %w", path, err)
	}
	say("INFO", "Removed %s.", path)
	return nil
}

// releaseStaleLoopsOf detaches the stale FUSE loops an interrupted run's maps
// left, by the baseline the run journaled with its first map. A journal without
// one releases nothing: the stale loop is then the operator's, as the
// preflight check says.
func releaseStaleLoopsOf(parent context.Context, r *journal.Record) error {
	unresolved := len(r.UnresolvedMapIntents())
	if unresolved == 0 {
		return nil
	}
	var baseline []string
	found := false
	for _, intent := range r.MapIntents {
		if intent.StaleLoopsChecked {
			baseline, found = intent.StaleLoopsBefore, true
			break
		}
	}
	if !found {
		return nil
	}
	if err := parent.Err(); err != nil {
		return fmt.Errorf("not started: releasing the stale FUSE loops an interrupted PBS map left: recovery was interrupted: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	released, problems := releaseStaleLoops(ctx, baseline, unresolved)
	for _, device := range released {
		slog.Warn("released a stale FUSE loop an interrupted PBS map left", "device", device)
		say("WARN", "Released %s, a loop device an interrupted PBS map of the run attached and left behind.", device)
	}
	return errors.Join(problems...)
}

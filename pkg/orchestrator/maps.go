// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/progress"
)

// mapSourceDrive maps one backed-up disk of snapshot read-only and returns
// its loop device. It is the one way CertiStack maps a backup, for a run's
// restore and for init's inspection alike:
//   - the map is journaled before proxmox-backup-client starts, with what it
//     reads from (never the repository itself) and a token that only its own
//     processes carry, so that recovery can release a map whose worker died
//     while it was being made;
//   - a map that fails is released through that record, and teardown tries
//     again when that fails;
//   - the loop's kernel identity (its backing file) is recorded before the
//     device is used, and its release is registered on the cleanup stack
//     before the journal records the loop.
//
// vmid names the VM in the cleanup step, and holds the map while that sandbox
// VM may still run (keptForVM). mapped, when set, is told whether the client
// made the map, before anything else is done with it. timings may be nil.
func (o *Orchestrator) mapSourceDrive(ctx context.Context, vmid int, snapshot string, sourceDrive config.SourceDrive, timings *attest.PhaseTimings, mapped func(bool)) (string, error) {
	// Journal the map before making it: a worker killed while the
	// client maps, or a map that times out after its loop device
	// exists, would otherwise leave a device no journal names.
	nameSuffix, err := pbs.MapNameSuffix(snapshot, sourceDrive.Archive)
	if err != nil {
		return "", fmt.Errorf("PBS map of %s: %w", sourceDrive.Slot, err)
	}
	mapArchive, err := pbs.MapArchiveName(sourceDrive.Archive)
	if err != nil {
		return "", fmt.Errorf("PBS map of %s: %w", sourceDrive.Slot, err)
	}
	// With it, what the map reads from (never the repository itself) and
	// a token that only this map's processes carry: recovery stops a map
	// process only when both show it is this map's.
	mapOwner, err := o.pbsClient.MapOwner(snapshot, sourceDrive.Archive)
	if err != nil {
		return "", fmt.Errorf("PBS map of %s: %w", sourceDrive.Slot, err)
	}
	mapToken, err := pbs.NewMapToken()
	if err != nil {
		return "", fmt.Errorf("PBS map of %s: %w", sourceDrive.Slot, err)
	}
	intent := o.record.AddMapIntent(snapshot, mapArchive, nameSuffix, time.Now())
	o.record.SetMapIntentIdentity(intent, mapOwner, mapToken)
	o.beginStaleLoopWatch(intent)
	if err := o.flushJournal(); err != nil {
		return "", err
	}
	// A map that failed or timed out may have left a process or a loop
	// behind: they are released through the intent, which proves them the
	// run's. Teardown tries again if that fails.
	releasePartial := func(err error) error {
		release := func() error {
			return o.unmapLeakedMapsFn([]*journal.MapIntent{&o.record.MapIntents[intent]}, o.trackedLoopDevices(), o.flushJournal)
		}
		if leakErr := release(); leakErr != nil {
			err = errors.Join(err, fmt.Errorf("release a partial map: %w", leakErr))
			// A partial map it cannot release either leaves the journal
			// unclean for recovery.
			o.cleanup.Push(fmt.Sprintf("release the partial PBS map for VM %d %s", vmid, sourceDrive.Slot), release)
		}
		return err
	}
	tMap := time.Now()
	loopDevice, err := o.pbsClient.MapWithToken(ctx, snapshot, sourceDrive.Archive, mapToken)
	if timings != nil {
		timings.PBSMappingSec += time.Since(tMap).Seconds()
	}
	if mapped != nil {
		mapped(err == nil)
	}
	if err != nil {
		return "", fmt.Errorf("PBS map error for %s: %w", sourceDrive.Slot, releasePartial(err))
	}
	progress.Info("Storage", "Mounted PBS snapshot %s (%s) read-only via %s.", snapshot, sourceDrive.Slot, loopDevice)

	// The kernel's identity of what the loop is attached to, recorded now,
	// is what says later that the device is still the run's: a loop number
	// is reused by whatever maps next once this map is gone. Without
	// it nothing is detached by device path: the map is released through its
	// intent instead. The attachment's disk sequence number, recorded with it
	// when the kernel has one, still tells the run's attachment once the map's
	// FUSE file is gone and the backing reads "/".
	loop, backingErr := sysutil.LoopAttachment(loopDevice)
	if backingErr != nil {
		return "", releasePartial(fmt.Errorf("verify mapped PBS loop identity for %s: %w", sourceDrive.Slot, backingErr))
	}
	// The device is the one the client's output names. Only a device attached
	// to this map's file is the backup: any other (another map's, a host
	// loop) is neither read nor recorded, and never released by the run.
	if !pbs.IsMapFile(loop.Backing, nameSuffix) {
		return "", releasePartial(fmt.Errorf("proxmox-backup-client named %s as its map of %s, but %s is attached to %q, not this map's file in %s: it is not the backup, so the run neither reads nor releases it. Run the plan again; if this repeats, report it with the output of losetup --list", loopDevice, sourceDrive.Slot, loopDevice, loop.Backing, pbs.MapRunDir))
	}
	o.cleanup.Push(fmt.Sprintf("unmap loop device %s for VM %d %s", loopDevice, vmid, sourceDrive.Slot), func() error {
		if err := o.keptForVM(vmid, "PBS map "+loopDevice); err != nil {
			return err
		}
		return o.unmapRecordedLoop(loop, o.record.MapIntents[intent])
	})
	o.record.AddTrackedLoop(loop)
	o.record.ResolveMapIntent(intent, loopDevice)
	if err := o.flushJournal(); err != nil {
		return "", err
	}
	return loopDevice, nil
}

// trackedLoopDevices is every loop device this run's journal records.
func (o *Orchestrator) trackedLoopDevices() map[string]bool {
	tracked := map[string]bool{}
	for _, loop := range o.record.Loops {
		tracked[loop.Device] = true
	}
	if o.record.LoopDevice != "" {
		tracked[o.record.LoopDevice] = true
	}
	return tracked
}

// releaseLoopHolders stops what the host assembled from a mapped disk's
// partitions (software RAID, LVM, dm-crypt) before the loop is unmapped; tests
// replace it. See sysutil.ReleaseLoopHolders.
var releaseLoopHolders = sysutil.ReleaseLoopHolders

// ownedLoops is every loop device this run's journal records, each with the
// backing file it had when it was mapped, and the loop device (device,
// backing) being released.
func (o *Orchestrator) ownedLoops(device, backing string) []sysutil.LoopIdentity {
	owned := []sysutil.LoopIdentity{{Device: device, Backing: backing}}
	seen := map[string]bool{device: true}
	for _, loop := range o.record.Loops {
		if !seen[loop.Device] {
			seen[loop.Device] = true
			owned = append(owned, sysutil.LoopIdentity{Device: loop.Device, Backing: loop.Backing})
		}
	}
	if o.record.LoopDevice != "" && !seen[o.record.LoopDevice] {
		owned = append(owned, sysutil.LoopIdentity{Device: o.record.LoopDevice, Backing: o.record.LoopBacking})
	}
	return owned
}

// unmapRecordedLoop releases a loop device this run mapped, recorded with the
// backing file it had then, and only while it still has it: a loop
// number is reused by whatever maps next, once this run's map is gone, and
// then belongs to someone else. The identity is checked before the map's daemon
// is stopped and again before the detach; a device that is gone is released;
// one that backs another file is not touched, and is clean for this run only if
// nothing of its map remains.
//
// The map's daemon is stopped by CertiStack itself, not by
// proxmox-backup-client unmap, which rereads the map's pid file and signals
// that bare PID, a process that may have taken the PID since it was checked:
// recovery.StopMapDaemon signals, through a pidfd, only the process it has
// verified to be this run's daemon. It runs only when the pid file names no
// live process or that daemon (recovery.MayStopMapDaemon, which is asked first,
// before anything is done to the map); when it names something else the
// verified detach alone runs. A daemon that cannot be stopped leaves the loop
// attached and is the step's error.
//
// Devices the host assembled from the loop's partitions (a guest's software
// RAID or LVM) hold it, and a loop that is held stays after the unmap. They
// are stopped first, when every member of theirs is a loop of this run's
// journal; one that is not is left, and the map is not unmapped. After the
// unmap the loop is waited for until it is gone: a loop that stays, with the
// devices that hold it named, is a cleanup failure, never a released map.
func (o *Orchestrator) unmapRecordedLoop(loop journal.TrackedLoop, intent journal.MapIntent) error {
	device, backing := loop.Device, loop.Backing
	mayStop, err := o.mayStopMapDaemonFn(backing, intent)
	if err != nil {
		return fmt.Errorf("unmap %s: %w", device, err)
	}
	stopped, err := releaseLoopHolders(context.Background(), device, o.ownedLoops(device, backing))
	if len(stopped) > 0 {
		progress.Info("Cleanup", "Stopped %s, which the host assembled from the partitions of %s, before unmapping it.", sysutil.HolderLabels(stopped), device)
	}
	if err != nil {
		return fmt.Errorf("unmap %s: %w", device, err)
	}
	var stopDaemon func() error
	if mayStop {
		stopDaemon = func() error {
			note, err := o.stopMapDaemonFn(backing, intent)
			if err != nil {
				return fmt.Errorf("unmap %s: %w", device, err)
			}
			if note != "" {
				progress.Warn("Cleanup", "Detaching %s without stopping a map daemon: %s.", device, note)
			}
			return nil
		}
	}
	err = o.pbsClient.Unmap(context.Background(), device, backing, stopDaemon)
	if !errors.Is(err, sysutil.ErrLoopReused) {
		if err != nil {
			return err
		}
		return sysutil.AwaitLoopReleased(loop, loopSettleAttempts, loopSettleInterval)
	}
	// The map's daemon is gone and the loop's backing no longer reads the map's
	// file (it reads "/" once the FUSE file is gone), so Unmap detached nothing.
	// It is either another operation's loop now, which the wait settles at once,
	// or the run's own attachment on its way out of the kernel: the map sets
	// autoclear, and whatever still has it open (the libguestfs appliance that
	// read it, udev probing the device) lets go within seconds. A 16-VM run on a
	// busy node had six such loops still attached a second after their unmap and
	// gone four seconds later; a single look failed that run's teardown. They
	// get the same wait as an unmap that ran.
	if err := sysutil.AwaitLoopReleased(loop, loopSettleAttempts, loopSettleInterval); err != nil {
		return err
	}
	note, noteErr := o.reusedLoopNoteFn(device, backing)
	if noteErr != nil {
		return noteErr
	}
	progress.Warn("Cleanup", "%s", note)
	return nil
}

// beginStaleLoopWatch records, before a map begins, the stale FUSE loops the
// host already has (journaled with the intent, for recovery), and the first time
// registers the last step of teardown: detaching a stale loop that appeared
// since. A map that is interrupted while its daemon starts can leave a loop its
// daemon attached and then died without detaching, after which the file behind
// it is gone and nothing names the loop: no journal entry, no backing path. The
// host lock is this run's alone, so what is stale now and was not before is
// what such a map left; a loop that was stale before is never touched.
func (o *Orchestrator) beginStaleLoopWatch(intent int) {
	if o.staleLoopDevicesFn == nil {
		return
	}
	before := o.staleLoopDevicesFn()
	o.record.SetMapIntentStaleLoops(intent, before)
	if o.staleLoopBaselineTaken {
		return
	}
	o.staleLoopBaseline, o.staleLoopBaselineTaken = before, true
	if o.cleanup == nil {
		return
	}
	// Pushed first, so the LIFO unwind runs it after every map is released.
	o.cleanup.Push("release stale FUSE loop devices an interrupted PBS map left behind", func() error {
		unresolved := len(o.record.UnresolvedMapIntents())
		if unresolved == 0 || o.releaseStaleLoopsFn == nil {
			return nil
		}
		released, problems := o.releaseStaleLoopsFn(context.Background(), o.staleLoopBaseline, unresolved)
		for _, device := range released {
			progress.Warn("Cleanup", "Released %s, a loop device an interrupted PBS map attached and left behind.", device)
		}
		return errors.Join(problems...)
	})
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cliftcloud/certistack/internal/diskslot"
	"github.com/cliftcloud/certistack/internal/guestnet"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// guestNetworkOverlays are the overlays guest-network recovery opens: one per
// restored disk, in the order the sandbox VM presents its disks. The
// selected boot disk is not a guarantee that the whole installation is on it:
// a root filesystem can live on a second disk, an LVM volume group can span
// several, and libguestfs sees a multi-disk guest whole only when every disk
// is added. The boot disk must be one of them, and none may be missing.
func guestNetworkOverlays(disks []pve.DiskOverlay, bootSlot string) ([]string, error) {
	ordered := append([]pve.DiskOverlay(nil), disks...)
	sort.SliceStable(ordered, func(i, j int) bool { return diskslot.Less(ordered[i].Slot, ordered[j].Slot) })
	overlays := make([]string, 0, len(ordered))
	boot := false
	for _, disk := range ordered {
		if disk.Path == "" {
			return nil, fmt.Errorf("restored disk %s has no overlay to open for guest network recovery", disk.Slot)
		}
		boot = boot || disk.Slot == bootSlot
		overlays = append(overlays, disk.Path)
	}
	if !boot {
		return nil, fmt.Errorf("boot disk %s has no overlay among the restored disks", bootSlot)
	}
	return overlays, nil
}

// guestNetworkConfig is what Apply is given for one VM: every restored disk's
// overlay, so the adapter inspects and writes the guest as the guest has it.
func (o *Orchestrator) guestNetworkConfig(vmCfg config.VM, address string, overlays []string, progress func(string)) guestnet.Config {
	return guestnet.Config{
		VMID:               vmCfg.VMID,
		Overlays:           overlays,
		MAC:                vmCfg.MAC,
		Address:            address,
		CIDR:               o.plan.Network.IPRange,
		Mode:               vmCfg.NetworkRecovery.EffectiveMode(),
		InterfaceName:      vmCfg.NetworkRecovery.InterfaceName,
		OnlyNIC:            len(vmCfg.AdditionalNICs) == 0,
		CaptureDiagnostics: vmCfg.NetworkRecovery.CaptureDiagnostics,
		ProbeIP:            o.plan.Network.ProbeIP,
		FirewallPorts:      firewallPorts(vmCfg.Probes),
		Progress:           progress,
	}
}

// guestNetworkTarget names the overlays a plan step writes into.
func guestNetworkTarget(overlays []string) string {
	return strings.Join(overlays, ", ")
}

// applyGuestNetwork adapts the restored guest's network in its overlays.
func (o *Orchestrator) applyGuestNetwork(ctx context.Context, cfg guestnet.Config) (guestnet.Result, error) {
	if o.applyGuestNetworkFn != nil {
		return o.applyGuestNetworkFn(ctx, cfg)
	}
	return guestnet.New(o.opts.ScratchDir).Apply(ctx, cfg)
}

func (o *Orchestrator) readNetworkDiagnostic(ctx context.Context, overlays []string) (string, error) {
	if o.readNetworkDiagnosticFn != nil {
		return o.readNetworkDiagnosticFn(ctx, overlays)
	}
	return guestnet.ReadDiagnostics(ctx, overlays)
}

// vmQuiescence is what teardown knows of a sandbox VM at the point between
// stopping it and destroying it.
type vmQuiescence int

const (
	// vmNotConfirmedStopped: PVE did not say the VM stopped, or teardown could
	// not get as far as asking. QEMU may still be writing to the VM's disks.
	vmNotConfirmedStopped vmQuiescence = iota
	// vmStopped: PVE says the VM is stopped. QEMU no longer writes to its disks,
	// which are still there: PVE frees them with the destroy that follows.
	vmStopped
	// vmAbsent: PVE says the VM does not exist. Nothing runs. What PVE freed
	// with the VM is gone; a file the VM never owned is still there.
	vmAbsent
)

// beforeVMDestroy registers fn to run once for VM vmid, in the VM's teardown
// (destroyOwnedVM), at the point the VM has been stopped and PVE has not yet
// destroyed it. PVE's destroy frees the volumes the VM owns, which includes the
// disposable overlays: they are volumes of the scratch directory storage, so
// anything that has to read them after QEMU stopped has to read them here.
func (o *Orchestrator) beforeVMDestroy(vmid int, fn func(state vmQuiescence, why error)) {
	if o.preDestroy == nil {
		o.preDestroy = make(map[int]func(vmQuiescence, error))
	}
	o.preDestroy[vmid] = fn
}

// runBeforeVMDestroy runs what beforeVMDestroy registered for VM vmid, once. A
// panic in it is logged and goes no further: the destroy that follows must
// happen whatever the read did.
func (o *Orchestrator) runBeforeVMDestroy(vmid int, state vmQuiescence, why error) {
	fn := o.preDestroy[vmid]
	if fn == nil {
		return
	}
	delete(o.preDestroy, vmid)
	defer func() {
		if r := recover(); r != nil {
			slog.Error("the read before the destroy of a sandbox VM panicked", "vmid", vmid, "panic", r)
		}
	}()
	fn(state, why)
}

// captureNetworkDiagnosticBeforeDestroy registers the read of the failed VM's
// boot-time diagnostic from its disposable overlays. It reads nothing unless
// this VM later has a failed probe and live QGA diagnostics were unavailable
// (or partial); a passing validation must not pay for a guestfs read or emit an
// irrelevant diagnostic warning during teardown.
//
// The read opens the overlay, so QEMU must no longer be writing to it:
// it runs once PVE reports the VM stopped. It cannot run after the destroy, as
// it once did: PVE's destroy frees the overlay, which is a volume of the sandbox
// VM, and the read then finds no file. If the VM is not confirmed stopped the
// overlay is not read at all and the report says so.
//
// The read is bounded (guestnet's diagnosticReadTimeout), and none of its
// outcomes is a cleanup failure: the diagnostic is evidence, and a missing or
// unreadable one leaves nothing behind. What went wrong is said in the
// diagnostic itself and in a warning.
func (o *Orchestrator) captureNetworkDiagnosticBeforeDestroy(vmid int, overlays []string) {
	o.beforeVMDestroy(vmid, func(state vmQuiescence, why error) {
		o.captureNetworkDiagnostic(vmid, overlays, state, why)
	})
}

func (o *Orchestrator) captureNetworkDiagnostic(vmid int, overlays []string, state vmQuiescence, why error) {
	if !o.shouldReadNetworkDiagnostic(vmid) {
		// No probe failed, or a failed probe captured a complete live QGA
		// diagnostic while the VM was running: that stronger evidence is not
		// replaced by a delayed overlay fallback.
		return
	}
	live, capturedLive := o.networkDiagnostics[vmid]
	// note says in the diagnostic why the overlay did not add to it. A live
	// diagnostic without listeners is kept, with the note under it.
	note := func(text string) {
		if capturedLive {
			o.networkDiagnostics[vmid] = live + "\n[boot-time diagnostic from the COW overlay]\n" + text
		} else {
			o.networkDiagnostics[vmid] = text
		}
	}
	if state == vmNotConfirmedStopped {
		progress.Warn("Sandbox", "Guest network diagnostic for VM %d was not read from its COW overlay: the VM was not confirmed stopped (%v), so QEMU may still be writing to it. The teardown goes on to destroy the VM, which removes the overlay.", vmid, why)
		note("Not read from the COW overlay: the sandbox VM was not confirmed stopped, so QEMU may still have been writing to it.")
		return
	}
	if gone := missingOverlays(overlays); len(gone) > 0 {
		progress.Warn("Sandbox", "Guest network diagnostic for VM %d was not read: its COW overlay was already removed (%s).", vmid, strings.Join(gone, ", "))
		note(fmt.Sprintf("Not read from the COW overlay: the overlay was already removed (%s).", strings.Join(gone, ", ")))
		return
	}
	diagnostic, err := o.readNetworkDiagnostic(context.Background(), overlays)
	if err != nil {
		if gone := missingOverlays(overlays); len(gone) > 0 {
			progress.Warn("Sandbox", "Guest network diagnostic for VM %d was not read: its COW overlay was removed while it was read (%s).", vmid, strings.Join(gone, ", "))
			note(fmt.Sprintf("Not read from the COW overlay: the overlay was already removed (%s).", strings.Join(gone, ", ")))
			return
		}
		progress.Warn("Sandbox", "Guest network diagnostic for VM %d could not be read from its COW overlay: %v", vmid, err)
		note(fmt.Sprintf("The boot-time diagnostic could not be read from the COW overlay: %v", err))
		return
	}
	if capturedLive {
		// The live read had interfaces only: add what the guest recorded at
		// boot, listeners and all.
		if diagnostic != "" {
			progress.Info("Sandbox", "Added VM %d's boot-time listeners and services from its disposable COW overlay.", vmid)
			note(diagnostic)
		}
		return
	}
	if diagnostic == "" {
		diagnostic = "Guest did not produce the optional network diagnostic before shutdown."
		progress.Warn("Sandbox", "Guest network diagnostic was not produced before shutdown for VM %d.", vmid)
	} else {
		progress.Info("Sandbox", "Captured guest network diagnostic for VM %d from its disposable COW overlay.", vmid)
	}
	o.networkDiagnostics[vmid] = diagnostic
}

// missingOverlays names the overlays that are no longer on disk. A stat that
// fails for another reason is not "removed": the read is attempted and its own
// error says what is wrong.
func missingOverlays(overlays []string) []string {
	var gone []string
	for _, overlay := range overlays {
		if _, err := os.Stat(overlay); errors.Is(err, os.ErrNotExist) {
			gone = append(gone, filepath.Base(overlay))
		}
	}
	return gone
}

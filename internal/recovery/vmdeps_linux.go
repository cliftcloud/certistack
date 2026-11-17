//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// vmsMayRemain says why a sandbox VM or QEMU process the journal records may
// still exist, or nil once each is confirmed gone. running are the recorded
// QEMU processes a stop did not confirm gone. The recorded VMs are asked
// about afresh, after recoverPVEResources, so their absence is what PVE says
// now, not what a step assumed.
//
// parent is the operator's interrupt: a read it ends is an answer of "cannot be
// confirmed gone", which keeps what the VMs use in place.
func vmsMayRemain(parent context.Context, r *journal.Record, running []string) error {
	reasons := append([]string(nil), running...)
	if len(r.VMs) > 0 {
		client, err := recoveryPVEClientFromEnv()
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("the sandbox VMs cannot be confirmed gone: %v", err))
		} else {
			ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
			defer cancel()
			if err := recordedVMsMayRemain(ctx, client, r); err != nil {
				reasons = append(reasons, err.Error())
			}
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	return errors.New(strings.Join(reasons, "; "))
}

// recordedVMsMayRemain says why a sandbox VM the journal records may still
// exist, or nil once PVE answers that none of them does. An unreadable
// answer or a malformed identity is not absence.
func recordedVMsMayRemain(ctx context.Context, client *pve.Client, r *journal.Record) error {
	var reasons []string
	for _, vm := range r.VMs {
		if vm.VMID <= 0 || strings.TrimSpace(vm.Node) == "" {
			reasons = append(reasons, fmt.Sprintf("the recorded VM identity vmid=%d node=%q cannot be confirmed gone", vm.VMID, vm.Node))
			continue
		}
		if err := vmMayStillExist(ctx, client, vm, r.RunID); err != nil {
			reasons = append(reasons, err.Error())
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	return errors.New(strings.Join(reasons, "; "))
}

// vmMayStillExist asks PVE about the exact node and VM ID, and returns nil
// only when PVE answers that the VM does not exist. It is the proof that a
// stop or a destruction did its work: a task's own success is not, since
// the task can be another's, or PVE's account of it wrong. A VM
// that is still there, an unreadable answer and an empty one all say why the
// VM cannot be taken for gone.
func vmMayStillExist(ctx context.Context, client *pve.Client, vm journal.TrackedVM, runID string) error {
	status, err := client.GetVMStatus(ctx, vm.Node, vm.VMID)
	switch {
	case client.VMNotFound(ctx, err, vm.Node, vm.VMID):
		return nil
	case err != nil:
		return fmt.Errorf("sandbox VM %d on %s cannot be confirmed gone (%v)", vm.VMID, vm.Node, err)
	case status == nil:
		return fmt.Errorf("sandbox VM %d on %s cannot be confirmed gone (PVE returned an empty status)", vm.VMID, vm.Node)
	}
	// A VM at the ID without the run's markers is not touched. It may
	// be a replacement that reuses the ID, and it may be this run's VM whose
	// markers were removed: only an operator can tell, so it is reported and
	// the journal stays.
	if owned, ownErr := client.IsCertiStackRunOwned(ctx, vm.Node, vm.VMID, runID); ownErr == nil && !owned {
		return fmt.Errorf("sandbox VM %d on %s still exists (status: %s) but does not carry this run's ownership markers, so it is not touched; if it is not this run's VM (the ID was reused), check it and remove VM %d from the journal's vms", vm.VMID, vm.Node, status.Status, vm.VMID)
	}
	return fmt.Errorf("sandbox VM %d on %s still exists (status: %s)", vm.VMID, vm.Node, status.Status)
}

// unbackedNotFound is the error of a stop or destroy that PVE answered with an
// HTTP 404 which the cluster does not back (Client.VMNotFound did not take it
// for the VM's absence), with what PVE says of the VM now: a VM that is still
// there, or one that is there and is not the run's, is what the operator has to
// act on, not an opaque "not found". Any other error is returned as it is.
func unbackedNotFound(ctx context.Context, client *pve.Client, vm journal.TrackedVM, runID string, err error) error {
	if !pve.IsNotFound(err) {
		return err
	}
	if remains := vmMayStillExist(ctx, client, vm, runID); remains != nil {
		return fmt.Errorf("%w; PVE's answer was an HTTP 404 that the cluster does not back, and reading the VM again: %v", err, remains)
	}
	return err
}

// vmStoppedAfterTask asks PVE about a VM whose stop task reported success,
// and returns nil only when the VM is stopped or gone (gone says which). A VM
// still running, an unreadable answer and an empty one are failures: the VM is
// not destroyed on the word of a task that may not be its own.
func vmStoppedAfterTask(ctx context.Context, client *pve.Client, vm journal.TrackedVM) (gone bool, err error) {
	status, err := client.GetVMStatus(ctx, vm.Node, vm.VMID)
	switch {
	case client.VMNotFound(ctx, err, vm.Node, vm.VMID):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("recorded VM %d on %s cannot be confirmed stopped, although its stop task reported success: %w", vm.VMID, vm.Node, err)
	case status == nil:
		return false, fmt.Errorf("recorded VM %d on %s cannot be confirmed stopped, although its stop task reported success: PVE returned an empty status", vm.VMID, vm.Node)
	case status.Status != "stopped":
		return false, fmt.Errorf("recorded VM %d on %s is still %s, although its stop task reported success", vm.VMID, vm.Node, status.Status)
	}
	return false, nil
}

// vnetDeletionNote says what happens to a kept probe address when the
// journal's VNet is deleted, which recovery does before it decides whether a
// VM remains: the deletion does not wait for the VMs, so once it is applied
// the bridge goes, the address on it goes with it, and a surviving VM's NIC is
// on no bridge. Only the containment table stays, and a later recovery removes
// it once the address is gone and the VMs are.
func vnetDeletionNote(r *journal.Record) string {
	if len(r.SDNVNets) == 0 {
		return ""
	}
	for _, address := range r.HostAddresses {
		if !address.ContainmentOnly {
			return "; the sandbox VNet's deletion does not wait for the VMs: once it is applied, its bridge and the probe address on it are gone and the guest is left on no network, and only the containment stays"
		}
	}
	return ""
}

// recordedVMOwnedNow reads the VM's own configuration and requires the exact
// markers of the run that journaled it. It reports gone when PVE says
// the VM does not exist. A VM that is there without the run's markers is not
// the run's (a replacement at a reused ID, or a VM whose markers were removed):
// it is never stopped or destroyed, and the error says so for the operator.
func recordedVMOwnedNow(ctx context.Context, client *pve.Client, vm journal.TrackedVM, runID string) (gone bool, err error) {
	owned, err := client.IsCertiStackRunOwned(ctx, vm.Node, vm.VMID, runID)
	switch {
	case client.VMNotFound(ctx, err, vm.Node, vm.VMID):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("verify CertiStack ownership of VM %d: %w", vm.VMID, err)
	case !owned:
		return false, fmt.Errorf("refusing to destroy recorded VM %d: it does not carry this run's CertiStack ownership markers (a VM that reuses the ID, or one whose markers were removed); it was left alone", vm.VMID)
	}
	return false, nil
}

// vmDependencies names what the sandbox VMs use that the journal records,
// or "" when it records none of it.
func vmDependencies(r *journal.Record) string {
	var kept []string
	for _, address := range r.HostAddresses {
		if address.ContainmentOnly {
			kept = append(kept, fmt.Sprintf("the containment for %s on %s", address.CIDR, address.Interface))
		} else {
			kept = append(kept, fmt.Sprintf("host probe address %s on %s and its containment", address.CIDR, address.Interface))
		}
	}
	if loops := len(trackedLoops(*r)); loops > 0 {
		kept = append(kept, fmt.Sprintf("%d PBS map(s)", loops))
	}
	if r.Mapper.PID > 0 {
		kept = append(kept, fmt.Sprintf("map process %d", r.Mapper.PID))
	}
	overlays := 0
	for _, delta := range r.DeltaFiles {
		if delta != "" {
			overlays++
		}
	}
	if overlays > 0 {
		kept = append(kept, fmt.Sprintf("%d overlay file(s)", overlays))
	}
	return strings.Join(kept, ", ")
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/diskslot"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// maxFirmwareImageBytes bounds a restored firmware state image. A UEFI
// variable store is at most a few MiB and PVE's TPM state 4 MiB, so anything
// larger is not a firmware image.
const maxFirmwareImageBytes = 64 << 20

func firmwareFileName(vmid int, slot string, timestamp int64, index int) string {
	return fmt.Sprintf("certistack-delta-vm%d-%s-%d-%d.raw", vmid, slot, timestamp, index)
}

// restoreFirmwareDisks restores a UEFI source VM's variable store (efidisk0)
// and TPM state (tpmstate0) as disposable raw volumes. Unlike data disks
// they cannot be read-only maps behind a COW overlay: OVMF writes its
// variable store, and PVE keeps TPM state only in raw volumes. Both are
// small, so each is restored whole. The PBS client checks every chunk while
// restoring, and the SHA-256 of the restored image is the evidence. The
// copies hold the source's firmware secrets (Secure Boot variables, TPM
// keys), so they are private to root and journaled for removal like every
// overlay. When record is not nil, each disk's evidence is written into it as
// the disk is restored, and a disk whose restore failed says so, so a failure
// part way keeps what the earlier disks established.
func (o *Orchestrator) restoreFirmwareDisks(ctx context.Context, vmCfg config.VM, timestamp int64, timings *attest.PhaseTimings, record *probe.VMValidationRecord) ([]pve.FirmwareVolume, []probe.SourceDiskEvidence, error) {
	if len(vmCfg.FirmwareDisks) == 0 {
		return nil, nil, nil
	}
	if o.opts.OverlayStorage == "" {
		return nil, nil, fmt.Errorf("VM %d has firmware state to restore (%s): that needs storage.overlay_storage, because Proxmox VE attaches firmware state only from a storage volume", vmCfg.VMID, vmCfg.FirmwareDisks[0].Slot)
	}
	if o.restoreImageFn == nil {
		return nil, nil, fmt.Errorf("PBS restore is unavailable for the firmware state of VM %d", vmCfg.VMID)
	}

	volumes := make([]pve.FirmwareVolume, 0, len(vmCfg.FirmwareDisks))
	evidence := make([]probe.SourceDiskEvidence, 0, len(vmCfg.FirmwareDisks))
	for index, disk := range vmCfg.FirmwareDisks {
		name := firmwareFileName(vmCfg.VMID, disk.Slot, timestamp, index)
		volume := overlayVolumeID(o.opts.OverlayStorage, vmCfg.VMID, name)
		volumePath, err := o.overlayVolumePathFn(ctx, volume)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve firmware volume for %s: %w", disk.Slot, err)
		}
		if err := checkOverlayPath(volumePath, vmCfg.VMID, name); err != nil {
			return nil, nil, err
		}
		if err := o.prepareOverlayDirOnce(path.Dir(volumePath), vmCfg.VMID); err != nil {
			return nil, nil, err
		}
		// The restore writes a staging file this run named and journaled
		// first, as for overlays: an interrupted restore can leave a partial
		// file with source secrets. The finished file is published at the
		// volume path without replacing anything.
		tRestore := time.Now()
		err = o.createTracked(vmCfg.VMID, volumePath, func(staging string) error {
			return o.restoreImageFn(ctx, vmCfg.SourcePBS.Snapshot, disk.Archive, staging)
		})
		if timings != nil {
			timings.PBSMappingSec += time.Since(tRestore).Seconds()
		}
		if err != nil {
			setSourceDiskStatus(record, disk.Slot, probe.DiskRestoreFailed)
			return nil, nil, fmt.Errorf("restore %s from PBS: %w", disk.Slot, err)
		}
		digest, err := sealFirmwareImage(volumePath)
		if err != nil {
			setSourceDiskStatus(record, disk.Slot, probe.DiskRestoreFailed)
			return nil, nil, fmt.Errorf("restored %s: %w", disk.Slot, err)
		}
		volumes = append(volumes, pve.FirmwareVolume{Slot: disk.Slot, Volume: volume, Options: disk.Options})
		restored := probe.SourceDiskEvidence{
			Slot:              disk.Slot,
			Archive:           disk.Archive,
			ManifestReference: manifestReference(disk.Archive),
			IntegrityStatus:   "verified",
			ImageDigest:       digest,
		}
		evidence = append(evidence, restored)
		setSourceDisk(record, restored)
	}
	return volumes, evidence, nil
}

// sealFirmwareImage makes a restored image private and returns its SHA-256.
// It refuses anything but a regular file of plausible firmware size.
func sealFirmwareImage(p string) (string, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", p)
	}
	if info.Size() == 0 || info.Size() > maxFirmwareImageBytes {
		return "", fmt.Errorf("%s is %d bytes, not a firmware state image", p, info.Size())
	}
	if err := os.Chmod(p, 0o600); err != nil {
		return "", fmt.Errorf("secure %s: %w", p, err)
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", p, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// bootSlotFor is the disk the sandbox VM boots: the worker's choice from the
// source boot order, or PVE's first disk when the orchestrator runs without
// one. It must be one of the restored disks.
func bootSlotFor(vmCfg config.VM, drives []config.SourceDrive) (string, error) {
	slots := make([]string, 0, len(drives))
	for _, drive := range drives {
		slots = append(slots, drive.Slot)
	}
	if vmCfg.BootDisk == "" {
		return diskslot.First(slots), nil
	}
	for _, slot := range slots {
		if slot == vmCfg.BootDisk {
			return slot, nil
		}
	}
	return "", fmt.Errorf("VM %d boot disk %s is not one of its restored disks", vmCfg.VMID, vmCfg.BootDisk)
}

// pveNICs converts the plan's additional NICs for VM creation.
func pveNICs(nics []config.SourceNIC) []pve.NIC {
	var out []pve.NIC
	for _, nic := range nics {
		out = append(out, pve.NIC{Slot: nic.Slot, Model: nic.Model, MAC: nic.MAC})
	}
	return out
}

// windowsOSType reports a PVE Windows guest type (wxp, w2k, w2k3, w2k8,
// wvista, win7, win8, win10, win11), whose unversioned machine type PVE
// resolves from the VM's creation QEMU version.
func windowsOSType(ostype string) bool {
	return strings.HasPrefix(ostype, "w")
}

// unversionedMachine reports a machine setting PVE resolves at start: none
// (i440fx), or a bare pc, i440fx or q35 type with any options.
func unversionedMachine(machine string) bool {
	machineType, _, _ := strings.Cut(machine, ",")
	switch strings.TrimPrefix(machineType, "type=") {
	case "", "pc", "i440fx", "q35":
		return true
	}
	return false
}

// manifestReference is the PBS index file that backs an archive, for
// evidence: "drive-scsi0" becomes "drive-scsi0.img.fidx".
func manifestReference(archive string) string {
	switch {
	case path.Ext(archive) == ".fidx":
		return archive
	case path.Ext(archive) == ".img":
		return archive + ".fidx"
	default:
		return archive + ".img.fidx"
	}
}

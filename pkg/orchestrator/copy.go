// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/progress"
)

// copyFileName names a disk's local copy beside its overlay.
func copyFileName(vmid int, slot string, timestamp int64, diskIndex int) string {
	return fmt.Sprintf("certistack-copy-vm%d-%s-%d-%d.raw", vmid, slot, timestamp, diskIndex)
}

// copyInputs is what decides whether a VM's scan also copies its disks to
// local storage for the sandbox to boot from (copy-before-boot).
type copyInputs struct {
	mode        string // config.CopyBeforeBoot*; "" is auto
	vmBytes     int64  // the VM's mapped disks; -1 when unknown
	tierScanned int64  // the tier's disks already kept in the cache
	// tierBytes is the tier's disks all together, from the backups' recorded
	// sizes; 0 or less when they are not known, which decides nothing.
	tierBytes   int64
	budgetKnown bool
	budget      int64 // what the node can keep cached (see tierCache)
	freeBytes   int64 // free space where the copies go; -1 when unknown
	sharedDisk  bool  // the copies' disk also holds the cluster database
	// sharedUnknown is why it could not be determined whether it does; auto
	// then does not copy.
	sharedUnknown string
	// standalone is set when the node is known to be in no cluster: the database's
	// disk is then the node's own, and the risk is to its services, not to a cluster's corosync.
	standalone bool
	copied     int64 // what the run's earlier copies take
	capBytes   int64 // storage.max_copy_gib; 0 is no cap
	windows    bool  // the VM's guest is Windows: only the wording of the warning depends on it
}

// decideCopy says whether to copy, and gives a warning to show (or ""). It
// returns an error only when an explicit "always" cannot be honoured.
//
// Auto copies a VM whose disks would not all stay cached until its boot:
// a cold boot misses Windows' service start deadline. It also copies every
// VM of a tier whose disks together are more than the node can keep cached,
// the VMs that fit as well: a VM that boots from the backup map keeps running
// from the cache its scan filled, and the later VMs' reads would push that
// cache out under it (a four-controller domain went cold fifty minutes after
// its first controller booted). It never copies onto the cluster database's
// disk, whose writes can delay corosync, or without room for the copies and
// the overlays' growth.
func decideCopy(in copyInputs) (bool, string, error) {
	need := in.vmBytes + minOverlayStorageFreeBytes
	switch in.mode {
	case config.CopyBeforeBootNever:
		return false, "", nil
	case config.CopyBeforeBootAlways:
		if in.vmBytes < 0 {
			return false, "", fmt.Errorf("copy_before_boot: always, but the size of the VM's disks is unknown")
		}
		if in.freeBytes < 0 {
			return false, "", fmt.Errorf("copy_before_boot: always, but the free space where the copies go is unknown")
		}
		if in.freeBytes < need {
			return false, "", fmt.Errorf("copy_before_boot: always needs %d GiB free where the overlays go (the disks plus a 5 GiB reserve), but there are %d GiB", need>>30, in.freeBytes>>30)
		}
		if in.overCap() {
			return false, "", fmt.Errorf("copy_before_boot: always would bring the run's copies to %d GiB, over storage.max_copy_gib (%d GiB)", (in.copied+in.vmBytes)>>30, in.capBytes>>30)
		}
		if in.sharedDisk {
			if in.standalone {
				return true, "The copies go onto the disk that also holds the node's configuration database; their writes can slow the node's own services.", nil
			}
			return true, "The copies go onto the disk that also holds the cluster's configuration database; their writes can delay corosync.", nil
		}
		if in.sharedUnknown != "" {
			if in.standalone {
				return true, "Whether the copies' disk also holds the node's configuration database could not be determined (" + in.sharedUnknown + "); if it does, their writes can slow the node's own services.", nil
			}
			return true, "Whether the copies' disk also holds the cluster's configuration database could not be determined (" + in.sharedUnknown + "); if it does, their writes can delay corosync.", nil
		}
		return true, "", nil
	}
	ownOverflow := in.tierScanned+in.vmBytes > in.budget
	if !in.budgetKnown || in.vmBytes < 0 || (!ownOverflow && !in.tierOverflows()) {
		return false, "", nil
	}
	why := ""
	switch {
	case in.sharedDisk && in.standalone:
		why = "overlay storage is on the disk of the node's configuration database, whose writes can slow the node's own services"
	case in.sharedDisk:
		why = "overlay storage shares the cluster database's disk, whose writes can delay corosync"
	case in.sharedUnknown != "" && in.standalone:
		why = "whether overlay storage is on the disk of the node's configuration database could not be determined (" + in.sharedUnknown + "), and copying onto it could slow the node's own services"
	case in.sharedUnknown != "":
		why = "whether overlay storage shares the cluster database's disk could not be determined (" + in.sharedUnknown + "), and copying onto it could delay corosync"
	case in.freeBytes < 0:
		why = "the free space where the copies go is unknown"
	case in.freeBytes < need:
		why = fmt.Sprintf("overlay storage has %d GiB free, and the copies need %d GiB", in.freeBytes>>30, need>>30)
	case in.overCap():
		why = fmt.Sprintf("the run's copies would reach %d GiB, over storage.max_copy_gib (%d GiB)", (in.copied+in.vmBytes)>>30, in.capBytes>>30)
	default:
		return true, "", nil
	}
	if !ownOverflow {
		// The VM's own disks fit; it is the tier that does not.
		return false, fmt.Sprintf("The tier's disks (%d GiB together) are more than this node can keep cached (%d GiB), and this VM's disks (%d GiB) are not copied to local storage first: %s. While this VM runs from the backup, the other VMs' disk reads can push its cached blocks out, so its guest agent or services can time out long after its boot. Put overlay storage on a disk of its own with room for the disks, or split the tier.",
			in.tierBytes>>30, in.budget>>30, in.vmBytes>>30, why), nil
	}
	return false, fmt.Sprintf("The VM's disks (%d GiB) won't all stay cached until it boots (%d GiB fits), and they are not copied to local storage first: %s. Parts of the boot will read from PBS, %s. Put overlay storage on a disk of its own with room for the disks, or split the tier.",
		in.vmBytes>>30, max(0, in.budget-in.tierScanned)>>30, why, slowBootConsequence(in.windows)), nil
}

// tierOverflows reports whether the tier's disks together are more than the
// node can keep cached.
func (in copyInputs) tierOverflows() bool {
	return in.budgetKnown && in.tierBytes > in.budget
}

// slowBootConsequence says what a boot that reads from PBS risks. Windows gives
// up on a service that misses its 30-second start deadline and does not retry it
// (troubleshooting Issue 19); a Linux service manager has start timeouts of its
// own (Issue 18). The plan names Windows only for a Windows guest.
func slowBootConsequence(windows bool) string {
	if windows {
		return "and Windows services can miss their start deadline"
	}
	return "so the boot is slower and a service can miss the service manager's start deadline"
}

// plannedDir is dir, or, when the run has not made it yet, its parent or
// grandparent: a sandbox VM's image directory <storage>/images/<vmid> is
// made by the run, on the storage whose free space and disks decide the
// copy. It never climbs higher, so an unmounted storage stays unknown
// instead of being measured on the root file system. With none existing
// it returns dir, whose measurement fails as it should.
func plannedDir(dir string, exists func(string) bool) string {
	if exists == nil {
		exists = dirExists
	}
	for d, up := dir, 0; up <= 2; d, up = filepath.Dir(d), up+1 {
		if exists(d) {
			return d
		}
	}
	return dir
}

func dirExists(dir string) bool {
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}

// overCap reports whether this VM's copies would take the run's over the
// cap.
func (in copyInputs) overCap() bool {
	return in.capBytes > 0 && in.copied+in.vmBytes > in.capBytes
}

// chooseCopyBeforeBoot gathers decideCopy's inputs for a VM whose disks are
// mapped at devices and whose overlays are in copyDir, and reports the
// decision.
func (o *Orchestrator) chooseCopyBeforeBoot(ctx context.Context, vmCfg config.VM, devices []string, copyDir string) (bool, error) {
	in := copyInputs{
		mode:        vmCfg.CopyBeforeBoot,
		tierScanned: o.tierCache.scanned,
		tierBytes:   o.tierCache.plannedBytes,
		budgetKnown: o.tierCache.budgetKnown,
		budget:      o.tierCache.budgetBytes,
		freeBytes:   -1,
		copied:      o.copiedBytes,
		capBytes:    o.copyCapBytes(),
		windows:     windowsOSType(vmCfg.OSType),
	}
	if in.mode == config.CopyBeforeBootNever || (in.mode != config.CopyBeforeBootAlways && o.opts.SkipIntegrity) {
		return false, nil // test mode has no scan, so auto has nothing to copy with
	}
	for _, device := range devices {
		n, err := o.deviceBytesFn(device)
		if err != nil {
			in.vmBytes = -1
			break
		}
		in.vmBytes += n
	}
	if free, err := o.freeBytesFn(copyDir); err == nil {
		in.freeBytes = free
	}
	if shared, err := o.sharedDisksFn(ctx, copyDir, sysutil.ClusterStateDir); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// Cancelled while the disks were looked up: the run ends, and
			// teardown must not wait on a decision nothing will use.
			return false, ctxErr
		}
		in.sharedUnknown = err.Error()
	} else if len(shared) > 0 {
		in.sharedDisk = true
	}
	in.standalone = (in.sharedDisk || in.sharedUnknown != "") && o.standaloneNode(ctx)
	copyDisks, warning, err := decideCopy(in)
	if err != nil {
		return false, err
	}
	if warning != "" {
		progress.Warn("Storage", "VM %d: %s", vmCfg.VMID, warning)
	}
	if copyDisks {
		o.copiedBytes += in.vmBytes
		reason := "copy_before_boot: always"
		if in.mode != config.CopyBeforeBootAlways {
			reason = fmt.Sprintf("its %d GiB of disks would not all stay cached until it boots", in.vmBytes>>30)
		}
		progress.Info("Storage", "VM %d: copying its disks to local storage while verifying them, and booting from the copies as a restore does (%s).", vmCfg.VMID, strings.TrimSpace(reason))
	}
	return copyDisks, nil
}

// copyCapBytes is storage.max_copy_gib in bytes; 0 is no cap.
func (o *Orchestrator) copyCapBytes() int64 {
	if o.plan == nil {
		return 0
	}
	return int64(o.plan.Storage.MaxCopyGiB) << 30
}

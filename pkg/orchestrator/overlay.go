// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// minOverlayStorageFreeBytes matches the scratch-directory reserve: COW
// overlays only grow with guest writes, so a few GiB covers a sandbox run.
const minOverlayStorageFreeBytes = 5 << 30

func overlayFileName(vmid int, slot string, timestamp int64, diskIndex int) string {
	return fmt.Sprintf("certistack-delta-vm%d-%s-%d-%d.qcow2", vmid, slot, timestamp, diskIndex)
}

func overlayVolumeID(storage string, vmid int, name string) string {
	return fmt.Sprintf("%s:%d/%s", storage, vmid, name)
}

// pvesmVolumePath asks PVE where a volume lives on this node. PVE owns the
// storage layout; the worker never parses storage.cfg itself.
func pvesmVolumePath(ctx context.Context, volume string) (string, error) {
	result, err := sysutil.Run(ctx, 30*time.Second, "pvesm", "path", volume)
	if err != nil {
		return "", fmt.Errorf("pvesm path %s: %w", volume, err)
	}
	return strings.TrimSpace(string(result.Stdout)), nil
}

// warnOverlaySharesClusterDisk warns, once per run, when the overlay
// directory is on a physical disk that also holds the cluster file system's
// database. A sandbox's first writes to its overlays can saturate that disk:
// corosync then misses its token deadline and the node can lose its cluster
// membership. It returns ctx's error when the run was cancelled while the
// disks were being looked up: the run is over, and the check must not hold up
// its teardown.
func (o *Orchestrator) warnOverlaySharesClusterDisk(ctx context.Context, dir string) error {
	if o.clusterDiskChecked {
		return nil
	}
	o.clusterDiskChecked = true
	warning, err := o.overlayClusterDiskWarning(ctx, dir)
	if err != nil {
		return err
	}
	if warning != "" {
		progress.Warn("Storage", "%s", warning)
	}
	return nil
}

// corosyncConfig exists on a node that is in a cluster, and on no other.
const corosyncConfig = "/etc/pve/corosync.conf"

// clusterNodes says how many nodes the cluster this node is in has: 0 for a
// standalone node, which has no cluster, and at least 1 for a node that is in
// one. ok is false when that could not be told (PVE did not answer the list of
// nodes and the node has no cluster configuration), which callers treat as a
// cluster, the wording that is right where it matters.
func (o *Orchestrator) clusterNodes(ctx context.Context) (nodes int, ok bool) {
	if o.clusterNodesFn != nil {
		return o.clusterNodesFn(ctx)
	}
	if o.pveClient == nil {
		return 0, false
	}
	return readClusterNodes(ctx, o.pveClient, corosyncConfig)
}

// readClusterNodes counts the nodes PVE lists, which is 1 on a standalone node
// as well, and reads a node as clustered when it lists more than one or the
// node has a corosync configuration (a cluster of one).
func readClusterNodes(ctx context.Context, client *pve.Client, corosync string) (int, bool) {
	count, err := client.NodeCount(ctx)
	_, statErr := os.Stat(corosync)
	switch {
	case err == nil && count > 1:
		return count, true
	case statErr == nil:
		return max(count, 1), true
	case err != nil:
		return 0, false
	}
	return 0, true
}

// standaloneNode reports whether the node is known to be in no cluster.
func (o *Orchestrator) standaloneNode(ctx context.Context) bool {
	nodes, ok := o.clusterNodes(ctx)
	return ok && nodes == 0
}

// overlayClusterDiskWarning is the warning for overlays in dir, or ""
// when dir's disks are not the cluster database's. A lookup that failed is a
// warning, never an error, unless ctx ended: then it is ctx's error, and not a
// reason to think the topology unknown. On a cluster node the risk is the
// cluster's: corosync, and with it the node's membership. A standalone node has
// no cluster, so the warning says what is true there: the database's disk is
// shared with the node's own services.
func (o *Orchestrator) overlayClusterDiskWarning(ctx context.Context, dir string) (string, error) {
	shared, err := o.sharedDisksFn(ctx, dir, sysutil.ClusterStateDir)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		// Unknown is not safe: say so.
		if o.standaloneNode(ctx) {
			return fmt.Sprintf("Could not determine whether overlay storage %s shares a disk with the node's configuration database (%s): %v. If it does, a sandbox's disk writes can slow the node's own services; put overlay storage on a disk of its own.", o.opts.OverlayStorage, sysutil.ClusterStateDir, err), nil
		}
		return fmt.Sprintf("Could not determine whether overlay storage %s shares a disk with the cluster's configuration database (%s): %v. If it does, a sandbox's disk writes can delay corosync; put overlay storage on a disk the cluster file system does not use.", o.opts.OverlayStorage, sysutil.ClusterStateDir, err), nil
	}
	if len(shared) == 0 {
		return "", nil
	}
	var warning string
	if o.standaloneNode(ctx) {
		warning = fmt.Sprintf("Overlay storage %s is on the same disk (%s) as the node's configuration database (%s). A sandbox's disk writes can slow everything else on that disk, the node's own services included. Put overlay storage on a disk of its own.", o.opts.OverlayStorage, strings.Join(shared, ", "), sysutil.ClusterStateDir)
	} else {
		warning = fmt.Sprintf("Overlay storage %s is on the same disk (%s) as the cluster's configuration database (%s). A sandbox's disk writes can delay corosync and cost this node its cluster membership. Put overlay storage on a disk the cluster file system does not use.", o.opts.OverlayStorage, strings.Join(shared, ", "), sysutil.ClusterStateDir)
	}
	if o.plan != nil && o.plan.AdmissionControl.MaxConcurrentBoots == 0 && planVMCount(o.plan) > 1 {
		warning += " Until then, admission_control.max_concurrent_boots: 1 boots the sandboxes one at a time."
	}
	return warning, nil
}

func planVMCount(plan *config.Plan) int {
	n := 0
	for _, tier := range plan.Tiers {
		n += len(tier.VMs)
	}
	return n
}

// checkOverlayPath accepts only <storage path>/images/<vmid>/<name>, the dir
// plugin layout, so a surprising storage mapping cannot redirect overlay
// writes or cleanup elsewhere.
//
// Node paths are always Linux paths, so the slash-only path package is used.
func checkOverlayPath(p string, vmid int, name string) error {
	if !path.IsAbs(p) || path.Clean(p) != p {
		return fmt.Errorf("overlay path %q is not a clean absolute path", p)
	}
	dir := path.Dir(p)
	if path.Base(p) != name || path.Base(dir) != strconv.Itoa(vmid) || path.Base(path.Dir(dir)) != "images" {
		return fmt.Errorf("overlay path %q is not <storage>/images/%d/%s", p, vmid, name)
	}
	return nil
}

// prepareOverlayDir makes sure the VM's image directory exists and holds
// nothing but this VM's CertiStack overlays. Sharing it with other volumes
// would let PVE's destroy of the sandbox VM touch data CertiStack does not own.
// It reports whether it created the directory.
func prepareOverlayDir(dir string, vmid int) (bool, error) {
	entries, err := os.ReadDir(dir)
	switch {
	case err == nil:
		prefix := fmt.Sprintf("certistack-delta-vm%d-", vmid)
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), prefix) {
				return false, fmt.Errorf("overlay directory %s already holds %q; refusing to share a VM image directory with volumes CertiStack does not own", dir, entry.Name())
			}
		}
		return false, nil
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return false, fmt.Errorf("create overlay directory %s: %w", dir, err)
		}
		return true, nil
	default:
		return false, fmt.Errorf("inspect overlay directory %s: %w", dir, err)
	}
}

// removeEmptyOverlayDir removes a directory prepareOverlayDir created once
// its overlays are gone; a missing directory is the desired end state.
func removeEmptyOverlayDir(dir string) error {
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove overlay directory %s: %w", dir, err)
	}
	return nil
}

// overlayStorageStatusTimeout bounds PVE's status read of the overlay
// storage, which answers in well under a second when PVE is healthy.
const overlayStorageStatusTimeout = 45 * time.Second

// checkOverlayStorage validates the overlay storage through PVE: file-based,
// active, allowing disk images, with room. PVE computes a storage's status
// together with every other storage on the node, so one slow storage, such as
// a PBS in its backup window, can time the read out (2 min 19 s,
// then HTTP 596). The run is on the node, so it then checks the storage
// there: the directory pvesm resolves for it must have the room. It returns
// a warning that names the cause, so the operator sees the unhealthy
// storage.
func (o *Orchestrator) checkOverlayStorage(ctx context.Context) (warning string, err error) {
	storage := o.opts.OverlayStorage
	validate := o.validateOverlayStorageFn
	if validate == nil {
		validate = func(ctx context.Context) error {
			_, err := o.pveClient.ValidateOverlayStorage(ctx, o.opts.NodeName, storage, minOverlayStorageFreeBytes)
			return err
		}
	}
	statusCtx, cancel := context.WithTimeout(ctx, overlayStorageStatusTimeout)
	err = validate(statusCtx)
	cancel()
	if err == nil || ctx.Err() != nil || (!pve.IsTransient(err) && !errors.Is(err, context.DeadlineExceeded)) {
		return "", err
	}
	dir, dirErr := o.localOverlayStorageDir(ctx, storage)
	if dirErr != nil {
		return "", errors.Join(err, fmt.Errorf("check overlay storage %q on the node instead: %w", storage, dirErr))
	}
	// The directory is only the storage if PVE's configuration and the mount
	// table say so; an unconfirmed one is refused, not measured.
	confirmed, confirmErr := o.confirmLocalOverlayStorage(storage, dir)
	if confirmErr != nil {
		return "", errors.Join(err, fmt.Errorf("check overlay storage %q on the node instead: %w", storage, confirmErr))
	}
	free, freeErr := o.freeBytesFn(dir)
	if freeErr != nil {
		return "", errors.Join(err, fmt.Errorf("check overlay storage %q on the node instead: %w", storage, freeErr))
	}
	if free < minOverlayStorageFreeBytes {
		return "", fmt.Errorf("overlay storage %q has %d MiB free on node %s (checked on the node, since PVE's storage status did not answer); at least %d MiB is required", storage, free>>20, o.opts.NodeName, minOverlayStorageFreeBytes>>20)
	}
	return fmt.Sprintf("PVE's storage status for %q did not answer (%v), so PVE has not confirmed it is active; checked it on the node directly instead: %s, its directory %s has %d GiB free. PVE computes every storage's status on the node together, so another storage, often a PBS storage, is slow or unreachable.", storage, err, confirmed, dir, free>>30), nil
}

// localOverlayStorageDir is the directory of a file-based storage on this
// node, as pvesm resolves it, without asking PVE for any storage's status.
func (o *Orchestrator) localOverlayStorageDir(ctx context.Context, storage string) (string, error) {
	const probe = "certistack-storage-check.qcow2"
	p, err := o.overlayVolumePathFn(ctx, overlayVolumeID(storage, 1, probe))
	if err != nil {
		return "", err
	}
	images := path.Dir(path.Dir(p)) // <storage>/images/1/<probe>
	if path.Base(p) != probe || path.Base(images) != "images" {
		return "", fmt.Errorf("storage %q does not resolve to a directory with images (%s)", storage, p)
	}
	return path.Dir(images), nil
}

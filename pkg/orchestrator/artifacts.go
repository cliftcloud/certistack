// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// stagingPath is where a disposable file is first written: next to its final
// path (so it can be published without copying) under a name with an
// unguessable token, which no other tool has a reason to create. The file name
// prefix the overlay directory check requires is kept, and the suffix is none
// PVE reads as a volume.
func stagingPath(final string) (string, error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("choose a staging name for %s: %w", final, err)
	}
	return filepath.Join(filepath.Dir(final), filepath.Base(final)+".part-"+hex.EncodeToString(token)), nil
}

// createTracked creates a disposable file of VM vmid (an overlay, a firmware
// copy, a local copy of a disk) at final by way of create, and takes ownership
// of exactly the file create made. Tracking the final path before its
// creator ran would make cleanup unlink whatever was at that path, including a
// file another tool put there after the creator refused it, and then report
// the path cleanly absent.
//
// create writes a staging path, whose token name is this run's alone; that name
// is journaled before create runs, so a partial file a failed or interrupted
// creator leaves is still removed. When create succeeds the file's identity (its
// device, inode and creation time) is journaled for final, and only then is the
// file published at final without replacing anything: a file that is already
// there stays untouched, is not tracked, and is reported. From then on cleanup
// removes final only while it still holds that file.
func (o *Orchestrator) createTracked(vmid int, final string, create func(path string) error) error {
	if _, err := os.Lstat(final); err == nil {
		return fmt.Errorf("%s already exists and is not this run's; it is left alone", final)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect %s before creating it: %w", final, err)
	}
	staging, err := stagingPath(final)
	if err != nil {
		return err
	}
	if err := o.trackDeltaOverlay(vmid, staging); err != nil {
		return err
	}
	if err := create(staging); err != nil {
		return err
	}
	identity, err := sysutil.FileIdentityOf(staging)
	if err != nil {
		return fmt.Errorf("the file just created at %s cannot be identified: %w", staging, err)
	}
	// Journal the identity before the file can appear at final: a crash after
	// the publication then finds the file recorded.
	o.record.SetDeltaFile(final, identity)
	if err := o.flushJournal(); err != nil {
		return err
	}
	if err := sysutil.PublishNoReplace(staging, final); err != nil {
		// Nothing of this run's is at final. The staging file is its own: it
		// goes at once (it can hold a firmware image's secrets), and both
		// paths leave the journal once it is gone.
		o.record.DropDeltaFile(final)
		if removeErr := os.Remove(staging); removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
			o.record.DropDeltaFile(staging)
		}
		if flushErr := o.flushJournal(); flushErr != nil {
			err = errors.Join(err, flushErr)
		}
		if errors.Is(err, sysutil.ErrPublishExists) {
			return fmt.Errorf("%s appeared after this run chose it, and is not the file this run created; it is left alone, and this run's own copy is removed: %w", final, err)
		}
		return fmt.Errorf("publish the file created at %s to %s: %w", staging, final, err)
	}
	o.cleanup.Push(fmt.Sprintf("remove delta overlay %s", final), func() error {
		if err := o.keptForVM(vmid, "overlay "+final); err != nil {
			return err
		}
		return sysutil.RemoveIfSame(final, identity)
	})
	// Both names lead to the file now; the staging name has done its work.
	if err := os.Remove(staging); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil // journaled and registered still: cleanup removes it
	}
	o.record.DropDeltaFile(staging)
	return o.flushJournal()
}

// diskSize is what the backup says of a restored disk's length: the image size
// its snapshot's manifest records, and the size= its configuration carries (0
// for what it does not give). See pbs.DiskSize.
func diskSize(vmCfg config.VM, slot string) pbs.DiskSize {
	return pbs.DiskSize{Manifest: vmCfg.SourceImageBytes[slot], Config: vmCfg.SourceDiskBytes[slot]}
}

// verifyMappedDisk and copyMappedDisk are the integrity scan and the
// copy-before-boot scan of one mapped disk of vmCfg. They are the only calls the
// orchestrator makes of pbs.VerifyMappedImageWithProgress and
// pbs.CopyMappedImageWithProgress, so that what the backup says of the disk's
// length always reaches them: a scan that is not told the length passes a map
// that is short.
func (o *Orchestrator) verifyMappedDisk(ctx context.Context, vmCfg config.VM, slot, device string, progress func(int64)) (*pbs.VerifySummary, string, error) {
	verify := o.verifyImageFn
	if verify == nil {
		verify = pbs.VerifyMappedImageWithProgress
	}
	return verify(ctx, vmCfg.SourcePBS.Snapshot, device, diskSize(vmCfg, slot), progress)
}

func (o *Orchestrator) copyMappedDisk(ctx context.Context, vmCfg config.VM, slot, device, fusePath, copyPath string, progress func(int64)) (*pbs.VerifySummary, string, error) {
	copyImage := o.copyImageFn
	if copyImage == nil {
		copyImage = pbs.CopyMappedImageWithProgress
	}
	return copyImage(ctx, vmCfg.SourcePBS.Snapshot, device, fusePath, copyPath, diskSize(vmCfg, slot), progress)
}

// sourceDiskLength is the length of a restored disk as far as a plan can tell
// before anything is mapped: the image size the snapshot's manifest records,
// else the size= of the backup's configuration.
func sourceDiskLength(vmCfg config.VM, slot string) (int64, bool) {
	if n, ok := vmCfg.SourceImageBytes[slot]; ok {
		return n, true
	}
	n, ok := vmCfg.SourceDiskBytes[slot]
	return n, ok
}

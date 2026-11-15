// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/process"
)

// DetachLoop detaches a loopback device using losetup -d <device>.
func DetachLoop(ctx context.Context, device string) error {
	if !validNumberedDevice(device, "/dev/loop") {
		return fmt.Errorf("invalid loop device %q", device)
	}

	timeout := 10 * time.Second
	_, err := Run(ctx, timeout, "losetup", "-d", device)
	if err != nil {
		return fmt.Errorf("failed to detach loop device %s: %w", device, err)
	}

	return nil
}

// SysBlockDir is the sysfs block directory LoopBacking reads. Tests point it
// at a fake tree.
var SysBlockDir = "/sys/block"

// LoopBacking returns the kernel-reported backing-file identity for a loop
// device. This is the identity that must be persisted for crash recovery: PBS
// snapshot labels describe provenance, but Linux verifies loop ownership using
// this resolved sysfs value.
func LoopBacking(device string) (string, error) {
	return loopBackingIn(SysBlockDir, device)
}

func loopBackingIn(sysBlock, device string) (string, error) {
	if !validNumberedDevice(device, "/dev/loop") {
		return "", fmt.Errorf("invalid loop device %q", device)
	}
	name := filepath.Base(device)
	data, err := os.ReadFile(filepath.Join(sysBlock, name, "loop", "backing_file"))
	if err != nil {
		return "", err
	}
	backing := strings.TrimSpace(string(data))
	if backing == "" {
		return "", fmt.Errorf("loop device %s has no backing-file identity", device)
	}
	return backing, nil
}

// LoopDiskSeq returns the kernel's disk sequence number of a loop device
// (/sys/block/loopN/diskseq, Linux 5.15 and later). A loop device gets a new
// number when it is attached and again when it is finally released, not while
// a detach is deferred because something still holds it, and no number comes
// twice in one boot: within one boot, the same number on the same device is
// the same attachment, whatever its backing file reads now. os.ErrNotExist
// means the device or the attribute is not there.
func LoopDiskSeq(device string) (uint64, error) {
	return loopDiskSeq(SysBlockDir, device)
}

func loopDiskSeq(sysBlock, device string) (uint64, error) {
	if !validNumberedDevice(device, "/dev/loop") {
		return 0, fmt.Errorf("invalid loop device %q", device)
	}
	data, err := os.ReadFile(filepath.Join(sysBlock, filepath.Base(device), "diskseq"))
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(data))
	seq, err := strconv.ParseUint(text, 10, 64)
	if err != nil || seq == 0 {
		return 0, fmt.Errorf("loop device %s has no usable disk sequence number (%q)", device, text)
	}
	return seq, nil
}

// currentBootID is the boot an attachment's disk sequence number is read in;
// tests replace it.
var currentBootID = process.CurrentBootID

// LoopAttachment is what the run records of a loop device it has just mapped:
// the backing file the kernel reports (an error when it cannot be read, as
// LoopBacking) and, when they can be read, the attachment's disk sequence
// number and the boot. The number is read before and after the backing file;
// if they differ, or either cannot be read, no number is recorded, and the loop
// is later judged by its backing path alone.
func LoopAttachment(device string) (journal.TrackedLoop, error) {
	return loopAttachment(SysBlockDir, device, currentBootID)
}

func loopAttachment(sysBlock, device string, bootID func() (string, error)) (journal.TrackedLoop, error) {
	before, seqErr := loopDiskSeq(sysBlock, device)
	backing, err := loopBackingIn(sysBlock, device)
	if err != nil {
		return journal.TrackedLoop{}, err
	}
	loop := journal.TrackedLoop{Device: device, Backing: backing}
	after, afterErr := loopDiskSeq(sysBlock, device)
	boot, bootErr := bootID()
	if seqErr == nil && afterErr == nil && bootErr == nil && before == after && strings.TrimSpace(boot) != "" {
		loop.DiskSeq, loop.BootID = before, strings.TrimSpace(boot)
	}
	return loop, nil
}

// ValidMappedDevice reports whether device is an exact numbered loop or NBD path.
func ValidMappedDevice(device string) bool {
	return validNumberedDevice(device, "/dev/loop") || validNumberedDevice(device, "/dev/nbd")
}

func validNumberedDevice(device, prefix string) bool {
	if !strings.HasPrefix(device, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(device, prefix)
	if suffix == "" {
		return false
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// mappingMarkers are the phrases proxmox-backup-client uses to name the
// mapped device: "mapped to" up to 4.1.x, "mapped on" from 4.2.
var mappingMarkers = []string{"mapped to", "mapped on"}

// ExtractLoopDevice finds the exact numbered loop or NBD device named by the
// PBS mapping result. Other command output may mention unrelated devices.
func ExtractLoopDevice(output string) (string, error) {
	foundMapping := false
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		markerIndex, markerLen := -1, 0
		for _, marker := range mappingMarkers {
			if i := strings.Index(lower, marker); i >= 0 {
				markerIndex, markerLen = i, len(marker)
				break
			}
		}
		if markerIndex < 0 {
			continue
		}
		foundMapping = true
		mappedFields := strings.Fields(line[markerIndex+markerLen:])
		if len(mappedFields) == 0 {
			continue
		}
		mappedDevice := strings.Trim(mappedFields[0], "'\",:;")
		if ValidMappedDevice(mappedDevice) {
			return mappedDevice, nil
		}
	}
	// Mapping-client output can include connection or repository context. The
	// caller only needs to know that no safe device path was found; retaining
	// the raw output would leak it through wrapped errors and evidence logs.
	if foundMapping {
		return "", fmt.Errorf("PBS mapping result did not contain a valid mapped loop or NBD device")
	}
	return "", fmt.Errorf("no valid mapped loop or NBD device found")
}

// BlockDeviceBytes is a loop or NBD device's size, from sysfs.
func BlockDeviceBytes(device string) (int64, error) {
	return blockDeviceBytes("/sys/block", device)
}

func blockDeviceBytes(sysBlock, device string) (int64, error) {
	if !ValidMappedDevice(device) {
		return 0, fmt.Errorf("invalid mapped device %q", device)
	}
	data, err := os.ReadFile(filepath.Join(sysBlock, filepath.Base(device), "size"))
	if err != nil {
		return 0, err
	}
	sectors, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || sectors < 0 {
		return 0, fmt.Errorf("device %s size %q: %v", device, strings.TrimSpace(string(data)), err)
	}
	return sectors * 512, nil
}

// LoopState is what a loop device's kernel-reported backing says about the
// file a run recorded for it.
type LoopState int

const (
	// LoopGone: the device is not attached to anything.
	LoopGone LoopState = iota
	// LoopRecorded: the device still backs the recorded file.
	LoopRecorded
	// LoopReused: the device backs another file now. Loop numbers are
	// reused: once the run's map is gone, the number can be another
	// operation's map or an ordinary loop.
	LoopReused
)

// ErrLoopReused is what an operation that would detach or unmap a recorded
// loop device returns, having done nothing, when the device backs another file
// than the one recorded.
var ErrLoopReused = errors.New("the loop device backs another file now, not the PBS map the run recorded; it was left alone")

// CheckLoop says whether device still backs the file recorded for it. Call it
// right before anything is done to the device, and again between two such
// steps: what a loop number is attached to can change at any time. An error
// means it is not known (unreadable sysfs, no recorded identity, an invalid
// device), and the device must be left alone.
func CheckLoop(device, recorded string) (LoopState, error) {
	current, err := LoopBacking(device)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return LoopGone, nil
	case err != nil:
		return 0, fmt.Errorf("cannot read what %s is attached to: %w", device, err)
	case strings.TrimSpace(recorded) == "":
		return 0, fmt.Errorf("no backing identity was recorded for %s, so it cannot be told from another operation's loop", device)
	case strings.TrimSuffix(current, " (deleted)") == strings.TrimSuffix(recorded, " (deleted)"):
		return LoopRecorded, nil
	}
	return LoopReused, nil
}

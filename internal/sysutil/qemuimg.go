// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CreateDeltaOverlay creates an ephemeral Copy-on-Write (COW) qcow2 delta overlay
// backed by an immutable loopback device or raw image.
// All writes during VM execution go to this delta file, leaving the backing device untouched.
func CreateDeltaOverlay(ctx context.Context, backingDevice, deltaPath string) error {
	if backingDevice == "" {
		return fmt.Errorf("backing device must not be empty")
	}
	if deltaPath == "" {
		return fmt.Errorf("delta path must not be empty")
	}

	// Ensure parent directory exists
	dir := filepath.Dir(deltaPath)
	if err := EnsurePrivateDirectory(dir); err != nil {
		return fmt.Errorf("failed to prepare private directory for delta overlay %s: %w", dir, err)
	}

	timeout := 30 * time.Second
	_, err := Run(ctx, timeout, "qemu-img", deltaOverlayArgs(backingDevice, deltaPath)...)
	if err != nil {
		return fmt.Errorf("qemu-img failed to create delta overlay at %s: %w", deltaPath, err)
	}
	if err := os.Chmod(deltaPath, 0600); err != nil {
		return fmt.Errorf("failed to secure delta overlay %s: %w", deltaPath, err)
	}

	return nil
}

// deltaOverlayArgs is qemu-img create -f qcow2 -o lazy_refcounts=on -b
// <backingDevice> -F raw <deltaPath>. Lazy refcounts spare the overlay a
// refcount update on each newly allocated cluster; the overlay is
// disposable, so the repair a crash would need never matters.
func deltaOverlayArgs(backingDevice, deltaPath string) []string {
	return []string{
		"create",
		"-f", "qcow2",
		"-o", "lazy_refcounts=on",
		"-b", backingDevice,
		"-F", "raw",
		deltaPath,
	}
}

// RebaseDeltaOverlay points a delta overlay at backing without copying
// anything (qemu-img rebase -u). backing must hold exactly what the old
// backing held: copy-before-boot swaps a mapped PBS image for its verified
// local copy, keeping the writes already in the overlay.
func RebaseDeltaOverlay(ctx context.Context, deltaPath, backing string) error {
	if deltaPath == "" || backing == "" {
		return fmt.Errorf("delta overlay and backing must not be empty")
	}
	if _, err := Run(ctx, 30*time.Second, "qemu-img", rebaseOverlayArgs(deltaPath, backing)...); err != nil {
		return fmt.Errorf("qemu-img failed to rebase delta overlay %s: %w", deltaPath, err)
	}
	return nil
}

func rebaseOverlayArgs(deltaPath, backing string) []string {
	return []string{"rebase", "-u", "-f", "qcow2", "-F", "raw", "-b", backing, deltaPath}
}

//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
)

// ClusterStateDir holds the Proxmox VE cluster file system's database.
const ClusterStateDir = "/var/lib/pve-cluster"

// SharedDisks reports no shared disks off Linux, where no PVE node runs. It
// answers a context that has ended as the Linux build does.
func SharedDisks(ctx context.Context, pathA, pathB string) ([]string, error) {
	return nil, ctx.Err()
}

// ErrDisksUnknown means the disks under a file system could not be
// determined.
var ErrDisksUnknown = errors.New("cannot determine which disks hold the file system")

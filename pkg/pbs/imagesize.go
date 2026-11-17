// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"encoding/json"
	"fmt"

	"github.com/cliftcloud/certistack/internal/diskslot"
)

// DiskSize is what is known of a backed-up disk's length before its map is
// read, from two sources that do not always agree.
//
// Manifest is the size the snapshot's manifest records for the disk's archive
// (`snapshot files` lists it): for a fixed-index image archive, the length of the
// image that was backed up. It is authoritative for what the map must be. 0
// means the manifest gave none.
//
// Config is the size= of the drive in the backup's qemu-server.conf. That is
// the size PVE recorded when the disk was last created or resized, and it is
// what the resize ASKED for: storage rounds a volume up (LVM to whole extents,
// ZFS and RBD to 1 MiB), and a disk resized or imported outside PVE leaves it
// stale. vzdump backs up what QEMU sees, the volume's real size, so a config
// size that differs from the manifest's is not a defect of the backup. 0 means
// the configuration gave none.
type DiskSize struct {
	Manifest int64
	Config   int64
}

// ParseSnapshotImageBytes reads, from `proxmox-backup-client snapshot files
// --output-format json`, the size the manifest records for each disk image
// archive, by slot. A slot whose archive lists no usable size, or lists two
// different ones, is left out: nothing is then known of it from the manifest.
// The listing is the same for an encrypted or signed snapshot.
func ParseSnapshotImageBytes(data []byte) map[string]int64 {
	var files []struct {
		Filename string          `json:"filename"`
		Size     json.RawMessage `json:"size"`
	}
	if json.Unmarshal(data, &files) != nil {
		return nil
	}
	sizes := make(map[string]int64)
	conflicted := make(map[string]bool)
	for _, file := range files {
		slot, ok := diskslot.ArchiveSlot(file.Filename)
		if !ok {
			continue
		}
		// One entry whose size is not a size leaves that slot unknown, not the rest.
		var size json.Number
		if json.Unmarshal(file.Size, &size) != nil {
			continue
		}
		n, err := size.Int64()
		if err != nil || n <= 0 || n > maxSourceDiskBytes {
			continue
		}
		if previous, seen := sizes[slot]; seen && previous != n {
			conflicted[slot] = true
		}
		sizes[slot] = n
	}
	for slot := range conflicted {
		delete(sizes, slot)
	}
	if len(sizes) == 0 {
		return nil
	}
	return sizes
}

// checkMappedSize compares the size of a mapped image with what is known of the
// disk's length, and returns the note the evidence carries. The image is what
// the manifest records or the run fails; a configuration size that differs from
// the manifest's is reported in the note with both numbers, and is not a failure.
// Without a manifest size the map must still be at least as long as the
// configuration says, and the note says what was and was not checked.
func checkMappedSize(size int64, want DiskSize) (note string, err error) {
	switch {
	case want.Manifest > 0:
		if size != want.Manifest {
			return "", fmt.Errorf("the mapped PBS image is %d bytes, but the snapshot's manifest records %d bytes for this disk: a %s map is not the image that was backed up", size, want.Manifest, shortOrLong(size, want.Manifest))
		}
		if want.Config > 0 && want.Config != want.Manifest {
			return fmt.Sprintf("the size the snapshot's manifest records; the backup's configuration says size=%d bytes, which PVE records as the resize asked for, and the image PBS backed up is %d bytes", want.Config, want.Manifest), nil
		}
		return "the size the snapshot's manifest records", nil
	case want.Config > 0:
		if size < want.Config {
			return "", fmt.Errorf("the mapped PBS image is %d bytes, shorter than the %d bytes the backup's configuration declares for this disk, and the snapshot's manifest gave no size to settle it: a short map is not the disk that was backed up", size, want.Config)
		}
		if size > want.Config {
			return fmt.Sprintf("the snapshot's manifest gave no size, so only the read of the whole map was checked; the backup's configuration says size=%d bytes and the map is %d, which storage rounding or a resize outside PVE explains", want.Config, size), nil
		}
		return "the size the backup's configuration declares (the snapshot's manifest gave none)", nil
	}
	return "neither the snapshot's manifest nor the backup's configuration gives a size, so only the read of the whole map was checked", nil
}

func shortOrLong(size, want int64) string {
	if size < want {
		return "short"
	}
	return "long"
}

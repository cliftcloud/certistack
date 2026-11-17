// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cliftcloud/certistack/internal/sysutil"
)

// copyHoleBlock is the granularity at which an all-zero range of the image
// is left as a hole in the copy instead of being written.
const copyHoleBlock = 64 << 10

// copyFlushInterval is how much of the copy is written before it is flushed
// to disk and its pages released: enough for large writes, small enough
// that the copy never holds much memory.
const copyFlushInterval = int64(64 << 20)

// CopyMappedImageWithProgress reads a mapped image once, as
// VerifyMappedImageWithProgress does, and also writes it to copyPath as a
// sparse raw file. The sandbox then boots from local storage, as a restore
// does (copy-before-boot). The digest is a verification pass's.
//
// fusePath is the map's FUSE file (the loop device's sysfs backing file), or
// "". The read leaves the image in that file's page cache, where a sandbox
// booting from the copy never reads it. It is released behind the read, and
// the copy's own pages after each flush, so copying a large disk doesn't
// crowd out another VM's cached boot. copyPath must not exist.
//
// want is what VerifyMappedImage's is (see DiskSize). The mapped image, the
// bytes read and the finished local copy must all be the size the manifest
// records; nothing is created when the mapped image is not.
func CopyMappedImageWithProgress(ctx context.Context, snapshot, loopDevice, fusePath, copyPath string, want DiskSize, progress func(bytesVerified int64)) (*VerifySummary, string, error) {
	if !validSnapshotPath(snapshot) || !sysutil.ValidMappedDevice(loopDevice) {
		return nil, "", fmt.Errorf("invalid PBS snapshot path or mapped device")
	}
	src, err := os.Open(loopDevice)
	if err != nil {
		return nil, "", fmt.Errorf("open mapped PBS image %s: %w", loopDevice, err)
	}
	defer src.Close()
	digest, total, note, err := copyImage(ctx, src, fusePath, copyPath, want, progress)
	if err != nil {
		return nil, "", err
	}
	summary := &VerifySummary{
		Snapshot:   snapshot,
		VerifiedAt: time.Now().UTC(),
		Passed:     true,
		Detail:     fmt.Sprintf("full mapped image read (%d bytes; %s) and copied to local storage; SHA-256 %s", total, note, digest),
		BytesRead:  total,
	}
	return summary, digest, nil
}

// copyImage is CopyMappedImageWithProgress on an open source.
func copyImage(ctx context.Context, src *os.File, fusePath, copyPath string, want DiskSize, progress func(int64)) (string, int64, string, error) {
	size, err := mappedImageSize(src)
	if err != nil {
		return "", 0, "", err
	}
	note, err := checkMappedSize(size, want)
	if err != nil {
		return "", 0, "", err
	}
	dst, err := os.OpenFile(copyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, "", fmt.Errorf("create local copy %s: %w", copyPath, err)
	}
	defer dst.Close()
	if err := dst.Truncate(size); err != nil { // sparse: holes read as zeros
		return "", 0, "", fmt.Errorf("size local copy: %w", err)
	}
	// Opening the FUSE file only to release its pages: this sandbox never
	// reads them. A failure just leaves them to normal reclaim.
	var fuse *os.File
	if fusePath != "" {
		if fuse, err = os.Open(fusePath); err == nil {
			defer fuse.Close()
		}
	}
	var flushed int64
	digest, total, err := readMappedImage(ctx, src, progress, func(p []byte, off int64) error {
		for start := 0; start < len(p); start += copyHoleBlock {
			end := min(start+copyHoleBlock, len(p))
			if allZero(p[start:end]) {
				continue
			}
			if _, err := dst.WriteAt(p[start:end], off+int64(start)); err != nil {
				return fmt.Errorf("write local copy: %w", err)
			}
		}
		if fuse != nil {
			dropDevicePages(fuse, off, int64(len(p)))
		}
		if end := off + int64(len(p)); end-flushed >= copyFlushInterval {
			if err := flushCopyRange(dst, flushed, end-flushed); err != nil {
				return fmt.Errorf("flush local copy: %w", err)
			}
			flushed = end
		}
		return nil
	})
	if err != nil {
		return "", 0, "", err
	}
	if err := dst.Sync(); err != nil {
		return "", 0, "", fmt.Errorf("sync local copy: %w", err)
	}
	dropDevicePages(dst, flushed, total-flushed)
	if total != size {
		return "", 0, "", fmt.Errorf("read %d of the %d bytes of the mapped PBS image before a clean end of file: the image is not complete", total, size)
	}
	if after, err := mappedImageSize(src); err != nil {
		return "", 0, "", err
	} else if after != size {
		return "", 0, "", fmt.Errorf("the mapped PBS image changed size during the copy: %d bytes before, %d after", size, after)
	}
	if info, err := dst.Stat(); err != nil {
		return "", 0, "", fmt.Errorf("size local copy: %w", err)
	} else if info.Size() != total {
		return "", 0, "", fmt.Errorf("the local copy is %d bytes, not the %d bytes read", info.Size(), total)
	}
	return digest, total, note, nil
}

func allZero(p []byte) bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}

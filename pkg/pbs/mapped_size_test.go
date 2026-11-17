// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	mib4 = int64(4 << 20)
	mib1 = int64(1 << 20)
)

// mappedFile is an image of size bytes, opened.
func mappedFile(t *testing.T, size int64) (*os.File, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.raw")
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, path
}

// A mapped image that ended cleanly before the disk's length was
// reported as a full, verified read, and copy-before-boot kept the short image
// and rebased the sandbox onto it. The length a map must have is the one the
// snapshot's manifest records for the image, which is what was backed up. The
// drive's size= in the backup's configuration is what PVE recorded a resize as
// asking for: storage rounds a volume up (LVM to 4 MiB extents) and a disk
// resized outside PVE leaves it stale, so a difference from the manifest is
// noted, not refused.
func TestVerifyChecksTheMapAgainstTheManifestsImageSize(t *testing.T) {
	for name, tc := range map[string]struct {
		imageSize int64
		want      DiskSize
		wantErr   string // "" wants a pass
		wantNote  []string
	}{
		// A 1 MiB map of a 4 MiB image.
		"short of the manifest":                          {imageSize: mib1, want: DiskSize{Manifest: mib4, Config: mib4}, wantErr: "the mapped PBS image is 1048576 bytes, but the snapshot's manifest records 4194304 bytes for this disk: a short map"},
		"short of the manifest, the configuration stale": {imageSize: mib1, want: DiskSize{Manifest: mib4, Config: mib1}, wantErr: "records 4194304 bytes for this disk: a short map"},
		"long":           {imageSize: mib4, want: DiskSize{Manifest: mib1}, wantErr: "the mapped PBS image is 4194304 bytes, but the snapshot's manifest records 1048576 bytes for this disk: a long map"},
		"one byte short": {imageSize: mib4 - 1, want: DiskSize{Manifest: mib4}, wantErr: "4194303 bytes, but the snapshot's manifest records 4194304"},
		"exact":          {imageSize: mib4, want: DiskSize{Manifest: mib4, Config: mib4}, wantNote: []string{"the size the snapshot's manifest records"}},
		// A 32 MiB LVM disk grown by `qm resize +1M` is
		// size=33M in the configuration and 36 MiB (9 extents) on disk.
		"the configuration says what the resize asked for": {imageSize: 36 << 20, want: DiskSize{Manifest: 36 << 20, Config: 33 << 20}, wantNote: []string{"size=34603008 bytes", "the image PBS backed up is 37748736 bytes"}},
		"a stale configuration larger than the image":      {imageSize: 30 << 20, want: DiskSize{Manifest: 30 << 20, Config: 32 << 20}, wantNote: []string{"size=33554432 bytes", "is 31457280 bytes"}},
		// No manifest size: the map must still reach the configuration's.
		"no manifest, short of the configuration":    {imageSize: mib1, want: DiskSize{Config: mib4}, wantErr: "shorter than the 4194304 bytes the backup's configuration declares for this disk, and the snapshot's manifest gave no size"},
		"no manifest, longer than the configuration": {imageSize: 36 << 20, want: DiskSize{Config: 33 << 20}, wantNote: []string{"the snapshot's manifest gave no size", "size=34603008 bytes and the map is 37748736"}},
		"no manifest, as the configuration":          {imageSize: mib4, want: DiskSize{Config: mib4}, wantNote: []string{"the size the backup's configuration declares"}},
		"nothing known":                              {imageSize: mib1, want: DiskSize{}, wantNote: []string{"neither the snapshot's manifest nor the backup's configuration gives a size"}},
	} {
		t.Run(name, func(t *testing.T) {
			f, path := mappedFile(t, tc.imageSize)
			summary, digest, err := verifyOpenImage(context.Background(), "vm/100/2026-09-27T03:00:00Z", f, tc.want, nil)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || summary != nil || digest != "" {
					t.Fatalf("verify = %v, %v, %v; want an error containing %q and no verified image", summary, digest, err, tc.wantErr)
				}
			} else {
				if err != nil || !summary.Passed || summary.BytesRead != tc.imageSize {
					t.Fatalf("verify = %+v, %v; want a pass over %d bytes", summary, err, tc.imageSize)
				}
				for _, note := range tc.wantNote {
					if !strings.Contains(summary.Detail, note) {
						t.Errorf("evidence detail %q lacks %q", summary.Detail, note)
					}
				}
			}

			// Copy-before-boot holds the same line, and creates nothing for a
			// map that is not the image that was backed up.
			src, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer src.Close()
			copyPath := filepath.Join(t.TempDir(), "copy.raw")
			_, total, note, err := copyImage(context.Background(), src, "", copyPath, tc.want, nil)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("copy = %v, want an error containing %q", err, tc.wantErr)
				}
				if _, statErr := os.Lstat(copyPath); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("a local copy was created for a map that is not the image that was backed up: %v", statErr)
				}
			} else if err != nil || total != tc.imageSize || note == "" {
				t.Fatalf("copy = %d, %q, %v", total, note, err)
			}
		})
	}
}

// A map that shrinks or grows under the scan is not the image that was
// declared, and a clean end reached early is not completion.
func TestVerifyRefusesAMappedImageThatChangesSizeDuringTheScan(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, path string){
		"shrinks": func(t *testing.T, path string) {
			if err := os.Truncate(path, mib4+7); err != nil {
				t.Fatal(err)
			}
		},
		"grows": func(t *testing.T, path string) {
			if err := os.Truncate(path, 3*mib4+7); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, path := mappedFile(t, 3*mib4)
			orig := dropScannedPages
			changed := false
			dropScannedPages = func(file *os.File, off, n int64) {
				orig(file, off, n)
				if !changed { // after the first chunk
					changed = true
					change(t, path)
				}
			}
			defer func() { dropScannedPages = orig }()

			summary, _, err := verifyOpenImage(context.Background(), "vm/100/2026-09-27T03:00:00Z", f, DiskSize{Manifest: 3 * mib4}, nil)
			if err == nil || summary != nil {
				t.Fatalf("verify = %+v, %v; want a failure", summary, err)
			}
			if !strings.Contains(err.Error(), "bytes") || !strings.Contains(err.Error(), "of the") && !strings.Contains(err.Error(), "changed size") {
				t.Fatalf("error %q lacks the numbers", err)
			}

			// The copy is held to it too.
			src, openErr := os.Open(path)
			if openErr != nil {
				t.Fatal(openErr)
			}
			defer src.Close()
			if err := os.Truncate(path, 3*mib4); err != nil {
				t.Fatal(err)
			}
			changed = false
			copyPath := filepath.Join(t.TempDir(), "copy.raw")
			if _, _, _, err := copyImage(context.Background(), src, "", copyPath, DiskSize{Manifest: 3 * mib4}, nil); err == nil {
				t.Fatal("a copy of a map that changed size during it was accepted")
			}
		})
	}
}

// After the read there are two checks, and each masked the other: a
// scan that ended cleanly early also left the image a different size, so either
// check alone made the earlier test pass. Each is held here on its own, for the
// verifying scan and for the copy.
func TestEachSizeCheckAfterTheScanHoldsOnItsOwn(t *testing.T) {
	const snapshot = "vm/100/2026-09-27T03:00:00Z"
	size := 3 * mib4
	// changeAt runs once, when the scan has read the chunk that ends at
	// offset end or later.
	run := func(t *testing.T, copying bool, end int64, to int64) error {
		f, path := mappedFile(t, size)
		// The hook below acts after a chunk is processed and expects the next read to see
		// its effect: one buffer makes the scan serial, as the test was written for.
		oldBuffers := scanBuffers
		scanBuffers = 1
		defer func() { scanBuffers = oldBuffers }()
		orig := dropScannedPages
		changed := false
		dropScannedPages = func(file *os.File, off, n int64) {
			orig(file, off, n)
			if !changed && off+n >= end {
				changed = true
				if err := os.Truncate(path, to); err != nil {
					t.Fatal(err)
				}
			}
		}
		defer func() { dropScannedPages = orig }()
		if copying {
			_, _, _, err := copyImage(context.Background(), f, "", filepath.Join(t.TempDir(), "copy.raw"), DiskSize{Manifest: size}, nil)
			return err
		}
		_, _, err := verifyOpenImage(context.Background(), snapshot, f, DiskSize{Manifest: size}, nil)
		return err
	}
	for _, copying := range []bool{false, true} {
		name := map[bool]string{false: "the verifying scan", true: "the copy"}[copying]
		t.Run(name, func(t *testing.T) {
			// The image ends cleanly after the first chunk and 7 bytes, short of the length it
			// had when the scan began: the bytes read are not the image.
			err := run(t, copying, mib4, mib4+7)
			if err == nil || !strings.Contains(err.Error(), "before a clean end of file") || !strings.Contains(err.Error(), "4194311 of the 12582912 bytes") {
				t.Errorf("a clean end before the length: %v; want the bytes read and the length named", err)
			}
			// Every byte of the length was read, and the image is shorter once the
			// scan has read the last of them: the size it was checked against is gone.
			err = run(t, copying, size, size-7)
			if err == nil || !strings.Contains(err.Error(), "changed size during the") || !strings.Contains(err.Error(), "12582912 bytes before, 12582905 after") {
				t.Errorf("a size that changes after the last byte: %v; want the change named with both sizes", err)
			}
			// The control: nothing changes.
			if err := run(t, copying, size+1, size); err != nil {
				t.Errorf("an image that does not change: %v", err)
			}
		})
	}
}

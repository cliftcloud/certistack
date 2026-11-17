// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	warmHeadBytes      = 16 << 20
	warmTailBytes      = 1 << 20
	warmPartitionBytes = 1 << 20
)

// warmDiskLabels reads the parts of a mapped disk that the guest's udev
// probes first: its head (partition tables, LVM labels, the first file
// system's superblock), its tail (the GPT backup header) and the start of
// each partition the kernel found on the map. Test mode skips the full
// scan, and under load a cold PBS read of these can outlast a data disk's
// 30 s device timeout, so the guest skips its mount (Linux guests too). It returns
// the bytes read; a failure costs only the warm-up. It returns when ctx ends,
// even while a read of the map waits on PBS; that read is left to finish on its
// own (releasing the map fails it).
func warmDiskLabels(ctx context.Context, sysClassBlock, device string) (int64, error) {
	type warmed struct {
		read int64
		err  error
	}
	done := make(chan warmed, 1)
	go func() {
		read, err := readDiskLabels(sysClassBlock, device)
		done <- warmed{read, err}
	}()
	select {
	case w := <-done:
		return w.read, w.err
	case <-ctx.Done():
		return 0, fmt.Errorf("read %s's labels: %w", device, ctx.Err())
	}
}

// readDiskLabels is warmDiskLabels's reading.
func readDiskLabels(sysClassBlock, device string) (int64, error) {
	f, err := os.Open(device)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("size of %s: %w", device, err)
	}
	regions := [][2]int64{{0, warmHeadBytes}, {size - warmTailBytes, warmTailBytes}}
	base := filepath.Base(device)
	starts, _ := filepath.Glob(filepath.Join(sysClassBlock, base, base+"p*", "start"))
	for _, start := range starts {
		data, err := os.ReadFile(start)
		if err != nil {
			continue
		}
		if sector, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil && sector >= 0 {
			regions = append(regions, [2]int64{sector * 512, warmPartitionBytes})
		}
	}
	buf := make([]byte, 1<<20)
	var read int64
	for _, region := range regions {
		offset, end := max(region[0], 0), min(region[0]+region[1], size)
		for offset < end {
			n, err := f.ReadAt(buf[:min(int64(len(buf)), end-offset)], offset)
			read += int64(n)
			offset += int64(n)
			if err != nil {
				if err == io.EOF {
					break
				}
				return read, fmt.Errorf("read %s at %d: %w", device, offset, err)
			}
		}
	}
	return read, nil
}

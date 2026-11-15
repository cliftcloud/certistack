// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// benchImage writes a 256 MiB image of mostly incompressible bytes once.
func benchImage(b *testing.B) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "image.raw")
	buf := make([]byte, 1<<20)
	x := uint64(88172645463325252)
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		for j := 0; j+8 <= len(buf); j += 8 { // xorshift: cheap, not compressible
			x ^= x << 13
			x ^= x >> 7
			x ^= x << 17
			for k := 0; k < 8; k++ {
				buf[j+k] = byte(x >> (8 * k))
			}
		}
		if _, err := f.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	return path
}

// The scan's pure CPU cost: read a cached image through readMappedImage (no PBS, no FUSE).
func BenchmarkReadMappedImageCached(b *testing.B) {
	path := benchImage(b)
	b.SetBytes(256 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f, err := os.Open(path)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := readMappedImage(context.Background(), f, nil, nil); err != nil {
			b.Fatal(err)
		}
		f.Close()
	}
}

// The floor: SHA-256 alone over the same bytes in memory.
func BenchmarkSHA256Only(b *testing.B) {
	data, err := os.ReadFile(benchImage(b))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := sha256.New()
		for off := 0; off < len(data); off += 4 << 20 {
			h.Write(data[off : off+4<<20])
		}
		h.Sum(nil)
	}
}

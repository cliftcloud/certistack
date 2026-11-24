// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowReaderAt stands in for a mapped PBS image: every read costs a round trip.
type slowReaderAt struct {
	latency time.Duration
	mu      sync.Mutex
	offsets []int64
	live    int32
	peak    int32
}

func (s *slowReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n := atomic.AddInt32(&s.live, 1)
	for {
		peak := atomic.LoadInt32(&s.peak)
		if n <= peak || atomic.CompareAndSwapInt32(&s.peak, peak, n) {
			break
		}
	}
	time.Sleep(s.latency)
	s.mu.Lock()
	s.offsets = append(s.offsets, off)
	s.mu.Unlock()
	atomic.AddInt32(&s.live, -1)
	return len(p), nil
}

func (s *slowReaderAt) read() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.offsets...)
}

// The read-ahead overlaps the round trips of the chunks ahead of the scan, and
// never runs further ahead than its window.
func TestReadaheadOverlapsReadsAndStaysWithinItsWindow(t *testing.T) {
	const chunk, workers, window = 1 << 20, 4, 8
	ra := &slowReaderAt{latency: 15 * time.Millisecond}
	p := startReadahead(ra, 64*chunk, chunk, workers, window)
	if p == nil {
		t.Fatal("no read-ahead started")
	}
	defer p.stop()
	time.Sleep(200 * time.Millisecond) // the scan has consumed nothing yet
	if got := len(ra.read()); got > window {
		t.Fatalf("read %d chunks ahead of a scan that consumed none, window is %d", got, window)
	}
	if peak := atomic.LoadInt32(&ra.peak); peak < 2 || peak > workers {
		t.Fatalf("peak concurrent reads = %d, want between 2 and %d", peak, workers)
	}
	for i := 0; i < 30; i++ { // the scan advances
		p.consumed(int64(i+1) * chunk)
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(ra.read()); got <= window || got > window+30 {
		t.Fatalf("after 30 consumed chunks it has read %d, want more than the window and at most window+30", got)
	}
}

// It reads each chunk once, in order of claim, never past the end, and stops reading when stopped.
func TestReadaheadNeverReadsPastTheEndAndStops(t *testing.T) {
	const chunk = 1 << 20
	size := int64(10*chunk + 123) // eleven chunks, the last one short
	ra := &slowReaderAt{latency: time.Millisecond}
	p := startReadahead(ra, size, chunk, 4, 16)
	if p == nil {
		t.Fatal("no read-ahead started")
	}
	time.Sleep(150 * time.Millisecond)
	p.stop()
	offs := ra.read()
	seen := map[int64]bool{}
	for _, o := range offs {
		if o < 0 || o >= size || o%chunk != 0 || seen[o] {
			t.Fatalf("bad or repeated read at %d (offsets %v)", o, offs)
		}
		seen[o] = true
	}
	if len(offs) != 11 {
		t.Fatalf("read %d chunks, want all 11 once", len(offs))
	}
	before := len(ra.read())
	p.consumed(chunk)
	time.Sleep(50 * time.Millisecond)
	if len(ra.read()) != before {
		t.Fatal("a stopped read-ahead went on reading")
	}
	p.stop() // idempotent
}

func TestReadaheadIsOffWhenThereIsNothingToOverlap(t *testing.T) {
	ra := &slowReaderAt{}
	if startReadahead(ra, 1<<20, 1<<20, 8, 64) != nil {
		t.Fatal("an image of one chunk got a read-ahead")
	}
	if startReadahead(ra, 100<<20, 1<<20, 1, 64) != nil {
		t.Fatal("one worker got a read-ahead")
	}
	if startReadahead(nil, 100<<20, 1<<20, 8, 64) != nil {
		t.Fatal("no reader got a read-ahead")
	}
	var nilAhead *imageReadahead
	nilAhead.consumed(1 << 20) // a nil read-ahead is a no-op
	nilAhead.stop()
}

func TestReadaheadWorkersFromTheEnvironment(t *testing.T) {
	for value, want := range map[string]int{"": 8, "0": 0, "1": 1, "16": 16, "99": 32, "-3": 8, "many": 8} {
		t.Setenv("CERTISTACK_SCAN_READAHEAD", value)
		if got := readaheadWorkers(); got != want {
			t.Errorf("CERTISTACK_SCAN_READAHEAD=%q: %d workers, want %d", value, got, want)
		}
	}
}

// The scan with the read-ahead reads, hashes and counts exactly what the scan
// without it does.
func TestScanDigestIsTheSameWithAndWithoutReadahead(t *testing.T) {
	content := make([]byte, 13<<20+4321) // 13 MiB and a short last chunk
	for i := range content {
		content[i] = byte(i*7 + i>>11)
	}
	path := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	for _, workers := range []string{"0", "1", "2", "8", "32"} {
		t.Setenv("CERTISTACK_SCAN_READAHEAD", workers)
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var onChunk bytes.Buffer
		digest, total, err := readMappedImage(context.Background(), f, nil, func(p []byte, off int64) error {
			onChunk.Write(p)
			return nil
		})
		f.Close()
		if err != nil || digest != want || total != int64(len(content)) || !bytes.Equal(onChunk.Bytes(), content) {
			t.Fatalf("readahead workers=%s: digest %s total %d err %v, want %s / %d", workers, digest, total, err, want, len(content))
		}
	}
}

// gatedReaderAt records each read and holds it until the gate opens.
type gatedReaderAt struct {
	gate    chan struct{}
	mu      sync.Mutex
	offsets []int64
}

func (g *gatedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	g.mu.Lock()
	g.offsets = append(g.offsets, off)
	g.mu.Unlock()
	<-g.gate
	return len(p), nil
}

func (g *gatedReaderAt) read() []int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]int64(nil), g.offsets...)
}

// A worker that falls behind the scan does not read a chunk the scan has
// already passed: it would read it from PBS a second time and leave it cached
// after the scan released it.
func TestReadaheadSkipsChunksTheScanHasPassed(t *testing.T) {
	const chunk, workers, window = 1 << 20, 2, 4
	ra := &gatedReaderAt{gate: make(chan struct{})}
	p := startReadahead(ra, 20*chunk, chunk, workers, window)
	if p == nil {
		t.Fatal("no read-ahead started")
	}
	defer p.stop()
	// The scan reads and releases the first eight chunks itself while the
	// workers are held in their first reads (or have not claimed one yet).
	for i := 1; i <= 8; i++ {
		p.consumed(int64(i) * chunk)
	}
	close(ra.gate)
	deadline := time.Now().Add(5 * time.Second)
	for len(ra.read()) < workers+1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	p.stop()
	behind := 0
	for _, off := range ra.read() {
		if off < 8*chunk {
			behind++
		}
	}
	// Only the reads claimed before the scan passed them (one per worker at
	// most) may lie behind it.
	if behind > workers {
		t.Fatalf("read %d chunks the scan had passed (offsets %v), want at most %d", behind, ra.read(), workers)
	}
	if len(ra.read()) <= behind {
		t.Fatalf("read nothing ahead of the scan (offsets %v)", ra.read())
	}
}

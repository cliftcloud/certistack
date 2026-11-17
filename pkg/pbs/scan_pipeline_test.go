// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// pipeImage serves content through a pipe in n pieces, a pause after each: an
// image that arrives at the pace of a PBS read. It cannot be sought or sized.
func pipeImage(t *testing.T, content []byte, pieces int, pause time.Duration) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	go func() {
		defer w.Close()
		step := len(content) / pieces
		for i := 0; i < pieces; i++ {
			end := (i + 1) * step
			if i == pieces-1 {
				end = len(content)
			}
			_, _ = w.Write(content[i*step : end])
			time.Sleep(pause)
		}
	}()
	return r
}

// A callback that fails stops the scan with its error, and nothing runs after
// the scan returns.
func TestScanStopsAtAFailingCallbackAndLeavesNothingRunning(t *testing.T) {
	content := bytes.Repeat([]byte("x"), 1<<20)
	f := pipeImage(t, content, 20, time.Millisecond)
	boom := errors.New("write the copy: disk full")
	var calls, after int32
	var returned atomic.Bool
	_, _, err := readMappedImage(context.Background(), f, nil, func(p []byte, off int64) error {
		if returned.Load() {
			atomic.AddInt32(&after, 1)
		}
		if atomic.AddInt32(&calls, 1) == 3 {
			return boom
		}
		return nil
	})
	returned.Store(true)
	if !errors.Is(err, boom) {
		t.Fatalf("scan error = %v, want the callback's", err)
	}
	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&after) != 0 || atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("callback ran %d times (%d after the scan returned), want 3 and 0", atomic.LoadInt32(&calls), atomic.LoadInt32(&after))
	}
}

// The digest and the byte count are the same for every number of buffers, and
// a scan cancelled in the middle returns the cancellation, not a result.
func TestScanIsTheSameForEveryBufferCount(t *testing.T) {
	content := make([]byte, 9<<20+777)
	for i := range content {
		content[i] = byte(i*31 + i>>13)
	}
	path := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	old := scanBuffers
	t.Cleanup(func() { scanBuffers = old })
	for _, buffers := range []int{0, 1, 2, 3, 6} {
		scanBuffers = buffers
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		digest, total, err := readMappedImage(context.Background(), f, nil, nil)
		f.Close()
		if err != nil || digest != want || total != int64(len(content)) {
			t.Fatalf("%d buffers: %s / %d / %v, want %s / %d", buffers, digest, total, err, want, len(content))
		}
	}
	scanBuffers = 3
	ctx, cancel := context.WithCancel(context.Background())
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _, err = readMappedImage(ctx, f, nil, func(p []byte, off int64) error {
		cancel() // after the first chunk
		return nil
	})
	if err == nil || !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "<nil>") {
		t.Fatalf("a scan cancelled during its first chunk returned %v, want the cancellation", err)
	}
}

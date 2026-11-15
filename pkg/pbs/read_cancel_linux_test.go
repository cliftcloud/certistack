//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// startPipeScan scans the read end of a pipe, which stands in for a mapped
// image whose next read waits on PBS. It returns the write end and the
// scan's result, once the scan has read first and waits for more.
func startPipeScan(t *testing.T, ctx context.Context, first string) (*os.File, <-chan error) {
	t.Helper()
	oldRoot := numaRoot
	numaRoot = t.TempDir() // no affinity changes
	t.Cleanup(func() { numaRoot = oldRoot })
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	var once sync.Once
	firstChunk := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, _, err := readMappedImage(ctx, reader, nil, func([]byte, int64) error {
			once.Do(func() { close(firstChunk) })
			return nil
		})
		done <- err
	}()
	if _, err := writer.Write([]byte(first)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstChunk:
	case <-time.After(2 * time.Second):
		t.Fatal("the scan did not read the first chunk")
	}
	select {
	case err := <-done:
		t.Fatalf("the scan ended before its input did: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	return writer, done
}

// A scan cancelled while its read waited stayed in that read until
// it returned. It now stops within readCancelGrace, and says a read is left.
func TestScanStopsWhenCancelledDuringARead(t *testing.T) {
	oldGrace := readCancelGrace
	readCancelGrace = 100 * time.Millisecond
	t.Cleanup(func() { readCancelGrace = oldGrace })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer, done := startPipeScan(t, ctx, "synthetic first chunk")

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "still waiting") {
			t.Fatalf("cancelled scan = %v, want the cancellation and the read left waiting", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the cancelled scan is still blocked in its read")
	}
	_ = writer.Close() // the read left waiting ends
}

// A read that reached the end after cancellation made the scan
// report a complete image.
func TestScanEndingAfterCancellationFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer, done := startPipeScan(t, ctx, "synthetic first chunk")

	cancel()
	_ = writer.Close() // the waiting read now returns EOF
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("scan ending after cancellation = %v, want the cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the scan did not return once its read ended")
	}
}

// The control: the same scan, uncancelled, reads to the end.
func TestPipeScanWithoutCancellationCompletes(t *testing.T) {
	ctx := context.Background()
	oldRoot := numaRoot
	numaRoot = t.TempDir()
	t.Cleanup(func() { numaRoot = oldRoot })
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	content := []byte("synthetic first chunk, then the rest")
	go func() {
		_, _ = writer.Write(content[:21])
		time.Sleep(20 * time.Millisecond)
		_, _ = writer.Write(content[21:])
		_ = writer.Close()
	}()
	digest, total, err := readMappedImage(ctx, reader, nil, nil)
	sum := sha256.Sum256(content)
	if err != nil || total != int64(len(content)) || digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("scan = %s %d %v, want %x %d", digest, total, err, sum, len(content))
	}
}

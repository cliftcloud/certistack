// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package screendump

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe/qmp"
)

// silentScreendumpServer is a QMP monitor that negotiates, answers everything
// but screendump, and holds the screendump reply: QEMU busy writing a frame, or
// hung. seen is closed when the screendump command arrives; the reply is never
// sent until the test ends.
func silentScreendumpServer(t *testing.T, frame []byte) (socket string, seen <-chan struct{}) {
	t.Helper()
	dir, err := os.MkdirTemp("", "cs-qmp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket = filepath.Join(dir, "qmp.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	seenC := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader, encoder := bufio.NewReader(conn), json.NewEncoder(conn)
		if err := encoder.Encode(map[string]any{"QMP": map[string]any{}}); err != nil {
			return
		}
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var command map[string]any
			if err := json.Unmarshal(line, &command); err != nil {
				return
			}
			if command["execute"] == "screendump" {
				arguments, _ := command["arguments"].(map[string]any)
				filename, _ := arguments["filename"].(string)
				_ = os.WriteFile(filename, frame, 0o600) // the frame is written; the reply is not
				close(seenC)
				<-release
				return
			}
			if err := encoder.Encode(map[string]any{"return": map[string]any{}, "id": command["id"]}); err != nil {
				return
			}
		}
	}()
	return socket, seenC
}

// Capture passes its context on, so canceling a screendump that QEMU does not
// answer ends the capture at once, not after the whole 15 s QMP command
// timeout, and leaves nothing in the scratch directory.
func TestCaptureEndsAtOnceWhenCanceledDuringAnUnansweredScreendump(t *testing.T) {
	socket, seen := silentScreendumpServer(t, onePixel(0))
	client, err := qmp.Dial(socket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	scratch := t.TempDir()
	if err := os.Chmod(scratch, 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		artifact *Artifact
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		artifact, err := Capture(ctx, client, 9931, scratch)
		done <- outcome{artifact, err}
	}()
	select {
	case <-seen:
	case got := <-done:
		t.Fatalf("Capture returned before the screendump was asked for: %+v, %v", got.artifact, got.err)
	case <-time.After(5 * time.Second):
		t.Fatal("the screendump command never arrived")
	}
	time.Sleep(200 * time.Millisecond)
	canceled := time.Now()
	cancel()
	select {
	case got := <-done:
		if got.artifact != nil || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("Capture = %+v, %v, want the cancellation", got.artifact, got.err)
		}
		if took := time.Since(canceled); took > 2*time.Second {
			t.Fatalf("Capture took %v to end after cancellation", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Capture was still waiting for QEMU 5 seconds after cancellation")
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a canceled capture left %d file(s) in the scratch directory", len(entries))
	}
}

// A capture that starts after the run was interrupted sends nothing.
func TestCaptureAfterCancellationAsksQEMUForNothing(t *testing.T) {
	socket, seen := silentScreendumpServer(t, onePixel(0))
	client, err := qmp.Dial(socket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scratch := t.TempDir()
	if err := os.Chmod(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	if artifact, err := Capture(ctx, client, 9932, scratch); artifact != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Capture = %+v, %v, want the cancellation", artifact, err)
	}
	select {
	case <-seen:
		t.Fatal("a screendump was requested after the run was interrupted")
	case <-time.After(300 * time.Millisecond):
	}
	if entries, _ := os.ReadDir(scratch); len(entries) != 0 {
		t.Fatalf("scratch directory holds %d file(s)", len(entries))
	}
}

//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	progresspkg "github.com/cliftcloud/certistack/pkg/progress"
)

// A worker streams valid progress events, each with the largest message the
// decoder keeps, for 4 MiB more than the controller keeps of its stderr, and
// then writes a marker and ends. The controller shows the worker's progress up
// to its budget, says so once, and stops the command at the stderr limit,
// before the marker, rather than rendering all 37 MB and learning of the
// overflow only when the command ends on its own.
func TestWorkerProgressStreamPastTheStderrLimitIsBoundedAndStopsTheCommand(t *testing.T) {
	eventLine, err := progresspkg.Encode(progresspkg.Event{Level: "INFO", Stage: "stream", Message: strings.Repeat("p", 4<<10)})
	if err != nil {
		t.Fatal(err)
	}
	eventCount := (maxWorkerStderr + (4 << 20) + len(eventLine) - 1) / len(eventLine)
	sourceBytes := eventCount * len(eventLine)
	if sourceBytes <= maxWorkerStderr {
		t.Fatalf("source stderr = %d bytes, want over %d", sourceBytes, maxWorkerStderr)
	}
	streamPath := filepath.Join(t.TempDir(), "worker-progress.log")
	stream, err := os.OpenFile(streamPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	buffered := bufio.NewWriterSize(stream, 256<<10)
	for i := 0; i < eventCount; i++ {
		if _, err := buffered.Write(eventLine); err != nil {
			t.Fatal(err)
		}
	}
	if err := buffered.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}

	markerPath := filepath.Join(t.TempDir(), "post-stream.marker")
	var rendered bytes.Buffer
	reporter := newProgressReporter(&rendered)
	// A hang guard only: under -race on a loaded 4-CPU runner the stream takes
	// half a minute or more, and nothing below depends on how long it took.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	started := time.Now()
	output, runErr := runCommand(ctx, "/bin/sh", []string{
		"-c", "/bin/cat \"$1\" >&2\nprintf done > \"$2\"", "sh", streamPath, markerPath,
	}, reporter)
	took := time.Since(started)
	if ctx.Err() != nil {
		t.Fatalf("the command was not stopped within five minutes: %v", ctx.Err())
	}
	if len(output) != 0 {
		t.Fatalf("stdout = %d bytes, want none", len(output))
	}
	if runErr == nil || !strings.Contains(runErr.Error(), "output exceeded 33554432 bytes") || !strings.Contains(runErr.Error(), "the command was stopped") {
		t.Fatalf("runCommand error = %v, want the stderr limit, with the command stopped", runErr)
	}
	// The marker is written only by a command that goes on to the end.
	time.Sleep(200 * time.Millisecond)
	if marker, err := os.ReadFile(markerPath); err == nil {
		t.Fatalf("the command ran to its end (marker %q) after it had crossed the stderr limit, %s into the stream", marker, took)
	}
	if err := reporter.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	text := rendered.String()
	if rendered.Len() > maxWorkerProgressBytes+4096 {
		t.Fatalf("rendered %d bytes of the worker's progress, want at most the %d it is shown", rendered.Len(), maxWorkerProgressBytes)
	}
	if got := strings.Count(text, "\n"); got >= eventCount {
		t.Fatalf("rendered %d lines of the %d the worker sent", got, eventCount)
	}
	if strings.Count(text, "progress is over the 16777216 bytes") != 1 {
		t.Fatalf("the budget was not announced exactly once:\n%.400s", text[len(text)-min(len(text), 400):])
	}
	// Every whole line was taken. The stream may end inside a line: the shell
	// is stopped at the limit, but cat goes on writing until the pipes are
	// closed (commandPipeDelay), and on a loaded machine that cuts a line.
	if len(reporter.pending) >= len(eventLine) || bytes.IndexByte(reporter.pending, '\n') >= 0 {
		t.Fatalf("pending progress bytes = %d, want less than one line (%d) and no whole line", len(reporter.pending), len(eventLine))
	}
	t.Logf("rendered %d of %d bytes (%d lines of %d events), the command stopped after %s", rendered.Len(), sourceBytes, strings.Count(text, "\n"), eventCount, took.Round(time.Millisecond))
}

// The same stop for a result that goes past what the controller holds.
func TestStdoutPastTheResultLimitStopsTheCommand(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "post-stream.marker")
	started := time.Now()
	// 70,000,000 bytes: 64 MiB is 67,108,864.
	output, err := runCommand(context.Background(), "/bin/sh", []string{
		"-c", "/usr/bin/head -c 70000000 /dev/zero\nsleep 30\nprintf done > \"$1\"", "sh", marker,
	}, nil)
	if output != nil || err == nil || !strings.Contains(err.Error(), "output exceeded 67108864 bytes") || !strings.Contains(err.Error(), "the command was stopped") {
		t.Fatalf("runCommand = %d bytes, %v; want the result limit, with the command stopped", len(output), err)
	}
	if took := time.Since(started); took > 20*time.Second {
		t.Fatalf("the command was stopped after %s: it ran to its end", took)
	}
	if _, err := os.ReadFile(marker); err == nil {
		t.Fatal("the command ran to its end")
	}
}

// A valid event reaches a progress writer that blocks, and the context is
// cancelled: runCommand returns at once, with the writer still blocked, and
// does not wait for the writer to be let go.
func TestCancelledCommandReturnsWhileTheProgressWriterIsBlocked(t *testing.T) {
	shortFlush(t, 200*time.Millisecond)
	eventLine, err := progresspkg.Encode(progresspkg.Event{Level: "INFO", Stage: "blocking-writer", Message: "synthetic worker progress"})
	if err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(t.TempDir(), "progress-event.log")
	if err := os.WriteFile(eventPath, eventLine, 0o600); err != nil {
		t.Fatal(err)
	}
	blocking := newStuckWriter()
	defer blocking.unstick()
	reporter := newProgressReporter(blocking)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		output []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		output, err := runCommand(ctx, "/bin/sh", []string{"-c", "/bin/cat \"$1\" >&2\nexec /bin/sleep 30", "sh", eventPath}, reporter)
		done <- result{output, err}
	}()
	select {
	case <-blocking.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the progress writer was never given the event")
	}
	cancelled := time.Now()
	cancel()
	select {
	case got := <-done:
		if got.err == nil || !strings.Contains(got.err.Error(), "signal: killed") || len(got.output) != 0 {
			t.Fatalf("runCommand = %d bytes, %v; want the killed child", len(got.output), got.err)
		}
		if took := time.Since(cancelled); took > 3*time.Second {
			t.Fatalf("runCommand returned %s after the cancellation", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runCommand did not return while the progress writer was blocked")
	}
	select {
	case <-blocking.release:
		t.Fatal("the writer was released before the test let it go")
	default:
	}
	// Control: a writer that takes output gets the event.
	var normal bytes.Buffer
	normalReporter := newProgressReporter(&normal)
	if _, err := runCommand(context.Background(), "/bin/sh", []string{"-c", "/bin/cat \"$1\" >&2", "sh", eventPath}, normalReporter); err != nil {
		t.Fatal(err)
	}
	_ = normalReporter.close()
	if !strings.Contains(normal.String(), "synthetic worker progress") {
		t.Fatalf("a writer that takes output was not given the event: %q", normal.String())
	}
}

// A flood into a writer too slow for it does not slow the command: the
// command ends while the writer is still held in its first write, so it waited
// for none of them. No clock decides it, so a loaded machine cannot fail it (a
// time limit cannot: the command can take 19 s with the load at 7.6).
func TestCommandIsNotSlowedByASlowProgressWriter(t *testing.T) {
	shortFlush(t, 10*time.Second)
	eventLine := workerEventLine(t, "a worker event")
	path := filepath.Join(t.TempDir(), "flood")
	var flood bytes.Buffer
	for i := 0; i < 20_000; i++ {
		flood.Write(eventLine)
	}
	if err := os.WriteFile(path, flood.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	slow := newStuckWriter()
	defer slow.unstick()
	reporter := newProgressReporter(slow)
	returned := make(chan error, 1)
	go func() {
		_, err := runCommand(context.Background(), "/bin/sh", []string{"-c", "/bin/cat \"$1\" >&2", "sh", path}, reporter)
		returned <- err
	}()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Minute): // a hang guard only
		t.Fatal("the command did not end while the progress writer was held")
	}
	select {
	case <-slow.release:
		t.Fatal("the writer was released before the test let it go")
	default:
	}
	slow.unstick()
	if err := reporter.close(); err == nil || !strings.Contains(err.Error(), "progress lines were not shown") {
		t.Fatalf("close = %v, want the lines the slow writer missed", err)
	}
	if !strings.Contains(slow.text(), "a worker event") {
		t.Fatalf("the writer was given none of the lines it had room for: %q", slow.text())
	}
}

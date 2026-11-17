// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	progresspkg "github.com/cliftcloud/certistack/pkg/progress"
)

// stuckWriter takes no output until it is released: a terminal that stopped
// reading, a full pipe, a logging adapter that waits on its collector.
type stuckWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	got     bytes.Buffer
}

func newStuckWriter() *stuckWriter {
	return &stuckWriter{entered: make(chan struct{}), release: make(chan struct{})}
}

func (w *stuckWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.got.Write(p)
}

// unstick lets the writer go, once, at the end of a test at the latest.
func (w *stuckWriter) unstick() {
	select {
	case <-w.release:
	default:
		close(w.release)
	}
}

func (w *stuckWriter) text() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.got.String()
}

// shortFlush makes the reporter and Run give up on a writer that does not
// answer after d, for the life of the test.
func shortFlush(t *testing.T, d time.Duration) {
	t.Helper()
	saved := progressFlushTimeout
	progressFlushTimeout = d
	t.Cleanup(func() { progressFlushTimeout = saved })
}

func workerEventLine(t *testing.T, message string) []byte {
	t.Helper()
	line, err := progresspkg.Encode(progresspkg.Event{Level: "INFO", Stage: "stream", Message: message})
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// A progress writer that stops taking output delays nothing. The
// reporter takes what a command writes at once, and closes within a bound.
func TestReporterTakesProgressAtOnceFromAWriterThatIsStuck(t *testing.T) {
	shortFlush(t, 200*time.Millisecond)
	w := newStuckWriter()
	defer w.unstick()
	reporter := newProgressReporter(w)
	// Four times what overflows both bounds of the queue. A Write that waited
	// for the stuck writer would wait the flush timeout, so the writes past the
	// queue would take tens of minutes; taking them at once takes seconds, more
	// under the race detector on a small runner (200,000 writes can take 16 s
	// there). The limit sits far from both.
	line := workerEventLine(t, "event")
	writes := 4 * max(maxQueuedProgressLines, maxQueuedProgressBytes/len(line)+1)
	limit := 60 * time.Second
	if blocked := time.Duration(writes-maxQueuedProgressLines) * progressFlushTimeout; blocked < 10*limit {
		t.Fatalf("%d writes would wait only %s in all if each waited the flush timeout: not far enough from %s", writes, blocked, limit)
	}
	started := time.Now()
	for i := 0; i < writes; i++ {
		if n, err := reporter.Write(workerEventLine(t, "event")); err != nil || n == 0 {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	reporter.status("controller status")
	reporter.notice("a notice")
	if took := time.Since(started); took > limit {
		t.Fatalf("feeding a writer that is stuck %d lines took %s", writes, took)
	}
	// What waits for the writer is bounded, whatever was written.
	reporter.sink.mu.Lock()
	queued, queuedBytes := reporter.sink.lines, reporter.sink.bytes
	reporter.sink.mu.Unlock()
	if queued > maxQueuedProgressLines || queuedBytes > maxQueuedProgressBytes {
		t.Fatalf("%d lines and %d bytes wait for the writer, want at most %d and %d", queued, queuedBytes, maxQueuedProgressLines, maxQueuedProgressBytes)
	}
	closed := time.Now()
	err := reporter.close()
	if took := time.Since(closed); took > 5*time.Second {
		t.Fatalf("close took %s with a writer that is stuck", took)
	}
	if err == nil || !strings.Contains(err.Error(), "progress lines were not shown") {
		t.Fatalf("close = %v, want the lines that never reached the writer", err)
	}
}

// The writer is not written to after the reporter is closed, when it
// takes output, and what was written before arrives whole and in order.
func TestReporterWritesInOrderAndNothingAfterClose(t *testing.T) {
	var out bytes.Buffer
	reporter := newProgressReporter(&out)
	for i := 0; i < 100; i++ {
		reporter.status("line %03d", i)
	}
	reporter.notice("a notice")
	if err := reporter.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 101 {
		t.Fatalf("%d lines, want 101", len(lines))
	}
	for i := 0; i < 100; i++ {
		if want := fmt.Sprintf("INFO line %03d", i); !strings.HasSuffix(lines[i], want) {
			t.Fatalf("line %d = %q, want it to end %q", i, lines[i], want)
		}
	}
	if lines[100] != "a notice" {
		t.Fatalf("the notice = %q", lines[100])
	}
	reporter.status("after close")
	if err := reporter.close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "after close") {
		t.Fatal("the reporter wrote after it was closed")
	}
}

// A writer that keeps up a little, too slowly for the flood, gets
// what fits, and is told how much it missed.
func TestReporterTellsASlowWriterWhatItMissed(t *testing.T) {
	shortFlush(t, 10*time.Second)
	slow := &pacedWriter{delay: 2 * time.Millisecond}
	reporter := newProgressReporter(slow)
	const events = 5000
	for i := 0; i < events; i++ {
		reporter.status("event %d", i)
	}
	if err := reporter.close(); err == nil || !strings.Contains(err.Error(), "progress lines were not shown") {
		t.Fatalf("close = %v, want the lines the writer did not keep up with", err)
	}
	text := slow.text()
	if !strings.Contains(text, "event 0\n") || !strings.Contains(text, "progress lines were not shown because the progress output did not keep up") {
		t.Fatalf("the writer was not told what it missed:\n%.300s", text)
	}
	if strings.Count(text, "\n") >= events {
		t.Fatalf("the writer was given %d lines of %d: nothing was dropped", strings.Count(text, "\n"), events)
	}
}

type pacedWriter struct {
	delay time.Duration
	mu    sync.Mutex
	got   bytes.Buffer
}

func (w *pacedWriter) Write(p []byte) (int, error) {
	time.Sleep(w.delay)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.got.Write(p)
}

func (w *pacedWriter) text() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.got.String()
}

// The first error of the writer is kept, and is the run's to tell.
func TestReporterKeepsTheWritersFirstError(t *testing.T) {
	first := errors.New("first failure")
	calls := 0
	reporter := newProgressReporter(writerFunc(func(p []byte) (int, error) {
		calls++
		return 0, fmt.Errorf("%w (write %d)", first, calls)
	}))
	reporter.status("one")
	reporter.status("two")
	err := reporter.close()
	if err == nil || !errors.Is(err, first) || !strings.Contains(err.Error(), "(write 1)") {
		t.Fatalf("close = %v, want the writer's first error", err)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// Exact limit and one over: the worker's events are shown up to the
// budget, to the byte; the first over it is said once, and the rest counted.
func TestWorkerProgressIsShownUpToItsBudget(t *testing.T) {
	var probe bytes.Buffer
	measure := newProgressReporter(&probe)
	measure.Write(workerEventLine(t, "event 0"))
	_ = measure.close()
	lineSize := probe.Len()

	for name, tc := range map[string]struct {
		budget, events, shown int
		notice                bool
	}{
		"exactly the budget":    {3 * lineSize, 3, 3, false},
		"one event over":        {3 * lineSize, 4, 3, true},
		"a hundred over":        {3 * lineSize, 103, 3, true},
		"a budget of one event": {lineSize, 2, 1, true},
		"no budget at all":      {0, 1, 0, true},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			reporter := newProgressReporter(&out)
			reporter.budget = tc.budget
			for i := 0; i < tc.events; i++ {
				if _, err := reporter.Write(workerEventLine(t, fmt.Sprintf("event %d", i))); err != nil {
					t.Fatal(err)
				}
			}
			// The controller's own lines are never held to it.
			reporter.status("the controller's own line")
			if err := reporter.close(); err != nil {
				t.Fatal(err)
			}
			text := out.String()
			if got := strings.Count(text, "] INFO [stream] event "); got != tc.shown {
				t.Fatalf("%d worker events shown, want %d:\n%s", got, tc.shown, text)
			}
			if got := strings.Count(text, "progress is over the"); (got == 1) != tc.notice || got > 1 {
				t.Fatalf("the budget was announced %d times, want once=%v:\n%s", got, tc.notice, text)
			}
			if !strings.Contains(text, "the controller's own line") {
				t.Fatalf("the controller's line was held to the worker's budget:\n%s", text)
			}
			if over := tc.events - tc.shown; over > 0 && !strings.Contains(text, fmt.Sprintf("%d events of the node worker's progress were not shown", over)) {
				t.Fatalf("the count of %d events over the budget is missing:\n%s", over, text)
			}
			if tc.shown*lineSize > tc.budget {
				t.Fatalf("the test shows %d bytes of a %d budget", tc.shown*lineSize, tc.budget)
			}
		})
	}
}

// A run's cleanup starts while the progress writer is stuck, and the run
// ends: the interruption path does not wait for the writer, although every
// line of the run's own output goes through it.
func TestRunCleansUpWhileTheProgressWriterIsStuck(t *testing.T) {
	shortFlush(t, 300*time.Millisecond)
	w := newStuckWriter()
	defer w.unstick()
	opts := preflightTestOptions(t)
	opts.Writer = w
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := &fakeCommandRunner{
		nodeRunHook:  cancel,
		nodeRunError: errors.New("ssh session ended"),
		nodeStderr:   progresspkg.EventPrefix + `{"level":"INFO","stage":"Storage","message":"Mounted PBS backup disk read-only."}` + "\n",
	}
	done := make(chan error, 1)
	go func() {
		_, err := (&Executor{runner: fake}).Run(ctx, opts)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v, want the interruption", err)
		}
		if err == nil || !strings.Contains(err.Error(), "progress") {
			t.Fatalf("Run = %v, want what the writer did wrong told in the error", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not end while its progress writer was stuck")
	}
	commands := make([]string, 0, len(fake.calls))
	for _, call := range fake.calls {
		commands = append(commands, strings.Join(call.args, " "))
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "worker.pid") || !strings.Contains(joined, "kill -TERM") || !strings.Contains(joined, "'recover'") {
		t.Fatalf("the interruption cleanup did not run while the writer was stuck:\n%s", joined)
	}
	select {
	case <-w.entered:
	default:
		t.Fatal("the writer was never given anything: the test did not stick it")
	}
}

// Keeps its meaning behind the queue: the emergency copy of a report
// is written by the operator's writer itself, in its turn, and what that
// writer does wrong is an error of the run; a writer that does not answer is
// given up on.
func TestEmergencyReportGivesUpOnAWriterThatIsStuck(t *testing.T) {
	shortFlush(t, 300*time.Millisecond)
	w := newStuckWriter()
	defer w.unstick()
	started := time.Now()
	result, err := unsavableRun(t, w, nil)
	if took := time.Since(started); took > 30*time.Second {
		t.Fatalf("Run took %s", took)
	}
	if !errors.Is(err, ErrEmergencyReportNotWritten) || !strings.Contains(err.Error(), "did not take it within") || result == nil || result.Report == nil {
		t.Fatalf("Run = %v, %+v; want the report kept in memory and the failed emergency copy reported", err, result)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// A run's progress is for an operator's terminal, a job log or a pipe, and
// any of them can stop taking it. What the controller does about the run, and
// above all its cleanup, must not wait for one that does: the
// progress goes to the writer through a bounded queue, from a goroutine of
// its own, and the commands and the control path only add to the queue.
const (
	// maxQueuedProgressLines and maxQueuedProgressBytes bound what waits for
	// the writer. A line that does not fit is not queued, and counted.
	maxQueuedProgressLines = 512
	maxQueuedProgressBytes = 1 << 20
)

// progressFlushTimeout is how long a run's end, and the emergency copy of a
// report, wait for the writer to take what is queued. A variable for tests.
var progressFlushTimeout = 5 * time.Second

// progressItem is one thing for the writer: a line, or a function that uses
// the writer itself, in its turn.
type progressItem struct {
	text string
	run  func(io.Writer) error
	done chan error
}

// progressSink writes progress to an io.Writer, in order, from one goroutine.
// Every method returns at once, or within the time it is given, whatever the
// writer does. A writer that blocks holds that goroutine, not the caller.
type progressSink struct {
	writer io.Writer

	mu      sync.Mutex
	items   []progressItem
	lines   int
	bytes   int
	dropped int   // lines refused since the writer was last told
	lost    int   // lines refused or abandoned, over the whole run
	err     error // the first error of the writer
	closed  bool
	wake    chan struct{}
	done    chan struct{}
}

func newProgressSink(writer io.Writer) *progressSink {
	s := &progressSink{writer: writer, wake: make(chan struct{}, 1), done: make(chan struct{})}
	go s.drain()
	return s
}

func (s *progressSink) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// put queues one line, or counts it when the writer is not keeping up.
func (s *progressSink) put(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if s.lines >= maxQueuedProgressLines || s.bytes+len(line) > maxQueuedProgressBytes {
		s.dropped++
		s.lost++
		return
	}
	s.items = append(s.items, progressItem{text: line})
	s.lines++
	s.bytes += len(line)
	s.signal()
}

// do has fn use the writer, in its turn among the lines, and returns its
// error, or an error when fn has not finished within timeout: fn may still
// run then.
func (s *progressSink) do(timeout time.Duration, fn func(io.Writer) error) error {
	done := make(chan error, 1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("the progress output is closed")
	}
	s.items = append(s.items, progressItem{run: fn, done: done})
	s.signal()
	s.mu.Unlock()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return fmt.Errorf("the progress output did not take it within %s", timeout)
	}
}

// close stops the queue taking lines and waits up to timeout for the writer to
// take what is queued. It reports whether it did: if not, what is queued is
// lost and counted, and the goroutine ends when the writer comes back.
func (s *progressSink) close(timeout time.Duration) bool {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.signal()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-s.done:
		return true
	case <-timer.C:
		s.mu.Lock()
		s.lost += s.lines
		s.items, s.lines, s.bytes = nil, 0, 0
		s.mu.Unlock()
		return false
	}
}

// problem is what the writer did wrong, if anything: its first error, and the
// lines that never reached it.
func (s *progressSink) problem() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.err != nil && s.lost > 0:
		return fmt.Errorf("the progress output failed (%w) and %d progress lines were not shown", s.err, s.lost)
	case s.err != nil:
		return fmt.Errorf("the progress output failed: %w", s.err)
	case s.lost > 0:
		return fmt.Errorf("%d progress lines were not shown because the progress output did not keep up", s.lost)
	}
	return nil
}

func (s *progressSink) write(text string) {
	if _, err := io.WriteString(s.writer, text); err != nil {
		s.mu.Lock()
		if s.err == nil {
			s.err = err
		}
		s.mu.Unlock()
	}
}

func (s *progressSink) drain() {
	defer close(s.done)
	for {
		s.mu.Lock()
		items, dropped, closed := s.items, s.dropped, s.closed
		s.items, s.lines, s.bytes, s.dropped = nil, 0, 0, 0
		s.mu.Unlock()
		for _, item := range items {
			if item.run == nil {
				s.write(item.text)
				continue
			}
			err := item.run(s.writer)
			item.done <- err
		}
		if dropped > 0 {
			s.write(fmt.Sprintf("warning: %d progress lines were not shown because the progress output did not keep up\n", dropped))
		}
		if len(items) == 0 && dropped == 0 {
			if closed {
				return
			}
			<-s.wake
		}
	}
}

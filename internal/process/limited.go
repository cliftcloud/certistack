// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package process

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"sync"
)

// ErrOutputLimit marks a command that wrote more than the limit it was run
// with: it was killed, and what its output held beyond the limit was not kept.
var ErrOutputLimit = errors.New("command output exceeded its limit")

// CombinedOutputLimited is CombinedOutput with a ceiling on what is buffered:
// the first limit bytes of the command's stdout and stderr, in the order it
// wrote them. A command that writes more is killed and waited for (it is never
// left running), and the error wraps ErrOutputLimit and says how much it had
// written; the bytes returned are the first limit. Nothing beyond the limit is
// retained, however long the command runs, so a client that streams for its
// whole time limit costs no more memory than one that stops at the limit.
func CombinedOutputLimited(cmd *exec.Cmd, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("output limit must be positive")
	}
	var out limitedWriter
	out.limit = limit
	// One writer for both, so exec gives the command one pipe for both and its
	// output keeps the order it was written in.
	cmd.Stdout, cmd.Stderr = &out, &out
	out.kill = func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	// Pdeathsig fires when the creating thread exits: the lock covers the
	// command's whole life, as in Run.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err := pipeHeld(cmd, cmd.Run())
	written, exceeded := out.result()
	if exceeded {
		return out.bytes(), fmt.Errorf("%w: it wrote %d bytes, over the %d it may write; it was stopped", ErrOutputLimit, written, limit)
	}
	return out.bytes(), err
}

// limitedWriter keeps the first limit bytes written to it, counts the rest and
// kills the command on the first byte over. It always accepts a write, so the
// command's pipe drains and the command is never blocked on it.
type limitedWriter struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	limit    int
	total    int64
	exceeded bool
	kill     func()
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total += int64(len(p))
	if room := w.limit - w.buf.Len(); room > 0 {
		w.buf.Write(p[:min(room, len(p))])
	}
	if w.total > int64(w.limit) && !w.exceeded {
		w.exceeded = true
		if w.kill != nil {
			w.kill()
		}
	}
	return len(p), nil
}

func (w *limitedWriter) result() (int64, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.total, w.exceeded
}

func (w *limitedWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

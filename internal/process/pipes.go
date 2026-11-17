// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package process

import (
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// PipeWaitDelay is how long a command's output pipes may stay open after the
// command has ended or been stopped (its context done, its output over the
// limit) before they are closed under it and the call returns. A program the
// command started, and left running, can keep a pipe open for as long as it
// lives, and the call, which reads the pipe to its end, would wait as long.
// Every command built here carries it as WaitDelay. It is a variable so that a
// test can shorten it.
//
// Closing the pipes stops no process: a descendant is left as it was, so a
// PBS map's daemon, which the run owns and recovery stops, is not killed by
// it. It stops the wait, not the work.
var PipeWaitDelay = 10 * time.Second

// ErrPipeHeld marks a command that ended on its own while a program it started
// still held its output pipe: the pipe was closed under the reader after
// PipeWaitDelay, so what the command wrote last may not have been read. The
// output is not to be taken as the command's whole output, and the error is
// not the command's success.
var ErrPipeHeld = errors.New("a program the command started kept its output open after it ended, so its output may be incomplete")

// pipeHeld turns exec's ErrWaitDelay into ErrPipeHeld, which says what it
// means for the output and keeps ErrWaitDelay for errors.Is. Other errors, and
// a command that failed or was stopped (whose error is its own), are returned
// as they are.
func pipeHeld(cmd *exec.Cmd, err error) error {
	if !errors.Is(err, exec.ErrWaitDelay) {
		return err
	}
	return fmt.Errorf("%w (its pipes were closed after %v): %w", ErrPipeHeld, cmd.WaitDelay, err)
}

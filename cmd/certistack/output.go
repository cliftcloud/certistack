// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"fmt"
	"io"
)

// checkedOutput is where a command writes its text result. The many
// fmt.Fprintf calls that render a summary drop their errors, so a failed write
// (a full disk, a closed descriptor, a failing collector) would let the command
// exit zero without having delivered its result, for verify-report the only
// visible signature verdict. checkedOutput remembers the first failure, refuses
// further writes, and deliver reports it in the command's exit status.
type checkedOutput struct {
	w   io.Writer
	err error
}

func newCheckedOutput(w io.Writer) *checkedOutput {
	return &checkedOutput{w: w}
}

// Write passes p on until a write fails or falls short.
func (o *checkedOutput) Write(p []byte) (int, error) {
	if o.err != nil {
		return 0, o.err
	}
	n, err := o.w.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		o.err = err
	}
	return n, err
}

// deliver is the command's result: err, joined with the failure to write its
// output if there was one. A command that otherwise succeeded exits with the
// infrastructure status, since what it was asked to show was not delivered;
// one that failed keeps its own exit status. saved says what the command had
// already done, when it changed something, so the failure is not read as
// having done nothing.
func (o *checkedOutput) deliver(err error, saved ...string) error {
	if o.err == nil {
		return err
	}
	message := "the command's result could not be written to standard output"
	if len(saved) > 0 {
		message += " (" + saved[0] + ")"
	}
	failure := fmt.Errorf("%s: %w", message, o.err)
	if err == nil {
		return withExitCode(failure, exitCodeInfrastructure)
	}
	return errors.Join(err, failure)
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build !linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
)

// readHiddenLine needs Linux, the platform a controller runs on: elsewhere a
// secret is never read from the terminal, where it would be shown.
func readHiddenLine(context.Context, string, io.Writer) (string, error) {
	return "", errors.New("pasting a secret needs a Linux controller; let certistack setup reach the PBS over ssh (--pbs-ssh) instead")
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

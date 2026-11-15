// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// readHiddenLine reads one line from the terminal with echo turned off, for a
// secret the operator pastes. Echo is restored on every path, including an
// error and Ctrl-C (which ends ctx).
func readHiddenLine(ctx context.Context, prompt string, out io.Writer) (string, error) {
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", errors.New("a secret can only be pasted at a terminal")
	}
	hidden := *old
	hidden.Lflag &^= unix.ECHO
	hidden.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &hidden); err != nil {
		return "", fmt.Errorf("turn terminal echo off: %w", err)
	}
	defer func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, old) }()
	fmt.Fprint(out, prompt)
	type answer struct {
		line string
		err  error
	}
	read := make(chan answer, 1)
	go func() {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		read <- answer{line, err}
	}()
	select {
	case <-ctx.Done():
		fmt.Fprintln(out)
		return "", ctx.Err()
	case a := <-read:
		fmt.Fprintln(out)
		if a.err != nil && a.line == "" {
			return "", errors.New("no secret was read")
		}
		return strings.TrimRight(a.line, "\r\n"), nil
	}
}

// stdinIsTerminal reports whether standard input is a terminal.
func stdinIsTerminal() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}

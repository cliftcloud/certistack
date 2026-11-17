// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
)

// The two first-run questions, word for word.
const (
	QuestionShare    = "Share anonymous usage statistics with Clift Cloud? Nothing but the five fields shown by `certistack telemetry show` is sent. [y/N] "
	QuestionBusiness = "Do you use CertiStack for a business or commercial purpose? [y/N] "
)

// Answer is what the user said. Share false means the second question was not
// asked and Business is false.
type Answer struct {
	Share    bool
	Business bool
}

// Ask puts the questions to the user on out and reads the answers from in.
// Only an explicit y or yes is a yes: an empty line, end of input and anything
// else is a no. ok is false when ctx ended first, so nothing is stored and the
// user is asked again next time.
func Ask(ctx context.Context, in io.Reader, out io.Writer) (a Answer, ok bool) {
	reader := bufio.NewReader(in)
	share, ok := askYesNo(ctx, reader, out, QuestionShare)
	if !ok {
		return Answer{}, false
	}
	if !share {
		fmt.Fprintln(out, "Nothing will be sent. `certistack telemetry enable` changes this at any time.")
		return Answer{}, true
	}
	business, ok := askYesNo(ctx, reader, out, QuestionBusiness)
	if !ok {
		return Answer{}, false
	}
	fmt.Fprintln(out, "Thank you. `certistack telemetry show` prints exactly what is sent; `certistack telemetry disable` stops it.")
	return Answer{Share: true, Business: business}, true
}

func askYesNo(ctx context.Context, r *bufio.Reader, out io.Writer, question string) (yes, ok bool) {
	fmt.Fprint(out, question)
	done := make(chan string, 1)
	go func() {
		// An error, including end of input, leaves line as read so far: a
		// final "y" without a newline still counts, and nothing else does.
		line, _ := r.ReadString('\n')
		done <- line
	}()
	select {
	case <-ctx.Done():
		fmt.Fprintln(out)
		return false, false
	case line := <-done:
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true, true
		}
		if !strings.HasSuffix(line, "\n") {
			fmt.Fprintln(out) // end of input: do not leave the cursor on the question
		}
		return false, true
	}
}

//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	progresspkg "github.com/cliftcloud/certistack/pkg/progress"
)

// bidiControls are the twelve Bidi_Control code points of the reporter: the
// marks, embeddings, overrides and isolates that reorder the text around them.
var bidiControls = []rune{
	'\u061c', '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069',
}

// unsafeForALine reports a rune a line of the operator's output must not
// carry: a control character other than the line's own end, or a format
// character (the bidi controls among them).
func unsafeForALine(line string) (rune, bool) {
	for _, r := range strings.TrimSuffix(line, "\n") {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) {
			return r, true
		}
	}
	return 0, false
}

// The reported case. A worker streams progress events that carry the
// bidirectional controls, one code point at a time and the reporter's paired
// RLO/PDF around a word, through the real command runner into the real
// progress reporter. The line the operator reads must be the line in logical
// order: the control is gone from the level, the stage and the message, and the
// words, the right-to-left letters among them, are untouched. The controller
// rendered them as they came.
func TestWorkerProgressRendersNoDirectionalControls(t *testing.T) {
	var stream bytes.Buffer
	emit := func(level, stage, message string) {
		line, err := progresspkg.Encode(progresspkg.Event{Level: level, Stage: stage, Message: message})
		if err != nil {
			t.Fatal(err)
		}
		stream.Write(line)
	}
	for _, r := range bidiControls {
		c := string(r)
		emit("WARN"+c, "ver"+c+"ification", "before"+c+"after")
	}
	// The reporter's event.
	emit("WARN", "verification", "worker status: FAILED "+string('\u202e')+"SSAP"+string('\u202c'))
	// Control characters of the classes the sanitizer always caught, with a
	// no-break space and a line separator the renderer flattens.
	emit("INFO", "term", "ok\x1b[2Kgone\u00a0here\u2028next")
	// Text people read is the worker's to send.
	emit("INFO", "שלום", "مرحبا Zoë 日本語 ✓")

	streamPath := filepath.Join(t.TempDir(), "worker-progress.log")
	if err := os.WriteFile(streamPath, stream.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	reporter := newProgressReporter(&rendered)
	if output, err := runCommand(context.Background(), "/bin/sh", []string{"-c", "/bin/cat \"$1\" >&2", "sh", streamPath}, reporter); err != nil || len(output) != 0 {
		t.Fatalf("progress command: stdout %d bytes, %v", len(output), err)
	}
	if err := reporter.close(); err != nil {
		t.Fatal(err)
	}

	lines := strings.SplitAfter(rendered.String(), "\n")
	lines = lines[:len(lines)-1]
	if want := len(bidiControls) + 3; len(lines) != want {
		t.Fatalf("rendered %d lines, want %d:\n%s", len(lines), want, rendered.String())
	}
	for i, line := range lines {
		if r, bad := unsafeForALine(line); bad {
			t.Errorf("line %d carries U+%04X: %q", i+1, r, line)
		}
	}
	for i, r := range bidiControls {
		if want := "WARN [verification] beforeafter\n"; !strings.HasSuffix(lines[i], want) {
			t.Errorf("U+%04X: rendered %q, want it to end %q", r, lines[i], want)
		}
	}
	if want := "WARN [verification] worker status: FAILED SSAP\n"; !strings.HasSuffix(lines[len(bidiControls)], want) {
		t.Errorf("the reporter's event rendered %q, want it to end %q", lines[len(bidiControls)], want)
	}
	if want := "INFO [term] ok[2Kgone here; next\n"; !strings.HasSuffix(lines[len(bidiControls)+1], want) {
		t.Errorf("control characters rendered %q, want it to end %q", lines[len(bidiControls)+1], want)
	}
	if want := "INFO [שלום] مرحبا Zoë 日本語 ✓\n"; !strings.HasSuffix(lines[len(bidiControls)+2], want) {
		t.Errorf("ordinary text rendered %q, want it to end %q", lines[len(bidiControls)+2], want)
	}
}

// The controller's own lines hold text a guest or a worker influenced
// (a probe's output in an error, a node's message). Whatever method renders it,
// the line is one line without a control that reorders it. The worker's events
// pass through the decoder too, so this is the renderer's own guard.
func TestControllerProgressLinesRenderNoDirectionalControls(t *testing.T) {
	hostile := fmt.Errorf("probe output FAILED %cSSAP%c\nforged line %c%c", '\u202e', '\u202c', '\u2067', '\u2069')
	for name, emit := range map[string]func(*progressReporter){
		"status":  func(p *progressReporter) { p.status("note: %v", hostile) },
		"success": func(p *progressReporter) { p.success("done: %v", hostile) },
		"warning": func(p *progressReporter) { p.warning("careful: %v", hostile) },
		"failure": func(p *progressReporter) { p.failure("broken: %v", hostile) },
		"notice":  func(p *progressReporter) { p.notice("warning: %v", hostile) },
	} {
		t.Run(name, func(t *testing.T) {
			var rendered bytes.Buffer
			reporter := newProgressReporter(&rendered)
			emit(reporter)
			if err := reporter.close(); err != nil {
				t.Fatal(err)
			}
			text := rendered.String()
			if strings.Count(text, "\n") != 1 || !strings.Contains(text, "FAILED SSAP; forged line") {
				t.Fatalf("rendered %q, want one line reading \"FAILED SSAP; forged line\"", text)
			}
			if r, bad := unsafeForALine(text); bad {
				t.Fatalf("the line carries U+%04X: %q", r, text)
			}
		})
	}
}

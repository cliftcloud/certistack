// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package progress transports concise, safe worker lifecycle events to a
// controller without sharing the worker's JSON result channel.
package progress

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode"
)

const (
	// EnvironmentEvents enables event emission on stderr. It is set only in the
	// short-lived controller-to-worker runtime environment.
	EnvironmentEvents = "CERTISTACK_PROGRESS_EVENTS"
	// EventPrefix makes event lines unambiguous among normal structured logs.
	EventPrefix = "CERTISTACK_PROGRESS "
	// maxDecodedFieldLength bounds how much text one worker-originated event
	// can inject into the controller operator's terminal and logs. The node
	// worker is the less-trusted tier; nothing enforces this length on the
	// encode side beyond well-behaved callers, so the decode side must not
	// trust it.
	maxDecodedFieldLength = 4 << 10
)

// Event is a user-safe lifecycle update. It intentionally excludes credentials,
// tokens, full runtime environment values, and arbitrary command output.
type Event struct {
	Level   string `json:"level"`
	Stage   string `json:"stage,omitempty"`
	Message string `json:"message"`
}

// Emit writes one machine-readable progress event to stderr only when the
// controller has explicitly enabled the event channel.
func Emit(level, stage, format string, args ...any) {
	if os.Getenv(EnvironmentEvents) != "1" {
		return
	}
	event := Event{
		Level:   strings.ToUpper(level),
		Stage:   normalizeLineBreaks(stage),
		Message: normalizeLineBreaks(fmt.Sprintf(format, args...)),
	}
	line, err := Encode(event)
	if err != nil {
		return
	}
	_, _ = os.Stderr.Write(line)
}

func normalizeLineBreaks(value string) string {
	return strings.NewReplacer("\r\n", "; ", "\r", "; ", "\n", "; ").Replace(value)
}

func Info(stage, format string, args ...any)  { Emit("INFO", stage, format, args...) }
func Warn(stage, format string, args ...any)  { Emit("WARN", stage, format, args...) }
func Error(stage, format string, args ...any) { Emit("ERROR", stage, format, args...) }

// Encode turns an event into one newline-delimited stderr record.
func Encode(event Event) ([]byte, error) {
	if strings.TrimSpace(event.Level) == "" || strings.TrimSpace(event.Message) == "" {
		return nil, fmt.Errorf("progress event level and message are required")
	}
	if strings.ContainsAny(event.Stage, "\x00\r\n") || strings.ContainsAny(event.Message, "\x00\r\n") {
		return nil, fmt.Errorf("progress event contains a control character")
	}
	data, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(EventPrefix), data...), '\n'), nil
}

// DecodeLine identifies and decodes one event line. Non-event lines are
// expected normal worker logs and return ok=false.
//
// The event originates on the node worker, the less-trusted side of the
// controller/worker boundary: a compromised or malfunctioning worker must not
// be able to inject terminal escape sequences (to hide or forge lines an
// operator watches live) or unbounded text into the controller's process.
// Every field is therefore stripped of control characters and length-capped
// before it is returned, in addition to the structural checks below.
func DecodeLine(line string) (event Event, ok bool) {
	if !strings.HasPrefix(line, EventPrefix) {
		return Event{}, false
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, EventPrefix)), &event); err != nil || strings.TrimSpace(event.Level) == "" || strings.TrimSpace(event.Message) == "" {
		return Event{}, false
	}
	// \x00\r\n specifically break the controller's one-event-per-line
	// rendering (a raw newline could forge a second, fabricated line); reject
	// the whole event rather than trying to repair it.
	if strings.ContainsAny(event.Level, "\x00\r\n") || strings.ContainsAny(event.Stage, "\x00\r\n") || strings.ContainsAny(event.Message, "\x00\r\n") {
		return Event{}, false
	}
	// Every other control character - notably ESC (\x1b), which starts an
	// ANSI/terminal escape sequence a hostile worker could use to overwrite
	// or hide prior lines an operator is watching live - is stripped rather
	// than rejected, and each field is length-capped so one event cannot grow
	// without bound in the controller's terminal and logs.
	event.Level = sanitizeDecodedField(event.Level)
	event.Stage = sanitizeDecodedField(event.Stage)
	event.Message = sanitizeDecodedField(event.Message)
	if event.Level == "" || event.Message == "" {
		return Event{}, false
	}
	event.Level = strings.ToUpper(event.Level)
	return event, true
}

// sanitizeDecodedField strips remaining Unicode control characters (the
// caller has already rejected \x00\r\n outright) and format characters, and
// truncates the result. The format characters (Cf) include the bidirectional
// controls, which reorder the text around them on a terminal: ordinary right
// to left letters are kept, the characters that rearrange them are not. The
// renderer flattens the text once more (SingleLine), so a field is clean
// whichever of the two is bypassed.
func sanitizeDecodedField(value string) string {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, value)
	clean = strings.TrimSpace(clean)
	if len(clean) > maxDecodedFieldLength {
		clean = clean[:maxDecodedFieldLength] + "...(truncated)"
	}
	return clean
}

// SingleLine flattens text that a less-trusted party can influence (a guest's
// output in a failure, a worker's error) into one line that cannot forge
// another, cannot drive a terminal, and cannot make what follows it read
// differently than it is written. Each run of line breaks (CR, LF, vertical
// tab, form feed, NEL, and the Unicode line and paragraph separators) becomes
// "; ", a tab and every other space separator (no-break, em, thin and the
// like) becomes an ordinary space, and these are dropped: the control
// characters (ESC among them), the Unicode format characters (Cf: the bidi
// controls U+202A to U+202E and U+2066 to U+2069, U+200E, U+200F and U+061C,
// which reorder text on screen, and the zero-width, joiner, soft-hyphen,
// byte-order-mark and tag characters, which hide it), private-use characters
// and unpaired surrogates. What stays is what a person reads: letters,
// combining marks, digits, punctuation and symbols, emoji included (an emoji
// sequence a joiner held together is shown as its parts). Text of CertiStack's
// own that spans lines, such as joined errors, stays readable as "first;
// second".
func SingleLine(text string) string {
	var out strings.Builder
	pendingBreak := false
	for _, r := range text {
		switch {
		case r == '\r' || r == '\n' || r == '\v' || r == '\f' || r == '\u0085' || r == '\u2028' || r == '\u2029':
			pendingBreak = true
			continue
		case r == '\t' || unicode.Is(unicode.Zs, r):
			r = ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r) || unicode.Is(unicode.Cs, r):
			continue
		}
		if pendingBreak && out.Len() > 0 {
			out.WriteString("; ")
		}
		pendingBreak = false
		out.WriteRune(r)
	}
	return strings.TrimSpace(out.String())
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package progress

import (
	"strings"
	"testing"
)

func TestEncodeDecodeLine(t *testing.T) {
	encoded, err := Encode(Event{Level: "INFO", Stage: "QMP check", Message: "QMP verified"})
	if err != nil {
		t.Fatal(err)
	}
	event, ok := DecodeLine(string(encoded[:len(encoded)-1]))
	if !ok {
		t.Fatal("encoded event was not decoded")
	}
	if event.Level != "INFO" || event.Stage != "QMP check" || event.Message != "QMP verified" {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func TestDecodeLineRejectsNormalLogs(t *testing.T) {
	if _, ok := DecodeLine(`time=2026-09-18T00:00:00Z level=INFO msg="normal log"`); ok {
		t.Fatal("normal log was decoded as a progress event")
	}
}

func TestDecodeLineRejectsEmbeddedNewline(t *testing.T) {
	line := EventPrefix + `{"level":"INFO","message":"first\nsecond"}`
	if _, ok := DecodeLine(line); ok {
		t.Fatal("event with embedded newline was decoded")
	}
}

func TestDecodeLineStripsANSIEscapeSequences(t *testing.T) {
	line := EventPrefix + `{"level":"SUCCESS","message":"restore test passed\u001b[1A\u001b[2Khidden"}`
	event, ok := DecodeLine(line)
	if !ok {
		t.Fatal("event with an ANSI escape sequence was rejected outright, want stripped and accepted")
	}
	if strings.ContainsRune(event.Message, '\x1b') {
		t.Fatalf("decoded message still contains an ANSI escape byte: %q", event.Message)
	}
	if event.Message != "restore test passed[1A[2Khidden" {
		t.Fatalf("decoded message = %q, want escape bytes stripped with surrounding text preserved", event.Message)
	}
}

// The decoder promises that a worker's event cannot drive the
// controller's terminal. The twelve Bidi_Control code points (and the other
// format characters that hide text) left it in the level, the stage and the
// message; ordinary right-to-left letters are the worker's to send.
func TestDecodeLineDropsFormatAndBidiCharacters(t *testing.T) {
	bidi := []rune{'\u061c', '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069'}
	for _, r := range append(bidi, '\u200b', '\u200d', '\ufeff', '\u00ad', '\U000e0041') {
		text := string(r)
		line := EventPrefix + `{"level":"WARN` + text + `","stage":"ver` + text + `ification","message":"worker status: FAILED ` + text + `SSAP` + text + `"}`
		event, ok := DecodeLine(line)
		if !ok {
			t.Fatalf("U+%04X: the event was rejected", r)
		}
		if event.Level != "WARN" || event.Stage != "verification" || event.Message != "worker status: FAILED SSAP" {
			t.Errorf("U+%04X: decoded %+v, want the format character gone from level, stage and message", r, event)
		}
	}
	line := EventPrefix + `{"level":"INFO","stage":"שלום","message":"مرحبا Zoë 日本語 ✓"}`
	if event, ok := DecodeLine(line); !ok || event.Stage != "שלום" || event.Message != "مرحبا Zoë 日本語 ✓" {
		t.Errorf("ordinary right-to-left and other text: %+v, ok %v; want it kept", event, ok)
	}
	// An event that is nothing but format characters says nothing.
	if _, ok := DecodeLine(EventPrefix + `{"level":"INFO","message":"\u202e\u202c"}`); ok {
		t.Error("an event whose whole message is format characters was accepted")
	}
}

func TestDecodeLineTruncatesOversizedFields(t *testing.T) {
	huge := strings.Repeat("a", maxDecodedFieldLength*2)
	encoded, err := Encode(Event{Level: "INFO", Message: huge})
	if err != nil {
		t.Fatal(err)
	}
	event, ok := DecodeLine(string(encoded[:len(encoded)-1]))
	if !ok {
		t.Fatal("oversized event was rejected outright, want truncated and accepted")
	}
	if len(event.Message) > maxDecodedFieldLength+len("...(truncated)") {
		t.Fatalf("decoded message length = %d, want bounded near %d", len(event.Message), maxDecodedFieldLength)
	}
	if !strings.HasSuffix(event.Message, "...(truncated)") {
		t.Fatalf("truncated message missing truncation marker: %q", event.Message[:40])
	}
}

func TestNormalizeLineBreaks(t *testing.T) {
	got := normalizeLineBreaks("first\r\nsecond\rthird\nfourth")
	if got != "first; second; third; fourth" {
		t.Fatalf("normalized line breaks = %q", got)
	}
	encoded, err := Encode(Event{Level: "ERROR", Message: got})
	if err != nil {
		t.Fatalf("normalized event was rejected: %v", err)
	}
	if _, ok := DecodeLine(string(encoded[:len(encoded)-1])); !ok {
		t.Fatal("normalized event was not decodable")
	}
}

// Text a guest can influence must not forge a line, or drive a terminal, in a
// log or a signed failure reason.
func TestSingleLineFlattensWhatCouldForgeALine(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"plain":                {"probe failed: connection refused", "probe failed: connection refused"},
		"a newline":            {"probe failed\n✓ Controller report saved to: /reports/forged.json", "probe failed; ✓ Controller report saved to: /reports/forged.json"},
		"CRLF and CR":          {"a\r\nb\rc", "a; b; c"},
		"a run of breaks":      {"a\n\n\r\nb", "a; b"},
		"leading and trailing": {"\n\na\n\n", "a"},
		"other line breaks":    {"a\u0085b\u2028c\u2029d\ve\ff", "a; b; c; d; e; f"},
		"a tab":                {"a\tb", "a b"},
		"an escape sequence":   {"passed\x1b[1A\x1b[2Khidden", "passed[1A[2Khidden"},
		"NUL and DEL":          {"a\x00b\x7fc", "abc"},
		"joined errors":        {"first error\nsecond error", "first error; second error"},
		"empty":                {"", ""},
		"only breaks":          {"\n\r\n", ""},
	} {
		if got := SingleLine(tc.in); got != tc.want {
			t.Errorf("%s: SingleLine(%q) = %q, want %q", name, tc.in, got, tc.want)
		}
	}
}

// The Unicode format characters stayed, so a right-to-left override in
// guest-controlled text could reorder what followed it on a terminal and in a signed
// failure reason. They and the other invisible characters are dropped; text people
// read is kept.
func TestSingleLineDropsFormatAndBidiCharacters(t *testing.T) {
	for name, r := range map[string]rune{
		"right-to-left override": '\u202e', "left-to-right override": '\u202d', "embedding": '\u202a', "pop": '\u202c',
		"isolate": '\u2066', "first strong isolate": '\u2068', "pop isolate": '\u2069',
		"left-to-right mark": '\u200e', "right-to-left mark": '\u200f', "arabic letter mark": '\u061c',
		"zero-width space": '\u200b', "zero-width joiner": '\u200d', "zero-width non-joiner": '\u200c',
		"word joiner": '\u2060', "soft hyphen": '\u00ad', "byte-order mark": '\ufeff', "a tag character": '\U000e0041',
		"a private-use character": '\ue000',
	} {
		in := "probe failed: stdout=" + string(r) + "DESSAP" + string(r) + " done"
		if got, want := SingleLine(in), "probe failed: stdout=DESSAP done"; got != want {
			t.Errorf("%s (U+%04X): SingleLine = %q, want %q", name, r, got, want)
		}
	}
	for name, tc := range map[string]struct{ in, want string }{
		"no-break and em spaces": {"a\u00a0b\u2003c\u3000d", "a b c d"},
		"letters and marks":      {"Zoë é 日本語 مرحبا", "Zoë é 日本語 مرحبا"},
		"symbols and emoji":      {"disk 100% ✓ ⚠ 🙂", "disk 100% ✓ ⚠ 🙂"},
		"an emoji joined":        {"👨\u200d👩", "👨👩"},
	} {
		if got := SingleLine(tc.in); got != tc.want {
			t.Errorf("%s: SingleLine(%q) = %q, want %q", name, tc.in, got, tc.want)
		}
	}
}

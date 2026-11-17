// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The structure a report the verifier or the public API parses may have. A
// report's signature says who signed it, not that it is safe to hold in memory:
// decoded several times, a genuinely signed report of 16 MiB in one string
// costs 38 times its size in allocations, and a hostile or runaway signer
// chooses the shape.
// The limits are far above any report CertiStack writes and far below what
// could exhaust memory or CPU, and they are checked, in one pass over the
// bytes that allocates nothing for values, before a byte is decoded or
// canonicalized.
//
// What real reports weigh: across 1,773 reports written by test runs
// (schema 1.5) the largest was 5.0 MiB (8 failing Windows VMs, each with a
// base64 screenshot of the console), nesting reached 6 levels, an object held
// at most 26 members, an array at most 132 elements, a member name at most 30
// bytes, a string at most 0.97 MiB and a whole report at most 6,470 values.
// The largest report the controller can produce is bound by what it accepts
// from a worker, 64 MiB of JSON, about a hundred failing VMs.
const (
	// MaxReportFileBytes bounds a whole report, as a file or as the bytes given
	// to the verifier: twice the controller's largest worker result (64 MiB),
	// which leaves room for the indentation of the saved report and for what
	// signing adds.
	MaxReportFileBytes = 128 << 20
	// MaxReportDepth bounds how deeply arrays and objects nest (the report
	// itself is level 1). Real reports reach 6.
	MaxReportDepth = 32
	// MaxReportMembers bounds the members of one object. Real reports reach 26.
	// The member bound is what protects canonicalization: the RFC 8785 library
	// sorts an object's members in time quadratic in their number (one object
	// of 80,000 members took 13 seconds, one of 1,000,000 more than nine
	// minutes), so the work is bounded here, not there.
	MaxReportMembers = 256
	// MaxReportElements bounds the elements of one array. Real reports reach
	// 132 (a plan holds a few thousand VMs at most).
	MaxReportElements = 65536
	// MaxReportKeyBytes bounds one member name, as written. Real names reach 30.
	MaxReportKeyBytes = 256
	// MaxReportStringBytes bounds one string value, as written: the controller's
	// whole worker result (64 MiB), which no single value can exceed. Real
	// strings, the base64 screenshots, reach about 1 MiB.
	MaxReportStringBytes = 64 << 20
	// MaxReportValues bounds every value in a report (containers included),
	// which bounds the work of decoding and canonicalizing it. Real reports
	// reach 6,470; a worker result of 64 MiB cannot hold more than a few
	// million.
	MaxReportValues = 2 << 20
)

// ErrReportLimit is wrapped by the error for a report that exceeds a byte or
// structural limit above. Such a report is refused before it is decoded.
var ErrReportLimit = errors.New("report exceeds a size or structure limit")

// jsonLimits is what a JSON document may be, and what else scanJSON checks.
type jsonLimits struct {
	what           string // the document, in errors: "report" or "keyring"
	sentinel       error  // wrapped by a limit error, when not nil
	maxBytes       int
	maxDepth       int
	maxMembers     int
	maxElements    int
	maxKeyBytes    int
	maxStringBytes int
	maxValues      int
	// numbers refuses an integer of 2^53 or more, which RFC 8785 canonicalization
	// would round: it is a property of what is signed, so it is checked for
	// reports only.
	numbers bool
	// strictText refuses text that is not Unicode: a byte that is not UTF-8, and
	// a \u escape of half a surrogate pair. encoding/json reads each of them as
	// U+FFFD, so several different files would carry one canonical form and one
	// signature (RFC 8259 section 8.1 and RFC 8785 forbid both). Checked for
	// reports only, since it too is a property of what is signed.
	strictText bool
	// foldNames refuses two members of one object whose names differ only by
	// case folding. encoding/json matches a member to a struct field without
	// regard to case, so both would be read into one field and the later would
	// shadow the earlier, while the canonical form keeps both. Checked for
	// reports only.
	foldNames bool
}

var reportLimits = &jsonLimits{
	what: "report", sentinel: ErrReportLimit,
	maxBytes: MaxReportFileBytes, maxDepth: MaxReportDepth, maxMembers: MaxReportMembers,
	maxElements: MaxReportElements, maxKeyBytes: MaxReportKeyBytes,
	maxStringBytes: MaxReportStringBytes, maxValues: MaxReportValues, numbers: true,
	strictText: true, foldNames: true,
}

// keyringLimits are generous for a file of at most MaxKeyringFileBytes, which
// holds thousands of signers, each a small object.
var keyringLimits = &jsonLimits{
	what:     "keyring",
	maxBytes: MaxKeyringFileBytes, maxDepth: 16, maxMembers: 1024,
	maxElements: 32768, maxKeyBytes: 256,
	maxStringBytes: 64 << 10, maxValues: 1 << 20,
}

// scanJSON checks data in one pass, without decoding a value: it is one JSON
// document (RFC 8259, the grammar encoding/json applies: any byte from 0x80 is
// allowed inside a string, a control character or a bad escape is not), within
// limits, in which no object repeats a member name (names compared as
// encoding/json reads them, so "a" and "a" are one name), and, for a
// report, no integer of 2^53 or more. Errors carry the path of the offending
// value, or its byte offset for a fault of grammar. The check stops at the first
// fault, so a document is never scanned past the point it is refused.
func scanJSON(data []byte, limits *jsonLimits) error {
	if len(data) > limits.maxBytes {
		return limits.exceeded(fmt.Sprintf("is %d bytes; at most %d are read", len(data), limits.maxBytes), "")
	}
	s := &jsonScan{data: data, limits: limits}
	s.skipSpace()
	if err := s.value(1); err != nil {
		return err
	}
	s.skipSpace()
	if s.pos != len(data) {
		return s.syntax("unexpected data after the top-level JSON value")
	}
	return nil
}

func (l *jsonLimits) exceeded(what, path string) error {
	where := ""
	if path != "" {
		where = " at " + path
	}
	if l.sentinel != nil {
		return fmt.Errorf("%w: it %s%s", l.sentinel, what, where)
	}
	return fmt.Errorf("%s exceeds a size or structure limit: it %s%s", l.what, what, where)
}

// frame is one level of the path to the value being scanned.
type frame struct {
	array          bool
	index          int
	keyLo, keyHi   int
	keyNeedsUnwrap bool
}

type jsonScan struct {
	data   []byte
	pos    int
	values int
	limits *jsonLimits
	path   []frame
}

func (s *jsonScan) syntax(problem string) error {
	return fmt.Errorf("invalid JSON at byte %d: %s", s.pos, problem)
}

// pathString renders the path of the value being scanned, such as
// $.vm_records[3].probe_results[0].
func (s *jsonScan) pathString() string {
	var b strings.Builder
	b.WriteString("$")
	for _, f := range s.path {
		if f.array {
			fmt.Fprintf(&b, "[%d]", f.index)
			continue
		}
		b.WriteString(".")
		quoted := quoteShort(string(s.unquoteKey(f.keyLo, f.keyHi, f.keyNeedsUnwrap)))
		b.WriteString(quoted[1 : len(quoted)-1])
	}
	return b.String()
}

func (s *jsonScan) skipSpace() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\r', '\n':
			s.pos++
		default:
			return
		}
	}
}

func (s *jsonScan) value(depth int) error {
	s.values++
	if s.values > s.limits.maxValues {
		return s.limits.exceeded(fmt.Sprintf("holds more than %d values", s.limits.maxValues), s.pathString())
	}
	if s.pos >= len(s.data) {
		return s.syntax("unexpected end of JSON input")
	}
	switch c := s.data[s.pos]; {
	case c == '{':
		return s.object(depth)
	case c == '[':
		return s.array(depth)
	case c == '"':
		_, _, _, err := s.str(s.limits.maxStringBytes, "a string longer than %d bytes")
		return err
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return s.number()
	}
	return s.syntax("invalid character looking for the beginning of a value")
}

func (s *jsonScan) literal(word string) error {
	if !bytes.HasPrefix(s.data[s.pos:], []byte(word)) {
		return s.syntax("invalid literal")
	}
	s.pos += len(word)
	return nil
}

func (s *jsonScan) object(depth int) error {
	if depth > s.limits.maxDepth {
		return s.limits.exceeded(fmt.Sprintf("is nested more than %d levels deep", s.limits.maxDepth), s.pathString())
	}
	s.pos++ // {
	s.skipSpace()
	if s.pos < len(s.data) && s.data[s.pos] == '}' {
		s.pos++
		return nil
	}
	var seen, seenFolded keySet
	members := 0
	for {
		s.skipSpace()
		if s.pos >= len(s.data) || s.data[s.pos] != '"' {
			return s.syntax("expected a string as the object key")
		}
		lo, hi, special, err := s.str(s.limits.maxKeyBytes, "a member name longer than %d bytes")
		if err != nil {
			return err
		}
		members++
		// Faults about the object are reported at the object's own path; the
		// member joins the path for the value it holds.
		if members > s.limits.maxMembers {
			return s.limits.exceeded(fmt.Sprintf("has an object of more than %d members", s.limits.maxMembers), s.pathString())
		}
		name := s.unquoteKey(lo, hi, special)
		if seen.add(name) {
			return fmt.Errorf("duplicate JSON object key %s at %s", quoteShort(string(name)), s.pathString())
		}
		if s.limits.foldNames && seenFolded.add(foldName(name)) {
			return fmt.Errorf("member name %s differs only by letter case (or case folding) from another member of the same object at %s: the decoder matches names without regard to case, so one would hide the other", quoteShort(string(name)), s.pathString())
		}
		s.path = append(s.path, frame{keyLo: lo, keyHi: hi, keyNeedsUnwrap: special})
		s.skipSpace()
		if s.pos >= len(s.data) || s.data[s.pos] != ':' {
			return s.syntax("expected a colon after the object key")
		}
		s.pos++
		s.skipSpace()
		if err := s.value(depth + 1); err != nil {
			return err
		}
		s.path = s.path[:len(s.path)-1]
		s.skipSpace()
		if s.pos >= len(s.data) {
			return s.syntax("unexpected end of JSON input")
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
		case '}':
			s.pos++
			return nil
		default:
			return s.syntax("expected a comma or the end of the object")
		}
	}
}

func (s *jsonScan) array(depth int) error {
	if depth > s.limits.maxDepth {
		return s.limits.exceeded(fmt.Sprintf("is nested more than %d levels deep", s.limits.maxDepth), s.pathString())
	}
	s.pos++ // [
	s.skipSpace()
	if s.pos < len(s.data) && s.data[s.pos] == ']' {
		s.pos++
		return nil
	}
	for index := 0; ; index++ {
		s.path = append(s.path, frame{array: true, index: index})
		if index >= s.limits.maxElements {
			return s.limits.exceeded(fmt.Sprintf("has an array of more than %d elements", s.limits.maxElements), s.pathString())
		}
		s.skipSpace()
		if err := s.value(depth + 1); err != nil {
			return err
		}
		s.path = s.path[:len(s.path)-1]
		s.skipSpace()
		if s.pos >= len(s.data) {
			return s.syntax("unexpected end of JSON input")
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
		case ']':
			s.pos++
			return nil
		default:
			return s.syntax("expected a comma or the end of the array")
		}
	}
}

// str scans the string at s.pos and returns the bytes between its quotes, and
// whether they hold an escape or a byte from 0x80, in which case the name they
// spell is not the bytes themselves. A string longer than max as written is
// refused as soon as it is, not after it was read to its end.
func (s *jsonScan) str(max int, tooLong string) (lo, hi int, special bool, err error) {
	s.pos++ // the opening quote
	lo = s.pos
	for {
		if s.pos >= len(s.data) {
			return 0, 0, false, s.syntax("unexpected end of JSON input inside a string")
		}
		if s.pos-lo > max {
			return 0, 0, false, s.limits.exceeded(fmt.Sprintf("holds "+tooLong, max), s.pathString())
		}
		switch c := s.data[s.pos]; {
		case c == '"':
			hi = s.pos
			s.pos++
			return lo, hi, special, nil
		case c == '\\':
			special = true
			s.pos++
			if s.pos >= len(s.data) {
				return 0, 0, false, s.syntax("unexpected end of JSON input inside a string")
			}
			switch s.data[s.pos] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				s.pos++
			case 'u':
				if s.pos+4 >= len(s.data) {
					return 0, 0, false, s.syntax("unexpected end of JSON input inside a string")
				}
				var unit rune
				for i := 1; i <= 4; i++ {
					if !isHexDigit(s.data[s.pos+i]) {
						s.pos += i
						return 0, 0, false, s.syntax("invalid character in a \\u escape")
					}
					unit = unit<<4 | rune(hexDigitValue(s.data[s.pos+i]))
				}
				s.pos += 5
				if s.limits.strictText {
					if err := s.surrogate(unit); err != nil {
						return 0, 0, false, err
					}
				}
			default:
				return 0, 0, false, s.syntax("invalid escape in a string")
			}
		case c < 0x20:
			return 0, 0, false, s.syntax("control character in a string")
		case c >= 0x80:
			special = true
			if s.limits.strictText {
				if r, size := utf8.DecodeRune(s.data[s.pos:]); r == utf8.RuneError && size <= 1 {
					return 0, 0, false, s.syntax("invalid UTF-8 in a string: a report is Unicode text")
				} else {
					s.pos += size
					continue
				}
			}
			s.pos++
		default:
			s.pos++
		}
	}
}

// surrogate checks the \u escape of unit, just read: a high surrogate must be
// followed at once by the \u escape of a low one (together they spell one
// character), and a low surrogate must follow a high one, which the case below
// consumes. Half of a pair spells no character, and encoding/json would read it
// as U+FFFD.
func (s *jsonScan) surrogate(unit rune) error {
	switch {
	case unit >= 0xD800 && unit <= 0xDBFF:
		next := s.pos
		if next+6 <= len(s.data) && s.data[next] == '\\' && s.data[next+1] == 'u' &&
			isHexDigit(s.data[next+2]) && isHexDigit(s.data[next+3]) && isHexDigit(s.data[next+4]) && isHexDigit(s.data[next+5]) {
			low := rune(hexDigitValue(s.data[next+2]))<<12 | rune(hexDigitValue(s.data[next+3]))<<8 | rune(hexDigitValue(s.data[next+4]))<<4 | rune(hexDigitValue(s.data[next+5]))
			if low >= 0xDC00 && low <= 0xDFFF {
				s.pos += 6
				return nil
			}
		}
		return s.syntax("a \\u escape holds half of a surrogate pair (a high surrogate with no low one after it), which spells no character")
	case unit >= 0xDC00 && unit <= 0xDFFF:
		return s.syntax("a \\u escape holds half of a surrogate pair (a low surrogate with no high one before it), which spells no character")
	}
	return nil
}

// foldRune is the representative of r's simple case-folding orbit (see foldName).
func foldRune(r rune) rune {
	smallest := r
	for f := unicode.SimpleFold(r); ; f = unicode.SimpleFold(f) {
		if f >= 'a' && f <= 'z' {
			return f
		}
		if f < smallest {
			smallest = f
		}
		if f == r {
			break
		}
	}
	return smallest
}

// hexDigitValue is the value of a hexadecimal digit (isHexDigit is true of it).
func hexDigitValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return int(c-'A') + 10
}

// foldName is the key under which two names that differ only by case folding
// collide: the name itself when it is plain lower-case ASCII (nearly every
// member name, and no allocation), else each character replaced by its
// representative in its simple case-folding orbit (the relation strings.EqualFold,
// and so the decoder, uses: K, k and the Kelvin sign are one character; so are s
// and the long s). The representative is the orbit's ASCII lower-case letter
// when it has one, so that it agrees with the plain case, else its smallest.
func foldName(name []byte) []byte {
	plain := true
	for _, c := range name {
		if c >= utf8.RuneSelf || (c >= 'A' && c <= 'Z') {
			plain = false
			break
		}
	}
	if plain {
		return name
	}
	folded := make([]byte, 0, len(name))
	for len(name) > 0 {
		r, size := utf8.DecodeRune(name)
		name = name[size:]
		folded = utf8.AppendRune(folded, foldRune(r))
	}
	return folded
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// unquoteKey returns the name spelled by the string bytes data[lo:hi], exactly
// as encoding/json reads it (escapes resolved, invalid UTF-8 replaced), so two
// spellings of one name compare equal. The common case, a plain ASCII name, is
// the bytes themselves and allocates nothing.
func (s *jsonScan) unquoteKey(lo, hi int, special bool) []byte {
	if !special {
		return s.data[lo:hi]
	}
	var name string
	if err := json.Unmarshal(s.data[lo-1:hi+1], &name); err != nil {
		return s.data[lo:hi] // not reached: the string was validated
	}
	return []byte(name)
}

func (s *jsonScan) number() error {
	start := s.pos
	if s.data[s.pos] == '-' {
		s.pos++
	}
	if s.pos >= len(s.data) {
		return s.syntax("invalid number")
	}
	intDigits := 0
	switch c := s.data[s.pos]; {
	case c == '0':
		s.pos++
		intDigits = 1
	case c >= '1' && c <= '9':
		for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
			s.pos++
			intDigits++
		}
	default:
		return s.syntax("invalid number")
	}
	exponent := false
	if s.pos < len(s.data) && s.data[s.pos] == '.' {
		s.pos++
		if !s.digits() {
			return s.syntax("invalid number: no digit after the decimal point")
		}
	}
	if s.pos < len(s.data) && (s.data[s.pos] == 'e' || s.data[s.pos] == 'E') {
		exponent = true
		s.pos++
		if s.pos < len(s.data) && (s.data[s.pos] == '+' || s.data[s.pos] == '-') {
			s.pos++
		}
		if !s.digits() {
			return s.syntax("invalid number: no digit in the exponent")
		}
	}
	// Only a number that could reach 2^53, or is spelled with an exponent, is
	// converted: fifteen digits or fewer cannot.
	if s.limits.numbers && (exponent || intDigits >= 16) {
		if problem := numberProblem(s.data[start:s.pos]); problem != "" {
			return fmt.Errorf("%s at %s", problem, s.pathString())
		}
	}
	return nil
}

func (s *jsonScan) digits() bool {
	start := s.pos
	for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
		s.pos++
	}
	return s.pos > start
}

// numberProblem says why a number cannot be signed exactly, or "" (see
// maxSignedInteger).
func numberProblem(token []byte) string {
	f, err := strconv.ParseFloat(string(token), 64)
	if err != nil {
		return "a number that cannot be represented as an IEEE-754 double, which RFC 8785 canonicalization requires,"
	}
	if math.Abs(f) >= maxSignedInteger && f == math.Trunc(f) {
		return "an integer of 2^53 or more cannot be signed exactly: RFC 8785 canonicalization rounds it to an IEEE-754 double, so a different integer with the same double would carry the same signature; store it as a string,"
	}
	return ""
}

// keySet holds the member names of one object, to find a repeat. The names of
// the first 32 members, nearly every object, are kept in the set itself and
// searched linearly, so scanning them allocates nothing; a larger object moves
// to a map.
type keySet struct {
	small [32][]byte
	count int
	big   map[string]struct{}
}

// add records name and reports whether it was already there.
func (k *keySet) add(name []byte) (duplicate bool) {
	if k.big != nil {
		if _, duplicate = k.big[string(name)]; duplicate {
			return true
		}
		k.big[string(name)] = struct{}{}
		return false
	}
	for _, seen := range k.small[:k.count] {
		if bytes.Equal(seen, name) {
			return true
		}
	}
	if k.count < len(k.small) {
		k.small[k.count] = name
		k.count++
		return false
	}
	k.big = make(map[string]struct{}, 2*len(k.small))
	for _, seen := range k.small {
		k.big[string(seen)] = struct{}{}
	}
	k.big[string(name)] = struct{}{}
	k.small, k.count = [32][]byte{}, 0
	return false
}

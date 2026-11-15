// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package ldapdn parses distinguished names in the string representation of
// RFC 4514 and compares them the way a directory client must: by what they
// name, not by how they are spelled. One parser serves the plan validator
// (which must refuse a DN no server would accept) and the LDAP prober (which
// must compare the DN it asked for with the one a server returns).
//
// Beyond RFC 4514, spaces around the separators "," "+" and "=" are ignored,
// as RFC 2253 and Active Directory's own tools allow; everything else follows
// the grammar: an escape is a backslash and one of the special characters or
// two hexadecimal digits, and the characters that must be escaped in a value
// are rejected unescaped.
//
// Equality compares attribute types case-insensitively by name (an OID and
// the name it stands for are different spellings of one type that only the
// server's schema can equate, so they compare unequal), decodes every escape,
// compares string values case-insensitively without the schema's finer
// matching rules (multiple internal spaces are not collapsed), compares a
// #hexstring value by its octets, and treats the assertions of one
// multi-valued RDN as an unordered set.
package ldapdn

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxLength is the longest DN, in bytes, a plan may carry. It is far above any
// real directory's DNs and keeps every request the probe builds small.
const MaxLength = 1024

// AVA is one attribute type and value assertion.
type AVA struct {
	Type  string // a descriptor lower-cased, or a numeric OID as written
	Value []byte // the value with its escapes decoded; a #hexstring's octets
	Hex   bool   // the value was written as a #hexstring
}

// RDN is a relative distinguished name: one or more assertions joined by "+".
type RDN []AVA

// DN is a distinguished name, its RDNs from the entry up to the root. The
// empty DN, which names the Root DSE, has no RDNs.
type DN []RDN

// Parse reads s as a distinguished name. The error says what is wrong and
// where, and never repeats the whole DN.
func Parse(s string) (DN, error) {
	if len(s) > MaxLength {
		return nil, fmt.Errorf("is %d bytes long, and at most %d are accepted", len(s), MaxLength)
	}
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("is not valid UTF-8")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return nil, fmt.Errorf("has a control character at byte %d", i)
		}
	}
	if s == "" {
		return nil, nil
	}
	p := &parser{s: s}
	dn := DN{}
	for {
		rdn, err := p.rdn()
		if err != nil {
			return nil, err
		}
		dn = append(dn, rdn)
		p.spaces()
		if p.i == len(s) {
			return dn, nil
		}
		if s[p.i] != ',' {
			return nil, fmt.Errorf("has %q at byte %d, where a comma or the end was expected", s[p.i], p.i)
		}
		p.i++
	}
}

// Valid reports why s is not a distinguished name, or returns nil.
func Valid(s string) error {
	_, err := Parse(s)
	return err
}

// Equal reports whether a and b are the same distinguished name. A string that
// is not a DN is equal to nothing, itself included.
func Equal(a, b string) bool {
	x, err := Parse(a)
	if err != nil {
		return false
	}
	y, err := Parse(b)
	return err == nil && x.Canonical() == y.Canonical()
}

// Canonical returns a string that is the same for exactly the DNs Equal
// treats as the same, for comparing and for keying a set.
func (d DN) Canonical() string {
	rdns := make([]string, len(d))
	for i, rdn := range d {
		avas := make([]string, len(rdn))
		for j, ava := range rdn {
			if ava.Hex {
				avas[j] = ava.Type + "=#" + hex.EncodeToString(ava.Value)
			} else {
				avas[j] = ava.Type + "=" + strconv.Quote(strings.ToLower(string(ava.Value)))
			}
		}
		slices.Sort(avas)
		rdns[i] = strings.Join(avas, "+")
	}
	return strings.Join(rdns, ",")
}

type parser struct {
	s string
	i int
}

func (p *parser) spaces() {
	for p.i < len(p.s) && p.s[p.i] == ' ' {
		p.i++
	}
}

func (p *parser) rdn() (RDN, error) {
	var rdn RDN
	for {
		ava, err := p.ava()
		if err != nil {
			return nil, err
		}
		rdn = append(rdn, ava)
		p.spaces()
		if p.i < len(p.s) && p.s[p.i] == '+' {
			p.i++
			continue
		}
		return rdn, nil
	}
}

func (p *parser) ava() (AVA, error) {
	p.spaces()
	typ, err := p.attributeType()
	if err != nil {
		return AVA{}, err
	}
	p.spaces()
	if p.i >= len(p.s) || p.s[p.i] != '=' {
		return AVA{}, fmt.Errorf("has the attribute type %q at byte %d with no '=' and value after it", typ, p.i-len(typ))
	}
	p.i++
	p.spaces()
	value, isHex, err := p.value(typ)
	if err != nil {
		return AVA{}, err
	}
	return AVA{Type: typ, Value: value, Hex: isHex}, nil
}

// attributeType reads a descriptor (ALPHA *(ALPHA / DIGIT / "-")) or a numeric
// OID (number 1*("." number), no leading zeros), RFC 4514 section 3.
func (p *parser) attributeType() (string, error) {
	start := p.i
	if p.i >= len(p.s) {
		return "", fmt.Errorf("ends where an attribute type was expected at byte %d (an empty RDN, or a comma or plus sign with nothing after it)", start)
	}
	switch c := p.s[p.i]; {
	case isAlpha(c):
		for p.i < len(p.s) && (isAlpha(p.s[p.i]) || isDigit(p.s[p.i]) || p.s[p.i] == '-') {
			p.i++
		}
		return strings.ToLower(p.s[start:p.i]), nil
	case isDigit(c):
		for p.i < len(p.s) && (isDigit(p.s[p.i]) || p.s[p.i] == '.') {
			p.i++
		}
		oid := p.s[start:p.i]
		parts := strings.Split(oid, ".")
		valid := len(parts) >= 2
		for _, part := range parts {
			valid = valid && part != "" && (part == "0" || part[0] != '0')
		}
		if !valid {
			return "", fmt.Errorf("has %q at byte %d, which is neither an attribute name nor a numeric OID such as 2.5.4.3", oid, start)
		}
		return oid, nil
	default:
		return "", fmt.Errorf("has %q at byte %d, where an attribute type was expected (an empty RDN, or a comma or plus sign with nothing after it)", p.s[p.i], p.i)
	}
}

// value reads an attribute value: a #hexstring or a string in which
// a backslash escapes one special character or introduces two hexadecimal
// digits (one octet of the UTF-8 encoding).
func (p *parser) value(typ string) ([]byte, bool, error) {
	if p.i < len(p.s) && p.s[p.i] == '#' {
		p.i++
		start := p.i
		for p.i < len(p.s) && isHex(p.s[p.i]) {
			p.i++
		}
		digits := p.s[start:p.i]
		if digits == "" || len(digits)%2 != 0 {
			return nil, false, fmt.Errorf("has a #hexstring for %q at byte %d that is empty or has an odd number of hexadecimal digits", typ, start-1)
		}
		p.spaces()
		if p.i < len(p.s) && p.s[p.i] != ',' && p.s[p.i] != '+' {
			return nil, false, fmt.Errorf("has %q at byte %d after the #hexstring for %q", p.s[p.i], p.i, typ)
		}
		octets, _ := hex.DecodeString(digits)
		return octets, true, nil
	}
	var value []byte
	significant := 0 // the length of value up to its last byte that is not a trailing space
scan:
	for p.i < len(p.s) {
		switch c := p.s[p.i]; c {
		case ',', '+':
			break scan
		case '\\':
			if p.i+1 >= len(p.s) {
				return nil, false, fmt.Errorf("ends with a backslash that escapes nothing, in the value of %q", typ)
			}
			next := p.s[p.i+1]
			if isHex(next) {
				if p.i+2 >= len(p.s) || !isHex(p.s[p.i+2]) {
					return nil, false, fmt.Errorf("has \\%c at byte %d, which is neither two hexadecimal digits nor an escaped special character", next, p.i)
				}
				octet, _ := hex.DecodeString(p.s[p.i+1 : p.i+3])
				value = append(value, octet[0])
				p.i += 3
			} else if strings.IndexByte(`"+,;<>#=\ `, next) >= 0 {
				value = append(value, next)
				p.i += 2
			} else {
				return nil, false, fmt.Errorf("has \\%c at byte %d, which is not an escape RFC 4514 defines", next, p.i)
			}
			significant = len(value)
		case '"', ';', '<', '>':
			return nil, false, fmt.Errorf("has %q at byte %d in the value of %q, where RFC 4514 requires it escaped as \\%c", c, p.i, typ, c)
		case ' ':
			value = append(value, c)
			p.i++
		default:
			value = append(value, c)
			p.i++
			significant = len(value)
		}
	}
	value = value[:significant]
	if len(value) == 0 {
		return nil, false, fmt.Errorf("has no value for %q at byte %d", typ, p.i)
	}
	if !utf8.Valid(value) {
		return nil, false, fmt.Errorf("has a value for %q whose escapes do not decode to valid UTF-8", typ)
	}
	return value, false, nil
}

func isAlpha(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isDigit(c byte) bool { return '0' <= c && c <= '9' }
func isHex(c byte) bool   { return isDigit(c) || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' }

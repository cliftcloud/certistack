// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package ldapdn

import (
	"strings"
	"testing"
)

// Malformed DNs a conforming parser must refuse, each with what it says is
// wrong.
func TestParseRejectsMalformedDistinguishedNames(t *testing.T) {
	for _, tc := range []struct{ name, dn, want string }{
		{"not a DN", "not-a-distinguished-name", "no '=' and value"},
		{"dangling escape", `CN=broken\`, "backslash that escapes nothing"},
		{"plus with no assertion after it", "CN=value+", "attribute type was expected"},
		{"plus before an assertion", "+CN=value", "attribute type was expected"},
		{"empty RDN", "DC=a,,DC=b", "attribute type was expected"},
		{"leading comma", ",DC=a", "attribute type was expected"},
		{"trailing comma", "DC=a,", "attribute type was expected"},
		{"only spaces", "   ", "attribute type was expected"},
		{"no value", "CN=,DC=a", "no value"},
		{"space value", "CN=  ,DC=a", "no value"},
		{"invalid escape", `CN=a\zb`, "not an escape"},
		{"half a hex escape", `CN=a\4`, "neither two hexadecimal digits"},
		{"hex escape with a non-hex digit", `CN=a\4g`, "neither two hexadecimal digits"},
		{"unescaped semicolon", "CN=a;b,DC=x", "requires it escaped"},
		{"unescaped less-than", "CN=a<b", "requires it escaped"},
		{"unescaped greater-than", "CN=a>b", "requires it escaped"},
		{"unescaped double quote", `CN="Smith",DC=x`, "requires it escaped"},
		{"type starting with a digit", "1cn=x", "neither an attribute name nor a numeric OID"},
		{"single-component OID", "1=x", "neither an attribute name nor a numeric OID"},
		{"OID with a leading zero", "1.02.3=x", "neither an attribute name nor a numeric OID"},
		{"OID ending in a dot", "1.2.=x", "neither an attribute name nor a numeric OID"},
		{"type with an underscore", "c_n=x", "no '=' and value"},
		{"type starting with a hyphen", "-cn=x", "attribute type was expected"},
		{"attribute option", "cn;lang-en=x", "no '=' and value"},
		{"empty hexstring", "CN=#", "#hexstring"},
		{"odd hexstring", "CN=#abc", "#hexstring"},
		{"non-hex hexstring", "CN=#zz", "#hexstring"},
		{"text after a hexstring", "CN=#0403616263 x", "after the #hexstring"},
		{"escapes that are not UTF-8", `CN=\ff\fe`, "valid UTF-8"},
		{"control character", "CN=a\nb", "control character at byte 4"},
		{"NUL", "CN=a\x00b", "control character"},
		{"invalid UTF-8", "CN=a\xffb", "not valid UTF-8"},
		{"too long", "CN=" + strings.Repeat("a", MaxLength), "at most 1024"},
		{"a 65,538-byte base", "dc=" + strings.Repeat("a", 65535), "at most 1024"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.dn)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse error = %v, want one mentioning %q", err, tc.want)
			}
			if len(tc.dn) > 64 && strings.Contains(err.Error(), tc.dn) {
				t.Fatalf("error repeats the whole DN")
			}
			if Equal(tc.dn, tc.dn) {
				t.Fatalf("%q, which is not a DN, is equal to itself", tc.dn)
			}
		})
	}
}

// Every DN a directory returns, in the spellings servers use.
func TestParseAcceptsRealDistinguishedNames(t *testing.T) {
	for _, dn := range []string{
		"",
		"DC=example,DC=com",
		"dc=example, dc=com",
		"dc = example , dc = com",
		"CN=Smith\\, John,OU=Sales,DC=example,DC=com",
		"CN=Smith\\2C John,OU=Sales,DC=example,DC=com",
		"CN=J. Smith+OU=Sales,DC=example,DC=com",
		"CN=Andr\\C3\\A9,DC=example,DC=com",
		"CN=André,DC=example,DC=com",
		"CN=日本語,DC=example,DC=com",
		"CN=a=b,DC=example",
		"CN=a#b,DC=example",
		"CN=\\#lead,DC=example",
		"CN=\\ lead\\ ,DC=example",
		"CN=a\\;b\\<c\\>d\\\"e\\\\f\\+g,DC=example",
		"2.5.4.3=#0403616263,DC=example",
		"CN=Users,CN=Configuration,DC=CertiStack,DC=Test",
		"cn=x-y1,dc=example",
		"CN=" + strings.Repeat("a", MaxLength-3),
	} {
		if err := Valid(dn); err != nil {
			t.Errorf("Valid(%q): %v", dn, err)
		}
	}
}

// Pairs that are forms of one DN, which a string normalization would compare
// as different, and the other spellings that name the same entry.
func TestEqualComparesWhatTheDNNames(t *testing.T) {
	for _, pair := range [][2]string{
		{`OU=Smith\2C John,DC=example,DC=com`, `OU=Smith\, John,DC=example,DC=com`},
		{`CN=J. Smith+OU=Sales,DC=example,DC=com`, `OU=Sales+CN=J. Smith,DC=example,DC=com`},
		{"DC=example,DC=com", "dc=EXAMPLE,dc=Com"},
		{"dc=example, dc=com", "dc = example ,dc= com"},
		{`CN=Andr\C3\A9,DC=x`, `CN=André,DC=x`},
		{`CN=Andr\c3\a9,DC=x`, `cn=ANDRÉ,dc=x`},
		{`cn=\ lead,dc=x`, `cn=\20lead,dc=x`},
		{`cn=a\+sn=b,dc=x`, `cn=a\2Bsn=b,dc=x`},
		{"cn=a+sn=b+ou=c,dc=x", "ou=c+cn=a+sn=b,dc=x"},
		{"2.5.4.3=#0403616263,dc=x", "2.5.4.3=#0403616263 , dc=x"},
		{"2.5.4.3=#0403ABcd,dc=x", "2.5.4.3=#0403abCD,dc=x"},
		{"cn=a,cn=a,dc=x", "CN=A,cn=a,dc=x"},
		{"", ""},
	} {
		if !Equal(pair[0], pair[1]) || !Equal(pair[1], pair[0]) {
			t.Errorf("%q and %q name the same entry but compare different", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{
		{"dc=example,dc=com", "dc=example,dc=org"},
		{"dc=example,dc=com", "dc=com,dc=example"},
		{"dc=example,dc=com", "dc=example"},
		{"dc=example,dc=com", ""},
		{`cn=a\,b,dc=x`, "cn=a,cn=b,dc=x"},
		{`cn=a\+sn=b,dc=x`, "cn=a+sn=b,dc=x"},
		{`cn=\ lead,dc=x`, "cn=lead,dc=x"},
		{"cn=a,dc=x", "sn=a,dc=x"},
		{"cn=a,dc=x", "2.5.4.3=a,dc=x"}, // only the schema equates a name and its OID
		{"cn=a+sn=b,dc=x", "cn=a,dc=x"},
		{"cn=a+sn=b,dc=x", "cn=a+sn=c,dc=x"},
		{"cn=ab,dc=x", "cn=#6162,dc=x"}, // a #hexstring is not compared as a string
		{"2.5.4.3=#0403616263,dc=x", "2.5.4.3=#0403616264,dc=x"},
		{"cn=a,dc=x", "not a dn"},
		{"not a dn", "not a dn"},
	} {
		if Equal(pair[0], pair[1]) || Equal(pair[1], pair[0]) {
			t.Errorf("%q and %q are different names but compare equal", pair[0], pair[1])
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ldapBindSuccess is an ordinary BindResponse: message ID 1, success, empty
// matchedDN and diagnosticMessage.
var ldapBindSuccess = ldapBindWithCode(0)

func ldapBindWithCode(code int) []byte {
	return ldapBindResponse(1, ldapResultFields(code))
}

// ldapResultFields encodes the components of an LDAPResult: resultCode,
// matchedDN and diagnosticMessage (both empty), then any extra elements.
func ldapResultFields(code int, extra ...[]byte) []byte {
	fields := append(ldapIntegerTLV(0x0a, code), ldapTLV(0x04, nil)...)
	fields = append(fields, ldapTLV(0x04, nil)...)
	for _, element := range extra {
		fields = append(fields, element...)
	}
	return fields
}

func ldapBindResponse(messageID int, body []byte, controls ...byte) []byte {
	return ldapTLV(0x30, append(append(ldapIntegerTLV(0x02, messageID), ldapTLV(0x61, body)...), controls...))
}

func ldapDonePacket(messageID int, body []byte) []byte {
	return ldapTLV(0x30, append(ldapIntegerTLV(0x02, messageID), ldapTLV(0x65, body)...))
}

// serveLDAPBind answers the anonymous bind with bind and then every request
// with answer(request, its message ID), until the probe hangs up.
func serveLDAPBind(t *testing.T, bind []byte, answer func(request []byte, messageID int) []byte) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := readLDAPMessage(conn); err != nil {
			return
		}
		_, _ = conn.Write(bind)
		if answer == nil {
			return // nothing but the bind is expected
		}
		for {
			request, err := readLDAPMessage(conn)
			if err != nil {
				return
			}
			messageID, _, _ := ldapMessageEnvelope(request)
			_, _ = conn.Write(answer(request, messageID))
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// serveLDAP answers one anonymous bind with success and then every request
// with answer(request, its message ID), until the probe hangs up.
func serveLDAP(t *testing.T, answer func(request []byte, messageID int) []byte) int {
	return serveLDAPBind(t, ldapBindSuccess, answer)
}

func ldapSearchReferencePacket(messageID int, uri string) []byte {
	return ldapTLV(0x30, append(ldapIntegerTLV(0x02, messageID), ldapTLV(0x73, ldapTLV(0x04, []byte(uri)))...))
}

// A successful base-object search is evidence of the object only
// when it returns that object's entry. The reporter's three responses (success
// with no entry, the same after base_dn: auto discovery, and success with an
// unrelated entry) each used to report the requested search verified.
func TestLDAPProberBaseObjectRequiresTheRequestedEntry(t *testing.T) {
	const requestedDN = "dc=required,dc=test"
	for _, tc := range []struct {
		name, baseDN, want string
		search             func(messageID int) []byte
	}{
		{"explicit, no entry", requestedDN, "returned no entry for it", func(id int) []byte {
			return ldapSearchResultDonePacket(id, 0)
		}},
		{"auto, no entry for the advertised context", "auto", "returned no entry for it", func(id int) []byte {
			return ldapSearchResultDonePacket(id, 0)
		}},
		{"explicit, unrelated entry", requestedDN, `entry for "dc=unrelated,dc=test" instead of the requested base object`, func(id int) []byte {
			return append(ldapObjectEntryPacket(id, "dc=unrelated,dc=test"), ldapSearchResultDonePacket(id, 0)...)
		}},
		{"explicit, the entry and an unrelated one", requestedDN, `entry for "dc=unrelated,dc=test"`, func(id int) []byte {
			entries := append(ldapObjectEntryPacket(id, requestedDN), ldapObjectEntryPacket(id, "dc=unrelated,dc=test")...)
			return append(entries, ldapSearchResultDonePacket(id, 0)...)
		}},
		{"explicit, a referral only", requestedDN, "returned no entry for it", func(id int) []byte {
			return append(ldapSearchReferencePacket(id, "ldap://other.test/dc=required,dc=test"), ldapSearchResultDonePacket(id, 0)...)
		}},
		{"explicit, the entry for another request", requestedDN, "returned no entry for it", func(id int) []byte {
			return append(ldapObjectEntryPacket(id+1, requestedDN), ldapSearchResultDonePacket(id, 0)...)
		}},
		{"explicit, a malformed entry", requestedDN, "malformed SearchResultEntry", func(id int) []byte {
			entry := ldapTLV(0x30, append(ldapIntegerTLV(0x02, id), ldapTLV(0x64, ldapTLV(0x04, []byte(requestedDN)))...))
			return append(entry, ldapSearchResultDonePacket(id, 0)...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := serveLDAP(t, func(request []byte, id int) []byte {
				if strings.Contains(string(request), "namingContexts") {
					return append(ldapRootDSEEntryPacket(id, requestedDN), ldapSearchResultDonePacket(id, 0)...)
				}
				if !strings.Contains(string(request), requestedDN) {
					t.Errorf("search is not for %s: %x", requestedDN, request)
				}
				return tc.search(id)
			})
			res := NewLDAPProber("127.0.0.1", port, tc.baseDN, 2*time.Second, tc.name).Probe(context.Background())
			if res.Passed || !strings.Contains(res.Error, tc.want) {
				t.Fatalf("result = %+v, want a failure mentioning %q", res, tc.want)
			}
		})
	}
}

// Control: directories return the entry's DN in their own spelling.
// Active Directory writes "DC=CertiStack,DC=Test"; the comparison ignores
// case and the spaces around separators, and accepts either escape form.
func TestLDAPProberBaseObjectAcceptsTheEntryInTheServersSpelling(t *testing.T) {
	for _, tc := range []struct{ requested, returned string }{
		{"dc=certistack, dc=test", "DC=CertiStack,DC=Test"},
		{"OU=Sales\\, EMEA,DC=certistack,DC=test", "ou=sales\\2c emea,dc=certistack,dc=test"},
	} {
		port := serveLDAP(t, func(_ []byte, id int) []byte {
			entry := ldapObjectEntryPacket(id, tc.returned, ldapAttribute{"objectClass", []string{"top", "domain", "domainDNS"}})
			return append(entry, ldapSearchResultDonePacket(id, 0)...)
		})
		res := NewLDAPProber("127.0.0.1", port, tc.requested, 2*time.Second, "AD base object").Probe(context.Background())
		if !res.Passed || !strings.Contains(res.Detail, "which returned its entry") {
			t.Fatalf("%s returned as %s: %+v", tc.requested, tc.returned, res)
		}
	}
}

// The reporter's two pairs, each a valid RFC 4514 spelling of the naming
// context the directory advertises, used to fail the Root DSE assertion. The
// third row is a different name, which still fails.
func TestLDAPProberNamingContextComparesEquivalentDNs(t *testing.T) {
	for _, tc := range []struct {
		name, configured, advertised string
		pass                         bool
	}{
		{"escaped value", `OU=Smith\2C John,DC=example,DC=com`, `OU=Smith\, John,DC=example,DC=com`, true},
		{"multi-valued RDN in another order", `CN=J. Smith+OU=Sales,DC=example,DC=com`, `OU=Sales+CN=J. Smith,DC=example,DC=com`, true},
		{"UTF-8 spelled as escapes", `CN=Andr\C3\A9,DC=example,DC=com`, `CN=André,DC=example,DC=com`, true},
		{"a different value", `OU=Smith\, Jane,DC=example,DC=com`, `OU=Smith\, John,DC=example,DC=com`, false},
		{"a different RDN in the multi-valued one", `CN=J. Smith+OU=Sales,DC=example,DC=com`, `OU=Sales+CN=J. Smyth,DC=example,DC=com`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port, _ := serveRootDSE(t, 0, ldapAttribute{"namingContexts", []string{tc.advertised}})
			prober := NewLDAPProber("127.0.0.1", port, "", 2*time.Second, tc.name)
			prober.NamingContext = tc.configured
			if res := prober.Probe(context.Background()); res.Passed != tc.pass {
				t.Fatalf("result = %+v, want pass=%v", res, tc.pass)
			}
		})
	}
}

// The Root DSE is the entry with the empty DN, and one entry. A naming
// context advertised by some other entry does not describe this directory.
// The first case is the reporter's entry.
func TestLDAPProberRootDSEMustBeOneEntryWithTheEmptyDN(t *testing.T) {
	naming := ldapAttribute{"namingContexts", []string{"DC=certistack,DC=test"}}
	for _, tc := range []struct {
		name, want string
		pass       bool
		answer     func(id int) []byte
	}{
		{"an entry for another DN", "instead of the Root DSE", false, func(id int) []byte {
			return append(ldapObjectEntryPacket(id, "CN=Not Root,DC=example,DC=com", naming), ldapSearchResultDonePacket(id, 0)...)
		}},
		{"the Root DSE and an entry for another DN", "instead of the Root DSE", false, func(id int) []byte {
			entries := append(ldapEntryPacket(id, naming), ldapObjectEntryPacket(id, "dc=other,dc=test", naming)...)
			return append(entries, ldapSearchResultDonePacket(id, 0)...)
		}},
		{"two Root DSE entries", "returned 2 entries", false, func(id int) []byte {
			entries := append(ldapEntryPacket(id, naming), ldapEntryPacket(id, naming)...)
			return append(entries, ldapSearchResultDonePacket(id, 0)...)
		}},
		{"an objectName that is not an OCTET STRING", "malformed SearchResultEntry", false, func(id int) []byte {
			entry := append(ldapTLV(0x02, nil), ldapTLV(0x30, nil)...)
			return append(ldapTLV(0x30, append(ldapIntegerTLV(0x02, id), ldapTLV(0x64, entry)...)), ldapSearchResultDonePacket(id, 0)...)
		}},
		{"an attribute that is not a type and a set of values", "malformed SearchResultEntry", false, func(id int) []byte {
			attribute := ldapTLV(0x30, ldapTLV(0x04, []byte("namingContexts"))) // no vals
			entry := append(ldapTLV(0x04, nil), ldapTLV(0x30, attribute)...)
			return append(ldapTLV(0x30, append(ldapIntegerTLV(0x02, id), ldapTLV(0x64, entry)...)), ldapSearchResultDonePacket(id, 0)...)
		}},
		{"a value that is not an OCTET STRING", "malformed SearchResultEntry", false, func(id int) []byte {
			attribute := ldapTLV(0x30, append(ldapTLV(0x04, []byte("namingContexts")), ldapTLV(0x31, ldapTLV(0x02, []byte{1}))...))
			entry := append(ldapTLV(0x04, nil), ldapTLV(0x30, attribute)...)
			return append(ldapTLV(0x30, append(ldapIntegerTLV(0x02, id), ldapTLV(0x64, entry)...)), ldapSearchResultDonePacket(id, 0)...)
		}},
		{"an operation a search never returns", "unexpected LDAP operation 0x61", false, func(id int) []byte {
			return ldapBindResponse(id, ldapResultFields(0))
		}},
		{"the Root DSE", "", true, func(id int) []byte {
			return append(ldapEntryPacket(id, naming), ldapSearchResultDonePacket(id, 0)...)
		}},
		{"the Root DSE after a referral and an unsolicited notice", "", true, func(id int) []byte {
			notice := ldapTLV(0x30, append(ldapIntegerTLV(0x02, 0), ldapTLV(0x78, ldapResultFields(52))...))
			answer := append(notice, ldapSearchReferencePacket(id, "ldap://other.test/")...)
			return append(append(answer, ldapEntryPacket(id, naming)...), ldapSearchResultDonePacket(id, 0)...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := serveLDAP(t, func(_ []byte, id int) []byte { return tc.answer(id) })
			prober := NewLDAPProber("127.0.0.1", port, "", 2*time.Second, "Root DSE")
			prober.NamingContext = "DC=certistack,DC=test"
			res := prober.Probe(context.Background())
			if res.Passed != tc.pass || (!tc.pass && !strings.Contains(res.Error, tc.want)) {
				t.Fatalf("result = %+v, want pass=%v with %q", res, tc.pass, tc.want)
			}
		})
	}
}

// An LDAPResult has three mandatory fields, and a BindResponse or a
// SearchResultDone that stops after the resultCode is not one. The first row is
// the reporter's packet; the rest are the other ways to be incomplete or to
// carry more than the RFC allows, then what real servers send. bindWant and
// searchWant are the error each response type must give ("" where it passes):
// serverSaslCreds belongs to a BindResponse alone.
func TestLDAPResultNeedsItsMandatoryFieldsInOrder(t *testing.T) {
	code := ldapIntegerTLV(0x0a, 0)
	empty := ldapTLV(0x04, nil)
	referral := ldapTLV(0xa3, ldapTLV(0x04, []byte("ldap://other.test/dc=example,dc=com")))
	credentials := ldapTLV(0x87, []byte{1, 2, 3})
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for _, tc := range []struct {
		name                 string
		body                 []byte
		bindWant, searchWant string
	}{
		{"resultCode only (the reporter's packet)", code, "missing matchedDN", "missing matchedDN"},
		{"resultCode and matchedDN", join(code, empty), "missing diagnosticMessage", "missing diagnosticMessage"},
		{"empty result", nil, "missing resultCode", "missing resultCode"},
		{"matchedDN of the wrong type", join(code, ldapTLV(0x02, []byte{0}), empty), "missing matchedDN", "missing matchedDN"},
		{"diagnosticMessage of the wrong type", join(code, empty, ldapTLV(0x0a, []byte{0})), "missing diagnosticMessage", "missing diagnosticMessage"},
		{"resultCode of the wrong type", join(ldapTLV(0x02, []byte{0}), empty, empty), "missing resultCode", "missing resultCode"},
		{"fields out of order", join(empty, code, empty), "missing resultCode", "missing resultCode"},
		{"matchedDN that is not UTF-8", join(code, ldapTLV(0x04, []byte{0xff, 0xfe}), empty), "not valid UTF-8", "not valid UTF-8"},
		{"diagnosticMessage that is not UTF-8", join(code, empty, ldapTLV(0x04, []byte{0xc3})), "not valid UTF-8", "not valid UTF-8"},
		{"an extra element", ldapResultFields(0, empty), "unexpected element (tag 0x04)", "unexpected element (tag 0x04)"},
		{"an empty referral", ldapResultFields(0, ldapTLV(0xa3, nil)), "malformed referral", "malformed referral"},
		{"a referral of another type", ldapResultFields(0, ldapTLV(0xa3, ldapTLV(0x02, []byte{1}))), "malformed referral", "malformed referral"},
		{"a referral that is not UTF-8", ldapResultFields(0, ldapTLV(0xa3, ldapTLV(0x04, []byte{0xff}))), "malformed referral", "malformed referral"},
		{"credentials before the referral", ldapResultFields(0, credentials, referral), "unexpected element (tag 0xa3)", "unexpected element (tag 0x87)"},
		{"two sets of credentials", ldapResultFields(0, credentials, credentials), "unexpected element (tag 0x87)", "unexpected element (tag 0x87)"},
		{"empty strings, as every server sends them", ldapResultFields(0), "", ""},
		{"a diagnostic message, as Active Directory sends one", join(code, empty, ldapTLV(0x04, []byte("80090308: LdapErr: DSID-0C09030B, comment: AcceptSecurityContext error, data 52e, v3839\x00"))), "", ""},
		{"a matchedDN", join(code, ldapTLV(0x04, []byte("dc=example,dc=com")), empty), "", ""},
		{"a referral", ldapResultFields(0, referral), "", ""},
		{"server credentials", ldapResultFields(0, credentials), "", "unexpected element (tag 0x87)"},
		{"a referral and server credentials", ldapResultFields(0, referral, credentials), "", "unexpected element (tag 0x87)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Through the actual listener-only probe: a BindResponse.
			bindPort := serveLDAPBind(t, ldapBindResponse(1, tc.body), nil)
			bindRes := NewLDAPProber("127.0.0.1", bindPort, "", 2*time.Second, tc.name).Probe(context.Background())
			if bindRes.Passed != (tc.bindWant == "") || !strings.Contains(bindRes.Error, tc.bindWant) {
				t.Errorf("BindResponse: result = %+v, want %q", bindRes, tc.bindWant)
			}
			// And the search that supports a Root DSE assertion: a SearchResultDone.
			donePort := serveLDAP(t, func(_ []byte, id int) []byte {
				return append(ldapEntryPacket(id, ldapAttribute{"namingContexts", []string{"DC=example,DC=com"}}), ldapDonePacket(id, tc.body)...)
			})
			prober := NewLDAPProber("127.0.0.1", donePort, "", 2*time.Second, tc.name)
			prober.NamingContext = "DC=example,DC=com"
			searchRes := prober.Probe(context.Background())
			if searchRes.Passed != (tc.searchWant == "") || !strings.Contains(searchRes.Error, tc.searchWant) {
				t.Errorf("SearchResultDone: result = %+v, want %q", searchRes, tc.searchWant)
			}
		})
	}
}

// The protocol operation may be followed by the message's controls and by
// nothing else.
func TestLDAPMessageAllowsOnlyControlsAfterTheOperation(t *testing.T) {
	controls := ldapTLV(0xa0, ldapTLV(0x30, ldapTLV(0x04, []byte("1.2.840.113556.1.4.319"))))
	for name, tc := range map[string]struct {
		bind []byte
		pass bool
	}{
		"controls":                {ldapBindResponse(1, ldapResultFields(0), controls...), true},
		"another element":         {ldapBindResponse(1, ldapResultFields(0), ldapTLV(0x04, []byte("x"))...), false},
		"controls, then another":  {ldapBindResponse(1, ldapResultFields(0), append(controls, ldapTLV(0xa0, nil)...)...), false},
		"message ID above 127":    {ldapBindResponse(200, ldapResultFields(0)), false}, // not the ID of the request
		"a negative message ID":   {ldapTLV(0x30, append(ldapTLV(0x02, []byte{0xff}), ldapTLV(0x61, ldapResultFields(0))...)), false},
		"no protocol operation":   {ldapTLV(0x30, ldapIntegerTLV(0x02, 1)), false},
		"outer element not a SEQ": {ldapTLV(0x31, append(ldapIntegerTLV(0x02, 1), ldapTLV(0x61, ldapResultFields(0))...)), false},
	} {
		t.Run(name, func(t *testing.T) {
			port := serveLDAPBind(t, tc.bind, nil)
			if res := NewLDAPProber("127.0.0.1", port, "", 2*time.Second, name).Probe(context.Background()); res.Passed != tc.pass {
				t.Fatalf("result = %+v, want pass=%v", res, tc.pass)
			}
		})
	}
}

// With no base assertion the probe proves an LDAP v3 server answered
// the handshake, and a directory that refuses the anonymous bind by policy
// answered it as much as one that accepted it. Signing-required (8) and
// disallowed-anonymous (48) are the same case here as in the Root DSE
// assertion; any other failure is not.
func TestLDAPProberListenerAcceptsAPolicyRefusalOfTheBind(t *testing.T) {
	for _, tc := range []struct {
		code int
		pass bool
		want string
	}{
		{0, true, "verified (resultCode: 0)"},
		{8, true, "refused the anonymous bind by policy (strongAuthRequired (resultCode 8))"},
		{48, true, "refused the anonymous bind by policy (inappropriateAuthentication (resultCode 48))"},
		{2, false, "failed with resultCode 2"},
		{7, false, "failed with resultCode 7"},
		{49, false, "failed with resultCode 49"},
		{53, false, "failed with resultCode 53"},
	} {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			port := serveLDAPBind(t, ldapBindWithCode(tc.code), nil)
			res := NewLDAPProber("127.0.0.1", port, "", 2*time.Second, "listener").Probe(context.Background())
			text := res.Detail
			if !tc.pass {
				text = res.Error
			}
			if res.Passed != tc.pass || !strings.Contains(text, tc.want) {
				t.Fatalf("bind result %d = %+v, want pass=%v with %q", tc.code, res, tc.pass, tc.want)
			}
		})
	}
	// An assertion of directory data needs the bind to have succeeded.
	port := serveLDAPBind(t, ldapBindWithCode(8), func(_ []byte, id int) []byte {
		t.Errorf("a search was sent after the bind was refused")
		return ldapSearchResultDonePacket(id, 0)
	})
	if res := NewLDAPProber("127.0.0.1", port, "dc=example,dc=com", time.Second, "search").Probe(context.Background()); res.Passed || !strings.Contains(res.Error, "failed with resultCode 8") {
		t.Fatalf("base search after a refused bind = %+v", res)
	}
}

// A base_dn or naming_context that is not a DN is refused before a
// byte is sent, and the request that carries a DN is framed correctly at
// every length, so it can never declare a length other than its own.
func TestLDAPProberRefusesADNItCannotSend(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var connections atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	for _, tc := range []struct{ name, baseDN, namingContext string }{
		{"not a DN", "not-a-distinguished-name", ""},
		{"65,538 bytes", "dc=" + strings.Repeat("a", 65535), ""},
		{"a dangling escape", "", `CN=broken\`},
		{"a plus with no assertion after it", "", "CN=value+"},
	} {
		prober := NewLDAPProber("127.0.0.1", port, tc.baseDN, time.Second, tc.name)
		prober.NamingContext = tc.namingContext
		if res := prober.Probe(context.Background()); res.Passed || !strings.Contains(res.Error, "is not a valid distinguished name") {
			t.Errorf("%s: result = %+v", tc.name, res)
		}
	}
	if n := connections.Load(); n != 0 {
		t.Fatalf("%d connections were made for DNs that cannot be sent", n)
	}
}

func TestLDAPRequestsAreFramedAtEveryLength(t *testing.T) {
	for _, length := range []int{0, 1, 127, 128, 255, 256, 1024, 65535, 65536, 70000} {
		value := bytes.Repeat([]byte{'x'}, length)
		encoded := ldapTLV(0x04, value)
		elements, err := ldapBERElements(encoded)
		if err != nil || len(elements) != 1 || elements[0].tag != 0x04 || len(elements[0].value) != length {
			t.Fatalf("a %d-byte element decodes as %d elements (%v), want one of %d bytes", length, len(elements), err, length)
		}
	}
	// The reporter's 65,538-byte base: the whole request is one element whose
	// declared length is its actual length.
	packet := ldapSearchRequestPacket(2, "dc="+strings.Repeat("a", 65535), nil)
	elements, err := ldapBERElements(packet)
	if err != nil || len(elements) != 1 || len(packet) < 65538 {
		t.Fatalf("oversized search request decodes as %d elements (%v), %d bytes", len(elements), err, len(packet))
	}
	for _, id := range []int{1, 127, 128, 255, 256, 65535, 70000} {
		got, _, err := ldapMessageEnvelope(ldapSearchResultDonePacket(id, 0))
		if err != nil || got != id {
			t.Errorf("message ID %d encodes and decodes as %d (%v)", id, got, err)
		}
	}
}

// base_dn: auto tries every naming context the Root DSE advertises,
// in whatever order it lists them, and reports what it did not reach.
func TestLDAPProberAutoTriesEveryAdvertisedNamingContext(t *testing.T) {
	contexts := func(n int) []string {
		list := make([]string, n)
		for i := range list {
			list[i] = fmt.Sprintf("dc=context%d,dc=test", i+1)
		}
		return list
	}
	for _, tc := range []struct {
		name     string
		list     []string
		readable string // the one that returns its entry ("" for none)
		searches int32
	}{
		{"the ninth of nine, the reporter's fixture", contexts(9), "dc=context9,dc=test", 9},
		{"the eighth of nine, the reporter's control", contexts(9), "dc=context8,dc=test", 8},
		{"the last of 300, message IDs past 127", contexts(300), "dc=context300,dc=test", 300},
		{"the readable one repeated in another case", append(contexts(12), "DC=Context12,DC=Test", "dc=context12,dc=test"), "dc=context12,dc=test", 12},
		{"none of nine", contexts(9), "", 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var searches atomic.Int32
			port := serveLDAP(t, func(request []byte, id int) []byte {
				if strings.Contains(string(request), "namingContexts") {
					return append(ldapRootDSEEntryPacket(id, tc.list...), ldapSearchResultDonePacket(id, 0)...)
				}
				searches.Add(1)
				if tc.readable != "" && bytes.Contains(request, []byte(tc.readable)) {
					return append(ldapObjectEntryPacket(id, tc.readable, openLDAPBaseAttributes...), ldapSearchResultDonePacket(id, 0)...)
				}
				return ldapSearchResultDonePacket(id, 32)
			})
			res := NewLDAPProber("127.0.0.1", port, "auto", 5*time.Second, "auto").Probe(context.Background())
			if tc.readable == "" {
				if res.Passed || !strings.Contains(res.Error, "none passed a base-object search") || !strings.Contains(res.Error, "(+1 more)") {
					t.Fatalf("result = %+v", res)
				}
			} else if !res.Passed || !strings.Contains(res.Detail, "discovered base-object search "+tc.readable) {
				t.Fatalf("result = %+v", res)
			}
			if got := searches.Load(); got != tc.searches {
				t.Fatalf("%d searches sent, want %d (each distinct context once)", got, tc.searches)
			}
		})
	}
}

// A naming context that is an empty string (some servers advertise the root)
// is not searched, and one exchange that fails ends discovery: the remaining
// contexts are reported as not tried rather than asked over a connection that
// can no longer be trusted.
func TestLDAPProberAutoSkipsTheEmptyContextAndStopsAtABrokenExchange(t *testing.T) {
	var searches atomic.Int32
	port := serveLDAP(t, func(request []byte, id int) []byte {
		if strings.Contains(string(request), "namingContexts") {
			return append(ldapRootDSEEntryPacket(id, "", "dc=one,dc=test", "dc=two,dc=test", "dc=three,dc=test"), ldapSearchResultDonePacket(id, 0)...)
		}
		searches.Add(1)
		return ldapTLV(0x30, ldapIntegerTLV(0x02, id)) // an LDAPMessage with no operation
	})
	res := NewLDAPProber("127.0.0.1", port, "auto", 2*time.Second, "auto").Probe(context.Background())
	if res.Passed || !strings.Contains(res.Error, "dc=one,dc=test: parse response") || !strings.Contains(res.Error, "2 more not tried after that exchange failed") {
		t.Fatalf("result = %+v", res)
	}
	if got := searches.Load(); got != 1 {
		t.Fatalf("%d searches sent after a broken exchange, want 1", got)
	}
}

// A naming context is compared as the server sent it. A value that only equals
// the configured one after control characters or spaces were stripped is not
// that name, and is not shown with them either (audit F90).
func TestLDAPProberComparesNamingContextsAsSentAndShowsThemCleaned(t *testing.T) {
	for _, tc := range []struct {
		name, advertised string
		pass             bool
	}{
		{"as configured", "DC=certistack,DC=test", true},
		{"equivalent spelling", "dc=CertiStack, dc=test", true},
		{"a control character inside", "DC=certis\x0ack,DC=test", false},
		{"a NUL at the end", "DC=certistack,DC=test\x00", false},
		{"a newline at the end", "DC=certistack,DC=test\n", false},
		{"a trailing space, which the DN parser itself ignores", "DC=certistack,DC=test ", true},
		{"a tab before it", "\tDC=certistack,DC=test", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port, _ := serveRootDSE(t, 0, ldapAttribute{"namingContexts", []string{tc.advertised}})
			prober := NewLDAPProber("127.0.0.1", port, "", 2*time.Second, tc.name)
			prober.NamingContext = "DC=certistack,DC=test"
			res := prober.Probe(context.Background())
			if res.Passed != tc.pass {
				t.Fatalf("result = %+v, want pass=%v", res, tc.pass)
			}
			for _, field := range []string{res.Error, res.Detail} {
				if strings.ContainsAny(field, "\x00\n\t") {
					t.Fatalf("the report carries a control character from the server: %q", field)
				}
			}
		})
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"encoding/binary"
	"testing"
)

// FuzzWireReplyParsers feeds what a restored guest's service answers to every
// parser of a wire probe's reply (DNS, LDAP, TDS, SMB2): a guest is the least
// trusted thing a run talks to, and any reply either parses or is an error,
// never a panic.
func FuzzWireReplyParsers(f *testing.F) {
	query, _, err := buildDNSQuery("dc01.example.test.", dnsTypeA)
	if err != nil {
		f.Fatal(err)
	}
	reply := append([]byte(nil), query...)
	reply[2] |= 0x80
	f.Add(reply)
	f.Add(ldapTLV(0x30, append(ldapTLV(0x02, []byte{1}), ldapTLV(0x61, append(ldapTLV(0x0a, []byte{0}), append(ldapTLV(0x04, nil), ldapTLV(0x04, nil)...)...))...)))
	f.Add(tdsPreloginPacket()[tdsHeaderLen:])
	smb := make([]byte, smb2HeaderLen+smb2NegotiateRespFixed)
	copy(smb, "\xfeSMB")
	binary.LittleEndian.PutUint16(smb[4:], smb2HeaderLen)
	binary.LittleEndian.PutUint32(smb[16:], smb2FlagServerToRedir)
	binary.LittleEndian.PutUint16(smb[smb2HeaderLen:], smb2NegotiateRespSize)
	binary.LittleEndian.PutUint16(smb[smb2HeaderLen+4:], smb2Dialect311)
	f.Add(smb)
	f.Fuzz(func(t *testing.T, data []byte) {
		msg := data
		if len(msg) >= 2 {
			// Most replies that do not echo the query's ID end at the first check.
			msg = append([]byte(nil), data...)
			copy(msg, query[:2])
		}
		_, _ = parseDNSReply(msg, query)
		_, _ = ldapBindResultCode(data, 1)
		if _, operation, err := ldapMessageEnvelope(data); err == nil {
			_, _ = parseLDAPSearchEntry(operation)
		}
		_, _ = parseLDAPResult(data, false)
		_, _ = parseLDAPResult(data, true)
		_, _, _ = parseTDSPrelogin(data)
		_, _, _ = parseSMBNegotiateResponse(data)
		_ = sanitizeLDAPContext(data)
	})
}

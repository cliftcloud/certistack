// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// smbRequestDialects returns the dialects a NEGOTIATE request offers.
func smbRequestDialects(t *testing.T, request []byte) []uint16 {
	t.Helper()
	body := request[smb2HeaderLen:]
	count := int(binary.LittleEndian.Uint16(body[2:]))
	if len(body) < smb2NegotiateReqSize+2*count {
		t.Fatalf("NEGOTIATE body has %d bytes, too few for %d dialects", len(body), count)
	}
	dialects := make([]uint16, count)
	for i := range dialects {
		dialects[i] = binary.LittleEndian.Uint16(body[smb2NegotiateReqSize+2*i:])
	}
	return dialects
}

// smbRequestContexts checks a NEGOTIATE request that offers SMB 3.1.1 against
// MS-SMB2 2.2.3 the way a server does, and returns its negotiate contexts by
// type. The offsets count from the start of the SMB2 header.
func smbRequestContexts(t *testing.T, request []byte) map[uint16][]byte {
	t.Helper()
	body := request[smb2HeaderLen:]
	if size := binary.LittleEndian.Uint16(body); size != smb2NegotiateReqSize {
		t.Fatalf("NEGOTIATE StructureSize %d, want %d", size, smb2NegotiateReqSize)
	}
	dialects := smbRequestDialects(t, request)
	offset, count := int(binary.LittleEndian.Uint32(body[28:])), int(binary.LittleEndian.Uint16(body[32:]))
	if reserved := binary.LittleEndian.Uint16(body[34:]); reserved != 0 {
		t.Errorf("Reserved2 is %d, want 0", reserved)
	}
	if offset%8 != 0 || offset < smb2HeaderLen+smb2NegotiateReqSize+2*len(dialects) {
		t.Fatalf("NegotiateContextOffset %d is not an 8-byte aligned place after the dialects", offset)
	}
	for _, padding := range request[smb2HeaderLen+smb2NegotiateReqSize+2*len(dialects) : offset] {
		if padding != 0 {
			t.Errorf("padding before the negotiate contexts is not zero")
		}
	}
	contexts := map[uint16][]byte{}
	for i := 0; i < count; i++ {
		if offset%8 != 0 || offset+8 > len(request) {
			t.Fatalf("negotiate context %d at offset %d is misaligned or outside the %d-byte request", i, offset, len(request))
		}
		kind, length := binary.LittleEndian.Uint16(request[offset:]), int(binary.LittleEndian.Uint16(request[offset+2:]))
		if offset+8+length > len(request) {
			t.Fatalf("negotiate context %d overruns the request", i)
		}
		contexts[kind] = request[offset+8 : offset+8+length]
		offset = (offset + 8 + length + 7) &^ 7
	}
	return contexts
}

// smbContext frames one negotiate context: type, data length, 4 reserved
// octets, and the data.
func smbContext(kind uint16, data []byte) []byte {
	context := binary.LittleEndian.AppendUint16(nil, kind)
	context = binary.LittleEndian.AppendUint16(context, uint16(len(data)))
	return append(append(context, 0, 0, 0, 0), data...)
}

// smbPreauthData is PREAUTH_INTEGRITY_CAPABILITIES data (MS-SMB2 2.2.3.1.1)
// naming the given hash algorithms and carrying a salt of saltLen octets.
func smbPreauthData(saltLen int, algorithms ...uint16) []byte {
	data := binary.LittleEndian.AppendUint16(nil, uint16(len(algorithms)))
	data = binary.LittleEndian.AppendUint16(data, uint16(saltLen))
	for _, algorithm := range algorithms {
		data = binary.LittleEndian.AppendUint16(data, algorithm)
	}
	for i := 0; i < saltLen; i++ {
		data = append(data, byte(0xa0+i))
	}
	return data
}

// smbNegotiateResponse311 frames an SMB 3.1.1 NEGOTIATE response the way
// Samba and Windows send one: the security buffer at 0x80, then the negotiate
// contexts at the next 8-byte boundary, each padded to a multiple of 8. The
// message it returns is framed for the wire, like smbNegotiateResponse's.
func smbNegotiateResponse311(securityMode uint16, contexts ...[]byte) []byte {
	message := smbNegotiateResponse(0, securityMode, smb2Dialect311)[4:]
	for len(message)%8 != 0 {
		message = append(message, 0)
	}
	contextOffset := len(message)
	for i, context := range contexts {
		message = append(message, context...)
		for i < len(contexts)-1 && len(message)%8 != 0 {
			message = append(message, 0)
		}
	}
	body := message[smb2HeaderLen:]
	binary.LittleEndian.PutUint16(body[6:], uint16(len(contexts)))
	binary.LittleEndian.PutUint32(body[60:], uint32(contextOffset))
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(message))), message...)
}

// serveSMBPolicy answers like an SMB server that supports dialects from
// minDialect through maxDialect and picks the highest one the client offers
// (MS-SMB2 3.3.5.4). One that must use 3.1.1 also requires the client's
// preauthentication integrity context, as Samba does, and answers with
// SHA-512 and its own salt.
func serveSMBPolicy(t *testing.T, minDialect, maxDialect uint16) int {
	t.Helper()
	port, _ := serveOnce(t, readSMBRequest, func(request []byte) []byte {
		var chosen uint16
		for _, dialect := range smbRequestDialects(t, request) {
			if dialect >= minDialect && dialect <= maxDialect && dialect > chosen {
				chosen = dialect
			}
		}
		switch {
		case chosen == 0:
			return smbErrorResponse(0xc00000bb) // STATUS_NOT_SUPPORTED
		case chosen != smb2Dialect311:
			return smbNegotiateResponse(0, 0x0003, chosen)
		}
		preauth, ok := smbRequestContexts(t, request)[smb2ContextPreauthIntegrity]
		if !ok || len(preauth) < 6 || binary.LittleEndian.Uint16(preauth[4:]) != smb2HashSHA512 {
			return smbErrorResponse(0xc000000d) // STATUS_INVALID_PARAMETER
		}
		return smbNegotiateResponse311(0x0003, smbContext(smb2ContextPreauthIntegrity, smbPreauthData(32, smb2HashSHA512)))
	})
	return port
}

// The request offers SMB 3.1.1 the way MS-SMB2 2.2.3 defines it: the
// dialect, the context list's offset and count in the fixed body, padding to
// an 8-byte boundary, and the mandatory preauthentication integrity context
// with a SHA-512 offer and a fresh 32-byte salt.
func TestSMBNegotiateRequestOffersSMB311Conformingly(t *testing.T) {
	first, err := smbNegotiatePacket()
	if err != nil {
		t.Fatal(err)
	}
	second, err := smbNegotiatePacket()
	if err != nil {
		t.Fatal(err)
	}
	request := first[4:]
	if length := int(binary.BigEndian.Uint32(first)); length != len(request) {
		t.Fatalf("session frame declares %d bytes, the request has %d", length, len(request))
	}
	contexts := smbRequestContexts(t, request)
	if len(contexts) != 1 {
		t.Fatalf("request carries %d negotiate contexts, want exactly the preauthentication integrity one", len(contexts))
	}
	preauth := contexts[smb2ContextPreauthIntegrity]
	if len(preauth) != 4+2+smb2PreauthSaltLen || binary.LittleEndian.Uint16(preauth) != 1 ||
		int(binary.LittleEndian.Uint16(preauth[2:])) != smb2PreauthSaltLen || binary.LittleEndian.Uint16(preauth[4:]) != smb2HashSHA512 {
		t.Fatalf("preauthentication integrity data % x", preauth)
	}
	if bytes.Equal(preauth[6:], smbRequestContexts(t, second[4:])[smb2ContextPreauthIntegrity][6:]) {
		t.Error("two requests carry the same salt")
	}
	if bytes.Equal(request[smb2HeaderLen+12:smb2HeaderLen+28], second[4:][smb2HeaderLen+12:smb2HeaderLen+28]) {
		t.Error("two requests carry the same client GUID")
	}
}

// Servers that require SMB 3.1.1 (Samba's server min protocol =
// SMB3_11, Windows with the older dialects disabled) are tested like any
// other, and older servers still negotiate the dialect they support. The
// first row is the reporter's fixture, which used to fail with
// STATUS_NOT_SUPPORTED.
func TestSMBProberNegotiatesWhateverTheServerRequires(t *testing.T) {
	for _, tc := range []struct {
		name          string
		min, max      uint16
		want, refused string
	}{
		{"server min protocol SMB3_11", 0x0311, 0x0311, "negotiated SMB 3.1.1 (signing required)", ""},
		{"current server, all dialects", 0x0202, 0x0311, "negotiated SMB 3.1.1", ""},
		{"Windows Server 2012 R2", 0x0202, 0x0302, "negotiated SMB 3.0.2", ""},
		{"Windows 7 and Server 2008 R2", 0x0202, 0x0210, "negotiated SMB 2.1", ""},
		{"server that supports none of the offered dialects", 0x0400, 0x0400, "", "NTSTATUS 0xc00000bb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := NewSMBProber("127.0.0.1", serveSMBPolicy(t, tc.min, tc.max), 2*time.Second, tc.name).Probe(context.Background())
			if tc.refused != "" {
				if res.Passed || !strings.Contains(res.Error, tc.refused) {
					t.Fatalf("result = %+v, want a failure mentioning %q", res, tc.refused)
				}
				return
			}
			if !res.Passed || !strings.Contains(res.Detail, tc.want) {
				t.Fatalf("result = %+v, want a pass with %q", res, tc.want)
			}
		})
	}
}

// Controls: 3.1.1 answers as Samba and Windows send them pass, and a
// context of a type the probe does not know is skipped, not refused.
func TestSMBProberAcceptsSMB311Answers(t *testing.T) {
	preauth := smbContext(smb2ContextPreauthIntegrity, smbPreauthData(32, smb2HashSHA512))
	for name, response := range map[string][]byte{
		"Samba": smbNegotiateResponse311(0x0001, preauth),
		"Windows Server 2022, encryption and signing contexts": smbNegotiateResponse311(0x0003, preauth,
			smbContext(0x0002, []byte{1, 0, 2, 0}),  // ENCRYPTION_CAPABILITIES: AES-128-GCM
			smbContext(0x0008, []byte{1, 0, 2, 0})), // SIGNING_CAPABILITIES: AES-GMAC
		"context of an unknown type first":     smbNegotiateResponse311(0x0003, smbContext(0x00ff, []byte{1, 2, 3}), preauth),
		"no salt":                              smbNegotiateResponse311(0x0003, smbContext(smb2ContextPreauthIntegrity, smbPreauthData(0, smb2HashSHA512))),
		"no security buffer, contexts at 0x80": noBufferSMB311(preauth),
	} {
		t.Run(name, func(t *testing.T) {
			port, _ := serveOnce(t, readSMBRequest, func([]byte) []byte { return response })
			res := NewSMBProber("127.0.0.1", port, time.Second, name).Probe(context.Background())
			if !res.Passed || !strings.Contains(res.Detail, "negotiated SMB 3.1.1") {
				t.Fatalf("result = %+v", res)
			}
		})
	}
}

// noBufferSMB311 is a 3.1.1 response with an empty security buffer, so the
// contexts follow the fixed body directly at offset 0x80.
func noBufferSMB311(contexts ...[]byte) []byte {
	message := append([]byte(nil), smbNegotiateResponse(0, 0x0003, smb2Dialect311)[4:4+smb2HeaderLen+smb2NegotiateRespFixed]...)
	binary.LittleEndian.PutUint16(message[smb2HeaderLen+58:], 0) // SecurityBufferLength
	for i, context := range contexts {
		message = append(message, context...)
		for i < len(contexts)-1 && len(message)%8 != 0 {
			message = append(message, 0)
		}
	}
	binary.LittleEndian.PutUint16(message[smb2HeaderLen+6:], uint16(len(contexts)))
	binary.LittleEndian.PutUint32(message[smb2HeaderLen+60:], smb2HeaderLen+smb2NegotiateRespFixed)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(message))), message...)
}

// A 3.1.1 answer is complete only with a well-formed preauthentication
// integrity context naming the one hash algorithm the client offered.
func TestSMBProberRejectsIncompleteSMB311Answers(t *testing.T) {
	preauth := smbContext(smb2ContextPreauthIntegrity, smbPreauthData(32, smb2HashSHA512))
	edit := func(response []byte, change func(message []byte)) []byte {
		change(response[4:])
		return response
	}
	const fixed = smb2HeaderLen // body offsets below count from the start of the body
	for name, tc := range map[string]struct {
		answer []byte
		want   string
	}{
		"no contexts": {smbNegotiateResponse311(0x0003), "no negotiate contexts"},
		"contexts declared, the list ends first": {edit(smbNegotiateResponse311(0x0003, preauth), func(m []byte) {
			binary.LittleEndian.PutUint16(m[fixed+6:], 2)
		}), "negotiate context 2 of 2 has no header"},
		"context data overruns the message": {edit(smbNegotiateResponse311(0x0003, preauth), func(m []byte) {
			binary.LittleEndian.PutUint16(m[binary.LittleEndian.Uint32(m[fixed+60:])+2:], 0xffff)
		}), "declares 65535 bytes"},
		"list starts inside the security buffer": {edit(smbNegotiateResponse311(0x0003, preauth), func(m []byte) {
			binary.LittleEndian.PutUint32(m[fixed+60:], 0x88)
		}), "8-byte aligned place after the security buffer"},
		"list offset not aligned": {edit(smbNegotiateResponse311(0x0003, preauth), func(m []byte) {
			binary.LittleEndian.PutUint32(m[fixed+60:], binary.LittleEndian.Uint32(m[fixed+60:])+4)
		}), "8-byte aligned place"},
		"list offset past the message": {edit(smbNegotiateResponse311(0x0003, preauth), func(m []byte) {
			binary.LittleEndian.PutUint32(m[fixed+60:], 0x1000)
		}), "8-byte aligned place"},
		"only an encryption context":  {smbNegotiateResponse311(0x0003, smbContext(0x0002, []byte{1, 0, 2, 0})), "no preauthentication integrity context"},
		"preauthentication twice":     {smbNegotiateResponse311(0x0003, preauth, preauth), "twice"},
		"two hash algorithms":         {smbNegotiateResponse311(0x0003, smbContext(smb2ContextPreauthIntegrity, smbPreauthData(32, smb2HashSHA512, smb2HashSHA512))), "names 2 hash algorithms"},
		"no hash algorithm":           {smbNegotiateResponse311(0x0003, smbContext(smb2ContextPreauthIntegrity, smbPreauthData(32))), "names 0 hash algorithms"},
		"hash algorithm not offered":  {smbNegotiateResponse311(0x0003, smbContext(smb2ContextPreauthIntegrity, smbPreauthData(32, 0x0002))), "0x0002 was not offered"},
		"salt shorter than declared":  {smbNegotiateResponse311(0x0003, smbContext(smb2ContextPreauthIntegrity, smbPreauthData(32, smb2HashSHA512)[:20])), "truncated"},
		"preauthentication data of 2": {smbNegotiateResponse311(0x0003, smbContext(smb2ContextPreauthIntegrity, []byte{1, 0})), "fixed part alone is 4"},
	} {
		t.Run(name, func(t *testing.T) {
			port, _ := serveOnce(t, readSMBRequest, func([]byte) []byte { return tc.answer })
			res := NewSMBProber("127.0.0.1", port, time.Second, name).Probe(context.Background())
			if res.Passed || !strings.Contains(res.Error, tc.want) {
				t.Fatalf("result = %+v, want an error containing %q", res, tc.want)
			}
		})
	}
}

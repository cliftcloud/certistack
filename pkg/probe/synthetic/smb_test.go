// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func readSMBRequest(conn net.Conn) ([]byte, error) {
	var frame [4]byte
	if _, err := io.ReadFull(conn, frame[:]); err != nil {
		return nil, err
	}
	message := make([]byte, binary.BigEndian.Uint32(frame[:])&0x00ffffff)
	_, err := io.ReadFull(conn, message)
	return message, err
}

// spnegoNegTokenInit stands in for a server's security buffer: a SPNEGO
// negTokenInit (RFC 4178) offering NTLMSSP with Samba's negHints principal,
// 74 bytes. The probe never interprets it.
var spnegoNegTokenInit = append([]byte{
	0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, // GSS-API, SPNEGO OID
	0xa0, 0x3e, 0x30, 0x3c, // negTokenInit
	0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, // mechTypes: NTLMSSP
	0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, // negHints hintName
}, "not_defined_in_RFC4178@please_ignore"...)

// smbNegotiateResponse frames an SMB2 NEGOTIATE response the way Windows
// Server and Samba send one: the 64-byte fixed body, then the security
// buffer at offset 0x80.
func smbNegotiateResponse(status uint32, securityMode, dialect uint16) []byte {
	header := make([]byte, smb2HeaderLen)
	copy(header, []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(header[4:], smb2HeaderLen)
	binary.LittleEndian.PutUint16(header[14:], 1) // CreditResponse
	binary.LittleEndian.PutUint32(header[8:], status)
	binary.LittleEndian.PutUint32(header[16:], smb2FlagServerToRedir)
	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:], smb2NegotiateRespSize)
	binary.LittleEndian.PutUint16(body[2:], securityMode)
	binary.LittleEndian.PutUint16(body[4:], dialect)
	copy(body[8:24], "certistack-guid!")                                           // ServerGuid
	binary.LittleEndian.PutUint32(body[24:], 0x0000002f)                           // Capabilities
	binary.LittleEndian.PutUint32(body[28:], 8<<20)                                // MaxTransactSize
	binary.LittleEndian.PutUint32(body[32:], 8<<20)                                // MaxReadSize
	binary.LittleEndian.PutUint32(body[36:], 8<<20)                                // MaxWriteSize
	binary.LittleEndian.PutUint64(body[40:], 133700000000000000)                   // SystemTime (FILETIME)
	binary.LittleEndian.PutUint16(body[56:], smb2HeaderLen+smb2NegotiateRespFixed) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[58:], uint16(len(spnegoNegTokenInit)))      // SecurityBufferLength
	message := append(append(header, body...), spnegoNegTokenInit...)
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(message)))
	return append(frame, message...)
}

// smbErrorResponse is how a server refuses the NEGOTIATE: the header with the
// NTSTATUS and a 9-byte SMB2 ERROR body (MS-SMB2 2.2.2), not a NEGOTIATE body.
func smbErrorResponse(status uint32) []byte {
	response := smbNegotiateResponse(status, 0, 0)[:4+smb2HeaderLen]
	response = append(response, 9, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(response, uint32(len(response)-4))
	return response
}

func TestSMBProberPassesOnANegotiateResponse(t *testing.T) {
	port, requests := serveOnce(t, readSMBRequest, func([]byte) []byte { return smbNegotiateResponse(0, 0x0003, 0x0302) })
	res := NewSMBProber("127.0.0.1", port, 2*time.Second, "file server").Probe(context.Background())
	if !res.Passed || !strings.Contains(res.Detail, "negotiated SMB 3.0.2 (signing required)") {
		t.Fatalf("NEGOTIATE result = %+v", res)
	}
	request := <-requests
	if string(request[:4]) != "\xfeSMB" || binary.LittleEndian.Uint16(request[12:]) != 0 {
		t.Fatalf("request is not an SMB2 NEGOTIATE: % x", request[:16])
	}
	// SMB 2.0.2 through 3.1.1 are offered; smb311_test.go checks the rest of
	// the request against MS-SMB2 2.2.3.
	if got := smbRequestDialects(t, request); len(got) != 5 || got[0] != 0x0202 || got[4] != smb2Dialect311 {
		t.Fatalf("NEGOTIATE offers dialects %#04x", got)
	}
}

func TestSMBProberFailsOnRefusalsAndOtherProtocols(t *testing.T) {
	smb1 := smbNegotiateResponse(0, 0, 0)
	smb1[4] = 0xff
	for name, tc := range map[string]struct {
		answer []byte
		want   string
	}{
		"ntstatus error":       {smbErrorResponse(0xc00000bb), "NTSTATUS 0xc00000bb"},
		"smb1 only":            {smb1, "SMB1"},
		"dialect not offered":  {smbNegotiateResponse(0, 0x0001, 0x02ff), "not offered"},
		"not a session frame":  {[]byte("HTTP/1.1 400 Bad Request\r\n\r\n"), "invalid session frame"},
		"connection closed":    {nil, "did not answer"},
		"truncated negotiate":  {smbNegotiateResponse(0, 0, 0x0302)[:40], "truncated"},
		"frame under a header": {binary.BigEndian.AppendUint32(nil, 10), "invalid session frame"},
	} {
		t.Run(name, func(t *testing.T) {
			port, _ := serveOnce(t, readSMBRequest, func([]byte) []byte { return tc.answer })
			res := NewSMBProber("127.0.0.1", port, time.Second, name).Probe(context.Background())
			if res.Passed || !strings.Contains(res.Error, tc.want) {
				t.Fatalf("%s result = %+v, want an error containing %q", name, res, tc.want)
			}
		})
	}
}

// A NEGOTIATE response passes only when its header and fixed body
// are complete and its security buffer lies inside the message. The first
// three replies would otherwise read as negotiated SMB 3.0.2 with signing
// required.
func TestSMBProberRejectsIncompleteOrInconsistentNegotiation(t *testing.T) {
	edit := func(change func(message []byte) []byte) []byte {
		response := change(smbNegotiateResponse(0, 0x0003, 0x0302)[4:])
		return append(binary.BigEndian.AppendUint32(nil, uint32(len(response))), response...)
	}
	body := smb2HeaderLen
	for name, tc := range map[string]struct {
		answer []byte
		want   string
	}{
		"eight-byte body": {edit(func(m []byte) []byte { return m[:body+8] }), "truncated: its body has 8 bytes"},
		"security buffer outside the message": {edit(func(m []byte) []byte {
			binary.LittleEndian.PutUint16(m[body+56:], 0xff00)
			binary.LittleEndian.PutUint16(m[body+58:], 40)
			return m
		}), "security buffer (offset 65280, length 40)"},
		"header structure size zero": {edit(func(m []byte) []byte { binary.LittleEndian.PutUint16(m[4:], 0); return m }), "header declares structure size 0"},
		"security buffer over the fixed body": {edit(func(m []byte) []byte {
			binary.LittleEndian.PutUint16(m[body+56:], smb2HeaderLen)
			return m
		}), "security buffer"},
		"security buffer past the end": {edit(func(m []byte) []byte { return m[:len(m)-1] }), "security buffer"},
		"empty security buffer past the end": {edit(func(m []byte) []byte {
			binary.LittleEndian.PutUint16(m[body+56:], 0x4000)
			binary.LittleEndian.PutUint16(m[body+58:], 0)
			return m
		}), "security buffer"},
		"body structure size 64":   {edit(func(m []byte) []byte { binary.LittleEndian.PutUint16(m[body:], 64); return m }), "structure size 64, not 65"},
		"reply to another message": {edit(func(m []byte) []byte { m[24] = 7; return m }), "message 7"},
		"chained reply":            {edit(func(m []byte) []byte { binary.LittleEndian.PutUint32(m[20:], 128); return m }), "chained"},
	} {
		t.Run(name, func(t *testing.T) {
			port, _ := serveOnce(t, readSMBRequest, func([]byte) []byte { return tc.answer })
			res := NewSMBProber("127.0.0.1", port, time.Second, name).Probe(context.Background())
			if res.Passed || !strings.Contains(res.Error, tc.want) {
				t.Fatalf("%s result = %+v, want an error containing %q", name, res, tc.want)
			}
		})
	}
}

// Controls: complete responses still pass, including one without a
// security buffer and a Samba-style signing-optional SMB 2.1 answer.
func TestSMBProberAcceptsCompleteNegotiateResponses(t *testing.T) {
	noBuffer := smbNegotiateResponse(0, 0x0001, 0x0210)[:4+smb2HeaderLen+smb2NegotiateRespFixed]
	binary.BigEndian.PutUint32(noBuffer, uint32(len(noBuffer)-4))
	binary.LittleEndian.PutUint16(noBuffer[4+smb2HeaderLen+58:], 0)
	for name, tc := range map[string]struct {
		answer []byte
		want   string
	}{
		"domain controller, signing required": {smbNegotiateResponse(0, 0x0003, 0x0302), "negotiated SMB 3.0.2 (signing required)"},
		"file server, signing optional":       {smbNegotiateResponse(0, 0x0001, 0x0210), "negotiated SMB 2.1 (signing optional)"},
		"no security buffer":                  {noBuffer, "negotiated SMB 2.1"},
	} {
		t.Run(name, func(t *testing.T) {
			port, _ := serveOnce(t, readSMBRequest, func([]byte) []byte { return tc.answer })
			res := NewSMBProber("127.0.0.1", port, time.Second, name).Probe(context.Background())
			if !res.Passed || !strings.Contains(res.Detail, tc.want) {
				t.Fatalf("%s result = %+v, want a pass with %q", name, res, tc.want)
			}
		})
	}
}

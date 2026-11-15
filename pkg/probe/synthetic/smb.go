// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// SMBProber sends an SMB2 NEGOTIATE (MS-SMB2 2.2.3) over direct TCP and
// requires a successful NEGOTIATE response. The exchange needs no session,
// credentials or share, so it proves the guest's SMB server answers its
// protocol, not only that port 445 accepts connections. It does not show
// that any particular share or its data survived the restore.
type SMBProber struct {
	TargetIP    string
	Port        int
	Timeout     time.Duration
	Description string
	Source      Source
}

// NewSMBProber creates an SMB2/3 prober.
func NewSMBProber(targetIP string, port int, timeout time.Duration, desc string) *SMBProber {
	if port <= 0 {
		port = 445
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &SMBProber{TargetIP: targetIP, Port: port, Timeout: timeout, Description: desc}
}

const (
	smb2HeaderLen          = 64
	smb2NegotiateReqSize   = 36
	smb2NegotiateRespSize  = 65
	smb2NegotiateRespFixed = 64 // the response body before its variable buffer
	smb2FlagServerToRedir  = 0x00000001
	smb2SigningRequired    = 0x0002
	smbMaxNegotiateMessage = 64 << 10

	smb2Dialect311 = 0x0311
	// SMB 3.1.1 negotiate contexts (MS-SMB2 2.2.3.1): the client must offer
	// PREAUTH_INTEGRITY_CAPABILITIES with a hash algorithm and a salt, and the
	// server must answer with exactly one of the algorithms offered.
	smb2ContextPreauthIntegrity = 0x0001
	smb2HashSHA512              = 0x0001
	smb2PreauthSaltLen          = 32
)

// The dialects offered: SMB 2.0.2 through 3.1.1. The server picks the highest
// it supports, so a server that requires 3.1.1 (Samba's "server min protocol
// = SMB3_11", or Windows with older dialects disabled) is tested like any
// other.
var smbDialects = map[uint16]string{0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", smb2Dialect311: "3.1.1"}

func smbNegotiatePacket() ([]byte, error) {
	header := make([]byte, smb2HeaderLen)
	copy(header, []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(header[4:], smb2HeaderLen)
	binary.LittleEndian.PutUint16(header[14:], 1) // CreditRequest

	body := make([]byte, smb2NegotiateReqSize)
	binary.LittleEndian.PutUint16(body[0:], smb2NegotiateReqSize)
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302, smb2Dialect311}
	binary.LittleEndian.PutUint16(body[2:], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:], 0x0001)   // SecurityMode: signing enabled
	if _, err := rand.Read(body[12:28]); err != nil { // ClientGuid
		return nil, fmt.Errorf("generate client GUID: %w", err)
	}
	for _, dialect := range dialects {
		body = binary.LittleEndian.AppendUint16(body, dialect)
	}
	// With 3.1.1 offered, the last eight fixed octets carry the negotiate
	// context list's offset (from the start of the header, 8-byte aligned) and
	// count in place of ClientStartTime. The list follows the dialects.
	contextOffset := (smb2HeaderLen + len(body) + 7) &^ 7
	body = append(body, make([]byte, contextOffset-smb2HeaderLen-len(body))...)
	salt := make([]byte, smb2PreauthSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate preauthentication salt: %w", err)
	}
	preauth := binary.LittleEndian.AppendUint16(nil, 1) // HashAlgorithmCount
	preauth = binary.LittleEndian.AppendUint16(preauth, smb2PreauthSaltLen)
	preauth = binary.LittleEndian.AppendUint16(preauth, smb2HashSHA512)
	preauth = append(preauth, salt...)
	body = binary.LittleEndian.AppendUint16(body, smb2ContextPreauthIntegrity)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(preauth)))
	body = append(body, 0, 0, 0, 0) // Reserved
	body = append(body, preauth...)
	binary.LittleEndian.PutUint32(body[28:], uint32(contextOffset))
	binary.LittleEndian.PutUint16(body[32:], 1) // NegotiateContextCount

	message := append(header, body...)
	frame := make([]byte, 4, 4+len(message))
	binary.BigEndian.PutUint32(frame, uint32(len(message))) // first byte 0: session message
	return append(frame, message...), nil
}

// Probe sends one NEGOTIATE and validates the response.
func (p *SMBProber) Probe(ctx context.Context) (res probe.Result) {
	start := time.Now()
	addr := net.JoinHostPort(p.TargetIP, strconv.Itoa(p.Port))
	res = probe.Result{Type: "smb", Target: addr, Description: p.Description}
	p.Source.annotate(&res)

	request, err := smbNegotiatePacket()
	if err != nil {
		res.Duration = time.Since(start)
		res.Error = err.Error()
		return res
	}
	probeCtx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	defer func() { res = finishProbe(probeCtx, res) }()
	dialer, err := p.Source.dialer("tcp", 0)
	if err != nil {
		res.Duration = time.Since(start)
		res.Error = fmt.Sprintf("SMB TCP connection to %s failed: %v", addr, err)
		return res
	}
	conn, err := dialer.DialContext(probeCtx, "tcp", addr)
	if err != nil {
		res.Duration = time.Since(start)
		res.Error = fmt.Sprintf("SMB TCP connection to %s failed: %v", addr, err)
		return res
	}
	defer conn.Close()
	defer interruptOnCancel(probeCtx, conn)()
	deadline, _ := probeCtx.Deadline()
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(request); err != nil {
		res.Duration = time.Since(start)
		res.Error = fmt.Sprintf("failed to send SMB2 NEGOTIATE to %s: %v", addr, err)
		return res
	}
	var frame [4]byte
	if _, err := io.ReadFull(conn, frame[:]); err != nil {
		res.Duration = time.Since(start)
		res.Error = fmt.Sprintf("SMB server at %s did not answer SMB2 NEGOTIATE: %v", addr, err)
		return res
	}
	length := int(binary.BigEndian.Uint32(frame[:]) & 0x00ffffff)
	if frame[0] != 0 || length < smb2HeaderLen || length > smbMaxNegotiateMessage {
		res.Duration = time.Since(start)
		res.Error = fmt.Sprintf("SMB server at %s sent an invalid session frame (type 0x%02x, length %d)", addr, frame[0], length)
		return res
	}
	message := make([]byte, length)
	if _, err := io.ReadFull(conn, message); err != nil {
		res.Duration = time.Since(start)
		res.Error = fmt.Sprintf("SMB server at %s sent a truncated NEGOTIATE response: %v", addr, err)
		return res
	}
	res.Duration = time.Since(start)
	dialect, signingRequired, err := parseSMBNegotiateResponse(message)
	if err != nil {
		res.Error = fmt.Sprintf("SMB server at %s: %v", addr, err)
		return res
	}
	signing := "optional"
	if signingRequired {
		signing = "required"
	}
	res.Passed = true
	res.Detail = fmt.Sprintf("SMB server at %s negotiated SMB %s (signing %s) in %v", addr, dialect, signing, res.Duration)
	return res
}

// parseSMBNegotiateResponse validates an SMB2 NEGOTIATE response (MS-SMB2
// 2.2.1.2 and 2.2.4) to the request smbNegotiatePacket sends, message ID 0:
// the complete 64-byte header, then, on success, the complete 64-byte fixed
// body and a security buffer that lies inside the message.
func parseSMBNegotiateResponse(message []byte) (string, bool, error) {
	if len(message) < smb2HeaderLen {
		return "", false, errors.New("NEGOTIATE response is too short")
	}
	if message[0] != 0xfe || string(message[1:4]) != "SMB" {
		if message[0] == 0xff && string(message[1:4]) == "SMB" {
			return "", false, errors.New("answered with SMB1, which offers no SMB2 dialect")
		}
		return "", false, errors.New("response is not an SMB2 message")
	}
	if size := binary.LittleEndian.Uint16(message[4:]); size != smb2HeaderLen {
		return "", false, fmt.Errorf("SMB2 header declares structure size %d, not %d", size, smb2HeaderLen)
	}
	status := binary.LittleEndian.Uint32(message[8:])
	command := binary.LittleEndian.Uint16(message[12:])
	flags := binary.LittleEndian.Uint32(message[16:])
	if command != 0 || flags&smb2FlagServerToRedir == 0 {
		return "", false, errors.New("response is not a NEGOTIATE reply")
	}
	if next := binary.LittleEndian.Uint32(message[20:]); next != 0 {
		return "", false, fmt.Errorf("NEGOTIATE response is chained to another message (NextCommand %d)", next)
	}
	if messageID := binary.LittleEndian.Uint64(message[24:]); messageID != 0 {
		return "", false, fmt.Errorf("response is for message %d, not the NEGOTIATE request (message 0)", messageID)
	}
	if status != 0 {
		return "", false, fmt.Errorf("NEGOTIATE failed with NTSTATUS 0x%08x", status)
	}
	body := message[smb2HeaderLen:]
	if len(body) < smb2NegotiateRespFixed {
		return "", false, fmt.Errorf("NEGOTIATE response is truncated: its body has %d bytes, and the fixed part alone is %d", len(body), smb2NegotiateRespFixed)
	}
	if size := binary.LittleEndian.Uint16(body[0:]); size != smb2NegotiateRespSize {
		return "", false, fmt.Errorf("NEGOTIATE response declares structure size %d, not %d", size, smb2NegotiateRespSize)
	}
	securityMode := binary.LittleEndian.Uint16(body[2:])
	dialect, ok := smbDialects[binary.LittleEndian.Uint16(body[4:])]
	if !ok {
		return "", false, fmt.Errorf("server selected dialect 0x%04x, which was not offered", binary.LittleEndian.Uint16(body[4:]))
	}
	// The security buffer offset counts from the start of the SMB2 header, and
	// the buffer follows the fixed body.
	offset, length := int(binary.LittleEndian.Uint16(body[56:])), int(binary.LittleEndian.Uint16(body[58:]))
	if length > 0 && (offset < smb2HeaderLen+smb2NegotiateRespFixed || offset+length > len(message)) || offset > len(message) {
		return "", false, fmt.Errorf("NEGOTIATE response security buffer (offset %d, length %d) lies outside its %d-byte message", offset, length, len(message))
	}
	if binary.LittleEndian.Uint16(body[4:]) == smb2Dialect311 {
		contextsFrom := smb2HeaderLen + smb2NegotiateRespFixed
		if length > 0 {
			contextsFrom = offset + length
		}
		if err := checkSMB311Contexts(message, contextsFrom); err != nil {
			return "", false, err
		}
	}
	return dialect, securityMode&smb2SigningRequired != 0, nil
}

// checkSMB311Contexts validates the negotiate contexts of an SMB 3.1.1
// NEGOTIATE response (MS-SMB2 2.2.4 and 2.2.4.1): the list must lie in the
// message, after the security buffer, 8-byte aligned, with every context whole,
// and it must carry the one PREAUTH_INTEGRITY_CAPABILITIES context that names
// the hash algorithm the client offered. Contexts of other types are skipped.
func checkSMB311Contexts(message []byte, notBefore int) error {
	body := message[smb2HeaderLen:]
	count, offset := int(binary.LittleEndian.Uint16(body[6:])), int(binary.LittleEndian.Uint32(body[60:]))
	if count == 0 {
		return errors.New("SMB 3.1.1 NEGOTIATE response has no negotiate contexts, so it names no preauthentication integrity hash algorithm")
	}
	if offset%8 != 0 || offset < notBefore || offset > len(message) {
		return fmt.Errorf("SMB 3.1.1 NEGOTIATE response puts its %d negotiate contexts at offset %d, which is not an 8-byte aligned place after the security buffer inside its %d-byte message", count, offset, len(message))
	}
	preauth := false
	for i := 1; i <= count; i++ {
		if offset+8 > len(message) {
			return fmt.Errorf("SMB 3.1.1 NEGOTIATE response is truncated: negotiate context %d of %d has no header", i, count)
		}
		contextType, dataLength := binary.LittleEndian.Uint16(message[offset:]), int(binary.LittleEndian.Uint16(message[offset+2:]))
		data := message[offset+8:]
		if dataLength > len(data) {
			return fmt.Errorf("SMB 3.1.1 NEGOTIATE response is truncated: negotiate context %d of %d declares %d bytes of data, and %d follow", i, count, dataLength, len(data))
		}
		data = data[:dataLength]
		if contextType == smb2ContextPreauthIntegrity {
			if preauth {
				return errors.New("SMB 3.1.1 NEGOTIATE response carries the preauthentication integrity context twice")
			}
			preauth = true
			if err := checkSMB311Preauth(data); err != nil {
				return err
			}
		}
		offset = (offset + 8 + dataLength + 7) &^ 7 // the next context is 8-byte aligned
	}
	if !preauth {
		return errors.New("SMB 3.1.1 NEGOTIATE response has no preauthentication integrity context")
	}
	return nil
}

// checkSMB311Preauth validates PREAUTH_INTEGRITY_CAPABILITIES data (MS-SMB2
// 2.2.3.1.1): a response names exactly one hash algorithm, from those offered,
// and its salt is complete.
func checkSMB311Preauth(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("SMB 3.1.1 preauthentication integrity context has %d bytes of data, and its fixed part alone is 4", len(data))
	}
	hashes, salt := int(binary.LittleEndian.Uint16(data)), int(binary.LittleEndian.Uint16(data[2:]))
	if hashes != 1 {
		return fmt.Errorf("SMB 3.1.1 preauthentication integrity context names %d hash algorithms, and a response names exactly one", hashes)
	}
	if len(data) < 4+2*hashes+salt {
		return fmt.Errorf("SMB 3.1.1 preauthentication integrity context is truncated: %d bytes of data for one hash algorithm and a %d-byte salt", len(data), salt)
	}
	if algorithm := binary.LittleEndian.Uint16(data[4:]); algorithm != smb2HashSHA512 {
		return fmt.Errorf("SMB 3.1.1 preauthentication integrity hash algorithm 0x%04x was not offered (only SHA-512, 0x0001)", algorithm)
	}
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// MSSQLProber sends a TDS PRELOGIN message (MS-TDS 2.2.6.5) and requires a
// well-formed PRELOGIN response carrying the server's version. PRELOGIN is
// the first exchange of every SQL Server connection and needs no login, so
// the probe proves the SQL Server engine answers its protocol, not only that
// a port is open, without credentials and without touching any database.
//
// The first attempt is the classic cleartext PRELOGIN of TDS 7.x. A server
// that forces TDS 8.0 strict encryption (SQL Server 2022 with Force Strict
// Encryption) answers that with a TLS record or drops the connection, and only
// then does the probe retry once, on a fresh connection, as TDS 8.0 strict: the
// TLS handshake first (ALPN tds/8.0, TLS 1.2 or later) and the same PRELOGIN
// inside the tunnel. The result's detail says which path answered. That
// strict path does not verify the server's certificate: a default SQL Server
// presents a self-signed one, and the probe asserts that the engine answers.
//
// A probe that sets ServerName asks for more and makes only the strict
// attempt: TLS first, ALPN tds/8.0, the certificate chain verified against the
// node's system trust store and the certificate checked for ServerName (which is
// also the SNI). A cleartext PRELOGIN shows no certificate, so it cannot satisfy
// such a probe and is not tried.
type MSSQLProber struct {
	TargetIP    string
	Port        int
	Timeout     time.Duration
	Description string
	Source      Source
	// ServerName makes the probe verify a TDS 8.0 strict handshake for this
	// name. Empty keeps the probe that does not verify the certificate.
	ServerName string
	// TLSRootCAs is intended for trusted, controller-supplied roots in
	// programmatic callers and tests, like the http probe's. Plans do not
	// expose a TLS bypass: when nil, Go's system trust store is used. It is read
	// only when ServerName is set.
	TLSRootCAs *x509.CertPool
}

// NewMSSQLProber creates a SQL Server (TDS) prober.
func NewMSSQLProber(targetIP string, port int, timeout time.Duration, desc string) *MSSQLProber {
	if port <= 0 {
		port = 1433
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &MSSQLProber{TargetIP: targetIP, Port: port, Timeout: timeout, Description: desc}
}

const (
	tdsHeaderLen        = 8
	tdsTypePrelogin     = 0x12
	tdsTypeTabular      = 0x04
	tdsStatusEOM        = 0x01
	tdsOptionVersion    = 0x00
	tdsOptionEncryption = 0x01
	tdsOptionTerminator = 0xff
	tdsMaxPacket        = 32 << 10
)

var tdsEncryptionNames = map[byte]string{0: "off", 1: "on", 2: "not supported", 3: "required"}

// tdsStrictALPN is the ALPN protocol id of TDS 8.0 strict encryption
// ([MS-TDS], TDS 8.0): the client opens the TCP connection, performs the TLS
// handshake at once offering this protocol, and every TDS message, PRELOGIN
// included, then travels inside the tunnel.
const tdsStrictALPN = "tds/8.0"

// errTLSFirst is what a cleartext PRELOGIN gets from a server that forces TDS
// 8.0 strict encryption and answers with a TLS record instead of TDS.
var errTLSFirst = errors.New("it answered with TLS, so the server forces TDS 8.0 strict encryption (TLS before any TDS message)")

// tdsPreloginPacket is a client PRELOGIN with VERSION, ENCRYPTION (not
// supported: the probe never proceeds to a login), INSTOPT (default
// instance), THREADID and MARS, the options every SQL Server client sends.
func tdsPreloginPacket() []byte {
	type option struct {
		token byte
		data  []byte
	}
	options := []option{
		{tdsOptionVersion, make([]byte, 6)},
		{tdsOptionEncryption, []byte{0x02}},
		{0x02, []byte{0x00}},    // INSTOPT: default instance
		{0x03, make([]byte, 4)}, // THREADID
		{0x04, []byte{0x00}},    // MARS off
	}
	offset := len(options)*5 + 1
	var headers, data []byte
	for _, o := range options {
		headers = append(headers, o.token)
		headers = binary.BigEndian.AppendUint16(headers, uint16(offset+len(data)))
		headers = binary.BigEndian.AppendUint16(headers, uint16(len(o.data)))
		data = append(data, o.data...)
	}
	payload := append(append(headers, tdsOptionTerminator), data...)
	packet := []byte{tdsTypePrelogin, tdsStatusEOM, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(packet[2:], uint16(tdsHeaderLen+len(payload)))
	return append(packet, payload...)
}

// tdsAttempt is the outcome of one connection's PRELOGIN exchange.
type tdsAttempt struct {
	version, encryption string
	// tlsVersion is the negotiated TLS version of a strict attempt, "" in clear.
	tlsVersion string
	// failure is the whole error sentence, "" when the server answered.
	failure string
	// verified is true when the strict attempt verified the certificate for
	// the prober's ServerName.
	verified bool
	// strictCue is true when a cleartext attempt met the signature of a server
	// that forces TDS 8.0 strict encryption: an answer that begins with a TLS
	// record, or a dropped connection. Nothing else (a refusal, a silent
	// server, a malformed TDS answer) is a reason to try TLS.
	strictCue bool
}

// Probe sends one cleartext PRELOGIN and validates the response. If the server
// answered with TLS or dropped the connection, it sends the PRELOGIN again, once,
// on a fresh connection as TDS 8.0 strict encryption. With ServerName set it
// sends only the strict one, with the certificate verified.
func (p *MSSQLProber) Probe(ctx context.Context) (res probe.Result) {
	start := time.Now()
	addr := net.JoinHostPort(p.TargetIP, strconv.Itoa(p.Port))
	// ServerName is the identity the plan asserted, whatever the outcome: the
	// report must carry it, as the http probe's does.
	res = probe.Result{Type: "mssql", Target: addr, Description: p.Description, ServerName: p.ServerName}
	p.Source.annotate(&res)

	probeCtx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	defer func() { res = finishProbe(probeCtx, res) }()

	// With a server name the first attempt is the strict one and no cleartext
	// attempt is made, so there is nothing to retry as strict.
	attempt := p.preloginAttempt(probeCtx, addr, p.ServerName != "")
	if attempt.failure != "" && attempt.strictCue && probeCtx.Err() == nil {
		cleartext := attempt.failure
		attempt = p.preloginAttempt(probeCtx, addr, true)
		if attempt.failure != "" {
			attempt.failure = fmt.Sprintf("the cleartext TDS PRELOGIN failed (%s); the server may force TDS 8.0 strict encryption, so the probe retried once on a fresh connection with TLS first (ALPN %s), and that failed too (%s)", cleartext, tdsStrictALPN, attempt.failure)
		}
	}
	res.Duration = time.Since(start)
	if attempt.failure != "" {
		res.Error = attempt.failure
		return res
	}
	res.Passed = true
	if attempt.tlsVersion != "" {
		// The detail says that the strict path answered and how, and whether
		// the certificate was checked: a reader of the report must not take an
		// unverified pass for an authenticated server.
		certificate := "certificate not verified"
		if attempt.verified {
			certificate = fmt.Sprintf("certificate verified for %s", p.ServerName)
		}
		res.Detail = fmt.Sprintf("SQL Server at %s answered TDS PRELOGIN over TDS 8.0 strict encryption (%s, ALPN %s, %s): version %s, encryption %s, in %v", addr, attempt.tlsVersion, tdsStrictALPN, certificate, attempt.version, attempt.encryption, res.Duration)
		return res
	}
	res.Detail = fmt.Sprintf("SQL Server at %s answered TDS PRELOGIN: version %s, encryption %s, in %v", addr, attempt.version, attempt.encryption, res.Duration)
	return res
}

// preloginAttempt makes one connection to addr and exchanges one PRELOGIN on
// it: in clear, or, when strict, inside a TDS 8.0 strict encryption tunnel.
func (p *MSSQLProber) preloginAttempt(ctx context.Context, addr string, strict bool) (out tdsAttempt) {
	dialer, err := p.Source.dialer("tcp", 0)
	if err != nil {
		out.failure = fmt.Sprintf("SQL Server TCP connection to %s failed: %v", addr, err)
		return out
	}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		out.failure = fmt.Sprintf("SQL Server TCP connection to %s failed: %v", addr, err)
		return out
	}
	defer raw.Close()
	defer interruptOnCancel(ctx, raw)()
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)

	conn := raw
	where := ""
	if strict {
		verify := p.ServerName != ""
		tunnel := tls.Client(raw, p.strictTLSConfig())
		if err := tunnel.HandshakeContext(ctx); err != nil {
			if verify {
				out.failure = fmt.Sprintf("server_name %q asks for a verified TDS 8.0 strict handshake (TLS first, ALPN %s, certificate chain and name checked), and the handshake with %s failed: the server did not offer it, or its certificate did not verify: %v", p.ServerName, tdsStrictALPN, addr, err)
			} else {
				out.failure = fmt.Sprintf("the TDS 8.0 strict TLS handshake with %s failed: %v", addr, err)
			}
			return out
		}
		defer tunnel.Close()
		state := tunnel.ConnectionState()
		if state.NegotiatedProtocol != tdsStrictALPN {
			// A TLS server that does not select tds/8.0 is not a TDS 8.0 strict
			// endpoint, whatever it would answer: nothing is sent to it.
			out.failure = fmt.Sprintf("the TLS server at %s did not select ALPN protocol %s (it selected %q), so it is not a TDS 8.0 strict endpoint", addr, tdsStrictALPN, state.NegotiatedProtocol)
			if verify {
				out.failure = fmt.Sprintf("server_name %q asks for a verified TDS 8.0 strict handshake, and %s", p.ServerName, out.failure)
			}
			return out
		}
		out.tlsVersion = tls.VersionName(state.Version)
		out.verified = verify
		conn = tunnel
		where = " inside TLS"
	}

	if _, err := conn.Write(tdsPreloginPacket()); err != nil {
		out.failure = fmt.Sprintf("failed to send TDS PRELOGIN%s to %s: %v", where, addr, err)
		return out
	}
	payload, err := readTDSMessage(conn, !strict)
	if err != nil {
		out.failure = fmt.Sprintf("SQL Server at %s did not answer TDS PRELOGIN%s: %v", addr, where, err)
		// Only a cleartext attempt can cue the strict one.
		out.strictCue = !strict && (errors.Is(err, errTLSFirst) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || connectionReset(err))
		return out
	}
	out.version, out.encryption, err = parseTDSPrelogin(payload)
	if err != nil {
		out.failure = fmt.Sprintf("SQL Server at %s returned a malformed PRELOGIN response%s: %v", addr, where, err)
	}
	return out
}

// strictTLSConfig is the client side of the TDS 8.0 strict handshake: TLS 1.2
// or later with ALPN tds/8.0. Without a server name it does not verify the
// certificate; with one it verifies the chain against TLSRootCAs (the system
// trust store when nil) and the name, which is also the SNI.
func (p *MSSQLProber) strictTLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{tdsStrictALPN}}
	if p.ServerName != "" {
		cfg.ServerName = p.ServerName
		cfg.RootCAs = p.TLSRootCAs
		return cfg
	}
	// A probe with no server_name asserts that the SQL Server engine answers
	// PRELOGIN, not who runs it, as its cleartext PRELOGIN does: the exchange
	// authenticates nobody, sends no credential and no secret, and reads a
	// version number. SQL Server presents a self-signed certificate unless the
	// operator installed one, so a chain check would fail every default
	// instance. The result's detail says the certificate was not verified. A
	// plan that wants the identity asserts it with server_name, and the branch
	// above verifies, as the http probe does because it asserts a named
	// service.
	cfg.InsecureSkipVerify = true // #nosec G402 -- identity is not asserted without server_name; see above
	return cfg
}

// wsaeConnReset and wsaeConnAborted are WSAECONNRESET and WSAECONNABORTED: what
// Windows reports for a connection the peer reset or dropped, which are not the
// numbers of syscall.ECONNRESET and ECONNABORTED there.
const (
	wsaeConnReset   = syscall.Errno(10054)
	wsaeConnAborted = syscall.Errno(10053)
)

// connectionReset reports a connection the peer reset or dropped, on any
// platform.
func connectionReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, wsaeConnReset) || errors.Is(err, wsaeConnAborted)
}

// readTDSMessage reads one tabular-result message, which may span several
// packets, and returns its payload. In clear (detectTLS), an answer that begins
// with a TLS alert or handshake record is reported as errTLSFirst; inside a TLS
// tunnel the first byte is a TDS packet type or nothing.
func readTDSMessage(conn net.Conn, detectTLS bool) ([]byte, error) {
	var payload []byte
	for packets := 0; packets < 16; packets++ {
		var header [tdsHeaderLen]byte
		n, err := io.ReadFull(conn, header[:])
		if detectTLS && packets == 0 && n > 0 && (header[0] == 0x15 || header[0] == 0x16) {
			// A TLS alert or handshake record instead of TDS.
			return nil, errTLSFirst
		}
		if err != nil {
			return nil, err
		}
		if header[0] != tdsTypeTabular {
			return nil, fmt.Errorf("unexpected TDS packet type 0x%02x", header[0])
		}
		length := int(binary.BigEndian.Uint16(header[2:]))
		if length < tdsHeaderLen || length > tdsMaxPacket {
			return nil, fmt.Errorf("invalid TDS packet length %d", length)
		}
		body := make([]byte, length-tdsHeaderLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, err
		}
		payload = append(payload, body...)
		if header[1]&tdsStatusEOM != 0 {
			return payload, nil
		}
	}
	return nil, errors.New("TDS response did not end within 16 packets")
}

// parseTDSPrelogin returns the server version ("15.0.2000.5") and the
// encryption setting from a PRELOGIN response (MS-TDS 2.2.6.5). The option
// table is read to its terminator first; every option's data must then lie
// in the data area after the table and inside the payload, without two
// options sharing bytes, so no part of the table is ever decoded as data.
func parseTDSPrelogin(payload []byte) (string, string, error) {
	type option struct {
		token         byte
		start, length int
	}
	var options []option
	tableEnd := 0
	for off := 0; tableEnd == 0; off += 5 {
		if off >= len(payload) {
			return "", "", errors.New("option list has no terminator")
		}
		if payload[off] == tdsOptionTerminator {
			tableEnd = off + 1
			break
		}
		if off+5 > len(payload) {
			return "", "", errors.New("option header is truncated")
		}
		options = append(options, option{payload[off], int(binary.BigEndian.Uint16(payload[off+1:])), int(binary.BigEndian.Uint16(payload[off+3:]))})
	}
	for i, o := range options {
		// An option with no data reads nothing, wherever its offset points.
		if o.length > 0 && (o.start < tableEnd || o.start+o.length > len(payload)) {
			return "", "", fmt.Errorf("option 0x%02x data (offset %d, length %d) lies outside the data area, bytes %d to %d", o.token, o.start, o.length, tableEnd, len(payload))
		}
		for _, earlier := range options[:i] {
			if earlier.token == o.token {
				return "", "", fmt.Errorf("option 0x%02x appears twice", o.token)
			}
			if o.length > 0 && earlier.length > 0 && o.start < earlier.start+earlier.length && earlier.start < o.start+o.length {
				return "", "", fmt.Errorf("options 0x%02x and 0x%02x share data bytes", earlier.token, o.token)
			}
		}
	}
	var versionOption *option
	for i := range options {
		if options[i].token == tdsOptionVersion {
			versionOption = &options[i]
		}
	}
	if versionOption == nil {
		return "", "", errors.New("response has no VERSION option")
	}
	if versionOption.length < 6 {
		return "", "", errors.New("VERSION option is shorter than 6 bytes")
	}
	data := payload[versionOption.start:]
	version := fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], binary.BigEndian.Uint16(data[2:]), binary.BigEndian.Uint16(data[4:]))
	encryption := "unknown"
	for _, o := range options {
		if o.token != tdsOptionEncryption {
			continue
		}
		if o.length != 1 {
			return "", "", fmt.Errorf("ENCRYPTION option has %d bytes, not 1", o.length)
		}
		if name, ok := tdsEncryptionNames[payload[o.start]]; ok {
			encryption = name
		}
	}
	return version, encryption, nil
}

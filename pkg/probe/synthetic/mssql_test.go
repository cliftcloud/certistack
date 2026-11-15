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

// serveOnce accepts one connection, hands the client's first bytes to
// answer, and writes whatever it returns.
func serveOnce(t *testing.T, read func(net.Conn) ([]byte, error), answer func(request []byte) []byte) (int, <-chan []byte) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	requests := make(chan []byte, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := read(conn)
		requests <- request
		if err != nil {
			return
		}
		_, _ = conn.Write(answer(request))
	}()
	return l.Addr().(*net.TCPAddr).Port, requests
}

func readTDSRequest(conn net.Conn) ([]byte, error) {
	header := make([]byte, tdsHeaderLen)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	body := make([]byte, int(binary.BigEndian.Uint16(header[2:]))-tdsHeaderLen)
	_, err := io.ReadFull(conn, body)
	return append(header, body...), err
}

// tdsPreloginResponse is what SQL Server 2019 RTM answers: VERSION
// 15.0.2000.0 and the given ENCRYPTION setting.
func tdsPreloginResponse(encryption byte) []byte {
	payload := []byte{
		tdsOptionVersion, 0, 11, 0, 6,
		tdsOptionEncryption, 0, 17, 0, 1,
		tdsOptionTerminator,
		15, 0, 0x07, 0xd0, 0, 0,
		encryption,
	}
	packet := []byte{tdsTypeTabular, tdsStatusEOM, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(packet[2:], uint16(tdsHeaderLen+len(payload)))
	return append(packet, payload...)
}

func TestMSSQLProberPassesOnAPreloginResponse(t *testing.T) {
	port, requests := serveOnce(t, readTDSRequest, func([]byte) []byte { return tdsPreloginResponse(0x02) })
	res := NewMSSQLProber("127.0.0.1", port, 2*time.Second, "SQL Express").Probe(context.Background())
	if !res.Passed || !strings.Contains(res.Detail, "version 15.0.2000.0, encryption not supported") {
		t.Fatalf("PRELOGIN result = %+v", res)
	}
	request := <-requests
	if request[0] != tdsTypePrelogin || request[1] != tdsStatusEOM {
		t.Fatalf("request header % x is not a single-packet PRELOGIN", request[:tdsHeaderLen])
	}
	// The client's own option list must parse with the same rules.
	if version, _, err := parseTDSPrelogin(request[tdsHeaderLen:]); err != nil || version != "0.0.0.0" {
		t.Fatalf("client PRELOGIN parses as %q, %v", version, err)
	}
}

// A server that forces TDS 8.0 strict encryption answers the cleartext
// PRELOGIN with a TLS record or drops it. Those, and only those, make the probe
// retry once, on a fresh connection, as TDS 8.0 strict (a TLS ClientHello that
// offers ALPN tds/8.0, as its first bytes); the peer here is plain TCP and
// closes that connection, so the probe fails, says that both attempts failed,
// and must not pass on a TLS record or on nothing. (Until the owner's decision
// on RO-098 the probe never retried and reported such a server as untestable.)
func TestMSSQLProberRetriesAsStrictEncryptionOnAStrictSignature(t *testing.T) {
	tlsAlert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46}
	tlsHandshake := []byte{0x16, 0x03, 0x03, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2c}
	for name, tc := range map[string]struct {
		answer []byte
		want   []string
	}{
		"TLS alert":                     {tlsAlert, []string{"forces TDS 8.0 strict encryption", "cleartext", "retried once"}},
		"TLS handshake record":          {tlsHandshake, []string{"forces TDS 8.0 strict encryption", "cleartext", "retried once"}},
		"cleartext PRELOGIN is dropped": {nil, []string{"did not answer TDS PRELOGIN", "cleartext", "retried once"}},
	} {
		t.Run(name, func(t *testing.T) {
			firstBytes := make(chan []byte, 2)
			port, connections := serveEvery(t, func(n int, conn net.Conn) {
				if n == 1 {
					request, err := readTDSRequest(conn)
					firstBytes <- request
					if err == nil && tc.answer != nil {
						_, _ = conn.Write(tc.answer)
					}
					return
				}
				hello := make([]byte, 1024)
				got, _ := conn.Read(hello)
				firstBytes <- hello[:got]
			})
			res := NewMSSQLProber("127.0.0.1", port, 2*time.Second, "strict").Probe(context.Background())
			if res.Passed {
				t.Fatalf("result = %+v", res)
			}
			for _, want := range tc.want {
				if !strings.Contains(res.Error, want) {
					t.Errorf("error %q lacks %q", res.Error, want)
				}
			}
			if strings.Contains(res.Error, "qga probe") {
				t.Errorf("error %q still sends the operator to a qga probe", res.Error)
			}
			if got := connections.Load(); got != 2 {
				t.Errorf("%d connections, want the cleartext attempt and one retry", got)
			}
			if request := <-firstBytes; len(request) == 0 || request[0] != tdsTypePrelogin {
				t.Errorf("first bytes sent were % x, want a cleartext TDS PRELOGIN", request[:min(len(request), 8)])
			}
			if hello := <-firstBytes; len(hello) < 5 || hello[0] != 0x16 || !strings.Contains(string(hello), "tds/8.0") {
				t.Errorf("the retry began with % x, want a TLS ClientHello offering ALPN tds/8.0", hello[:min(len(hello), 8)])
			}
		})
	}
}

// Only a server that closed on the PRELOGIN is described as one that
// may force strict encryption; a silent one is just silent.
func TestMSSQLProberDoesNotBlameStrictEncryptionForATimeout(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		if conn, err := l.Accept(); err == nil {
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn) // read the PRELOGIN, answer nothing, stay open
		}
	}()
	res := NewMSSQLProber("127.0.0.1", l.Addr().(*net.TCPAddr).Port, 300*time.Millisecond, "silent").Probe(context.Background())
	if res.Passed || !strings.Contains(res.Error, "did not answer TDS PRELOGIN") || strings.Contains(res.Error, "strict") {
		t.Fatalf("silent server result = %+v", res)
	}
}

func TestMSSQLProberFailsWhenNothingAnswers(t *testing.T) {
	port, _ := serveOnce(t, readTDSRequest, func([]byte) []byte { return nil })
	res := NewMSSQLProber("127.0.0.1", port, 2*time.Second, "silent").Probe(context.Background())
	if res.Passed || !strings.Contains(res.Error, "did not answer TDS PRELOGIN") {
		t.Fatalf("closed connection result = %+v", res)
	}
}

func TestParseTDSPreloginRejectsMalformedResponses(t *testing.T) {
	valid := tdsPreloginResponse(0x00)[tdsHeaderLen:]
	for name, payload := range map[string][]byte{
		"empty":          nil,
		"no terminator":  valid[:10],
		"offset too far": append([]byte{tdsOptionVersion, 0, 200, 0, 6, tdsOptionTerminator}, valid[11:]...),
		"short version":  {tdsOptionVersion, 0, 6, 0, 2, tdsOptionTerminator, 15, 0},
		"no version":     {tdsOptionEncryption, 0, 6, 0, 1, tdsOptionTerminator, 0},
	} {
		if _, _, err := parseTDSPrelogin(payload); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
	if version, encryption, err := parseTDSPrelogin(valid); err != nil || version != "15.0.2000.0" || encryption != "off" {
		t.Fatalf("valid response parsed as %q, %q, %v", version, encryption, err)
	}
}

// tdsPacket frames payload as one tabular-result packet.
func tdsPacket(payload []byte) []byte {
	packet := []byte{tdsTypeTabular, tdsStatusEOM, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(packet[2:], uint16(tdsHeaderLen+len(payload)))
	return append(packet, payload...)
}

// The reporter's six-byte payload is a VERSION header pointing at the
// option table itself, which the probe used to report as SQL Server version
// 0.0.0.1791.
func TestMSSQLProberRejectsAVersionDecodedFromTheOptionTable(t *testing.T) {
	payload := []byte{tdsOptionVersion, 0, 0, 0, 6, tdsOptionTerminator}
	port, _ := serveOnce(t, readTDSRequest, func([]byte) []byte { return tdsPacket(payload) })
	res := NewMSSQLProber("127.0.0.1", port, 2*time.Second, "self-referential PRELOGIN option").Probe(context.Background())
	if res.Passed || strings.Contains(res.Detail, "0.0.0.1791") || !strings.Contains(res.Error, "outside the data area") {
		t.Fatalf("result = %+v", res)
	}
}

// Option data must lie after the terminated option table, inside the
// payload, with VERSION first and no option twice or sharing bytes.
func TestParseTDSPreloginRejectsStructurallyImpossibleResponses(t *testing.T) {
	version := []byte{15, 0, 0x07, 0xd0, 0, 0}
	for name, tc := range map[string]struct {
		payload []byte
		want    string
	}{
		"version inside the table":    {[]byte{tdsOptionVersion, 0, 0, 0, 6, tdsOptionTerminator}, "outside the data area"},
		"version over the terminator": {append([]byte{tdsOptionVersion, 0, 5, 0, 6, tdsOptionTerminator}, version[:5]...), "outside the data area"},
		"encryption inside the table": {append(append([]byte{tdsOptionVersion, 0, 11, 0, 6, tdsOptionEncryption, 0, 0, 0, 1, tdsOptionTerminator}, version...), 0), "outside the data area"},
		"version twice":               {append(append([]byte{tdsOptionVersion, 0, 11, 0, 6, tdsOptionVersion, 0, 11, 0, 6, tdsOptionTerminator}, version...), 0), "appears twice"},
		"options sharing bytes":       {append([]byte{tdsOptionVersion, 0, 11, 0, 6, tdsOptionEncryption, 0, 16, 0, 1, tdsOptionTerminator}, version...), "share data bytes"},
		"two-byte encryption":         {append(append([]byte{tdsOptionVersion, 0, 11, 0, 6, tdsOptionEncryption, 0, 17, 0, 2, tdsOptionTerminator}, version...), 0, 0), "ENCRYPTION option has 2 bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseTDSPrelogin(tc.payload); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseTDSPrelogin error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// Controls: the layout SQL Server 2019 answers with (VERSION,
// ENCRYPTION, INSTOPT, an empty THREADID at the same offset as MARS, MARS)
// and an empty option at the very end of the payload both parse.
func TestParseTDSPreloginAcceptsServerLayouts(t *testing.T) {
	sqlServer2019 := []byte{
		tdsOptionVersion, 0x00, 0x1a, 0x00, 0x06,
		tdsOptionEncryption, 0x00, 0x20, 0x00, 0x01,
		0x02, 0x00, 0x21, 0x00, 0x01, // INSTOPT
		0x03, 0x00, 0x22, 0x00, 0x00, // THREADID, empty from a server
		0x04, 0x00, 0x22, 0x00, 0x01, // MARS
		tdsOptionTerminator,
		0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00, // 15.0.2000.0
		0x02, // encryption not supported
		0x00, // INSTOPT
		0x00, // MARS off
	}
	emptyAtTheEnd := []byte{
		tdsOptionVersion, 0x00, 0x0b, 0x00, 0x06,
		0x03, 0x00, 0x11, 0x00, 0x00, // THREADID, empty, at the end of the payload
		tdsOptionTerminator,
		0x10, 0x00, 0x0f, 0xa0, 0x00, 0x01, // 16.0.4000.1
	}
	// The order of the options is the server's; only their data must lie in the
	// data area. An option with no data reads nothing, so where it points is
	// immaterial.
	encryptionFirst := []byte{
		tdsOptionEncryption, 0x00, 0x10, 0x00, 0x01,
		tdsOptionVersion, 0x00, 0x11, 0x00, 0x06,
		0x03, 0x00, 0x00, 0x00, 0x00, // THREADID, empty, pointing into the option table
		tdsOptionTerminator,
		0x03,                               // encryption required
		0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00, // 15.0.2000.0
	}
	for name, tc := range map[string]struct {
		payload             []byte
		version, encryption string
	}{
		"SQL Server 2019":           {sqlServer2019, "15.0.2000.0", "not supported"},
		"empty option at the end":   {emptyAtTheEnd, "16.0.4000.1", "unknown"},
		"ENCRYPTION before VERSION": {encryptionFirst, "15.0.2000.0", "required"},
	} {
		if version, encryption, err := parseTDSPrelogin(tc.payload); err != nil || version != tc.version || encryption != tc.encryption {
			t.Errorf("%s parsed as %q, %q, %v", name, version, encryption, err)
		}
	}
	port, _ := serveOnce(t, readTDSRequest, func([]byte) []byte { return tdsPacket(sqlServer2019) })
	if res := NewMSSQLProber("127.0.0.1", port, 2*time.Second, "SQL Server 2019").Probe(context.Background()); !res.Passed {
		t.Fatalf("SQL Server 2019 layout: %+v", res)
	}
}

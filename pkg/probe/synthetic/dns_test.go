// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDNSServer answers every UDP query with reply(query). It records each
// question name so a test can prove a packet actually reached the server.
type fakeDNSServer struct {
	port      int
	mu        sync.Mutex
	questions []string
}

func (s *fakeDNSServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.questions...)
}

func startFakeDNS(t *testing.T, reply func(query []byte) [][]byte) *fakeDNSServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	server := &fakeDNSServer{port: conn.LocalAddr().(*net.UDPAddr).Port}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			query := append([]byte(nil), buf[:n]...)
			server.mu.Lock()
			server.questions = append(server.questions, questionName(query))
			server.mu.Unlock()
			for _, datagram := range reply(query) {
				_, _ = conn.WriteTo(datagram, peer)
			}
		}
	}()
	return server
}

func questionName(query []byte) string {
	var labels []string
	for off := dnsHeaderLen; off < len(query) && query[off] != 0; {
		length := int(query[off])
		labels = append(labels, string(query[off+1:off+1+length]))
		off += 1 + length
	}
	return strings.Join(labels, ".") + "."
}

// dnsResponse echoes the query's ID and question with the given rcode and
// optional A answers.
func dnsResponse(query []byte, rcode int, ips ...net.IP) []byte {
	resp := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(resp[2:], 0x8180|uint16(rcode))
	binary.BigEndian.PutUint16(resp[6:], uint16(len(ips)))
	for _, ip := range ips {
		resp = append(resp, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04)
		resp = append(resp, ip.To4()...)
	}
	return resp
}

// dcLocatorName is the question every srv test asks; "certistack.test"
// starts at offset 33 of the query, where the SRV targets point.
const dcLocatorName = "_ldap._tcp.dc._msdcs.certistack.test"

// srvResponse answers with one SRV record per target label, each target
// being "<label>.certistack.test" compressed against the question.
func srvResponse(query []byte, port uint16, labels ...string) []byte {
	resp := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(resp[2:], 0x8180)
	binary.BigEndian.PutUint16(resp[6:], uint16(len(labels)))
	for i, label := range labels {
		rdata := binary.BigEndian.AppendUint16(nil, 0)              // priority
		rdata = binary.BigEndian.AppendUint16(rdata, uint16(100*i)) // weight
		rdata = binary.BigEndian.AppendUint16(rdata, port)
		rdata = append(rdata, byte(len(label)))
		rdata = append(rdata, label...)
		rdata = append(rdata, 0xc0, 33)
		resp = append(resp, 0xc0, 0x0c, 0x00, dnsTypeSRV, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58)
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(rdata)))
		resp = append(resp, rdata...)
	}
	return resp
}

func queryType(query []byte) uint16 {
	return binary.BigEndian.Uint16(query[len(query)-4:])
}

func TestDNSProberSRVRequiresAnSRVRecord(t *testing.T) {
	var asked []uint16
	var mu sync.Mutex
	server := startFakeDNS(t, func(query []byte) [][]byte {
		mu.Lock()
		asked = append(asked, queryType(query))
		mu.Unlock()
		return [][]byte{srvResponse(query, 389, "cs-w16-dc", "cs-w19-dc")}
	})
	prober := NewDNSProber("127.0.0.1", server.port, dcLocatorName, "udp", 2*time.Second, "DC locator")
	prober.RecordType = "SRV"
	res := prober.Probe(context.Background())
	if !res.Passed {
		t.Fatalf("SRV answer failed: %s", res.Error)
	}
	for _, want := range []string{"2 SRV record(s)", "cs-w16-dc.certistack.test:389 (priority 0, weight 0)", "cs-w19-dc.certistack.test:389 (priority 0, weight 100)"} {
		if !strings.Contains(res.Detail, want) {
			t.Errorf("detail %q lacks %q", res.Detail, want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 1 || asked[0] != dnsTypeSRV {
		t.Fatalf("query types sent %v, want one SRV query", asked)
	}
}

func TestDNSProberSRVFailsOnAddressOnlyAnswers(t *testing.T) {
	server := startFakeDNS(t, func(query []byte) [][]byte {
		return [][]byte{dnsResponse(query, 0, net.IPv4(10, 0, 71, 143))}
	})
	prober := NewDNSProber("127.0.0.1", server.port, dcLocatorName, "udp", 2*time.Second, "DC locator")
	prober.RecordType = "srv"
	if res := prober.Probe(context.Background()); res.Passed || !strings.Contains(res.Error, "without an SRV record") {
		t.Fatalf("A-only answer to an SRV check = %+v", res)
	}
}

func TestDNSProberSRVTreatsARootTargetAsUnavailable(t *testing.T) {
	server := startFakeDNS(t, func(query []byte) [][]byte {
		resp := append([]byte(nil), query...)
		binary.BigEndian.PutUint16(resp[2:], 0x8180)
		binary.BigEndian.PutUint16(resp[6:], 1)
		resp = append(resp, 0xc0, 0x0c, 0x00, dnsTypeSRV, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x07)
		return [][]byte{append(resp, 0, 0, 0, 0, 0, 0, 0)} // SRV 0 0 0 .
	})
	prober := NewDNSProber("127.0.0.1", server.port, dcLocatorName, "udp", 2*time.Second, "unavailable")
	prober.RecordType = "srv"
	if res := prober.Probe(context.Background()); res.Passed || !strings.Contains(res.Error, "without an SRV record") {
		t.Fatalf("SRV target \".\" result = %+v", res)
	}
}

func TestDNSProberBoundsTheAnswersItReports(t *testing.T) {
	labels := make([]string, 200)
	for i := range labels {
		labels[i] = "dc"
	}
	server := startFakeDNS(t, func(query []byte) [][]byte {
		return [][]byte{srvResponse(query, 389, labels...)}
	})
	prober := NewDNSProber("127.0.0.1", server.port, dcLocatorName, "tcp", 2*time.Second, "many")
	prober.Transport = "udp"
	prober.RecordType = "srv"
	res := prober.Probe(context.Background())
	if !res.Passed || !strings.Contains(res.Detail, "200 SRV record(s)") || !strings.Contains(res.Detail, "(+192 more)") || len(res.Detail) > 1024 {
		t.Fatalf("detail is %d bytes: %.200q", len(res.Detail), res.Detail)
	}
}

func TestDNSProberSRVRejectsAPointerLoop(t *testing.T) {
	server := startFakeDNS(t, func(query []byte) [][]byte {
		resp := srvResponse(query, 389, "x")
		// Point the target's suffix at itself instead of at the question.
		loop := len(resp) - 4
		resp[len(resp)-2], resp[len(resp)-1] = 0xc0|byte(loop>>8), byte(loop)
		return [][]byte{resp}
	})
	prober := NewDNSProber("127.0.0.1", server.port, dcLocatorName, "udp", 2*time.Second, "loop")
	prober.RecordType = "srv"
	if res := prober.Probe(context.Background()); res.Passed || !strings.Contains(res.Error, "malformed reply") {
		t.Fatalf("pointer loop result = %+v", res)
	}
}

func TestDNSProberPassesOnlyForAnAnsweredRecord(t *testing.T) {
	server := startFakeDNS(t, func(query []byte) [][]byte {
		return [][]byte{dnsResponse(query, 0, net.IPv4(192, 0, 2, 19))}
	})
	res := NewDNSProber("127.0.0.1", server.port, "healthy.certistack.test", "udp", 2*time.Second, "record").Probe(context.Background())
	if !res.Passed || !strings.Contains(res.Detail, "192.0.2.19") {
		t.Fatalf("answered A record result = %+v", res)
	}
}

func TestDNSProberFailsWhenTheAssertedRecordIsMissing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rcode int
		want  string
	}{
		{"nxdomain", 3, "NXDOMAIN"},
		{"refused", 5, "REFUSED"},
		{"nodata", 0, "without an A or AAAA record"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := startFakeDNS(t, func(query []byte) [][]byte {
				return [][]byte{dnsResponse(query, tc.rcode)}
			})
			res := NewDNSProber("127.0.0.1", server.port, "healthy.certistack.test", "udp", 2*time.Second, tc.name).Probe(context.Background())
			if res.Passed || !strings.Contains(res.Error, tc.want) {
				t.Fatalf("%s result = %+v, want failure mentioning %q", tc.name, res, tc.want)
			}
		})
	}
}

func TestDNSProberListenerCheckQueriesTheServer(t *testing.T) {
	server := startFakeDNS(t, func(query []byte) [][]byte {
		return [][]byte{dnsResponse(query, 5)} // an authoritative-only server refuses "."
	})
	res := NewDNSProber("127.0.0.1", server.port, "", "udp", 2*time.Second, "listener").Probe(context.Background())
	if !res.Passed || !strings.Contains(res.Detail, "listener check") {
		t.Fatalf("listener check result = %+v", res)
	}
	if got := server.seen(); len(got) != 1 || got[0] != "." {
		t.Fatalf("server saw questions %v, want exactly one root query (not a local /etc/hosts lookup)", got)
	}
}

func TestDNSProberIgnoresARepliesWithTheWrongID(t *testing.T) {
	server := startFakeDNS(t, func(query []byte) [][]byte {
		spoofed := dnsResponse(query, 0, net.IPv4(203, 0, 113, 66))
		binary.BigEndian.PutUint16(spoofed, binary.BigEndian.Uint16(spoofed)+1)
		return [][]byte{spoofed, dnsResponse(query, 0, net.IPv4(192, 0, 2, 20))}
	})
	res := NewDNSProber("127.0.0.1", server.port, "healthy.certistack.test", "udp", 2*time.Second, "spoof").Probe(context.Background())
	if !res.Passed || strings.Contains(res.Detail, "203.0.113.66") || !strings.Contains(res.Detail, "192.0.2.20") {
		t.Fatalf("result = %+v, want only the reply carrying the query ID", res)
	}
}

func TestDNSProberResendsALostUDPQuery(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	server := startFakeDNS(t, func(query []byte) [][]byte {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return nil // first datagram lost
		}
		return [][]byte{dnsResponse(query, 0, net.IPv4(192, 0, 2, 21))}
	})
	res := NewDNSProber("127.0.0.1", server.port, "healthy.certistack.test", "udp", 5*time.Second, "resend").Probe(context.Background())
	if !res.Passed {
		t.Fatalf("resent query result = %+v", res)
	}
	if len(server.seen()) < 2 {
		t.Fatalf("server saw %d queries, want a re-send after the lost datagram", len(server.seen()))
	}
}

func TestParseDNSReplyRejectsMalformedMessages(t *testing.T) {
	query, _, err := buildDNSQuery("healthy.certistack.test", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	good := dnsResponse(query, 0, net.IPv4(192, 0, 2, 19))
	for name, msg := range map[string][]byte{
		"short":        good[:5],
		"not-response": func() []byte { m := append([]byte(nil), good...); m[2] &^= 0x80; return m }(),
		"truncated-rr": good[:len(good)-2],
	} {
		if _, err := parseDNSReply(msg, query); err == nil {
			t.Errorf("%s: parseDNSReply accepted a malformed message", name)
		}
	}
}

// dnsRR encodes one resource record: owner (already wire-encoded, possibly a
// compression pointer), type, class, a 300-second TTL, and data.
func dnsRR(owner []byte, rrType, class uint16, data []byte) []byte {
	rr := append([]byte(nil), owner...)
	rr = binary.BigEndian.AppendUint16(rr, rrType)
	rr = binary.BigEndian.AppendUint16(rr, class)
	rr = binary.BigEndian.AppendUint32(rr, 300)
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(data)))
	return append(rr, data...)
}

// dnsWireName encodes a dotted name without compression.
func dnsWireName(name string) []byte {
	var wire []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label != "" {
			wire = append(append(wire, byte(len(label))), label...)
		}
	}
	return append(wire, 0)
}

// dnsReplyWith answers query with NOERROR (recursion available), its
// question echoed, and the given answer, authority and additional records.
func dnsReplyWith(query []byte, answers, authority, additional [][]byte) []byte {
	resp := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(resp[2:], 0x8180)
	binary.BigEndian.PutUint16(resp[6:], uint16(len(answers)))
	binary.BigEndian.PutUint16(resp[8:], uint16(len(authority)))
	binary.BigEndian.PutUint16(resp[10:], uint16(len(additional)))
	for _, section := range [][][]byte{answers, authority, additional} {
		for _, rr := range section {
			resp = append(resp, rr...)
		}
	}
	return resp
}

var questionPointer = []byte{0xc0, dnsHeaderLen} // the question name, as servers compress it

// A reply that carries the right transaction ID must still answer the question
// asked. None of these replies may report that expected.test resolved to
// 192.0.2.77.
func TestDNSProberRejectsAnswersToAnotherQuestion(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		reply      func(query []byte) []byte
	}{
		{"different question", "not the question asked", func(query []byte) []byte {
			other, _, err := buildDNSQuery("wrong.test", dnsTypeA)
			if err != nil {
				t.Error(err)
			}
			copy(other, query[:2])
			return dnsResponse(other, 0, net.ParseIP("192.0.2.77"))
		}},
		{"different answer owner", "without an A or AAAA record", func(query []byte) []byte {
			return dnsReplyWith(query, [][]byte{dnsRR(dnsWireName("wrong.test"), dnsTypeA, dnsClassIN, []byte{192, 0, 2, 77})}, nil, nil)
		}},
		{"answer in class CHAOS", "without an A or AAAA record", func(query []byte) []byte {
			return dnsReplyWith(query, [][]byte{dnsRR(questionPointer, dnsTypeA, 3, []byte{192, 0, 2, 77})}, nil, nil)
		}},
		{"owner pointer outside the message", "malformed reply", func(query []byte) []byte {
			return dnsReplyWith(query, [][]byte{dnsRR([]byte{0xff, 0xff}, dnsTypeA, dnsClassIN, []byte{192, 0, 2, 77})}, nil, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := startFakeDNS(t, func(query []byte) [][]byte {
				if queryType(query) != dnsTypeA {
					return [][]byte{dnsResponse(query, 0)} // no AAAA either
				}
				return [][]byte{tc.reply(query)}
			})
			res := NewDNSProber("127.0.0.1", server.port, "expected.test", "udp", 2*time.Second, tc.name).Probe(context.Background())
			if res.Passed || strings.Contains(res.Detail, "192.0.2.77") || !strings.Contains(res.Error, tc.want) {
				t.Fatalf("result = %+v, want a failure mentioning %q", res, tc.want)
			}
		})
	}
}

// Malformed and inconsistent replies fail instead of passing on
// whatever address-shaped data they hold.
func TestParseDNSReplyRejectsInconsistentReplies(t *testing.T) {
	query, _, err := buildDNSQuery("healthy.certistack.test", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	address := []byte{192, 0, 2, 19}
	withFlags := func(flags uint16) []byte {
		m := dnsResponse(query, 0, net.IPv4(192, 0, 2, 19))
		binary.BigEndian.PutUint16(m[2:], flags)
		return m
	}
	withQuestionCount := func(count uint16) []byte {
		m := dnsResponse(query, 0, net.IPv4(192, 0, 2, 19))
		binary.BigEndian.PutUint16(m[4:], count)
		return m
	}
	answerAt := func(owner []byte, data []byte) []byte {
		return dnsReplyWith(query, [][]byte{dnsRR(owner, dnsTypeA, dnsClassIN, data)}, nil, nil)
	}
	for name, tc := range map[string]struct {
		msg  []byte
		want string
	}{
		"opcode differs":   {withFlags(0x8980), "opcode"},
		"unassigned rcode": {withFlags(0x818c), "RCODE 12"},
		"two questions":    {withQuestionCount(2), "2 questions"},
		"noerror without question": {func() []byte {
			m := append([]byte(nil), query[:dnsHeaderLen]...)
			binary.BigEndian.PutUint16(m[2:], 0x8180)
			binary.BigEndian.PutUint16(m[4:], 0)
			return m
		}(), "does not repeat the question"},
		"question type differs": {func() []byte {
			m := dnsResponse(query, 0)
			binary.BigEndian.PutUint16(m[len(query)-4:], dnsTypeAAAA)
			return m
		}(), "not the question asked"},
		"forward pointer":           {answerAt([]byte{0xc0, byte(len(query) + 20)}, address), "does not point back"},
		"pointer into the header":   {answerAt([]byte{0xc0, 0x02}, address), "does not point back"},
		"pointer to itself":         {answerAt([]byte{0xc0, byte(len(query))}, address), "does not point back"},
		"A record of five bytes":    {answerAt(questionPointer, []byte{192, 0, 2, 19, 1}), "5 bytes"},
		"truncated additional":      {dnsReplyWith(query, [][]byte{dnsRR(questionPointer, dnsTypeA, dnsClassIN, address)}, nil, [][]byte{dnsRR(questionPointer, dnsTypeA, dnsClassIN, address)[:8]}), "additional record 1"},
		"cname loop":                {dnsReplyWith(query, [][]byte{dnsRR(questionPointer, dnsTypeCNAME, dnsClassIN, dnsWireName("a.certistack.test")), dnsRR(dnsWireName("a.certistack.test"), dnsTypeCNAME, dnsClassIN, dnsWireName("healthy.certistack.test"))}, nil, nil), "loops"},
		"conflicting cnames":        {dnsReplyWith(query, [][]byte{dnsRR(questionPointer, dnsTypeCNAME, dnsClassIN, dnsWireName("a.certistack.test")), dnsRR(questionPointer, dnsTypeCNAME, dnsClassIN, dnsWireName("b.certistack.test"))}, nil, nil), "conflicting CNAME"},
		"cname with trailing bytes": {dnsReplyWith(query, [][]byte{dnsRR(questionPointer, dnsTypeCNAME, dnsClassIN, append(dnsWireName("a.certistack.test"), 0))}, nil, nil), "data after its target"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDNSReply(tc.msg, query); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseDNSReply error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// Controls: the shapes real servers (BIND, Unbound, dnsmasq, Windows
// DNS) answer with still pass, and only records for the question count.
func TestParseDNSReplyAcceptsRealServerShapes(t *testing.T) {
	query, _, err := buildDNSQuery("www.certistack.test", dnsTypeA)
	if err != nil {
		t.Fatal(err)
	}
	web := dnsWireName("web.certistack.test")
	for name, tc := range map[string]struct {
		msg        []byte
		addrs      string
		chain      string
		truncated  bool
		rcode      int
		noQuestion bool
	}{
		"compressed owner": {msg: dnsResponse(query, 0, net.IPv4(192, 0, 2, 19)), addrs: "192.0.2.19"},
		"uncompressed owner": {msg: dnsReplyWith(query, [][]byte{dnsRR(dnsWireName("www.certistack.test"), dnsTypeA, dnsClassIN, []byte{192, 0, 2, 20})}, nil, nil),
			addrs: "192.0.2.20"},
		"owner in another case (0x20)": {msg: func() []byte {
			m := dnsReplyWith(query, [][]byte{dnsRR(dnsWireName("WWW.CertiStack.TEST"), dnsTypeA, dnsClassIN, []byte{192, 0, 2, 21})}, nil, nil)
			copy(m[dnsHeaderLen:], dnsWireName("wWw.cErTiStAcK.tEsT")) // question echoed in the case a forwarder sent
			return m
		}(), addrs: "192.0.2.21"},
		// www -> web (compressed against the question) -> A, as a recursive
		// server answers an alias; the authority and additional sections
		// carry an NS and its glue, which answer nothing.
		"cname chain with authority and glue": {msg: dnsReplyWith(query,
			[][]byte{
				dnsRR(questionPointer, dnsTypeCNAME, dnsClassIN, append([]byte{3, 'w', 'e', 'b'}, 0xc0, dnsHeaderLen+4)),
				dnsRR([]byte{0xc0, byte(len(query) + 12)}, dnsTypeA, dnsClassIN, []byte{192, 0, 2, 22}),
				dnsRR(questionPointer, dnsTypeA, dnsClassIN, []byte{192, 0, 2, 66}), // an A beside a CNAME answers nothing
			},
			[][]byte{dnsRR([]byte{0xc0, dnsHeaderLen + 4}, dnsTypeNS, dnsClassIN, dnsWireName("ns1.certistack.test"))},
			[][]byte{dnsRR(dnsWireName("ns1.certistack.test"), dnsTypeA, dnsClassIN, []byte{192, 0, 2, 2})},
		), addrs: "192.0.2.22", chain: "web.certistack.test"},
		"cname chain, target uncompressed": {msg: dnsReplyWith(query, [][]byte{
			dnsRR(questionPointer, dnsTypeCNAME, dnsClassIN, web),
			dnsRR(web, dnsTypeA, dnsClassIN, []byte{192, 0, 2, 23}),
		}, nil, nil), addrs: "192.0.2.23", chain: "web.certistack.test"},
		"refused without the question": {msg: func() []byte {
			m := append([]byte(nil), query[:dnsHeaderLen]...)
			binary.BigEndian.PutUint16(m[2:], 0x8105)
			binary.BigEndian.PutUint16(m[4:], 0)
			return m
		}(), rcode: 5, noQuestion: true},
		"truncated after the answer": {msg: func() []byte {
			m := dnsReplyWith(query, [][]byte{dnsRR(questionPointer, dnsTypeA, dnsClassIN, []byte{192, 0, 2, 24})}, nil, nil)
			binary.BigEndian.PutUint16(m[2:], 0x8380)
			binary.BigEndian.PutUint16(m[10:], 3) // additional records that did not fit
			return m
		}(), addrs: "192.0.2.24", truncated: true},
	} {
		t.Run(name, func(t *testing.T) {
			reply, err := parseDNSReply(tc.msg, query)
			if err != nil {
				t.Fatalf("parseDNSReply: %v", err)
			}
			if got := strings.Join(reply.addrs, ","); got != tc.addrs {
				t.Errorf("addresses %q, want %q", got, tc.addrs)
			}
			if got := strings.Join(reply.chain, ","); got != tc.chain {
				t.Errorf("CNAME chain %q, want %q", got, tc.chain)
			}
			if reply.truncated != tc.truncated || reply.rcode != tc.rcode {
				t.Errorf("reply = %+v", reply)
			}
		})
	}
}

// An address record for a name the CNAME chain does not reach is
// not an answer.
func TestDNSProberFollowsTheCNAMEChainOnly(t *testing.T) {
	server := startFakeDNS(t, func(query []byte) [][]byte {
		// The same alias answers the A query and the AAAA query after it.
		return [][]byte{dnsReplyWith(query, [][]byte{
			dnsRR(questionPointer, dnsTypeCNAME, dnsClassIN, dnsWireName("web.certistack.test")),
			dnsRR(dnsWireName("other.certistack.test"), dnsTypeA, dnsClassIN, []byte{192, 0, 2, 30}),
		}, nil, nil)}
	})
	res := NewDNSProber("127.0.0.1", server.port, "www.certistack.test", "udp", 2*time.Second, "alias").Probe(context.Background())
	if res.Passed || !strings.Contains(res.Error, "via CNAME web.certistack.test without an A or AAAA record") {
		t.Fatalf("result = %+v", res)
	}

	chained := startFakeDNS(t, func(query []byte) [][]byte {
		return [][]byte{dnsReplyWith(query, [][]byte{
			dnsRR(questionPointer, dnsTypeCNAME, dnsClassIN, dnsWireName("web.certistack.test")),
			dnsRR(dnsWireName("web.certistack.test"), dnsTypeA, dnsClassIN, []byte{192, 0, 2, 31}),
		}, nil, nil)}
	})
	res = NewDNSProber("127.0.0.1", chained.port, "www.certistack.test", "udp", 2*time.Second, "alias").Probe(context.Background())
	if !res.Passed || !strings.Contains(res.Detail, "resolved www.certistack.test via CNAME web.certistack.test to 192.0.2.31") {
		t.Fatalf("result = %+v", res)
	}
}

// The documented "A or AAAA record" holds for a name with only AAAA records:
// the A query answers NOERROR with no data, and the probe then asks for AAAA.
func TestDNSProberAsksForAAAAWhenTheNameHasNoA(t *testing.T) {
	var mu sync.Mutex
	var types []uint16
	server := startFakeDNS(t, func(query []byte) [][]byte {
		mu.Lock()
		types = append(types, queryType(query))
		mu.Unlock()
		if queryType(query) == dnsTypeAAAA {
			return [][]byte{dnsReplyWith(query, [][]byte{dnsRR(questionPointer, dnsTypeAAAA, dnsClassIN, net.ParseIP("fd00:70::19"))}, nil, nil)}
		}
		return [][]byte{dnsResponse(query, 0)}
	})
	res := NewDNSProber("127.0.0.1", server.port, "v6only.certistack.test", "udp", 2*time.Second, "aaaa").Probe(context.Background())
	if !res.Passed || !strings.Contains(res.Detail, "fd00:70::19") {
		t.Fatalf("result = %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(types) != 2 || types[0] != dnsTypeA || types[1] != dnsTypeAAAA {
		t.Fatalf("query types %v, want A then AAAA", types)
	}
}

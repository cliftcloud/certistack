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

// startFakeDNSTCP answers every TCP query with the chunks reply(query)
// returns, written one after another with a pause between them so the client
// reads each separately. A test frames its own bytes, length prefix included.
func startFakeDNSTCP(t *testing.T, reply func(query []byte) [][]byte) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				for _, chunk := range reply(query) {
					if _, err := conn.Write(chunk); err != nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
			}(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func tcpFrame(message []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(message))), message...)
}

// dnsRootReply is a reply to the listener's root NS query: it
// copies the transaction ID and carries the response bit and NOERROR, declares
// QDCOUNT = qd and the given record counts, and then holds exactly body.
func dnsRootReply(query []byte, qd, an, ns, ar uint16, body ...byte) []byte {
	reply := make([]byte, dnsHeaderLen, dnsHeaderLen+len(body))
	copy(reply, query[:2])
	binary.BigEndian.PutUint16(reply[2:], 0x8180) // response, recursion desired and available, NOERROR
	binary.BigEndian.PutUint16(reply[4:], qd)
	binary.BigEndian.PutUint16(reply[6:], an)
	binary.BigEndian.PutUint16(reply[8:], ns)
	binary.BigEndian.PutUint16(reply[10:], ar)
	return append(reply, body...)
}

// rootNSQuestion is the question the listener check asks: the root name, NS, IN.
var rootNSQuestion = []byte{0, 0, dnsTypeNS, 0, dnsClassIN}

func dnsQuestion(name []byte, qtype, qclass uint16) []byte {
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(append([]byte(nil), name...), qtype), qclass)
}

// The listener check passes only on a structurally complete reply, over UDP
// and TCP; none of these may count as an answer to the root NS query.
func TestDNSListenerRejectsStructurallyIncompleteReplies(t *testing.T) {
	root := []byte{0}
	complete := dnsQuestion(root, dnsTypeNS, dnsClassIN)
	for _, tc := range []struct {
		name, want string
		reply      func(query []byte) []byte
	}{
		{"question without its type and class", "question is truncated", func(q []byte) []byte { return dnsRootReply(q, 1, 0, 0, 0, root...) }},
		{"question with one type octet", "question is truncated", func(q []byte) []byte { return dnsRootReply(q, 1, 0, 0, 0, append(root, 0)...) }},
		{"question with a type only", "question is truncated", func(q []byte) []byte { return dnsRootReply(q, 1, 0, 0, 0, append(root, 0, dnsTypeNS)...) }},
		{"question missing its last octet", "question is truncated", func(q []byte) []byte { return dnsRootReply(q, 1, 0, 0, 0, complete[:len(complete)-1]...) }},
		{"authority record declared, none present", "authority record 1", func(q []byte) []byte { return dnsRootReply(q, 1, 0, 1, 0, complete...) }},
		{"additional record declared, none present", "additional record 1", func(q []byte) []byte { return dnsRootReply(q, 1, 0, 0, 1, complete...) }},
		{"answer declared, none present", "answer record 1", func(q []byte) []byte { return dnsRootReply(q, 1, 1, 0, 0, complete...) }},
		{"undeclared trailing octet", "1 bytes after its last counted record", func(q []byte) []byte { return dnsRootReply(q, 1, 0, 0, 0, append(complete, 0x42)...) }},
		{"a second question the header does not count", "5 bytes after its last counted record", func(q []byte) []byte { return dnsRootReply(q, 1, 0, 0, 0, append(complete, complete...)...) }},
		{"no question", "does not repeat the question", func(q []byte) []byte { return dnsRootReply(q, 0, 0, 0, 0) }},
		{"two questions", "2 questions", func(q []byte) []byte { return dnsRootReply(q, 2, 0, 0, 0, append(complete, complete...)...) }},
		{"question for another type", "not the question asked", func(q []byte) []byte { return dnsRootReply(q, 1, 0, 0, 0, dnsQuestion(root, dnsTypeA, dnsClassIN)...) }},
		{"question in another class", "not the question asked", func(q []byte) []byte { return dnsRootReply(q, 1, 0, 0, 0, dnsQuestion(root, dnsTypeNS, 3)...) }},
		{"question for another name", "not the question asked", func(q []byte) []byte {
			return dnsRootReply(q, 1, 0, 0, 0, dnsQuestion(dnsWireName("example.test"), dnsTypeNS, dnsClassIN)...)
		}},
		{"question name that is a pointer to itself", "does not point back", func(q []byte) []byte {
			return dnsRootReply(q, 1, 0, 0, 0, dnsQuestion([]byte{0xc0, dnsHeaderLen}, dnsTypeNS, dnsClassIN)...)
		}},
	} {
		for _, transport := range []string{"udp", "tcp"} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				var port int
				if transport == "udp" {
					port = startFakeDNS(t, func(query []byte) [][]byte { return [][]byte{tc.reply(query)} }).port
				} else {
					port = startFakeDNSTCP(t, func(query []byte) [][]byte { return [][]byte{tcpFrame(tc.reply(query))} })
				}
				res := NewDNSProber("127.0.0.1", port, "", transport, 2*time.Second, tc.name).Probe(context.Background())
				if res.Passed || !strings.Contains(res.Error, "malformed reply") || !strings.Contains(res.Error, tc.want) {
					t.Fatalf("result = %+v, want a malformed-reply failure mentioning %q", res, tc.want)
				}
			})
		}
	}
}

// Controls: what real servers answer to the root NS query still
// passes, however the bytes arrive.
func TestDNSListenerAcceptsCompleteReplies(t *testing.T) {
	root := []byte{0}
	complete := dnsQuestion(root, dnsTypeNS, dnsClassIN)
	// A recursive server's priming answer: three root servers, their names
	// compressed against the first, and glue in the additional section.
	pointerTo := func(offset int) []byte { return []byte{0xc0, byte(offset)} }
	priming := func(q []byte) []byte {
		reply := dnsRootReply(q, 1, 3, 0, 1, complete...)
		// The first record's data starts after its owner (the root name), type,
		// class, TTL and data length; "root-servers.net" starts after its "a".
		first := len(reply) + len(root) + 2 + 2 + 4 + 2
		reply = append(reply, dnsRR(root, dnsTypeNS, dnsClassIN, dnsWireName("a.root-servers.net"))...)
		reply = append(reply, dnsRR(root, dnsTypeNS, dnsClassIN, append([]byte{1, 'b'}, pointerTo(first+2)...))...)
		reply = append(reply, dnsRR(root, dnsTypeNS, dnsClassIN, append([]byte{1, 'c'}, pointerTo(first+2)...))...)
		return append(reply, dnsRR(pointerTo(first), dnsTypeA, dnsClassIN, []byte{198, 41, 0, 4})...)
	}
	refused := func(q []byte) []byte { // an authoritative-only server refusing "."
		reply := dnsRootReply(q, 1, 0, 0, 0, complete...)
		binary.BigEndian.PutUint16(reply[2:], 0x8105)
		return reply
	}
	formerr := func(q []byte) []byte { // a header-only FORMERR, which some servers send
		reply := dnsRootReply(q, 0, 0, 0, 0)
		binary.BigEndian.PutUint16(reply[2:], 0x8101)
		return reply
	}
	withOPT := func(q []byte) []byte { // an EDNS(0) OPT record is a counted additional record
		return append(dnsRootReply(q, 1, 0, 0, 1, complete...), dnsRR(root, 41, 1232, nil)...)
	}
	for _, tc := range []struct {
		name  string
		reply func(query []byte) []byte
	}{
		{"one complete question and nothing else", func(q []byte) []byte { return dnsRootReply(q, 1, 0, 0, 0, complete...) }},
		{"priming answer with compressed names and glue", priming},
		{"refused, question repeated", refused},
		{"format error without a question", formerr},
		{"EDNS OPT record", withOPT},
	} {
		for _, transport := range []string{"udp", "tcp"} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				var port int
				if transport == "udp" {
					port = startFakeDNS(t, func(query []byte) [][]byte { return [][]byte{tc.reply(query)} }).port
				} else {
					port = startFakeDNSTCP(t, func(query []byte) [][]byte { return [][]byte{tcpFrame(tc.reply(query))} })
				}
				res := NewDNSProber("127.0.0.1", port, "", transport, 2*time.Second, tc.name).Probe(context.Background())
				if !res.Passed {
					t.Fatalf("result = %+v", res)
				}
			})
		}
	}
}

// A TCP reply arrives in as many segments as the network makes of it: the
// length prefix alone, then the message in pieces, and the probe reads the
// whole of it. A frame cut short by the server closing fails.
func TestDNSTCPReplyIsReadWhenSplitAndRejectedWhenCutShort(t *testing.T) {
	complete := dnsQuestion([]byte{0}, dnsTypeNS, dnsClassIN)
	whole := func(q []byte) []byte { return dnsRootReply(q, 1, 0, 0, 0, complete...) }
	port := startFakeDNSTCP(t, func(q []byte) [][]byte {
		frame := tcpFrame(whole(q))
		return [][]byte{frame[:1], frame[1:2], frame[2:9], frame[9:]}
	})
	if res := NewDNSProber("127.0.0.1", port, "", "tcp", 2*time.Second, "split").Probe(context.Background()); !res.Passed {
		t.Fatalf("split reply result = %+v", res)
	}

	port = startFakeDNSTCP(t, func(q []byte) [][]byte {
		frame := tcpFrame(whole(q))
		return [][]byte{frame[:len(frame)-3]} // the server closes with 3 octets outstanding
	})
	res := NewDNSProber("127.0.0.1", port, "", "tcp", 2*time.Second, "cut short").Probe(context.Background())
	if res.Passed || !strings.Contains(res.Error, "failed") {
		t.Fatalf("cut-short reply result = %+v", res)
	}

	port = startFakeDNSTCP(t, func(q []byte) [][]byte { return [][]byte{{0, 0}} }) // a zero-length message
	res = NewDNSProber("127.0.0.1", port, "", "tcp", 2*time.Second, "empty").Probe(context.Background())
	if res.Passed || !strings.Contains(res.Error, "shorter than a DNS header") {
		t.Fatalf("empty reply result = %+v", res)
	}
}

// Hold for a name assertion too: an answer record cut short after the counted
// ones, or a message with bytes after its last record, is not a resolution.
func TestDNSAssertedNameNeedsACompleteReply(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		reply      func(query []byte) []byte
	}{
		{"trailing octet", "after its last counted record", func(q []byte) []byte {
			return append(dnsResponse(q, 0, net.IPv4(10, 0, 70, 19)), 0x42)
		}},
		{"authority declared, none present", "authority record 1", func(q []byte) []byte {
			reply := dnsResponse(q, 0, net.IPv4(10, 0, 70, 19))
			binary.BigEndian.PutUint16(reply[8:], 1)
			return reply
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := startFakeDNS(t, func(query []byte) [][]byte { return [][]byte{tc.reply(query)} })
			res := NewDNSProber("127.0.0.1", server.port, "healthy.certistack.test", "udp", 2*time.Second, tc.name).Probe(context.Background())
			if res.Passed || !strings.Contains(res.Error, tc.want) {
				t.Fatalf("result = %+v, want a failure mentioning %q", res, tc.want)
			}
		})
	}
}

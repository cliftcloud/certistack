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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/internal/ldapdn"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// DNSProber sends one DNS query directly to the target server over UDP or TCP.
//
// The query is built and parsed here instead of going through net.Resolver:
// the Go resolver consults the worker's /etc/hosts and search domains first,
// so a name such as "localhost" would "resolve" without a single packet
// reaching the restored guest.
type DNSProber struct {
	TargetIP    string
	Port        int
	QueryDomain string // empty: listener check only, any well-formed reply passes
	// RecordType is "srv" to require SRV records for QueryDomain; anything
	// else requires an A or AAAA answer.
	RecordType  string
	Transport   string
	Timeout     time.Duration
	Description string
	Source      Source
}

// NewDNSProber creates a DNS service prober. With a domain, the probe passes
// only when the server answers NOERROR with at least one A or AAAA record for
// it (directly or at the end of a CNAME chain). Without one it is a listener
// check: any well-formed reply to the root NS query passes.
func NewDNSProber(targetIP string, port int, domain, transport string, timeout time.Duration, desc string) *DNSProber {
	if port <= 0 {
		port = 53
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport = strings.ToLower(strings.TrimSpace(transport))
	if transport == "" {
		transport = "udp"
	}
	return &DNSProber{
		TargetIP:    targetIP,
		Port:        port,
		QueryDomain: strings.TrimSpace(domain),
		Transport:   transport,
		Timeout:     timeout,
		Description: desc,
	}
}

const (
	dnsTypeA      = 1
	dnsTypeNS     = 2
	dnsTypeCNAME  = 5
	dnsTypeAAAA   = 28
	dnsTypeSRV    = 33
	dnsClassIN    = 1
	dnsHeaderLen  = 12
	dnsUDPResend  = 2 * time.Second
	dnsMaxMessage = 65535
	// dnsMaxCNAMEChain bounds how many CNAMEs a reply may chain from the
	// question name; recursive servers stop following well before this.
	dnsMaxCNAMEChain = 16
)

// dnsRcodeNames holds every RCODE a server can put in the header of a reply
// to a standard query (RFC 1035, RFC 2136, RFC 2845; YXDOMAIN also answers a
// query whose DNAME substitution overflows, RFC 6672). Anything else in the
// four-bit field is not a valid reply.
var dnsRcodeNames = map[int]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
	6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}

var dnsTypeNames = map[uint16]string{dnsTypeA: "A", dnsTypeNS: "NS", dnsTypeCNAME: "CNAME", dnsTypeAAAA: "AAAA", dnsTypeSRV: "SRV"}

func dnsTypeName(rrType uint16) string {
	if name, ok := dnsTypeNames[rrType]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", rrType)
}

func dnsRcodeName(rcode int) string {
	if name, ok := dnsRcodeNames[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE %d", rcode)
}

// Probe dispatches a DNS query to the target nameserver and validates the reply.
func (p *DNSProber) Probe(ctx context.Context) (res probe.Result) {
	start := time.Now()
	addr := net.JoinHostPort(p.TargetIP, strconv.Itoa(p.Port))

	res = probe.Result{
		Type:        "dns",
		Target:      fmt.Sprintf("%s://%s", p.Transport, addr),
		Description: p.Description,
	}
	p.Source.annotate(&res)

	srv := strings.EqualFold(p.RecordType, "srv")
	name, qtype := p.QueryDomain, uint16(dnsTypeA)
	if srv {
		qtype = dnsTypeSRV
	}
	if name == "" {
		name, qtype = ".", dnsTypeNS
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	defer func() { res = finishProbe(ctxTimeout, res) }()
	reply, failure := p.ask(ctxTimeout, addr, name, qtype)
	res.Duration = time.Since(start)
	if failure != "" {
		res.Error = failure
		return res
	}

	if p.QueryDomain == "" {
		res.Passed = true
		res.Detail = fmt.Sprintf("DNS server at %s over %s answered a root NS query with %s in %v (listener check; no domain asserted)",
			addr, p.Transport, dnsRcodeName(reply.rcode), res.Duration)
		return res
	}
	if !srv && reply.rcode == 0 && len(reply.addrs) == 0 && !reply.truncated {
		// The query asked for A records, and a name that has only AAAA
		// records answers that with NOERROR and no data. Ask for AAAA
		// before failing, within the same deadline.
		aaaa, aaaaFailure := p.ask(ctxTimeout, addr, name, dnsTypeAAAA)
		res.Duration = time.Since(start)
		switch {
		case aaaaFailure != "":
			res.Error = fmt.Sprintf("DNS server at %s answered NOERROR for %s without an A record, and the AAAA query failed: %s", addr, p.QueryDomain, aaaaFailure)
			return res
		case aaaa.rcode != 0:
			res.Error = fmt.Sprintf("DNS server at %s answered NOERROR for %s without an A record, and %s to the AAAA query", addr, p.QueryDomain, dnsRcodeName(aaaa.rcode))
			return res
		}
		reply = aaaa
	}
	answers, wanted := reply.addrs, "an A or AAAA record"
	if srv {
		answers, wanted = reply.srv, "an SRV record"
	}
	via := ""
	if len(reply.chain) > 0 {
		via = " via CNAME " + listForReport(reply.chain, " -> ")
	}
	switch {
	case reply.rcode != 0:
		res.Error = fmt.Sprintf("DNS server at %s answered %s for %s", addr, dnsRcodeName(reply.rcode), p.QueryDomain)
	case len(answers) == 0 && reply.truncated:
		res.Error = fmt.Sprintf("DNS reply for %s from %s was truncated with no usable answer; use transport tcp", p.QueryDomain, addr)
	case len(answers) == 0:
		res.Error = fmt.Sprintf("DNS server at %s answered NOERROR for %s%s without %s", addr, p.QueryDomain, via, wanted)
	case srv:
		res.Passed = true
		res.Detail = fmt.Sprintf("DNS server at %s over %s returned %d SRV record(s) for %s%s: %s in %v",
			addr, p.Transport, len(answers), p.QueryDomain, via, listForReport(answers, "; "), res.Duration)
	default:
		res.Passed = true
		res.Detail = fmt.Sprintf("DNS server at %s over %s resolved %s%s to %s in %v",
			addr, p.Transport, p.QueryDomain, via, listForReport(answers, ", "), res.Duration)
	}
	return res
}

// ask sends one query for name and validates the reply against it. The
// returned message is the probe error when the exchange fails.
func (p *DNSProber) ask(ctx context.Context, addr, name string, qtype uint16) (dnsReply, string) {
	query, id, err := buildDNSQuery(name, qtype)
	if err != nil {
		return dnsReply{}, fmt.Sprintf("build DNS query for %q: %v", name, err)
	}
	raw, err := exchangeDNS(ctx, p.Source, p.Transport, addr, query, id)
	if err != nil {
		return dnsReply{}, fmt.Sprintf("DNS query to %s over %s failed: %v", addr, p.Transport, err)
	}
	reply, err := parseDNSReply(raw, query)
	if err != nil {
		return dnsReply{}, fmt.Sprintf("DNS server at %s returned a malformed reply: %v", addr, err)
	}
	return reply, ""
}

// maxReportedAnswers bounds how many server-supplied answers a probe result
// lists. A 64 KiB reply can hold thousands of compressed records, each of
// which would otherwise expand into the report.
const maxReportedAnswers = 8

func listForReport(answers []string, separator string) string {
	if len(answers) <= maxReportedAnswers {
		return strings.Join(answers, separator)
	}
	return fmt.Sprintf("%s%s(+%d more)", strings.Join(answers[:maxReportedAnswers], separator), separator, len(answers)-maxReportedAnswers)
}

func buildDNSQuery(name string, qtype uint16) ([]byte, uint16, error) {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, 0, fmt.Errorf("generate query id: %w", err)
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	msg := make([]byte, dnsHeaderLen, dnsHeaderLen+len(name)+6)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(msg[4:], 1)      // QDCOUNT
	if trimmed := strings.TrimSuffix(name, "."); trimmed != "" {
		if len(trimmed) > 253 {
			return nil, 0, errors.New("name exceeds 253 octets")
		}
		for _, label := range strings.Split(trimmed, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, 0, fmt.Errorf("invalid label %q", label)
			}
			msg = append(msg, byte(len(label)))
			msg = append(msg, label...)
		}
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	return msg, id, nil
}

// exchangeDNS sends the query and returns the first reply carrying its ID.
// UDP queries are re-sent every few seconds until the deadline because a
// single datagram (or reply) may be lost while the guest is still booting.
// A guest that is up but has no DNS server listening yet answers a datagram
// with ICMP port unreachable, and one that is not up yet leaves its address
// unresolved (host unreachable); the connected socket reports either as an
// error on its next read or write. Both are the same state as a lost datagram,
// so the query is re-sent through them, and the last such error is what the
// probe reports if no server ever answered.
func exchangeDNS(ctx context.Context, source Source, transport, addr string, query []byte, id uint16) ([]byte, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	dialer, err := source.dialer(transport, 0)
	if err != nil {
		return nil, err
	}
	conn, err := dialer.DialContext(ctx, transport, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer interruptOnCancel(ctx, conn)()
	_ = conn.SetDeadline(deadline)

	if transport == "tcp" {
		framed := binary.BigEndian.AppendUint16(make([]byte, 0, len(query)+2), uint16(len(query)))
		if _, err := conn.Write(append(framed, query...)); err != nil {
			return nil, err
		}
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return nil, err
		}
		reply := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return nil, err
		}
		return reply, nil
	}

	return exchangeUDP(conn, deadline, query, id)
}

// exchangeUDP is the UDP half of exchangeDNS on a connected socket: it sends
// the query, re-sends it every dnsUDPResend, and returns the first reply that
// carries id, until deadline. Errors that mean "nothing there yet" (see
// isUDPNotThereYet) do not end it.
func exchangeUDP(conn net.Conn, deadline time.Time, query []byte, id uint16) ([]byte, error) {
	buf := make([]byte, dnsMaxMessage)
	var unreachable error // the last "not there yet" error, the evidence if nothing answers
	for {
		if _, err := conn.Write(query); err != nil {
			if !isUDPNotThereYet(err) {
				return nil, err
			}
			unreachable = err // the datagram was not sent; the read below waits for the next slot
		}
		readUntil := time.Now().Add(dnsUDPResend)
		if readUntil.After(deadline) {
			readUntil = deadline
		}
		_ = conn.SetReadDeadline(readUntil)
	read:
		for {
			n, err := conn.Read(buf)
			if err != nil {
				var netErr net.Error
				timeout := errors.As(err, &netErr) && netErr.Timeout()
				switch {
				case isUDPNotThereYet(err):
					// Reported once per ICMP message: the next read waits for an
					// answer or for the next send slot, so this cannot spin.
					unreachable = err
					continue
				case timeout && time.Now().Before(deadline):
					break read // re-send
				case timeout && unreachable != nil:
					return nil, fmt.Errorf("%w (the network refused or could not deliver the datagrams until the deadline, so no DNS server was reachable)", unreachable)
				}
				return nil, err
			}
			if n >= 2 && binary.BigEndian.Uint16(buf) == id {
				return append([]byte(nil), buf[:n]...), nil
			}
			// A stale or spoofed datagram: keep waiting for our reply.
		}
	}
}

// isUDPNotThereYet reports whether err is what a connected UDP socket returns
// when an earlier datagram found nothing to answer it: "connection refused"
// (ICMP port unreachable: the host is up, nothing listens on the port yet) or
// "no route to host" / "host is down" (its address is not resolved yet), and
// the network-unreachable variant. It is not a failure of this machine's own
// socket, firewall or permissions, which stay errors. The Winsock numbers are
// listed because the Go runtime's own constants do not match them on Windows.
func isUDPNotThereYet(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.EHOSTDOWN, syscall.ENETUNREACH:
		return true
	}
	switch uintptr(errno) {
	case 10061, 10065, 10064, 10051: // WSAECONNREFUSED, WSAEHOSTUNREACH, WSAEHOSTDOWN, WSAENETUNREACH
		return true
	}
	return false
}

// dnsReply is what a reply says about the question asked. Only records of
// the question's type and class, owned by the question name or by the name
// its CNAME chain ends at, count as answers.
type dnsReply struct {
	rcode     int
	truncated bool
	chain     []string // CNAME targets followed from the question name
	addrs     []string
	srv       []string // "target:port (priority p, weight w)"
}

// dnsName is a decoded domain name. key compares names the way DNS does,
// ASCII case-insensitively (RFC 4343), so a server that returns a name in
// another case (or a forwarder using DNS 0x20) still matches; the root name's
// key is empty. text is the name for a report, without control characters.
type dnsName struct {
	key, text string
}

// dnsRecord is one resource record of a reply. Its data stays in the
// message, at msg[data:end].
type dnsRecord struct {
	owner         dnsName
	rrType, class uint16
	data, end     int
}

// parseDNSReply validates a reply against the query it answers, matching the
// ID and the question's name, type and class (RFC 5452 section 9.1), and
// returns the answers to that question. Every record must be well formed,
// except past a truncation the server announced with TC.
func parseDNSReply(msg, query []byte) (dnsReply, error) {
	if len(msg) < dnsHeaderLen {
		return dnsReply{}, errors.New("reply shorter than a DNS header")
	}
	if binary.BigEndian.Uint16(msg) != binary.BigEndian.Uint16(query) {
		return dnsReply{}, errors.New("reply ID does not match the query")
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	if flags&0x8000 == 0 {
		return dnsReply{}, errors.New("message is not a response")
	}
	if opcode, asked := flags>>11&0xf, binary.BigEndian.Uint16(query[2:])>>11&0xf; opcode != asked {
		return dnsReply{}, fmt.Errorf("reply has opcode %d, but the query had opcode %d", opcode, asked)
	}
	reply := dnsReply{rcode: int(flags & 0x000f), truncated: flags&0x0200 != 0}
	if _, ok := dnsRcodeNames[reply.rcode]; !ok {
		return dnsReply{}, fmt.Errorf("reply has RCODE %d, which is not an answer to a query", reply.rcode)
	}
	question, questionEnd, err := parseDNSName(query, dnsHeaderLen)
	if err != nil || questionEnd+4 > len(query) {
		return dnsReply{}, errors.New("the query has no valid question")
	}
	qtype, qclass := binary.BigEndian.Uint16(query[questionEnd:]), binary.BigEndian.Uint16(query[questionEnd+2:])

	off := dnsHeaderLen
	switch questions := binary.BigEndian.Uint16(msg[4:]); {
	case questions == 1:
		name, next, err := parseDNSName(msg, off)
		if err != nil {
			return dnsReply{}, fmt.Errorf("question: %w", err)
		}
		if next+4 > len(msg) {
			return dnsReply{}, errors.New("question is truncated")
		}
		rrType, class := binary.BigEndian.Uint16(msg[next:]), binary.BigEndian.Uint16(msg[next+2:])
		if name.key != question.key || rrType != qtype || class != qclass {
			return dnsReply{}, fmt.Errorf("reply is for %s %s class %d, not the question asked (%s %s class %d)",
				name.text, dnsTypeName(rrType), class, question.text, dnsTypeName(qtype), qclass)
		}
		off = next + 4
	case questions == 0 && reply.rcode != 0:
		// An error reply may leave the question out (some servers do for
		// FORMERR). It answers nothing, so there is nothing to match.
	case questions == 0:
		return dnsReply{}, errors.New("NOERROR reply does not repeat the question")
	default:
		return dnsReply{}, fmt.Errorf("reply carries %d questions; the query asked one", questions)
	}

	var answers []dnsRecord
records:
	for section, name := range []string{"answer", "authority", "additional"} {
		count := int(binary.BigEndian.Uint16(msg[6+2*section:]))
		for i := 0; i < count; i++ {
			record, next, err := parseDNSRecord(msg, off)
			if err != nil {
				if reply.truncated {
					break records // the server cut the reply short and said so
				}
				return dnsReply{}, fmt.Errorf("%s record %d: %w", name, i+1, err)
			}
			off = next
			if section == 0 {
				answers = append(answers, record)
			}
		}
	}
	// The four counts must describe the whole message: bytes after the last
	// counted record are not part of any section (RFC 1035 section 4.1). Past a
	// truncation the server announced with TC the message may end anywhere.
	if !reply.truncated && off != len(msg) {
		return dnsReply{}, fmt.Errorf("reply has %d bytes after its last counted record", len(msg)-off)
	}
	if err := reply.collect(msg, answers, question, qtype); err != nil {
		return dnsReply{}, err
	}
	return reply, nil
}

// collect gathers the answers to the question: records of its type in class
// IN, owned by the question name or by the name its CNAME chain ends at.
// Records for any other name, class or type answer something else.
func (reply *dnsReply) collect(msg []byte, answers []dnsRecord, question dnsName, qtype uint16) error {
	owner := question
	seen := map[string]bool{owner.key: true}
	for {
		target, found, err := dnsCNAMETarget(msg, answers, owner)
		if err != nil {
			return err
		}
		if !found {
			break
		}
		if seen[target.key] {
			return fmt.Errorf("CNAME chain from %s loops at %s", question.text, target.text)
		}
		if len(reply.chain) == dnsMaxCNAMEChain {
			return fmt.Errorf("CNAME chain from %s is longer than %d names", question.text, dnsMaxCNAMEChain)
		}
		seen[target.key] = true
		reply.chain = append(reply.chain, target.text)
		owner = target
	}
	for _, record := range answers {
		if record.owner.key != owner.key || record.class != dnsClassIN || record.rrType != qtype {
			continue
		}
		data := msg[record.data:record.end]
		switch qtype {
		case dnsTypeA:
			if len(data) != net.IPv4len {
				return fmt.Errorf("A record for %s has %d bytes of data, not 4", owner.text, len(data))
			}
			reply.addrs = append(reply.addrs, net.IP(data).String())
		case dnsTypeAAAA:
			if len(data) != net.IPv6len {
				return fmt.Errorf("AAAA record for %s has %d bytes of data, not 16", owner.text, len(data))
			}
			reply.addrs = append(reply.addrs, net.IP(data).String())
		case dnsTypeSRV:
			if len(data) < 7 {
				return fmt.Errorf("SRV record for %s has only %d bytes of data", owner.text, len(data))
			}
			target, next, err := parseDNSName(msg[:record.end], record.data+6)
			if err != nil {
				return fmt.Errorf("SRV record target: %w", err)
			}
			if next != record.end {
				return fmt.Errorf("SRV record for %s has data after its target", owner.text)
			}
			// RFC 2782: a target of "." means the service is decidedly not
			// available at this domain, so it is not an answer.
			if target.key != "" {
				reply.srv = append(reply.srv, fmt.Sprintf("%s:%d (priority %d, weight %d)", target.text,
					binary.BigEndian.Uint16(data[4:]), binary.BigEndian.Uint16(data), binary.BigEndian.Uint16(data[2:])))
			}
		}
	}
	return nil
}

// dnsCNAMETarget returns the name that owner is an alias for, when the
// answers hold a CNAME record for it.
func dnsCNAMETarget(msg []byte, answers []dnsRecord, owner dnsName) (dnsName, bool, error) {
	var target dnsName
	found := false
	for _, record := range answers {
		if record.owner.key != owner.key || record.class != dnsClassIN || record.rrType != dnsTypeCNAME {
			continue
		}
		name, next, err := parseDNSName(msg[:record.end], record.data)
		if err != nil {
			return dnsName{}, false, fmt.Errorf("CNAME record for %s: %w", owner.text, err)
		}
		if next != record.end {
			return dnsName{}, false, fmt.Errorf("CNAME record for %s has data after its target", owner.text)
		}
		if found && name.key != target.key {
			return dnsName{}, false, fmt.Errorf("%s has conflicting CNAME records (%s and %s)", owner.text, target.text, name.text)
		}
		target, found = name, true
	}
	return target, found, nil
}

// parseDNSRecord decodes the resource record at off and returns the offset
// just past it.
func parseDNSRecord(msg []byte, off int) (dnsRecord, int, error) {
	owner, next, err := parseDNSName(msg, off)
	if err != nil {
		return dnsRecord{}, 0, fmt.Errorf("owner name: %w", err)
	}
	if next+10 > len(msg) {
		return dnsRecord{}, 0, errors.New("record header is truncated")
	}
	record := dnsRecord{
		owner:  owner,
		rrType: binary.BigEndian.Uint16(msg[next:]),
		class:  binary.BigEndian.Uint16(msg[next+2:]),
		data:   next + 10,
	}
	record.end = record.data + int(binary.BigEndian.Uint16(msg[next+8:]))
	if record.end > len(msg) {
		return dnsRecord{}, 0, errors.New("record data is truncated")
	}
	return record, record.end, nil
}

// parseDNSName decodes the name at off and returns the offset just past it
// where it is written. A compression pointer (RFC 1035 section 4.1.4) must
// point strictly before the part of the name that holds it, into the message
// body, which is where every real server points them: a name can then
// neither loop nor reach outside the message.
func parseDNSName(msg []byte, off int) (dnsName, int, error) {
	var key, text []byte
	next, limit, wire := -1, off, 1
	for pointers := 0; ; {
		if off >= len(msg) {
			return dnsName{}, 0, errors.New("name runs past the end of the message")
		}
		length := int(msg[off])
		switch {
		case length == 0:
			if next < 0 {
				next = off + 1
			}
			if len(text) == 0 {
				text = []byte(".")
			}
			return dnsName{key: string(key), text: string(text)}, next, nil
		case length&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return dnsName{}, 0, errors.New("compression pointer is truncated")
			}
			if next < 0 {
				next = off + 2
			}
			target := int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
			if target < dnsHeaderLen || target >= limit {
				return dnsName{}, 0, fmt.Errorf("compression pointer to offset %d does not point back to an earlier name", target)
			}
			if pointers++; pointers > 127 {
				return dnsName{}, 0, errors.New("name has too many compression pointers")
			}
			off, limit = target, target
			continue
		case length&0xc0 != 0:
			return dnsName{}, 0, errors.New("unsupported label type")
		}
		if off+1+length > len(msg) {
			return dnsName{}, 0, errors.New("label runs past the end of the message")
		}
		if wire += 1 + length; wire > 255 {
			return dnsName{}, 0, errors.New("name exceeds 255 octets")
		}
		key = append(key, byte(length))
		if len(text) > 0 {
			text = append(text, '.')
		}
		for _, c := range msg[off+1 : off+1+length] {
			if 'A' <= c && c <= 'Z' {
				key = append(key, c+'a'-'A')
			} else {
				key = append(key, c)
			}
			if c >= 0x20 && c != 0x7f {
				text = append(text, c)
			}
		}
		off += 1 + length
	}
}

// Anonymous LDAP v3 Bind Request packet (RFC 4511 Section 4.2)
// 30 0c (SEQUENCE, len 12)
//
//	02 01 01 (INTEGER 1 - messageID)
//	60 07 (BindRequest [APPLICATION 0], len 7)
//	  02 01 03 (INTEGER 3 - version 3)
//	  04 00 (OCTET STRING, len 0 - empty name)
//	  80 00 (simple [0], len 0 - empty password)
var ldapAnonymousBindPacket = []byte{
	0x30, 0x0c,
	0x02, 0x01, 0x01,
	0x60, 0x07,
	0x02, 0x01, 0x03,
	0x04, 0x00,
	0x80, 0x00,
}

// The message IDs of the requests a probe sends on its one connection. The
// bind is 1; base-object searches of naming contexts the Root DSE advertised
// take the IDs from ldapFirstDiscoveredID on, one each.
const (
	ldapBindID            = 1
	ldapBaseSearchID      = 2
	ldapRootDSEID         = 3
	ldapFirstDiscoveredID = 4
)

// LDAPProber dispatches a TCP connection, LDAP v3 anonymous bind, and an
// optional base-object search or Root DSE assertion to port 389.
type LDAPProber struct {
	TargetIP string
	Port     int
	BaseDN   string
	// NamingContext, when set, replaces the base-object search with a Root
	// DSE read that must advertise this naming context.
	NamingContext string
	Timeout       time.Duration
	Description   string
	Source        Source
}

// NewLDAPProber creates an LDAP directory service prober.
func NewLDAPProber(targetIP string, port int, baseDN string, timeout time.Duration, desc string) *LDAPProber {
	if port <= 0 {
		port = 389
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &LDAPProber{
		TargetIP:    targetIP,
		Port:        port,
		BaseDN:      baseDN,
		Timeout:     timeout,
		Description: desc,
	}
}

// Probe attempts a TCP handshake and executes an LDAP v3 BindRequest protocol validation.
func (p *LDAPProber) Probe(ctx context.Context) (res probe.Result) {
	start := time.Now()
	addr := net.JoinHostPort(p.TargetIP, strconv.Itoa(p.Port))
	probeCtx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	defer func() { res = finishProbe(probeCtx, res) }()

	res = probe.Result{
		Type:        "ldap",
		Target:      addr,
		Description: p.Description,
	}
	p.Source.annotate(&res)

	// A DN that is not one cannot say what the plan asked for, and the request
	// that carried it would be malformed. Nothing is sent for it.
	baseDN := strings.TrimSpace(p.BaseDN)
	auto := strings.EqualFold(baseDN, "auto")
	if baseDN != "" && !auto {
		if err := ldapdn.Valid(baseDN); err != nil {
			res.Error = fmt.Sprintf("LDAP base_dn is not a valid distinguished name: %v", err)
			return res
		}
	}
	if p.NamingContext != "" {
		if err := ldapdn.Valid(p.NamingContext); err != nil {
			res.Error = fmt.Sprintf("LDAP naming_context is not a valid distinguished name: %v", err)
			return res
		}
	}

	dialer, err := p.Source.dialer("tcp", 0)
	if err != nil {
		res.Duration = time.Since(start)
		res.Error = fmt.Sprintf("LDAP TCP connection to %s failed: %v", addr, err)
		return res
	}
	conn, err := dialer.DialContext(probeCtx, "tcp", addr)
	res.Duration = time.Since(start)

	if err != nil {
		res.Passed = false
		res.Error = fmt.Sprintf("LDAP TCP connection to %s failed: %v", addr, err)
		return res
	}
	defer conn.Close()
	defer interruptOnCancel(probeCtx, conn)()
	deadline, _ := probeCtx.Deadline()
	// One absolute deadline covers connect, bind, Root-DSE discovery, and every
	// base-object search. A directory that advertises many contexts must not
	// turn a 10-second configured probe timeout into several minutes of waits.
	_ = conn.SetDeadline(deadline)

	// Write LDAP anonymous bind packet
	if _, err := conn.Write(ldapAnonymousBindPacket); err != nil {
		res.Duration = time.Since(start)
		res.Passed = false
		res.Error = fmt.Sprintf("failed to send LDAP bind request to %s: %v", addr, err)
		return res
	}

	// Read LDAP BindResponse.
	buf, err := readLDAPMessage(conn)
	res.Duration = time.Since(start)

	if err != nil || len(buf) < 7 {
		res.Passed = false
		res.Error = fmt.Sprintf("failed to read LDAP response from %s: %v", addr, err)
		return res
	}

	// Parse the LDAPMessage structurally. Do not scan arbitrary response bytes
	// for 0x61/0x0a: those values can appear in diagnostic strings or controls
	// and would otherwise turn malformed or unrelated responses into a pass.
	resultCode, bindErr := ldapBindResultCode(buf, ldapBindID)
	if bindErr != nil {
		res.Passed = false
		res.Error = fmt.Sprintf("invalid LDAP BindResponse from %s: %v", addr, bindErr)
		return res
	}

	if p.NamingContext != "" {
		return p.assertNamingContext(conn, addr, resultCode, start, res)
	}

	if baseDN == "" {
		// Only the handshake is asserted. A valid BindResponse proves an LDAP v3
		// server is answering; a directory that refuses the anonymous bind by
		// policy still answered it. strongAuthRequired (8) is what a domain
		// controller that requires signing answers, inappropriateAuthentication
		// (48) what one that disallows anonymous binds answers; the Root DSE
		// assertion accepts the same two.
		switch resultCode {
		case 0:
			res.Passed = true
			res.Detail = fmt.Sprintf("LDAP directory service at %s verified (resultCode: %d) in %v", addr, resultCode, res.Duration)
		case ldapStrongAuthRequired, ldapInappropriateAuthentication:
			res.Passed = true
			res.Detail = fmt.Sprintf("LDAP directory service at %s answered the LDAP v3 bind and refused the anonymous bind by policy (%s) in %v; only the handshake is verified, no directory data was read",
				addr, ldapResultDescription(resultCode), res.Duration)
		default:
			res.Passed = false
			res.Error = fmt.Sprintf("LDAP bind to %s failed with resultCode %d", addr, resultCode)
		}
		return res
	}
	// A search asserts directory data, which needs the bind to have succeeded.
	if resultCode != 0 {
		res.Passed = false
		res.Error = fmt.Sprintf("LDAP bind to %s failed with resultCode %d", addr, resultCode)
		return res
	}

	if auto {
		// "auto" is an explicit portable-directory policy, not a fallback for a
		// configured DN. It validates a real directory object selected from the
		// server's Root DSE, which suits estates with different AD, OpenLDAP and
		// appliance naming contexts.
		contexts, discoveryErr := ldapRootDSENamingContexts(conn)
		if discoveryErr != nil {
			res.Duration = time.Since(start)
			res.Passed = false
			res.Error = fmt.Sprintf("LDAP Root DSE discovery at %s failed: %v", addr, discoveryErr)
			return res
		}
		if len(contexts) == 0 {
			res.Duration = time.Since(start)
			res.Passed = false
			res.Error = fmt.Sprintf("LDAP Root DSE at %s advertised no naming contexts for base_dn: auto", addr)
			return res
		}

		// Every advertised context is tried, in the order the server listed them
		// (which carries no meaning, RFC 4511 section 4.1.7), until one returns
		// its entry or the one probe deadline runs out.
		failures := make([]string, 0, len(contexts))
		for index, candidate := range contexts {
			shown := sanitizeLDAPContext([]byte(candidate)) // reports show a value cleaned for display; the search sends it as advertised
			resultCode, entries, searchErr := ldapBaseObjectSearch(conn, candidate, ldapFirstDiscoveredID+index)
			if searchErr != nil {
				// The connection can no longer be trusted to hold the answer to
				// the next request, so the remaining contexts are not tried.
				failures = append(failures, fmt.Sprintf("%s: %v", shown, searchErr))
				if untried := len(contexts) - index - 1; untried > 0 {
					failures = append(failures, fmt.Sprintf("%d more not tried after that exchange failed", untried))
				}
				break
			}
			if resultCode != 0 {
				failures = append(failures, fmt.Sprintf("%s: %s", shown, ldapResultDescription(resultCode)))
				continue
			}
			if problem := ldapBaseEntryProblem(candidate, entries); problem != "" {
				failures = append(failures, fmt.Sprintf("%s: search %s", shown, problem))
				continue
			}
			res.Duration = time.Since(start)
			res.Passed = true
			res.Detail = fmt.Sprintf("LDAP directory service at %s verified with discovered base-object search %s, which returned its entry, in %v", addr, shown, res.Duration)
			return res
		}
		res.Duration = time.Since(start)
		res.Passed = false
		res.Error = fmt.Sprintf("LDAP Root DSE at %s advertised naming contexts, but none passed a base-object search: %s", addr, listForReport(failures, "; "))
		return res
	}

	searchResultCode, entries, searchErr := ldapBaseObjectSearch(conn, baseDN, ldapBaseSearchID)
	res.Duration = time.Since(start)
	if searchErr != nil {
		res.Passed = false
		res.Error = fmt.Sprintf("LDAP base search for %s at %s failed: %v", baseDN, addr, searchErr)
		return res
	}
	if searchResultCode != 0 {
		res.Passed = false
		detail := ldapResultDescription(searchResultCode)
		if searchResultCode == 32 {
			// A failed explicit base-DN assertion is never silently relaxed.
			// Root DSE is queried only to make the failure actionable for
			// heterogeneous directories: it can reveal the naming contexts the
			// restored server advertises without modifying the guest or source.
			if contexts, discoveryErr := ldapRootDSENamingContexts(conn); discoveryErr == nil && len(contexts) > 0 {
				detail += fmt.Sprintf("; server naming contexts: %s", listForReport(displayLDAPContexts(contexts), ", "))
			}
		}
		res.Error = fmt.Sprintf("LDAP base search for %s at %s failed: %s", baseDN, addr, detail)
		return res
	}
	if problem := ldapBaseEntryProblem(baseDN, entries); problem != "" {
		res.Passed = false
		res.Error = fmt.Sprintf("LDAP base search for %s at %s %s", baseDN, addr, problem)
		return res
	}
	res.Passed = true
	res.Detail = fmt.Sprintf("LDAP directory service at %s verified with base-object search %s, which returned its entry, in %v", addr, baseDN, res.Duration)
	return res
}

// Result codes (RFC 4511 section 4.1.9) with a meaning to the probe.
const (
	ldapStrongAuthRequired          = 8
	ldapInappropriateAuthentication = 48
)

// assertNamingContext reads the Root DSE and requires the directory to
// advertise the configured naming context. Reading the Root DSE needs no
// access to directory data, so this asserts a directory that refuses
// anonymous searches (Active Directory's default) without weakening that
// policy. The directory service itself answers the Root DSE, so a DC whose
// database did not open fails here even though its LDAP port accepts binds.
func (p *LDAPProber) assertNamingContext(conn net.Conn, addr string, bindResult int, start time.Time, res probe.Result) probe.Result {
	// A refused anonymous bind leaves the connection anonymous, and
	// directories serve the Root DSE to anonymous clients anyway: a DC that
	// requires signed binds answers strongAuthRequired (8) or
	// inappropriateAuthentication (48) to the bind, not to the Root DSE.
	if bindResult != 0 && bindResult != ldapStrongAuthRequired && bindResult != ldapInappropriateAuthentication {
		res.Duration = time.Since(start)
		res.Error = fmt.Sprintf("LDAP anonymous bind to %s failed with %s, so its Root DSE cannot be read", addr, ldapResultDescription(bindResult))
		return res
	}
	attributes, err := ldapRootDSEAttributes(conn, ldapRootDSEID, "namingContexts", "defaultNamingContext", "dnsHostName", "isSynchronized")
	res.Duration = time.Since(start)
	if err != nil {
		res.Error = fmt.Sprintf("LDAP Root DSE read at %s failed: %v", addr, err)
		return res
	}
	advertised := append(append([]string(nil), attributes["defaultnamingcontext"]...), attributes["namingcontexts"]...)
	for _, context := range advertised {
		if ldapdn.Equal(context, p.NamingContext) {
			res.Passed = true
			res.Detail = fmt.Sprintf("LDAP directory at %s advertises naming context %s in its Root DSE%s in %v", addr, sanitizeLDAPContext([]byte(context)), ldapRootDSESummary(attributes), res.Duration)
			return res
		}
	}
	if len(advertised) == 0 {
		res.Error = fmt.Sprintf("LDAP Root DSE at %s advertises no naming contexts; expected %s", addr, p.NamingContext)
		return res
	}
	res.Error = fmt.Sprintf("LDAP Root DSE at %s does not advertise naming context %s; it advertises %s", addr, p.NamingContext, listForReport(displayLDAPContexts(uniqueLDAPContexts(advertised)), ", "))
	return res
}

// ldapRootDSESummary reports the Root DSE facts an auditor of a restored
// directory cares about. isSynchronized is informational only: a domain
// controller restored without its replication partners may report FALSE
// while serving its own directory correctly.
func ldapRootDSESummary(attributes map[string][]string) string {
	var facts []string
	for _, attribute := range []string{"defaultNamingContext", "dnsHostName", "isSynchronized"} {
		if values := attributes[strings.ToLower(attribute)]; len(values) > 0 {
			facts = append(facts, attribute+" "+sanitizeLDAPContext([]byte(values[0])))
		}
	}
	if len(facts) == 0 {
		return ""
	}
	return " (" + strings.Join(facts, ", ") + ")"
}

func ldapResultDescription(code int) string {
	name := map[int]string{
		0:  "success",
		1:  "operationsError",
		2:  "protocolError",
		3:  "timeLimitExceeded",
		4:  "sizeLimitExceeded",
		5:  "compareFalse",
		6:  "compareTrue",
		7:  "authMethodNotSupported",
		8:  "strongAuthRequired",
		32: "noSuchObject (the requested directory entry is absent from this recovered snapshot)",
		48: "inappropriateAuthentication",
		49: "invalidCredentials",
		50: "insufficientAccessRights",
		51: "busy",
		52: "unavailable",
		53: "unwillingToPerform",
		80: "other",
	}[code]
	if name == "" {
		name = "unrecognized LDAP result"
	}
	return fmt.Sprintf("%s (resultCode %d)", name, code)
}

// readLDAPMessage reads one complete BER LDAPMessage. A single conn.Read is
// not sufficient because TCP can fragment LDAP frames.
func readLDAPMessage(conn net.Conn) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, fmt.Errorf("unexpected LDAP outer tag 0x%02x", header[0])
	}
	length := int(header[1])
	message := []byte{header[0], header[1]}
	if header[1]&0x80 != 0 {
		lengthBytes := int(header[1] & 0x7f)
		if lengthBytes == 0 || lengthBytes > 4 {
			return nil, fmt.Errorf("invalid LDAP BER length")
		}
		encodedLength := make([]byte, lengthBytes)
		if _, err := io.ReadFull(conn, encodedLength); err != nil {
			return nil, err
		}
		message = append(message, encodedLength...)
		length = 0
		for _, b := range encodedLength {
			length = (length << 8) | int(b)
		}
	}
	if length < 0 || length > 1<<20 {
		return nil, fmt.Errorf("invalid LDAP message length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return append(message, payload...), nil
}

// ldapSearchRequestPacket is a base-object search (objectClass=*) of baseDN,
// asking for at most one entry and the named attributes (all when none).
func ldapSearchRequestPacket(messageID int, baseDN string, attributes []string) []byte {
	searchRequest := make([]byte, 0, len(baseDN)+32)
	searchRequest = append(searchRequest, ldapTLV(0x04, []byte(baseDN))...)        // baseObject
	searchRequest = append(searchRequest, ldapTLV(0x0a, []byte{0x00})...)          // baseObject scope
	searchRequest = append(searchRequest, ldapTLV(0x0a, []byte{0x00})...)          // never deref aliases
	searchRequest = append(searchRequest, ldapTLV(0x02, []byte{0x01})...)          // size limit one entry
	searchRequest = append(searchRequest, ldapTLV(0x02, []byte{0x00})...)          // no time limit
	searchRequest = append(searchRequest, ldapTLV(0x01, []byte{0x00})...)          // typesOnly false
	searchRequest = append(searchRequest, ldapTLV(0x87, []byte("objectClass"))...) // (objectClass=*)
	attributeList := make([]byte, 0, len(attributes)*16)
	for _, attribute := range attributes {
		attributeList = append(attributeList, ldapTLV(0x04, []byte(attribute))...)
	}
	searchRequest = append(searchRequest, ldapTLV(0x30, attributeList)...)

	message := append(ldapIntegerTLV(0x02, messageID), ldapTLV(0x63, searchRequest)...)
	return ldapTLV(0x30, message)
}

// ldapSearch sends one search and reads its responses up to its
// SearchResultDone: the entries it returned and its result. A message that
// answers another request (an unsolicited notification, say) is skipped; one
// that answers this request with an operation a search never yields, or that
// is not well formed, is an error.
func ldapSearch(conn net.Conn, messageID int, baseDN string, attributes []string) ([]ldapEntry, ldapResult, error) {
	if _, err := conn.Write(ldapSearchRequestPacket(messageID, baseDN, attributes)); err != nil {
		return nil, ldapResult{}, fmt.Errorf("send request: %w", err)
	}
	var entries []ldapEntry
	for responseCount := 0; responseCount < 16; responseCount++ {
		message, err := readLDAPMessage(conn)
		if err != nil {
			return nil, ldapResult{}, fmt.Errorf("read response: %w", err)
		}
		id, operation, err := ldapMessageEnvelope(message)
		if err != nil {
			return nil, ldapResult{}, fmt.Errorf("parse response: %w", err)
		}
		if id != messageID {
			continue // an unsolicited notification or another request's response
		}
		switch operation.tag {
		case 0x64: // SearchResultEntry
			entry, err := parseLDAPSearchEntry(operation)
			if err != nil {
				return nil, ldapResult{}, fmt.Errorf("parse response: %w", err)
			}
			entries = append(entries, entry)
		case 0x73: // SearchResultReference: a referral, not an entry
			if uris, err := ldapBERElements(operation.value); err != nil || len(uris) == 0 || slices.ContainsFunc(uris, func(uri ldapBERElement) bool { return uri.tag != 0x04 }) {
				return nil, ldapResult{}, errors.New("parse response: malformed SearchResultReference")
			}
		case 0x65: // SearchResultDone
			result, err := parseLDAPResult(operation.value, false)
			if err != nil {
				return nil, ldapResult{}, fmt.Errorf("parse response: %w", err)
			}
			return entries, result, nil
		default:
			return nil, ldapResult{}, fmt.Errorf("parse response: unexpected LDAP operation 0x%02x for a search", operation.tag)
		}
	}
	return nil, ldapResult{}, errors.New("did not return SearchResultDone")
}

// ldapRootDSENamingContexts returns the server-advertised namingContexts, for
// base_dn: auto and as the diagnostic after an explicit base-DN assertion
// returns noSuchObject. In the diagnostic case callers still fail the
// original assertion regardless of the result.
func ldapRootDSENamingContexts(conn net.Conn) ([]string, error) {
	attributes, err := ldapRootDSEAttributes(conn, ldapRootDSEID, "namingContexts")
	if err != nil {
		return nil, err
	}
	return uniqueLDAPContexts(attributes["namingcontexts"]), nil
}

// ldapRootDSEAttributes reads the requested Root DSE attributes, keyed by
// lower-cased attribute name. The Root DSE is the empty-DN entry that
// directories, Active Directory included, let anonymous clients read; a
// base-object search of the empty DN returns that one entry and nothing
// else, so an entry with another name, or a second entry, is not the Root
// DSE and its attributes do not describe this server (RFC 4511 section 4.5.2,
// RFC 4512 section 5.1).
func ldapRootDSEAttributes(conn net.Conn, messageID int, attributes ...string) (map[string][]string, error) {
	entries, result, err := ldapSearch(conn, messageID, "", attributes)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.dn != "" {
			return nil, fmt.Errorf("Root DSE search returned an entry for %q instead of the Root DSE", sanitizeLDAPContext([]byte(entry.dn)))
		}
	}
	if len(entries) > 1 {
		return nil, fmt.Errorf("Root DSE search returned %d entries; the Root DSE is one", len(entries))
	}
	if result.code != 0 {
		return nil, fmt.Errorf("Root DSE search returned %s", ldapResultDescription(result.code))
	}
	if len(entries) == 0 {
		return map[string][]string{}, nil
	}
	return entries[0].attributes, nil
}

// ldapBaseObjectSearch runs one bounded base-object search and returns its
// result code and the DNs of the entries it returned. The caller owns
// policy: explicit assertions fail on any non-success result, while automatic
// discovery may try each server-advertised naming context in turn.
func ldapBaseObjectSearch(conn net.Conn, baseDN string, messageID int) (int, []string, error) {
	entries, result, err := ldapSearch(conn, messageID, baseDN, nil)
	if err != nil {
		return -1, nil, err
	}
	dns := make([]string, len(entries))
	for i, entry := range entries {
		dns[i] = entry.dn
	}
	return result.code, dns, nil
}

// ldapEntry is a SearchResultEntry: its objectName and its attribute values,
// keyed by lower-cased attribute name (LDAP attribute names are
// case-insensitive). The values are as the server sent them, cut to a bounded
// length: compare them as they are, and pass them through sanitizeLDAPContext to
// show them.
type ldapEntry struct {
	dn         string
	attributes map[string][]string
}

// parseLDAPSearchEntry reads a SearchResultEntry (RFC 4511 section 4.5.2) in
// full: the objectName, then the attribute list, each attribute a type and a
// set of values. Anything else, or an element of another type, is malformed.
func parseLDAPSearchEntry(operation ldapBERElement) (ldapEntry, error) {
	malformed := errors.New("malformed SearchResultEntry")
	fields, err := ldapBERElements(operation.value)
	if err != nil || len(fields) != 2 || fields[0].tag != 0x04 || fields[1].tag != 0x30 || !utf8.Valid(fields[0].value) {
		return ldapEntry{}, malformed
	}
	list, err := ldapBERElements(fields[1].value)
	if err != nil {
		return ldapEntry{}, malformed
	}
	entry := ldapEntry{dn: string(fields[0].value), attributes: map[string][]string{}}
	for _, attribute := range list {
		parts, err := ldapBERElements(attribute.value)
		if attribute.tag != 0x30 || err != nil || len(parts) != 2 || parts[0].tag != 0x04 || len(parts[0].value) == 0 || parts[1].tag != 0x31 {
			return ldapEntry{}, malformed
		}
		values, err := ldapBERElements(parts[1].value)
		if err != nil {
			return ldapEntry{}, malformed
		}
		name := strings.ToLower(string(parts[0].value))
		for _, value := range values {
			if value.tag != 0x04 {
				return ldapEntry{}, malformed
			}
			// The value as the server sent it, so that a naming context is compared
			// as sent and not as it reads once control characters and spaces are
			// cleaned off; reports show it through sanitizeLDAPContext.
			if text := boundedLDAPValue(value.value); text != "" {
				entry.attributes[name] = append(entry.attributes[name], text)
			}
		}
	}
	return entry, nil
}

// ldapBaseEntryProblem says why the entries a successful base-object search
// returned do not show the requested object, or returns "" when they do.
// Success alone is not evidence: RFC 4511 lets a search succeed with no
// entries, which is what a directory that hides the object from anonymous
// clients returns.
func ldapBaseEntryProblem(baseDN string, entries []string) string {
	if len(entries) == 0 {
		return "succeeded but returned no entry for it (the object is missing or hidden from anonymous clients)"
	}
	for _, dn := range entries {
		if !ldapdn.Equal(dn, baseDN) {
			return fmt.Sprintf("returned an entry for %q instead of the requested base object", sanitizeLDAPContext([]byte(dn)))
		}
	}
	return ""
}

type ldapBERElement struct {
	tag   byte
	value []byte
}

func ldapBERElements(data []byte) ([]ldapBERElement, error) {
	elements := make([]ldapBERElement, 0, 4)
	for len(data) > 0 {
		if len(data) < 2 || data[0]&0x1f == 0x1f {
			return nil, fmt.Errorf("invalid LDAP BER element")
		}
		tag := data[0]
		lengthByte := data[1]
		headerLen := 2
		length := int(lengthByte)
		if lengthByte&0x80 != 0 {
			lengthBytes := int(lengthByte & 0x7f)
			if lengthBytes == 0 || lengthBytes > 4 || len(data) < 2+lengthBytes {
				return nil, fmt.Errorf("invalid LDAP BER length")
			}
			length = 0
			for _, b := range data[2 : 2+lengthBytes] {
				length = (length << 8) | int(b)
			}
			headerLen += lengthBytes
		}
		if length > len(data)-headerLen {
			return nil, fmt.Errorf("truncated LDAP BER element")
		}
		elements = append(elements, ldapBERElement{tag: tag, value: data[headerLen : headerLen+length]})
		data = data[headerLen+length:]
	}
	return elements, nil
}

// ldapMessageEnvelope returns the LDAP message ID and protocol operation from
// a complete LDAPMessage (RFC 4511 section 4.1.1): the ID, the operation, and
// optionally a controls element, which is never accepted as the operation.
func ldapMessageEnvelope(message []byte) (int, ldapBERElement, error) {
	outer, err := ldapBERElements(message)
	if err != nil || len(outer) != 1 || outer[0].tag != 0x30 {
		return 0, ldapBERElement{}, errors.New("invalid LDAPMessage envelope")
	}
	fields, err := ldapBERElements(outer[0].value)
	if err != nil || len(fields) < 2 || fields[0].tag != 0x02 {
		return 0, ldapBERElement{}, errors.New("LDAPMessage is missing message ID or protocol operation")
	}
	if len(fields) > 3 || len(fields) == 3 && fields[2].tag != 0xa0 {
		return 0, ldapBERElement{}, errors.New("LDAPMessage has an element after its protocol operation that is not its controls")
	}
	messageID, err := ldapNonNegativeInteger(fields[0].value)
	if err != nil {
		return 0, ldapBERElement{}, errors.New("LDAPMessage has an invalid message ID")
	}
	return messageID, fields[1], nil
}

func ldapNonNegativeInteger(value []byte) (int, error) {
	if len(value) == 0 || len(value) > 4 || value[0]&0x80 != 0 {
		return 0, errors.New("invalid non-negative LDAP integer")
	}
	result := 0
	for _, part := range value {
		result = (result << 8) | int(part)
	}
	return result, nil
}

func ldapBindResultCode(message []byte, expectedMessageID int) (int, error) {
	messageID, operation, err := ldapMessageEnvelope(message)
	if err != nil {
		return -1, err
	}
	if messageID != expectedMessageID {
		return -1, fmt.Errorf("BindResponse message ID %d does not match request %d", messageID, expectedMessageID)
	}
	if operation.tag != 0x61 { // BindResponse [APPLICATION 1]
		return -1, fmt.Errorf("expected BindResponse tag 0x61, got 0x%02x", operation.tag)
	}
	result, err := parseLDAPResult(operation.value, true)
	if err != nil {
		return -1, err
	}
	return result.code, nil
}

// ldapResult is an LDAPResult (RFC 4511 section 4.1.9).
type ldapResult struct {
	code int
}

// parseLDAPResult reads the components of an LDAPResult, which a BindResponse
// extends and a SearchResultDone is: resultCode, matchedDN and
// diagnosticMessage, all mandatory and in that order (an unused one is an empty
// string, never absent), then an optional referral and, for a BindResponse
// only, optional serverSaslCreds. The strings must be UTF-8. Nothing else may
// follow.
func parseLDAPResult(data []byte, bindResponse bool) (ldapResult, error) {
	fields, err := ldapBERElements(data)
	if err != nil || len(fields) == 0 || fields[0].tag != 0x0a {
		return ldapResult{}, errors.New("LDAP result is missing resultCode")
	}
	code, err := ldapNonNegativeInteger(fields[0].value)
	if err != nil {
		return ldapResult{}, fmt.Errorf("invalid LDAP resultCode: %w", err)
	}
	for i, name := range []string{"matchedDN", "diagnosticMessage"} {
		if len(fields) < 2+i || fields[1+i].tag != 0x04 {
			return ldapResult{}, fmt.Errorf("LDAP result is missing %s", name)
		}
		if !utf8.Valid(fields[1+i].value) {
			return ldapResult{}, fmt.Errorf("LDAP result has a %s that is not valid UTF-8", name)
		}
	}
	rest := fields[3:]
	if len(rest) > 0 && rest[0].tag == 0xa3 { // referral [3]: one or more URIs
		uris, err := ldapBERElements(rest[0].value)
		if err != nil || len(uris) == 0 || slices.ContainsFunc(uris, func(uri ldapBERElement) bool { return uri.tag != 0x04 || !utf8.Valid(uri.value) }) {
			return ldapResult{}, errors.New("LDAP result has a malformed referral")
		}
		rest = rest[1:]
	}
	if bindResponse && len(rest) > 0 && rest[0].tag == 0x87 { // serverSaslCreds [7]
		rest = rest[1:]
	}
	if len(rest) > 0 {
		return ldapResult{}, fmt.Errorf("LDAP result has an unexpected element (tag 0x%02x) after its mandatory fields", rest[0].tag)
	}
	return ldapResult{code: code}, nil
}

// boundedLDAPValue is value as a string, cut to one byte more than the longest
// distinguished name: nothing longer can be a name, so memory stays bounded and
// no longer value can compare equal to one.
func boundedLDAPValue(value []byte) string {
	if len(value) > ldapdn.MaxLength+1 {
		value = value[:ldapdn.MaxLength+1]
	}
	return string(value)
}

// sanitizeLDAPContext is a value made fit to show: trimmed, without control
// characters, cut to the longest distinguished name. It is for reports only; a
// value is never compared after it has been through it.
func sanitizeLDAPContext(value []byte) string {
	context := strings.TrimSpace(string(value))
	context = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, context)
	if len(context) > ldapdn.MaxLength {
		end := ldapdn.MaxLength
		for end > 0 && !utf8.RuneStart(context[end]) {
			end--
		}
		return context[:end]
	}
	return context
}

// uniqueLDAPContexts drops the naming contexts that repeat an earlier one,
// spelled the same or differently. The set is unordered, so none is skipped:
// a directory with many contexts has all of them tried, under the probe's one
// deadline.
func uniqueLDAPContexts(contexts []string) []string {
	seen := make(map[string]struct{}, len(contexts))
	unique := make([]string, 0, len(contexts))
	for _, context := range contexts {
		key := context
		if dn, err := ldapdn.Parse(context); err == nil {
			key = dn.Canonical()
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, context)
	}
	return unique
}

// ldapTLV encodes one BER element with a definite length in the fewest
// octets, whatever the length.
func ldapTLV(tag byte, value []byte) []byte {
	encoded := []byte{tag}
	if length := len(value); length < 0x80 {
		encoded = append(encoded, byte(length))
	} else {
		var octets []byte
		for n := length; n > 0; n >>= 8 {
			octets = append([]byte{byte(n)}, octets...)
		}
		encoded = append(append(encoded, 0x80|byte(len(octets))), octets...)
	}
	return append(encoded, value...)
}

// ldapIntegerTLV encodes a non-negative integer (a message ID) as a BER
// INTEGER or ENUMERATED with the given tag: the fewest octets that keep the
// sign bit clear.
func ldapIntegerTLV(tag byte, value int) []byte {
	octets := []byte{byte(value)}
	for n := value >> 8; n > 0; n >>= 8 {
		octets = append([]byte{byte(n)}, octets...)
	}
	if octets[0]&0x80 != 0 {
		octets = append([]byte{0}, octets...)
	}
	return ldapTLV(tag, octets)
}

// displayLDAPContexts is the contexts made fit to show in a report.
func displayLDAPContexts(contexts []string) []string {
	shown := make([]string, len(contexts))
	for i, context := range contexts {
		shown[i] = sanitizeLDAPContext([]byte(context))
	}
	return shown
}

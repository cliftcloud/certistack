// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// closedUDPPort returns a loopback UDP port nothing listens on: a datagram to
// it is answered with ICMP port unreachable, which a connected UDP socket
// reports as "connection refused" on its next read or write.
func closedUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// startDNSAfter starts a DNS server on port once delay has passed, the way a
// guest's DNS service comes up after the guest has booted. It answers every
// query with reply(query). The returned channel reports the bind error, if any,
// when the server is gone; the test reads it after the probe ends.
func startDNSAfter(t *testing.T, port int, delay time.Duration, reply func(query []byte) []byte) <-chan error {
	t.Helper()
	bindErr := make(chan error, 1)
	go func() {
		time.Sleep(delay)
		conn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			bindErr <- err
			return
		}
		bindErr <- nil
		defer conn.Close()
		buf := make([]byte, 1500)
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(reply(append([]byte(nil), buf[:n]...)), peer)
		}
	}()
	return bindErr
}

// A guest that is up but has not started its DNS server yet refuses the first
// datagrams with ICMP port unreachable. That is the same state as a lost
// datagram: the prober keeps asking until its deadline, as the TCP and HTTP
// probers do and the plan reference and probe.Result promise. A UDP probe was
// seen to give up after 0 s with "read: connection refused" while the service
// was still starting.
func TestDNSOverUDPPollsThroughICMPRefusalUntilTheServerStarts(t *testing.T) {
	port := closedUDPPort(t)
	// After the first refusal, before the second send.
	bound := startDNSAfter(t, port, 1200*time.Millisecond, func(query []byte) []byte {
		return dnsResponse(query, 0, net.IPv4(192, 0, 2, 30))
	})

	begin := time.Now()
	res := NewDNSProber("127.0.0.1", port, "healthy.certistack.test", "udp", 8*time.Second, "starting").Probe(context.Background())
	took := time.Since(begin)
	if err := <-bound; err != nil {
		t.Fatalf("the test's DNS server could not bind its port: %v", err)
	}
	if !res.Passed || !strings.Contains(res.Detail, "192.0.2.30") {
		t.Fatalf("result = %+v after %v, want the probe to keep asking through the refusals and pass once the server answered", res, took)
	}
	if took < time.Second {
		t.Fatalf("the probe passed after %v, before the server could have started: it did not wait", took)
	}
}

// The same holds for a listener check, which sends the root NS query.
func TestDNSListenerCheckOverUDPPollsThroughICMPRefusal(t *testing.T) {
	port := closedUDPPort(t)
	bound := startDNSAfter(t, port, 1200*time.Millisecond, func(query []byte) []byte {
		return dnsResponse(query, 0)
	})
	res := NewDNSProber("127.0.0.1", port, "", "udp", 8*time.Second, "listener").Probe(context.Background())
	if err := <-bound; err != nil {
		t.Fatalf("the test's DNS server could not bind its port: %v", err)
	}
	if !res.Passed {
		t.Fatalf("listener result = %+v, want a pass once the server started", res)
	}
}

// A server that never starts is still a failure, and it fails at the deadline
// with the refusal as the evidence, not after 0 s and not as a bare timeout.
func TestDNSOverUDPFailsAtTheDeadlineWhenNothingEverListens(t *testing.T) {
	port := closedUDPPort(t)
	begin := time.Now()
	res := NewDNSProber("127.0.0.1", port, "healthy.certistack.test", "udp", 1500*time.Millisecond, "never").Probe(context.Background())
	took := time.Since(begin)
	if res.Passed {
		t.Fatalf("result = %+v, want a failure: nothing listens", res)
	}
	if took < 1400*time.Millisecond {
		t.Fatalf("the probe gave up after %v of a 1.5 s budget; it must keep polling until the deadline", took)
	}
	// Windows sockets do not report the ICMP refusal of a UDP datagram, so there
	// the probe simply hears nothing until the deadline.
	if runtime.GOOS != "windows" && (!strings.Contains(res.Error, "connection refused") || !strings.Contains(res.Error, "no DNS server was reachable")) {
		t.Fatalf("error = %q, want the refusal named as the evidence", res.Error)
	}
}

// Canceling the probe ends the polling at once, however long its budget is.
func TestDNSOverUDPPollingEndsAtOnceWhenCanceled(t *testing.T) {
	port := closedUDPPort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan probe.Result, 1)
	go func() {
		done <- NewDNSProber("127.0.0.1", port, "healthy.certistack.test", "udp", 30*time.Second, "cancel").Probe(ctx)
	}()
	time.Sleep(400 * time.Millisecond)
	canceled := time.Now()
	cancel()
	select {
	case res := <-done:
		if res.Passed {
			t.Fatalf("result = %+v, want a failure", res)
		}
		if took := time.Since(canceled); took > 2*time.Second {
			t.Fatalf("the probe took %v to give up after cancellation", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the probe was still polling 5 seconds after cancellation")
	}
}

// The errors a connected UDP socket reports for a datagram that found nothing
// to answer it are the "not there yet" ones; a failure of this machine's own
// socket or firewall is not.
func TestIsUDPNotThereYet(t *testing.T) {
	wrap := func(errno syscall.Errno) error {
		return &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("read", errno)}
	}
	for _, errno := range []syscall.Errno{syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.EHOSTDOWN, syscall.ENETUNREACH, 10061, 10065, 10064, 10051} {
		if !isUDPNotThereYet(wrap(errno)) {
			t.Errorf("%v is what an unanswered datagram earns, and the probe must keep polling through it", errno)
		}
	}
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EPERM, syscall.EINVAL, syscall.EMSGSIZE, syscall.EBADF} {
		if isUDPNotThereYet(wrap(errno)) {
			t.Errorf("%v is a failure of this machine's own socket and must stay an error", errno)
		}
	}
	if isUDPNotThereYet(errors.New("connection refused")) || isUDPNotThereYet(nil) {
		t.Error("only an operating-system error number counts, not text")
	}
}

// TCP keeps its behavior: a refused connection fails the probe at once, as
// the attempt has no later datagram to wait for.
func TestDNSOverTCPStillFailsAtOnceOnARefusedConnection(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	begin := time.Now()
	res := NewDNSProber("127.0.0.1", port, "healthy.certistack.test", "tcp", 5*time.Second, "tcp").Probe(context.Background())
	if res.Passed || !strings.Contains(res.Error, "refused") {
		t.Fatalf("result = %+v", res)
	}
	if took := time.Since(begin); took > 2*time.Second {
		t.Fatalf("a refused TCP connection took %v", took)
	}
}

// scriptedConn is a connected UDP socket whose writes and reads follow a
// script, for what a loopback test cannot arrange: an ICMP refusal that is
// reported to a write (it arrived after the read that would have taken it).
type scriptedConn struct {
	net.Conn // never used; the methods below are all the exchange calls
	writes   []error
	reads    []func([]byte) (int, error)
	// readDelay is how long a read takes before it returns, so a script that
	// only times out runs into the deadline.
	readDelay time.Duration
	nWrites   int
	nReads    int
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	i := c.nWrites
	c.nWrites++
	if i < len(c.writes) && c.writes[i] != nil {
		return 0, c.writes[i]
	}
	return len(p), nil
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	time.Sleep(c.readDelay)
	i := c.nReads
	c.nReads++
	if i < len(c.reads) {
		return c.reads[i](p)
	}
	return 0, readTimeout()
}

func (c *scriptedConn) SetReadDeadline(time.Time) error { return nil }

func readTimeout() error {
	return &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
}

func refusal(op string) error {
	return &net.OpError{Op: op, Net: "udp", Err: os.NewSyscallError(op, syscall.ECONNREFUSED)}
}

func replyWithID(id uint16) func([]byte) (int, error) {
	return func(p []byte) (int, error) {
		binary.BigEndian.PutUint16(p, id)
		return copy(p[2:], "reply") + 2, nil
	}
}

// An ICMP refusal can reach the socket after the read that would have taken it
// has timed out; the next write then reports it, and the datagram it carried
// was not sent. That is the same "nothing there yet" as one a read reports.
func TestExchangeUDPKeepsAskingAfterAWriteReportsARefusal(t *testing.T) {
	const id = 0x1234
	conn := &scriptedConn{
		writes: []error{refusal("write"), refusal("write"), nil},
		reads: []func([]byte) (int, error){
			func([]byte) (int, error) { return 0, readTimeout() },
			func([]byte) (int, error) { return 0, readTimeout() },
			replyWithID(id),
		},
	}
	reply, err := exchangeUDP(conn, time.Now().Add(5*time.Second), []byte("query"), id)
	if err != nil || string(reply[2:]) != "reply" {
		t.Fatalf("exchange = %q, %v, want the reply after two refused writes", reply, err)
	}
	if conn.nWrites != 3 {
		t.Errorf("%d writes, want 3: the query is sent again after each refusal", conn.nWrites)
	}
}

func TestExchangeUDPKeepsAskingAfterAReadReportsARefusal(t *testing.T) {
	const id = 0x4321
	conn := &scriptedConn{reads: []func([]byte) (int, error){
		func([]byte) (int, error) { return 0, refusal("read") },
		func([]byte) (int, error) { return 0, readTimeout() },
		replyWithID(id),
	}}
	reply, err := exchangeUDP(conn, time.Now().Add(5*time.Second), []byte("query"), id)
	if err != nil || string(reply[2:]) != "reply" {
		t.Fatalf("exchange = %q, %v", reply, err)
	}
	if conn.nWrites != 2 {
		t.Errorf("%d writes, want 2: one query, and one after the slot ran out", conn.nWrites)
	}
}

// Refused writes until the deadline end in the refusal as the evidence.
func TestExchangeUDPReportsTheRefusalWhenWritesAreRefusedUntilTheDeadline(t *testing.T) {
	conn := &scriptedConn{
		writes:    []error{refusal("write"), refusal("write"), refusal("write"), refusal("write"), refusal("write"), refusal("write")},
		readDelay: 20 * time.Millisecond,
	}
	_, err := exchangeUDP(conn, time.Now().Add(60*time.Millisecond), []byte("query"), 1)
	if err == nil || !strings.Contains(err.Error(), "connection refused") || !strings.Contains(err.Error(), "no DNS server was reachable") {
		t.Fatalf("error = %v, want the refusal named as the evidence", err)
	}
	if conn.nWrites < 2 {
		t.Errorf("%d writes: the query was not sent again after the first refusal", conn.nWrites)
	}
}

// An error of this machine's own (a firewall that forbids the send, say) is
// not "nothing there yet".
func TestExchangeUDPStopsOnAWriteErrorOfItsOwn(t *testing.T) {
	conn := &scriptedConn{writes: []error{&net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("write", syscall.EACCES)}}}
	_, err := exchangeUDP(conn, time.Now().Add(5*time.Second), []byte("query"), 1)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error = %v, want the write error at once", err)
	}
	if conn.nWrites != 1 || conn.nReads != 0 {
		t.Errorf("%d writes and %d reads after an error of the machine's own", conn.nWrites, conn.nReads)
	}
}

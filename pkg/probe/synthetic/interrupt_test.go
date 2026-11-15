// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// holdThenAnswer accepts one connection, reads the client's first request
// with read, tells the test it arrived, and answers only after the test
// releases it, which is after the probe's context has been canceled.
func holdThenAnswer(t *testing.T, read func(net.Conn) ([]byte, error), answer func(request []byte) []byte) (port int, seen <-chan struct{}, release chan<- struct{}) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	seenC, releaseC := make(chan struct{}), make(chan struct{})
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		request, err := read(conn)
		if err != nil {
			return
		}
		close(seenC)
		<-releaseC
		_, _ = conn.Write(answer(request))
	}()
	return l.Addr().(*net.TCPAddr).Port, seenC, releaseC
}

// cancelWhileWaiting runs a probe whose peer holds its answer, cancels the
// probe's context once the request has arrived, and returns the result and how
// long the probe took to give up. The peer then answers, which must change
// nothing.
func cancelWhileWaiting(t *testing.T, seen <-chan struct{}, release chan<- struct{}, run func(ctx context.Context) probe.Result) (probe.Result, time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan probe.Result, 1)
	go func() { done <- run(ctx) }()
	select {
	case <-seen:
	case res := <-done:
		t.Fatalf("probe finished before the request arrived: %+v", res)
	case <-time.After(5 * time.Second):
		t.Fatal("the request never arrived")
	}
	started := time.Now()
	cancel()
	select {
	case res := <-done:
		took := time.Since(started)
		close(release)
		return res, took
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the probe was still waiting for its peer 5 seconds after cancellation")
		return probe.Result{}, 0
	}
}

// Its DNS, LDAP, MSSQL and SMB extensions: canceling a probe ends it
// at once, with a failure, however long its own timeout is and whatever the
// peer answers afterwards. The reporter's DNS and LDAP peers withheld a valid
// answer until the parent context was canceled and then released it; the
// probes passed. Each here has a 30-second timeout, so only the cancellation
// can end the wait.
func TestWireProbesEndAtOnceWhenCanceledAndNeverPassOnTheLateAnswer(t *testing.T) {
	for _, tc := range []struct {
		name string
		peer func(t *testing.T) (int, <-chan struct{}, chan<- struct{})
		run  func(port int) func(ctx context.Context) probe.Result
	}{
		{"dns over tcp",
			func(t *testing.T) (int, <-chan struct{}, chan<- struct{}) {
				return holdThenAnswer(t, func(conn net.Conn) ([]byte, error) {
					var length [2]byte
					if _, err := io.ReadFull(conn, length[:]); err != nil {
						return nil, err
					}
					query := make([]byte, int(length[0])<<8|int(length[1]))
					_, err := io.ReadFull(conn, query)
					return query, err
				}, func(query []byte) []byte { return tcpFrame(dnsResponse(query, 0, net.IPv4(10, 0, 70, 99))) })
			},
			func(port int) func(ctx context.Context) probe.Result {
				return func(ctx context.Context) probe.Result {
					return NewDNSProber("127.0.0.1", port, "healthy.certistack.test", "tcp", 30*time.Second, "dns").Probe(ctx)
				}
			}},
		{"ldap",
			func(t *testing.T) (int, <-chan struct{}, chan<- struct{}) {
				return holdThenAnswer(t, readLDAPMessage, func([]byte) []byte { return ldapBindSuccess })
			},
			func(port int) func(ctx context.Context) probe.Result {
				return func(ctx context.Context) probe.Result {
					return NewLDAPProber("127.0.0.1", port, "", 30*time.Second, "ldap").Probe(ctx)
				}
			}},
		{"mssql",
			func(t *testing.T) (int, <-chan struct{}, chan<- struct{}) {
				return holdThenAnswer(t, readTDSRequest, func([]byte) []byte { return tdsPreloginResponse(0x02) })
			},
			func(port int) func(ctx context.Context) probe.Result {
				return func(ctx context.Context) probe.Result {
					return NewMSSQLProber("127.0.0.1", port, 30*time.Second, "mssql").Probe(ctx)
				}
			}},
		{"smb",
			func(t *testing.T) (int, <-chan struct{}, chan<- struct{}) {
				return holdThenAnswer(t, readSMBRequest, func([]byte) []byte { return smbNegotiateResponse(0, 0x0003, 0x0302) })
			},
			func(port int) func(ctx context.Context) probe.Result {
				return func(ctx context.Context) probe.Result {
					return NewSMBProber("127.0.0.1", port, 30*time.Second, "smb").Probe(ctx)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port, seen, release := tc.peer(t)
			res, took := cancelWhileWaiting(t, seen, release, tc.run(port))
			if res.Passed || !strings.Contains(res.Error, "interrupted") {
				t.Fatalf("result = %+v, want a failure that says the probe was interrupted", res)
			}
			if took > 2*time.Second {
				t.Fatalf("the probe took %v to give up after cancellation", took)
			}
		})
	}
}

// A DNS query over UDP is canceled the same way.
func TestDNSOverUDPEndsAtOnceWhenCanceled(t *testing.T) {
	seenC, releaseC := make(chan struct{}), make(chan struct{})
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		close(seenC)
		<-releaseC
		_, _ = conn.WriteTo(dnsResponse(buf[:n], 0, net.IPv4(10, 0, 70, 99)), peer)
	}()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	res, took := cancelWhileWaiting(t, seenC, releaseC, func(ctx context.Context) probe.Result {
		return NewDNSProber("127.0.0.1", port, "healthy.certistack.test", "udp", 30*time.Second, "dns").Probe(ctx)
	})
	if res.Passed || !strings.Contains(res.Error, "interrupted") || took > 2*time.Second {
		t.Fatalf("result = %+v after %v", res, took)
	}
}

func TestFinishProbeRefusesAPassAfterTheProbeEnded(t *testing.T) {
	pass := probe.Result{Passed: true, Detail: "answered", Duration: time.Second}
	live := context.Background()
	canceled, cancel := context.WithCancelCause(context.Background())
	cancel(errors.New("run interrupted"))
	timedOut, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Millisecond))
	defer stop()

	if got := finishProbe(live, pass); !got.Passed || got.Detail != "answered" {
		t.Errorf("a pass in time = %+v", got)
	}
	for name, ctx := range map[string]context.Context{"canceled": canceled, "out of time": timedOut} {
		got := finishProbe(ctx, pass)
		if got.Passed || got.Detail != "" || !strings.Contains(got.Error, "does not count") {
			t.Errorf("a pass after the probe was %s = %+v", name, got)
		}
	}
	closed := probe.Result{Error: "read response: use of closed network connection"}
	if got := finishProbe(canceled, closed); got.Error != "the probe was interrupted (run interrupted)" {
		t.Errorf("an interrupted exchange = %q", got.Error)
	}
	if got := finishProbe(timedOut, closed); got.Error != closed.Error {
		t.Errorf("a timed-out exchange = %q, want its error kept", got.Error)
	}
	refused := probe.Result{Error: "connection refused"}
	if got := finishProbe(canceled, refused); got.Error != "connection refused" {
		t.Errorf("a refusal before the interruption = %q", got.Error)
	}
}

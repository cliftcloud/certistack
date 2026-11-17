// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package qmp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func qmpTestListener(t *testing.T, serve func(*bufio.Reader, *json.Encoder)) string {
	t.Helper()
	return qmpConnTestListener(t, func(conn net.Conn) {
		serve(bufio.NewReader(conn), json.NewEncoder(conn))
	})
}

// qmpConnTestListener is qmpTestListener for a fixture that writes raw
// bytes, such as half a message.
func qmpConnTestListener(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	// A unix socket's path is limited (108 bytes on Linux, 104 on macOS, and
	// the same on Windows), and t.TempDir embeds the test's name and its
	// subtest's: a long one made the listen fail with "invalid argument" on a
	// Windows runner whose temporary directory is long. The socket
	// goes in a short directory of its own.
	dir, err := os.MkdirTemp("", "cs-qmp")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "qmp.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serve(conn)
	}()
	return socketPath
}

func readQMPCommand(t *testing.T, reader *bufio.Reader) map[string]any {
	t.Helper()
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read QMP command: %v", err)
	}
	var command map[string]any
	if err := json.Unmarshal(line, &command); err != nil {
		t.Fatalf("decode QMP command: %v", err)
	}
	return command
}

// reply is QEMU's reply to command: it echoes the command's id.
func reply(command map[string]any, value any) map[string]any {
	return map[string]any{"return": value, "id": command["id"]}
}

// greetAndNegotiate plays QEMU's side of the handshake.
func greetAndNegotiate(t *testing.T, reader *bufio.Reader, encoder *json.Encoder) {
	t.Helper()
	if err := encoder.Encode(map[string]any{"QMP": map[string]any{"version": map[string]any{}, "capabilities": []any{}}}); err != nil {
		t.Errorf("write greeting: %v", err)
		return
	}
	command := readQMPCommand(t, reader)
	if command["execute"] != "qmp_capabilities" {
		t.Errorf("capabilities command = %v", command["execute"])
	}
	if err := encoder.Encode(reply(command, map[string]any{})); err != nil {
		t.Errorf("write capabilities response: %v", err)
	}
}

func status(running bool) map[string]any {
	if running {
		return map[string]any{"running": true, "status": "running"}
	}
	return map[string]any{"running": false, "status": "paused"}
}

// shortCommandTimeout lets a test time a command out without waiting the
// production fifteen seconds.
func shortCommandTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	previous := commandTimeout
	commandTimeout = d
	t.Cleanup(func() { commandTimeout = previous })
}

func TestDialRejectsNonQMPGreeting(t *testing.T) {
	socketPath := qmpTestListener(t, func(_ *bufio.Reader, encoder *json.Encoder) {
		if err := encoder.Encode(map[string]any{"hello": "not qmp"}); err != nil {
			t.Errorf("write greeting: %v", err)
		}
	})
	if _, err := Dial(socketPath, time.Second); err == nil {
		t.Fatal("Dial accepted a greeting without a QMP object")
	}
}

func TestReadResponseLineRejectsOversizedResponse(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("x", maxResponseLineBytes+1)))
	if _, _, err := readResponseLine(reader, nil); err == nil || !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("readResponseLine error = %v, want maximum-size rejection", err)
	}
}

func TestExecuteSkipsEventAndParsesStatus(t *testing.T) {
	socketPath := qmpTestListener(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		greetAndNegotiate(t, reader, encoder)
		command := readQMPCommand(t, reader)
		if command["execute"] != "query-status" {
			t.Errorf("status command = %v", command["execute"])
		}
		if err := encoder.Encode(map[string]any{"event": "RESET"}); err != nil {
			t.Errorf("write event: %v", err)
			return
		}
		if err := encoder.Encode(reply(command, status(true))); err != nil {
			t.Errorf("write status response: %v", err)
		}
	})
	client, err := Dial(socketPath, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	status, err := client.QueryStatus()
	if err != nil {
		t.Fatalf("QueryStatus: %v", err)
	}
	if !status.Running || status.Status != "running" {
		t.Fatalf("status = %+v, want running", status)
	}
}

func TestExecuteRejectsMalformedResponse(t *testing.T) {
	socketPath := qmpTestListener(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		greetAndNegotiate(t, reader, encoder)
		_ = readQMPCommand(t, reader)
		_ = encoder.Encode("not an object")
	})
	client, err := Dial(socketPath, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if _, err := client.QueryStatus(); err == nil {
		t.Fatal("QueryStatus accepted a malformed QMP response")
	}
}

func TestExecuteRejectsNullReturn(t *testing.T) {
	socketPath := qmpTestListener(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		greetAndNegotiate(t, reader, encoder)
		_ = encoder.Encode(reply(readQMPCommand(t, reader), nil))
	})
	client, err := Dial(socketPath, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if _, err := client.QueryStatus(); err == nil {
		t.Fatal("QueryStatus accepted a null QMP return value")
	}
}

func TestExecuteRejectsReplyWithoutCommandID(t *testing.T) {
	socketPath := qmpTestListener(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		greetAndNegotiate(t, reader, encoder)
		_ = readQMPCommand(t, reader)
		_ = encoder.Encode(map[string]any{"return": status(true)})
	})
	client, err := Dial(socketPath, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if _, err := client.QueryStatus(); err == nil || !strings.Contains(err.Error(), "no command id") {
		t.Fatalf("QueryStatus of a reply without an id = %v, want a rejection", err)
	}
}

// staleRunningQMP plays a QEMU whose first query-status reply ("running",
// sampled then) arrives only after the client's command timeout, when the
// VM is paused; it answers every later query with the fresh "paused".
// sent is closed once the reply to the second query is written.
func staleRunningQMP(t *testing.T, delay time.Duration) (string, <-chan struct{}) {
	t.Helper()
	sent := make(chan struct{})
	socketPath := qmpTestListener(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		greetAndNegotiate(t, reader, encoder)
		for query := 1; ; query++ {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var command map[string]any
			if err := json.Unmarshal(line, &command); err != nil {
				return
			}
			running := query == 1
			if running {
				time.Sleep(delay)
			}
			if err := encoder.Encode(reply(command, status(running))); err != nil {
				return
			}
			if query == 2 {
				close(sent)
			}
		}
	})
	return socketPath, sent
}

// A query that timed out gets its reply later on the same
// connection. The next query must read past it to its own reply, never
// take the stale "running" as the answer to the fresh question.
func TestQueryStatusIgnoresTheReplyToATimedOutQuery(t *testing.T) {
	shortCommandTimeout(t, 200*time.Millisecond)
	socketPath, sent := staleRunningQMP(t, 250*time.Millisecond)
	client, err := Dial(socketPath, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	var timeout net.Error
	if _, err := client.QueryStatus(); !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("first query = %v, want its socket timeout", err)
	}
	second, err := client.QueryStatus()
	if err != nil {
		t.Fatalf("second query: %v", err)
	}
	if second.Running || second.Status != "paused" {
		t.Fatalf("second query = %+v: the timed-out query's stale running reply answered it", second)
	}
	<-sent
}

// The boot waiter retries on the same connection, so it must not
// accept the timed-out query's stale "running" either.
func TestWaitForRunningIgnoresTheReplyToATimedOutQuery(t *testing.T) {
	shortCommandTimeout(t, 200*time.Millisecond)
	socketPath, _ := staleRunningQMP(t, 250*time.Millisecond)
	client, err := Dial(socketPath, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if err := client.WaitForRunning(context.Background(), 5*time.Millisecond, 800*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitForRunning on a paused VM = %v, want its deadline", err)
	}
}

// A reply cut off by the timeout mid-message is completed on the
// next read, not read as a malformed new message.
func TestExecuteResumesAReplyCutOffByTheTimeout(t *testing.T) {
	shortCommandTimeout(t, 200*time.Millisecond)
	socketPath := qmpConnTestListener(t, func(conn net.Conn) {
		reader, encoder := bufio.NewReader(conn), json.NewEncoder(conn)
		greetAndNegotiate(t, reader, encoder)
		first := readQMPCommand(t, reader)
		stale, _ := json.Marshal(reply(first, status(true)))
		half := len(stale) / 2
		_, _ = conn.Write(stale[:half])
		time.Sleep(250 * time.Millisecond)
		_, _ = conn.Write(append(stale[half:], '\n'))
		_ = encoder.Encode(reply(readQMPCommand(t, reader), status(false)))
	})
	client, err := Dial(socketPath, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if _, err := client.QueryStatus(); err == nil {
		t.Fatal("first query passed without its whole reply")
	}
	second, err := client.QueryStatus()
	if err != nil || second.Running || second.Status != "paused" {
		t.Fatalf("second query = %+v, %v; want its own paused reply", second, err)
	}
}

// Positive control: a VM that answers running at once passes the boot wait.
func TestWaitForRunningAcceptsAFreshRunningReply(t *testing.T) {
	socketPath := qmpTestListener(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		greetAndNegotiate(t, reader, encoder)
		_ = encoder.Encode(reply(readQMPCommand(t, reader), status(true)))
	})
	client, err := Dial(socketPath, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if err := client.WaitForRunning(context.Background(), 5*time.Millisecond, time.Second); err != nil {
		t.Fatalf("WaitForRunning = %v, want running", err)
	}
}

// The boot waiter bounds each query by its own deadline and its
// parent's cancellation, so a "running" that arrives after either does not
// count; the fresh on-time running reply and a paused VM are controls.
func TestWaitForRunningDoesNotAcceptALateRunningReply(t *testing.T) {
	for name, tc := range map[string]struct {
		timeout   time.Duration
		cancel    bool
		delay     time.Duration
		running   bool
		wantError error
	}{
		"running after the deadline": {70 * time.Millisecond, false, 150 * time.Millisecond, true, context.DeadlineExceeded},
		"running after cancellation": {time.Second, true, 150 * time.Millisecond, true, context.Canceled},
		"paused after the deadline":  {70 * time.Millisecond, false, 150 * time.Millisecond, false, context.DeadlineExceeded},
		"running on time (control)":  {time.Second, false, 0, true, nil},
	} {
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{})
			socketPath := qmpTestListener(t, func(reader *bufio.Reader, encoder *json.Encoder) {
				greetAndNegotiate(t, reader, encoder)
				command := readQMPCommand(t, reader)
				close(entered)
				time.Sleep(tc.delay)
				_ = encoder.Encode(reply(command, status(tc.running)))
				_, _ = reader.ReadBytes('\n')
			})
			client, err := Dial(socketPath, time.Second)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				go func() {
					<-entered
					time.Sleep(20 * time.Millisecond)
					cancel()
				}()
			}
			start := time.Now()
			err = client.WaitForRunning(ctx, time.Millisecond, tc.timeout)
			if tc.wantError == nil {
				if err != nil {
					t.Fatalf("WaitForRunning = %v, want running", err)
				}
				return
			}
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("WaitForRunning = %v, want %v", err, tc.wantError)
			}
			if elapsed := time.Since(start); elapsed >= tc.delay {
				t.Fatalf("WaitForRunning took %v, want it to stop before the %v reply", elapsed, tc.delay)
			}
		})
	}
}

// Capability negotiation is bounded by the caller's context: a
// negotiation reply after its deadline is not a connection.
func TestDialContextRejectsLateCapabilityNegotiation(t *testing.T) {
	for name, delay := range map[string]time.Duration{"late": 150 * time.Millisecond, "on time (control)": 0} {
		t.Run(name, func(t *testing.T) {
			socketPath := qmpTestListener(t, func(reader *bufio.Reader, encoder *json.Encoder) {
				_ = encoder.Encode(map[string]any{"QMP": map[string]any{}})
				command := readQMPCommand(t, reader)
				time.Sleep(delay)
				_ = encoder.Encode(reply(command, map[string]any{}))
				_, _ = reader.ReadBytes('\n')
			})
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			client, err := DialContext(ctx, socketPath, time.Second)
			if delay == 0 {
				if err != nil {
					t.Fatalf("on-time DialContext: %v", err)
				}
				_ = client.Close()
				return
			}
			if err == nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("DialContext with a late negotiation = %v, want the context deadline", err)
			}
		})
	}
}

// The fixtures' socket path does not grow with the name of the test that uses
// it. Two tests failed on Windows because t.TempDir put the test's and subtest's
// names in the path, past the limit of a unix socket's (108 bytes on Linux, 104
// on macOS); a name this long fails the same way anywhere if the socket is not
// in a short directory of its own.
func TestQMPTestSocketPathDoesNotDependOnTheTestName(t *testing.T) {
	name := strings.Repeat("a-very-long-subtest-name-", 8)
	t.Run(name, func(t *testing.T) {
		path := qmpConnTestListener(t, func(conn net.Conn) { _ = conn.Close() })
		// Whatever the system's temporary directory is, the rest of the path
		// is short and fixed.
		if extra := len(path) - len(os.TempDir()); extra > 30 {
			t.Errorf("the socket path is %d bytes beyond the temporary directory: %s", extra, path)
		}
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("dial %s: %v", path, err)
		}
		_ = conn.Close()
	})
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package qga

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, serve func(*bufio.Reader, *json.Encoder)) *Client {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	go func() {
		defer serverConn.Close()
		serve(bufio.NewReader(serverConn), json.NewEncoder(serverConn))
	}()
	return &Client{
		conn:    clientConn,
		reader:  bufio.NewReader(clientConn),
		encoder: json.NewEncoder(clientConn),
	}
}

func readQGARequest(t *testing.T, reader *bufio.Reader) map[string]any {
	t.Helper()
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read QGA request: %v", err)
	}
	var request map[string]any
	if err := json.Unmarshal(line, &request); err != nil {
		t.Fatalf("decode QGA request: %v", err)
	}
	return request
}

// readRawQGARequest is readQGARequest for serve loops that end when the
// client disconnects, where a read error is expected rather than a failure.
func readRawQGARequest(reader *bufio.Reader) (map[string]any, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var request map[string]any
	if err := json.Unmarshal(line, &request); err != nil {
		return nil, err
	}
	return request, nil
}

func qgaTestSocket(t *testing.T, serve func(*bufio.Reader, *json.Encoder)) string {
	t.Helper()
	return qgaConnTestSocket(t, func(conn net.Conn) {
		serve(bufio.NewReader(conn), json.NewEncoder(conn))
	})
}

// qgaConnTestSocket is qgaTestSocket for a fixture that writes raw bytes,
// including lines that are not JSON.
func qgaConnTestSocket(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	// Not t.TempDir(): it embeds the test name, and a long subtest name pushes
	// the path past the ~108-byte unix socket limit (Windows included).
	dir, err := os.MkdirTemp("", "qga")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "qga.sock")
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

// staleSyncAgent answers the guest-sync request with prefix(id) and then,
// unless omitReply, the matching reply, in one write: the stale data is
// already queued ahead of the reply when the client reads.
func staleSyncAgent(t *testing.T, prefix func(id int64) string, omitReply bool) string {
	t.Helper()
	return qgaConnTestSocket(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var request struct {
			Execute   string `json:"execute"`
			Arguments struct {
				ID int64 `json:"id"`
			} `json:"arguments"`
		}
		if err := json.Unmarshal(line, &request); err != nil || request.Execute != "guest-sync" {
			t.Errorf("sync request %q: %v", line, err)
			return
		}
		if request.Arguments.ID <= 0 {
			t.Errorf("sync id %d, want a positive id that no absent return value decodes to", request.Arguments.ID)
		}
		response := prefix(request.Arguments.ID)
		if !omitReply {
			response += fmt.Sprintf("{\"return\":%d}\n", request.Arguments.ID)
		}
		if _, err := io.WriteString(conn, response); err != nil {
			return
		}
		_, _ = reader.ReadBytes('\n') // hold the connection until the client closes it
	})
}

// Guest-sync reads past replies left over from an earlier client or
// command, whatever their shape, to the reply that echoes its own id.
func TestDialReadsPastStaleDataToTheSyncReply(t *testing.T) {
	for name, prefix := range map[string]func(int64) string{
		"clean channel":   func(int64) string { return "" },
		"earlier sync id": func(id int64) string { return fmt.Sprintf("{\"return\":%d}\n", id+1) },
		"earlier command": func(int64) string { return "{\"return\":{\"host-name\":\"previous-client\"}}\n" },
		"earlier error": func(int64) string {
			return "{\"error\":{\"class\":\"GenericError\",\"desc\":\"previous command failed\"}}\n"
		},
		"tail of an old line":  func(int64) string { return "tail-of-previous-json}\n" },
		"absent return values": func(int64) string { return "{}\nnull\n{\"return\":null}\n{\"return\":0}\n" },
		"several stale lines": func(id int64) string {
			return fmt.Sprintf("{\"return\":{}}\n{\"return\":%d}\n{\"return\":\"%d\"}\n", id-1, id)
		},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := Dial(staleSyncAgent(t, prefix, false), time.Second)
			if err != nil {
				t.Fatalf("Dial with %s = %v, want the matching sync reply found", name, err)
			}
			_ = client.Close()
		})
	}
}

// Reading past stale data is bounded, by the timeout and by size,
// and without its own reply the handshake fails.
func TestDialFailsWithoutAMatchingSyncReply(t *testing.T) {
	agentError := func(int64) string {
		return "{\"error\":{\"class\":\"GenericError\",\"desc\":\"JSON parse error\"}}\n"
	}
	start := time.Now()
	_, err := Dial(staleSyncAgent(t, agentError, true), 200*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "QGA sync handshake failed") || !strings.Contains(err.Error(), "JSON parse error") {
		t.Fatalf("Dial without a sync reply = %v, want a failed handshake naming the agent's error", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Dial took %v, want it bounded by its timeout", elapsed)
	}

	flood := func(int64) string {
		line := "{\"return\":\"" + strings.Repeat("x", maxResponseLineBytes/2) + "\"}\n"
		return strings.Repeat(line, maxSyncDiscardBytes/len(line)+2)
	}
	_, err = Dial(staleSyncAgent(t, flood, false), 10*time.Second)
	if err == nil || !strings.Contains(err.Error(), "bytes of earlier data") {
		t.Fatalf("Dial behind %d bytes of stale data = %v, want the size bound", maxSyncDiscardBytes, err)
	}
}

// A command whose reply did not arrive in time leaves that reply on its
// way: no later command on the session may read it as its own. Sync reads
// past it and makes the session usable again.
func TestClientRefusesCommandsAfterALostReplyUntilResynced(t *testing.T) {
	released := make(chan struct{})
	answerSync := func(reader *bufio.Reader, encoder *json.Encoder) {
		request := readQGARequest(t, reader)
		arguments, _ := request["arguments"].(map[string]any)
		_ = encoder.Encode(map[string]any{"return": arguments["id"]})
	}
	socketPath := qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		answerSync(reader, encoder)
		if request := readQGARequest(t, reader); request["execute"] != "guest-ping" {
			t.Errorf("first command = %v", request["execute"])
			return
		}
		<-released
		_ = encoder.Encode(map[string]any{"return": map[string]any{}}) // the late ping reply
		answerSync(reader, encoder)
		if request := readQGARequest(t, reader); request["execute"] != "guest-get-host-name" {
			t.Errorf("command after resync = %v", request["execute"])
			return
		}
		_ = encoder.Encode(map[string]any{"return": map[string]any{"host-name": "restored-guest"}})
	})
	client, err := Dial(socketPath, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	if err := client.Ping(50 * time.Millisecond); err == nil {
		t.Fatal("ping without a reply passed")
	}
	if _, err := client.GetHostName(); err == nil || !strings.Contains(err.Error(), "session unusable") {
		t.Fatalf("command after a lost reply = %v, want the session refused", err)
	}
	close(released)
	if err := client.Sync(time.Second); err != nil {
		t.Fatalf("resync: %v", err)
	}
	if name, err := client.GetHostName(); err != nil || name != "restored-guest" {
		t.Fatalf("GetHostName after resync = %q, %v", name, err)
	}
}

// slowAgent answers guest-sync at once and command after delay; every
// other command at once.
func slowAgent(t *testing.T, command string, delay time.Duration, answer any) string {
	t.Helper()
	return qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		for {
			request, err := readRawQGARequest(reader)
			if err != nil {
				return
			}
			var reply any = map[string]any{"return": answer}
			switch request["execute"] {
			case "guest-sync":
				arguments, _ := request["arguments"].(map[string]any)
				reply = map[string]any{"return": arguments["id"]}
			case command:
				time.Sleep(delay)
			case "guest-exec":
				reply = map[string]any{"return": map[string]any{"pid": 7}}
			}
			if err := encoder.Encode(reply); err != nil {
				return
			}
		}
	})
}

// A reply that arrives after the caller's deadline or cancellation
// does not count, and the probe stops waiting at that moment rather than at
// its own socket timeouts.
func TestQGAProberDoesNotAcceptAnAnswerAfterItsContext(t *testing.T) {
	succeeded := map[string]any{"exited": true, "exitcode": 0, "out-data": base64.StdEncoding.EncodeToString([]byte("active\n"))}
	// The prober polls guest-exec-status every 500ms, so the exec cases end
	// their context after the first poll is sent and before its reply.
	for name, tc := range map[string]struct {
		command, slow string
		answer        any
		ends          time.Duration
		cancel        bool
	}{
		"ping after deadline":         {"ping", "guest-ping", map[string]any{}, 100 * time.Millisecond, false},
		"ping after cancellation":     {"ping", "guest-ping", map[string]any{}, 100 * time.Millisecond, true},
		"hostname after deadline":     {"hostname", "guest-get-host-name", map[string]any{"host-name": "restored"}, 100 * time.Millisecond, false},
		"exec status after deadline":  {"systemctl is-active postgresql", "guest-exec-status", succeeded, 650 * time.Millisecond, false},
		"exec status after cancel":    {"systemctl is-active postgresql", "guest-exec-status", succeeded, 650 * time.Millisecond, true},
		"sc query after cancellation": {"sc query W3SVC", "guest-exec-status", succeeded, 650 * time.Millisecond, true},
	} {
		t.Run(name, func(t *testing.T) {
			socketPath := slowAgent(t, tc.slow, tc.ends+400*time.Millisecond, tc.answer)
			ctx, cancel := context.WithTimeout(context.Background(), tc.ends)
			defer cancel()
			if tc.cancel {
				ctx, cancel = context.WithCancel(context.Background())
				defer cancel()
				time.AfterFunc(tc.ends, cancel)
			}
			start := time.Now()
			result := NewQGAProber(socketPath, tc.command, "", true, 5*time.Second, name).Probe(ctx)
			if result.Passed {
				t.Fatalf("%s passed: %+v", name, result)
			}
			if elapsed := time.Since(start); elapsed > tc.ends+250*time.Millisecond {
				t.Fatalf("%s took %v, want it to stop when its context ended after %v", name, elapsed, tc.ends)
			}
		})
	}

	// Positive control: the same agent answering in time passes.
	socketPath := slowAgent(t, "guest-ping", 0, map[string]any{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if result := NewQGAProber(socketPath, "ping", "", true, 5*time.Second, "on time").Probe(ctx); !result.Passed {
		t.Fatalf("on-time ping result = %+v", result)
	}
}

// The handshake is bounded by the caller's context too: an agent
// that does not answer guest-sync holds Dial only until ctx's deadline.
func TestDialContextStopsAtTheContextDeadline(t *testing.T) {
	socketPath := qgaTestSocket(t, func(reader *bufio.Reader, _ *json.Encoder) {
		_, _ = reader.ReadBytes('\n')
		_, _ = reader.ReadBytes('\n') // never answer
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := DialContext(ctx, socketPath, 5*time.Second); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext = %v, want the context deadline", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("DialContext took %v, want it to stop at the 100ms context deadline", elapsed)
	}
}

// A sync reply that arrives only after the context ended is not a
// handshake.
func TestSyncContextRejectsALateReply(t *testing.T) {
	socketPath := qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		request := readQGARequest(t, reader)
		arguments, _ := request["arguments"].(map[string]any)
		time.Sleep(200 * time.Millisecond)
		_ = encoder.Encode(map[string]any{"return": arguments["id"]})
		_, _ = reader.ReadBytes('\n')
	})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := DialContext(ctx, socketPath, 5*time.Second); err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext = %v, want the cancellation", err)
	}
}

func TestGetHostNameRejectsEmptySuccessResponse(t *testing.T) {
	client := testClient(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		request := readQGARequest(t, reader)
		if request["execute"] != "guest-get-host-name" {
			t.Errorf("command = %v", request["execute"])
		}
		if err := encoder.Encode(map[string]any{"return": map[string]any{}}); err != nil {
			t.Errorf("write QGA response: %v", err)
		}
	})
	if _, err := client.GetHostName(); err == nil || !strings.Contains(err.Error(), "empty hostname") {
		t.Fatalf("empty hostname response error = %v, want explicit failure", err)
	}
}

func TestReadResponseLineRejectsUnterminatedOversizedResponse(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("x", maxResponseLineBytes+1)))
	if _, err := readResponseLine(reader); err == nil || !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("readResponseLine error = %v, want maximum-size rejection", err)
	}
}

func TestExecRejectsStatusErrorInsteadOfTimingOut(t *testing.T) {
	client := testClient(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		request := readQGARequest(t, reader)
		if request["execute"] != "guest-exec" {
			t.Errorf("first command = %v", request["execute"])
		}
		if err := encoder.Encode(map[string]any{"return": map[string]any{"pid": 42}}); err != nil {
			t.Errorf("write exec response: %v", err)
			return
		}
		request = readQGARequest(t, reader)
		if request["execute"] != "guest-exec-status" {
			t.Errorf("status command = %v", request["execute"])
		}
		if err := encoder.Encode(map[string]any{"error": map[string]any{"desc": "guest-exec disabled"}}); err != nil {
			t.Errorf("write status response: %v", err)
		}
	})
	_, err := client.Exec(context.Background(), "hostname", time.Millisecond, time.Second)
	if err == nil || !strings.Contains(err.Error(), "guest-exec-status error: guest-exec disabled") {
		t.Fatalf("Exec error = %v, want direct status failure", err)
	}
}

func TestExecRejectsMalformedGuestOutput(t *testing.T) {
	client := testClient(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		_ = readQGARequest(t, reader)
		if err := encoder.Encode(map[string]any{"return": map[string]any{"pid": 42}}); err != nil {
			t.Errorf("write exec response: %v", err)
			return
		}
		_ = readQGARequest(t, reader)
		if err := encoder.Encode(map[string]any{"return": map[string]any{
			"exited": true, "exitcode": 0, "out-data": "not base64***",
		}}); err != nil {
			t.Errorf("write status response: %v", err)
		}
	})
	_, err := client.Exec(context.Background(), "hostname", time.Millisecond, time.Second)
	if err == nil || !strings.Contains(err.Error(), "decode guest-exec stdout") {
		t.Fatalf("Exec error = %v, want malformed output failure", err)
	}
}

func TestExecRejectsMalformedStatusResponse(t *testing.T) {
	client := testClient(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		_ = readQGARequest(t, reader)
		if err := encoder.Encode(map[string]any{"return": map[string]any{"pid": 42}}); err != nil {
			t.Errorf("write exec response: %v", err)
			return
		}
		_ = readQGARequest(t, reader)
		if err := encoder.Encode("not an object"); err != nil {
			t.Errorf("write malformed status response: %v", err)
		}
	})
	_, err := client.Exec(context.Background(), "hostname", time.Millisecond, time.Second)
	if err == nil || !strings.Contains(err.Error(), "unmarshal guest-exec-status") {
		t.Fatalf("Exec error = %v, want malformed status failure", err)
	}
}

func TestTruncateForReportBoundsGuestControlledText(t *testing.T) {
	short := "guest output that easily fits"
	if got := truncateForReport(short); got != short {
		t.Fatalf("short text was modified: %q", got)
	}

	huge := strings.Repeat("a", maxReportOutputBytes*2)
	got := truncateForReport(huge)
	if len(got) > maxReportOutputBytes+len("...(truncated)") {
		t.Fatalf("truncated length = %d, want bounded near %d", len(got), maxReportOutputBytes)
	}
	if !strings.HasSuffix(got, "...(truncated)") {
		t.Fatalf("truncated text missing truncation marker: %q", got[:40])
	}
}

func TestExecTruncatesLargeGuestOutput(t *testing.T) {
	client := testClient(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		_ = readQGARequest(t, reader)
		if err := encoder.Encode(map[string]any{"return": map[string]any{"pid": 42}}); err != nil {
			t.Errorf("write exec response: %v", err)
			return
		}
		_ = readQGARequest(t, reader)
		largeOutput := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", maxGuestOutputBytes+1)))
		if err := encoder.Encode(map[string]any{"return": map[string]any{
			"exited": true, "exitcode": 0, "out-data": largeOutput,
		}}); err != nil {
			t.Errorf("write status response: %v", err)
		}
	})
	result, err := client.Exec(context.Background(), "hostname", time.Millisecond, time.Second)
	if err != nil {
		t.Fatalf("Exec returned error: %v", err)
	}
	if len(result.Stdout) != maxGuestOutputBytes {
		t.Fatalf("stdout length = %d, want %d", len(result.Stdout), maxGuestOutputBytes)
	}
}

func TestQGAProberPingDoesNotFallBackToShellCommand(t *testing.T) {
	socketPath := qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		request := readQGARequest(t, reader)
		if request["execute"] != "guest-sync" {
			t.Errorf("sync command = %v", request["execute"])
			return
		}
		arguments, _ := request["arguments"].(map[string]any)
		if err := encoder.Encode(map[string]any{"return": arguments["id"]}); err != nil {
			t.Errorf("write sync response: %v", err)
			return
		}
		request = readQGARequest(t, reader)
		if request["execute"] != "guest-ping" {
			t.Errorf("ping command = %v", request["execute"])
		}
		if err := encoder.Encode(map[string]any{"error": map[string]any{"desc": "guest ping unavailable"}}); err != nil {
			t.Errorf("write ping error: %v", err)
		}
	})
	result := NewQGAProber(socketPath, "ping", "", true, time.Second, "required guest ping").Probe(context.Background())
	if result.Passed || !strings.Contains(result.Error, "QGA guest-ping failed") {
		t.Fatalf("failed QGA ping result = %+v, want direct failure", result)
	}
}

// A required ping passes only on the agent's success envelope,
// {"return": {}}. Well-formed JSON without it is not an answer.
func TestQGAProberPingRequiresSuccessEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		pass        bool
	}{
		{"empty object", `{}`, false},
		{"json null", `null`, false},
		{"unrelated object", `{"unrelated":"message"}`, false},
		{"null return", `{"return":null}`, false},
		{"array return", `{"return":[]}`, false},
		{"string return", `{"return":"pong"}`, false},
		{"return and error", `{"return":{},"error":{"class":"GenericError","desc":"contradictory"}}`, false},
		{"agent error control", `{"error":{"class":"GenericError","desc":"synthetic refusal"}}`, false},
		{"wrong top-level type control", `"not-an-object"`, false},
		{"success", `{"return":{}}`, true},
		{"success with id", `{"return":{},"id":"x"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socketPath := qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
				request := readQGARequest(t, reader)
				arguments, _ := request["arguments"].(map[string]any)
				if err := encoder.Encode(map[string]any{"return": arguments["id"]}); err != nil {
					return
				}
				if request = readQGARequest(t, reader); request["execute"] != "guest-ping" {
					t.Errorf("unexpected command %v", request)
					return
				}
				_ = encoder.Encode(json.RawMessage(tc.reply))
			})
			result := NewQGAProber(socketPath, "ping", "", true, time.Second, "required agent ping").Probe(context.Background())
			if result.Passed != tc.pass || result.Skipped {
				t.Fatalf("ping reply %s: result = %+v, want passed=%v", tc.reply, result, tc.pass)
			}
		})
	}
}

// The sync id is never zero, which is what an absent or null return
// value decodes to, and is drawn from a range wide enough that a stale reply
// cannot echo it by chance.
func TestSyncIDIsNeverZeroAndIsWide(t *testing.T) {
	var largest int64
	for i := 0; i < 200000; i++ {
		id := newSyncID()
		if id < 1 || id > maxSyncID {
			t.Fatalf("sync id %d outside [1, %d]", id, int64(maxSyncID))
		}
		largest = max(largest, id)
	}
	if largest < 1<<40 {
		t.Fatalf("largest of 200000 sync ids is %d, want ids drawn from the whole range up to %d", largest, int64(maxSyncID))
	}
}

// The handshake is complete only on a reply that carries an integer
// return member equal to its own id and no error member. An object without a
// return member (which decodes as zero), null, zero, a different id, a
// string, a float, and a reply that also carries an error are none of them
// it; without the genuine reply behind them the handshake fails, and with it
// they are read past.
func TestDialAcceptsOnlyAnExplicitMatchingSyncReply(t *testing.T) {
	notOurs := map[string]func(int64) string{
		"unrelated object": func(int64) string { return "{\"unrelated\":\"missing return\"}\n" },
		"empty object":     func(int64) string { return "{}\n" },
		"json null":        func(int64) string { return "null\n" },
		"null return":      func(int64) string { return "{\"return\":null}\n" },
		"zero":             func(int64) string { return "{\"return\":0}\n" },
		"another id":       func(id int64) string { return fmt.Sprintf("{\"return\":%d}\n", id+1) },
		"id as string":     func(id int64) string { return fmt.Sprintf("{\"return\":\"%d\"}\n", id) },
		"id as float":      func(id int64) string { return fmt.Sprintf("{\"return\":%d.5}\n", id) },
		"id in an object":  func(id int64) string { return fmt.Sprintf("{\"return\":{\"id\":%d}}\n", id) },
		"our id beside an error": func(id int64) string {
			return fmt.Sprintf("{\"return\":%d,\"error\":{\"class\":\"GenericError\",\"desc\":\"contradictory\"}}\n", id)
		},
	}
	for name, reply := range notOurs {
		t.Run(name+" alone", func(t *testing.T) {
			client, err := Dial(staleSyncAgent(t, reply, true), 200*time.Millisecond)
			if err == nil {
				_ = client.Close()
				t.Fatalf("Dial accepted %s as the sync reply", name)
			}
		})
		t.Run(name+" before the reply", func(t *testing.T) {
			client, err := Dial(staleSyncAgent(t, reply, false), time.Second)
			if err != nil {
				t.Fatalf("Dial with %s ahead of the reply = %v, want it read past", name, err)
			}
			_ = client.Close()
		})
	}
}

// The full path, through the actual required prober. An unrelated object sits
// in the channel ahead of the genuine sync reply, and the agent then never
// answers guest-ping. With a zero sync id the unrelated object would be taken
// for the sync reply, the genuine reply read as the ping's, and a required ping
// would pass without any ping response.
func TestRequiredPingDoesNotPassOnAShiftedSyncReply(t *testing.T) {
	stale := func(int64) string { return "{\"unrelated\":\"missing return\"}\n" }
	socketPath := staleSyncAgent(t, stale, false)
	result := NewQGAProber(socketPath, "ping", "", true, 300*time.Millisecond, "required agent ping").Probe(context.Background())
	if result.Passed || result.Skipped || !strings.Contains(result.Error, "QGA guest-ping failed") {
		t.Fatalf("required ping with no ping response = %+v, want a failure", result)
	}
}

// A ping answers with an empty object, so an expected_output on one
// could never be checked. A probe built with one fails, whether or not the
// agent answers and whether or not the probe is required, naming the way
// out; a ping without one passes.
func TestQGAProberPingWithExpectedOutputFailsClosed(t *testing.T) {
	answering := func() string {
		return qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
			for {
				request, err := readRawQGARequest(reader)
				if err != nil {
					return
				}
				switch request["execute"] {
				case "guest-sync":
					arguments, _ := request["arguments"].(map[string]any)
					_ = encoder.Encode(map[string]any{"return": arguments["id"]})
				case "guest-ping":
					_ = encoder.Encode(map[string]any{"return": map[string]any{}})
				}
			}
		})
	}
	for _, command := range []string{"ping", "guest-ping", " ping "} {
		for name, socketPath := range map[string]string{"agent answering": answering(), "no agent": filepath.Join(t.TempDir(), "absent.sock")} {
			for _, required := range []bool{true, false} {
				t.Run(fmt.Sprintf("%q, %s, required=%v", command, name, required), func(t *testing.T) {
					result := NewQGAProber(socketPath, command, "IMPOSSIBLE-AUDIT-SUBSTRING", required, time.Second, "guest agent ping").Probe(context.Background())
					if result.Passed || result.Skipped || !strings.Contains(result.Error, "has no output to match against expected_output") || !strings.Contains(result.Error, "remove expected_output") {
						t.Fatalf("ping with an expected output = %+v, want a failure naming the way out", result)
					}
				})
			}
		}
		t.Run(fmt.Sprintf("%q without expected output passes (control)", command), func(t *testing.T) {
			result := NewQGAProber(answering(), command, "", true, time.Second, "guest agent ping").Probe(context.Background())
			if !result.Passed || result.Skipped || !strings.Contains(result.Detail, "guest-ping responsive") {
				t.Fatalf("ping without expected output = %+v, want a pass", result)
			}
		})
	}
	// The commands that do produce output still enforce it.
	socketPath := qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		for {
			request, err := readRawQGARequest(reader)
			if err != nil {
				return
			}
			switch request["execute"] {
			case "guest-sync":
				arguments, _ := request["arguments"].(map[string]any)
				_ = encoder.Encode(map[string]any{"return": arguments["id"]})
			case "guest-get-host-name":
				_ = encoder.Encode(map[string]any{"return": map[string]any{"host-name": "restored-guest"}})
			}
		}
	})
	if result := NewQGAProber(socketPath, "hostname", "another-guest", true, time.Second, "host name").Probe(context.Background()); result.Passed {
		t.Fatalf("hostname with a mismatching expected output passed: %+v", result)
	}
}

// A command that plan validation accepts after trimming its space runs as
// the trimmed command: " ping " is the agent's guest-ping, not the ping(8)
// program run through /bin/sh.
func TestQGAProberRunsTheCommandPlanValidationApproved(t *testing.T) {
	executed := make(chan string, 16)
	socketPath := qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		for {
			request, err := readRawQGARequest(reader)
			if err != nil {
				return
			}
			command, _ := request["execute"].(string)
			executed <- command
			switch command {
			case "guest-sync":
				arguments, _ := request["arguments"].(map[string]any)
				_ = encoder.Encode(map[string]any{"return": arguments["id"]})
			default:
				_ = encoder.Encode(map[string]any{"return": map[string]any{}})
			}
		}
	})
	result := NewQGAProber(socketPath, "  guest-ping\t", "", true, time.Second, "padded ping").Probe(context.Background())
	if !result.Passed {
		t.Fatalf("padded ping = %+v, want a pass", result)
	}
	var got []string
	for len(executed) > 0 {
		got = append(got, <-executed)
	}
	if strings.Join(got, ",") != "guest-sync,guest-ping" {
		t.Fatalf("agent commands = %v, want guest-sync then guest-ping and no guest-exec", got)
	}
}

func TestQGAProberServiceNoHostNameFallback(t *testing.T) {
	var hostNameRequested bool
	socketPath := qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		for {
			request, err := readRawQGARequest(reader)
			if err != nil {
				return
			}
			switch request["execute"] {
			case "guest-sync":
				arguments, _ := request["arguments"].(map[string]any)
				_ = encoder.Encode(map[string]any{"return": arguments["id"]})
			case "guest-exec":
				_ = encoder.Encode(map[string]any{"error": map[string]any{"class": "GenericError", "desc": "Command guest-exec has been disabled"}})
			case "guest-get-host-name":
				hostNameRequested = true
				_ = encoder.Encode(map[string]any{"return": map[string]any{"host-name": "cs-postgresql-rocky-01"}})
			default:
				_ = encoder.Encode(map[string]any{"error": map[string]any{"desc": "unexpected command"}})
			}
		}
	})
	// expected_output deliberately matches the guest host name: a host-name
	// fallback would turn this into a pass without checking the service.
	result := NewQGAProber(socketPath, "systemctl is-active postgresql", "postgresql", true, time.Second, "service check").Probe(context.Background())
	if result.Passed {
		t.Fatalf("service check passed through the host-name fallback: %+v", result)
	}
	if !strings.Contains(result.Error, "QGA execution failed") {
		t.Fatalf("service check error = %q, want the guest-exec failure", result.Error)
	}
	if hostNameRequested {
		t.Fatal("service check must not consult guest-get-host-name")
	}
}

func TestQGAExitReportsStdout(t *testing.T) {
	socketPath := qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		for {
			request, err := readRawQGARequest(reader)
			if err != nil {
				return
			}
			switch request["execute"] {
			case "guest-sync":
				arguments, _ := request["arguments"].(map[string]any)
				_ = encoder.Encode(map[string]any{"return": arguments["id"]})
			case "guest-exec":
				_ = encoder.Encode(map[string]any{"return": map[string]any{"pid": 962}})
			case "guest-exec-status":
				_ = encoder.Encode(map[string]any{"return": map[string]any{
					"exited": true, "exitcode": 3, "out-data": base64.StdEncoding.EncodeToString([]byte("inactive\n")),
				}})
			default:
				_ = encoder.Encode(map[string]any{"error": map[string]any{"desc": "unexpected command"}})
			}
		}
	})
	result := NewQGAProber(socketPath, "systemctl is-active nginx", "", true, 2*time.Second, "service check").Probe(context.Background())
	if result.Passed || !strings.Contains(result.Error, "exited with code 3: stdout=inactive") {
		t.Fatalf("service check error = %q, want the guest's stdout answer", result.Error)
	}
}

// execStatusAgent serves one guest-exec whose guest-exec-status reply
// returns status as it is, so a test controls which termination fields the
// agent reports.
func execStatusAgent(t *testing.T, status map[string]any) string {
	t.Helper()
	return qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		for {
			request, err := readRawQGARequest(reader)
			if err != nil {
				return
			}
			switch request["execute"] {
			case "guest-sync":
				arguments, _ := request["arguments"].(map[string]any)
				_ = encoder.Encode(map[string]any{"return": arguments["id"]})
			case "guest-exec":
				_ = encoder.Encode(map[string]any{"return": map[string]any{"pid": 123}})
			case "guest-exec-status":
				_ = encoder.Encode(map[string]any{"return": status})
			default:
				_ = encoder.Encode(map[string]any{"error": map[string]any{"desc": "unexpected command"}})
			}
		}
	})
}

// The agent reports a process killed by a signal with "signal" and
// no "exitcode". That is a failure naming the signal, never exit code 0,
// even when the output holds the expected text; so is a completion that
// carries neither field, or both.
func TestQGAProberFailsCommandTerminatedBySignal(t *testing.T) {
	active := base64.StdEncoding.EncodeToString([]byte("active\n"))
	for name, tc := range map[string]struct {
		status map[string]any
		want   string
	}{
		"signal 9":             {map[string]any{"exited": true, "signal": 9, "out-data": active}, "in-guest command was terminated by signal 9: stdout=active"},
		"no exit status":       {map[string]any{"exited": true, "out-data": active}, "PID 123 exited without an exit code or signal"},
		"exit code and signal": {map[string]any{"exited": true, "exitcode": 0, "signal": 15, "out-data": active}, "both exit code 0 and signal 15"},
		"nonzero exit control": {map[string]any{"exited": true, "exitcode": 2, "out-data": active}, "in-guest command exited with code 2: stdout=active"},
	} {
		t.Run(name, func(t *testing.T) {
			socketPath := execStatusAgent(t, tc.status)
			result := NewQGAProber(socketPath, "systemctl is-active postgresql", "active", true, 2*time.Second, name).Probe(context.Background())
			if result.Passed || !strings.Contains(result.Error, tc.want) {
				t.Fatalf("%s result = %+v, want a failure containing %q", name, result, tc.want)
			}
			if strings.Contains(result.Error+result.Detail, "exit code 0;") {
				t.Fatalf("%s was reported as a normal exit: %+v", name, result)
			}
		})
	}

	socketPath := execStatusAgent(t, map[string]any{"exited": true, "exitcode": 0, "out-data": active})
	result := NewQGAProber(socketPath, "systemctl is-active postgresql", "active", true, 2*time.Second, "control").Probe(context.Background())
	if !result.Passed || !strings.Contains(result.Detail, "exit code 0; matched \"active\"") {
		t.Fatalf("explicit exit code 0 result = %+v, want a pass", result)
	}
}

// A Windows agent reports an unhandled exception as the signal, an
// NTSTATUS code; sc.exe ending that way fails, however RUNNING its output.
func TestQGAProberWindowsServiceFailsOnException(t *testing.T) {
	socketPath := execStatusAgent(t, map[string]any{
		"exited": true, "signal": int32(-1073741819), // 0xC0000005, as the agent's signed int
		"out-data": base64.StdEncoding.EncodeToString([]byte(scQueryOutput("4  RUNNING"))),
	})
	result := NewQGAProber(socketPath, "sc query W3SVC", "", true, 2*time.Second, "IIS").Probe(context.Background())
	if result.Passed || !strings.Contains(result.Error, "sc query W3SVC was terminated by exception 0xC0000005") {
		t.Fatalf("sc.exe exception result = %+v, want a failure naming the exception", result)
	}
}

// The in-guest network probe also fails a signaled command.
func TestNetworkProberFailsCommandTerminatedBySignal(t *testing.T) {
	socketPath := execStatusAgent(t, map[string]any{"exited": true, "signal": 9})
	result := NewTCPNetworkProber(socketPath, "10.60.70.15", 443, 2*time.Second, "tcp").Probe(context.Background())
	if result.Passed || !strings.Contains(result.Error, "guest network command was terminated by signal 9") {
		t.Fatalf("signaled network probe result = %+v, want a failure naming the signal", result)
	}
}

func TestExecResultOutcome(t *testing.T) {
	for _, tc := range []struct {
		result    ExecResult
		succeeded bool
		outcome   string
	}{
		{ExecResult{Exited: true}, true, "exited with code 0"},
		{ExecResult{Exited: true, ExitCode: 3}, false, "exited with code 3"},
		{ExecResult{Exited: true, ExitCode: -1, Signaled: true, Signal: 11}, false, "was terminated by signal 11"},
		{ExecResult{Exited: true, ExitCode: -1, Signaled: true, Signal: -1073741819}, false, "was terminated by exception 0xC0000005"},
		{ExecResult{}, false, "exited with code 0"},
	} {
		if got := tc.result.Succeeded(); got != tc.succeeded {
			t.Errorf("%+v Succeeded() = %v, want %v", tc.result, got, tc.succeeded)
		}
		if got := tc.result.Outcome(); got != tc.outcome {
			t.Errorf("%+v Outcome() = %q, want %q", tc.result, got, tc.outcome)
		}
	}
}

// windowsAgent serves the guest-exec exchange of a Windows guest agent: it
// records each exec request and answers with the given exit code and stdout.
func windowsAgent(t *testing.T, exitCode int, stdout string) (string, <-chan map[string]any) {
	t.Helper()
	execs := make(chan map[string]any, 4)
	socketPath := qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		for {
			request, err := readRawQGARequest(reader)
			if err != nil {
				return
			}
			switch request["execute"] {
			case "guest-sync":
				arguments, _ := request["arguments"].(map[string]any)
				_ = encoder.Encode(map[string]any{"return": arguments["id"]})
			case "guest-exec":
				execs <- request["arguments"].(map[string]any)
				_ = encoder.Encode(map[string]any{"return": map[string]any{"pid": 4242}})
			case "guest-exec-status":
				_ = encoder.Encode(map[string]any{"return": map[string]any{
					"exited": true, "exitcode": exitCode, "out-data": base64.StdEncoding.EncodeToString([]byte(stdout)),
				}})
			default:
				_ = encoder.Encode(map[string]any{"error": map[string]any{"desc": "unexpected command"}})
			}
		}
	})
	return socketPath, execs
}

func scQueryOutput(state string) string {
	return "\r\nSERVICE_NAME: MSSQL$SQLEXPRESS\r\n        TYPE               : 10  WIN32_OWN_PROCESS\r\n" +
		"        STATE              : " + state + "\r\n                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)\r\n" +
		"        WIN32_EXIT_CODE    : 0  (0x0)\r\n"
}

func TestQGAProberWindowsServiceRunsSCWithoutAShell(t *testing.T) {
	socketPath, execs := windowsAgent(t, 0, scQueryOutput("4  RUNNING"))
	result := NewQGAProber(socketPath, "sc query MSSQL$SQLEXPRESS", "", true, 2*time.Second, "SQL service").Probe(context.Background())
	if !result.Passed || !strings.Contains(result.Detail, "MSSQL$SQLEXPRESS is RUNNING") {
		t.Fatalf("running service result = %+v", result)
	}
	request := <-execs
	args, _ := request["arg"].([]any)
	if request["path"] != "sc.exe" || len(args) != 2 || args[0] != "query" || args[1] != "MSSQL$SQLEXPRESS" {
		t.Fatalf("guest-exec request = %v, want sc.exe with the literal arguments query and the service name", request)
	}
}

func TestQGAProberWindowsServiceFailsUnlessRunning(t *testing.T) {
	for name, tc := range map[string]struct {
		exitCode int
		stdout   string
		want     string
	}{
		"stopped":       {0, scQueryOutput("1  STOPPED"), "is STOPPED (state 1), not RUNNING"},
		"start pending": {0, scQueryOutput("2  START_PENDING"), "is START_PENDING (state 2), not RUNNING"},
		"not installed": {1060, "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\r\n\r\nThe specified service does not exist as an installed service.\r\n", "exited with code 1060"},
		"no state line": {0, "SERVICE_NAME: MSSQL$SQLEXPRESS\r\n", "printed no service state"},
	} {
		t.Run(name, func(t *testing.T) {
			socketPath, _ := windowsAgent(t, tc.exitCode, tc.stdout)
			result := NewQGAProber(socketPath, "sc query MSSQL$SQLEXPRESS", "", true, 2*time.Second, name).Probe(context.Background())
			if result.Passed || !strings.Contains(result.Error, tc.want) {
				t.Fatalf("%s result = %+v, want an error containing %q", name, result, tc.want)
			}
		})
	}
}

func TestQGAProberWindowsServiceHonorsExpectedOutput(t *testing.T) {
	socketPath, _ := windowsAgent(t, 0, scQueryOutput("4  RUNNING"))
	result := NewQGAProber(socketPath, "sc query MSSQL$SQLEXPRESS", "ACCEPTS_PRESHUTDOWN", true, 2*time.Second, "extra").Probe(context.Background())
	if result.Passed || !strings.Contains(result.Error, "lacks \"ACCEPTS_PRESHUTDOWN\"") {
		t.Fatalf("expected_output mismatch result = %+v", result)
	}
}

func TestWindowsServiceStateSurvivesTranslationAndHostileOutput(t *testing.T) {
	german := "\r\nDIENSTNAME: W3SVC\r\n        TYP                : 20  WIN32_SHARE_PROCESS\r\n        STATUS             : 4  RUNNING\r\n"
	if code, ok := windowsServiceState(german); !ok || code != windowsServiceRunning {
		t.Fatalf("German sc.exe output: code %d, found %v", code, ok)
	}
	for name, output := range map[string]string{
		"code and name disagree": "        STATE              : 4  STOPPED\r\n",
		"no state at all":        "SERVICE_NAME: W3SVC\r\n",
		"name without a code":    "        STATE              : RUNNING\r\n",
	} {
		if code, ok := windowsServiceState(output); ok {
			t.Errorf("%s: parsed state %d", name, code)
		}
	}

	// A hostile guest cannot put its own text, or escape sequences, into
	// the signed report through the state line.
	hostile := "        STATE              : 1  STOPPED " + strings.Repeat("X ", 300000) + "\x1b[2J\r\n"
	socketPath, _ := windowsAgent(t, 0, hostile)
	result := NewQGAProber(socketPath, "sc query W3SVC", "", true, 2*time.Second, "hostile").Probe(context.Background())
	if result.Passed || len(result.Error) > 200 || strings.Contains(result.Error, "\x1b") {
		t.Fatalf("hostile state line produced a %d-byte error %q", len(result.Error), result.Error[:min(len(result.Error), 120)])
	}
	if got := truncateForReport("ok\x1b[31m\x00\u009b\tdone\n"); got != "ok[31m\tdone\n" {
		t.Fatalf("truncateForReport kept control characters: %q", got)
	}
}

func TestWindowsServiceQueryParsesOnlyTheExactForm(t *testing.T) {
	for command, want := range map[string]string{
		"sc query W3SVC":            "W3SVC",
		"sc query MSSQL$SQLEXPRESS": "MSSQL$SQLEXPRESS",
		"sc queryex W3SVC":          "",
		"sc query":                  "",
		"sc query W3SVC extra":      "",
		"systemctl is-active nginx": "",
	} {
		got, ok := WindowsServiceQuery(command)
		if got != want || ok != (want != "") {
			t.Errorf("WindowsServiceQuery(%q) = %q, %v; want %q", command, got, ok, want)
		}
	}
}

func TestQGAProber_RequiredChannelFailsWhenUnavailable(t *testing.T) {
	prober := NewQGAProber("/tmp/certistack-qga-does-not-exist", "ping", "", true, time.Second, "required QGA")
	result := prober.Probe(context.Background())
	if result.Passed || result.Skipped {
		t.Fatalf("required unavailable QGA must fail, got %+v", result)
	}
	if !strings.Contains(result.Error, "required QGA") {
		t.Fatalf("unexpected error: %q", result.Error)
	}
}

func TestQGAProber_OptionalChannelSkipsWhenUnavailable(t *testing.T) {
	prober := NewQGAProber("/tmp/certistack-qga-does-not-exist", "ping", "", false, time.Second, "optional QGA")
	result := prober.Probe(context.Background())
	if !result.Passed || !result.Skipped {
		t.Fatalf("optional unavailable QGA must skip, got %+v", result)
	}
}

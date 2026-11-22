// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package qga

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// silentAgentSocket accepts the connection and reads the guest-sync request,
// like QEMU's socket does when no qemu-guest-agent runs behind it, and never
// answers.
func silentAgentSocket(t *testing.T) string {
	t.Helper()
	return qgaTestSocket(t, func(reader *bufio.Reader, _ *json.Encoder) {
		_, _ = readRawQGARequest(reader)
		// Until the client gives up and closes the connection.
		_, _ = reader.ReadByte()
	})
}

// A guest without a running qemu-guest-agent failed a required QGA probe with
// "required QGA channel is unavailable: QGA sync handshake failed: ... i/o
// timeout", which does not say that the agent is the thing that is missing.
func TestUnavailableChannelNamesTheMissingAgent(t *testing.T) {
	// The handshake error as the report carried it.
	_, err := Dial(silentAgentSocket(t), 200*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "QGA sync handshake failed") || !strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("Dial to a silent agent = %v, want the handshake to fail with an i/o timeout", err)
	}
	if !IsAgentSilent(err) {
		t.Fatalf("IsAgentSilent(%v) = false", err)
	}

	for _, required := range []bool{true, false} {
		t.Run(fmt.Sprintf("required=%v", required), func(t *testing.T) {
			// The probe's own budget ends the handshake, as it does in a run.
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			result := NewQGAProber(silentAgentSocket(t), "systemctl is-active nginx", "", required, time.Second, "nginx is running").Probe(ctx)
			text := result.Error
			if !required {
				if !result.Skipped || !result.Passed {
					t.Fatalf("an optional probe of a silent agent = %+v, want a skip", result)
				}
				text = result.Detail
			} else if result.Passed {
				t.Fatalf("a required probe of a silent agent passed: %+v", result)
			}
			for _, want := range []string{
				"QGA sync handshake failed",
				"qemu-guest-agent is not running in the guest",
				"Install and start qemu-guest-agent",
				"take a new backup",
				"tcp or http probe",
			} {
				if !strings.Contains(text, want) {
					t.Errorf("text lacks %q: %s", want, text)
				}
			}
			if required && !strings.HasPrefix(text, "required QGA channel is unavailable: ") {
				t.Errorf("the required failure does not start with the usual prefix: %s", text)
			}
		})
	}
}

// Other ways the channel can fail are not the agent's silence and get no such
// remedy.
func TestUnavailableChannelAdviceIsForASilentAgentOnly(t *testing.T) {
	notAnAgent := qgaConnTestSocket(t, func(conn net.Conn) {
		_, _ = bufio.NewReader(conn).ReadBytes('\n')
		_, _ = conn.Write([]byte("{\"error\":{\"class\":\"GenericError\",\"desc\":\"JSON parse error\"}}\n"))
	})
	_, parseErr := Dial(notAnAgent, 200*time.Millisecond)
	for _, tc := range []struct {
		name   string
		err    error
		advice bool
	}{
		{"handshake that timed out", fmt.Errorf("%w: %w", errSyncHandshake, os.ErrDeadlineExceeded), true},
		{"handshake the probe's budget ended", fmt.Errorf("%w: qga: guest-sync interrupted: %w", errSyncHandshake, context.DeadlineExceeded), true},
		{"socket missing", fmt.Errorf("qga: failed to connect to socket /var/run/qemu-server/100.qga: %w", os.ErrNotExist), false},
		{"agent error", parseErr, false},
		{"timeout after the handshake", fmt.Errorf("failed to read guest-ping response: %w", os.ErrDeadlineExceeded), false},
		{"interrupted handshake", fmt.Errorf("%w: %w", errSyncHandshake, context.Canceled), false},
		{"handshake with no reply of its own", fmt.Errorf("%w: qga: no guest-sync response in 100 bytes of earlier data", errSyncHandshake), false},
		{"no error", nil, false},
	} {
		if got := unavailableAdvice(tc.err); (got != "") != tc.advice {
			t.Errorf("%s (%v): advice %q, want advice = %v", tc.name, tc.err, got, tc.advice)
		}
	}
	missing := NewQGAProber("/tmp/certistack-qga-does-not-exist", "ping", "", true, time.Second, "required QGA").Probe(context.Background())
	if missing.Passed || strings.Contains(missing.Error, "qemu-guest-agent") {
		t.Errorf("a missing socket was blamed on the agent: %+v", missing)
	}
}

// The stock qemu-guest-agent of the Red Hat family answers guest-exec with
// "Command guest-exec has been disabled: the command is not allowed", and a
// probe such as `systemctl is-active nginx` failed with only that text.
func TestDisabledGuestExecNamesTheAllowList(t *testing.T) {
	const agentText = "QGA guest-exec error: Command guest-exec has been disabled: the command is not allowed"
	for _, tc := range []struct {
		name, command, errorPrefix string
	}{
		{"systemd service", "systemctl is-active nginx", "QGA execution failed: "},
		{"Windows service", "sc query EventLog", "QGA execution of sc.exe failed: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socketPath := qgaTestSocket(t, guestExecAgent("Command guest-exec has been disabled: the command is not allowed"))
			result := NewQGAProber(socketPath, tc.command, "active", true, time.Second, "service check").Probe(context.Background())
			if result.Passed {
				t.Fatalf("a refused guest-exec passed: %+v", result)
			}
			if !strings.HasPrefix(result.Error, tc.errorPrefix+agentText) {
				t.Errorf("error does not start with the agent's own words: %s", result.Error)
			}
			for _, want := range []string{
				"the guest agent's allow-list refuses guest-exec",
				"stock setting on Red Hat family guests",
				"Rocky Linux, AlmaLinux, RHEL and Oracle Linux",
				"tcp or http probe",
				"Issue 32 at https://certistack.dev/docs/troubleshooting/#issue-32",
			} {
				if !strings.Contains(result.Error, want) {
					t.Errorf("error lacks %q: %s", want, result.Error)
				}
			}
		})
	}

	// A different refusal, or the same words about another command, are not
	// the allow-list.
	for _, desc := range []string{"Invalid parameter 'path'", "Command guest-exec failed"} {
		socketPath := qgaTestSocket(t, guestExecAgent(desc))
		result := NewQGAProber(socketPath, "systemctl is-active nginx", "active", true, time.Second, "service check").Probe(context.Background())
		if strings.Contains(result.Error, "allow-list") {
			t.Errorf("agent text %q got the allow-list remedy: %s", desc, result.Error)
		}
	}
	if IsGuestExecDisabled(&AgentError{Command: "guest-ping", Desc: "Command guest-ping has been disabled: the command is not allowed"}) {
		t.Error("a disabled guest-ping was reported as a disabled guest-exec")
	}
	if !IsGuestExecDisabled(fmt.Errorf("wrapped: %w", &AgentError{Command: "guest-exec", Desc: "Command guest-exec has been disabled"})) {
		t.Error("a wrapped disabled guest-exec was not recognised")
	}
	if IsGuestExecDisabled(errors.New(agentText)) {
		t.Error("plain text that merely reads like the agent's error was recognised")
	}
}

// guestExecAgent answers the handshake and refuses guest-exec with desc.
func guestExecAgent(desc string) func(*bufio.Reader, *json.Encoder) {
	return func(reader *bufio.Reader, encoder *json.Encoder) {
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
				_ = encoder.Encode(map[string]any{"error": map[string]any{"class": "GenericError", "desc": desc}})
			default:
				_ = encoder.Encode(map[string]any{"error": map[string]any{"desc": "unexpected command"}})
			}
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package qga

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The prober runs any command outside its fast paths as "/bin/sh -c"
// in the guest, so it refuses a command the plan allowlist refuses, however
// the prober was built: before the agent is asked, required or not, and as a
// failure (an optional probe whose agent is absent is skipped, and a refused
// command must not be hidden by that skip).
func TestQGAProberRefusesACommandOffTheAllowlist(t *testing.T) {
	for _, command := range []string{
		"printf audit-qga-alias-marker",
		"hostname; id",
		"systemctl is-active ssh && id",
		"sc query W3SVC & whoami",
		"cat /etc/shadow",
		"",
	} {
		for _, required := range []bool{true, false} {
			executed := make(chan string, 16)
			socketPath := qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
				for {
					request, err := readRawQGARequest(reader)
					if err != nil {
						return
					}
					name, _ := request["execute"].(string)
					executed <- name
					arguments, _ := request["arguments"].(map[string]any)
					_ = encoder.Encode(map[string]any{"return": arguments["id"]})
				}
			})
			result := NewQGAProber(socketPath, command, "", required, time.Second, "refused").Probe(context.Background())
			if result.Passed || result.Skipped || !strings.Contains(result.Error, "arbitrary guest shell commands are not permitted") {
				t.Errorf("command %q (required %v): %+v, want a failure that names the allowlist", command, required, result)
			}
			if len(executed) != 0 {
				t.Errorf("command %q (required %v): the agent was asked %d times, want it never asked", command, required, len(executed))
			}
		}
	}

	// The optional probe whose agent is absent: a refused command still fails.
	result := NewQGAProber("/tmp/certistack-qga-does-not-exist", "printf x", "", false, time.Second, "optional").Probe(context.Background())
	if result.Passed || result.Skipped {
		t.Errorf("an optional probe with a refused command and no agent = %+v, want a failure, not a skip", result)
	}
}

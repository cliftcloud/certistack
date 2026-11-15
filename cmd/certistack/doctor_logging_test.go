// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/runner"
)

// The structured log line a PBS lookup writes ("level=INFO msg=resolved latest
// PBS snapshot ...") did not belong in the human report: it is not shown
// unless --debug asks for it (hardening F14, CR1-14).
func TestDoctorHumanOutputCarriesNoStructuredInfoLine(t *testing.T) {
	logging := func(context.Context, *config.Plan, runner.Options) ([]runner.SourceCheck, error) {
		slog.Info("resolved latest PBS snapshot", "group", "vm/7011", "snapshot", "vm/7011/2026-10-02T03:00:01Z")
		return []runner.SourceCheck{{VMID: 9100, Status: runner.SourcePassed, Detail: "vm/7011/2026-10-02T03:00:01Z; BIOS; 1 disk(s) restored"}}, nil
	}
	for name, test := range map[string]struct {
		extra   []string
		visible bool
	}{
		"human output": {nil, false},
		"with --debug": {[]string{"--debug"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			root, args := readyHost(t, logging)
			previousDefault := slog.Default()
			t.Cleanup(func() { slog.SetDefault(previousDefault) })
			stderr := captureStderr(t, func() {
				out, err := runRootWithInput(t, "", append(append([]string{"doctor", planWithScratch(t, root, "")}, args...), test.extra...)...)
				if err != nil {
					t.Fatalf("doctor: %v\n%s", err, out)
				}
				if strings.Contains(out, "level=INFO") {
					t.Errorf("the report has a log line:\n%s", out)
				}
			})
			if got := strings.Contains(stderr, "resolved latest PBS snapshot"); got != test.visible {
				t.Errorf("the structured line is on standard error = %v, want %v:\n%s", got, test.visible, stderr)
			}
		})
	}
}

// captureStderr runs fn with os.Stderr replaced by a pipe and returns what was
// written to it. The command installs its log handler on os.Stderr as it starts.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = writer
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		done <- string(data)
	}()
	func() {
		defer func() { os.Stderr = previous }()
		fn()
	}()
	_ = writer.Close()
	return <-done
}

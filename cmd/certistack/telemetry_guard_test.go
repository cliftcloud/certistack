// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cliftcloud/certistack/pkg/telemetry"
)

// No test in this package may ask a developer's terminal the first-run
// question, read the answer they gave on their own machine, or send them
// anywhere: by default every test sees a process with no terminal and a
// manager that is forced off, with its state in a directory nothing writes.
// A test that wants the real behaviour takes a newTelemetryRig, which
// replaces both. (TestMain is taken by process_test.go, and the process tests
// run this binary's main, which inherits the guard.)
func init() {
	newTelemetryManager = func() *telemetry.Manager {
		return &telemetry.Manager{
			Version:   "test",
			StatePath: filepath.Join(os.TempDir(), "certistack-tests-never-write-here", "telemetry.json"),
			Getenv: func(name string) string {
				if name == telemetry.VarTelemetry {
					return "off"
				}
				return ""
			},
		}
	}
	processTelemetryTerminals = func() telemetryTerminals {
		return telemetryTerminals{Stdin: strings.NewReader(""), Stderr: io.Discard}
	}
}

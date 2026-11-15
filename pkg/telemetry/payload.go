// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package telemetry is CertiStack's opt-in usage report: five fields, off by
// default, sent at most once a day after a completed run (an opt-in through the
// environment keeps an install in the state file for that, and sends nothing
// where it cannot), and never from the PVE node. docs/telemetry.md is the
// user-facing statement of everything here.
//
// The privacy properties are structural, not promised:
//
//   - What is sent is the Payload struct and nothing else; a test pins its five
//     fields and the bytes it encodes to.
//   - Nothing reaches the network unless the decision (Manager) says enabled.
//   - The cluster identity the run knows is hashed with a per-install salt into
//     a local set; only the size of the set is sent.
package telemetry

import (
	"encoding/json"
	"strings"
)

// DateLayout is the form of last_test_run: a UTC calendar date, no time of day.
const DateLayout = "2006-01-02"

// MaxVersionLen bounds the version string.
const MaxVersionLen = 64

// Payload is the whole report. It is the request body, encoded by Encode, and
// `certistack telemetry show` prints the same bytes. Do not add a field without
// changing the test that pins this struct, docs/telemetry.md and the receiver.
type Payload struct {
	// InstallID is a random UUID v4 made when the user opts in. It is derived
	// from nothing on the machine.
	InstallID string `json:"install_id"`
	// Version is the CertiStack version string, printable ASCII, at most 64.
	Version string `json:"version"`
	// ClusterCount is how many distinct Proxmox VE clusters this installation
	// has tested on: clusters by the SHA-256 of the cluster CA certificate the
	// controller pins (the nodes of one cluster share it), or by node name where
	// the run has no CA file. The hashes it is counted from never leave the
	// machine.
	ClusterCount int `json:"cluster_count"`
	// LastTestRun is the UTC date (2006-01-02) of the last completed restore
	// test; empty until one has completed.
	LastTestRun string `json:"last_test_run"`
	// BusinessUse is the answer to "Do you use CertiStack for a business or
	// commercial purpose?".
	BusinessUse bool `json:"business_use"`
}

// Encode is the canonical request body: the payload as indented JSON with a
// final newline. `telemetry show` prints exactly these bytes.
func (p Payload) Encode() []byte {
	out, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		// Five strings, an int and a bool cannot fail to encode.
		panic("telemetry: encode payload: " + err.Error())
	}
	return append(out, '\n')
}

// SanitizeVersion is the version as it may be sent: printable ASCII only (so
// it cannot carry a control character, a newline or a non-ASCII byte), at most
// MaxVersionLen, and "unknown" when nothing is left.
func SanitizeVersion(v string) string {
	var b strings.Builder
	for i := 0; i < len(v) && b.Len() < MaxVersionLen; i++ {
		if c := v[i]; c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

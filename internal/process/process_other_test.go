//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package process

import (
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
)

func TestStopRecorded_FailsClosedWithoutIdentity(t *testing.T) {
	err := StopRecorded(journal.Process{PID: 1234, StartTicks: "54321"})
	if err == nil {
		t.Fatal("StopRecorded succeeded without a verifiable process identity")
	}
}

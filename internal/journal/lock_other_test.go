//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

import "testing"

func TestLock_FailsClosedWithoutPortableImplementation(t *testing.T) {
	if _, err := Lock(); err == nil {
		t.Fatal("Lock succeeded without a portable host-wide lock")
	}
}

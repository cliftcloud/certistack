//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"context"
	"testing"
)

// Off Linux no check runs, and the host is not called ready.
func TestCheckOffLinuxRunsNothingAndIsNotReady(t *testing.T) {
	result := Check(context.Background(), nil, Options{})
	if result.Ready {
		t.Error("a platform no check ran on was called ready")
	}
	if len(result.Checks) != 1 || result.Checks[0].Status != "skipped" || result.Checks[0].Detail != "preflight checks run only on Linux" {
		t.Errorf("checks = %+v, want the one skipped Platform item", result.Checks)
	}
}

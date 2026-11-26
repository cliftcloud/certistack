//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import "context"

// The node worker runs only on Linux, where admission_linux.go reads /proc.
// Elsewhere nothing can be measured: these stubs report no memory and no I/O
// wait, so a check on another platform measures nothing and grants the run,
// and ReservationFits judges no reservation. They exist so that the controller
// and the other tools build there.

func readRAMUsagePercent() (float64, error) {
	return 0.0, nil
}

func readRAMCapacityMB() (totalMB, availableMB float64, err error) {
	return 0.0, 0.0, nil
}

func readIOWaitPercent(ctx context.Context) (float64, error) {
	return 0.0, nil
}

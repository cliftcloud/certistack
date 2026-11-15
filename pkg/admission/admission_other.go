//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package admission

import "context"

func readRAMUsagePercent() (float64, error) {
	return 0.0, nil
}

func readRAMCapacityMB() (totalMB, availableMB float64, err error) {
	return 0.0, 0.0, nil
}

func readIOWaitPercent(ctx context.Context) (float64, error) {
	return 0.0, nil
}

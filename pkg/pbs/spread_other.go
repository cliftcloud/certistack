//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

// scanSpread exists only on Linux, where PBS maps and NUMA nodes are.
type scanSpread struct{}

func startScanSpread(string) *scanSpread { return nil }

// ScanSpreadNodes is 0: scans spread only on Linux.
func ScanSpreadNodes() int     { return 0 }
func (s *scanSpread) at(int64) {}
func (s *scanSpread) stop()    {}

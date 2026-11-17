// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package repocontract has no code of its own. Its tests check that the
// files shipped around the Go code (the GitHub workflows, the appliance
// wrapper and the controller installation instructions) do what they say,
// by parsing them and running their shell against local stubs. Nothing
// they run reaches a network, registry or PVE node.
package repocontract

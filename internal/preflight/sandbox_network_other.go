//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import "errors"

// ReadNodeNetworks cannot read a node's networks off Linux, where no node
// worker runs: the check that needs them reports that it could not be made.
func ReadNodeNetworks() (NodeNetworks, error) {
	return NodeNetworks{}, errors.New("reading a node's routes is supported only on Linux")
}

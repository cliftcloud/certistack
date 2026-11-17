// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build !linux

package synthetic

import (
	"fmt"
	"syscall"
)

// bindToDevice fails closed: only the Linux worker can pin a socket to the
// sandbox interface, and an unpinned probe is not evidence about the guest.
func bindToDevice(iface string) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error {
		return fmt.Errorf("binding a probe to sandbox interface %s requires Linux", iface)
	}
}

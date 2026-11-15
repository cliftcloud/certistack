// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindToDevice sets SO_BINDTODEVICE so the kernel routes the socket only
// through iface, whatever the host routing table says about the target.
func bindToDevice(iface string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, conn syscall.RawConn) error {
		var bindErr error
		if err := conn.Control(func(fd uintptr) {
			bindErr = unix.BindToDevice(int(fd), iface)
		}); err != nil {
			return err
		}
		if bindErr != nil {
			return fmt.Errorf("bind probe socket to sandbox interface %s: %w", iface, bindErr)
		}
		return nil
	}
}

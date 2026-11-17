// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"net"
	"strconv"
)

// hostPort is host:port the way the probers record it, with an IPv6 host in
// brackets ("[fd00:10::5]:5432"). Gluing the two with a bare colon reads as
// the address "fd00:10::5:5432" and is not an address the prober can dial.
func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

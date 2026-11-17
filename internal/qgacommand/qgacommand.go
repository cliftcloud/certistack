// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package qgacommand is the one list of commands a plan may run in a guest
// through the QEMU guest agent. Plan validation, the probe dispatcher and the
// guest-agent prober all ask it, so a command one of them refuses is refused
// by the others: the agent runs anything that is not a fast-path command as
// "/bin/sh -c <command>" in the recovered guest, so this list is the only
// thing between a plan's text and a shell there.
package qgacommand

import (
	"regexp"
	"strings"
)

// Description names the allowed commands, for an error message.
const Description = "hostname, guest-get-host-name, ping, guest-ping, 'systemctl is-active <service>', or 'sc query <service>'"

var (
	systemdServiceExpr = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@_.-]{0,127}$`)
	// Windows service key names such as MSSQL$SQLEXPRESS. sc.exe runs without
	// a shell, so "$" is literal.
	windowsServiceExpr = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9$_.-]{0,255}$`)
)

// Allowed reports whether command is one a plan may run in a guest: a host
// name read, a guest-agent ping, "systemctl is-active <service>" or
// "sc query <service>". It keeps a plan author from turning a service-health
// assertion into arbitrary shell execution in a recovered guest; network
// probes are constructed internally, and plan-authored QGA probes expose only
// these narrow read-only operations. The surrounding space is ignored, as the
// prober ignores it.
func Allowed(command string) bool {
	command = strings.TrimSpace(command)
	switch command {
	case "hostname", "guest-get-host-name", "ping", "guest-ping":
		return true
	}
	if service, found := strings.CutPrefix(command, "sc query "); found {
		return windowsServiceExpr.MatchString(service)
	}
	const prefix = "systemctl is-active "
	if !strings.HasPrefix(command, prefix) {
		return false
	}
	return systemdServiceExpr.MatchString(strings.TrimPrefix(command, prefix))
}

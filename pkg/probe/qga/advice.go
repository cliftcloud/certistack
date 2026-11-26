// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package qga

import (
	"context"
	"errors"
	"os"
	"strings"
)

// errSyncHandshake begins the error of a guest-sync handshake that failed. The
// text is fixed: IsAgentSilent and the reports carry it.
var errSyncHandshake = errors.New("QGA sync handshake failed")

// IsGuestExecDisabled reports whether err is the guest agent refusing
// guest-exec by its own policy: "Command guest-exec has been disabled: the
// command is not allowed". The stock qemu-guest-agent of the Red Hat family
// (Rocky Linux, AlmaLinux, RHEL, Oracle Linux) is configured that way, with an
// allow-list in /etc/sysconfig/qemu-ga that has no guest-exec.
func IsGuestExecDisabled(err error) bool {
	var refusal *AgentError
	if !errors.As(err, &refusal) || refusal.Command != "guest-exec" {
		return false
	}
	desc := strings.ToLower(refusal.Desc)
	return strings.Contains(desc, "has been disabled") || strings.Contains(desc, "is not allowed")
}

// IsAgentSilent reports whether err is a guest-sync handshake the guest agent
// never answered within its time: the QEMU socket is there and accepts the
// connection whether or not an agent is running behind it, so an agent that is
// not installed, not started, or not yet booted shows as a timeout.
func IsAgentSilent(err error) bool {
	return errors.Is(err, errSyncHandshake) &&
		(errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded))
}

// agentSilentAdvice and guestExecDisabledAdvice are appended to the errors
// above. They are fixed text: the report records them, and they hold nothing of
// the guest.
const (
	agentSilentAdvice = " (the guest agent did not answer in time: qemu-guest-agent is not running in the guest, or the guest had not finished starting. " +
		"Install and start qemu-guest-agent in the guest (on Windows, the VirtIO guest agent) and take a new backup, or probe the service over the network instead with a tcp or http probe)"
	guestExecDisabledAdvice = " (the guest agent's allow-list refuses guest-exec, which is the stock setting on Red Hat family guests such as Rocky Linux, AlmaLinux, RHEL and Oracle Linux, " +
		"so no command can run inside this guest. Probe the service over the network instead with a tcp or http probe; see Issue 32 at https://certistack.dev/docs/troubleshooting/#issue-32)"
)

// unavailableAdvice is the remedy for a channel that did not come up, or "".
func unavailableAdvice(err error) string {
	if IsAgentSilent(err) {
		return agentSilentAdvice
	}
	return ""
}

// execAdvice is the remedy for a guest-exec the agent refused, or "".
func execAdvice(err error) string {
	if IsGuestExecDisabled(err) {
		return guestExecDisabledAdvice
	}
	return ""
}

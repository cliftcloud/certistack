// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/process"
)

// versionOutputLimit bounds what `proxmox-backup-client version` may write:
// it prints two lines.
const versionOutputLimit = 64 << 10

// versionTimeout bounds the command whatever deadline its caller sets (the
// earlier one wins): asking the server for its version is one request. A var
// so a test can shorten it.
var versionTimeout = 15 * time.Second

// Versions runs `proxmox-backup-client version` with this client's scoped
// environment and returns the client's version and the PBS server's, as the
// client wrote them. The server's is empty when the client could not reach
// the repository (none configured, wrong credentials, unreachable): the
// command then prints the client line alone. A command that failed after it
// printed a version still returns what it printed; an error is returned only
// when it printed none, and it names the failure without the client's output,
// which can echo the repository. Callers treat a version they could not read
// as unknown, not as a failure (internal/support).
func (c *Client) Versions(ctx context.Context) (client, server string, err error) {
	runCtx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	output, runErr := process.CombinedOutputLimited(c.command(runCtx, []string{"version"}), versionOutputLimit)
	client, server = ParseVersionOutput(output)
	if client == "" && server == "" && runErr != nil {
		return "", "", commandFailure("read the PBS client's version", runErr, output)
	}
	return client, server, nil
}

// ParseVersionOutput reads the text `proxmox-backup-client version` prints:
//
//	client version: 4.2.5
//	server version: 4.2.7
//
// The server line is absent when the client could not reach the server, and
// the client may write other lines around them (a connection error, a
// warning). The first of each line wins; a line that is not one of them, and
// a value-less line, is ignored. A version it cannot find is empty.
func ParseVersionOutput(output []byte) (client, server string) {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "client version":
			if client == "" {
				client = fields[0]
			}
		case "server version":
			if server == "" {
				server = fields[0]
			}
		}
	}
	return client, server
}

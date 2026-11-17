// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"strings"
)

// Version is the Proxmox VE version the API reports (GET /version: "8.4.1",
// "9.1.1"), as the node wrote it. Any authenticated token may read it. An
// answer without a version is an empty string, not an error: what a caller
// does with a version it cannot read is its decision (see internal/support).
func (c *Client) Version(ctx context.Context) (string, error) {
	var result struct {
		Version string `json:"version"`
	}
	if err := c.Do(ctx, "GET", "version", nil, &result); err != nil {
		return "", err
	}
	return strings.TrimSpace(result.Version), nil
}

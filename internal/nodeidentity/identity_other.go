// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build !linux

package nodeidentity

// readLocalName is the short host name: PVE runs on Linux only, so there is no
// /etc/pve/local to read elsewhere.
func readLocalName() (string, error) { return shortHostName() }

// onPVENode is false: PVE runs on Linux only.
func onPVENode() bool { return false }

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import "strings"

// The known_hosts file is the controller's only trust in the node, and the
// SSH identity is how the node knows the controller: whoever can change either
// can stand in for one of them. Each is refused when someone other than the
// user running CertiStack, or root, could change it (UnsafeToTrust), wherever
// it is read: every command's SSH validation, check's layer 2, and setup.
const (
	KnownHostsWhat = "the SSH known_hosts file"
	KnownHostsRisk = "add a host key for the node and answer as the node, making a report say anything"
	IdentityWhat   = "the SSH identity"
	IdentityRisk   = "replace the key the controller signs in to the node with"
)

// UntrustedFileError is a file the controller trusts (a known_hosts file, an
// SSH identity) that someone other than the user running CertiStack, or root,
// could change: OpenSSH's StrictModes rule. Problem says what is wrong and what
// that someone could do; Fix is the command that makes the file safe.
type UntrustedFileError struct {
	Path    string
	Problem string
	Fix     string
}

func (e *UntrustedFileError) Error() string { return e.Problem + "; " + e.Fix }

// shellWord is word as one shell word: unchanged when it holds only characters
// a shell leaves alone, else in single quotes. It is for printed commands.
func shellWord(word string) string {
	if word != "" && !strings.ContainsFunc(word, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_-./:@%+=,", r))
	}) {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
}

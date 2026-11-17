// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package nodeidentity checks that the node name a command was given is the
// PVE name of the host the command runs on.
//
// A run, a plan or a check is addressed to a PVE node twice: by the SSH host
// the temporary worker is staged on, and by the node name the worker is told
// to use for every PVE API call. When the two disagree (a typo, a copied
// environment file, a node that was renamed) the worker runs on one node and
// the plan addresses another, and the failure comes late and cryptically ("proxy
// loop detected", "HTTP 500", "limited to nodes ..."). PVE names a node's
// directory in its cluster file system after the node, and /etc/pve/local is
// the link to this node's own, so the host knows its PVE name for certain.
package nodeidentity

import (
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// hostname is the host's name; a variable so that a test can name any host.
var hostname = os.Hostname

// localName is the PVE name of this host (Linux: identity_linux.go, which reads
// PVE's own link and falls back to the short host name; elsewhere:
// identity_other.go, the short host name).
var localName = readLocalName

// nodeNameExpr is what a PVE node name looks like in a link target.
var nodeNameExpr = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)

// safeName is a name that may be shown as it is.
var safeName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func show(name string) string {
	if safeName.MatchString(name) {
		return name
	}
	// ASCII-only: a Cyrillic or other lookalike letter would print as the real one.
	return strconv.QuoteToASCII(name)
}

// Local is the PVE name of the host this process runs on: the basename of the
// target of /etc/pve/local (nodes/<name>), or, where that link does not exist
// (not a PVE host, a test), the short host name.
func Local() (string, error) { return localName() }

// OnPVENode is false only when this host is evidently not a PVE node: no
// /etc/pve (PVE's cluster file system) and neither pveversion nor qm on the
// PATH. A controller is such a host; a command that works on the node itself
// uses it to stop early instead of failing on tools and services that are not
// there.
func OnPVENode() bool { return onPVENode() }

// Verify is nil when named is this host's PVE node name, compared exactly:
// the API knows nodes by name and tells them apart by case. An empty name is a
// name left out, whose default is the host's own, and is not compared. A host
// whose name cannot be read is refused too: a check that cannot be made is not
// one that passed.
func Verify(named string) error {
	if named == "" {
		return nil
	}
	local, err := Local()
	if err != nil {
		return fmt.Errorf("could not read this host's PVE node name, so the node name %s (CERTISTACK_NODE or --node) cannot be checked against it: %w", show(named), err)
	}
	return Compare(local, named)
}

// Compare is nil when named, the name given, is local, the name of this host,
// exactly. An empty name is not compared.
func Compare(local, named string) error {
	if named == "" || named == local {
		return nil
	}
	return &MismatchError{Local: local, Named: named}
}

// MismatchError is a node name that is not the name of the host.
type MismatchError struct {
	// Local is the PVE name of the host; Named the name the command was given.
	Local, Named string
}

// Error is the refusal of a node-side command: what is wrong, and the fix.
func (e *MismatchError) Error() string {
	return fmt.Sprintf("this host is PVE node %s, but the node name given (CERTISTACK_NODE or --node) is %s: set CERTISTACK_NODE=%s, or point CERTISTACK_SSH_HOST at node %s.%s",
		show(e.Local), show(e.Named), show(e.Local), show(e.Named), e.hints())
}

// Reached finishes the sentence "ssh works and reaches ...": the node it is and
// the node the environment names.
func (e *MismatchError) Reached() string {
	return fmt.Sprintf("PVE node %s, but CERTISTACK_NODE names node %s", show(e.Local), show(e.Named))
}

// Fix is the fix check prints for a mismatch, in terms of the environment file.
func (e *MismatchError) Fix(envPath string) string {
	return fmt.Sprintf("Set CERTISTACK_NODE=%s in %s, or point CERTISTACK_SSH_HOST at node %s.%s", show(e.Local), envPath, show(e.Named), e.hints())
}

// hints are the sentences that explain the likely cause: a name with a domain,
// or one that differs in case only.
func (e *MismatchError) hints() string {
	var hints string
	if strings.Contains(e.Named, ".") {
		if short := ShortHostName(e.Named); short != "" {
			hints += fmt.Sprintf(" A PVE node name has no domain: use the short node name %s, without the domain.", show(short))
		}
	}
	if strings.EqualFold(e.Local, e.Named) {
		hints += fmt.Sprintf(" PVE node names are case-sensitive: %s and %s are different names to the PVE API.", show(e.Local), show(e.Named))
	}
	return hints
}

// NameFromLinkTarget is the node name in the target of /etc/pve/local
// (nodes/<name>): its last element.
func NameFromLinkTarget(target string) (string, error) {
	name := path.Base(strings.TrimRight(target, "/"))
	if target == "" || name == "." || name == "/" || name == "nodes" || !nodeNameExpr.MatchString(name) {
		return "", fmt.Errorf("the link target %s does not name a PVE node (nodes/<name>)", strconv.Quote(target))
	}
	return name, nil
}

// ShortHostName is the host name up to its first dot.
func ShortHostName(host string) string {
	short, _, _ := strings.Cut(host, ".")
	return short
}

// shortHostName is this host's short name.
func shortHostName() (string, error) {
	host, err := hostname()
	if err != nil {
		return "", fmt.Errorf("read the host name: %w", err)
	}
	short := ShortHostName(host)
	if short == "" {
		return "", errors.New("the host name is empty")
	}
	return short, nil
}

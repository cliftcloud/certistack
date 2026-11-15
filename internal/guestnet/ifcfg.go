// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/cliftcloud/certistack/internal/ifname"
)

// ifcfgIgnoredSuffixes are the endings NetworkManager's ifcfg-rh plugin never
// loads a profile from, and the legacy network scripts (initscripts'
// is_ignored_file) never source: the editor, rpm and augeas leftovers that sit
// beside a live profile (utils_should_ignore_file of NetworkManager 1.18.8). A
// package upgrade that finds the profile edited leaves the old copy as
// ifcfg-eth0.rpmsave or .rpmorig, bound to the same MAC. The
// comparison is case-insensitive and needs a name longer than the suffix.
var ifcfgIgnoredSuffixes = []string{".bak", "~", ".orig", ".rej", ".rpmnew", ".rpmorig", ".rpmsave", ".augnew", ".augsave", ".augtmp"}

// ifcfgIgnored reports a file in /etc/sysconfig/network-scripts that
// NetworkManager does not load as a connection profile: one that does not
// start with "ifcfg-", one of the ignored endings, or an rpm temporary file
// (";" and exactly eight hexadecimal digits). A profile written, or chosen as
// the one to rewrite, under such a name would never be read, and the recovery
// address would not be applied.
func ifcfgIgnored(name string) bool {
	if !strings.HasPrefix(name, "ifcfg-") {
		return true
	}
	lower := strings.ToLower(name)
	for _, suffix := range ifcfgIgnoredSuffixes {
		if len(lower) > len(suffix) && strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	if i := strings.LastIndexByte(name, ';'); i >= 0 && len(name)-i-1 == 8 {
		hex := true
		for _, c := range name[i+1:] {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				hex = false
			}
		}
		return hex
	}
	return false
}

// ifcfgAssignments are the KEY=value assignments of an ifcfg file as the shell
// that sources it reads them: a later assignment replaces an earlier one, a
// value is bare (up to white space) or inside one pair of quotes, and a line
// that starts with "#" is a comment.
func ifcfgAssignments(contents string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" || strings.ContainsAny(key, " \t") {
			continue
		}
		value = strings.TrimSpace(value)
		if value != "" && (value[0] == '"' || value[0] == '\'') {
			if end := strings.IndexByte(value[1:], value[0]); end >= 0 {
				value = value[1 : 1+end]
			} else {
				value = value[1:]
			}
		} else if end := strings.IndexAny(value, " \t"); end >= 0 {
			value = value[:end]
		}
		values[key] = value
	}
	return values
}

// ifcfgMatch is a legacy profile bound to the recovered NIC.
type ifcfgMatch struct {
	file  string // the profile's path in the guest
	iface string // the interface name it configures
}

// ifcfgProfileForMAC finds the legacy profile currently associated with the
// restored NIC: a profile NetworkManager loads whose HWADDR is the source MAC.
// The interface it configures is the profile's own DEVICE, as NetworkManager
// reads it; only a profile without one is named after its file (ifcfg-eth0
// configures eth0). Profiles NetworkManager ignores are not candidates. More
// than one profile bound to the MAC is not a choice CertiStack can make from
// directory order, so it asks for the interface name instead.
func (a *Adapter) ifcfgProfileForMAC(ctx context.Context, overlays []string, mac string) (ifcfgMatch, bool, error) {
	exists, err := a.directoryExists(ctx, overlays, ifcfgDir)
	if err != nil {
		return ifcfgMatch{}, false, dependencyError("inspect legacy network profiles", err)
	}
	if !exists {
		return ifcfgMatch{}, false, nil
	}
	entries, err := a.run(ctx, guestfishReadArgs(overlays, "ls", ifcfgDir)...)
	if err != nil {
		return ifcfgMatch{}, false, dependencyError("list legacy network profiles", err)
	}
	var matches []ifcfgMatch
	for _, entry := range listingEntries(entries) {
		if !isProfileSeed(modeIfcfg, entry) {
			continue
		}
		file := path.Join(ifcfgDir, entry)
		contents, err := a.run(ctx, guestfishReadArgs(overlays, "cat", file)...)
		if err != nil {
			return ifcfgMatch{}, false, dependencyError("read legacy network profile", err)
		}
		if !ifcfgMatchesMAC(contents, mac) {
			continue
		}
		iface := ifcfgAssignments(contents)["DEVICE"]
		if iface == "" {
			iface = strings.TrimPrefix(entry, "ifcfg-")
		}
		if !ifname.Valid(iface) {
			continue
		}
		matches = append(matches, ifcfgMatch{file: file, iface: iface})
	}
	switch len(matches) {
	case 0:
		return ifcfgMatch{}, false, nil
	case 1:
		return matches[0], true, nil
	}
	files := make([]string, len(matches))
	for i, match := range matches {
		files[i] = match.file
	}
	return ifcfgMatch{}, false, fmt.Errorf("several legacy profiles are bound to the recovered NIC's MAC (%s), and CertiStack cannot tell which one NetworkManager activates; set network_recovery.interface_name to the NIC's name", strings.Join(files, ", "))
}

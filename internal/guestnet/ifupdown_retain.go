// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"fmt"
	"path"
	"strings"
)

// With attach_all_nics the sandbox VM has the source's other NICs on the
// isolated bridge too, and the plan's documentation says only net0 gets a
// recovery address while the others keep the guest's own configuration. The
// replacement /etc/network/interfaces therefore keeps every stanza that is not
// the recovered NIC's. It is written as one file with no "source"
// line, so the fragments the guest's main file includes cannot bring back the
// recovered NIC's own stanza with its gateway and DNS: what they define for
// other interfaces is copied into the file, and the fragments stay unread.

// ifupdownStanza is one stanza of an interfaces file: the line that starts it
// and the option lines that follow an iface or mapping line.
type ifupdownStanza struct {
	keyword string   // iface, mapping, auto, allow-*, no-auto-down, no-scripts, source, ...
	fields  []string // the tokens of the first line
	lines   []string // every non-comment line of the stanza, as written
	options [][]string
}

func isIfupdownStanzaStart(word string) bool {
	return word == "iface" || ifupdownStanzaKeyword(word)
}

// parseIfupdownStanzas splits an interfaces file into stanzas, keeping each
// line as it was written. Blank and comment lines are left out, and a line
// ending in a backslash is one line with the next (as in ifupdownLogicalLines).
// An option line before any iface or mapping line is an error: ifupdown
// rejects the file itself.
func parseIfupdownStanzas(contents string) ([]ifupdownStanza, error) {
	var stanzas []ifupdownStanza
	var written []string // the physical lines of the logical line being read
	var joined strings.Builder
	flush := func() error {
		defer func() {
			written = nil
			joined.Reset()
		}()
		fields := strings.Fields(joined.String())
		if len(fields) == 0 {
			return nil
		}
		text := strings.Join(written, "\n")
		if isIfupdownStanzaStart(fields[0]) {
			stanzas = append(stanzas, ifupdownStanza{keyword: fields[0], fields: fields, lines: []string{text}})
			return nil
		}
		if len(stanzas) == 0 || (stanzas[len(stanzas)-1].keyword != "iface" && stanzas[len(stanzas)-1].keyword != "mapping") {
			return fmt.Errorf("the option line %q is not in an iface or mapping stanza", strings.TrimSpace(fields[0]))
		}
		last := &stanzas[len(stanzas)-1]
		last.lines = append(last.lines, text)
		last.options = append(last.options, fields)
		return nil
	}
	for _, raw := range strings.Split(contents, "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		if joined.Len() == 0 {
			if trimmed := strings.TrimSpace(raw); trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
		}
		written = append(written, raw)
		if continued, found := strings.CutSuffix(raw, "\\"); found {
			joined.WriteString(continued)
			joined.WriteByte(' ')
			continue
		}
		joined.WriteString(raw)
		if err := flush(); err != nil {
			return nil, err
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return stanzas, nil
}

// structuralIfupdownOptions name the interfaces a bridge, bond, VLAN or Open
// vSwitch device is built on.
var structuralIfupdownOptions = map[string]bool{
	"bridge_ports": true, "bridge-ports": true,
	"bond-slaves": true, "bond_slaves": true, "bond-primary": true, "bond_primary": true,
	"vlan-raw-device": true, "vlan_raw_device": true,
	"ovs_ports": true, "ovs-ports": true, "ovs_bonds": true, "ovs-bonds": true,
	"ovs_bridge": true, "ovs-bridge": true,
}

// dependsOnInterface reports a kept stanza built on the recovered NIC: a VLAN
// named after it (eth0.100), or a bridge, bond or VLAN option that lists it,
// "all", or a pattern that matches it. Keeping such a stanza beside a flat
// recovery address on the NIC would describe a layout the guest never had.
func (s ifupdownStanza) dependsOnInterface(names []string) (string, bool) {
	if s.keyword == "iface" && len(s.fields) > 1 {
		for _, name := range names {
			if strings.HasPrefix(s.fields[1], name+".") {
				return name, true
			}
		}
	}
	for _, option := range s.options {
		if !structuralIfupdownOptions[option[0]] {
			continue
		}
		for _, value := range option[1:] {
			for _, name := range names {
				if value == name || value == "all" {
					return name, true
				}
				if hasGlobMeta(value) {
					if ok, err := path.Match(value, name); err == nil && ok {
						return name, true
					}
				}
			}
		}
	}
	return "", false
}

// retainedIfupdown is the text of every stanza of the guest's interfaces files
// (the main file and, in the order they are included, the files it includes)
// that does not belong to the recovered NIC or to the loopback the replacement
// already declares. It is empty when there is nothing to keep, and an error
// when the stanzas cannot be kept as they are: a mapping stanza, which selects
// by interface name at run time, a rename or template stanza (ifupdown2 and
// ifupdown-ng extensions CertiStack does not interpret), or a stanza built on
// the recovered NIC.
func (g *ifupdownGraph) retainedIfupdown(names []string) (string, error) {
	var kept []string
	for _, file := range g.files {
		stanzas, err := parseIfupdownStanzas(file.contents)
		if err != nil {
			return "", fmt.Errorf("guest ifupdown file %s cannot be kept beside the recovery address (%v); set attach_all_nics to false or use network_recovery.mode: preserve", file.path, err)
		}
		for _, stanza := range stanzas {
			switch stanza.keyword {
			case "source", "source-directory":
				// Followed already; the replacement is one file.
			case "mapping", "rename", "template":
				return "", fmt.Errorf("guest ifupdown file %s has a %s stanza, which CertiStack cannot keep beside the recovery address (it chooses interfaces by name when ifup runs); set attach_all_nics to false or use network_recovery.mode: preserve", file.path, stanza.keyword)
			case "iface":
				if len(stanza.fields) < 2 || stanza.fields[1] == "lo" || containsString(names, stanza.fields[1]) {
					continue
				}
				if name, depends := stanza.dependsOnInterface(names); depends {
					return "", fmt.Errorf("guest ifupdown file %s: the stanza for %s is built on %s, the NIC that gets the recovery address, so it cannot be kept beside it; set attach_all_nics to false or use network_recovery.mode: preserve", file.path, stanza.fields[1], name)
				}
				kept = append(kept, strings.Join(stanza.lines, "\n"))
			default:
				// auto, allow-* and the like list interfaces: the recovered NIC and
				// lo are dropped from the list, the others stay.
				var remaining []string
				for _, name := range stanza.fields[1:] {
					if name != "lo" && !containsString(names, name) {
						remaining = append(remaining, name)
					}
				}
				if len(remaining) > 0 {
					kept = append(kept, stanza.keyword+" "+strings.Join(remaining, " "))
				}
			}
		}
	}
	if len(kept) == 0 {
		return "", nil
	}
	return "\n# The guest's own stanzas for its other interfaces (attach_all_nics), as they were.\n" + strings.Join(kept, "\n") + "\n", nil
}

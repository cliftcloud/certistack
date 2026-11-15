// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// systemd-networkd applies the first .network file, in file-name order
// across its directories, whose [Match] section selects a link, and udev
// the first matching .link file; later matches are ignored. netplan writes
// each definition as /run/systemd/network/10-netplan-<id>.network. A
// recovery profile therefore has to sort before every file that might also
// match the recovered NIC. The vendor files under /usr/lib/systemd/network
// sort after all of these names (80-*, 99-*), and /run is empty offline.

const netplanLibDir = "/lib/netplan"

// recoveryIDs are the netplan definition IDs, and recoveryFileBases the
// systemd file names, a recovery profile can take, in order of preference:
// each sorts before the one before it. The usual ID comes first (the one that
// was verified). A capital sorts before every lowercase ID, and only a guest ID
// that starts with a digit or a symbol needs the last two, which are the
// unusual ones (checked against netplan 0.106 only).
var (
	recoveryIDs       = []string{"certistack-recovery", "Certistack-recovery", "0-certistack-recovery", "-certistack-recovery"}
	recoveryFileBases = []string{"00-certistack-recovery", "0-certistack-recovery", "-certistack-recovery"}
)

// netplanDefinition is one netplan device definition, merged across files
// as netplan merges a definition ID: a later file adds or overrides keys.
type netplanDefinition struct {
	section         string // ethernets, bonds, bridges, ...
	mac             string // match: macaddress, as the last file sets it
	renderer        string // the definition's own renderer
	sectionRenderer string // the renderer of the section that first defined it
}

// netplanConfig is the guest's netplan configuration, read in netplan's
// order: *.yaml from /lib/netplan and /etc/netplan by file name, an /etc
// file hiding a /lib file of the same name.
type netplanConfig struct {
	renderer    string // the last global renderer; it applies to every file
	definitions map[string]*netplanDefinition
}

func (d *detection) readNetplan(ctx context.Context) (*netplanConfig, error) {
	files := map[string]string{}
	for _, dir := range []string{netplanLibDir, netplanDir} {
		exists, err := d.directoryExists(ctx, dir)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		entries, err := d.list(ctx, dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			// The recovery profile replaces a file of its own name.
			if !strings.HasSuffix(entry, ".yaml") || !safeEntryName(entry) || (dir == netplanDir && entry == path.Base(netplanProfile)) {
				continue
			}
			files[entry] = path.Join(dir, entry)
		}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	config := &netplanConfig{definitions: map[string]*netplanDefinition{}}
	for _, name := range names {
		contents, err := d.a.run(ctx, guestfishReadArgs(d.overlays, "cat", files[name])...)
		if err != nil {
			return nil, dependencyError("read guest netplan configuration", err)
		}
		if err := config.add(contents); err != nil {
			return nil, fmt.Errorf("guest netplan file %s cannot be read (%v); netplan generates nothing when one file is unreadable, so a recovery definition would not apply; use network_recovery.mode: systemd-networkd or preserve", files[name], err)
		}
	}
	return config, nil
}

func (c *netplanConfig) add(contents string) error {
	var document struct {
		Network map[string]yaml.Node `yaml:"network"`
	}
	if err := yaml.Unmarshal([]byte(contents), &document); err != nil {
		return err
	}
	if node, ok := document.Network["renderer"]; ok {
		if err := node.Decode(&c.renderer); err != nil {
			return err
		}
	}
	for section, node := range document.Network {
		if section == "renderer" || section == "version" || node.Kind == yaml.ScalarNode {
			continue
		}
		var entries map[string]yaml.Node
		if err := node.Decode(&entries); err != nil {
			return err
		}
		var sectionRenderer string
		if renderer, ok := entries["renderer"]; ok {
			if err := renderer.Decode(&sectionRenderer); err != nil {
				return err
			}
		}
		for id, entry := range entries {
			if id == "renderer" {
				continue
			}
			var definition struct {
				Renderer string `yaml:"renderer"`
				Match    struct {
					MACAddress string `yaml:"macaddress"`
				} `yaml:"match"`
			}
			if err := entry.Decode(&definition); err != nil {
				return fmt.Errorf("%s.%s: %w", section, id, err)
			}
			merged := c.definitions[id]
			if merged == nil {
				merged = &netplanDefinition{section: section, sectionRenderer: sectionRenderer}
				c.definitions[id] = merged
			}
			if definition.Match.MACAddress != "" {
				merged.mac = definition.Match.MACAddress
			}
			if definition.Renderer != "" {
				merged.renderer = definition.Renderer
			}
		}
	}
	return nil
}

// effectiveRenderer is the backend netplan renders a definition for: its
// own renderer, else its section's, else the last global one, else networkd.
func (c *netplanConfig) effectiveRenderer(definition *netplanDefinition) string {
	for _, renderer := range []string{definition.renderer, definition.sectionRenderer, c.renderer} {
		if renderer != "" {
			return renderer
		}
	}
	return "networkd"
}

// mayConfigure lists the ethernet definitions that can match the recovered
// NIC: those bound to its MAC and those matched by name or driver, or named
// after an interface, which offline cannot be ruled out.
func (c *netplanConfig) mayConfigure(mac string) []string {
	var ids []string
	for id, definition := range c.definitions {
		if definition.section == "ethernets" && (definition.mac == "" || sameMAC(definition.mac, mac)) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// networkdMayConfigure reports a definition that can match the recovered
// NIC and that netplan renders for systemd-networkd.
func (c *netplanConfig) networkdMayConfigure(mac string) bool {
	for _, id := range c.mayConfigure(mac) {
		if strings.EqualFold(c.effectiveRenderer(c.definitions[id]), "networkd") {
			return true
		}
	}
	return false
}

// recoveryID chooses the recovery definition's ID so that its generated
// .network file sorts before that of every definition that can match the
// recovered NIC, and before the given /etc/systemd/network files that can
// match it. A later YAML file name does not do it: netplan merges
// definitions by ID and writes one file per ID.
func (c *netplanConfig) recoveryID(mac string, systemdFiles []string) (string, error) {
	ids := c.mayConfigure(mac)
	competing := append([]string(nil), systemdFiles...)
	for _, id := range ids {
		// netplan escapes an ID for its file name (RFC 3986); older releases
		// used it as written. Either may sort first.
		competing = append(competing, netplanNetworkFile(id), netplanNetworkFile(escapeNetplanID(id)))
	}
	for _, id := range recoveryIDs {
		if _, taken := c.definitions[id]; !taken && sortsBeforeAll(netplanNetworkFile(id), competing) {
			return id, nil
		}
	}
	names := append([]string(nil), systemdFiles...)
	for _, id := range ids {
		names = append(names, "netplan definition "+id)
	}
	return "", fmt.Errorf("guest configuration (%s) sorts before every recovery definition name, so systemd-networkd would apply it first and ignore a netplan recovery definition; use network_recovery.mode: systemd-networkd (its recovery file is named to sort before netplan's), or preserve", strings.Join(names, ", "))
}

func netplanNetworkFile(id string) string {
	return "10-netplan-" + id + ".network"
}

// escapeNetplanID escapes an ID as netplan does for its file names
// (g_uri_escape_string with UTF-8 allowed).
func escapeNetplanID(id string) string {
	var b strings.Builder
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c >= 0x80 || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func sortsBeforeAll(name string, others []string) bool {
	for _, other := range others {
		if other <= name {
			return false
		}
	}
	return true
}

func sameMAC(a, b string) bool {
	left, errLeft := net.ParseMAC(strings.TrimSpace(a))
	right, errRight := net.ParseMAC(strings.TrimSpace(b))
	if errLeft != nil || errRight != nil {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return bytes.Equal(left, right)
}

// systemdSearchDirs are the directories systemd reads files with a suffix
// from, the highest priority first. For a .link file it applies the first
// match across all of them in file-name order, whichever directory a file is
// in, and a file in an earlier directory hides one of the same name in a later.
// Recovery precedence uses the same directories for .network files. The
// NetworkManager ownership check explicitly uses /etc only.
func systemdSearchDirs(suffix string) []string {
	if suffix == ".link" || suffix == ".network" {
		return []string{systemdNetworkdDir, "/run/systemd/network", "/usr/local/lib/systemd/network", "/usr/lib/systemd/network", "/lib/systemd/network"}
	}
	return []string{systemdNetworkdDir}
}

// systemdListings are the entries of each of dirs that exists. /etc is read
// through the detection's own cache; the others in two guestfish runs, what
// they are and what they hold.
func (d *detection) systemdListings(ctx context.Context, dirs []string) (map[string][]string, error) {
	listings := map[string][]string{}
	var others []string
	for _, dir := range dirs {
		if dir != systemdNetworkdDir {
			others = append(others, dir)
			continue
		}
		exists, err := d.directoryExists(ctx, dir)
		if err != nil {
			return nil, err
		}
		if exists {
			if listings[dir], err = d.list(ctx, dir); err != nil {
				return nil, err
			}
		}
	}
	if len(others) == 0 {
		return listings, nil
	}
	kinds, err := d.a.guestFileKinds(ctx, d.overlays, others)
	if err != nil {
		return nil, err
	}
	var present []string
	var commands [][]string
	for i, dir := range others {
		switch kinds[i] {
		case "":
		case kindDirectory:
			present = append(present, dir)
			commands = append(commands, []string{"ls", dir})
		default:
			return nil, fmt.Errorf("the guest's systemd network directory %s is %s, and CertiStack does not read through it; use network_recovery.mode: preserve", dir, kinds[i])
		}
	}
	outputs, err := d.a.guestOutputs(ctx, d.overlays, commands)
	if err != nil {
		return nil, dependencyError("list the guest's systemd network files", err)
	}
	for i, dir := range present {
		listings[dir] = listingEntries(outputs[i])
	}
	return listings, nil
}

// systemdFilesBefore lists the files with the given suffix in the guest's
// systemd network directories that sort before limit (all of them when limit
// is empty) and may match the recovered NIC. A file with a drop-in directory
// may match whatever its [Match] says, and so may one that is not a plain
// file CertiStack can read; one hidden by a link to /dev/null, or by a file of
// the same name in a directory of higher priority, is not there.
func (d *detection) systemdFilesBefore(ctx context.Context, suffix, limit string) ([]string, error) {
	return d.systemdFilesBeforeIn(ctx, suffix, limit, systemdSearchDirs(suffix))
}

func (d *detection) systemdFilesBeforeIn(ctx context.Context, suffix, limit string, dirs []string) ([]string, error) {
	cacheKey := suffix + "\x00" + limit + "\x00" + d.iface + "\x00" + strings.Join(dirs, "\x00")
	if cached, known := d.matching[cacheKey]; known {
		return cached, nil
	}
	listings, err := d.systemdListings(ctx, dirs)
	if err != nil {
		return nil, err
	}
	owner := map[string]string{} // file name -> the directory it is read from
	hasDropIn := map[string]bool{}
	for _, dir := range dirs {
		for _, entry := range listings[dir] {
			if _, taken := owner[entry]; !taken {
				owner[entry] = dir
			}
			hasDropIn[strings.TrimSuffix(entry, ".d")] = hasDropIn[strings.TrimSuffix(entry, ".d")] || strings.HasSuffix(entry, ".d")
		}
	}
	var names []string
	for entry := range owner {
		if strings.HasSuffix(entry, suffix) && !strings.HasPrefix(entry, ".") && safeEntryName(entry) && (limit == "" || entry < limit) && !isRecoveryFile(entry, suffix) {
			names = append(names, entry)
		}
	}
	sort.Strings(names)
	paths := make([]string, len(names))
	for i, name := range names {
		paths[i] = path.Join(owner[name], name)
	}
	var kinds []string
	if len(paths) > 0 {
		if kinds, err = d.a.guestFileKinds(ctx, d.overlays, paths); err != nil {
			return nil, err
		}
	}
	// What each candidate is: masked by a link to /dev/null (not there), a plain
	// file to read, or something that is treated as able to match.
	var links, reads []int
	for i, kind := range kinds {
		switch {
		case hasDropIn[names[i]]:
		case kind == kindSymlink:
			links = append(links, i)
		case kind == kindRegular:
			reads = append(reads, i)
		}
	}
	masked := map[int]bool{}
	if len(links) > 0 {
		commands := make([][]string, len(links))
		for j, i := range links {
			commands[j] = []string{"readlink", paths[i]}
		}
		targets, err := d.a.guestOutputs(ctx, d.overlays, commands)
		if err != nil {
			return nil, dependencyError("read a guest systemd network link", err)
		}
		for j, i := range links {
			target := strings.TrimSpace(targets[j])
			if !path.IsAbs(target) {
				target = path.Join(path.Dir(paths[i]), target)
			}
			masked[i] = path.Clean(target) == "/dev/null"
		}
	}
	mayMatch := map[int]bool{}
	if len(reads) > 0 {
		commands := make([][]string, len(reads))
		for j, i := range reads {
			commands[j] = []string{"cat", paths[i]}
		}
		contents, err := d.a.guestOutputs(ctx, d.overlays, commands)
		if err != nil {
			return nil, dependencyError("read guest systemd network configuration", err)
		}
		for j, i := range reads {
			mayMatch[i] = systemdMayMatchForName(contents[j], d.mac, d.iface)
		}
	}
	var matching []string
	for i, name := range names {
		switch {
		case masked[i]:
		case kinds[i] == kindRegular && !hasDropIn[name] && !mayMatch[i]:
		default:
			matching = append(matching, name)
		}
	}
	if d.matching == nil {
		d.matching = map[string][]string{}
	}
	d.matching[cacheKey] = matching
	return matching, nil
}

func isRecoveryFile(name, suffix string) bool {
	for _, base := range recoveryFileBases {
		if name == base+suffix {
			return true
		}
	}
	return false
}

// firstMatchFile names a recovery file with the given suffix in
// /etc/systemd/network that systemd applies before every other file there
// which may match the recovered NIC.
func (d *detection) firstMatchFile(ctx context.Context, suffix string) (string, error) {
	competing, err := d.systemdFilesBefore(ctx, suffix, recoveryFileBases[0]+suffix)
	if err != nil {
		return "", err
	}
	for _, base := range recoveryFileBases {
		if sortsBeforeAll(base+suffix, competing) {
			return path.Join(systemdNetworkdDir, base+suffix), nil
		}
	}
	return "", fmt.Errorf("guest files %s in %s sort before every recovery file name and may match the recovered NIC; use network_recovery.mode: preserve", strings.Join(competing, ", "), systemdNetworkdDir)
}

// netplanRecovery renders the recovery definition of a netplan guest so that
// systemd-networkd applies it before every definition of the guest that can
// match the recovered NIC. It refuses, with the reason, a guest where that
// cannot be established: a competing definition rendered by another backend
// (NetworkManager applies its own connection whatever networkd reads), an
// unreadable netplan file, or names that sort before every recovery name.
func (d *detection) netplanRecovery(ctx context.Context, cfg Config, subnet *net.IPNet) (string, error) {
	config, err := d.netplanConfig(ctx)
	if err != nil {
		return "", err
	}
	var foreign []string
	for _, id := range config.mayConfigure(cfg.MAC) {
		if renderer := config.effectiveRenderer(config.definitions[id]); !strings.EqualFold(renderer, "networkd") {
			foreign = append(foreign, id+" ("+renderer+")")
		}
	}
	if len(foreign) > 0 {
		return "", fmt.Errorf("guest netplan definitions %s can match the recovered NIC but are not rendered by systemd-networkd, so a networkd recovery definition would not be the one applied; use network_recovery.mode: networkmanager for a NetworkManager guest, or preserve", strings.Join(foreign, ", "))
	}
	// Files of /etc/systemd/network are sorted together with netplan's
	// generated 10-netplan-<id>.network files.
	systemdFiles, err := d.systemdFilesBefore(ctx, ".network", "")
	if err != nil {
		return "", err
	}
	id, err := config.recoveryID(cfg.MAC, systemdFiles)
	if err != nil {
		return "", err
	}
	// A definition without its own renderer takes the guest's global one, so
	// a global NetworkManager renderer would hand the recovery definition to
	// NetworkManager. Naming networkd is only needed then; otherwise the profile
	// stays what was verified.
	explicit := config.renderer != "" && !strings.EqualFold(config.renderer, "networkd")
	return renderNetplan(id, explicit, cfg, subnet), nil
}

// systemdMayMatch reports whether a .network or .link file's [Match]
// section could select the recovered NIC. Only conditions that certainly
// exclude it count: a MAC address list without its MAC, a Kind (a physical
// NIC has none), or a Type other than ether. Anything else (a name, driver
// or path pattern, host or virtualization condition) may match.
func systemdMayMatch(contents, mac string) bool {
	return systemdMayMatchForName(contents, mac, "")
}

// systemdLogicalLines splits a systemd configuration file into the lines
// systemd itself parses: a line that ends in an unescaped backslash is joined
// with the next one (the backslash becomes a space), and a comment line
// (starting with # or ;) is skipped even inside such a continuation.
func systemdLogicalLines(contents string) []string {
	var lines []string
	continuation := ""
	continued := false
	for _, raw := range strings.Split(contents, "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		l := strings.TrimLeft(raw, " \t")
		if l != "" && (l[0] == '#' || l[0] == ';') {
			continue
		}
		if continued {
			l = continuation + l
		}
		escaped := false
		for i := 0; i < len(l); i++ {
			if escaped {
				escaped = false
			} else if l[i] == '\\' {
				escaped = true
			}
		}
		if escaped {
			continuation = l[:len(l)-1] + " "
			continued = true
			continue
		}
		continuation, continued = "", false
		lines = append(lines, l)
	}
	if continued {
		lines = append(lines, continuation)
	}
	return lines
}

func systemdMayMatchForName(contents, mac, iface string) bool {
	values := map[string][]string{}
	section := ""
	for _, line := range systemdLogicalLines(contents) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || section != "[Match]" {
			continue
		}
		key = strings.TrimSpace(key)
		if fields := strings.Fields(value); len(fields) > 0 {
			values[key] = append(values[key], fields...)
		} else {
			delete(values, key) // an empty assignment resets the list
		}
	}
	for _, key := range []string{"MACAddress", "PermanentMACAddress"} {
		if list, set := values[key]; set && !negated(list) && !containsMAC(list, mac) {
			return false
		}
	}
	if names, set := values["Name"]; set && iface != "" && !negated(names) {
		matches := false
		for _, pattern := range names {
			matched, err := path.Match(pattern, iface)
			if err != nil { // syntax we cannot evaluate remains a competitor
				matches = true
				break
			}
			matches = matches || matched
		}
		if !matches {
			return false
		}
	}
	if kinds, set := values["Kind"]; set && !negated(kinds) {
		return false
	}
	if types, set := values["Type"]; set && !negated(types) {
		for _, kind := range types {
			if kind == "ether" {
				return true
			}
		}
		return false
	}
	return true
}

func negated(list []string) bool {
	for _, value := range list {
		if strings.HasPrefix(value, "!") {
			return true
		}
	}
	return false
}

func containsMAC(list []string, mac string) bool {
	for _, value := range list {
		if sameMAC(value, mac) {
			return true
		}
	}
	return false
}

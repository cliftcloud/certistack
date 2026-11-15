// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// What NetworkManager reads, and what recovery needs from it.
//
// NetworkManager.conf(5) (1.18): the configuration is the snippets of
// /usr/lib/NetworkManager/conf.d (parsed first, even before NetworkManager.conf),
// then those of /run/NetworkManager/conf.d, then /etc/NetworkManager/NetworkManager.conf,
// then the snippets of /etc/NetworkManager/conf.d, and last
// /var/lib/NetworkManager/NetworkManager-intern.conf, later values overriding
// earlier ones. Only files ending in ".conf" are snippets, read in file-name
// order; a snippet of the same name in /etc shadows one in /run and /usr/lib,
// and one in /run shadows one in /usr/lib. A list-valued key can be extended
// ("plugins+=a") and reduced ("plugins-=a") instead of replaced. A snippet can
// be switched off with "[.config] enable=false".
//
// Two answers depend on it. [keyfile] path is where keyfile profiles are read
// and stored (the conventional /etc/NetworkManager/system-connections only
// when it is not set), so a profile written anywhere else is never read.
// [main] plugins says which settings plugins load; EL7's NetworkManager reads
// no keyfile profile unless keyfile is listed.
//
// Not modeled, and so a limit of this reading: the command-line overrides
// (--config, --config-dir, --system-config-dir, --intern-config) of whatever
// starts NetworkManager, distribution patches to the defaults, and a snippet
// whose "[.config] enable" depends on the NetworkManager version or the
// environment, which is refused when it sets one of these two keys.
const (
	nmUsrLibConfDir = "/usr/lib/NetworkManager/conf.d"
	nmRunConfDir    = "/run/NetworkManager/conf.d"
	nmEtcConfDir    = "/etc/NetworkManager/conf.d"
	nmInternConf    = "/var/lib/NetworkManager/NetworkManager-intern.conf"
	// maxNMConfigFiles bounds the files one guest's NetworkManager configuration
	// may read.
	maxNMConfigFiles = 64
)

// nmSettings is the part of a guest's effective NetworkManager configuration
// that recovery depends on.
type nmSettings struct {
	keyfileDir string // where keyfile profiles are read and written
	configured bool   // keyfileDir is a configured [keyfile] path, not the default
	exists     bool   // keyfileDir is a directory in the guest
	plugins    []string
	pluginsSet bool
}

// loadsKeyfile reports whether the effective plugin list names keyfile. An
// unset list is the distribution's default, which EL7's NetworkManager builds
// without keyfile.
func (s *nmSettings) loadsKeyfile() bool {
	for _, plugin := range s.plugins {
		if plugin == "keyfile" {
			return true
		}
	}
	return false
}

// nmEntry is one assignment of a configuration file.
type nmEntry struct {
	group, key, value string
	line              int
}

// parseNMConfig reads a NetworkManager configuration file as GLib's key file
// parser does, for the keys that matter here, and refuses what that parser
// would: a line that is no group, comment or assignment, a group never opened.
func parseNMConfig(contents string) ([]nmEntry, error) {
	if !utf8.ValidString(contents) {
		return nil, fmt.Errorf("it is not valid UTF-8")
	}
	var entries []nmEntry
	group := ""
	for index, raw := range strings.Split(contents, "\n") {
		number := index + 1
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if index == 0 {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.IndexFunc(line, func(r rune) bool { return unicode.IsControl(r) && r != '\t' }) >= 0 {
			return nil, fmt.Errorf("line %d holds a control character", number)
		}
		if line[0] == '[' {
			if !strings.HasSuffix(line, "]") || len(line) < 3 || strings.ContainsAny(line[1:len(line)-1], "[]") {
				return nil, fmt.Errorf("line %d, %q, is not a group header", number, line)
			}
			group = line[1 : len(line)-1]
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || key == "" {
			return nil, fmt.Errorf("line %d, %q, is not a group, a comment or a key=value pair", number, line)
		}
		if group == "" {
			return nil, fmt.Errorf("line %d, %q, comes before any [group]", number, line)
		}
		entries = append(entries, nmEntry{group: group, key: key, value: strings.TrimSpace(value), line: number})
	}
	return entries, nil
}

// nmEnable is what a file's "[.config] enable" says: it is loaded, skipped, or
// depends on something recovery cannot evaluate offline.
type nmEnable int

const (
	nmLoaded nmEnable = iota
	nmSkipped
	nmConditional
)

func nmEnabled(entries []nmEntry) nmEnable {
	state := nmLoaded
	for _, entry := range entries {
		if entry.group != ".config" || entry.key != "enable" {
			continue
		}
		switch strings.ToLower(entry.value) {
		case "true", "yes", "on", "1":
			state = nmLoaded
		case "false", "no", "off", "0":
			state = nmSkipped
		default:
			state = nmConditional
		}
	}
	return state
}

// nmAccumulator applies configuration files in NetworkManager's order.
type nmAccumulator struct {
	plugins    []string
	pluginsSet bool
	path       string
	pathSet    bool
}

func splitNMList(value string) []string {
	var list []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list
}

// touchesRecoverySettings reports an entry that sets [main] plugins or
// [keyfile] path, in any of the forms the file format has.
func (e nmEntry) touchesRecoverySettings() bool {
	key := strings.TrimRight(e.key, "+-")
	return (e.group == "main" && key == "plugins") || (e.group == "keyfile" && key == "path")
}

func (n *nmAccumulator) apply(file string, entry nmEntry) error {
	switch {
	case entry.group == "main" && entry.key == "plugins":
		n.plugins, n.pluginsSet = splitNMList(entry.value), true
	case entry.group == "main" && entry.key == "plugins+":
		for _, item := range splitNMList(entry.value) {
			if !containsString(n.plugins, item) {
				n.plugins = append(n.plugins, item)
			}
		}
		n.pluginsSet = true
	case entry.group == "main" && entry.key == "plugins-":
		remove := splitNMList(entry.value)
		kept := n.plugins[:0:0]
		for _, item := range n.plugins {
			if !containsString(remove, item) {
				kept = append(kept, item)
			}
		}
		n.plugins, n.pluginsSet = kept, true
	case entry.group == "keyfile" && entry.key == "path":
		if strings.ContainsAny(entry.value, "\\") {
			return fmt.Errorf("%s line %d: the keyfile path %q holds a backslash, which the key file format reads as an escape; CertiStack does not evaluate it", file, entry.line, entry.value)
		}
		if entry.value == "" {
			return fmt.Errorf("%s line %d: [keyfile] path is empty; CertiStack cannot tell where NetworkManager then reads its profiles", file, entry.line)
		}
		n.path, n.pathSet = entry.value, true
	case entry.touchesRecoverySettings():
		return fmt.Errorf("%s line %d: %s=%s modifies a value in a way CertiStack does not evaluate offline", file, entry.line, entry.key, entry.value)
	}
	return nil
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// nmConfigFile is one configuration file of the guest, in reading order.
type nmConfigFile struct {
	path string
	main bool // NetworkManager.conf and the internal file cannot be disabled
}

// safeKeyfileDir validates a configured [keyfile] path as one recovery can
// write into: absolute, free of ".." and of anything a guestfish argument or a
// path join could misread.
func safeKeyfileDir(value string) (string, error) {
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\x00\r\n") || !utf8.ValidString(value) {
		return "", fmt.Errorf("the keyfile directory %q is not an absolute path", value)
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." || part == "." {
			return "", fmt.Errorf("the keyfile directory %q contains %q", value, part)
		}
	}
	clean := path.Clean(value)
	if clean == "/" {
		return "", fmt.Errorf("the keyfile directory is the root directory")
	}
	return clean, nil
}

// backendDirectory is the directory a backend keeps its profiles in for this
// guest, and whether it is there. Every backend's is fixed except
// NetworkManager's keyfile directory, which the guest's configuration can move.
func (d *detection) backendDirectory(ctx context.Context, strategy string) (string, bool, error) {
	if strategy == modeNetworkManager {
		settings, err := d.networkManagerSettings(ctx)
		if err != nil {
			return "", false, err
		}
		return settings.keyfileDir, settings.exists, nil
	}
	dir, _ := strategyDirectory(strategy)
	exists, err := d.directoryExists(ctx, dir)
	return dir, exists, err
}

// networkManagerSettings reads the guest's NetworkManager configuration once
// and answers from it. It costs a few guestfish runs, in this order:
// one for what exists, one for the snippet directories' listings, one for what
// each snippet is, and one for the contents; a guest with no configuration
// files costs the single run the directory check always did.
func (d *detection) networkManagerSettings(ctx context.Context) (*nmSettings, error) {
	if d.nm != nil || d.nmErr != nil {
		return d.nm, d.nmErr
	}
	d.nm, d.nmErr = d.readNetworkManagerSettings(ctx)
	return d.nm, d.nmErr
}

func (d *detection) readNetworkManagerSettings(ctx context.Context) (*nmSettings, error) {
	probe := []string{networkManagerDir, nmUsrLibConfDir, nmRunConfDir, nmEtcConfDir, networkManagerConf, nmInternConf}
	kinds, err := d.a.guestFileKinds(ctx, d.overlays, probe)
	if err != nil {
		return nil, err
	}
	settings := &nmSettings{keyfileDir: networkManagerDir}
	// The conventional directory counts as there only when it is a directory; a
	// link there is what the check always refused.
	defaultDirExists := kinds[0] == kindDirectory

	// The snippet directories, lowest priority first, and the files each holds.
	var present []string
	for i, dir := range []string{nmUsrLibConfDir, nmRunConfDir, nmEtcConfDir} {
		switch kinds[1+i] {
		case "":
		case kindDirectory:
			present = append(present, dir)
		default:
			return nil, fmt.Errorf("the guest's NetworkManager configuration directory %s is %s, which CertiStack does not read offline (a link would be resolved against the wrong root); use network_recovery.mode: preserve", dir, kinds[1+i])
		}
	}
	listings := map[string][]string{}
	if len(present) > 0 {
		commands := make([][]string, len(present))
		for i, dir := range present {
			commands[i] = []string{"ls", dir}
		}
		outputs, err := d.a.guestOutputs(ctx, d.overlays, commands)
		if err != nil {
			return nil, dependencyError("list the NetworkManager configuration", err)
		}
		for i, dir := range present {
			for _, name := range listingEntries(outputs[i]) {
				if strings.HasSuffix(name, ".conf") && safeEntryName(name) {
					listings[dir] = append(listings[dir], name)
				}
			}
			sort.Strings(listings[dir])
		}
	}

	// Which file each snippet name is read from: /etc over /run over /usr/lib.
	chosen := map[string]string{}
	for _, dir := range []string{nmUsrLibConfDir, nmRunConfDir, nmEtcConfDir} {
		for _, name := range listings[dir] {
			chosen[name] = path.Join(dir, name)
		}
	}
	var files []nmConfigFile
	appendSnippets := func(dir string) {
		for _, name := range listings[dir] {
			if chosen[name] == path.Join(dir, name) {
				files = append(files, nmConfigFile{path: chosen[name]})
			}
		}
	}
	appendSnippets(nmUsrLibConfDir)
	appendSnippets(nmRunConfDir)
	mainKind, internKind := kinds[4], kinds[5]
	if mainKind != "" {
		files = append(files, nmConfigFile{path: networkManagerConf, main: true})
	}
	appendSnippets(nmEtcConfDir)
	if internKind != "" {
		files = append(files, nmConfigFile{path: nmInternConf, main: true})
	}
	if len(files) > maxNMConfigFiles {
		return nil, fmt.Errorf("the guest's NetworkManager configuration has %d files, more than the %d CertiStack reads; use network_recovery.mode: preserve", len(files), maxNMConfigFiles)
	}

	contents, err := d.readNMConfigFiles(ctx, files, kinds[4], kinds[5])
	if err != nil {
		return nil, err
	}
	var accumulated nmAccumulator
	for i, file := range files {
		entries, err := parseNMConfig(contents[i])
		if err != nil {
			return nil, fmt.Errorf("the guest's NetworkManager configuration file %s cannot be read (%v), so CertiStack cannot tell which plugins or keyfile directory NetworkManager uses; fix the file, or use network_recovery.mode: preserve", file.path, err)
		}
		if !file.main {
			switch nmEnabled(entries) {
			case nmSkipped:
				continue
			case nmConditional:
				for _, entry := range entries {
					if entry.touchesRecoverySettings() {
						return nil, fmt.Errorf("the guest's NetworkManager configuration file %s sets %s=%s but is enabled only under a condition ([.config] enable) that CertiStack cannot evaluate offline; use network_recovery.mode: preserve", file.path, entry.key, entry.value)
					}
				}
				continue
			}
		}
		for _, entry := range entries {
			if err := accumulated.apply(file.path, entry); err != nil {
				return nil, fmt.Errorf("the guest's NetworkManager configuration is not evaluated offline: %w; use network_recovery.mode: preserve", err)
			}
		}
	}
	settings.plugins, settings.pluginsSet = accumulated.plugins, accumulated.pluginsSet
	settings.exists = defaultDirExists
	if accumulated.pathSet {
		dir, err := safeKeyfileDir(accumulated.path)
		if err != nil {
			return nil, fmt.Errorf("the guest's NetworkManager is configured with [keyfile] path=%s, but %v; use network_recovery.mode: preserve", accumulated.path, err)
		}
		if dir != networkManagerDir {
			exists, err := d.directoryExists(ctx, dir)
			if err != nil {
				return nil, err
			}
			settings.keyfileDir, settings.configured, settings.exists = dir, true, exists
		}
	}
	return settings, nil
}

// readNMConfigFiles returns the contents of each file. A regular file is read;
// a link to /dev/null (how an administrator masks a snippet) is an empty one;
// anything else is refused, since the appliance resolves an absolute link
// against its own root rather than the guest's.
func (d *detection) readNMConfigFiles(ctx context.Context, files []nmConfigFile, mainKind, internKind string) ([]string, error) {
	contents := make([]string, len(files))
	if len(files) == 0 {
		return contents, nil
	}
	paths := make([]string, len(files))
	kinds := make([]string, len(files))
	var unknown []string
	for i, file := range files {
		paths[i] = file.path
		switch file.path {
		case networkManagerConf:
			kinds[i] = mainKind
		case nmInternConf:
			kinds[i] = internKind
		default:
			unknown = append(unknown, file.path)
		}
	}
	if len(unknown) > 0 {
		found, err := d.a.guestFileKinds(ctx, d.overlays, unknown)
		if err != nil {
			return nil, err
		}
		next := 0
		for i := range files {
			if files[i].path != networkManagerConf && files[i].path != nmInternConf {
				kinds[i] = found[next]
				next++
			}
		}
	}
	var links, reads []int
	for i, kind := range kinds {
		switch kind {
		case kindRegular:
			reads = append(reads, i)
		case kindSymlink:
			links = append(links, i)
		case "":
			return nil, fmt.Errorf("the guest's NetworkManager configuration file %s disappeared while it was read", paths[i])
		default:
			return nil, fmt.Errorf("the guest's NetworkManager configuration file %s is %s, which CertiStack does not read; use network_recovery.mode: preserve", paths[i], kind)
		}
	}
	if len(links) > 0 {
		commands := make([][]string, len(links))
		for j, i := range links {
			commands[j] = []string{"readlink", paths[i]}
		}
		targets, err := d.a.guestOutputs(ctx, d.overlays, commands)
		if err != nil {
			return nil, dependencyError("read a NetworkManager configuration link", err)
		}
		for j, i := range links {
			target := strings.TrimSpace(targets[j])
			if !path.IsAbs(target) {
				target = path.Join(path.Dir(paths[i]), target)
			}
			if path.Clean(target) != "/dev/null" {
				return nil, fmt.Errorf("the guest's NetworkManager configuration file %s is a symbolic link to %s; CertiStack reads regular files and links to /dev/null (a masked snippet) only; use network_recovery.mode: preserve", paths[i], strings.TrimSpace(targets[j]))
			}
		}
	}
	if len(reads) > 0 {
		commands := make([][]string, len(reads))
		for j, i := range reads {
			commands[j] = []string{"cat", paths[i]}
		}
		outputs, err := d.a.guestOutputs(ctx, d.overlays, commands)
		if err != nil {
			return nil, dependencyError("read the NetworkManager configuration", err)
		}
		for j, i := range reads {
			contents[i] = outputs[j]
		}
	}
	return contents, nil
}

// guestOutputs runs several read-only guestfish commands in one appliance
// start and returns each command's own output. The outputs are told apart by
// a line this call makes up and echoes between them, so no file's contents can
// stand for one, and a count that is not what was asked refuses the answer.
func (a *Adapter) guestOutputs(ctx context.Context, overlays []string, commands [][]string) ([]string, error) {
	if len(commands) == 0 {
		return nil, nil
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("make a separator for guestfish output: %w", err)
	}
	marker := "certistack-end-" + hex.EncodeToString(nonce)
	script := make([][]string, 0, 2*len(commands)-1)
	for i, command := range commands {
		if i > 0 {
			script = append(script, []string{"echo", marker})
		}
		script = append(script, command)
	}
	output, err := a.run(ctx, guestfishQueryArgs(overlays, script)...)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(output, marker+"\n")
	if len(parts) != len(commands) {
		return nil, fmt.Errorf("guestfish returned %d answers for %d commands; refusing to use output it cannot attribute", len(parts), len(commands))
	}
	return parts, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// The adapter writes recovery files into the guest at fixed paths. guestfish's
// upload opens its destination with O_WRONLY|O_CREAT|O_TRUNC and no
// O_NOFOLLOW, "cp -a" keeps what it copies (a symbolic link stays a link, an
// owner stays the owner), and chmod follows links. So a symbolic link where
// one of these files belongs (or as the profile a copy was seeded from) sends
// the recovery content, and the mode, to an unrelated file of the guest, and a
// seed owned by another user hands that owner to the profile, which
// NetworkManager then ignores. The image is offline and this adapter its only
// writer, so the entry at each path is looked at before the write and the
// result after it.

// Permission and file-type bits of a stat mode.
const (
	modeFileType    = 0o170000
	modeRegularFile = 0o100000
	modePermissions = 0o7777
)

// kindTests are the guestfish tests that, without following a final symbolic
// link, say what an entry is. Exactly one is true for an entry that exists;
// none is for a path with nothing there. The tests never fail on a missing
// path.
var kindTests = []struct{ command, kind string }{
	{"is-symlink", kindSymlink},
	{"is-dir", kindDirectory},
	{"is-file", kindRegular},
	{"is-chardev", "a character device"},
	{"is-blockdev", "a block device"},
	{"is-fifo", "a named pipe"},
	{"is-socket", "a socket"},
}

const (
	kindRegular   = "a regular file"
	kindSymlink   = "a symbolic link"
	kindDirectory = "a directory"
)

// guestFileKinds says what is at each path: "" for nothing, otherwise the kind.
// It costs one guestfish run for all of them.
func (a *Adapter) guestFileKinds(ctx context.Context, overlays, paths []string) ([]string, error) {
	commands := make([][]string, 0, len(paths)*len(kindTests))
	for _, p := range paths {
		for _, test := range kindTests {
			commands = append(commands, []string{test.command, p})
		}
	}
	output, err := a.run(ctx, guestfishQueryArgs(overlays, commands)...)
	if err != nil {
		return nil, dependencyError("inspect where to write the", err)
	}
	answers := strings.Fields(output)
	if len(answers) != len(commands) {
		return nil, fmt.Errorf("guestfish answered %d of the %d questions about the guest files to write; refusing to write without knowing what is there", len(answers), len(commands))
	}
	kinds := make([]string, len(paths))
	for i, p := range paths {
		for j, test := range kindTests {
			switch strings.ToLower(answers[i*len(kindTests)+j]) {
			case "false":
			case "true":
				if kinds[i] != "" {
					return nil, fmt.Errorf("guestfish says %s is both %s and %s; refusing to write it", p, kinds[i], test.kind)
				}
				kinds[i] = test.kind
			default:
				return nil, fmt.Errorf("guestfish answered %q to %s %s; refusing to write without knowing what is there", answers[i*len(kindTests)+j], test.command, p)
			}
		}
	}
	return kinds, nil
}

// guestStat is the part of a stat that decides whether a write is safe.
type guestStat struct {
	mode, uid, gid, nlink int64
}

func (s guestStat) regular() bool { return s.mode&modeFileType == modeRegularFile }

// guestStats lstats each path in one guestfish run. Every path must exist.
func (a *Adapter) guestStats(ctx context.Context, overlays, paths []string) ([]guestStat, error) {
	commands := make([][]string, 0, len(paths))
	for _, p := range paths {
		commands = append(commands, []string{"lstat", p})
	}
	output, err := a.run(ctx, guestfishQueryArgs(overlays, commands)...)
	if err != nil {
		return nil, dependencyError("verify the written", err)
	}
	return parseGuestStats(output, len(paths))
}

// parseGuestStats reads the output of n guestfish lstat commands: for each, one
// "name: value" line per field of struct stat, decimal, the first being "dev".
// Anything else is an error: a write is not confirmed from output that cannot
// be read.
func parseGuestStats(output string, n int) ([]guestStat, error) {
	type block struct {
		guestStat
		seen map[string]bool
	}
	var blocks []*block
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, text, found := strings.Cut(line, ":")
		name, text = strings.TrimSpace(name), strings.TrimSpace(text)
		if !found || name == "" {
			return nil, fmt.Errorf("guestfish lstat printed %q, which is not a stat field", line)
		}
		value, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("guestfish lstat printed %q, which is not a number", line)
		}
		if name == "dev" {
			blocks = append(blocks, &block{seen: map[string]bool{}})
		}
		if len(blocks) == 0 {
			return nil, fmt.Errorf("guestfish lstat output starts with %q, not with dev", line)
		}
		current := blocks[len(blocks)-1]
		current.seen[name] = true
		switch name {
		case "mode":
			current.mode = value
		case "uid":
			current.uid = value
		case "gid":
			current.gid = value
		case "nlink":
			current.nlink = value
		}
	}
	if len(blocks) != n {
		return nil, fmt.Errorf("guestfish lstat described %d files, want %d", len(blocks), n)
	}
	stats := make([]guestStat, n)
	for i, b := range blocks {
		for _, field := range []string{"mode", "uid", "gid", "nlink"} {
			if !b.seen[field] {
				return nil, fmt.Errorf("guestfish lstat output lacks %s for file %d", field, i+1)
			}
		}
		stats[i] = b.guestStat
	}
	return stats, nil
}

// writeTargets are the guest paths a batch of commands writes or copies from.
type writeTargets struct {
	sources      []string          // "cp-a" sources; they must be regular files
	destinations []string          // "cp-a" and "upload" destinations
	uploads      []string          // "upload" destinations, whose final state is verified
	links        []writeLink       // "ln-s" links to create
	modes        map[string]string // chmod argument by path, decimal
}

// writeLink is a symbolic link a batch creates: guestfish's ln-s fails when
// anything is at the path, even the very link that is wanted.
type writeLink struct{ target, path string }

func collectWriteTargets(commands [][]string) writeTargets {
	targets := writeTargets{modes: map[string]string{}}
	add := func(list *[]string, p string) {
		if !slices.Contains(*list, p) {
			*list = append(*list, p)
		}
	}
	for _, command := range commands {
		switch {
		case command[0] == "cp-a" && len(command) == 3:
			add(&targets.sources, command[1])
			add(&targets.destinations, command[2])
		case command[0] == "upload" && len(command) == 3:
			add(&targets.destinations, command[2])
			add(&targets.uploads, command[2])
		case command[0] == "ln-s" && len(command) == 3:
			targets.links = append(targets.links, writeLink{target: command[1], path: command[2]})
		case command[0] == "chmod" && len(command) == 3:
			targets.modes[command[2]] = command[1]
		}
	}
	return targets
}

// checkWriteTargets refuses a batch whose paths are not what the batch
// assumes, before anything is written: a "cp -a" source or any destination
// that is not a regular file (a symbolic link would redirect the write, a
// directory, device or pipe would fail or hang it), a destination that other
// names share (the write would change them too), a missing "cp -a" source.
//
// A link the batch creates is looked at the same way: nothing there
// means create it; the very link that is wanted means there is nothing to do,
// so it is returned as satisfied and the batch leaves it out; anything else, a
// link to somewhere else included, is refused rather than replaced.
func (a *Adapter) checkWriteTargets(ctx context.Context, overlays []string, targets writeTargets) (satisfied map[string]bool, err error) {
	paths := append([]string(nil), targets.sources...)
	for _, destination := range targets.destinations {
		if !slices.Contains(paths, destination) {
			paths = append(paths, destination)
		}
	}
	linkAt := map[string]writeLink{}
	for _, link := range targets.links {
		if !slices.Contains(paths, link.path) {
			paths = append(paths, link.path)
		}
		linkAt[link.path] = link
	}
	if len(paths) == 0 {
		return nil, nil
	}
	kinds, err := a.guestFileKinds(ctx, overlays, paths)
	if err != nil {
		return nil, err
	}
	var existing, linked []string
	for i, p := range paths {
		isSource, isDestination := slices.Contains(targets.sources, p), slices.Contains(targets.destinations, p)
		if link, isLink := linkAt[p]; isLink {
			switch kinds[i] {
			case "":
			case kindSymlink:
				linked = append(linked, link.path)
			default:
				return nil, fmt.Errorf("guest network recovery would link %s -> %s, but %s is %s in the guest; it is not replaced. Use network_recovery.mode: preserve, or fix the image", link.path, link.target, link.path, kinds[i])
			}
			continue
		}
		switch {
		case kinds[i] == "":
			if isSource {
				return nil, fmt.Errorf("guest network recovery would copy %s, which is not there", p)
			}
		case kinds[i] != kindRegular:
			return nil, fmt.Errorf("guest network recovery would write through %s, which is %s in the guest; a link or special file there would send the write to another file or hang it. Use network_recovery.mode: preserve, or fix the image", p, kinds[i])
		case isDestination:
			existing = append(existing, p)
		}
	}
	if len(existing) > 0 {
		stats, err := a.guestStats(ctx, overlays, existing)
		if err != nil {
			return nil, err
		}
		for i, stat := range stats {
			if !stat.regular() {
				return nil, fmt.Errorf("guest network recovery would write %s, which is not a regular file in the guest; use network_recovery.mode: preserve, or fix the image", existing[i])
			}
			if stat.nlink > 1 {
				return nil, fmt.Errorf("guest network recovery would write %s, which has %d hard links in the guest; the write would change the other names too. Use network_recovery.mode: preserve, or fix the image", existing[i], stat.nlink)
			}
		}
	}
	if len(linked) > 0 {
		pointsTo, err := a.guestLinkTargets(ctx, overlays, linked)
		if err != nil {
			return nil, err
		}
		satisfied = map[string]bool{}
		for i, p := range linked {
			if pointsTo[i] != linkAt[p].target {
				return nil, fmt.Errorf("guest network recovery would link %s -> %s, but the guest already has that link pointing to %q; it is not replaced. Use network_recovery.mode: preserve, or fix the image", p, linkAt[p].target, pointsTo[i])
			}
			satisfied[p] = true
		}
	}
	return satisfied, nil
}

// guestLinkTargets reads where each symbolic link points, in one guestfish run.
func (a *Adapter) guestLinkTargets(ctx context.Context, overlays, links []string) ([]string, error) {
	commands := make([][]string, len(links))
	for i, link := range links {
		commands[i] = []string{"readlink", link}
	}
	outputs, err := a.guestOutputs(ctx, overlays, commands)
	if err != nil {
		return nil, dependencyError("read where a guest link points", err)
	}
	targets := make([]string, len(links))
	for i, output := range outputs {
		targets[i] = strings.TrimSuffix(output, "\n")
	}
	return targets, nil
}

// verifyWritten reads back what an upload left: a regular file, owned by
// root, with the mode the batch set. NetworkManager ignores a keyfile that
// another user can read or write, and the profile it ignores is one the
// sandbox VM would never configure, so a run that cannot show the file is
// right stops here.
func (a *Adapter) verifyWritten(ctx context.Context, overlays []string, targets writeTargets) error {
	if len(targets.links) > 0 {
		paths := make([]string, len(targets.links))
		for i, link := range targets.links {
			paths[i] = link.path
		}
		pointsTo, err := a.guestLinkTargets(ctx, overlays, paths)
		if err != nil {
			return err
		}
		for i, link := range targets.links {
			if pointsTo[i] != link.target {
				return fmt.Errorf("guest network recovery linked %s -> %s, but it reads back as %q; the run stops here", link.path, link.target, pointsTo[i])
			}
		}
	}
	if len(targets.uploads) == 0 {
		return nil
	}
	stats, err := a.guestStats(ctx, overlays, targets.uploads)
	if err != nil {
		return err
	}
	for i, p := range targets.uploads {
		stat := stats[i]
		want, hasMode := int64(-1), false
		if text, found := targets.modes[p]; found {
			if parsed, err := strconv.ParseInt(text, 10, 64); err == nil {
				want, hasMode = parsed&modePermissions, true
			}
		}
		if !stat.regular() || stat.uid != 0 || stat.gid != 0 || (hasMode && stat.mode&modePermissions != want) {
			wantText := "any mode"
			if hasMode {
				wantText = fmt.Sprintf("mode %04o", want)
			}
			return fmt.Errorf("guest network recovery wrote %s, but it is not a regular file owned by root:root with %s (found type %06o, owner %d:%d, mode %04o); the guest could ignore it, so the run stops here", p, wantText, stat.mode&modeFileType, stat.uid, stat.gid, stat.mode&modePermissions)
		}
	}
	return nil
}

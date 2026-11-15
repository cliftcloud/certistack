// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// An ifupdown guest's configuration is /etc/network/interfaces and what it
// includes (interfaces(5)): "source" names files, with shell wildcards, and
// "source-directory" names directories whose files are included. The default
// directory /etc/network/interfaces.d is convention, active only when the
// main file sources it; reading it unconditionally credited a stale fragment
// with an interface the guest never configures, and ignoring "source" missed
// the profile that was in fact included.
//
// Relative paths are resolved from the directory of the file that names them.
// The walk reads only what the include graph reaches, once per file, within
// bounds that make a hostile or broken image a refusal instead of a long read.
const (
	// maxIfupdownFiles bounds the files one guest's graph may read.
	maxIfupdownFiles = 64
	// maxIfupdownDepth bounds how deep includes may nest.
	maxIfupdownDepth = 8
	// maxIfupdownBytes bounds the text read across the whole graph.
	maxIfupdownBytes = 1 << 20
	// maxIfupdownQueries bounds the directory listings and directory checks a
	// wildcard may cost; each is a guestfish run.
	maxIfupdownQueries = 64
)

// sourceDirectoryName is what source-directory includes, as run-parts selects:
// names of ASCII letters, digits, underscores and hyphens. A file with a dot
// (interfaces.d/eth0.bak) is left out; "source dir/*" would include it.
var sourceDirectoryName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ifupdownLogicalLines are the tokens of each directive of an interfaces
// file: blank and comment lines dropped (a comment is a line that starts with
// "#"; ifupdown has no end-of-line comments), and a line ending in a backslash
// continued on the next.
func ifupdownLogicalLines(contents string) [][]string {
	var lines [][]string
	var pending strings.Builder
	flush := func() {
		if fields := strings.Fields(pending.String()); len(fields) > 0 {
			lines = append(lines, fields)
		}
		pending.Reset()
	}
	for _, raw := range strings.Split(contents, "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		if pending.Len() == 0 {
			if trimmed := strings.TrimSpace(raw); trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
		}
		if continued, found := strings.CutSuffix(raw, "\\"); found {
			pending.WriteString(continued)
			pending.WriteByte(' ')
			continue
		}
		pending.WriteString(raw)
		flush()
	}
	flush()
	return lines
}

// ifupdownInclude is one source or source-directory directive.
type ifupdownInclude struct {
	directive string
	operands  []string
}

func ifupdownIncludes(contents string) []ifupdownInclude {
	var includes []ifupdownInclude
	for _, fields := range ifupdownLogicalLines(contents) {
		if (fields[0] == "source" || fields[0] == "source-directory") && len(fields) > 1 {
			includes = append(includes, ifupdownInclude{directive: fields[0], operands: fields[1:]})
		}
	}
	return includes
}

// ifupdownGraph reads an interfaces file and the files it includes.
type ifupdownGraph struct {
	a          *Adapter
	overlays   []string
	visited    map[string]bool
	bytes      int
	queries    int
	dirs       map[string]bool
	lists      map[string][]string
	interfaces []ifupdownInterface
	// files are the files read, with their text, in the order their stanzas
	// count: a file's own, then those it includes.
	files []ifupdownFile
}

type ifupdownFile struct{ path, contents string }

func newIfupdownGraph(a *Adapter, overlays []string) *ifupdownGraph {
	return &ifupdownGraph{a: a, overlays: overlays, visited: map[string]bool{}, dirs: map[string]bool{}, lists: map[string][]string{}}
}

// read reads file and, after its own stanzas, every file it includes in the
// order it names them. A file already read is not read again, so a cycle ends.
// The main file must exist; an included file that does not (a literal path
// with nothing there) or is a directory contributes nothing.
func (g *ifupdownGraph) read(ctx context.Context, file string, depth int, required bool) error {
	file = path.Clean(file)
	if g.visited[file] {
		return nil
	}
	if depth > maxIfupdownDepth {
		return fmt.Errorf("guest ifupdown configuration nests includes more than %d levels deep (at %s); set network_recovery.interface_name or use network_recovery.mode: preserve", maxIfupdownDepth, file)
	}
	if len(g.visited) >= maxIfupdownFiles {
		return fmt.Errorf("guest ifupdown configuration includes more than %d files; set network_recovery.interface_name or use network_recovery.mode: preserve", maxIfupdownFiles)
	}
	g.visited[file] = true
	contents, err := g.a.run(ctx, guestfishReadArgs(g.overlays, "cat", file)...)
	if err != nil {
		if !required && namesFileError(err, file, "no such file or directory", "is a directory") {
			return nil
		}
		return dependencyError("read ifupdown configuration", err)
	}
	if g.bytes += len(contents); g.bytes > maxIfupdownBytes {
		return fmt.Errorf("guest ifupdown configuration is larger than %d KiB across the files it includes; set network_recovery.interface_name or use network_recovery.mode: preserve", maxIfupdownBytes>>10)
	}
	g.interfaces = mergeIfupdownInterfaces(g.interfaces, ifupdownInterfaces(contents))
	g.files = append(g.files, ifupdownFile{path: file, contents: contents})
	for _, include := range ifupdownIncludes(contents) {
		included, err := g.resolve(ctx, file, include)
		if err != nil {
			return err
		}
		for _, next := range included {
			if err := g.read(ctx, next, depth+1, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// namesFileError reports an error from guestfish about this very file with
// one of the given causes; an error about anything else (a missing overlay)
// is never taken for it.
func namesFileError(err error, file string, causes ...string) bool {
	message := strings.ToLower(err.Error())
	if !strings.Contains(message, strings.ToLower(file)) {
		return false
	}
	for _, cause := range causes {
		if strings.Contains(message, cause) {
			return true
		}
	}
	return false
}

// resolve lists the files one directive includes.
func (g *ifupdownGraph) resolve(ctx context.Context, from string, include ifupdownInclude) ([]string, error) {
	var files []string
	for _, operand := range include.operands {
		if reason := unsupportedIfupdownOperand(operand); reason != "" {
			return nil, fmt.Errorf("guest ifupdown file %s has \"%s %s\", which uses %s that cannot be evaluated offline; set network_recovery.interface_name or use network_recovery.mode: preserve", from, include.directive, operand, reason)
		}
		target := operand
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(from), target)
		}
		matches, err := g.expand(ctx, path.Clean(target))
		if err != nil {
			return nil, err
		}
		if include.directive != "source-directory" {
			files = append(files, matches...)
			continue
		}
		for _, dir := range matches {
			names, err := g.list(ctx, dir)
			if err != nil {
				return nil, err
			}
			for _, name := range names {
				if sourceDirectoryName.MatchString(name) {
					files = append(files, path.Join(dir, name))
				}
			}
		}
	}
	return files, nil
}

// unsupportedIfupdownOperand names the shell feature of an operand that only a
// shell could evaluate. ifupdown expands an operand with wordexp(3): globs are
// matched here against the guest's files, but variables, command substitution,
// quoting and ~ need a running system.
func unsupportedIfupdownOperand(operand string) string {
	switch {
	case strings.HasPrefix(operand, "~"):
		return "tilde expansion"
	case strings.ContainsAny(operand, "$`"):
		return "variable or command substitution"
	case strings.ContainsAny(operand, "\\\"'"):
		return "quoting"
	case strings.ContainsAny(operand, "|&;<>()"):
		return "shell syntax"
	}
	return ""
}

func hasGlobMeta(s string) bool { return strings.ContainsAny(s, "*?[") }

// globMatch matches one path component as glob(3) does: a leading dot of the
// name is matched only by a dot in the pattern, and [!x] negates a class.
func globMatch(pattern, name string) bool {
	if strings.HasPrefix(name, ".") && !strings.HasPrefix(pattern, ".") {
		return false
	}
	ok, err := path.Match(strings.ReplaceAll(pattern, "[!", "[^"), name)
	return err == nil && ok
}

// expand lists the paths a pattern names in the guest. A pattern with no
// wildcard names itself, present or not; a wildcard is matched against the
// directory's entries, and in a directory position only against directories.
func (g *ifupdownGraph) expand(ctx context.Context, pattern string) ([]string, error) {
	if !hasGlobMeta(pattern) {
		return []string{pattern}, nil
	}
	components := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	current := []string{"/"}
	for i, component := range components {
		var next []string
		for _, dir := range current {
			if !hasGlobMeta(component) {
				next = append(next, path.Join(dir, component))
				continue
			}
			names, err := g.list(ctx, dir)
			if err != nil {
				return nil, err
			}
			for _, name := range names {
				if !globMatch(component, name) {
					continue
				}
				candidate := path.Join(dir, name)
				if i < len(components)-1 {
					isDir, err := g.isDir(ctx, candidate)
					if err != nil {
						return nil, err
					}
					if !isDir {
						continue
					}
				}
				next = append(next, candidate)
			}
		}
		if len(next) > maxIfupdownFiles {
			return nil, fmt.Errorf("the ifupdown include %s matches more than %d paths; set network_recovery.interface_name or use network_recovery.mode: preserve", pattern, maxIfupdownFiles)
		}
		current = next
	}
	sort.Strings(current)
	return current, nil
}

func (g *ifupdownGraph) query() error {
	if g.queries++; g.queries > maxIfupdownQueries {
		return fmt.Errorf("guest ifupdown configuration needs more than %d directory reads to resolve its includes; set network_recovery.interface_name or use network_recovery.mode: preserve", maxIfupdownQueries)
	}
	return nil
}

func (g *ifupdownGraph) isDir(ctx context.Context, dir string) (bool, error) {
	if known, ok := g.dirs[dir]; ok {
		return known, nil
	}
	if err := g.query(); err != nil {
		return false, err
	}
	exists, err := g.a.directoryExists(ctx, g.overlays, dir)
	if err != nil {
		return false, dependencyError("inspect ifupdown configuration", err)
	}
	g.dirs[dir] = exists
	return exists, nil
}

// list is the usable entry names of a directory, sorted; none for a directory
// that is not there.
func (g *ifupdownGraph) list(ctx context.Context, dir string) ([]string, error) {
	if names, ok := g.lists[dir]; ok {
		return names, nil
	}
	exists, err := g.isDir(ctx, dir)
	if err != nil || !exists {
		return nil, err
	}
	if err := g.query(); err != nil {
		return nil, err
	}
	output, err := g.a.run(ctx, guestfishReadArgs(g.overlays, "ls", dir)...)
	if err != nil {
		return nil, dependencyError("list ifupdown configuration", err)
	}
	var names []string
	for _, entry := range listingEntries(output) {
		if safeEntryName(entry) {
			names = append(names, entry)
		}
	}
	sort.Strings(names)
	g.lists[dir] = names
	return names, nil
}

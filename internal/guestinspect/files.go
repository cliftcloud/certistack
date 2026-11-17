// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestinspect

import (
	"path"
	"sort"
	"strings"
)

// fileSet is what Detect has read of a guest: the files' contents, the files
// that could not be read, the regular files it found by name, and the
// listings of the configuration trees. Parsers read only through it, so a
// parser run on what has been read so far also says what it still wants:
// each file it asked for that exists and was not read is in wanted.
type fileSet struct {
	content map[string]string
	failed  map[string]string
	present map[string]bool
	// trees are listed directories and their entries, as paths relative to
	// them (find's output).
	trees  map[string][]string
	wanted map[string]bool
	notes  []string
}

func newFileSet() *fileSet {
	return &fileSet{content: map[string]string{}, failed: map[string]string{}, present: map[string]bool{}, trees: map[string][]string{}, wanted: map[string]bool{}}
}

// read is a file's contents, when it was read. A file that exists and was
// not read yet is wanted; one that could not be read is noted.
func (fs *fileSet) read(p string) (string, bool) {
	if contents, ok := fs.content[p]; ok {
		return contents, true
	}
	if reason, failed := fs.failed[p]; failed {
		fs.note(p + " could not be read (" + reason + ")")
		return "", false
	}
	if fs.exists(p) {
		fs.wanted[p] = true
	}
	return "", false
}

// note records what the findings should say was not read or followed, once.
func (fs *fileSet) note(text string) {
	for _, known := range fs.notes {
		if known == text {
			return
		}
	}
	fs.notes = append(fs.notes, text)
}

// tree is the listed tree that holds p, or "".
func (fs *fileSet) tree(p string) string {
	best := ""
	for dir := range fs.trees {
		if (p == dir || strings.HasPrefix(p, dir+"/")) && len(dir) > len(best) {
			best = dir
		}
	}
	return best
}

// exists reports whether p is known to exist: found by name, read, or in a
// listing.
func (fs *fileSet) exists(p string) bool {
	if fs.present[p] {
		return true
	}
	if _, ok := fs.content[p]; ok {
		return true
	}
	dir := fs.tree(p)
	if dir == "" || dir == p {
		return false
	}
	rel := strings.TrimPrefix(p, dir+"/")
	for _, entry := range fs.trees[dir] {
		if entry == rel {
			return true
		}
	}
	return false
}

// isDir reports whether p is a listed directory: a tree, or an entry that has
// entries beneath it. A listed directory that is empty cannot be told from a
// file.
func (fs *fileSet) isDir(p string) bool {
	if _, ok := fs.trees[p]; ok {
		return true
	}
	dir := fs.tree(p)
	if dir == "" {
		return false
	}
	prefix := strings.TrimPrefix(p, dir+"/") + "/"
	for _, entry := range fs.trees[dir] {
		if strings.HasPrefix(entry, prefix) {
			return true
		}
	}
	return false
}

// glob is the files a shell pattern names, sorted, as glob(3) finds them: a
// wildcard does not match a leading dot. known is false when the pattern is
// under no listed tree, so nothing can be said of what it names.
func (fs *fileSet) glob(pattern string) (matches []string, known bool) {
	if !strings.ContainsAny(pattern, "*?[") {
		if fs.isDir(pattern) {
			return nil, fs.tree(pattern) != ""
		}
		if fs.exists(pattern) {
			return []string{pattern}, true
		}
		return nil, fs.tree(pattern) != "" || fs.present[pattern]
	}
	dir := fs.tree(staticPrefix(pattern))
	if dir == "" {
		return nil, false
	}
	for _, entry := range fs.trees[dir] {
		candidate := dir + "/" + entry
		if fs.isDir(candidate) {
			continue
		}
		if globMatch(pattern, candidate) {
			matches = append(matches, candidate)
		}
	}
	sort.Strings(matches)
	return matches, true
}

// filesIn is the files directly in dir whose names end in suffix (any name,
// when suffix is ""), sorted, leaving out names that start with a dot.
// known is false when dir is under no listed tree.
func (fs *fileSet) filesIn(dir, suffix string) (files []string, known bool) {
	tree := fs.tree(dir)
	if tree == "" {
		return nil, false
	}
	prefix := ""
	if dir != tree {
		prefix = strings.TrimPrefix(dir, tree+"/") + "/"
	}
	for _, entry := range fs.trees[tree] {
		name, ok := strings.CutPrefix(entry, prefix)
		if !ok || name == "" || strings.Contains(name, "/") || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, suffix) {
			continue
		}
		if candidate := path.Join(dir, name); !fs.isDir(candidate) {
			files = append(files, candidate)
		}
	}
	sort.Strings(files)
	return files, true
}

// filesUnder is every file beneath dir, at any depth, sorted (Apache's
// Include of a directory).
func (fs *fileSet) filesUnder(dir string) []string {
	tree := fs.tree(dir)
	if tree == "" {
		return nil
	}
	prefix := ""
	if dir != tree {
		prefix = strings.TrimPrefix(dir, tree+"/") + "/"
	}
	var files []string
	for _, entry := range fs.trees[tree] {
		if rest, ok := strings.CutPrefix(entry, prefix); ok && rest != "" && !fs.isDir(tree+"/"+entry) {
			files = append(files, tree+"/"+entry)
		}
	}
	sort.Strings(files)
	return files
}

// staticPrefix is the directory part of a pattern before its first
// wildcard.
func staticPrefix(pattern string) string {
	i := strings.IndexAny(pattern, "*?[")
	if i < 0 {
		return pattern
	}
	return path.Dir(pattern[:i] + "x")
}

// globMatch matches name against pattern component by component, as glob(3)
// does: a wildcard matches no "/" and no leading ".".
func globMatch(pattern, name string) bool {
	patterns, names := strings.Split(pattern, "/"), strings.Split(name, "/")
	if len(patterns) != len(names) {
		return false
	}
	for i := range patterns {
		if strings.HasPrefix(names[i], ".") && !strings.HasPrefix(patterns[i], ".") {
			return false
		}
		if ok, err := path.Match(patterns[i], names[i]); err != nil || !ok {
			return false
		}
	}
	return true
}

// resolve is a configuration path as a server reads it: absolute as it is,
// else relative to base.
func resolve(base, p string) string {
	if path.IsAbs(p) {
		return path.Clean(p)
	}
	return path.Join(base, p)
}

// unquote takes the quotes off a configuration value written in them.
func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// fields splits a line into words, keeping a quoted word whole (without its
// quotes). A backslash keeps the next character in a word.
func fields(line string) []string {
	var words []string
	var word strings.Builder
	inWord := false
	quote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0:
			if c == '\\' && i+1 < len(line) {
				i++
				c = line[i]
			}
			word.WriteByte(c)
		case c == '"' || c == '\'':
			quote, inWord = c, true
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		default:
			if c == '\\' && i+1 < len(line) {
				i++
				c = line[i]
			}
			word.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, word.String())
	}
	return words
}

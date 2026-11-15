// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// docCommand is a certistack command line found in the documentation.
type docCommand struct {
	where string
	// words are the arguments after the command word, quotes removed.
	words []string
	// complete is set for a command in a fenced shell block that the page
	// presents as typeable as written: it has no "..." and no optional [parts],
	// so it must carry every flag the command requires.
	complete bool
	// wrapper is set for certistack-controller, which adds --env-file itself.
	wrapper bool
}

// shellFences are the languages of a block that holds commands to type.
// An untagged block counts too: the pages use it for commands and for output,
// and only a line whose command word is certistack is read.
var shellFences = map[string]bool{"": true, "bash": true, "sh": true, "shell": true, "zsh": true, "console": true}

// commandWordPattern is how a certistack command is spelled: the bare name, a
// path to it, the release file name, or the appliance wrapper.
var commandWordPattern = regexp.MustCompile(`^(?:\S*/)?(certistack(?:-linux-amd64|-controller)?)$`)

// textCommandLine is a command printed in a block of output after a prefix
// that says it is one (the "Next:" lines of init and run, numbered steps).
// A bare "certistack ..." line in a block of output may be output (the first
// line of `certistack version`), so only the synopsis blocks of the CLI
// reference, where every such line is a usage line, are read without a prefix.
var (
	textCommandLine     = regexp.MustCompile(`^\s*(?:Next:\s+|Now run:\s+|\d+\.\s+)((?:sudo\s+)?certistack(?:-controller)?\s.*)$`)
	textSynopsisCommand = regexp.MustCompile(`^\s*((?:sudo\s+)?certistack(?:-controller)?\s.*)$`)
)

// shellWords splits a line the way a reader types it: whitespace separates,
// quotes group and are removed, <placeholders> and [optional parts] with
// spaces in them stay together, and # starts a comment. Control operators
// come back as words of their own so that a pipeline can be cut apart.
func shellWords(line string) []string {
	var words []string
	var current strings.Builder
	started := false
	flush := func() {
		if started {
			words = append(words, current.String())
		}
		current.Reset()
		started = false
	}
	var quote rune
	angle, square := 0, 0 // inside <placeholder> and [optional] parts
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, started = r, true
		case r == '\\' && i+1 < len(runes):
			i++
			current.WriteRune(runes[i])
			started = true
		case r == '<' && !started && i+1 < len(runes) && runes[i+1] != ' ' && runes[i+1] != '<':
			angle++
			current.WriteRune(r)
			started = true
		case r == '<' && angle == 0 && started:
			// A placeholder inside a word (--host=<name>).
			angle++
			current.WriteRune(r)
		case r == '>' && angle > 0:
			angle--
			current.WriteRune(r)
		case r == '[' && angle == 0:
			// An optional part of a synopsis: its words are read as they are.
			square++
		case r == ']' && angle == 0 && square > 0:
			square--
		case r == '|' && square > 0 && angle == 0:
			// An alternative inside brackets, not a pipe.
			flush()
		case (r == ' ' || r == '\t') && angle > 0:
			current.WriteRune(r)
		case r == ' ' || r == '\t':
			flush()
		case r == '#' && !started && angle == 0:
			flush()
			return words
		case (r == '|' || r == ';' || r == '&' || r == '>') && angle == 0:
			flush()
			op := string(r)
			for i+1 < len(runes) && (runes[i+1] == r || (r == '>' && runes[i+1] == '&')) {
				i++
				op += string(runes[i])
			}
			words = append(words, op)
		default:
			current.WriteRune(r)
			started = true
		}
	}
	flush()
	return words
}

var assignmentWord = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// certistackInvocations finds the certistack commands in one shell line: a
// word that names the program, at the start of a pipeline stage, possibly after
// sudo (and its options), env, a prompt or variable assignments; and the
// controller service of a Compose file, whose entry point is certistack.
func certistackInvocations(words []string) (invocations [][]string, wrappers []bool) {
	var stage []string
	flushStage := func() {
		defer func() { stage = nil }()
		i := 0
		for i < len(stage) {
			w := stage[i]
			switch {
			case w == "$" || w == "exec" || w == "time" || w == "nohup" || w == "setsid" || w == "then" || w == "do" || w == "env" || assignmentWord.MatchString(w):
				i++
			case w == "sudo":
				i++
				for i < len(stage) && strings.HasPrefix(stage[i], "-") {
					if stage[i] == "-u" || stage[i] == "-g" || stage[i] == "-h" {
						i++
					}
					i++
				}
			default:
				goto found
			}
		}
		return
	found:
		if m := commandWordPattern.FindStringSubmatch(stage[i]); m != nil {
			invocations = append(invocations, stage[i+1:])
			wrappers = append(wrappers, m[1] == "certistack-controller")
			return
		}
		// docker compose -f FILE run --rm controller <command and flags>
		if stage[i] == "docker" || stage[i] == "podman" {
			sawCompose, sawRun := false, false
			for k := i + 1; k < len(stage); k++ {
				switch {
				case stage[k] == "compose":
					sawCompose = true
				case stage[k] == "run" && sawCompose:
					sawRun = true
				case stage[k] == "controller" && sawRun:
					invocations = append(invocations, stage[k+1:])
					wrappers = append(wrappers, false)
					return
				}
			}
		}
	}
	for _, w := range words {
		if isControlOperator(w) {
			flushStage()
			continue
		}
		stage = append(stage, w)
	}
	flushStage()
	return invocations, wrappers
}

func isControlOperator(w string) bool {
	switch w {
	case "|", "||", "&&", ";", "&", ">", ">>", "2>", "2>&1", ">&", "&>", "<<":
		return true
	}
	return strings.HasPrefix(w, ">") || strings.HasPrefix(w, "2>")
}

// documentedCommands lists every certistack command the documentation shows:
// the commands of fenced shell blocks, the command lines printed in output
// blocks, and inline code that starts with certistack.
func documentedCommands(t *testing.T) []docCommand {
	t.Helper()
	var found []docCommand
	add := func(line markdownLine, text string, fencedShell bool) {
		words := shellWords(text)
		invocations, wrappers := certistackInvocations(words)
		for k, args := range invocations {
			// A command with an elided or optional part is not typeable as written.
			complete := fencedShell && !strings.ContainsAny(text, "[…") && !strings.Contains(text, "...")
			found = append(found, docCommand{where: line.where(), words: args, complete: complete, wrapper: wrappers[k]})
		}
	}
	for _, file := range documentationFiles(t) {
		lines := markdownLines(t, file)
		for i := 0; i < len(lines); i++ {
			line := lines[i]
			switch {
			case line.fenced && shellFences[line.lang]:
				// Join backslash continuations into one command.
				text := line.text
				first := line
				for strings.HasSuffix(strings.TrimRight(text, " \t"), "\\") && i+1 < len(lines) && lines[i+1].fenced {
					text = strings.TrimSuffix(strings.TrimRight(text, " \t"), "\\") + " " + strings.TrimSpace(lines[i+1].text)
					i++
				}
				trimmed := strings.TrimSpace(text)
				switch {
				case line.lang == "console":
					prompt, rest, ok := strings.Cut(trimmed, " ")
					if !ok || (prompt != "$" && prompt != "#") {
						continue
					}
					add(first, rest, true)
				case strings.HasPrefix(trimmed, "#"):
					continue
				default:
					add(first, strings.TrimPrefix(trimmed, "$ "), true)
				}
			case line.fenced:
				m := textCommandLine.FindStringSubmatch(line.text)
				if m == nil && filepath.Base(file) == "cli-reference.md" {
					m = textSynopsisCommand.FindStringSubmatch(line.text)
				}
				if m != nil {
					text := m[1]
					if cut := strings.Index(text, "  "); cut >= 0 {
						text = text[:cut]
					}
					add(line, text, false)
				}
			default:
				for _, m := range inlineCode.FindAllStringSubmatch(line.text, -1) {
					code := strings.TrimSpace(m[1])
					if strings.HasPrefix(code, "certistack ") || strings.HasPrefix(code, "sudo certistack ") || strings.HasPrefix(code, "certistack-controller ") || strings.HasPrefix(code, "sudo certistack-controller ") {
						add(line, code, false)
					}
				}
			}
		}
	}
	return found
}

// commandIndex lets a documented command be checked against the real tree.
type commandIndex struct{ root *cobra.Command }

func newCommandIndex() commandIndex {
	root := rootCmd()
	// cobra adds these when the program runs.
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.InitDefaultHelpFlag()
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	return commandIndex{root}
}

func findSubcommand(c *cobra.Command, name string) *cobra.Command {
	for _, sub := range c.Commands() {
		if sub.Name() == name {
			return sub
		}
		for _, alias := range sub.Aliases {
			if alias == name {
				return sub
			}
		}
	}
	return nil
}

// isPlaceholder is a word the page leaves for the reader to fill in.
func isPlaceholder(w string) bool {
	return strings.HasPrefix(w, "<") || strings.HasPrefix(w, "[") || strings.HasPrefix(w, "$") ||
		strings.HasPrefix(w, "{") || strings.Contains(w, "...") || w == "…" || strings.HasPrefix(w, "FILE") ||
		strings.ToUpper(w) == w && strings.ToLower(w) != w
}

// check reports what is wrong with one documented command, or nothing.
func (x commandIndex) check(d docCommand) []string {
	var problems []string
	cur := x.root
	var positionals []string
	words := d.words
	for i := 0; i < len(words); i++ {
		w := words[i]
		w = strings.Trim(w, "[],")
		if w == "" {
			continue
		}
		switch {
		case strings.HasPrefix(w, "--") && len(w) > 2:
			name, _, hasValue := strings.Cut(strings.TrimPrefix(w, "--"), "=")
			flag := cur.Flags().Lookup(name)
			if flag == nil {
				flag = cur.InheritedFlags().Lookup(name)
			}
			if flag == nil {
				problems = append(problems, fmt.Sprintf("%q is not a flag of `%s`", "--"+name, cur.CommandPath()))
				continue
			}
			flag.Changed = true
			if !hasValue && flag.NoOptDefVal == "" && i+1 < len(words) && !strings.HasPrefix(words[i+1], "-") {
				i++
			}
		case strings.HasPrefix(w, "-") && len(w) >= 2 && !isPlaceholder(w):
			short := string(w[1])
			flag := cur.Flags().ShorthandLookup(short)
			if flag == nil {
				flag = cur.InheritedFlags().ShorthandLookup(short)
			}
			if flag == nil {
				problems = append(problems, fmt.Sprintf("%q is not a flag of `%s`", "-"+short, cur.CommandPath()))
				continue
			}
			flag.Changed = true
			if len(w) == 2 && flag.NoOptDefVal == "" && i+1 < len(words) && !strings.HasPrefix(words[i+1], "-") {
				i++
			}
		case len(cur.Commands()) > 0 && len(positionals) == 0:
			sub := findSubcommand(cur, w)
			if sub == nil {
				if isPlaceholder(w) {
					return problems
				}
				problems = append(problems, fmt.Sprintf("`%s` has no command %q (it has %s)", cur.CommandPath(), w, subcommandNames(cur)))
				return problems
			}
			cur = sub
		default:
			positionals = append(positionals, w)
		}
	}
	if cur == x.root {
		// Only flags, or nothing: `certistack` alone and `certistack --help` are fine.
		return problems
	}
	if len(problems) > 0 || !d.complete {
		return problems
	}
	if len(cur.Commands()) > 0 && !cur.Runnable() {
		problems = append(problems, fmt.Sprintf("`%s` needs one of its commands (%s)", cur.CommandPath(), subcommandNames(cur)))
		return problems
	}
	if d.wrapper {
		if flag := cur.Flags().Lookup("env-file"); flag != nil {
			flag.Changed = true
		}
	}
	if err := cur.ValidateRequiredFlags(); err != nil {
		problems = append(problems, fmt.Sprintf("`%s`: %v, and this command leaves it out", cur.CommandPath(), err))
	}
	if err := cur.ValidateFlagGroups(); err != nil {
		problems = append(problems, fmt.Sprintf("`%s`: %v", cur.CommandPath(), err))
	}
	if cur.Args != nil && !hasPlaceholderGap(d) {
		if err := cur.Args(cur, positionals); err != nil {
			problems = append(problems, fmt.Sprintf("`%s` with arguments %v: %v", cur.CommandPath(), positionals, err))
		}
	}
	return problems
}

// hasPlaceholderGap is true for a command whose arguments the page elides.
func hasPlaceholderGap(d docCommand) bool {
	for _, w := range d.words {
		if w == "..." || w == "…" {
			return true
		}
	}
	return false
}

func subcommandNames(c *cobra.Command) string {
	var names []string
	for _, sub := range c.Commands() {
		if !sub.Hidden {
			names = append(names, sub.Name())
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// TestDocumentedCommandsExistWithTheirFlags reads every certistack command in
// the README, docs/, the examples and deployment guides (fenced blocks, output
// blocks and inline code) and checks it against the command tree the binary is
// built from: the subcommand exists, every flag exists on it (the global flags
// included), and a command presented as complete carries the flags the command
// requires and a number of arguments it accepts.
func TestDocumentedCommandsExistWithTheirFlags(t *testing.T) {
	commands := documentedCommands(t)
	if len(commands) < 100 {
		t.Fatalf("found only %d documented commands; the pattern this test reads has changed", len(commands))
	}
	for _, d := range commands {
		// A fresh tree for each command: checking marks the flags it sees as set.
		for _, problem := range newCommandIndex().check(d) {
			t.Errorf("%s: certistack %s: %s", d.where, strings.Join(d.words, " "), problem)
		}
	}
}

// Every command a person can type has its section in the CLI reference (a
// "## name" heading for a top-level command), and every subcommand is named in
// its parent's section, so a command added later cannot ship undocumented.
func TestEveryVisibleCommandIsInTheCLIReference(t *testing.T) {
	reference := markdownText(t, docRoot+"/docs/cli-reference.md")
	sections := map[string]string{}
	for _, part := range strings.Split("\n"+reference, "\n## ")[1:] {
		heading, body, _ := strings.Cut(part, "\n")
		// "## report show" is the section of the report command.
		name, _, _ := strings.Cut(strings.Trim(heading, "` "), " ")
		sections[name] += body
	}
	for _, top := range rootCmd().Commands() {
		if top.Hidden || top.Name() == "help" || top.Name() == "completion" {
			continue
		}
		body, ok := sections[top.Name()]
		if !ok {
			t.Errorf("docs/cli-reference.md has no \"## %s\" section for `certistack %s`", top.Name(), top.Name())
			continue
		}
		for _, sub := range top.Commands() {
			if sub.Hidden {
				continue
			}
			if !regexp.MustCompile(`(^|[^a-z-])` + regexp.QuoteMeta(sub.Name()) + `([^a-z-]|$)`).MatchString(body) {
				t.Errorf("the \"## %s\" section of docs/cli-reference.md never names the subcommand `%s`", top.Name(), sub.Name())
			}
		}
	}
}

// flagInCode finds the --flags a span of inline code names, with whether the
// name ends in a wildcard (--ssh-*).
var flagInCode = regexp.MustCompile(`(?:^|[^\w-])(--[a-z][a-z0-9-]*)(\*)?`)

// flagExists reports whether some command has a flag with this name
// (or, for a wildcard, with this prefix), hidden commands included.
func flagExists(root *cobra.Command, name string, prefix bool) bool {
	if name == "help" {
		return true
	}
	if !prefix && root.LocalFlags().Lookup(name) != nil {
		return true
	}
	if prefix && strings.Contains(root.LocalFlags().FlagUsages(), "--"+name) {
		return true
	}
	for _, sub := range root.Commands() {
		if flagExists(sub, name, prefix) {
			return true
		}
	}
	return false
}

// otherProgramsFlags are flags the prose names that belong to a program other
// than certistack, each with the program and the page that names it.
var otherProgramsFlags = map[string]string{
	"machine-id":    "cloud-init clean (deploy/appliance/README.md)",
	"pull":          "podman run and docker compose run (deploy/*/README.md)",
	"ns":            "proxmox-backup-client (docs/configuration.md, docs/troubleshooting.md)",
	"config":        "NetworkManager (docs/guest-network-recovery.md)",
	"config-dir":    "NetworkManager (docs/guest-network-recovery.md)",
	"intern-config": "NetworkManager (docs/guest-network-recovery.md)",
	"exclude":       "vzdump (docs/plan-reference.md)",
	"nodes":         "pvesm add, which limits a storage to some nodes (docs/quickstart.md, docs/manual-setup.md)",
}

// Every --flag the prose names in inline code exists on some command, so a
// renamed or removed flag cannot linger in a table or a sentence. Spans that
// start with another program (pvesm, qm, systemctl ...) are about that
// program's flags and are not read.
func TestFlagsNamedInProseExist(t *testing.T) {
	root := newCommandIndex().root
	checked := 0
	for _, file := range documentationFiles(t) {
		for _, line := range markdownLines(t, file) {
			if line.fenced {
				continue
			}
			for _, m := range inlineCode.FindAllStringSubmatch(line.text, -1) {
				code := strings.TrimSpace(m[1])
				first, _, _ := strings.Cut(strings.TrimPrefix(code, "sudo "), " ")
				if !strings.HasPrefix(first, "--") && !strings.HasPrefix(first, "certistack") {
					continue
				}
				for _, f := range flagInCode.FindAllStringSubmatch(code, -1) {
					name, wildcard := strings.TrimPrefix(f[1], "--"), f[2] != ""
					if strings.HasSuffix(name, "-") {
						name, wildcard = strings.TrimSuffix(name, "-"), true
					}
					checked++
					if _, other := otherProgramsFlags[name]; !other && !flagExists(root, name, wildcard) {
						t.Errorf("%s: `%s` names --%s, which no command has", line.where(), code, name)
					}
				}
			}
		}
	}
	if checked < 100 {
		t.Fatalf("read only %d flags in the prose; the pattern this test reads has changed", checked)
	}
}

var (
	flagUsageLine = regexp.MustCompile(`(?m)^\s+(?:-\w, )?--([a-z][a-z0-9-]*)`)
	// The first cell of a flags table row; a row can name several flags
	// (\x60 is the backquote).
	flagTableRow   = regexp.MustCompile(`(?m)^\| ((?:\x60-{1,2}[a-z][a-z0-9-]*\x60(?:, )?)+) \|`)
	flagInCell     = regexp.MustCompile(`--([a-z][a-z0-9-]*)`)
	flagInSynopsis = regexp.MustCompile(`(?:^|\s|\[)--([a-z][a-z0-9-]*)`)
)

// visibleFlags are the names of the flags the command declares itself and
// shows in its help (the global ones and the hidden ones are not here).
func visibleFlags(c *cobra.Command) map[string]bool {
	names := map[string]bool{}
	for _, m := range flagUsageLine.FindAllStringSubmatch(c.LocalNonPersistentFlags().FlagUsages(), -1) {
		if m[1] != "help" {
			names[m[1]] = true
		}
	}
	return names
}

// documentedFlags are the flags a section of the CLI reference names as its
// own: the first cell of each flags table row, and the usage line at the top of
// the section (a command with one flag shows it there and has no table).
func documentedFlags(section string) map[string]bool {
	names := map[string]bool{}
	for _, row := range flagTableRow.FindAllStringSubmatch(section, -1) {
		for _, m := range flagInCell.FindAllStringSubmatch(row[1], -1) {
			names[m[1]] = true
		}
	}
	if _, rest, ok := strings.Cut(section, "```text\n"); ok {
		usage, _, _ := strings.Cut(rest, "```")
		for _, m := range flagInSynopsis.FindAllStringSubmatch(usage, -1) {
			names[m[1]] = true
		}
	}
	return names
}

// The CLI reference lists a command's flags in a table under its heading.
// Each table is exactly the command's flags: one the table names and the
// command lacks was removed or misspelled; one the command has and the table
// lacks is undocumented. A row that stands for the SSH flags ("SSH flags")
// stands for the six every node-reaching command shares.
func TestCLIReferenceListsExactlyTheFlagsOfEachCommand(t *testing.T) {
	reference := markdownText(t, docRoot+"/docs/cli-reference.md")
	sshFlags := map[string]bool{}
	for name := range documentedFlags(sectionOf(t, reference, "SSH flags")) {
		sshFlags[name] = true
	}
	if len(sshFlags) != 6 {
		t.Fatalf("the SSH flags table lists %d flags (%v), want the 6 every node-reaching command shares", len(sshFlags), sshFlags)
	}
	compared := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if sub.Hidden || sub.Name() == "help" || sub.Name() == "completion" {
				continue
			}
			if len(sub.Commands()) > 0 {
				walk(sub)
				continue
			}
			heading := strings.TrimPrefix(sub.CommandPath(), "certistack ")
			section := sectionOf(t, reference, heading)
			if section == "" {
				continue // the missing section is reported by the test above
			}
			documented := documentedFlags(section)
			if strings.Contains(section, "| [SSH flags](#ssh-flags)") {
				for name := range sshFlags {
					documented[name] = true
				}
			}
			actual := visibleFlags(sub)
			for name := range documented {
				if !actual[name] {
					t.Errorf("the flags table of `certistack %s` in docs/cli-reference.md lists --%s, which the command does not have", heading, name)
				}
			}
			for name := range actual {
				if !documented[name] {
					t.Errorf("`certistack %s` has --%s, which its flags table in docs/cli-reference.md does not list", heading, name)
				}
			}
			compared++
		}
	}
	walk(rootCmd())
	if compared < 10 {
		t.Fatalf("compared the flags of only %d commands; the layout this test reads has changed", compared)
	}
}

// sectionOf is the text under a heading of the CLI reference: the "## " or
// "### " heading whose text is the given name (code quotes removed), up to the
// next heading of the same or a higher level.
func sectionOf(t *testing.T, markdown, name string) string {
	t.Helper()
	lines := strings.Split(markdown, "\n")
	start, level := -1, 0
	for i, line := range lines {
		hashes := len(line) - len(strings.TrimLeft(line, "#"))
		if hashes < 2 || hashes > 4 || !strings.HasPrefix(line[hashes:], " ") {
			continue
		}
		if start >= 0 && hashes <= level {
			return strings.Join(lines[start:i], "\n")
		}
		if start < 0 && strings.Trim(line[hashes:], "` ") == name {
			start, level = i+1, hashes
		}
	}
	if start >= 0 {
		return strings.Join(lines[start:], "\n")
	}
	return ""
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"strings"
	"testing"
)

// systemdEnvironment is the environment of the transient service a test
// models: systemd gives a system service a PATH and little else, and no
// variable a script of the controller names.
var systemdEnvironment = map[string]string{"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}

// systemdExpandCommand is the command line systemd runs for the command line
// systemd-run was given: it substitutes environment variables in each word
// before the program starts. The rules are the ones measured on a real
// systemd 249 (TestLiveSystemdRunMatchesTheModel repeats the measurement on
// any host): "$$" is one "$"; "${NAME}" is the variable's value, or nothing;
// any other "${...}" form is deleted, which is what the older versions do
// and what newer ones may replace by a default, so a script that survives
// the model survives both; a word that is "$NAME" becomes the variable's
// value split at white space, which is no word when it is unset. "%" is
// left alone: a transient service's command has no specifiers.
func systemdExpandCommand(words []string, environment map[string]string) []string {
	var expanded []string
	for _, word := range words {
		if len(word) > 1 && word[0] == '$' && word[1] != '{' && word[1] != '$' && validEnvironmentName(word[1:]) {
			expanded = append(expanded, strings.Fields(environment[word[1:]])...)
			continue
		}
		expanded = append(expanded, systemdExpandWord(word, environment))
	}
	return expanded
}

func systemdExpandWord(word string, environment map[string]string) string {
	var b strings.Builder
	for i := 0; i < len(word); i++ {
		if word[i] != '$' || i+1 >= len(word) {
			b.WriteByte(word[i])
			continue
		}
		switch word[i+1] {
		case '$':
			b.WriteByte('$')
			i++
		case '{':
			end := strings.IndexByte(word[i:], '}')
			if end < 0 {
				b.WriteString(word[i:])
				return b.String()
			}
			if name := word[i+2 : i+end]; validEnvironmentName(name) {
				b.WriteString(environment[name])
			}
			i += end
		default:
			b.WriteByte('$')
		}
	}
	return b.String()
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

// launchedCommand is the command line systemd starts for a controller
// command that runs systemd-run: the words after its options, expanded as
// systemd expands them.
func launchedCommand(t *testing.T, command []string) []string {
	t.Helper()
	for i, word := range command {
		if word != "/usr/bin/systemd-run" {
			continue
		}
		i++
		for i < len(command) && strings.HasPrefix(command[i], "--") {
			if command[i] == "--unit" {
				i++
			}
			i++
		}
		if i >= len(command) {
			break
		}
		return systemdExpandCommand(command[i:], systemdEnvironment)
	}
	t.Fatalf("not a systemd-run command: %q", command)
	return nil
}

// launchedScript is the script a controller command hands to sh -c through
// systemd-run, as the shell receives it.
func launchedScript(t *testing.T, command []string) string {
	t.Helper()
	launched := launchedCommand(t, command)
	if len(launched) != 3 || launched[0] != "/bin/sh" || launched[1] != "-c" {
		t.Fatalf("the service does not run a script with sh -c: %q", launched)
	}
	return launched[2]
}

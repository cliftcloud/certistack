// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"reflect"
	"strings"
	"testing"
)

// The documentation test is only worth what it can catch. These cases are the
// mistakes a page can make, and what the test must say about each.
func TestDocumentedCommandCheckerFindsWhatIsWrong(t *testing.T) {
	for _, c := range []struct {
		name     string
		command  string
		complete bool
		wrapper  bool
		want     string // a fragment of the one problem expected; "" for none
	}{
		{"unknown command", "frobnicate x.yaml", false, false, `has no command "frobnicate"`},
		{"unknown subcommand", "report nope", false, false, `has no command "nope"`},
		{"unknown flag", "run plan.yaml --nope", false, false, `"--nope" is not a flag of`},
		{"unknown flag with value", "run plan.yaml --nope x --env-file e", false, false, `"--nope" is not a flag`},
		{"flag of another command", "validate plan.yaml --vm 100", false, false, `"--vm" is not a flag of`},
		{"short flag that does not exist", "run plan.yaml -z", false, false, `"-z" is not a flag`},
		{"global flag", "--debug version", true, false, ""},
		{"global flag after the command", "version --debug", true, false, ""},
		{"help flag", "run --help", true, false, ""},
		{"completion", "completion bash", true, false, ""},
		{"short flag", "init --env-file e --vm 100 -o plan.yaml --inspect", true, false, ""},
		{"flag with equals", "run plan.yaml --env-file=/e/controller.env", true, false, ""},
		{"check without the file uses the one setup recorded", "check plan.yaml", true, false, ""},
		{"a node worker command needs its file", "node-check", true, false, `required flag(s) "env-file" not set`},
		{"incomplete, it is not held to it", "node-check", false, false, ""},
		{"the appliance wrapper adds the environment file", "node-check", true, true, ""},
		{"rbac needs its names", "setup rbac --node n", true, false, `"overlay-storage"`},
		{"exclusive flags", "setup rbac --node n --overlay-storage s --zone a --sandbox-zones b", true, false, "none of the others can be"},
		{"trust-node needs the host", "setup trust-node", true, false, `"host"`},
		{"trust-node with the host", "setup trust-node --host h", true, false, ""},
		{"too many plans", "validate a.yaml b.yaml", true, false, "arg"},
		{"report show with no file shows the newest", "report show", true, false, ""},
		{"report show takes one report", "report show a.json b.json", true, false, "arg"},
		{"a command with subcommands needs one", "completion", true, false, "needs one of its commands"},
		{"setup runs by itself: the wizard", "setup", true, false, ""},
		{"a placeholder where the command goes", "<command> --env-file e", false, false, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			words := shellWords(c.command)
			problems := newCommandIndex().check(docCommand{where: "test", words: words, complete: c.complete, wrapper: c.wrapper})
			switch {
			case c.want == "" && len(problems) > 0:
				t.Fatalf("`certistack %s` was reported: %v", c.command, problems)
			case c.want != "" && !strings.Contains(strings.Join(problems, "\n"), c.want):
				t.Fatalf("`certistack %s`: problems = %v, want one containing %q", c.command, problems, c.want)
			}
		})
	}
}

// What counts as a certistack command in a line of shell: the program in
// command position, not every word that spells its name.
func TestCertistackInvocationsAreOnlyCommands(t *testing.T) {
	for _, c := range []struct {
		line    string
		want    [][]string
		wrapper []bool
	}{
		{"certistack validate plan.yaml", [][]string{{"validate", "plan.yaml"}}, []bool{false}},
		{"$ certistack version", [][]string{{"version"}}, []bool{false}},
		{"sudo certistack-controller run plan.yaml", [][]string{{"run", "plan.yaml"}}, []bool{true}},
		{"sudo -u certistack /usr/local/bin/certistack run plan.yaml", [][]string{{"run", "plan.yaml"}}, []bool{false}},
		{"CERTISTACK_NODE=n certistack check", [][]string{{"check"}}, []bool{false}},
		{"certistack report show r.json | less", [][]string{{"report", "show", "r.json"}}, []bool{false}},
		{"certistack run plan.yaml > out.log 2>&1", [][]string{{"run", "plan.yaml"}}, []bool{false}},
		{"certistack validate a.yaml && certistack plan a.yaml", [][]string{{"validate", "a.yaml"}, {"plan", "a.yaml"}}, []bool{false, false}},
		{"certistack init [--vm ID]... [--inspect]", [][]string{{"init", "--vm", "ID...", "--inspect"}}, []bool{false}},
		{"certistack validate plan.yaml # check it first", [][]string{{"validate", "plan.yaml"}}, []bool{false}},
		{"sudo docker compose -f deploy/controller/compose.yaml run --rm controller run /plans/n.yaml", [][]string{{"run", "/plans/n.yaml"}}, []bool{false}},
		{"sudo install -m 0755 certistack-linux-amd64 /usr/local/bin/certistack", nil, nil},
		{"sudo chown certistack:certistack /var/lib/certistack", nil, nil},
		{"su - certistack", nil, nil},
		{"ssh certistack@node", nil, nil},
		{"cp certistack /usr/local/bin/", nil, nil},
		{"echo certistack run", nil, nil},
	} {
		got, wrappers := certistackInvocations(shellWords(c.line))
		if !reflect.DeepEqual(got, c.want) || !reflect.DeepEqual(wrappers, c.wrapper) {
			t.Errorf("%q: invocations = %q wrapper %v, want %q %v", c.line, got, wrappers, c.want, c.wrapper)
		}
	}
}

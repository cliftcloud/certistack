// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// systemd-run hands the script to sh -c as a word of a service's command
// line, and systemd substitutes environment variables in such a word before
// the shell sees it, deleting every "${...}" form it does not know. The line
// "set -- ${proc_stat##*\) }" reached the shell as "set --", so no supervisor
// could identify its worker, stopped it with status 125 and then waited for
// ever for its progress tail. The repository's tests ran the script with sh -c
// and never saw it. These tests put the model of what systemd does
// (TestLiveSystemdRunMatchesTheModel checks the model against a real
// systemd-run) between the controller's command and the shell.

// TestSystemdModelFollowsMeasuredBehaviour pins the model to what a real
// systemd 249 was measured to hand to sh (Ubuntu 22.04, PID 1, systemd-run
// --wait --pipe): each row is a word and what the shell received.
func TestSystemdModelFollowsMeasuredBehaviour(t *testing.T) {
	for _, tc := range []struct{ word, want string }{
		{`a${x##*\) }b`, `ab`},
		{`a${x#y}b`, `ab`},
		{`a${x%y}b`, `ab`},
		{`a${x%%y}b`, `ab`},
		{`a${x}b`, `ab`},
		{`a${#x}b`, `ab`},
		{`a${x-y}b`, `ab`},
		{`a$((1+2))b`, `a$((1+2))b`},
		{`a$(echo hi)b`, `a$(echo hi)b`},
		{`a$xb`, `a$xb`},
		{`a$x b`, `a$x b`},
		{`a$$b`, `a$b`},
		{`a$$$b`, `a$$b`},
		{`a$${x##y}b`, `a${x##y}b`},
		{`a%sb`, `a%sb`},
		{`a%%b`, `a%%b`},
		{`a%hb`, `a%hb`},
		{`$HOME`, ``},
		{`$$HOME`, `$HOME`},
		{`${HOME}`, ``},
		{`x${HOME}`, `x`},
		{`x${PATH}y`, `x` + systemdEnvironment["PATH"] + `y`},
		{`trailing$`, `trailing$`},
		{"tab\tand \\ backslash \\$ and 'q' \"dq\"", "tab\tand \\ backslash \\$ and 'q' \"dq\""},
	} {
		got := systemdExpandCommand([]string{tc.word}, systemdEnvironment)
		if tc.want == "" && tc.word[0] == '$' && len(tc.word) > 1 && tc.word[1] != '{' && tc.word[1] != '$' {
			// A word that is "$NAME" is no word at all when NAME is unset.
			if len(got) != 0 {
				t.Errorf("%q became %q, want no word", tc.word, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%q became %q, want %q", tc.word, got, tc.want)
		}
	}
}

// supervisorFixture is one supervisor command and the script it is meant to
// run.
type supervisorFixture struct {
	command []string
	script  string
}

func newSupervisorFixture(t *testing.T, stateDir string, sudo bool) supervisorFixture {
	t.Helper()
	workspaceRoot := path.Join(stateDir, "workers")
	workspace := path.Join(workspaceRoot, uuid.NewString())
	worker := path.Join(workspace, "certistack-node")
	lease := path.Join(workspace, "controller.lease")
	env := path.Join(workspace, "runtime.env")
	result := path.Join(workspace, "worker-result.json")
	progress := path.Join(workspace, "worker-progress.log")
	pid := path.Join(workspace, "worker.pid")
	nodeRun := []string{worker, "node-run", "--plan", path.Join(workspace, "plan.yaml"), "--state-dir", stateDir}
	unit, err := workerUnitName(workspaceRoot, workspace)
	if err != nil {
		t.Fatal(err)
	}
	command := (&Executor{}).supervisedWorkerCommand(SSHConfig{UseSudo: sudo}, unit, workspaceRoot, workspace, pid, lease, stateDir, env, result, progress, nodeRun)
	if command == nil {
		t.Fatalf("no supervisor command for the state directory %q", stateDir)
	}
	return supervisorFixture{command: command, script: supervisorScript(workspaceShellVariables(lease, worker, stateDir, env, progress, workspace), pid, result, workspace, nodeRun)}
}

// TestSupervisorCommandReachesTheShellUnaltered is the regression test for
// that: the script the shell receives from the command the controller sends is,
// byte for byte, the script the supervisor is meant to run, for a state
// directory that holds no special character and for ones that hold every one
// the controller accepts in a path ("$" and "%" among them).
func TestSupervisorCommandReachesTheShellUnaltered(t *testing.T) {
	for _, stateDir := range []string{
		"/var/lib/certistack",
		"/var/lib/cert$tack",
		"/var/lib/${HOME}/certistack",
		"/var/lib/${x##*/}",
		"/var/lib/a$$b",
		"/var/lib/$HOME",
		"/var/lib/%h/%H/%%/%s",
		"/var/lib/100%",
		"/var/lib/trailing$",
		"/var/lib/it's",
	} {
		for _, sudo := range []bool{false, true} {
			f := newSupervisorFixture(t, stateDir, sudo)
			if got := launchedScript(t, f.command); got != f.script {
				t.Errorf("state dir %q (sudo %v): the shell would not receive the supervisor script as written:\n--- received\n%s\n--- written\n%s", stateDir, sudo, got, f.script)
			}
			if (f.command[0] == "/usr/bin/sudo") != sudo {
				t.Errorf("state dir %q: command starts %q with sudo = %v", stateDir, f.command[:2], sudo)
			}
		}
	}
}

// The script holds the forms systemd deletes; the test above is worth
// something only if it would have failed on them.
func TestSupervisorScriptHoldsTheFormsSystemdDeletes(t *testing.T) {
	f := newSupervisorFixture(t, "/var/lib/certistack", false)
	for _, hazard := range []string{`${proc_stat##*\) }`, `${worker_status:-$waited}`, `${state:-unknown}`} {
		if !strings.Contains(f.script, hazard) {
			t.Fatalf("the supervisor script no longer holds %q, which the launcher tests are about", hazard)
		}
	}
}

// Without the escaping, systemd's substitution takes the line out of the
// script, as it did on a real node.
func TestUnescapedSupervisorScriptIsAlteredBySystemd(t *testing.T) {
	f := newSupervisorFixture(t, "/var/lib/certistack", false)
	words := systemdExpandCommand([]string{"/bin/sh", "-c", f.script}, systemdEnvironment)
	if len(words) != 3 || words[2] == f.script {
		t.Fatal("systemd left the unescaped script alone: the model of it is wrong")
	}
	if !strings.Contains(words[2], "\n  set -- \n") {
		t.Fatalf("the unescaped script does not show the effect, `set --` with nothing after it:\n%s", words[2])
	}
}

// The lease watch is a script in a variable of the supervisor, which the
// supervisor gives to systemd-run again: it is escaped once for that, and
// again, with the rest, for the supervisor's own launch.
func TestLeaseWatchReachesTheShellUnaltered(t *testing.T) {
	for _, stateDir := range []string{"/var/lib/certistack", "/var/lib/cert$tack", "/var/lib/${x##*/}/%h"} {
		f := newSupervisorFixture(t, stateDir, false)
		launched := launchedScript(t, f.command)
		literal := shellLiteralAfter(t, launched, "\nwatch_script=")
		got := systemdExpandCommand([]string{literal}, systemdEnvironment)
		workspace := path.Dir(pathOfVariable(t, launched, "pid_file="))
		want := leaseWatchScript(workspaceShellVariables(path.Join(workspace, "controller.lease"), path.Join(workspace, "certistack-node"), stateDir, path.Join(workspace, "runtime.env"), path.Join(workspace, "worker-progress.log"), workspace))
		if len(got) != 1 || got[0] != want {
			t.Errorf("state dir %q: the lease watch would not reach its shell as written:\n--- received\n%q\n--- written\n%q", stateDir, got, want)
		}
	}
}

// Every word of the service's command line is escaped, the unit's name and
// the options included, and nothing else is.
func TestSystemdRunCommandEscapesEveryWord(t *testing.T) {
	got := systemdRunCommand("unit$1", "--property=A=${B}", "/bin/sh", "-c", "echo $x ${y##z} $$ %s")
	want := []string{"/usr/bin/systemd-run", "--unit", "unit$$1", "--description=CertiStack node run", "--collect", "--wait", "--pipe", "--quiet",
		"--property=A=$${B}", "/bin/sh", "-c", "echo $$x $${y##z} $$$$ %s"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("systemdRunCommand = %q, want %q", got, want)
	}
}

// The remote shell takes the whole command as one argument, and the kernel
// limits one argument to 128 KiB. The escaping doubles each "$" of the
// scripts, twice for the lease watch's, and the quoting for ssh more.
func TestSupervisorCommandFitsOneArgument(t *testing.T) {
	f := newSupervisorFixture(t, "/var/lib/certistack", true)
	var quoted []string
	for _, word := range f.command {
		quoted = append(quoted, shellQuote(word))
	}
	size := len(strings.Join(quoted, " "))
	const kernelLimit, margin = 128 << 10, 2
	if size*margin > kernelLimit {
		t.Fatalf("the supervisor command is %d bytes when quoted for ssh: less than a half of the kernel's %d-byte limit on one argument is left as room", size, kernelLimit)
	}
}

// pathOfVariable is the value of the single-quoted shell variable name
// (written "name=") in script.
func pathOfVariable(t *testing.T, script, name string) string {
	t.Helper()
	return shellLiteralAfter(t, script, "\n"+name)
}

// shellLiteralAfter is the value of the shell word that follows prefix in
// script, for a word made by shellQuote.
func shellLiteralAfter(t *testing.T, script, prefix string) string {
	t.Helper()
	at := strings.Index(script, prefix)
	if at < 0 {
		t.Fatalf("the script has no %q", prefix)
	}
	rest := script[at+len(prefix):]
	var b strings.Builder
	for len(rest) > 0 {
		switch {
		case rest[0] == '\'':
			end := strings.IndexByte(rest[1:], '\'')
			if end < 0 {
				t.Fatalf("unterminated quote after %q", prefix)
			}
			b.WriteString(rest[1 : 1+end])
			rest = rest[end+2:]
		case strings.HasPrefix(rest, `"'"`):
			b.WriteByte('\'')
			rest = rest[3:]
		default:
			return b.String()
		}
	}
	return b.String()
}

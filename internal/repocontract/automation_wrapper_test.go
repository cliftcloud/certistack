// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// bashFence is a fenced bash block of a documentation page that holds a whole
// script: the scheduling page includes the shipped file instead.
var bashFence = regexp.MustCompile("(?s)```bash\n(#!/usr/bin/env bash\n.*?)```")

// The scheduling page shows the shipped script by including the file, and has
// the reader fetch that file pinned to the release: never a copy to paste,
// which could drift from what the tests run.
func TestAutomationPageShipsTheWrapperFile(t *testing.T) {
	page, err := os.ReadFile(repoFile("docs", "automation.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`--8<-- "scripts/certistack-validate"`,
		"curl -fsSLo certistack-validate https://raw.githubusercontent.com/cliftcloud/certistack/" + changelogVersion(t) + "/scripts/certistack-validate",
		"sudo install -m 0755 certistack-validate /usr/local/bin/certistack-validate",
	} {
		if !strings.Contains(string(page), want) {
			t.Errorf("docs/automation.md does not say %q", want)
		}
	}
	if bashFence.Match(page) {
		t.Error("docs/automation.md pastes a script again; include scripts/certistack-validate instead")
	}
	info, err := os.Stat(repoFile("scripts", "certistack-validate"))
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Errorf("scripts/certistack-validate must exist and be executable: %v", err)
	}
}

// The script reads its environment file from CERTISTACK_ENV_FILE, so one copy
// serves several sites.
func TestAutomationWrapperTakesTheSitesEnvironmentFile(t *testing.T) {
	needTools(t, "flock", "jq", "sed")
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/bash\n[ \"$1\" = run ] && echo \"$@\" > \"$STUB_RUN_ARGS\"\nexit 2\n"
	if err := os.WriteFile(filepath.Join(bin, "certistack"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	plan := filepath.Join(dir, "site-a.yaml")
	if err := os.WriteFile(plan, []byte("version: v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := filepath.Join(dir, "run-args")
	for env, want := range map[string]string{
		"CERTISTACK_ENV_FILE=/secure/certistack/site-a/controller.env": "--env-file /secure/certistack/site-a/controller.env",
		"CERTISTACK_ENV_FILE=": "--env-file /secure/certistack/controller.env",
	} {
		cmd := exec.Command("bash", repoFile("scripts", "certistack-validate"), plan)
		cmd.Env = append(os.Environ(), env, "STUB_RUN_ARGS="+args, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		_ = cmd.Run()
		got, err := os.ReadFile(args)
		if err != nil || !strings.Contains(string(got), want) {
			t.Errorf("%s: run was given %q, want %q", env, got, want)
		}
	}
}

// The automation guide (docs/automation.md) calls its wrapper script tested.
// This extracts the script from the page, as an operator would copy it, and
// runs it against a stand-in `certistack` that gives a scripted exit status
// and summary, so the exit status a scheduler acts on follows from the run's
// status and from what verify-report says of the report: a verified pass is 0,
// a signed failure 1, a report that is missing or does not verify 2, a stop
// 130, and a run still going 75. verify-report must be asked to bind the
// report to the plan (--expect-plan), or its exit status says nothing of
// acceptance. The script serves both editions: with no KEYRING it judges the
// Community Edition's unsigned report (--unsigned), and with one it verifies a
// report the Enterprise Edition signed (--keyring).
func TestAutomationWrapperExitStatus(t *testing.T) {
	needTools(t, "flock", "jq", "sed")

	dir := t.TempDir()
	// The script the release ships, run as it is: the environment file and the
	// keyring come from its environment, as the page says.
	wrapper := repoFile("scripts", "certistack-validate")
	envFile := "CERTISTACK_ENV_FILE=" + filepath.Join(dir, "env_file")
	keyring := filepath.Join(dir, "keyring")
	plan := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(plan, []byte("version: v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := `#!/bin/bash
case "$1" in
  run)
    [ -n "${STUB_RUN_ARGS:-}" ] && echo "$@" > "$STUB_RUN_ARGS"
    [ -n "$STUB_REPORT" ] && echo "✓ Controller report saved to: $STUB_REPORT"
    exit ${STUB_RUN:-0}
    ;;
  verify-report)
    echo "$@" > "$STUB_ARGS"
    printf '%s\n' "$STUB_SUMMARY"
    exit ${STUB_VERIFY:-0}
    ;;
esac
exit 99
`
	if err := os.WriteFile(filepath.Join(bin, "certistack"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}

	const accepted = `{"all_passed":true,"all_cleaned":true,"acceptance":{"verdict":"accepted"}}`
	const rejected = `{"all_passed":false,"all_cleaned":true,"acceptance":{"verdict":"rejected"}}`
	report := filepath.Join(dir, "report.json")
	args := filepath.Join(dir, "verify-args")
	for _, edition := range []struct {
		name    string
		keyring string   // CERTISTACK_KEYRING
		given   []string // what verify-report must be asked for
		never   []string // and what it must not
	}{
		{"unsigned reports", "", []string{"--unsigned"}, []string{"--keyring"}},
		{"signed reports", keyring, []string{"--keyring " + keyring}, []string{"--unsigned"}},
	} {
		for _, tc := range []struct {
			name    string
			report  string // the path `run` says it saved, or none
			run     string // the stand-in run's exit status
			verify  string // the stand-in verify-report's exit status
			summary string
			want    int
		}{
			{"a verified pass", report, "0", "0", accepted, 0},
			{"a signed failure", report, "1", "1", rejected, 1},
			{"a run that says pass over a report that is not accepted", report, "0", "1", rejected, 1},
			{"an accepted report whose cleanup is not verified", report, "0", "0", `{"all_passed":true,"all_cleaned":false,"acceptance":{"verdict":"accepted"}}`, 1},
			{"an exit status 0 that is not an accepted verdict", report, "0", "0", rejected, 1},
			{"a run that failed over a report that is accepted", report, "1", "0", accepted, 1},
			{"a report that does not verify", report, "0", "2", "", 2},
			{"no report from a failed run", "", "2", "0", "", 2},
			{"no report from a run that says pass", "", "0", "0", "", 2},
			{"no report from a stopped run", "", "130", "0", "", 130},
		} {
			t.Run(edition.name+", "+tc.name, func(t *testing.T) {
				_ = os.Remove(args)
				cmd := exec.Command("bash", wrapper, plan)
				cmd.Env = append(os.Environ(), envFile, "CERTISTACK_KEYRING="+edition.keyring,
					"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
					"STUB_REPORT="+tc.report, "STUB_RUN="+tc.run, "STUB_VERIFY="+tc.verify,
					"STUB_SUMMARY="+tc.summary, "STUB_ARGS="+args)
				output, err := cmd.CombinedOutput()
				got := 0
				var exit *exec.ExitError
				if errors.As(err, &exit) {
					got = exit.ExitCode()
				} else if err != nil {
					t.Fatal(err)
				}
				if got != tc.want {
					t.Fatalf("exit status %d, want %d; output:\n%s", got, tc.want, output)
				}
				if tc.report == "" {
					return // no report, so nothing to verify
				}
				given, err := os.ReadFile(args)
				if err != nil {
					t.Fatalf("verify-report was not run: %v", err)
				}
				for _, want := range append([]string{"--expect-plan " + plan, "--format json", report}, edition.given...) {
					if !strings.Contains(string(given), want) {
						t.Errorf("verify-report was run as %q, without %q", strings.TrimSpace(string(given)), want)
					}
				}
				for _, never := range edition.never {
					if strings.Contains(string(given), never) {
						t.Errorf("verify-report was run as %q, with %q", strings.TrimSpace(string(given)), never)
					}
				}
			})
		}
	}

	t.Run("a previous run of the plan is still active", func(t *testing.T) {
		// The holder waits for the lock (no -n). The loop below also takes the lock, for a
		// moment, each time it asks whether it is free; a holder that asked without waiting
		// and met one of those moments gave up and exited, nothing held the lock, and the
		// loop ran to its deadline (now and then under -race, which the release check runs).
		holder := exec.Command("flock", plan, "sleep", "30")
		if err := holder.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = holder.Process.Kill()
			_ = holder.Wait()
		}()
		// A full parallel suite on a busy host can also starve a freshly started flock for
		// seconds (the gate failed this once at nice 19 on a busy host):
		// the wait is a bound on a hang, not a measurement.
		deadline := time.Now().Add(60 * time.Second)
		for exec.Command("flock", "-n", plan, "true").Run() == nil {
			if time.Now().After(deadline) {
				t.Fatal("the stand-in holder never took the plan's lock")
			}
			time.Sleep(50 * time.Millisecond)
		}
		cmd := exec.Command("bash", wrapper, plan)
		cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		output, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 75 {
			t.Fatalf("exit status %v, want 75; output:\n%s", err, output)
		}
	})
}

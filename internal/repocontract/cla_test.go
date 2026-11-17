// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The CLA check exempts no one by name. The only exemption is a
// pull request opened by Dependabot's account, by its immutable ID.
func TestCLAExemptsOnlyDependabotByAccountID(t *testing.T) {
	job := readWorkflow(t, "cla.yml").Jobs["CLAAssistant"]
	actionIndex := -1
	for i, step := range job.Steps {
		if !strings.HasPrefix(step.Uses, "contributor-assistant/github-action@") {
			continue
		}
		actionIndex = i
		if allowlist := strings.TrimSpace(fmt.Sprint(step.With["allowlist"])); step.With["allowlist"] != nil && allowlist != "" {
			t.Errorf("the CLA action has an allowlist %q: names are claimable by any commit", allowlist)
		}
		if step.If != "" {
			t.Errorf("the CLA action step has its own condition %q; the job condition decides", step.If)
		}
	}
	if actionIndex < 0 {
		t.Fatal("no CLA action step")
	}
	condition := strings.Join(strings.Fields(job.If), " ")
	for _, want := range []string{
		"github.event.pull_request.user.id != 49699333",
		"github.event.issue.user.id != 49699333",
		"github.event.issue.pull_request",
	} {
		if !strings.Contains(condition, want) {
			t.Errorf("job condition lacks %q: %s", want, condition)
		}
	}
	for _, name := range []string{"login", "[bot]", "*"} {
		if strings.Contains(condition, name) {
			t.Errorf("job condition matches on %q, a name rather than an account ID: %s", name, condition)
		}
	}
	guardIndex, _ := job.step(t, "Refuse pull requests the CLA check cannot read in full")
	if guardIndex > actionIndex {
		t.Error("the commit-count guard runs after the CLA action")
	}
}

// The pinned CLA action reads only the first 100 commits of a pull
// request, so a longer one fails rather than passing on a partial read.
func TestCLARefusesPullRequestsBeyondTheActionsFirstPage(t *testing.T) {
	needTools(t)
	_, guard := readWorkflow(t, "cla.yml").Jobs["CLAAssistant"].step(t, "Refuse pull requests the CLA check cannot read in full")
	root := t.TempDir()
	logPath := filepath.Join(root, "calls.log")
	writeExecutable(t, filepath.Join(root, "gh"), `#!/usr/bin/env bash
printf 'gh %s\n' "$*" >> "$STUB_LOG"
if [[ -z "$STUB_COMMITS" ]]; then echo 'HTTP 404: Not Found' >&2; exit 1; fi
printf '%s\n' "$STUB_COMMITS"
`)
	for _, c := range []struct {
		commits string
		pass    bool
	}{
		{"1", true},
		{"100", true},
		{"101", false},
		{"250", false},
		{"", false},
		{"null", false},
	} {
		_ = os.Remove(logPath)
		out, err := runStep(t, root, shellEnv(t, root, root, map[string]string{
			"STUB_LOG": logPath, "STUB_COMMITS": c.commits,
			"GH_TOKEN": "test-token", "GH_REPO": "test-owner/certistack", "PR_NUMBER": "42",
		}), guard.Run)
		if (err == nil) != c.pass {
			t.Errorf("%q commits: passed=%v, want %v\n%s", c.commits, err == nil, c.pass, out)
		}
		if calls := readLog(t, logPath); len(calls) != 1 || calls[0] != "gh api repos/test-owner/certistack/pulls/42 --jq .commits" {
			t.Errorf("%q commits: gh calls %q", c.commits, calls)
		}
	}
}

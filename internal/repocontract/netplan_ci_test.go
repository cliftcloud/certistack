// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"strings"
	"testing"
)

// The guest-network tests that ask netplan's own generator which
// networkd file wins over the recovery profile skip where it is not installed.
// The Linux jobs that run the Go suite (CI's test job and the release gate)
// install netplan before the tests and set CERTISTACK_REQUIRE_NETPLAN, which
// turns a missing generator into a failure, so the guard cannot disappear
// silently on an image without it.
func TestWorkflowsInstallNetplanAndRequireIt(t *testing.T) {
	for _, c := range []struct{ workflow, job string }{{"ci.yml", "test"}, {"release.yml", "verify"}} {
		job, ok := readWorkflow(t, c.workflow).Jobs[c.job]
		if !ok {
			t.Fatalf("%s has no job %q", c.workflow, c.job)
		}
		if job.Env["CERTISTACK_REQUIRE_NETPLAN"] == "" {
			t.Errorf("%s %s does not set CERTISTACK_REQUIRE_NETPLAN, so a runner without netplan would skip the guest-network guard", c.workflow, c.job)
		}
		install, firstTest := -1, -1
		for i, step := range job.Steps {
			if strings.Contains(step.Run, "install") && strings.Contains(step.Run, "netplan.io") && install < 0 {
				install = i
				if step.If != "" || step.ContinueOnError != nil {
					t.Errorf("%s %s: the step %q that installs netplan is conditional or may fail silently", c.workflow, c.job, step.Name)
				}
			}
			if (strings.Contains(step.Run, "go test") || strings.Contains(step.Run, "make test")) && firstTest < 0 {
				firstTest = i
			}
		}
		switch {
		case install < 0:
			t.Errorf("%s %s never installs netplan (the netplan.io package)", c.workflow, c.job)
		case firstTest < 0:
			t.Fatalf("%s %s runs no Go tests; this check is looking in the wrong place", c.workflow, c.job)
		case install > firstTest:
			t.Errorf("%s %s installs netplan (step %d) after its first Go test (step %d)", c.workflow, c.job, install+1, firstTest+1)
		}
	}
}

// CertiStack ships Linux executables only: CI runs no
// Windows test job, and keeps the Windows build compiling with go vet in the
// Linux test job.
func TestCIVetsTheWindowsBuildAndRunsNoWindowsTests(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	for name, job := range ci.Jobs {
		if strings.Contains(strings.ToLower(job.RunsOn), "windows") {
			t.Errorf("ci.yml job %s runs on %s: the Windows tests are not run", name, job.RunsOn)
		}
	}
	vetted := false
	for _, step := range ci.Jobs["test"].Steps {
		if strings.Contains(step.Run, "GOOS=windows go vet ./...") {
			vetted = true
		}
	}
	if !vetted {
		t.Error("ci.yml's test job does not run GOOS=windows go vet ./...: the Windows build could stop compiling unseen")
	}
}

// Every job runs on one pinned runner image, the one the release workflow's
// replays were made on. ubuntu-latest can change underneath a workflow (Ubuntu
// 26.04 brings uutils coreutils and netplan 1.2), and a release must not meet a
// new environment at its tag.
func TestWorkflowsRunOnThePinnedRunnerImage(t *testing.T) {
	const pinned = "ubuntu-24.04"
	for _, name := range []string{"ci.yml", "release.yml", "cla.yml"} {
		for job, spec := range readWorkflow(t, name).Jobs {
			if spec.RunsOn != pinned {
				t.Errorf("%s job %s runs on %q, want %q", name, job, spec.RunsOn, pinned)
			}
		}
	}
}

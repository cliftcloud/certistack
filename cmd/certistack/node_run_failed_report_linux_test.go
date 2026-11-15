// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// sentBackupConfig is a source VM's configuration as a backup holds it, enough
// for the runner to inherit hardware from it.
const sentBackupConfig = "cores: 2\nsockets: 1\nmemory: 2048\nbios: seabios\nscsihw: virtio-scsi-single\nostype: l26\n" +
	"net0: virtio=BC:24:11:00:00:%02x,bridge=vmbr0\nscsi0: local-lvm:vm-%d-disk-0,size=32G\n"

// installFakeBackupClient puts a proxmox-backup-client on PATH that holds one
// snapshot of each VM in snapshots and, for each VM in configs, a
// configuration to restore from it. A group it holds nothing for lists no
// snapshots, as PBS does; a configuration it holds nothing for fails to
// restore, as a snapshot whose blob is unreadable does.
func installFakeBackupClient(t *testing.T, snapshots, configs []int) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range snapshots {
		write(fmt.Sprintf("list-%d.json", id), fmt.Sprintf(`[{"backup-type":"vm","backup-id":"%d","backup-time":1790273656,"files":[{"filename":"index.json.blob"}]}]`, id))
	}
	for _, id := range configs {
		write(fmt.Sprintf("conf-%d", id), fmt.Sprintf(sentBackupConfig, id%256, id))
	}
	write("files.json", `[{"filename":"qemu-server.conf.blob","crypt-mode":"none","size":512},{"filename":"drive-scsi0.img.fidx","crypt-mode":"none","size":34359738368}]`)
	script := "#!/bin/sh\n" +
		"for last; do :; done\n" +
		"case \"$1 $2\" in\n" +
		"  'snapshot list')\n" +
		"    id=${3#vm/}\n" +
		"    if [ -f " + dir + "/list-$id.json ]; then cat " + dir + "/list-$id.json; else echo '[]'; fi ;;\n" +
		"  'snapshot files') cat " + dir + "/files.json ;;\n" +
		"  restore*)\n" +
		"    prev=\n" +
		"    for a; do\n" +
		"      if [ \"$a\" = qemu-server.conf.blob ]; then snap=$prev; fi\n" +
		"      prev=$a\n" +
		"    done\n" +
		"    id=${snap#vm/}; id=${id%%/*}\n" +
		"    if [ -f " + dir + "/conf-$id ]; then cp " + dir + "/conf-$id \"$last\"; else echo 'unreadable blob' >&2; exit 1; fi ;;\n" +
		"  *) exit 1 ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

// runNodeWorkerOn runs the real node-run command, with the real runner, on the
// plan the controller would send for examples/three-tier-app.yaml, with the
// host checks passing, and returns the worker's result and the plan the
// controller holds.
func runNodeWorkerOn(t *testing.T) (nodeapi.RunResult, *config.Plan) {
	t.Helper()
	for name := range workerEnvironmentNames {
		t.Setenv(name, "")
	}
	previousLock, previousPreflight := acquireHostLock, runPreflight
	t.Cleanup(func() { acquireHostLock, runPreflight = previousLock, previousPreflight })
	root := t.TempDir()
	acquireHostLock = func() (*os.File, error) {
		return os.OpenFile(filepath.Join(root, "host.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	}
	runPreflight = func(context.Context, *config.Plan, preflight.Options) preflight.Result {
		return preflight.Result{Ready: true, Checks: []preflight.CheckItem{{Name: "kvm", Status: "passed", Detail: "/dev/kvm is accessible"}}}
	}

	controllersPlan, err := config.LoadFromFile(filepath.Join("..", "..", "examples", "three-tier-app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sent, err := config.MarshalWorkerPlan(controllersPlan)
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(root, "plan.yaml")
	if err := os.WriteFile(planPath, sent, 0o600); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(root, "runtime.env")
	if err := os.WriteFile(envFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := nodeRunCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--plan", planPath, "--node", "pve-01", "--env-file", envFile,
		"--state-dir", filepath.Join(root, "state"), "--scratch", filepath.Join(root, "scratch"),
		"--output", filepath.Join(root, "reports"), "--run-id", "run-seam06",
	})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("node-run: %v\n%s", err, stdout.String())
	}
	var result nodeapi.RunResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("the worker's result is not JSON: %v\n%s", err, stdout.String())
	}
	return result, controllersPlan
}

// A worker whose run ends before the orchestrator has a report builds
// its failure report from the plan it was given, and the runner had written
// what it resolved into that plan by then: VM 1's pinned snapshot, its
// hardware. The report then carried the digest and the reserved memory of a
// plan the controller never sent, and the controller's own rule refused the
// worker's genuine failure ("validated_plan_sha256 differs from the expected
// worker plan"), so the run ended with no signed evidence and not the reason.
// This is the reported case through the real command and the real runner:
// examples/three-tier-app.yaml, a PBS that holds a backup of VM 201 and, in
// the two cases, none of VM 202 or one whose configuration cannot be read.
func TestNodeRunFailureBeforeTheOrchestratorIsEvidenceOfThePlanTheControllerSent(t *testing.T) {
	for _, tc := range []struct {
		name      string
		snapshots []int
		configs   []int
		want      string
	}{
		{
			name:      "a later VM has no backup (snapshot resolution)",
			snapshots: []int{201},
			want:      "no snapshots found for PBS backup group vm/202",
		},
		{
			name:      "a later VM's backup configuration cannot be read (after the first VM took its hardware)",
			snapshots: []int{201, 202, 203},
			configs:   []int{201, 203},
			want:      "target VM 9102",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installFakeBackupClient(t, tc.snapshots, tc.configs)
			result, controllersPlan := runNodeWorkerOn(t)

			if result.Report == nil {
				t.Fatalf("the worker returned no evidence of its failure: %q", result.Error)
			}
			if !strings.Contains(result.Error, tc.want) {
				t.Fatalf("the worker's failure = %q, want it to name %q", result.Error, tc.want)
			}
			if result.Report.AllPassed || result.Report.FailureReason != result.Error || result.Report.RunID != "run-seam06" {
				t.Errorf("the failure report = passed %v, reason %q, run %q", result.Report.AllPassed, result.Report.FailureReason, result.Report.RunID)
			}
			// The controller's own rules over a worker's report (checkWorkerReport
			// applies exactly these to the plan it sent).
			if problems := attest.PolicyEvidenceProblems(result.Report, controllersPlan); len(problems) != 0 {
				t.Errorf("the controller refuses the worker's failure report: %s", strings.Join(problems, "; "))
			}
			sentDigest, err := config.CanonicalWorkerPlanSHA256(controllersPlan)
			if err != nil {
				t.Fatal(err)
			}
			if result.Report.ValidatedPlanSHA256 != sentDigest || result.Report.ResolvedPlanSHA256 != sentDigest {
				t.Errorf("the report's digests are validated %s, resolved %s; the plan the controller sent is %s",
					result.Report.ValidatedPlanSHA256, result.Report.ResolvedPlanSHA256, sentDigest)
			}
		})
	}
}

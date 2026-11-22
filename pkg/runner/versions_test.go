// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// versionNode is a node whose PVE answers /version with pveVersion and whose
// proxmox-backup-client answers `version` with clientOutput; every call of the
// client is appended to log.
type versionNode struct {
	pveURL string
	log    string
}

func newVersionNode(t *testing.T, pveVersion, clientOutput string) versionNode {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/version") {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"version": pveVersion}})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$1\" >> " + log + "\n" +
		"case \"$1\" in\n" +
		"  version) printf '%s' '" + clientOutput + "' ;;\n" +
		"  snapshot) echo '[]' ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("PVE_URL", server.URL)
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!run")
	t.Setenv("PVE_TOKEN_SECRET", "secret")
	t.Setenv("PBS_REPOSITORY", "certistack@pbs!restore@pbs.lab.example:backup-store")
	t.Setenv("PBS_PASSWORD", "pbs-secret")
	t.Setenv("PBS_FINGERPRINT", "")
	t.Setenv("PBS_NAMESPACE", "")
	t.Setenv("PVE_TLS_INSECURE", "")
	return versionNode{pveURL: server.URL, log: log}
}

// calls are the proxmox-backup-client subcommands that were run.
func (n versionNode) calls() []string {
	data, err := os.ReadFile(n.log)
	if err != nil {
		return nil
	}
	return strings.Fields(string(data))
}

const (
	pbs4 = "client version: 4.2.5\nserver version: 4.2.7\n"
	pbs3 = "client version: 3.3.7\nserver version: 3.4.0\n"
	pbs2 = "client version: 2.4.1\nserver version: 2.4.7\n"
)

func planWithOneVM() *config.Plan {
	return &config.Plan{PlanID: "versions", Tiers: []config.Tier{{Level: 1, VMs: []config.VM{
		{VMID: 9001, Name: "app", SourceVMID: 100, SourcePBS: config.SourcePBS{Snapshot: "latest"}},
	}}}}
}

// An unsupported pair is refused by the first thing a run and a plan do,
// naming the versions, before any backup is listed or read: not by whichever
// call of the unsupported PVE or PBS fails first.
func TestPrepareRunRefusesAnUnsupportedPairBeforeItReadsABackup(t *testing.T) {
	for _, tc := range []struct {
		name, pve, client string
		want              []string
	}{
		{"PVE 7", "7.4-20", pbs4, []string{"PVE 7.4-20", "PBS 4.2.7", "proxmox-backup-client 4.2.5", "unsupported", "older than PVE 8"}},
		{"PBS 2", "9.1.1", pbs2, []string{"PVE 9.1.1", "PBS 2.4.7", "proxmox-backup-client 2.4.1", "unsupported", "older than PBS 3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := newVersionNode(t, tc.pve, tc.client)
			opts := Options{versions: &versionRecord{}}
			_, _, err := prepareRun(context.Background(), planWithOneVM(), opts, t.TempDir())
			if err == nil {
				t.Fatal("an unsupported pair was not refused")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q lacks %q", err, want)
				}
			}
			for _, call := range node.calls() {
				if call != "version" {
					t.Errorf("the PBS client was asked to %q before the refusal", call)
				}
			}
			if !opts.versions.read || opts.versions.status.Verdict() != "unsupported" {
				t.Errorf("the refusal's versions were not kept: %+v", opts.versions)
			}
		})
	}
}

// An untested pair, and a version that cannot be read, are not refusals.
func TestPrepareRunGoesOnWithAnUntestedPair(t *testing.T) {
	for _, tc := range []struct {
		name, pve, client, verdict string
	}{
		{"a newer PVE major with PBS 3", "10.0.1", pbs3, "untested"},
		{"PVE 9 with PBS 3", "9.1.1", pbs3, "untested"},
		{"tested", "9.1.1", pbs4, "tested"},
		{"no server line", "9.1.1", "client version: 4.2.5\n", "unknown"},
		{"no versions at all", "", "", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newVersionNode(t, tc.pve, tc.client)
			opts := Options{versions: &versionRecord{}}
			if _, _, err := prepareRun(context.Background(), &config.Plan{PlanID: "empty"}, opts, t.TempDir()); err != nil {
				t.Fatalf("prepareRun refused a pair that is not unsupported: %v", err)
			}
			if !opts.versions.read || opts.versions.status.Verdict() != tc.verdict {
				t.Errorf("verdict = %q, want %q (%+v)", opts.versions.status.Verdict(), tc.verdict, opts.versions)
			}
		})
	}
}

// A node that answers nothing has versions that are unknown, not a failed
// run.
func TestUnreadableVersionsAreNotAnError(t *testing.T) {
	node := newVersionNode(t, "", "") // PVE answers with no version, the client prints none
	t.Setenv("PATH", t.TempDir())     // and then there is no proxmox-backup-client at all
	opts := Options{versions: &versionRecord{}}
	if err := gateVersions(context.Background(), opts, pve.NewClient(pve.Config{BaseURL: node.pveURL}), pbs.New(pbs.Config{})); err != nil {
		t.Fatalf("versions that could not be read were refused: %v", err)
	}
	if got := opts.versions.status.Verdict(); got != "unknown" {
		t.Fatalf("verdict = %q, want unknown", got)
	}
	if err := gateVersions(context.Background(), Options{}, nil, nil); err != nil {
		t.Fatalf("nil clients were refused: %v", err)
	}
}

// capturedProgress runs f with progress events enabled and returns what the
// worker wrote to standard error.
func capturedProgress(t *testing.T, f func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	t.Setenv("CERTISTACK_PROGRESS_EVENTS", "1")
	os.Stderr = writer
	f()
	os.Stderr = original
	t.Setenv("CERTISTACK_PROGRESS_EVENTS", "")
	_ = writer.Close()
	data, _ := io.ReadAll(reader)
	return string(data)
}

// boundedPlan is a plan that passes the runner's bounds, with no VM.
func boundedPlan(id string) *config.Plan {
	return &config.Plan{PlanID: id, Compliance: config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90},
		AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 90, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
		Tiers:            []config.Tier{{Level: 1}},
	}
}

func runWithGate(t *testing.T) (*attest.Report, string, error) {
	t.Helper()
	previousPrepare, previousOrchestrate := prepareRunFn, orchestrate
	t.Cleanup(func() { prepareRunFn, orchestrate = previousPrepare, previousOrchestrate })
	// The real gate, in a prepareRun that reads nothing else.
	prepareRunFn = func(ctx context.Context, _ *config.Plan, opts Options, _ string) (*pve.Client, *pbs.Client, error) {
		pveClient := pve.NewClient(pve.Config{BaseURL: os.Getenv("PVE_URL"), TokenID: "certistack@pve!run", TokenSecret: "secret"})
		pbsClient := pbs.New(pbs.Config{Repository: os.Getenv("PBS_REPOSITORY"), Password: os.Getenv("PBS_PASSWORD")})
		if err := gateVersions(ctx, opts, pveClient, pbsClient); err != nil {
			return nil, nil, err
		}
		return pveClient, pbsClient, nil
	}
	orchestrated := false
	orchestrate = func(context.Context, *orchestrator.Orchestrator) (*orchestrator.ExecutionResult, error) {
		orchestrated = true
		return &orchestrator.ExecutionResult{AllPassed: true, RTO: time.Second, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}}, nil
	}
	plan := boundedPlan("report-versions")
	root := t.TempDir()
	var report *attest.Report
	var runErr error
	progress := capturedProgress(t, func() {
		report, runErr = run(context.Background(), plan, Options{NodeName: "pve1", StateDir: filepath.Join(root, "state"), ScratchDir: filepath.Join(root, "scratch"), OutputDir: filepath.Join(root, "reports")})
	})
	if runErr != nil && orchestrated {
		t.Errorf("a run that was refused still reached the orchestrator")
	}
	if runErr != nil {
		if _, err := os.Stat(filepath.Join(root, "state", "active.json")); err == nil {
			t.Errorf("a refused run began a journal")
		}
	}
	return report, progress, runErr
}

// The report says which versions the run read and what the release makes of
// them, and an untested pair is warned about once.
func TestRunRecordsTheProxmoxVersionsInItsReport(t *testing.T) {
	for _, tc := range []struct {
		name, pve, client string
		wantSupport       string
		warns             bool
	}{
		{"tested", "9.1.1", pbs4, "tested", false},
		{"untested", "10.0.1", pbs3, "untested", true},
		{"unknown", "9.1.1", "client version: 4.2.5\n", "unknown", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newVersionNode(t, tc.pve, tc.client)
			report, progress, err := runWithGate(t)
			if err != nil {
				t.Fatalf("run = %v", err)
			}
			if report.PVEVersion != tc.pve || report.VersionSupport != tc.wantSupport {
				t.Errorf("report versions = pve %q, support %q; want %q, %q", report.PVEVersion, report.VersionSupport, tc.pve, tc.wantSupport)
			}
			data, _ := json.Marshal(report)
			if tc.name == "unknown" {
				if report.PBSVersion != "" || report.PBSClientVersion != "4.2.5" || strings.Contains(string(data), "pbs_version") {
					t.Errorf("a server version that was not read is in the report: %s", data)
				}
			} else if report.PBSVersion == "" || report.PBSClientVersion == "" {
				t.Errorf("report lacks the PBS versions: %s", data)
			}
			if warnings := strings.Count(progress, "CERTISTACK_PROGRESS "); tc.warns && warnings != 1 {
				t.Errorf("the operator was warned %d times, want once: %q", warnings, progress)
			} else if !tc.warns && strings.Contains(progress, "WARN") {
				t.Errorf("a tested pair was warned about: %q", progress)
			}
		})
	}
}

// An unsupported pair stops the run before its journal, its sandbox and its
// report exist.
func TestRunRefusesAnUnsupportedPairBeforeItCreatesAnything(t *testing.T) {
	newVersionNode(t, "7.4-20", pbs4)
	report, _, err := runWithGate(t)
	if err == nil || !strings.Contains(err.Error(), "PVE 7.4-20") || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("run = %v, want the refusal naming PVE 7.4-20", err)
	}
	if report != nil {
		t.Fatalf("a refused run produced a report: %+v", report)
	}
}

// A report from a prepareRun that read no versions carries no member for
// them.
func TestRunWithoutVersionsLeavesTheMembersOut(t *testing.T) {
	previousPrepare, previousOrchestrate := prepareRunFn, orchestrate
	t.Cleanup(func() { prepareRunFn, orchestrate = previousPrepare, previousOrchestrate })
	prepareRunFn = func(context.Context, *config.Plan, Options, string) (*pve.Client, *pbs.Client, error) {
		return pve.NewClient(pve.Config{}), pbs.New(pbs.Config{}), nil
	}
	orchestrate = func(context.Context, *orchestrator.Orchestrator) (*orchestrator.ExecutionResult, error) {
		return &orchestrator.ExecutionResult{AllPassed: true, RTO: time.Second, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}}, nil
	}
	plan := &config.Plan{PlanID: "no-versions", Compliance: config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90},
		AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 90, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
		Tiers:            []config.Tier{{Level: 1}},
	}
	root := t.TempDir()
	report, err := run(context.Background(), plan, Options{NodeName: "pve1", StateDir: filepath.Join(root, "state"), ScratchDir: filepath.Join(root, "scratch"), OutputDir: filepath.Join(root, "reports")})
	if err != nil {
		t.Fatal(err)
	}
	if report.PVEVersion != "" || report.PBSVersion != "" || report.PBSClientVersion != "" || report.VersionSupport != "" {
		t.Fatalf("report names versions nobody read: %+v", report)
	}
}

// plan shows the check, warns about an untested pair, and refuses an
// unsupported one in the words run does.
func TestPlanRunShowsAndRefusesByTheSameVersions(t *testing.T) {
	newVersionNode(t, "7.4-20", pbs4)
	_, refusal := PlanRun(context.Background(), boundedPlan("plan-versions"), Options{NodeName: "pve1", StateDir: t.TempDir(), ScratchDir: t.TempDir()})
	if refusal == nil || !strings.Contains(refusal.Error(), "PVE 7.4-20") || !strings.Contains(refusal.Error(), "unsupported") {
		t.Fatalf("PlanRun = %v, want the refusal naming PVE 7.4-20", refusal)
	}
	_, _, runRefusal := runWithGate(t)
	if runRefusal == nil || runRefusal.Error() != refusal.Error() {
		t.Fatalf("run refuses with %q and plan with %q; they must say the same", runRefusal, refusal)
	}

	for _, tc := range []struct {
		name, pve, client string
		status            string
		warns             bool
	}{
		{"untested", "10.0.1", pbs3, orchestrator.StatusWarning, true},
		{"tested", "9.1.1", pbs4, orchestrator.StatusOK, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newVersionNode(t, tc.pve, tc.client)
			plan, err := PlanRun(context.Background(), boundedPlan("plan-versions"), Options{NodeName: "pve1", StateDir: t.TempDir(), ScratchDir: t.TempDir()})
			if err != nil || plan == nil {
				t.Fatalf("PlanRun = %v, %v", plan, err)
			}
			if len(plan.Steps) == 0 || plan.Steps[0].Kind != "versions" || plan.Steps[0].Phase != "checks" || plan.Steps[0].Status != tc.status {
				t.Fatalf("first step = %+v, want the versions check with status %q", plan.Steps, tc.status)
			}
			warned := strings.Contains(strings.Join(plan.Warnings, "\n"), "not covered by the release evidence")
			if warned != tc.warns {
				t.Errorf("warnings = %v, want a release-evidence warning: %v", plan.Warnings, tc.warns)
			}
			if tc.warns && strings.Count(strings.Join(plan.Warnings, "\n"), "PVE 10.0.1, PBS 3.4.0") != 1 {
				t.Errorf("the plan does not warn of the untested pair exactly once: %v", plan.Warnings)
			}
		})
	}
}

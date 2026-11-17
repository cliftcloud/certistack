// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// keptRefusal is a refused result as the controller keeps it.
type keptRefusal struct {
	path   string
	banner string
	reason string
	raw    []byte
}

var keptRefusalName = regexp.MustCompile(`^run-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.refused\.txt$`)

// keptRefusals reads every file in outputDir/refused.
func keptRefusals(t *testing.T, outputDir string) []keptRefusal {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(outputDir, attest.RefusedDirName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var kept []keptRefusal
	for _, entry := range entries {
		path := filepath.Join(outputDir, attest.RefusedDirName, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.SplitN(data, []byte("\n"), 4)
		if len(lines) != 4 || string(lines[2]) != attest.RefusedRawMarker || !strings.HasPrefix(string(lines[1]), "Reason: ") {
			t.Fatalf("%s is not laid out as a kept refused result: %.300q", path, data)
		}
		kept = append(kept, keptRefusal{path: path, banner: string(lines[0]), reason: strings.TrimPrefix(string(lines[1]), "Reason: "), raw: lines[3]})
	}
	return kept
}

// requireRefusalKept holds a refused run to its contract: one result is kept in
// outputDir/refused, named for the run (wantRun, or any controller run ID when
// empty), starting with the banner, private to its owner, with the refusal's
// reason (containing wantReason) and the worker's JSON. It returns the file.
func requireRefusalKept(t *testing.T, outputDir, wantRun, wantReason string) keptRefusal {
	t.Helper()
	kept := keptRefusals(t, outputDir)
	if len(kept) != 1 {
		t.Fatalf("%d refused results kept in %s, want 1", len(kept), outputDir)
	}
	k := kept[0]
	name := filepath.Base(k.path)
	if !keptRefusalName.MatchString(name) || wantRun != "" && name != wantRun+".refused.txt" {
		t.Errorf("kept as %q, want <run-id>.refused.txt for %q", name, wantRun)
	}
	const banner = "REFUSED, NOT EVIDENCE: this worker result failed the controller's checks and was never signed"
	if k.banner != banner {
		t.Errorf("first line = %q, want the banner", k.banner)
	}
	if !strings.Contains(k.reason, wantReason) {
		t.Errorf("reason line %q lacks %q", k.reason, wantReason)
	}
	var result nodeapi.RunResult
	if err := json.Unmarshal(k.raw, &result); err != nil || result.Report == nil {
		t.Errorf("the worker's bytes are not its result: %v: %.200q", err, k.raw)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(k.path); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("kept result mode = %v, %v; want 0600", info, err)
		}
	}
	return k
}

// The refused result is the worker's bytes exactly as the node returned them,
// whatever their layout, and the operator is told where it is.
func TestARefusedWorkersResultIsKeptByteForByte(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	report := workerReportFor(t, opts)
	report.NodeFQDN = "unrelated-node"
	// Indented, with a trailing newline and a member the controller does not
	// know: nothing is re-encoded on the way to the file.
	raw, err := json.MarshalIndent(map[string]any{"report": report, "error": "", "x_future": []int{1, 2}}, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	fake := &fakeCommandRunner{journalPhase: "cleaned"}
	answersNodeRun(fake, string(raw))
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || result != nil || !strings.Contains(err.Error(), `the report names node "unrelated-node"`) {
		t.Fatalf("err = %v, result = %+v; want the report refused", err, result)
	}
	kept := requireRefusalKept(t, opts.OutputDir, fake.runID, `the report names node "unrelated-node"`)
	if !bytes.Equal(kept.raw, raw) {
		t.Errorf("kept bytes differ from the worker's:\n got %.200q\nwant %.200q", kept.raw, raw)
	}
	// The operator is told where it is, and what it is not.
	for _, want := range []string{"was refused, and no report was written", "raw result is kept at " + kept.path, "not evidence", "was never signed"} {
		if !strings.Contains(progress.String(), want) {
			t.Errorf("progress lacks %q:\n%s", want, progress.String())
		}
	}
	// The error of the run is the refusal, unchanged.
	if strings.Contains(err.Error(), "refused result") || strings.Contains(err.Error(), kept.path) {
		t.Errorf("the run's error was changed by keeping the result: %v", err)
	}
}

// A report that decodes but that the controller will not sign for a reason
// checkWorkerReport does not look at is kept too: a report ID that is not a
// UUID cannot name a file the controller would write.
func TestAReportRefusedWhilePreparingItIsKeptToo(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	report := workerReportFor(t, opts)
	report.ReportID = "../../etc/not-a-uuid"
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || result != nil || !strings.Contains(err.Error(), "worker report ID is not a UUID") {
		t.Fatalf("err = %v, result = %+v; want the report ID refused", err, result)
	}
	if reportsSaved(t, opts.OutputDir) != 0 {
		t.Errorf("a report was saved")
	}
	requireRefusalKept(t, opts.OutputDir, fake.runID, "worker report ID is not a UUID")
	if !strings.Contains(progress.String(), "was refused, and no report was written") || !strings.Contains(progress.String(), "raw result is kept at") {
		t.Errorf("progress does not tell the refusal and where the result is:\n%s", progress.String())
	}
}

// Scope: only a report the controller refuses is kept. A run that
// passes, a run that fails and is signed as it failed, and a result that holds
// no report keep nothing in refused/.
func TestOnlyARefusedReportIsKept(t *testing.T) {
	t.Run("a run that passes", func(t *testing.T) {
		opts := completedWorkerTeardownOptions(t)
		fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
		if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
		requireNothingKept(t, opts.OutputDir, 1)
	})
	t.Run("a failed run, signed as it failed", func(t *testing.T) {
		opts := completedWorkerTeardownOptions(t)
		report := workerReportFor(t, opts)
		report.AllPassed = false
		report.FailureReason = "recovery tier 1 failed: VM 9001 probes: one or more probes failed"
		report.VMRecords = report.VMRecords[:1]
		report.VMRecords[0].AllPassed = false
		report.VMRecords[0].VerificationStatus = "failed"
		report.VMRecords[0].ProbeResults[0].Passed = false
		report.VMRecords[0].SourceDisks[0].IntegrityStatus = probe.DiskMapFailed
		report.VMRecords[0].SourceDisks[0].ImageDigest = ""
		fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report, Error: report.FailureReason}, journalPhase: "cleaned"}
		result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
		if err == nil || result == nil || result.ReportPath == "" {
			t.Fatalf("err = %v, result = %+v; want a signed, saved failure", err, result)
		}
		requireNothingKept(t, opts.OutputDir, 1)
	})
	for name, tc := range map[string]struct {
		result string
		want   string
	}{
		"an empty result":        {"", "it is empty"},
		"output that is no JSON": {"Traceback (most recent call last):\n", "it begins"},
		"an error and no report": {`{"error":"refused the plan"}`, "node worker failed before producing evidence"},
		"neither":                {`{}`, "neither a report nor an error"},
	} {
		t.Run(name, func(t *testing.T) {
			opts := completedWorkerTeardownOptions(t)
			fake := &fakeCommandRunner{journalPhase: "cleanup_failed"}
			answersNodeRun(fake, tc.result)
			if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			requireNothingKept(t, opts.OutputDir, 0)
		})
	}
}

// requireNothingKept asserts the report directory holds no refused/ directory
// and want report files.
func requireNothingKept(t *testing.T, outputDir string, wantReports int) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(outputDir, attest.RefusedDirName)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s exists (%v), want nothing kept", attest.RefusedDirName, err)
	}
	if got := reportsSaved(t, outputDir); got != wantReports {
		t.Errorf("%d report file(s) saved, want %d", got, wantReports)
	}
}

// Keeping the result is best effort. When it cannot be kept the run is refused
// all the same, with the refusal's own error, and the operator is told the
// result is gone.
func TestARefusedResultThatCannotBeKeptDoesNotChangeTheRefusal(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	// A file where the directory must be.
	if err := os.WriteFile(filepath.Join(opts.OutputDir, attest.RefusedDirName), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := workerReportFor(t, opts)
	report.PlanName = "Another plan"
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || result != nil || !strings.Contains(err.Error(), "the node worker's report contradicts what was requested") {
		t.Fatalf("err = %v, result = %+v; want the refusal", err, result)
	}
	if !strings.Contains(progress.String(), "The worker's raw result could not be kept") || !strings.Contains(progress.String(), "not a directory") {
		t.Errorf("progress does not say the result was not kept:\n%s", progress.String())
	}
	if fake.workspaceRemoveCalls != 1 {
		t.Errorf("workspace removals = %d, want the usual 1", fake.workspaceRemoveCalls)
	}
}

// consumer is how one reader of a report directory finds its reports: each of
// them is a read-only copy of the discovery code of a reader that exists, named
// by file and function, because Community cannot import the others. A reader
// that finds the kept result would take unsigned worker bytes for evidence.
type consumer struct {
	name string
	// finds is the paths under root the reader considers a report.
	finds func(t *testing.T, root string) []string
}

func walkFiles(t *testing.T, root string, take func(path string, d fs.DirEntry) bool) []string {
	t.Helper()
	var found []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && take(path, d) {
			found = append(found, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(found)
	return found
}

var reportConsumers = []consumer{
	{"maintainer tooling that reads reports/*/*.json", func(t *testing.T, root string) []string {
		found, err := filepath.Glob(filepath.Join(root, "*", "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		return found
	}},
	{"every *.json at any depth (find -name '*.json')", func(t *testing.T, root string) []string {
		return walkFiles(t, root, func(path string, _ fs.DirEntry) bool {
			ok, _ := filepath.Match("*.json", filepath.Base(path))
			return ok
		})
	}},
	{"a downstream importer's find(): EqualFold(Ext, \".json\")", func(t *testing.T, root string) []string {
		return walkFiles(t, root, func(path string, d fs.DirEntry) bool {
			return strings.EqualFold(filepath.Ext(path), ".json") && d.Type().IsRegular()
		})
	}},
	{"a downstream pusher: HasSuffix(path, \".json\")", func(t *testing.T, root string) []string {
		return walkFiles(t, root, func(path string, _ fs.DirEntry) bool { return strings.HasSuffix(path, ".json") })
	}},
	{"a downstream scanner: filepath.Ext(path) == \".json\"", func(t *testing.T, root string) []string {
		return walkFiles(t, root, func(path string, _ fs.DirEntry) bool { return filepath.Ext(path) == ".json" })
	}},
	{"a downstream meter: HasSuffix(d.Name(), \".json\")", func(t *testing.T, root string) []string {
		return walkFiles(t, root, func(_ string, d fs.DirEntry) bool { return strings.HasSuffix(d.Name(), ".json") })
	}},
	{"enterprise internal/hub/store.go: HasSuffix(path, \".json\") and not \".receipt.json\"", func(t *testing.T, root string) []string {
		return walkFiles(t, root, func(path string, _ fs.DirEntry) bool {
			return strings.HasSuffix(path, ".json") && !strings.HasSuffix(path, ".receipt.json")
		})
	}},
}

// The point of the whole change: a report directory that holds a real signed
// report and a kept refused result, as one controller leaves it after two runs,
// is read by every discovery of reports as holding the one report; the verifier
// accepts the report and refuses the kept result even when it is handed the
// file by name; and the kept result is not in the directory root or beside a
// plan's reports.
func TestAKeptRefusalIsIgnoredByEveryReportDiscovery(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	// A run that passes, signs and saves its report.
	good := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
	passed, err := (&Executor{runner: good}).Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	// A run whose report is refused, into the same report directory.
	report := workerReportFor(t, opts)
	report.NodeFQDN = "unrelated-node"
	bad := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
	if _, err := (&Executor{runner: bad}).Run(context.Background(), opts); err == nil {
		t.Fatal("the contradicting report was accepted")
	}
	kept := requireRefusalKept(t, opts.OutputDir, bad.runID, `the report names node "unrelated-node"`)

	// The layout: the plan's reports in <out>/<plan_id>/, the kept result in
	// <out>/refused/, and nothing else; nothing of the refusal in the root.
	var root []string
	rootEntries, err := os.ReadDir(opts.OutputDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range rootEntries {
		root = append(root, entry.Name())
		if !entry.IsDir() {
			t.Errorf("%s is a file in the report directory's root", entry.Name())
		}
	}
	sort.Strings(root)
	if want := []string{attest.RefusedDirName, filepath.Base(filepath.Dir(passed.ReportPath))}; !equalSorted(root, want) {
		t.Errorf("report directory holds %v, want %v", root, want)
	}
	if filepath.Dir(kept.path) == filepath.Dir(passed.ReportPath) {
		t.Errorf("the kept result %s is beside the plan's reports", kept.path)
	}

	// Every discovery finds the one report, and not the kept result.
	for _, c := range reportConsumers {
		found := c.finds(t, opts.OutputDir)
		if len(found) != 1 || found[0] != passed.ReportPath {
			t.Errorf("%s finds %v, want only %s", c.name, found, passed.ReportPath)
		}
	}

	// The verifier accepts what was discovered, and refuses the kept result
	// handed to it by name, as every verifying function does.
	trusted := []ed25519.PublicKey{opts.Signer.(*attesttest.Signer).Public()}
	reportBytes, err := os.ReadFile(passed.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid, err := attest.VerifyReport(reportBytes, trusted); err != nil || !valid {
		t.Fatalf("the control report does not verify: valid=%v err=%v", valid, err)
	}
	keptBytes, err := os.ReadFile(kept.path)
	if err != nil {
		t.Fatal(err)
	}
	if json.Valid(keptBytes) {
		t.Error("the kept result is valid JSON")
	}
	if _, valid, err := attest.VerifyReport(keptBytes, trusted); err == nil || valid {
		t.Errorf("VerifyReport accepted the kept result: valid=%v err=%v", valid, err)
	}
	if _, valid, err := attest.VerifyReportSignatureOnly(keptBytes); err == nil || valid {
		t.Errorf("VerifyReportSignatureOnly accepted the kept result: valid=%v err=%v", valid, err)
	}
	if _, err := attest.ReadRegularFile(kept.path, "report", attest.MaxReportFileBytes); err != nil {
		t.Fatalf("the kept result is not even readable as a file: %v", err)
	}
}

func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

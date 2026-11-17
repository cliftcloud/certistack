// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/internal/recovery"
	"github.com/cliftcloud/certistack/internal/sysutil"
	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/runner"
	"github.com/spf13/cobra"
)

// acquireHostLock is the node's host-wide lock; a variable so that a test can
// run the worker's command without the node's /run.
var acquireHostLock = journal.Lock

// nodeRunCmd is the intentionally hidden half of the controller/worker split.
// A controller uploads the same controller binary into a single protected node
// workspace, calls this command over SSH, and receives exactly one JSON result
// on stdout. It is not a supported human-facing installation command.
func nodeRunCmd() *cobra.Command {
	var (
		planPath       string
		nodeName       string
		scratchDir     string
		overlayStorage string
		outputDir      string
		stateDir       string
		envFile        string
		runID          string
		sshClient      string
		skipIntegrity  bool
	)

	cmd := &cobra.Command{
		Use:    "node-run",
		Short:  "Execute one temporary node-worker validation",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// First, before the environment, the lock, the journal or the
			// directories: a worker on the wrong node must change nothing.
			if err := requireNodeName("node-run", nodeName); err != nil {
				return err
			}
			if err := verifyNodeIdentity(nodeName); err != nil {
				return err
			}
			if err := recordSSHClient(sshClient); err != nil {
				return err
			}
			restoreEnvironment, err := useCommandEnvironment(envFile, true)
			if err != nil {
				return err
			}
			defer restoreEnvironment()
			if skipIntegrity && !testModeOptedIn() {
				return fmt.Errorf("--skip-integrity is test-only; set CERTISTACK_ALLOW_TEST_MODE=1 for an explicit lab opt-in")
			}
			if err := ensureWorkerDirectories(stateDir, scratchDir); err != nil {
				return writeNodeResult(cmd, nodeapi.RunResult{Error: fmt.Sprintf("prepare node worker directories: %v", err)})
			}
			// A second worker must never observe the first worker's active journal
			// as an interrupted run. Keep one host lock from recovery through
			// preflight and validation, rather than acquiring it only inside the
			// runner after recovery has already inspected the journal.
			hostLock, err := acquireHostLock()
			if err != nil {
				return writeNodeResult(cmd, nodeapi.RunResult{Error: fmt.Sprintf("acquire node worker host lock: %v", err)})
			}
			defer hostLock.Close()
			if err := recovery.RecoverLocked(stateDir); err != nil {
				return writeNodeResult(cmd, nodeapi.RunResult{Error: fmt.Sprintf("recover previous node worker: %v", err)})
			}
			// The journal is clean and no other worker runs: a workspace an
			// earlier controller retained for recovery no longer needs its
			// credentials. This never fails the run.
			if scrubbed, err := scrubRetainedWorkspaces(filepath.Join(stateDir, "workers"), filepath.Dir(envFile), runID, time.Now()); err != nil {
				slog.Warn("could not remove all retained workspace credentials", "error", err)
			} else if len(scrubbed) > 0 {
				progress.Info("Cleanup", "Removed the credentials from %d retained worker workspace(s); their logs are kept.", len(scrubbed))
			}
			plan, err := config.LoadFromFileForWorker(planPath)
			if err != nil {
				return writeNodeResult(cmd, nodeapi.RunResult{Error: fmt.Sprintf("load node worker plan: %v", err)})
			}
			// The runner writes what it resolves into the plan it is given
			// (the pinned snapshots, the hardware and layout of each backup),
			// and it can stop at any VM. A failure before the orchestrator
			// has a report is evidence of the plan the controller sent, not
			// of whatever the runner had written into it by then: the
			// controller holds a report to that plan's digest and reserved
			// memory and refuses one that differs.
			sentPlan, err := config.CopyWorkerPlan(plan)
			if err != nil {
				return writeNodeResult(cmd, nodeapi.RunResult{Error: fmt.Sprintf("copy node worker plan: %v", err)})
			}
			preflightResult := runPreflight(cmd.Context(), plan, preflight.Options{
				ScratchDir:             scratchDir,
				StateDir:               stateDir,
				PVEURL:                 os.Getenv("PVE_URL"),
				PVETLSInsecure:         envBool("PVE_TLS_INSECURE"),
				PVETLSCAFile:           os.Getenv("CERTISTACK_PVE_CA_SOURCE"),
				PVETokenID:             os.Getenv("PVE_TOKEN_ID"),
				PVETokenSecret:         os.Getenv("PVE_TOKEN_SECRET"),
				RequirePVEConnectivity: true,
				WorkerMode:             true,
				PBSKeyfile:             os.Getenv("CERTISTACK_PBS_KEYFILE"),
				PBSEncryptionPassword:  os.Getenv("PBS_ENCRYPTION_PASSWORD"),
				NodeName:               nodeName,
				OverlayStorage:         overlayStorage,
			})
			if !preflightResult.Ready {
				return writeNodeResult(cmd, refusedRunResult(stateDir, runID, preflightRefusedResult(cmd.Context(), sentPlan, nodeName, preflightResult, skipIntegrity)))
			}
			// A passing check can still raise warnings (the token lacks a
			// privilege the run works around, a stale loop device, an
			// unreadable version). The operator reads the run's progress, not
			// this worker's result, so say them here.
			announcePreflightWarnings(preflightResult)

			report, runErr := runner.RunLocked(cmd.Context(), plan, runner.Options{
				NodeName:       nodeName,
				ScratchDir:     scratchDir,
				OverlayStorage: overlayStorage,
				OutputDir:      outputDir,
				StateDir:       stateDir,
				SkipIntegrity:  skipIntegrity,
				RunID:          runID,
				Build: runner.BuildInfo{
					Version:   version,
					Commit:    commit,
					BuildDate: buildDate,
				},
				Writer: io.Discard,
			})

			result := nodeapi.RunResult{Report: report}
			if runErr != nil {
				result.Error = runner.SafeFailureReason(runErr)
				if result.Report == nil {
					// Snapshot resolution and backup-profile discovery happen
					// before the orchestrator can create a report, and before
					// the run's journal exists. The controller must still be
					// able to retain evidence that validation safely
					// stopped before sandbox resources were created.
					result = refusedRunResult(stateDir, runID, nodeapi.RunResult{
						Report: failedNodeReport(sentPlan, nodeName, result.Error, skipIntegrity),
						Error:  result.Error,
					})
				}
			}
			if err := writeNodeResult(cmd, result); err != nil {
				return err
			}
			// A completed negative validation is still a successful worker RPC;
			// the controller decides the user-visible exit status after saving its
			// evidence locally (signed, when a signer is set).
			return nil
		},
	}

	cmd.Flags().StringVar(&planPath, "plan", "", "protected node-local plan path")
	cmd.Flags().StringVar(&nodeName, "node", "", "PVE node name")
	cmd.Flags().StringVar(&scratchDir, "scratch", "/var/lib/certistack/scratch", "node-local COW scratch directory")
	cmd.Flags().StringVar(&overlayStorage, "overlay-storage", "", "PVE storage for COW overlays (default: plan storage.overlay_storage)")
	cmd.Flags().StringVar(&outputDir, "output", "/var/lib/certistack/reports", "temporary node report directory")
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/certistack", "node-local recovery journal directory")
	cmd.Flags().StringVar(&envFile, "env-file", "", "protected node-local controller environment file")
	cmd.Flags().StringVar(&runID, "run-id", "", "run ID for the recovery journal, chosen by the controller")
	addSSHClientFlag(cmd, &sshClient)
	cmd.Flags().BoolVar(&skipIntegrity, "skip-integrity", false, "TEST ONLY: skip full mapped-PBS image verification")
	_ = cmd.Flags().MarkHidden("skip-integrity")
	_ = cmd.MarkFlagRequired("plan")
	_ = cmd.MarkFlagRequired("node")
	_ = cmd.MarkFlagRequired("env-file")
	return cmd
}

// refusedRunResult finishes the result of run runID, refused before it
// allocated anything. The report names the run, as every report does, and
// the node's journal shows that the run left nothing behind: a clean journal
// that names it. The controller verifies every run's cleanup from the
// journal and accepts no more than a record of that run; without this one a
// refusal, which leaves no journal of its own, would have nothing to verify.
// The host lock is held, and the previous journal is clean.
func refusedRunResult(stateDir, runID string, result nodeapi.RunResult) nodeapi.RunResult {
	if result.Report != nil {
		result.Report.RunID = runID
	}
	if runID == "" {
		return result
	}
	if err := journal.RecordRefusedRun(stateDir, runID); err != nil {
		slog.Warn("could not record that the refused run left nothing behind; its controller cannot verify the refusal's cleanup", "run_id", runID, "error", err)
	}
	return result
}

// preflightInterruptedPrefix starts the failure reason of a worker that was
// stopped while it checked the host. It is not accept.PreflightFailurePrefix
// (which starts the reason of a node preflight refusal, and by which the
// acceptance rules recognize a capacity denial): nothing was refused, so
// verify-report must not read it as a capacity denial.
const preflightInterruptedPrefix = "node preflight interrupted: "

// preflightRefusedResult is the worker's result for a preflight that did not
// pass. A worker that was stopped while it checked the host has refused
// nothing: the checks it stopped failed because it was stopped, and a refusal
// in the evidence would blame the host for that. It leaves what a refusal
// leaves, nothing created and a clean journal that names the run, and says it
// was stopped.
func preflightRefusedResult(ctx context.Context, plan *config.Plan, nodeName string, preflightResult preflight.Result, skipIntegrity bool) nodeapi.RunResult {
	if ctx.Err() != nil {
		failure := preflightInterruptedPrefix + "the worker was stopped before it created anything on the node"
		return nodeapi.RunResult{Report: failedNodeReport(plan, nodeName, failure, skipIntegrity), Error: failure}
	}
	return preflightFailureResult(plan, nodeName, preflightResult, skipIntegrity)
}

// preflightFailureResult preserves a controller-side evidence path for
// a worker refusal that occurs after the plan has been parsed but before any
// PBS map, overlay, sandbox VM, or SDN mutation. Prior-run reconciliation has
// already completed under the same host lock, so the evidence can accurately
// prove that this refused invocation left no owned resource to tear down.
func preflightFailureResult(plan *config.Plan, nodeName string, preflightResult preflight.Result, skipIntegrity bool) nodeapi.RunResult {
	failure := accept.PreflightFailurePrefix + summarizePreflight(preflightResult)
	report := failedNodeReport(plan, nodeName, failure, skipIntegrity)
	if preflightResult.MemoryEvaluation != nil {
		report.Admission = report.Admission.WithEvaluation(*preflightResult.MemoryEvaluation)
	}
	return nodeapi.RunResult{Report: report, Error: failure}
}

// failedNodeReport produces evidence for a refusal that occurred after plan
// parsing but before an orchestrator result exists. It has no VM records
// because PBS mapping, overlays, sandbox VMs, and SDN mutation were not
// reached. The caller has already reconciled the prior durable journal under
// the same lock, so the terminal teardown evidence is a verified no-op rather
// than an unknown cleanup state.
func failedNodeReport(plan *config.Plan, nodeName, failure string, skipIntegrity bool) *attest.Report {
	report := attest.BuildReport(plan, nodeName, 0, false, nil, "")
	report.FailureReason = failure
	report.TeardownEvidence = &attest.TeardownEvidence{
		OrphanSweepClean: true,
		AllCleaned:       true,
		VerifiedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	if skipIntegrity {
		report.ValidationMode = attest.ValidationModeTestSkipIntegrity
	}
	return report
}

// ensureWorkerDirectories creates only the operator-selected node work paths.
// A controller worker must not assume a manual /var/lib bootstrap step, but it
// also refuses a relative, traversal, or filesystem-root target before running
// as root on PVE.
func ensureWorkerDirectories(stateDir, scratchDir string) error {
	for label, path := range map[string]string{
		"state directory":   stateDir,
		"scratch directory": scratchDir,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.Contains(path, "..") {
			return fmt.Errorf("%s must be a clean non-root absolute path", label)
		}
		if err := sysutil.EnsurePrivateDirectory(path); err != nil {
			return fmt.Errorf("prepare %s %s: %w", label, path, err)
		}
	}
	return nil
}

// announcePreflightWarnings sends the warnings a passing preflight raised to
// the operator through the run's progress channel, once each, in the order the
// checks ran. The version_support warning is left to the runner: it reads the
// versions again for the report and warns in the same words (pkg/runner
// versionRecord.warn), so saying it here too would print it twice. The same
// goes for the sandbox_network warning, that the node's routes could not be
// read: the run checks them again as it starts (runner.requireSandboxSafe) and
// refuses to start, in the same words.
func announcePreflightWarnings(result preflight.Result) {
	for _, check := range result.Checks {
		if check.Status != "warning" || check.Name == preflight.VersionCheckName || check.Name == preflight.SandboxNetworkCheckName {
			continue
		}
		progress.Warn("Preflight", "%s: %s", check.Name, check.Detail)
	}
}

func summarizePreflight(result preflight.Result) string {
	var failures []string
	for _, check := range result.Checks {
		if check.Status == "failed" {
			failures = append(failures, check.Name+": "+check.Detail)
		}
	}
	if len(failures) == 0 {
		return "preflight did not report a specific failed check"
	}
	return strings.Join(failures, "; ")
}

func envBool(name string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return value == "1" || value == "true"
}

func writeNodeResult(cmd *cobra.Command, result nodeapi.RunResult) error {
	if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
		return fmt.Errorf("write node worker result: %w", err)
	}
	return nil
}

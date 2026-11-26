// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package runner provides the reusable local recovery-validation execution path.
package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/diskslot"
	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/sdn"
)

// BuildInfo identifies the executable that ran a validation.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
}

// Options controls one local validation run. It intentionally contains no
// licensing, tenant, or service-side concerns so the Community and Enterprise
// editions can share the same recovery engine.
type Options struct {
	// Recovered is what recovery of an unfinished run deletes before a run;
	// PlanRun counts it as gone.
	Recovered  orchestrator.Recovered
	NodeName   string
	ScratchDir string
	// OverlayStorage is the PVE storage for COW overlays; empty falls back to
	// the plan's storage.overlay_storage, then to files in ScratchDir.
	OverlayStorage string
	OutputDir      string
	StateDir       string
	// Signer, when set, attests the finished report before it is saved (see
	// attest.Signer), exactly once. The Community Edition sets none and its
	// reports are written unsigned, as is every report of the transient PVE node
	// worker, which returns its evidence to a controller; the Enterprise Edition
	// supplies one.
	Signer attest.Signer
	// SkipIntegrity is an explicit test-only shortcut. Production invocations
	// leave it false and perform a full mapped-image checksum verification.
	SkipIntegrity bool
	ChaosTrigger  string
	// RunID names the run in its recovery journal and on its PVE
	// resources. A controller passes one derived from the worker's workspace,
	// so it can tell its own journal from a later run's; empty generates one.
	RunID  string
	Build  BuildInfo
	Writer io.Writer

	// CheckResolvedPlan, when set, judges the plan after the engine has prepared it: each VM's
	// snapshot is resolved and the backup's configuration and layout are applied, so a plan that
	// inherits its hardware now carries the backup's cores, sockets, CPU weight and memory. It is
	// called before any PVE or PBS resource is created and before the recovery journal is begun
	// (the private scratch directory and the host lock already exist, as they do when any
	// preparation step refuses). A non-nil error refuses the run or the preview with that error.
	// A caller that embeds the engine uses it to hold the plans it writes to limits that depend
	// on what the plan finally says.
	//
	// A zero in a hardware override means no value: the backup configuration had none (a backup
	// seldom records cpuunits) and the engine applies its own default when it creates the VM
	// (2 cores, 1 socket, CPU weight 50, 2048 MB). The check judges the plan, not those defaults.
	// It must not change the plan (the plan digests are taken before and after preparation from
	// the same value), and it takes no context: keep it quick, it runs while the host lock is
	// held. It applies where the plan is prepared in this process (Run and PlanRun); a controller
	// that hands the plan to a worker over SSH prepares it in the worker, which sets no check.
	// Nil judges nothing, which is every run of the certistack command.
	CheckResolvedPlan func(plan *config.Plan) error

	// versions receives the Proxmox versions prepareRun read (versions.go).
	// Run and PlanRun set it; a caller cannot.
	versions *versionRecord
}

// prepareRunFn and orchestrate are prepareRun and the orchestrator's Run; tests
// replace them to drive run itself, without a PVE node or a PBS repository, to
// the report it builds, signs and saves.
var (
	prepareRunFn = prepareRun
	orchestrate  = func(ctx context.Context, orch *orchestrator.Orchestrator) (*orchestrator.ExecutionResult, error) {
		return orch.Run(ctx)
	}
)

// readNodeNetworks reads this node's routes and addresses; a variable so that a
// test can give the checks a node without reading the machine it runs on.
var readNodeNetworks = preflight.ReadNodeNetworks

// defaultSandboxChecks are the checks of plan's sandbox range against this node:
// that it holds neither the PVE API nor the PBS server the run uses (the
// environment's, else the plan's), and that it overlaps none of the node's real
// networks. The plan's own VNet is left out where the node is expected to
// carry the range on it (preflight.OwnVNetInterface).
func defaultSandboxChecks(plan *config.Plan, opts Options) *orchestrator.SandboxChecks {
	if plan == nil {
		return nil
	}
	pveURL := envOr("PVE_URL", "https://127.0.0.1:8006")
	repository := envOr("PBS_REPOSITORY", plan.Storage.PBSRepository)
	ignore := preflight.OwnVNetInterface(plan.Network, opts.Recovered.SDNVNetIDs...)
	return &orchestrator.SandboxChecks{
		Range: func(ctx context.Context) error {
			return preflight.CheckSandboxRange(ctx, plan, pveURL, repository, nil)
		},
		Network: func(context.Context) (string, error) {
			return preflight.VerifySandboxNetwork(plan.Network, ignore, readNodeNetworks)
		},
	}
}

// sandboxChecksFor are the checks of the plan's sandbox range against this
// node (nil: none). A variable so that a test can give a run or a plan the
// checks it wants.
var sandboxChecksFor = defaultSandboxChecks

// requireSandboxSafe is the first thing a run does with a plan: it refuses a
// sandbox range that would take over part of the node's own network, before the
// journal, the scratch directory, the SDN lock or any allocation exist. A run
// that could not compare the range with the node's networks (the routes cannot
// be read, or only part of them) does not go ahead either: it fails closed,
// naming the cause and how to retry. `plan`, `check` and `doctor` change
// nothing, so for them the same condition is a visible warning.
func requireSandboxSafe(ctx context.Context, plan *config.Plan, opts Options) error {
	checks := sandboxChecksFor(plan, opts)
	if checks == nil {
		return nil
	}
	if checks.Range != nil {
		if err := checks.Range(ctx); err != nil {
			return err
		}
	}
	if checks.Network != nil {
		warning, err := checks.Network(ctx)
		if err != nil {
			return err
		}
		if warning != "" {
			return fmt.Errorf("the run was not started: %s A run does not go ahead on a sandbox range that could not be compared with the node's networks (the unreadable table could be hiding the one that overlaps): once you have listed them as above, fix whatever keeps the worker from reading the node's routes (it needs root and a /proc that shows net/route; a container with a restricted /proc hides it), then run again", warning)
		}
	}
	return nil
}

// runIDExpr bounds a caller-chosen run ID: it is written into PVE tags and
// descriptions and compared by the controller.
var runIDExpr = regexp.MustCompile(`^run-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// LoadAndRun loads a plan from path and executes it with opts.
func LoadAndRun(ctx context.Context, path string, opts Options) (*attest.Report, error) {
	if path == "" {
		return nil, errors.New("plan path is required")
	}
	plan, err := config.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("load plan: %w", err)
	}
	return Run(ctx, plan, opts)
}

// RunLocked executes a plan while the caller holds the host execution lock
// returned by journal.Lock. It is for the temporary node worker, which must
// hold the same lock while it reconciles a previous interrupted run, performs
// preflight, and starts this validation. Callers that do not already own that
// lock must use Run.
func RunLocked(ctx context.Context, plan *config.Plan, opts Options) (*attest.Report, error) {
	return run(ctx, plan, opts)
}

// Run executes a validated plan, writes report artifacts, and returns the
// JSON report: signed when opts.Signer is set, unsigned otherwise. An
// orchestration error is returned only after report and journal handling have
// completed.
func Run(ctx context.Context, plan *config.Plan, opts Options) (*attest.Report, error) {
	hostLock, err := journal.Lock()
	if err != nil {
		return nil, fmt.Errorf("acquire host execution lock: %w", err)
	}
	defer hostLock.Close()

	return RunLocked(ctx, plan, opts)
}

// run contains the validation logic after the caller has obtained exclusive
// access to the host. Keeping it separate from Run makes the worker's
// crash-recovery-to-run transition atomic with respect to other workers.
func run(ctx context.Context, plan *config.Plan, opts Options) (*attest.Report, error) {
	if plan == nil {
		return nil, errors.New("plan is required")
	}
	if opts.RunID != "" && !runIDExpr.MatchString(opts.RunID) {
		return nil, fmt.Errorf("invalid run ID %q", opts.RunID)
	}
	if opts.SkipIntegrity && os.Getenv("CERTISTACK_ALLOW_TEST_MODE") != "1" {
		return nil, errors.New("SkipIntegrity requires CERTISTACK_ALLOW_TEST_MODE=1")
	}
	if err := requirePlanBounds(plan); err != nil {
		return nil, err
	}
	validatedPlanDigest, err := config.CanonicalWorkerPlanSHA256(plan)
	if err != nil {
		return nil, fmt.Errorf("digest validated worker plan: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	opts = normalizeOptions(plan, opts)
	// The node name goes into PVE's API paths and a simple zone's node list:
	// a bad one is refused before anything is touched.
	if err := pve.ValidateNodeName(opts.NodeName); err != nil {
		return nil, fmt.Errorf("invalid node: %w", err)
	}
	// A sandbox range that holds the PVE API or the PBS server, or overlaps a
	// real network of this node, is refused before anything exists: the
	// directories, the journal, the SDN lock and every allocation come after.
	if err := requireSandboxSafe(ctx, plan, opts); err != nil {
		return nil, err
	}
	if err := sysutil.EnsurePrivateDirectory(opts.ScratchDir); err != nil {
		return nil, fmt.Errorf("prepare scratch directory: %w", err)
	}
	activeJournalPath := filepath.Join(opts.StateDir, "active.json")
	// Run holds the host lock, so this check and the new journal initialization
	// are one decision. Never overwrite an interrupted, failed, or malformed
	// journal: it is the sole durable record of resources that recovery must
	// reconcile. A clean terminal record is deliberately reusable.
	if err := requireCleanJournal(activeJournalPath); err != nil {
		return nil, err
	}
	versions := &versionRecord{}
	opts.versions = versions
	pveClient, pbsClient, err := prepareRunFn(ctx, plan, opts, opts.ScratchDir)
	if err != nil {
		return nil, versions.withVersions(err)
	}
	if err := checkResolvedPlan(plan, opts); err != nil {
		return nil, versions.withVersions(err)
	}
	// An untested pair goes on, with one warning here and the versions in the
	// report; an unsupported one was refused by prepareRun.
	versions.warn()

	runID := opts.RunID
	if runID == "" {
		runID = fmt.Sprintf("run-%d", time.Now().UnixNano())
	}
	runRecord := journal.Record{
		RunID:     runID,
		Phase:     "running",
		UpdatedAt: time.Now().UTC(),
		Scratch:   opts.ScratchDir,
	}
	// Begin keeps the transition of the clean journal it replaces, so the
	// earlier run's controller can still verify that run's cleanup.
	if err := journal.Begin(opts.StateDir, runRecord); err != nil {
		return nil, fmt.Errorf("initialize recovery journal: %w", err)
	}

	orch := orchestrator.New(plan, orchestrator.Options{
		NodeName:       opts.NodeName,
		ScratchDir:     opts.ScratchDir,
		OverlayStorage: opts.OverlayStorage,
		StateDir:       opts.StateDir,
		SkipIntegrity:  opts.SkipIntegrity,
		ChaosTrigger:   opts.ChaosTrigger,
		RunID:          runID,
	}, pbsClient, pveClient)
	result, runErr := orchestrate(ctx, orch)
	// A temporary node worker returns its raw teardown evidence to the
	// controller, which has the protected workspace and authority to reconcile
	// the durable journal before deciding the run's final result.
	// A direct local run has no such second authority, so it must fail closed
	// immediately when teardown cannot be proven.
	runErr = requireVerifiedTeardown(result, runErr)

	report := attest.BuildReport(plan, opts.NodeName, result.RTO, result.AllPassed, result.VMRecords, result.FailureArtifact)
	report.ValidatedPlanSHA256 = validatedPlanDigest
	report.RunID = runID
	report.PBSFingerprint, report.PBSNamespace = effectiveReportPBSIdentity(plan)
	versions.stamp(report)
	if result.Error != nil {
		report.FailureReason = SafeFailureReason(result.Error)
	} else if runErr != nil {
		report.FailureReason = SafeFailureReason(runErr)
	}
	if rtoErr := enforceRTOTarget(report, plan); rtoErr != nil && runErr == nil {
		// A missed objective is a failed validation, not a warning: every
		// caller (CLI exit status, node worker result, daemon) decides
		// pass/fail from the returned error.
		runErr = rtoErr
	}
	if opts.SkipIntegrity {
		report.ValidationMode = attest.ValidationModeTestSkipIntegrity
	}
	report.EngineVersion = opts.Build.Version
	report.GitCommit = opts.Build.Commit
	report.BuildDate = opts.Build.BuildDate
	report.PhaseTimings = result.PhaseTimings
	report.TeardownEvidence = result.TeardownEvidence
	if result.Admission != nil {
		report.Admission = result.Admission
	}

	// The orchestrator writes resource identities as it allocates them. Its
	// terminal journal state is equally important: without it, a subsequent run
	// cannot distinguish a clean completion from an interrupted cleanup. Finalize
	// before the signer runs, so an evidence-persistence failure is part of the
	// report (and of its signature, when there is one) rather than an optimistic
	// report followed by a warning.
	if err := finalizeJournal(activeJournalPath, runRecord, result); err != nil {
		runErr = recordDurabilityFailure(report, runErr, "finalize recovery journal", err)
	}

	// The Community Edition has no signer and writes the report as it is. A
	// signer is asked once, here; one that fails fails the run, and no unsigned
	// report is written in its place.
	if err := attest.ApplySigner(report, opts.Signer); err != nil {
		// The run happened and its resources are gone: the report it had, with
		// every signature member cleared, and the error it had, come back with
		// the signer's, as they do when a report cannot be saved. Nothing is
		// written, and the error says the report is not evidence.
		runErr = errors.Join(runErr, fmt.Errorf("sign report: %w", err))
		fmt.Fprintf(opts.Writer, "✗ RESTORE TEST FAILED: %v\n", runErr)
		return report, runErr
	}

	reportPath := attest.DefaultReportPath(opts.OutputDir, plan.PlanID, report.ReportID)
	if err := report.Save(reportPath); err != nil {
		runErr = recordSaveFailure(report, runErr, err)
		// The in-memory report is not durable evidence: a run whose report
		// was not saved is never reported as a success.
		fmt.Fprintf(opts.Writer, "✗ RESTORE TEST FAILED: %v\n", runErr)
		return report, runErr
	} else {
		writeArtifacts(opts.Writer, reportPath)
	}

	if runErr != nil {
		fmt.Fprintf(opts.Writer, "✗ RESTORE TEST FAILED: %v\n", runErr)
		return report, runErr
	}
	fmt.Fprintln(opts.Writer, "✓ RESTORE TEST SUCCEEDED")
	fmt.Fprintf(opts.Writer, "  Plan:       %s\n", plan.Name)
	fmt.Fprintf(opts.Writer, "  Report ID:  %s\n", report.ReportID)
	fmt.Fprintf(opts.Writer, "  RTO:        %.2f seconds\n", report.RTOSeconds)
	fmt.Fprintf(opts.Writer, "  Frameworks: %v\n", report.Frameworks)
	return report, nil
}

// requirePlanBounds applies the plan validation of admission limits, the RTO
// target, durations, guest commands and compliance metadata to a plan handed
// to a run directly, which may not have been loaded through the validating
// loader: a NaN limit would admit any load, an overflowing duration would skip
// its wait, a guest-agent probe's command reaches a shell in the recovered
// guest (under either spelling of the probe type), and the report records the
// frameworks and retention it is given.
func requirePlanBounds(plan *config.Plan) error {
	errs := append(config.NumericBoundsErrors(plan), config.ProbeCommandErrors(plan)...)
	errs = append(errs, config.ComplianceErrors(plan)...)
	if len(errs) > 0 {
		return fmt.Errorf("invalid plan: %w", config.ValidationErrors(errs))
	}
	return nil
}

// requireCleanJournal makes an existing recovery record an explicit admission
// gate for a new run. It is intentionally independent of recovery itself:
// callers that have the authority and credentials to reconcile can invoke
// recover first, but no caller can destroy that evidence by starting over.
func requireCleanJournal(path string) error {
	record, err := journal.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("refusing to start while the active recovery journal cannot be read: %w", err)
	}
	if record.Phase != "cleaned" {
		return fmt.Errorf("refusing to start while recovery journal for run %q is phase %q; run "+recoverhint.Worker+" and resolve its recorded resources first ("+recoverhint.Guide+")", record.RunID, record.Phase)
	}
	return nil
}

// recordDurabilityFailure changes an otherwise optimistic report into a
// failed validation. It is intentionally shared by journal and report-store
// failures: neither condition leaves behind evidence that can support a clean
// recovery or compliance assertion.
func recordDurabilityFailure(report *attest.Report, runErr error, operation string, cause error) error {
	failure := fmt.Errorf("%s: %w", operation, cause)
	if runErr != nil {
		failure = errors.Join(runErr, failure)
	}
	if report != nil {
		report.AllPassed = false
		report.FailureReason = SafeFailureReason(failure)
	}
	return failure
}

// recordSaveFailure records that the report could not be saved, as
// recordDurabilityFailure does. That changes fields a signature covers, so a
// report the signer had signed no longer matches its signature. The signer is
// not asked again (it is called once per run, and a second call would be a second
// attestation of a run it already attested): the report returned with the error
// carries no signature members at all, rather than a signature over the earlier,
// passing content. It was never written, and is not evidence.
func recordSaveFailure(report *attest.Report, runErr, cause error) error {
	failure := recordDurabilityFailure(report, runErr, "save report", cause)
	if report != nil {
		report.Signature, report.PublicKey, report.SignerFingerprint, report.SignatureTimestamp = "", "", "", nil
	}
	return failure
}

// requireVerifiedTeardown gives local and controller-driven executions the
// same fail-closed contract. The controller can reconcile a worker's durable
// journal after it receives the report, but a direct local run has no later
// controller layer to correct an optimistic success result. Never print a
// successful validation while its owned temporary resources remain unproven.
func requireVerifiedTeardown(result *orchestrator.ExecutionResult, runErr error) error {
	if runErr != nil || result == nil || result.TeardownEvidence == nil || result.TeardownEvidence.AllCleaned {
		if runErr == nil && result != nil && result.Error != nil {
			return result.Error
		}
		return runErr
	}
	cleanupErr := errors.New("temporary CertiStack resource cleanup could not be verified; recovery journal retained")
	result.AllPassed = false
	result.Error = cleanupErr
	return cleanupErr
}

// pbsClientFor builds the PBS client a run of plan uses, after checking
// the key file and the plan's PBS routing. An encrypted backup needs its key
// on every PBS call. The key is a node-local file (PVE keeps a PBS storage's
// key in /etc/pve/priv/storage/<storage>.enc); the controller stages its own
// copy into the run's private workspace.
func pbsClientFor(plan *config.Plan) (*pbs.Client, error) {
	namespace := envOr("PBS_NAMESPACE", plan.Storage.PBSNamespace)
	if err := validatePBSRouting(plan, namespace); err != nil {
		return nil, err
	}
	return newPBSClient(plan.Storage, namespace)
}

// newPBSClient is a run's PBS client for namespace, with the endpoint and
// credentials from the environment, else storage.
func newPBSClient(storage config.Storage, namespace string) (*pbs.Client, error) {
	keyfile := os.Getenv("CERTISTACK_PBS_KEYFILE")
	if keyfile != "" {
		if err := pbs.ValidateKeyfile(keyfile); err != nil {
			return nil, err
		}
		if err := pbs.CheckKeyPassphrase(keyfile, os.Getenv("PBS_ENCRYPTION_PASSWORD")); err != nil {
			return nil, err
		}
	}
	return pbs.New(pbs.Config{
		Repository:         envOr("PBS_REPOSITORY", storage.PBSRepository),
		Password:           os.Getenv("PBS_PASSWORD"),
		Fingerprint:        envOr("PBS_FINGERPRINT", storage.PBSFingerprint),
		Namespace:          namespace,
		Keyfile:            keyfile,
		EncryptionPassword: os.Getenv("PBS_ENCRYPTION_PASSWORD"),
	}), nil
}

// validatePBSRouting rejects per-VM selectors that the configured single PBS
// endpoint cannot honor. StorageID is a PVE storage label, not a PBS endpoint;
// silently accepting a second label or namespace would restore the wrong data.
func validatePBSRouting(plan *config.Plan, namespace string) error {
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			if id := strings.TrimSpace(vm.SourcePBS.StorageID); id != "" && id != "pbs" {
				return fmt.Errorf("VM %d requests source_pbs.storage_id %q, but this run has one configured PBS endpoint; use storage_id pbs", vm.VMID, id)
			}
			if vmNamespace := strings.TrimSpace(vm.SourcePBS.Namespace); vmNamespace != "" && vmNamespace != namespace {
				return fmt.Errorf("VM %d requests PBS namespace %q, but this run is configured for namespace %q", vm.VMID, vmNamespace, namespace)
			}
		}
	}
	return nil
}

// SafeFailureReason keeps a failure report actionable without allowing
// process errors or a misbehaving dependency to leak credentials into an
// operator-facing artifact. It also prevents a pathological error from making
// a report unexpectedly large. Controller and node-worker boundaries must use
// the same sanitization before returning a failure to an operator.
func SafeFailureReason(err error) string {
	if err == nil {
		return ""
	}
	reason := strings.TrimSpace(err.Error())
	// Treat connection identities and private credential paths as sensitive too:
	// reports frequently outlive a credential rotation and are shared more
	// broadly than controller configuration. Keeping a failure actionable never
	// requires embedding any configured endpoint or key location.
	for _, key := range []string{
		"PVE_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET", "CERTISTACK_PVE_CA_SOURCE",
		"PBS_REPOSITORY", "PBS_PASSWORD", "PBS_PASSWORD_FILE", "PBS_FINGERPRINT",
		"PBS_ENCRYPTION_PASSWORD", "PBS_ENCRYPTION_PASSWORD_FILE", "CERTISTACK_PBS_KEYFILE",
		"CERTISTACK_SSH_IDENTITY", "CERTISTACK_SSH_KNOWN_HOSTS",
	} {
		if value := os.Getenv(key); value != "" {
			reason = strings.ReplaceAll(reason, value, "[REDACTED]")
		}
	}
	if configuredPVEURL := strings.TrimSpace(os.Getenv("PVE_URL")); configuredPVEURL != "" {
		if parsed, parseErr := url.Parse(configuredPVEURL); parseErr == nil {
			for _, identity := range []string{parsed.Host, parsed.Hostname()} {
				if identity == "" {
					continue
				}
				reason = regexp.MustCompile("(?i)"+regexp.QuoteMeta(identity)).ReplaceAllString(reason, "[REDACTED_HOST]")
			}
		}
	}
	// A failure reason is one line: guest output reaches it through probe and
	// boot errors, and a line break in it would forge a line in every log and
	// terminal that shows the reason, and in the report. Joined errors
	// read as "first; second".
	reason = progress.SingleLine(reason)
	const maximum = 4096
	if len(reason) > maximum {
		const suffix = " [truncated]"
		reason = reason[:maximum-len(suffix)] + suffix
	}
	return reason
}

func finalizeJournal(path string, fallback journal.Record, result *orchestrator.ExecutionResult) error {
	record, err := journal.Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Recreating a missing journal from the initial record would silently
			// discard identities recorded by the orchestrator. Leave the run failed
			// and require operator investigation instead of writing a misleading
			// resource-free cleanup record.
			return fmt.Errorf("active recovery journal disappeared during execution; refusing to finalize from resource-free fallback for run %q", fallback.RunID)
		}
		return fmt.Errorf("load active journal: %w", err)
	}

	// A nil teardown record is safe only when the durable journal contains no
	// tracked resources. Otherwise fail closed and leave it for Recover.
	clean := !journalHasResources(record)
	if result != nil && result.TeardownEvidence != nil {
		clean = result.TeardownEvidence.AllCleaned
	}
	record.UpdatedAt = time.Now().UTC()
	if clean {
		record.Phase = "cleaned"
		record.CleanupErrors = nil
	} else {
		record.Phase = "cleanup_failed"
		if result != nil && result.TeardownEvidence != nil {
			for _, cleanupErr := range result.TeardownEvidence.CleanupErrors {
				record.CleanupErrors = append(record.CleanupErrors, cleanupErr)
			}
		}
	}
	return journal.Write(path, record)
}

func journalHasResources(record journal.Record) bool {
	return record.QEMU.PID > 0 || record.Mapper.PID > 0 || record.LoopDevice != "" ||
		len(record.Loops) > 0 || len(record.VMs) > 0 || len(record.SDNZones) > 0 ||
		len(record.SDNVNets) > 0 || len(record.HostAddresses) > 0 || len(record.DeltaFiles) > 0 ||
		record.SDNLockToken != "" || record.SDNLockRequested != "" || record.SDNApplyUnknown != ""
}

// enforceRTOTarget makes compliance.rto_target_seconds a real pass/fail
// criterion, not just documentation: a run that boots and probes cleanly but
// blows through the operator's own recovery time objective must not be
// reported as a pass.
func enforceRTOTarget(report *attest.Report, plan *config.Plan) error {
	target := plan.Compliance.RTOTargetSeconds
	finite := !math.IsNaN(target) && !math.IsInf(target, 0)
	if finite && (target <= 0 || report.RTOSeconds <= target) {
		return nil
	}
	report.AllPassed = false
	rtoNote := fmt.Sprintf("recovery time objective exceeded: completed in %.1fs, target was %.1fs", report.RTOSeconds, target)
	if !finite {
		// Validation refuses it; a plan handed over unvalidated cannot turn
		// the objective into one no run meets, or one every run meets.
		rtoNote = fmt.Sprintf("recovery time objective not evaluated: compliance.rto_target_seconds is %v, not a finite number", target)
	}
	if report.FailureReason == "" {
		report.FailureReason = rtoNote
	} else {
		report.FailureReason = report.FailureReason + "; " + rtoNote
	}
	return errors.New(rtoNote)
}

func normalizeOptions(plan *config.Plan, opts Options) Options {
	if opts.NodeName == "" {
		opts.NodeName = "localhost"
	}
	if opts.ScratchDir == "" {
		// An explicit --scratch (or an Options.ScratchDir the caller set
		// directly) always wins over the plan; storage.scratch_dir is a
		// fallback for a plan author who wants a dedicated scratch location
		// without every invocation needing a matching flag. It goes through
		// exactly the same EnsurePrivateDirectory check below as any other
		// source of this value, so a plan cannot use it to point scratch
		// storage at /tmp or another shared/unsafe directory.
		opts.ScratchDir = config.EffectiveScratchDir("", plan, sysutil.DefaultScratchDir)
	}
	if opts.OverlayStorage == "" && plan != nil {
		opts.OverlayStorage = strings.TrimSpace(plan.Storage.OverlayStorage)
	}
	if opts.OutputDir == "" {
		opts.OutputDir = "/var/lib/certistack/reports"
	}
	if opts.StateDir == "" {
		opts.StateDir = "/var/lib/certistack"
	}
	if opts.Writer == nil {
		opts.Writer = io.Discard
	}
	return opts
}

type snapshotResolver interface {
	ResolveSnapshot(ctx context.Context, selector string, sourceVMID int) (string, error)
}

type backupProfileResolver interface {
	LoadVMProfile(ctx context.Context, snapshot, scratchDir string) (pbs.VMProfile, error)
	LoadVMLayout(ctx context.Context, snapshot, scratchDir string) (pbs.VMLayout, error)
}

// resolveLatestSnapshots pins every latest selector before orchestration starts.
// The plan is then carried through to report construction with immutable PBS
// snapshot paths, so an attestation identifies exactly what was tested.
//
// The report names the protected VM by source_vmid, so it is bound to the
// resolved snapshot: a snapshot of another VM's backup is refused, and a VM
// without source_vmid gets the ID of the VM whose backup it restores.
func resolveLatestSnapshots(ctx context.Context, plan *config.Plan, resolver snapshotResolver) error {
	for tierIndex := range plan.Tiers {
		for vmIndex := range plan.Tiers[tierIndex].VMs {
			vm := &plan.Tiers[tierIndex].VMs[vmIndex]
			resolved, err := resolver.ResolveSnapshot(ctx, vm.SourcePBS.Snapshot, vm.SourceVMID)
			if err != nil {
				return fmt.Errorf("resolve PBS snapshot for target VM %d (%s): %w", vm.VMID, vm.Name, err)
			}
			backedUp, ok := pbs.SnapshotVMID(resolved)
			switch {
			case !ok:
				return fmt.Errorf("resolve PBS snapshot for target VM %d (%s): %q is not a VM snapshot path", vm.VMID, vm.Name, resolved)
			case vm.SourceVMID > 0 && backedUp != vm.SourceVMID:
				return fmt.Errorf("target VM %d (%s) declares source_vmid %d, but its PBS snapshot %s is a backup of VM %d; both must name the protected VM", vm.VMID, vm.Name, vm.SourceVMID, resolved, backedUp)
			}
			vm.SourcePBS.Snapshot = resolved
			vm.SourceVMID = backedUp
		}
	}
	return nil
}

// applyBackupConfig discovers all backed-up disk images and inherits only the
// safe hardware subset stored with each source snapshot. It also preserves
// only net0's MAC so MAC-bound guest network profiles survive; sandbox
// topology, ownership tags, passthrough devices, hooks, and source PVE tags
// are never copied into the ephemeral VM.
func applyBackupConfig(ctx context.Context, plan *config.Plan, resolver backupProfileResolver, scratchDir string) error {
	for tierIndex := range plan.Tiers {
		for vmIndex := range plan.Tiers[tierIndex].VMs {
			vm := &plan.Tiers[tierIndex].VMs[vmIndex]
			profile, err := resolver.LoadVMProfile(ctx, vm.SourcePBS.Snapshot, scratchDir)
			if err != nil {
				return fmt.Errorf("load source backup configuration for target VM %d (%s): %w", vm.VMID, vm.Name, err)
			}
			discovered := make([]config.SourceDrive, 0, len(profile.Drives))
			for _, drive := range profile.Drives {
				discovered = append(discovered, config.SourceDrive{Slot: drive.Slot, Archive: drive.Archive})
			}
			configured := vm.SourcePBS.RestoreDrives()
			if len(configured) == 0 {
				vm.SourcePBS.Drives = discovered
			} else if !sameSourceDriveLayout(configured, discovered) {
				return fmt.Errorf("source disk layout for target VM %d (%s) does not match its PBS snapshot", vm.VMID, vm.Name)
			}

			memoryFrom := memoryFromPlan
			if vm.HardwareOverrides.MemoryMB == 0 {
				memoryFrom = memoryFromBackup
				if profile.MemoryMB == 0 {
					memoryFrom = memoryFromDefault
				}
			}
			if vm.HardwareOverrides.Cores == 0 {
				vm.HardwareOverrides.Cores = profile.Cores
			}
			if vm.HardwareOverrides.Sockets == 0 {
				vm.HardwareOverrides.Sockets = profile.Sockets
			}
			if vm.HardwareOverrides.MemoryMB == 0 {
				vm.HardwareOverrides.MemoryMB = profile.MemoryMB
			}
			if vm.HardwareOverrides.BalloonMB == 0 {
				vm.HardwareOverrides.BalloonMB = profile.BalloonMB
			}
			if vm.HardwareOverrides.CPUWeight == 0 {
				vm.HardwareOverrides.CPUWeight = profile.CPUWeight
			}
			if err := checkBalloonWithinMemory(vm, memoryFrom); err != nil {
				return err
			}
			if vm.Machine == "" {
				vm.Machine = profile.Machine
			}
			if vm.OSType == "" {
				vm.OSType = profile.OSType
			}
			if vm.BIOS == "" {
				vm.BIOS = profile.BIOS
			}
			if vm.SCSIHW == "" {
				vm.SCSIHW = profile.SCSIHW
			}
			if err := resolveNet0Identity(vm, profile.MAC, profile.NICModel); err != nil {
				return err
			}
			vm.SourceTags = append([]string(nil), profile.SourceTags...)
			if err := applySourceLayout(vm, layoutOf(profile)); err != nil {
				return err
			}
		}
	}
	// Every VM's address is known now: no two NICs of the plan may share one.
	return config.CheckNICIdentities(plan)
}

// applyBackupLayout reads each source VM's layout for plans that do not
// inherit the rest of the backup configuration, and applies it with
// applySourceLayout.
func applyBackupLayout(ctx context.Context, plan *config.Plan, resolver backupProfileResolver, scratchDir string) error {
	for tierIndex := range plan.Tiers {
		for vmIndex := range plan.Tiers[tierIndex].VMs {
			vm := &plan.Tiers[tierIndex].VMs[vmIndex]
			layout, err := resolver.LoadVMLayout(ctx, vm.SourcePBS.Snapshot, scratchDir)
			if err != nil {
				return fmt.Errorf("load source layout for target VM %d (%s): %w", vm.VMID, vm.Name, err)
			}
			memoryFrom := memoryFromPlan
			if vm.HardwareOverrides.MemoryMB == 0 {
				memoryFrom = memoryFromDefault
			}
			if err := checkBalloonWithinMemory(vm, memoryFrom); err != nil {
				return err
			}
			if err := applySourceLayout(vm, layout); err != nil {
				return err
			}
		}
	}
	// This is the last step of a plan that does not inherit the backup's
	// configuration, after net0's identity (applyBackupNetworkIdentity) and
	// each VM's other NICs: no two NICs of the plan may share an address.
	return config.CheckNICIdentities(plan)
}

// applySourceLayout carries what every restore needs from the backup into
// the sandbox VM, whatever the plan inherits:
//   - Firmware is part of what was backed up, not a tunable. A UEFI VM
//     restored under SeaBIOS, or without its variable store and TPM state,
//     is a different machine and fails for reasons that say nothing about
//     the backup. A plan may leave bios empty but may not contradict a UEFI
//     backup.
//   - Machine type, SCSI controller and guest OS type follow the backup
//     unless the plan sets them: a guest installed on q35 or an LSI
//     controller may not boot on PVE's defaults, whose drivers it may lack.
//     A source without a memory balloon device gets none either (unless the
//     plan sets balloon_mb): a new device is new hardware to the guest.
//   - The SMBIOS identity is the backup's, as qmrestore keeps it: a guest can
//     tell a new SMBIOS UUID from its own.
//   - The sandbox VM boots the first restored disk of the source boot order,
//     so a VM that boots from virtio0 or sata0 is restored as it runs, and its
//     boot order is the source's restricted to the restored disks, so a guest
//     that reads /boot from a second disk finds it (SeaBIOS shows the guest
//     only the disks in the order). CD-ROMs, net0 and omitted disks are not in
//     it: a restored VM never tries the network or a disk it does not have.
//   - A plan may restore only some of the backed-up disks, but never one the
//     backup does not have, and the disks it leaves out are recorded so the
//     report cannot pass a partial restore off as the whole VM.
func applySourceLayout(vm *config.VM, layout pbs.VMLayout) error {
	if err := requireSignedSource(vm, layout); err != nil {
		return err
	}
	vm.FirmwareDisks = nil
	for _, image := range layout.Firmware {
		vm.FirmwareDisks = append(vm.FirmwareDisks, config.FirmwareDisk{Slot: image.Slot, Archive: image.Archive, Options: image.Options})
	}
	if layout.BIOS == "ovmf" {
		switch vm.BIOS {
		case "":
			vm.BIOS = "ovmf"
		case "ovmf":
		default:
			return fmt.Errorf("target VM %d (%s) sets bios %q, but its backup is of a UEFI (ovmf) VM, which cannot boot under it", vm.VMID, vm.Name, vm.BIOS)
		}
	}

	backedUp := make(map[string]bool, len(layout.Disks))
	for _, slot := range layout.Disks {
		backedUp[slot] = true
	}
	var restored []string
	restoring := make(map[string]bool)
	for _, drive := range vm.SourcePBS.RestoreDrives() {
		if !backedUp[drive.Slot] {
			return fmt.Errorf("target VM %d (%s) restores %s, but the backup has no %s disk (its backed-up disks: %s)", vm.VMID, vm.Name, drive.Slot, drive.Slot, strings.Join(layout.Disks, ", "))
		}
		restored = append(restored, drive.Slot)
		restoring[drive.Slot] = true
	}
	vm.SourceDiskBytes, vm.SourceImageBytes = nil, nil
	for slot := range restoring {
		if n, ok := layout.DiskBytes[slot]; ok {
			if vm.SourceDiskBytes == nil {
				vm.SourceDiskBytes = map[string]int64{}
			}
			vm.SourceDiskBytes[slot] = n
		}
		if n, ok := layout.ImageBytes[slot]; ok {
			if vm.SourceImageBytes == nil {
				vm.SourceImageBytes = map[string]int64{}
			}
			vm.SourceImageBytes[slot] = n
		}
	}
	vm.OmittedDisks = nil
	for _, slot := range layout.Disks {
		if !restoring[slot] {
			vm.OmittedDisks = append(vm.OmittedDisks, slot)
		}
	}
	vm.BootDisk = diskslot.BootDisk(layout.BootOrder, restored)
	vm.BootOrder = diskslot.RestoredBootOrder(layout.BootOrder, restored)
	vm.SourceCryptMode = layout.CryptMode
	vm.SourceSignatureVerified = layout.SignatureVerified
	vm.ExcludedDisks = append([]string(nil), layout.ExcludedDisks...)
	if vm.Machine == "" {
		vm.Machine = layout.Machine
	}
	if vm.SCSIHW == "" {
		vm.SCSIHW = layout.SCSIHW
	}
	if vm.OSType == "" {
		vm.OSType = layout.OSType
	}
	vm.NoBalloon = layout.NoBalloon
	vm.SMBIOS1 = layout.SMBIOS1
	vm.SourceMeta = layout.Meta
	vm.SourceCDROMs = append([]string(nil), layout.CDROMs...)
	vm.SourceConsistency, vm.SourceConsistencyDetail = layout.Consistency.State, layout.Consistency.Detail
	vm.AdditionalNICs, vm.OmittedNICs = nil, nil
	for _, nic := range layout.NICs {
		if vm.NetworkRecovery.AttachAllNICs {
			if nic.Model == "" || nic.MAC == "" {
				return fmt.Errorf("target VM %d (%s) asks to attach all NICs, but its source %s has no usable model and MAC", vm.VMID, vm.Name, nic.Slot)
			}
			vm.AdditionalNICs = append(vm.AdditionalNICs, config.SourceNIC{Slot: nic.Slot, Model: nic.Model, MAC: nic.MAC})
		} else {
			vm.OmittedNICs = append(vm.OmittedNICs, nic.Slot)
		}
	}
	return nil
}

// requireSignedSource enforces a VM's require_signed_backup: unless the
// configured key verified the snapshot's manifest, the VM is refused before
// any sandbox resource exists. Without the requirement, a key is used only
// where the snapshot lists a signature, so a backup that lists none restores
// unsigned; PBS's own list is the server's word, and a plan that must not
// depend on it asks for a verified signature.
func requireSignedSource(vm *config.VM, layout pbs.VMLayout) error {
	if !vm.RequireSignedBackup || layout.SignatureVerified {
		return nil
	}
	return fmt.Errorf("target VM %d (%s) requires a signed backup (require_signed_backup), but PBS snapshot %s was not verified with a key: its disks are %s, and a signature is checked only when CERTISTACK_PBS_KEYFILE holds the key the backup was made with", vm.VMID, vm.Name, vm.SourcePBS.Snapshot, cryptModeWords(layout.CryptMode))
}

func cryptModeWords(mode string) string {
	switch mode {
	case pbs.CryptModeEncrypt:
		return "encrypted"
	case pbs.CryptModeSignOnly:
		return "signed"
	default:
		return "neither signed nor encrypted"
	}
}

// requireFirmwareStorage refuses, before any sandbox resource exists, a run
// with firmware state to restore but no overlay storage to restore it to:
// Proxmox VE attaches firmware state only from a storage volume.
func requireFirmwareStorage(plan *config.Plan, overlayStorage string) error {
	if strings.TrimSpace(overlayStorage) != "" {
		return nil
	}
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			if len(vm.FirmwareDisks) > 0 {
				return fmt.Errorf("target VM %d (%s) has firmware state to restore (%s): set storage.overlay_storage (or --overlay-storage) to a file-based PVE storage with images content, because Proxmox VE attaches firmware state only from a storage volume. %s", vm.VMID, vm.Name, vm.FirmwareDisks[0].Slot, pve.CreateOverlayStorageHint)
			}
		}
	}
	return nil
}

// layoutOf is the layout part of a full backup profile.
func layoutOf(profile pbs.VMProfile) pbs.VMLayout {
	disks := make([]string, 0, len(profile.Drives))
	for _, drive := range profile.Drives {
		disks = append(disks, drive.Slot)
	}
	return pbs.VMLayout{
		BIOS: profile.BIOS, Firmware: profile.Firmware, BootOrder: profile.BootOrder, Disks: disks, CryptMode: profile.CryptMode,
		Machine: profile.Machine, SCSIHW: profile.SCSIHW, OSType: profile.OSType, NICs: profile.NICs, NoBalloon: profile.NoBalloon, SMBIOS1: profile.SMBIOS1, Meta: profile.Meta, CDROMs: profile.CDROMs, Consistency: profile.Consistency,
		MAC: profile.MAC, NICModel: profile.NICModel, SourceTags: profile.SourceTags,
		SignatureVerified: profile.SignatureVerified, ExcludedDisks: profile.ExcludedDisks,
		DiskBytes: profile.DiskBytes, ImageBytes: profile.ImageBytes,
	}
}

// applyBackupNetworkIdentity reads only the net0 identity from the backed-up
// qemu-server configuration when an isolated wire probe needs COW guest
// networking but the plan intentionally did not opt into full backup config
// inheritance. It leaves the disk layout, compute profile, firmware, and all
// source topology untouched. This lets ordinary plans use the same automatic
// recovery behavior without duplicating a source MAC in YAML.
func applyBackupNetworkIdentity(ctx context.Context, plan *config.Plan, resolver backupProfileResolver, scratchDir string) error {
	for tierIndex := range plan.Tiers {
		for vmIndex := range plan.Tiers[tierIndex].VMs {
			vm := &plan.Tiers[tierIndex].VMs[vmIndex]
			if vm.NetworkRecovery.EffectiveMode() == "preserve" {
				// The guest keeps its own network, so net0 keeps the backup's
				// identity (resolveNet0Identity); there is no recovery address
				// to derive, and the other modes' rules below do not apply.
				layout, err := resolver.LoadVMLayout(ctx, vm.SourcePBS.Snapshot, scratchDir)
				if err != nil {
					return fmt.Errorf("load source backup network identity for target VM %d (%s): %w", vm.VMID, vm.Name, err)
				}
				if err := resolveNet0Identity(vm, layout.MAC, layout.NICModel); err != nil {
					return err
				}
				continue
			}
			_, configured, err := vm.SandboxAddress(plan.Network)
			if err != nil {
				return fmt.Errorf("resolve isolated network identity for target VM %d (%s): %w", vm.VMID, vm.Name, err)
			}
			if !configured || (vm.MAC != "" && vm.NICModel != "") {
				continue
			}

			layout, err := resolver.LoadVMLayout(ctx, vm.SourcePBS.Snapshot, scratchDir)
			if err != nil {
				return fmt.Errorf("load source backup network identity for target VM %d (%s): %w", vm.VMID, vm.Name, err)
			}
			if err := resolveNet0Identity(vm, layout.MAC, layout.NICModel); err != nil {
				return err
			}
			if len(vm.SourceTags) == 0 {
				vm.SourceTags = append([]string(nil), layout.SourceTags...)
			}
			if vm.MAC == "" {
				return fmt.Errorf("source backup network identity for target VM %d (%s) has no net0 MAC; set network_recovery.mode to preserve to opt out", vm.VMID, vm.Name)
			}
		}
	}
	return nil
}

func sameSourceDriveLayout(configured, discovered []config.SourceDrive) bool {
	if len(configured) != len(discovered) {
		return false
	}
	bySlot := make(map[string]string, len(discovered))
	for _, drive := range discovered {
		bySlot[drive.Slot] = drive.Archive
	}
	for _, drive := range configured {
		if bySlot[drive.Slot] != drive.Archive {
			return false
		}
	}
	return true
}

// writeArtifacts prints where the report was saved. The Community engine
// writes JSON only.
func writeArtifacts(w io.Writer, reportPath string) {
	fmt.Fprintf(w, "✓ Report saved to: %s\n", reportPath)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// ReportPBSIdentity is the PBS fingerprint and namespace a report of plan
// records, as a run's report does: the environment's, else the plan's.
func ReportPBSIdentity(plan *config.Plan) (fingerprint, namespace string) {
	return effectiveReportPBSIdentity(plan)
}

func effectiveReportPBSIdentity(plan *config.Plan) (string, string) {
	fingerprint := envOr("PBS_FINGERPRINT", plan.Storage.PBSFingerprint)
	if fingerprint == "" {
		repository := envOr("PBS_REPOSITORY", plan.Storage.PBSRepository)
		if repository != "" {
			sum := sha256.Sum256([]byte(strings.TrimSpace(repository)))
			fingerprint = "repository-sha256:" + hex.EncodeToString(sum[:])
		}
	}
	namespace := envOr("PBS_NAMESPACE", plan.Storage.PBSNamespace)
	if namespace == "" {
		namespace = "root"
	}
	return fingerprint, namespace
}

func envBool(name string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return value == "1" || value == "true"
}

// prepareRun is what run does with a plan before it creates anything: it
// refuses insecure TLS that was not opted into, resolves each VM's
// snapshot, and applies its backup's configuration and layout, which it
// reads into configDir. PlanRun does the same, so a plan shows what the run
// will really do.
func prepareRun(ctx context.Context, plan *config.Plan, opts Options, configDir string) (*pve.Client, *pbs.Client, error) {
	if envBool("PVE_TLS_INSECURE") {
		if err := pve.CheckInsecureTLSOptIn(); err != nil {
			return nil, nil, err
		}
	}
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			for _, probe := range vm.Probes {
				if probe.InsecureSkipVerify || probe.TLSSkipVerify {
					return nil, nil, fmt.Errorf("VM %d probe %q disables TLS certificate verification; insecure probe TLS is not permitted", vm.VMID, probe.Description)
				}
			}
		}
	}

	pveClient := pve.NewClient(pve.Config{
		BaseURL:     envOr("PVE_URL", "https://127.0.0.1:8006"),
		TokenID:     os.Getenv("PVE_TOKEN_ID"),
		TokenSecret: os.Getenv("PVE_TOKEN_SECRET"),
		TLSInsecure: envBool("PVE_TLS_INSECURE"),
		TLSCAFile:   os.Getenv("CERTISTACK_PVE_CA_SOURCE"),
	})
	pbsClient, err := pbsClientFor(plan)
	if err != nil {
		return nil, nil, err
	}
	// Before any backup is read: a pair this release does not support is
	// refused here, naming the versions, and not by whatever call of the
	// unsupported PVE or PBS fails first.
	if err := gateVersions(ctx, opts, pveClient, pbsClient); err != nil {
		return nil, nil, err
	}
	if err := resolveLatestSnapshots(ctx, plan, pbsClient); err != nil {
		return nil, nil, err
	}
	sources := newSourceCache(pbsClient)
	sources.prefetch(ctx, plan, configDir)
	if plan.UseBackupConfig {
		if err := applyBackupConfig(ctx, plan, sources, configDir); err != nil {
			return nil, nil, err
		}
	} else {
		if err := applyBackupNetworkIdentity(ctx, plan, sources, configDir); err != nil {
			return nil, nil, err
		}
		if err := applyBackupLayout(ctx, plan, sources, configDir); err != nil {
			return nil, nil, err
		}
	}
	if err := requireFirmwareStorage(plan, opts.OverlayStorage); err != nil {
		return nil, nil, err
	}
	return pveClient, pbsClient, nil
}

// checkResolvedPlan asks Options.CheckResolvedPlan, when there is one, whether the engine may go
// on with plan as prepareRun left it. Run and PlanRun call it right after preparation, so both
// judge the same prepared plan; the checks that Run makes before preparation (the sandbox range,
// the journal) and that PlanRun makes inside the orchestrator's plan are still their own.
func checkResolvedPlan(plan *config.Plan, opts Options) error {
	if opts.CheckResolvedPlan == nil {
		return nil
	}
	return opts.CheckResolvedPlan(plan)
}

// initplanDiscover is initplan.Discover, a variable so that a test can see
// the scratch directory Discover hands to it.
var initplanDiscover = initplan.Discover

// Discover reads, on this node, what init needs to write a first plan
// (initplan.Discover), with a run's PVE and PBS clients and credentials.
// It changes nothing but the scratchDir it is given, created private if it
// is missing (empty: the node's temporary directory). req.Namespace, else
// PBS_NAMESPACE, is the namespace read.
func Discover(ctx context.Context, req initplan.Request, scratchDir string) (*initplan.Discovery, error) {
	if envBool("PVE_TLS_INSECURE") {
		if err := pve.CheckInsecureTLSOptIn(); err != nil {
			return nil, err
		}
	}
	if req.Namespace == "" {
		req.Namespace = os.Getenv("PBS_NAMESPACE")
	}
	pbsClient, err := newPBSClient(config.Storage{}, req.Namespace)
	if err != nil {
		return nil, err
	}
	pveClient := pve.NewClient(pve.Config{
		BaseURL:     envOr("PVE_URL", "https://127.0.0.1:8006"),
		TokenID:     os.Getenv("PVE_TOKEN_ID"),
		TokenSecret: os.Getenv("PVE_TOKEN_SECRET"),
		TLSInsecure: envBool("PVE_TLS_INSECURE"),
		TLSCAFile:   os.Getenv("CERTISTACK_PVE_CA_SOURCE"),
	})
	// The backups' configurations are restored beneath the scratch directory
	// the operator chose (empty: the node's temporary directory), which is
	// created private if missing, as a run creates it.
	if scratchDir != "" {
		if err := sysutil.EnsurePrivateDirectory(scratchDir); err != nil {
			return nil, fmt.Errorf("prepare scratch directory %s: %w", scratchDir, err)
		}
	}
	d, err := initplanDiscover(ctx, pbsClient, discoveryCluster{Client: pveClient, sdn: sdn.NewManager(pveClient)}, req, scratchDir)
	return d, namePVECall(err)
}

// namePVECall puts the PVE API request that failed in front of a PVE error, so
// that init's error says which call PVE refused. An error that names it already
// (a missing SDN API) is left as it is.
func namePVECall(err error) error {
	var apiErr *pve.APIError
	if err == nil || !errors.As(err, &apiErr) {
		return err
	}
	call := apiErr.Call()
	if call == "" || strings.Contains(err.Error(), call) {
		return err
	}
	return fmt.Errorf("%s: %w", call, err)
}

// discoveryCluster is PVE as init reads it.
type discoveryCluster struct {
	*pve.Client
	sdn *sdn.Manager
}

func (c discoveryCluster) UsedSDNIDs(ctx context.Context) (map[string]bool, error) {
	return c.sdn.UsedIDs(ctx)
}

// PlanRun works out what Run would do with plan on this node without
// changing anything (orchestrator.Plan). It resolves the plan's backups as
// Run does, reading their configuration into a private temporary directory
// that is removed afterwards.
func PlanRun(ctx context.Context, plan *config.Plan, opts Options) (*orchestrator.RunPlan, error) {
	if plan == nil {
		return nil, errors.New("plan is required")
	}
	if err := requirePlanBounds(plan); err != nil {
		return nil, err
	}
	opts = normalizeOptions(plan, opts)
	if err := pve.ValidateNodeName(opts.NodeName); err != nil {
		return nil, fmt.Errorf("invalid node: %w", err)
	}
	configDir, err := os.MkdirTemp("", "certistack-plan-")
	if err != nil {
		return nil, fmt.Errorf("create private scratch directory: %w", err)
	}
	defer os.RemoveAll(configDir)
	versions := &versionRecord{}
	opts.versions = versions
	pveClient, pbsClient, err := prepareRunFn(ctx, plan, opts, configDir)
	if err != nil {
		return nil, err
	}
	if err := checkResolvedPlan(plan, opts); err != nil {
		return nil, err
	}
	runPlan, err := orchestrator.New(plan, orchestrator.Options{
		NodeName:       opts.NodeName,
		ScratchDir:     opts.ScratchDir,
		OverlayStorage: opts.OverlayStorage,
		StateDir:       opts.StateDir,
		SkipIntegrity:  opts.SkipIntegrity,
		RunID:          "run-planned",
		Recovered:      opts.Recovered,
		Sandbox:        sandboxChecksFor(plan, opts),
	}, pbsClient, pveClient).Plan(ctx)
	if err == nil {
		versions.addToPlan(runPlan)
	}
	return runPlan, err
}

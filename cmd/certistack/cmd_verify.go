// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/spf13/cobra"
)

// reportVerificationSummary is a deliberately small, machine-readable view of
// a cryptographically verified report. It contains no credentials, screenshot
// data or resource paths, so automation can make an evidence-backed decision
// without parsing human-oriented CLI output. It does say why a run failed:
// FailureReason, a failed probe's Error and Detail, and the cleanup errors are
// the report's own words, which a signature does not make safe: they can hold
// text a guest or a service produced. Each is flattened to one line, stripped of
// control characters and cut to a length (see verify_diagnostics.go), and is
// display text to be treated as untrusted. SignatureValid says only that a
// trusted signer signed these exact contents; Acceptance says whether they are
// acceptable evidence for the request.
type reportVerificationSummary struct {
	ReportID       string `json:"report_id"`
	PlanID         string `json:"plan_id"`
	ValidationMode string `json:"validation_mode"`
	TrustSource    string `json:"trust_source"`
	SignatureValid bool   `json:"signature_valid"`
	// Unsigned is set for a report judged with --unsigned: it carried no
	// signature, SignatureValid is false, and TrustSource says that the contents
	// are the run's own claim.
	Unsigned   bool `json:"unsigned,omitempty"`
	AllPassed  bool `json:"all_passed"`
	AllCleaned bool `json:"all_cleaned"`
	// FailureReason is the report's own account of a failure that has no probe
	// record (admission, SDN setup, mapping, cleanup), or the joined failures of
	// the run; CleanupErrors and InitialCleanupErrors are what teardown, and the
	// recovery of an earlier run before this one, could not undo.
	FailureReason        string   `json:"failure_reason,omitempty"`
	CleanupErrorCount    int      `json:"cleanup_error_count,omitempty"`
	CleanupErrors        []string `json:"cleanup_errors,omitempty"`
	InitialCleanupErrors []string `json:"initial_cleanup_errors,omitempty"`
	// RTOSeconds is the recovery time the run achieved, RTOTargetSeconds the
	// objective it was held to (absent when the plan set none, or the report
	// predates schema 1.7), and Admission the host admission policy and the
	// check that decided the run.
	ValidatedPlanSHA256 string                    `json:"validated_plan_sha256,omitempty"`
	ResolvedPlanSHA256  string                    `json:"resolved_plan_sha256,omitempty"`
	PlanDigestFormat    string                    `json:"plan_digest_format,omitempty"`
	RTOSeconds          float64                   `json:"rto_seconds"`
	RTOTargetSeconds    *float64                  `json:"rto_target_seconds,omitempty"`
	Admission           *attest.AdmissionEvidence `json:"admission,omitempty"`
	VMCount             int                       `json:"vm_count"`
	FailedProbeCount    int                       `json:"failed_probe_count"`
	IncompleteVMCount   int                       `json:"incomplete_vm_count"`
	FailedProbes        []failedProbeSummary      `json:"failed_probes,omitempty"`
	NodeFQDN            string                    `json:"node_fqdn"`
	EngineVersion       string                    `json:"engine_version"`
	GitCommit           string                    `json:"git_commit"`
	BuildDate           string                    `json:"build_date"`
	// The Proxmox versions the run read on its node and whether this release
	// has been tested with them (tested, untested or unknown); absent from a
	// report that records none. Display text, bounded like the failure reason.
	PVEVersion       string `json:"pve_version,omitempty"`
	PBSVersion       string `json:"pbs_version,omitempty"`
	PBSClientVersion string `json:"pbs_client_version,omitempty"`
	VersionSupport   string `json:"version_support,omitempty"`
	// SignatureTimestamp says what the report's optional signature_timestamp
	// amounts to; see reportTimestampSummary. It is always present, with status
	// "none" for a report that carries no timestamp.
	SignatureTimestamp reportTimestampSummary `json:"signature_timestamp"`
	Acceptance         accept.Result          `json:"acceptance"`
}

// reportTimestampSummary is the machine-readable account of a report's
// signature_timestamp. Status is none (no member), stub (a test token anyone
// can forge), unverified (a token no verifier of this build handles) or
// verified (a configured verifier accepted it); only verified is evidence, and
// Evidence says so. ClaimedTime is what the unsigned member states and proves
// nothing; VerifiedTime is the time a verifier attested, present only when
// verified. Authority and ClaimedTime come from an unsigned member and are
// display text, bounded like the other free text.
type reportTimestampSummary struct {
	Status       string `json:"status"`
	Evidence     bool   `json:"evidence"`
	Authority    string `json:"authority,omitempty"`
	ClaimedTime  string `json:"claimed_time,omitempty"`
	VerifiedTime string `json:"verified_time,omitempty"`
	Note         string `json:"note,omitempty"`
}

// boundTimestampStatus makes the free text of a timestamp status, which comes
// from an unsigned member, safe to print on one line.
func boundTimestampStatus(status attest.TimestampStatus) attest.TimestampStatus {
	status.Authority = boundedDiagnostic(status.Authority, maxDiagnosticRunes)
	status.ClaimedTime = boundedDiagnostic(status.ClaimedTime, maxVersionRunes)
	return status
}

func summarizeTimestamp(status attest.TimestampStatus) reportTimestampSummary {
	status = boundTimestampStatus(status)
	summary := reportTimestampSummary{
		Status:      string(status.State),
		Evidence:    status.Evidence(),
		Authority:   status.Authority,
		ClaimedTime: status.ClaimedTime,
	}
	if status.State != attest.TimestampNone {
		summary.Note = sanitizeVerifyText(status.Describe())
	}
	if status.Evidence() {
		summary.VerifiedTime = status.VerifiedTime.UTC().Format(time.RFC3339)
	}
	return summary
}

// configuredTimestampVerifiers are the timestamp verifiers this build was
// given. Community has none: a token of any authority but the stub test double
// is reported present and not verified. The real RFC 3161 verifier and the
// hosted timestamp service are later work; a build that has one returns it
// here, and a token it accepts is then reported verified. Tests replace it.
var configuredTimestampVerifiers = func() []attest.TimestampVerifier { return nil }

type failedProbeSummary struct {
	VMID        int    `json:"vmid"`
	Type        string `json:"type"`
	Target      string `json:"target"`
	Description string `json:"description"`
	// Error and Detail are why the probe failed, as the report records them.
	Error  string `json:"error,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// sanitizeVerifyText makes a value of a signed report safe to print on one line
// of a terminal. A signature says who wrote a value, not that it is harmless to
// show: it drops the control characters and the Unicode format characters
// (among them all twelve bidi controls, which reorder the text around them) and
// flattens line breaks, in the one place the progress stream does too
// (progress.SingleLine).
func sanitizeVerifyText(value string) string {
	return progress.SingleLine(value)
}

func sanitizeVerifyStrings(values []string) []string {
	sanitized := make([]string, len(values))
	for index, value := range values {
		sanitized[index] = sanitizeVerifyText(value)
	}
	return sanitized
}

// unsignedTrustSource is what verify-report --unsigned says in place of a trust
// source: there is none, and the contents are not authenticated.
const unsignedTrustSource = "UNSIGNED: the contents are the run's own claim, not authenticated"

func summarizeVerifiedReport(report *attest.Report, trustSource string) reportVerificationSummary {
	summary := reportVerificationSummary{
		ReportID:            report.ReportID,
		PlanID:              report.PlanID,
		ValidationMode:      report.ValidationMode,
		TrustSource:         trustSource,
		SignatureValid:      true,
		AllPassed:           report.AllPassed,
		ValidatedPlanSHA256: report.ValidatedPlanSHA256,
		ResolvedPlanSHA256:  report.ResolvedPlanSHA256,
		PlanDigestFormat:    report.PlanDigestFormat,
		RTOSeconds:          report.RTOSeconds,
		RTOTargetSeconds:    report.RTOTargetSeconds,
		Admission:           report.Admission,
		VMCount:             len(report.VMRecords),
		NodeFQDN:            report.NodeFQDN,
		EngineVersion:       report.EngineVersion,
		GitCommit:           report.GitCommit,
		BuildDate:           report.BuildDate,
		FailureReason:       boundedDiagnostic(report.FailureReason, maxFailureReasonRunes),
		PVEVersion:          boundedDiagnostic(report.PVEVersion, maxVersionRunes),
		PBSVersion:          boundedDiagnostic(report.PBSVersion, maxVersionRunes),
		PBSClientVersion:    boundedDiagnostic(report.PBSClientVersion, maxVersionRunes),
		VersionSupport:      boundedDiagnostic(report.VersionSupport, maxVersionRunes),
	}
	if evidence := report.TeardownEvidence; evidence != nil {
		summary.AllCleaned = evidence.AllCleaned
		summary.CleanupErrorCount = len(evidence.CleanupErrors) + len(evidence.InitialCleanupErrors)
		summary.CleanupErrors = boundedDiagnostics(evidence.CleanupErrors)
		summary.InitialCleanupErrors = boundedDiagnostics(evidence.InitialCleanupErrors)
		if len(summary.CleanupErrors) == 0 {
			summary.CleanupErrors = nil
		}
		if len(summary.InitialCleanupErrors) == 0 {
			summary.InitialCleanupErrors = nil
		}
	}
	for _, vm := range report.VMRecords {
		if vm.VerificationStatus == "incomplete" {
			summary.IncompleteVMCount++
		}
		for _, result := range vm.ProbeResults {
			if !result.Passed && !result.Skipped {
				summary.FailedProbeCount++
				summary.FailedProbes = append(summary.FailedProbes, failedProbeSummary{
					VMID: vm.VMID, Type: result.Type, Target: result.Target, Description: result.Description,
					Error: boundedDiagnostic(result.Error, maxDiagnosticRunes), Detail: boundedDiagnostic(result.Detail, maxDiagnosticRunes),
				})
			}
		}
	}
	return summary
}

// maxExpectedPlanBytes bounds how much of an --expect-plan file is read; the
// plan loader refuses anything over its own, smaller limit.
const maxExpectedPlanBytes = 16 << 20

// expectationFlags are the verify-report flags that bind the acceptance
// verdict to the caller's request. Setting any of them asks verify-report to
// exit non-zero when the report is not accepted.
var expectationFlags = []string{"expect-plan", "expect-node", "expect-version", "expect-commit", "expect-build-date", "expect-worker-sha256", "expect-validation-mode", "expect-version-support", "expect-outcome"}

// workerSHA256Pattern is the form of an --expect-worker-sha256 value: the
// 64 lowercase hex digits sha256sum prints, as the release registry and
// campaign.meta write them.
var workerSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// readReportExpectations validates the --expect-* flags and loads the
// expected plan. An expectation given as an empty value is refused: it would
// otherwise silently bind nothing.
func readReportExpectations(cmd *cobra.Command, planPath, outcome string, allowTestMode bool) (accept.Expectations, bool, error) {
	exp := accept.Expectations{Outcome: outcome, AllowTestMode: allowTestMode}
	requested := false
	for _, name := range expectationFlags {
		if !cmd.Flags().Changed(name) {
			continue
		}
		requested = true
		value, err := cmd.Flags().GetString(name)
		if err != nil {
			return exp, false, err
		}
		if strings.TrimSpace(value) == "" {
			return exp, false, fmt.Errorf("--%s must not be empty", name)
		}
		switch name {
		case "expect-node":
			exp.Node = &value
		case "expect-version":
			exp.Version = &value
		case "expect-commit":
			exp.Commit = &value
		case "expect-build-date":
			exp.BuildDate = &value
		case "expect-worker-sha256":
			if !workerSHA256Pattern.MatchString(value) {
				return exp, false, errors.New("--expect-worker-sha256 must be 64 lowercase hex digits, the SHA-256 of the executable (sha256sum prints it)")
			}
			exp.WorkerSHA256 = &value
		case "expect-validation-mode":
			exp.ValidationMode = &value
		case "expect-version-support":
			// The report states one of tested, untested or unknown. Only the
			// first two are a thing to require: "unknown" is a version that
			// could not be read, never evidence of either.
			if value != "tested" && value != "untested" {
				return exp, false, fmt.Errorf("unsupported --expect-version-support %q: use tested or untested", value)
			}
			exp.VersionSupport = &value
		}
	}
	switch outcome {
	case accept.OutcomePass, accept.OutcomeFault, accept.OutcomeDenied:
	default:
		return exp, false, fmt.Errorf("unsupported --expect-outcome %q: use pass, fault, or denied", outcome)
	}
	if exp.ValidationMode != nil {
		switch *exp.ValidationMode {
		case attest.ValidationModeFullIntegrity:
		case attest.ValidationModeTestSkipIntegrity:
			if !allowTestMode {
				return exp, false, errors.New("--expect-validation-mode test_skip_integrity requires --allow-test-mode")
			}
		default:
			return exp, false, fmt.Errorf("unsupported --expect-validation-mode %q: use %s or %s", *exp.ValidationMode, attest.ValidationModeFullIntegrity, attest.ValidationModeTestSkipIntegrity)
		}
	}
	if outcome == accept.OutcomeFault && planPath == "" {
		return exp, false, errors.New("--expect-outcome fault requires --expect-plan: the fault plan's first VM and probe name the expected failure")
	}
	if planPath != "" {
		// The plan is read as a bounded regular file, so a FIFO or a device
		// given as the plan never keeps verification waiting. The
		// worker loader validates the plan without requiring the controller's
		// private signing-key path, which verification never uses; it applies
		// its own, tighter size limit.
		data, err := attest.ReadRegularFile(planPath, "expected plan", maxExpectedPlanBytes)
		if err != nil {
			return exp, false, fmt.Errorf("load --expect-plan: %w", err)
		}
		plan, err := config.LoadFromReaderForWorker(bytes.NewReader(data))
		if err != nil {
			return exp, false, fmt.Errorf("load --expect-plan %s: %w", planPath, err)
		}
		exp.Plan = plan
		// The digest is of the file's bytes as read, which is what the
		// controller hashed when it read the plan it ran (plan_sha256).
		exp.PlanSHA256 = config.PlanDigest(data)
	}
	return exp, requested, nil
}

func verifyReportCmd() *cobra.Command {
	var (
		keyringPath   string
		pubKeyPath    string
		trustedKey    string
		format        string
		allowTestMode bool
		unsigned      bool
		expectPlan    string
		expectOutcome string
	)

	cmd := &cobra.Command{
		Use:   "verify-report <report.json>",
		Short: "Verify a signed DR report against a signer you trust, or judge an unsigned one",
		Long: `Verifies a report's Ed25519 signature against an explicitly trusted signer,
then evaluates whether the signed contents are acceptable evidence. The
Enterprise Edition signs its reports; this command, in the Community Edition,
is how anyone checks one, with no license.

The Community Edition writes its reports unsigned. A report with no signature
is refused by default, so that a signature taken off a report is never read
as a report that was verified. Pass --unsigned when the report is expected to
carry none: the signature is not checked, the output says that the contents
are the run's own claim and not authenticated, and the acceptance rules below
(and the --expect-* flags) decide the exit status as they do for a signed
report. --unsigned cannot be combined with --keyring, --public-key or
--trusted-key, and refuses a report that carries a signature: verify that one
against a key.

A valid, trusted signature proves who signed the report and that it is
unchanged; it does not prove that the recovery succeeded. The acceptance
verdict separately checks the VM population, every probe result, disk
integrity, and verified cleanup. The --expect-* flags bind it to the request:
the plan's exact VMs and probes (and, when the report records it, the plan
file's SHA-256 and each probe's timeout, retries and identity), the node, the
CertiStack build, the validation mode, and whether the Proxmox versions it ran
on were tested (--expect-version-support). Anything a report is too old to be
checked on is listed in the verdict as NOT BOUND.

A report may carry a signature_timestamp, a trusted timestamp over the
signature (a SHA-256 imprint of the signature bytes) that is not itself signed.
The command prints a "Sig timestamp" line: none, a stub timestamp (a test token
that anyone can forge, reported as NOT evidence), a token this build cannot
verify, or one verified at a time by an authority. Community has no timestamp
authority; the hosted one is not part of this release. A timestamp never makes
an invalid signature valid, and one that does not cover the report's signature
is refused.

Exit status: 0 means the signature is valid and trusted (with --unsigned: the
report was read) and, with any --expect-* flag (--expect-outcome pass is the
plain form), that the report is accepted; a report that is not accepted then
exits with status 1. Without an --expect-* flag the exit status says nothing
about acceptance: a rejected report still exits 0 (the verdict is printed, and
a note goes to standard error), so a script that needs the verdict must pass a
flag or read acceptance.verdict. Status 2 means the report cannot be trusted
or read: an invalid signature or untrusted signer, a report with no signature
(without --unsigned) or with one (with it), a validation mode other than
full_integrity (or test_skip_integrity with --allow-test-mode), or a
misused command.`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			reportPath := args[0]
			reportNoun := "signed report"
			if unsigned {
				reportNoun = "unsigned report"
			}
			// Refuse every invocation that can be refused from its arguments
			// alone before any file is opened, so a bad combination never waits
			// on, or reads from, a report path.
			if format != "text" && format != "json" {
				return fmt.Errorf("unsupported --format %q: use text or json", format)
			}
			sourceCount := 0
			firstSource := ""
			for _, name := range []string{"keyring", "public-key", "trusted-key"} {
				if !cmd.Flags().Changed(name) {
					continue
				}
				if value, _ := cmd.Flags().GetString(name); strings.TrimSpace(value) == "" {
					return fmt.Errorf("--%s must not be empty", name)
				}
				if firstSource == "" {
					firstSource = name
				}
				sourceCount++
			}
			// --unsigned says the report carries no signature, so there is nothing
			// to trust and naming something to trust is a contradiction. It is told
			// before any file is read.
			if unsigned && sourceCount > 0 {
				return fmt.Errorf("--unsigned and --%s cannot be used together: --unsigned is for a report that carries no signature, so there is no signer to trust; drop --unsigned to verify a signed report", firstSource)
			}
			if sourceCount == 0 && !unsigned {
				return fmt.Errorf("an explicit --keyring, --public-key, or --trusted-key is required; refusing trust from the report directory or current working directory (or pass --unsigned for a report that is expected to carry no signature, such as the Community Edition writes)")
			}
			if sourceCount > 1 {
				return fmt.Errorf("--keyring, --public-key, and --trusted-key are mutually exclusive")
			}
			// An inline trusted key is a value, not a file: check it with the
			// other arguments, before any file is opened.
			var inlineKey ed25519.PublicKey
			if trustedKey != "" {
				key, err := attest.ParsePublicKeyHex(trustedKey)
				if err != nil {
					return fmt.Errorf("invalid --trusted-key: %w", err)
				}
				inlineKey = key
			}
			expectations, acceptanceRequested, err := readReportExpectations(cmd, expectPlan, expectOutcome, allowTestMode)
			if err != nil {
				return err
			}
			// A report judged with --unsigned was authenticated by nothing; every
			// other path reaches the acceptance rules only after VerifyReport
			// verified its signature against a trusted key.
			expectations.Authenticated = !unsigned

			// Load the trusted signers, then open the report once.
			var keyring *attest.Keyring
			var trustedKeys []ed25519.PublicKey
			trustSource := ""
			switch {
			case unsigned:
				trustSource = unsignedTrustSource
			case keyringPath != "":
				kr, err := attest.LoadKeyringFile(keyringPath)
				if err != nil {
					return fmt.Errorf("failed to load keyring: %w", err)
				}
				keyring = kr
				trustedKeys = keyring.PublicKeys()
				trustSource = "keyring:" + keyringPath
			case pubKeyPath != "":
				key, err := attest.LoadPublicKeyFile(pubKeyPath)
				if err != nil {
					return fmt.Errorf("failed to read public key: %w", err)
				}
				trustedKeys = append(trustedKeys, key)
				trustSource = "public-key:" + pubKeyPath
			default:
				trustedKeys = append(trustedKeys, inlineKey)
				trustSource = "trusted-key:inline"
			}
			if !unsigned && len(trustedKeys) == 0 {
				return fmt.Errorf("the keyring %s holds no trusted signer keys, so it can accept no report; refusing untrusted signature-only verification", keyringPath)
			}

			data, err := attest.ReadRegularFile(reportPath, "report", attest.MaxReportFileBytes)
			if err != nil {
				return fmt.Errorf("failed to read report: %w", err)
			}

			var report *attest.Report
			if unsigned {
				// The caller says the report carries no signature. One that does is
				// not that, and is told so, not shown as an unauthenticated claim.
				report, err = attest.DecodeUnsignedReport(data)
				if errors.Is(err, attest.ErrReportSigned) {
					return fmt.Errorf("%w: it is not an unsigned report; verify it with --keyring, --public-key or --trusted-key instead of --unsigned", err)
				}
				if err != nil {
					return fmt.Errorf("failed to read report: %w", err)
				}
			} else {
				var valid bool
				report, valid, err = attest.VerifyReport(data, trustedKeys)
				if err != nil {
					if errors.Is(err, attest.ErrInvalidSignature) {
						fmt.Fprintln(cmd.ErrOrStderr(), "✗ REPORT SIGNATURE INVALID OR TAMPERED")
						return fmt.Errorf("cryptographic signature mismatch")
					}
					if errors.Is(err, attest.ErrReportUnsigned) {
						return fmt.Errorf("report verification failed: %w; if this report is expected to be unsigned (the Community Edition writes its reports unsigned), judge it with --unsigned", err)
					}
					return fmt.Errorf("report verification failed: %w", err)
				}
				if !valid {
					fmt.Fprintln(cmd.ErrOrStderr(), "✗ REPORT SIGNATURE INVALID OR TAMPERED")
					return fmt.Errorf("cryptographic signature mismatch")
				}
			}
			// The signature is good; now the timestamp beside it, which is not
			// signed. A token that does not cover this signature, or that a
			// configured verifier refuses, is a refusal. A stub token is
			// reported as the test double it is, and never as evidence.
			//
			// A report declared unsigned has no signature to be stamped: it has no
			// timestamp either (DecodeUnsignedReport refused any member of that
			// name), and none is evaluated for it, so that a token can never be
			// reported as verified evidence on a report nothing was verified for.
			timestamp := attest.TimestampStatus{State: attest.TimestampNone}
			if !unsigned {
				var err error
				timestamp, err = attest.EvaluateTimestamp(report, configuredTimestampVerifiers()...)
				if err != nil {
					return fmt.Errorf("report verification failed: the signature is valid, but the timestamp beside it is refused: %w", err)
				}
			}
			// The validation mode is an allowlist, judged for every report with or
			// without an --expect-* flag: a signed mode this verifier does not know
			// (empty, missing, another case, a later spelling) is refused at the
			// same exit status as the test mode it could be mistaken for.
			// The summary and the text are still written, with all_passed false, so
			// an operator can read what the report says.
			modeBlocked := accept.ValidationModeProblem(report.ValidationMode, allowTestMode) != ""
			testModeBlocked := modeBlocked && report.ValidationMode == attest.ValidationModeTestSkipIntegrity
			acceptance := accept.Evaluate(report, expectations)
			acceptanceErr := func() error {
				if testModeBlocked {
					return fmt.Errorf("test-mode report is not production evidence; pass --allow-test-mode to accept it")
				}
				if modeBlocked {
					return fmt.Errorf("unsupported validation mode %q: verify-report accepts only %s, or %s with --allow-test-mode", accept.BoundedReason(report.ValidationMode), attest.ValidationModeFullIntegrity, attest.ValidationModeTestSkipIntegrity)
				}
				if acceptanceRequested && acceptance.Verdict != accept.Accepted {
					more := ""
					if extra := len(acceptance.Reasons) - 1; extra > 0 {
						more = fmt.Sprintf(" (and %d more; see the acceptance reasons)", extra)
					}
					return withExitCode(fmt.Errorf("the %s is not accepted as %s evidence: %s%s", reportNoun, acceptance.Outcome, sanitizeVerifyText(acceptance.Reasons[0]), more), exitCodeValidationFailed)
				}
				if !acceptanceRequested && acceptance.Verdict != accept.Accepted {
					// Without an --expect-* flag the exit status reflects the
					// signature and the trust, which is documented; a script that
					// reads only that status would take this report for accepted
					// evidence, so the command says what it is.
					what := "its signature is valid and trusted"
					if unsigned {
						what = "the report was read"
					}
					fmt.Fprintf(cmd.ErrOrStderr(), "note: this report is %s as %s evidence (%s), but exit status 0 here means only that %s. Pass --expect-outcome %s, or any other --expect-* flag, to make the exit status follow the verdict.\n", strings.ToUpper(acceptance.Verdict), acceptance.Outcome, sanitizeVerifyText(acceptance.Reasons[0]), what, accept.OutcomePass)
				}
				return nil
			}
			if format == "json" {
				summary := summarizeVerifiedReport(report, trustSource)
				if unsigned {
					// Nothing was verified: the signature is not valid, and the
					// summary says it is the run's own claim.
					summary.SignatureValid, summary.Unsigned = false, true
				}
				summary.SignatureTimestamp = summarizeTimestamp(timestamp)
				summary.Acceptance = acceptance
				if modeBlocked {
					summary.AllPassed = false
				}
				if err := json.NewEncoder(cmd.OutOrStdout()).Encode(summary); err != nil {
					return err
				}
				return acceptanceErr()
			}

			// The verdict below is the whole result of the command: if it
			// cannot be written, the command fails instead of exiting zero
			// with nothing delivered.
			out := newCheckedOutput(cmd.OutOrStdout())
			trustDescription := "explicitly supplied public key"
			switch {
			case keyring != nil:
				trustDescription = "trusted keyring"
			case pubKeyPath != "":
				trustDescription = "public-key file"
			case trustedKey != "":
				trustDescription = "inline trusted public key"
			}

			if unsigned {
				// Nothing is authenticated: the output says so where a signed report
				// says whose signature it is, and prints the signer lines of neither.
				fmt.Fprintln(out, "! Audit Certificate NOT SIGNED (--unsigned)")
				fmt.Fprintf(out, "  Trust Source: %s\n", sanitizeVerifyText(trustSource))
				fmt.Fprintf(out, "  Sig timestamp: %s\n", sanitizeVerifyText(boundTimestampStatus(timestamp).Describe()))
			} else {
				fp := report.SignerFingerprint
				if fp == "" && report.PublicKey != "" {
					fp = attest.FingerprintFromHex(report.PublicKey)
				}

				fmt.Fprintln(out, "✓ Audit Certificate Signature VALID")
				fmt.Fprintf(out, "  Trust Source: %s\n", sanitizeVerifyText(trustSource))
				fmt.Fprintf(out, "✓ Signer identity verified against %s\n", trustDescription)

				var matchedSigner *attest.TrustedSigner
				if keyring != nil {
					matchedSigner = keyring.FindSigner(report.PublicKey)
				}

				if matchedSigner != nil {
					fmt.Fprintf(out, "✓ Signer Identity: TRUSTED (\"%s\")\n", sanitizeVerifyText(matchedSigner.Name))
					if matchedSigner.Node != "" {
						fmt.Fprintf(out, "  Signer Node: %s\n", sanitizeVerifyText(matchedSigner.Node))
					}
				} else {
					fmt.Fprintf(out, "✓ Signer Identity: TRUSTED (matched %s)\n", trustDescription)
				}

				fmt.Fprintf(out, "  Signer Key:  %s\n", sanitizeVerifyText(report.PublicKey))
				if fp != "" {
					fmt.Fprintf(out, "  Fingerprint: %s\n", sanitizeVerifyText(fp))
				}
				// Only a verified token is evidence; none, a stub and a token this
				// build cannot verify say so on the line.
				fmt.Fprintf(out, "  Sig timestamp: %s\n", sanitizeVerifyText(boundTimestampStatus(timestamp).Describe()))
			}
			if report.EngineVersion != "" {
				fmt.Fprintf(out, "  Engine:      %s (commit: %s)\n", sanitizeVerifyText(report.EngineVersion), sanitizeVerifyText(report.GitCommit))
			}
			if report.ReportSchemaVersion != "" {
				fmt.Fprintf(out, "  Schema:      %s\n", sanitizeVerifyText(report.ReportSchemaVersion))
			}
			writeProxmoxVersions(out, report)
			fmt.Fprintf(out, "  Report ID:   %s\n", sanitizeVerifyText(report.ReportID))
			fmt.Fprintf(out, "  Plan ID:     %s\n", sanitizeVerifyText(report.PlanID))
			fmt.Fprintf(out, "  Plan Name:   %s\n", sanitizeVerifyText(report.PlanName))
			fmt.Fprintf(out, "  Node:        %s\n", sanitizeVerifyText(report.NodeFQDN))
			fmt.Fprintf(out, "  Timestamp:   %s\n", sanitizeVerifyText(report.Timestamp))
			fmt.Fprintf(out, "  Frameworks:  %v\n", sanitizeVerifyStrings(report.Frameworks))
			fmt.Fprintf(out, "  RTO:         %.2f seconds\n", report.RTOSeconds)
			writeRTOTarget(out, report)
			allPassed := report.AllPassed
			if modeBlocked {
				allPassed = false
			}
			fmt.Fprintf(out, "  All Passed:  %v\n", allPassed)
			writeFailureReason(out, report)
			if modeBlocked && !testModeBlocked {
				// Quoted, so a mode that differs from a supported one only by case,
				// a space or an invisible character is seen to.
				fmt.Fprintf(out, "  Validation:  %q (not a supported mode)\n", accept.BoundedReason(report.ValidationMode))
				fmt.Fprintln(out, "  WARNING: the report does not say it was validated with a mode this verifier supports, so it cannot be accepted as evidence.")
			} else {
				fmt.Fprintf(out, "  Validation:  %s\n", sanitizeVerifyText(report.ValidationMode))
			}
			if report.ValidationMode == attest.ValidationModeTestSkipIntegrity {
				if testModeBlocked {
					fmt.Fprintln(out, "  WARNING: full mapped-PBS integrity verification was skipped; pass --allow-test-mode only for deliberate lab review.")
				} else {
					fmt.Fprintln(out, "  WARNING: full mapped-PBS integrity verification was skipped; this is not production compliance evidence.")
				}
			}

			writeAdmissionPolicy(out, report)

			if report.PhaseTimings != nil {
				pt := report.PhaseTimings
				fmt.Fprintln(out, "\n  Phase Timings Breakdown:")
				fmt.Fprintf(out, "    - Host Admission:        %.2fs\n", pt.AdmissionCheckSec)
				fmt.Fprintf(out, "    - SDN Sandbox Setup:     %.2fs\n", pt.SDNProvisioningSec)
				fmt.Fprintf(out, "    - PBS Chunk Mapping:     %.2fs\n", pt.PBSMappingSec)
				fmt.Fprintf(out, "    - Delta Overlay Create:  %.2fs\n", pt.OverlayCreationSec)
				fmt.Fprintf(out, "    - COW Guest Network Prep: %.2fs\n", pt.COWGuestNetworkRecoverySec)
				fmt.Fprintf(out, "    - Image Integrity Scan:  %.2fs\n", pt.IntegrityVerificationSec)
				fmt.Fprintf(out, "    - VM Registration:       %.2fs\n", pt.VMRegistrationSec)
				fmt.Fprintf(out, "    - QEMU Launch & Boot:    %.2fs\n", pt.VMStartSec)
				fmt.Fprintf(out, "    - Stage 1 QMP Wait:      %.2fs\n", pt.QMPRunningWaitSec)
				fmt.Fprintf(out, "    - Startup Soak Grace:    %.2fs\n", pt.StartupGracePeriodSec)
				fmt.Fprintf(out, "    - Probes Execution:      %.2fs\n", pt.ProbesExecutionSec)
				fmt.Fprintf(out, "    - Tier Soak Hold:        %.2fs\n", pt.SoakTimeSec)
				fmt.Fprintf(out, "    - Post-Test Teardown:    %.2fs\n", pt.TeardownSec)
				fmt.Fprintf(out, "    - Total RTO Time:        %.2fs\n", pt.TotalRTOSec)
			}

			if report.TeardownEvidence != nil {
				te := report.TeardownEvidence
				fmt.Fprintln(out, "\n  Teardown & Safety Evidence:")
				fmt.Fprintf(out, "    - VM Destroyed:          %v\n", te.VMStoppedAndDestroyed)
				fmt.Fprintf(out, "    - Overlays Removed:      %d disk(s)\n", len(te.OverlayFilesRemoved))
				fmt.Fprintf(out, "    - Loops Unmapped:        %d device(s)\n", len(te.LoopDevicesUnmapped))
				if te.SDNProvisioning == "preprovisioned" {
					fmt.Fprintf(out, "    - SDN Sandbox Retained:  Zone %s / VNet %s (validated, not modified)\n", sanitizeVerifyText(te.SDNZoneValidated), sanitizeVerifyText(te.SDNVNetValidated))
				} else {
					zone := te.SDNZoneRemoved
					if zone == "" {
						zone = "not allocated"
					}
					vnet := te.SDNVNetRemoved
					if vnet == "" {
						vnet = "not allocated"
					}
					fmt.Fprintf(out, "    - SDN Sandbox Purged:    Zone %s / VNet %s\n", sanitizeVerifyText(zone), sanitizeVerifyText(vnet))
				}
				fmt.Fprintf(out, "    - Owned Resources Clean: %v\n", te.OrphanSweepClean)
				fmt.Fprintf(out, "    - All Cleaned:           %v (at %s)\n", te.AllCleaned, sanitizeVerifyText(te.VerifiedAt))
			}
			writeSoakSummary(out, report)
			writeFailureDiagnostics(out, report)
			writeAcceptance(out, acceptance)

			return out.deliver(acceptanceErr())
		},
	}

	cmd.Flags().StringVar(&keyringPath, "keyring", "", "path to trusted signers keyring.json file")
	cmd.Flags().StringVar(&pubKeyPath, "public-key", "", "path to specific trusted public key file")
	cmd.Flags().StringVar(&trustedKey, "trusted-key", "", "trusted Ed25519 public key hex string")
	cmd.Flags().BoolVar(&unsigned, "unsigned", false, "the report is expected to carry no signature (the Community Edition writes none): do not check one, say the contents are not authenticated, and judge them by the acceptance rules; refused for a report that carries a signature, and not combined with a trust source")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&allowTestMode, "allow-test-mode", false, "allow verification of test-mode reports as lab evidence")
	cmd.Flags().StringVar(&expectPlan, "expect-plan", "", "accept only a report of exactly this plan: its VMs (and source VMs), probes and their policy, and the exact file when the report records its digest (plan_sha256)")
	cmd.Flags().String("expect-node", "", "accept only a report produced on this PVE node")
	cmd.Flags().String("expect-version", "", "accept only a report produced by this CertiStack version")
	cmd.Flags().String("expect-commit", "", "accept only a report produced by this CertiStack Git commit")
	cmd.Flags().String("expect-build-date", "", "accept only a report produced by a CertiStack build with this build date")
	cmd.Flags().String("expect-worker-sha256", "", "accept only a report whose recorded worker_sha256 is this SHA-256 of the executable the controller uploaded (for a release, the digest published for it)")
	cmd.Flags().String("expect-validation-mode", "", "accept only this validation mode: full_integrity or test_skip_integrity")
	cmd.Flags().String("expect-version-support", "", "accept only a report whose recorded version_support is exactly this: tested (the Proxmox pair the release evidence covers) or untested; a report that records none is not accepted")
	cmd.Flags().StringVar(&expectOutcome, "expect-outcome", accept.OutcomePass, "outcome to accept: pass; fault (exactly one failed probe, the first probe of the plan's first VM); or denied (refused before any VM was restored)")

	return cmd
}

// writeAcceptance prints the acceptance verdict after the signature details,
// so a reader of the text output never mistakes a valid signature for a pass.
func writeAcceptance(out io.Writer, acceptance accept.Result) {
	bindings := "internal consistency only; add --expect-plan, --expect-node, and --expect-version/--expect-commit to bind it to your request"
	var checked, unbound []string
	for _, binding := range acceptance.Bindings {
		if rest, isUnbound := strings.CutPrefix(binding, accept.UnboundPrefix); isUnbound {
			unbound = append(unbound, rest)
		} else {
			checked = append(checked, binding)
		}
	}
	if len(checked) > 0 {
		bindings = "checked against the expected " + strings.Join(checked, ", ")
	}
	// An expectation that could not be checked is said on the same line, so a
	// reader never takes it for a passed one.
	if len(unbound) > 0 {
		bindings += "; " + strings.TrimSpace(accept.UnboundPrefix) + " " + strings.Join(unbound, "; ")
	}
	if acceptance.Authenticated {
		fmt.Fprintf(out, "\n  Acceptance:  %s as %s evidence (%s)\n", strings.ToUpper(acceptance.Verdict), acceptance.Outcome, bindings)
	} else {
		// Nothing authenticated the report: the verdict is on its contents, and
		// the line says so where a script or a ticket quotes it from.
		fmt.Fprintf(out, "\n  Acceptance:  %s on its contents only (UNSIGNED: the run's own claim, not authenticated evidence)\n", strings.ToUpper(acceptance.Verdict))
		fmt.Fprintf(out, "               judged as %s evidence (%s)\n", acceptance.Outcome, bindings)
	}
	for _, reason := range acceptance.Reasons {
		fmt.Fprintf(out, "    - %s\n", sanitizeVerifyText(reason))
	}
}

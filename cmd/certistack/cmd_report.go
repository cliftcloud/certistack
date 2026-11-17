// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/spf13/cobra"
)

// reportTrust is the signer set a viewer was given with --keyring.
type reportTrust struct {
	keyring *attest.Keyring
	keys    []ed25519.PublicKey
	source  string
}

// loadReportTrust reads a keyring the way verify-report does: a keyring that
// holds no usable key can accept no report, and is refused, not read as "check
// nothing".
func loadReportTrust(path string) (*reportTrust, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("--keyring must not be empty")
	}
	keyring, err := attest.LoadKeyringFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load keyring: %w", err)
	}
	keys := keyring.PublicKeys()
	if len(keys) == 0 {
		return nil, fmt.Errorf("the keyring %s holds no trusted signer keys, so it can accept no report; refusing untrusted signature-only verification", path)
	}
	return &reportTrust{keyring: keyring, keys: keys, source: "keyring:" + path}, nil
}

func reportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Read the reports a run produced",
		Long: `Commands that read the JSON reports in the controller's report
directory. They only read: nothing is created, changed or sent anywhere. Use
verify-report when a script needs a verdict from the exit status.`,
		// A group with no action of its own: without a RunE cobra answers an
		// unknown subcommand with the help and exit status 0.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	cmd.AddCommand(reportShowCmd())
	return cmd
}

func reportShowCmd() *cobra.Command {
	var (
		keyringPath string
		asJSON      bool
		reportsDir  string
	)
	cmd := &cobra.Command{
		Use:   "show [report.json]",
		Short: "Print a readable summary of one report (the newest when none is named)",
		Long: `Prints what a report says: the outcome and why, the plan and node, the
engine build, whether full integrity verification ran (a test-mode report is
flagged at the top), the recovery time and where it went, and for each VM the
backup snapshot it was restored from, how its network was prepared, the integrity
result of every disk, every probe with what it asserted and how it ended, and the
teardown result.

With no file named, it shows the newest report in the reports directory
(--reports-dir, by default where run saves them) and names it on standard error.

Without --keyring the signature is NOT checked: the output is what the file says,
and it says so. A report with no signature at all (the Community Edition writes
its reports unsigned) is shown as unsigned, with the command that judges it. With
--keyring the signature is verified against a signer of that
keyring and the report is judged for acceptance as pass evidence, exactly as
verify-report does with no --expect-* flag (the verdict is not bound to your
plan, node or build: use verify-report --expect-* for that). A report whose
signature does not verify, or that has none, is an error and prints nothing of
its contents.

--json prints the same facts as JSON for scripts. Exit status: 0 when the report
was shown, whatever it says (this command does not decide a verdict: use
verify-report --expect-outcome pass for that), 2 when the file cannot be read,
is not a report of a schema this build understands, or fails the signature check.`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var path string
			if len(args) == 1 {
				path = args[0]
			} else {
				newest, err := newestReport(reportsDir)
				if err != nil {
					return err
				}
				path = newest
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Newest report: %s\n", path); err != nil {
					return err
				}
			}
			var trust *reportTrust
			if cmd.Flags().Changed("keyring") {
				loaded, err := loadReportTrust(keyringPath)
				if err != nil {
					return err
				}
				trust = loaded
			}
			data, err := attest.ReadRegularFile(path, "report", attest.MaxReportFileBytes)
			if err != nil {
				return fmt.Errorf("failed to read report: %w", err)
			}
			view, err := showReport(cmd, data, trust)
			if err != nil {
				return err
			}
			if asJSON {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(view)
			}
			out := newCheckedOutput(cmd.OutOrStdout())
			renderReportView(out, view)
			return out.deliver(nil)
		},
	}
	cmd.Flags().StringVar(&keyringPath, "keyring", "", "path to a trusted signers keyring; verifies the signature and judges acceptance as verify-report does")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the same facts as JSON")
	cmd.Flags().StringVar(&reportsDir, "reports-dir", defaultReportsDir, "where to look for the newest report when no file is named")
	return cmd
}

// showReport decodes a report, verifies it when a keyring was given, and builds
// its view. An unreadable report, an unsupported schema or a failed signature
// check is an error, never a partial view.
func showReport(cmd *cobra.Command, data []byte, trust *reportTrust) (*reportView, error) {
	if trust == nil {
		report, err := attest.DecodeReportUnverified(data)
		if err != nil {
			return nil, fmt.Errorf("cannot show this file: %w", err)
		}
		if err := reportSchemaError(report); err != nil {
			return nil, err
		}
		signature := viewSignature{
			Status: "not_checked",
			Note:   "signature not checked (no --keyring): the contents are what the file says, not verified evidence",
		}
		// Whether the report is unsigned is read from the members of its document,
		// the way DecodeUnsignedReport reads them, and not from the decoded fields:
		// the decoder reads a member in any letter case, and a member that holds
		// nothing ("signature": "", null) fills no field, but is a signature member
		// all the same, which --unsigned refuses.
		carried, err := attest.CarriedSignatureMembers(data)
		if err != nil {
			return nil, fmt.Errorf("cannot show this file: %w", err)
		}
		switch {
		case len(carried) == 0:
			signature = viewSignature{
				Status: "unsigned",
				Note:   "this report is unsigned (the Community Edition writes its reports unsigned): its contents are the run's own claim, not authenticated evidence",
			}
		case !usableSignatureMembers(carried, report):
			signature = viewSignature{
				Status: "malformed",
				Note: fmt.Sprintf("this report carries a signature member (%s) that is not a usable signature, so it is neither a signed report nor an unsigned one: verify-report --unsigned refuses it, and so does verify-report with a trust source; its contents are what the file says and nothing more",
					strings.Join(quotedNames(carried), ", ")),
			}
		}
		return buildReportView(report, signature, nil), nil
	}

	report, valid, err := attest.VerifyReport(data, trust.keys)
	if err != nil {
		if errors.Is(err, attest.ErrInvalidSignature) {
			fmt.Fprintln(cmd.ErrOrStderr(), "✗ REPORT SIGNATURE INVALID OR TAMPERED")
			return nil, errors.New("cryptographic signature mismatch")
		}
		return nil, fmt.Errorf("report verification failed: %w", err)
	}
	if !valid {
		fmt.Fprintln(cmd.ErrOrStderr(), "✗ REPORT SIGNATURE INVALID OR TAMPERED")
		return nil, errors.New("cryptographic signature mismatch")
	}
	timestamp, err := attest.EvaluateTimestamp(report, configuredTimestampVerifiers()...)
	if err != nil {
		return nil, fmt.Errorf("report verification failed: the signature is valid, but the timestamp beside it is refused: %w", err)
	}
	if err := reportSchemaError(report); err != nil {
		return nil, err
	}
	fingerprint := report.SignerFingerprint
	if fingerprint == "" && report.PublicKey != "" {
		fingerprint = attest.FingerprintFromHex(report.PublicKey)
	}
	signature := viewSignature{
		Status:            "valid",
		Note:              "signature verified against a signer of the keyring: these contents are exactly what was signed",
		TrustSource:       sanitizeVerifyText(trust.source),
		SignerKey:         sanitizeVerifyText(report.PublicKey),
		SignerFingerprint: sanitizeVerifyText(fingerprint),
	}
	if signer := trust.keyring.FindSigner(report.PublicKey); signer != nil {
		signature.SignerName = sanitizeVerifyText(signer.Name)
		signature.SignerNode = sanitizeVerifyText(signer.Node)
	}
	summary := summarizeTimestamp(timestamp)
	signature.SignatureTimestamp = &summary

	// The signature was verified above, against a signer of the keyring.
	acceptance := accept.Evaluate(report, accept.Expectations{Outcome: accept.OutcomePass, Authenticated: true})
	judged := &viewAcceptance{
		Verdict:         acceptance.Verdict,
		ExpectedOutcome: acceptance.Outcome,
		Bindings:        []string{},
		Reasons:         make([]string, 0, len(acceptance.Reasons)),
		Note:            "internal consistency only, not bound to your plan, node or build: add verify-report --expect-* to bind it",
		Authenticated:   acceptance.Authenticated,
	}
	for _, binding := range acceptance.Bindings {
		judged.Bindings = append(judged.Bindings, sanitizeVerifyText(binding))
	}
	for _, reason := range acceptance.Reasons {
		judged.Reasons = append(judged.Reasons, boundedDiagnostic(reason, 2*maxDiagnosticRunes))
	}
	if len(judged.Reasons) == 0 {
		judged.Reasons = nil
	}
	return buildReportView(report, signature, judged), nil
}

// usableSignatureMembers is whether the signature members a report carries are
// the ones a signed report has: spelled exactly, with a signature and the key
// that made it. Whether the signature verifies is another question.
func usableSignatureMembers(carried []string, report *attest.Report) bool {
	exact := map[string]bool{}
	for _, member := range attest.UnsignedReportMembers() {
		exact[member] = true
	}
	for _, name := range carried {
		if !exact[name] {
			return false
		}
	}
	return report.Signature != "" && report.PublicKey != ""
}

// quotedNames puts each name in quotes.
func quotedNames(names []string) []string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = strconv.Quote(sanitizeVerifyText(name))
	}
	return quoted
}

// reportSchemaError refuses a report whose schema this build cannot read, with
// the reason, as the acceptance verdict of verify-report words it.
func reportSchemaError(report *attest.Report) error {
	if problem := accept.SchemaProblem(report.ReportSchemaVersion); problem != "" {
		return fmt.Errorf("cannot show this report: %s", sanitizeVerifyText(problem))
	}
	return nil
}

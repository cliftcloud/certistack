// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
	"unicode"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// reportViewVersion is the version of the JSON that `report show --json`
// prints. Members are only ever added within a version; a change that removes
// or renames one raises it.
const reportViewVersion = 1

// Bounds on what the text view prints of a report: a signed report may carry
// thousands of records, and a viewer of one must not flood a terminal. The JSON
// view carries every record.
const (
	maxViewVMs         = 200
	maxViewProbesPerVM = 100
	maxViewDisksPerVM  = 50
	maxViewNameRunes   = 80
	maxViewTextRunes   = 200
	// The network diagnostic is the one text of a report that is shown whole
	// (a guest's capture, already cut to 16 KiB and a "[truncated]" mark when
	// the run kept it), so these bound what a hostile report could make the
	// view print: bytes, lines, and the width of one line.
	maxViewDiagnosticBytes     = 16<<10 + 64
	maxViewDiagnosticLines     = 400
	maxViewDiagnosticLineRunes = 300
)

// reportView is what `report show` knows of one report, in a shape that is the
// same for the terminal and for --json. Every string that came from the report
// has been flattened to one line, stripped of control and format characters and
// cut to a length (verify_diagnostics.go): a signature, when there is one,
// says who wrote the text, not that it is safe to print. The one exception is
// the network diagnostic, which is a guest's capture of many lines: it keeps
// its line breaks, each line cleaned and cut the same way, and the whole is
// bounded (viewDiagnostic).
type reportView struct {
	ViewVersion int             `json:"view_version"`
	Signature   viewSignature   `json:"signature"`
	Acceptance  *viewAcceptance `json:"acceptance,omitempty"`
	Report      viewReport      `json:"report"`
}

// viewSignature says whether the signature was checked. Status is
// "unsigned" (the report carries no signature: it is the run's own claim, as the
// Community Edition writes it), "not_checked" (a signed report, but no
// --keyring: the contents are whatever the file says), "malformed" (the report
// carries a signature member that is not a usable signature, so it is neither
// signed nor unsigned) or "valid" (the signature verified against a signer of
// the keyring). An invalid signature is an error and prints no view at all.
type viewSignature struct {
	Status             string                  `json:"status"`
	Note               string                  `json:"note"`
	TrustSource        string                  `json:"trust_source,omitempty"`
	SignerName         string                  `json:"signer_name,omitempty"`
	SignerNode         string                  `json:"signer_node,omitempty"`
	SignerKey          string                  `json:"signer_key,omitempty"`
	SignerFingerprint  string                  `json:"signer_fingerprint,omitempty"`
	SignatureTimestamp *reportTimestampSummary `json:"signature_timestamp,omitempty"`
}

// viewAcceptance is the acceptance verdict of verify-report for the pass
// outcome with no --expect-* flag: the report is internally complete and
// coherent, and it is not bound to a plan, a node or a build.
type viewAcceptance struct {
	Verdict         string   `json:"verdict"`
	ExpectedOutcome string   `json:"expected_outcome"`
	Bindings        []string `json:"bindings"`
	Reasons         []string `json:"reasons,omitempty"`
	Note            string   `json:"note"`
	// Authenticated is whether the signature was verified: always true here, a
	// verdict is only given for a report judged with --keyring.
	Authenticated bool `json:"authenticated"`
}

type viewReport struct {
	ReportID      string `json:"report_id"`
	RunID         string `json:"run_id,omitempty"`
	SchemaVersion string `json:"schema_version"`
	Timestamp     string `json:"timestamp"`
	PlanID        string `json:"plan_id"`
	PlanName      string `json:"plan_name"`
	Environment   string `json:"environment,omitempty"`
	Node          string `json:"node"`
	// Outcome is "pass" when the report records all_passed, else "fail". It is
	// the report's own word: only a checked signature makes it evidence, and
	// only the acceptance verdict says whether it is acceptable evidence.
	Outcome        string `json:"outcome"`
	FailureReason  string `json:"failure_reason,omitempty"`
	ValidationMode string `json:"validation_mode"`
	// TestMode is true for test_skip_integrity: full mapped-image integrity
	// verification was skipped and the report is not production evidence.
	TestMode        bool           `json:"test_mode"`
	ModeSupported   bool           `json:"validation_mode_supported"`
	Engine          viewEngine     `json:"engine"`
	Proxmox         *viewProxmox   `json:"proxmox,omitempty"`
	Frameworks      []string       `json:"frameworks"`
	RetentionDays   int            `json:"retention_days"`
	PBSNamespace    string         `json:"pbs_namespace,omitempty"`
	RTO             viewRTO        `json:"rto"`
	Phases          []viewPhase    `json:"phases,omitempty"`
	VMs             []viewVM       `json:"vms"`
	Teardown        *viewTeardown  `json:"teardown,omitempty"`
	AdmissionPolicy *viewAdmission `json:"admission,omitempty"`
}

type viewEngine struct {
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	BuildDate    string `json:"build_date,omitempty"`
	WorkerSHA256 string `json:"worker_sha256,omitempty"`
}

type viewProxmox struct {
	PVE            string `json:"pve_version,omitempty"`
	PBS            string `json:"pbs_version,omitempty"`
	PBSClient      string `json:"pbs_client_version,omitempty"`
	VersionSupport string `json:"version_support,omitempty"`
}

// viewRTO is the recovery time the run achieved and the objective it was held
// to. TargetMet is absent when the plan set no objective or the report predates
// the schema that records it.
type viewRTO struct {
	Seconds       float64  `json:"seconds"`
	TargetSeconds *float64 `json:"target_seconds,omitempty"`
	TargetMet     *bool    `json:"target_met,omitempty"`
}

type viewPhase struct {
	Key     string  `json:"key"`
	Label   string  `json:"label"`
	Seconds float64 `json:"seconds"`
}

type viewAdmission struct {
	MaxHostRAMPercent      float64 `json:"max_host_ram_percent"`
	MaxHostIOWaitPercent   float64 `json:"max_host_iowait_percent"`
	RecoveryReservationMiB int     `json:"recovery_reservation_mib"`
	RecoveryReservationVMs int     `json:"recovery_reservation_vms"`
	Decision               string  `json:"decision,omitempty"`
}

type viewVM struct {
	VMID       int    `json:"vmid"`
	SourceVMID int    `json:"source_vmid,omitempty"`
	Name       string `json:"name"`
	// Outcome is pass, fail, incomplete or unverified (see vmOutcome).
	Outcome            string  `json:"outcome"`
	VerificationStatus string  `json:"verification_status,omitempty"`
	SourceSnapshot     string  `json:"source_snapshot,omitempty"`
	CryptMode          string  `json:"source_crypt_mode,omitempty"`
	SignatureVerified  bool    `json:"source_signature_verified,omitempty"`
	Consistency        string  `json:"source_consistency,omitempty"`
	ConsistencyDetail  string  `json:"source_consistency_detail,omitempty"`
	CopiedBeforeBoot   bool    `json:"copied_before_boot,omitempty"`
	BootSeconds        float64 `json:"boot_seconds"`
	// NetworkRecovery is what guest network recovery did on the disposable
	// overlay, in the report's words.
	NetworkRecovery viewNetworkRecovery `json:"network_recovery"`
	Disks           []viewDisk          `json:"disks"`
	PBSVerifyStatus string              `json:"pbs_verify_status,omitempty"`
	OmittedDisks    []string            `json:"omitted_source_disks,omitempty"`
	ExcludedDisks   []string            `json:"excluded_source_disks,omitempty"`
	OmittedNICs     []string            `json:"omitted_nics,omitempty"`
	Hardware        string              `json:"hardware,omitempty"`
	Probes          []viewProbe         `json:"probes"`
	Soak            *viewSoak           `json:"soak,omitempty"`
}

type viewNetworkRecovery struct {
	Strategy   string  `json:"strategy,omitempty"`
	Address    string  `json:"address,omitempty"`
	Seconds    float64 `json:"seconds,omitempty"`
	Diagnostic string  `json:"diagnostic,omitempty"`
}

// viewDisk is one restored disk and its integrity result: IntegrityStatus is
// the report's (verified is the only value that means the whole image was read
// back and checksummed, or skipped_test_mode in the test mode), ImageDigest the
// SHA-256 of the whole mapped image.
type viewDisk struct {
	Slot              string `json:"slot"`
	Archive           string `json:"archive,omitempty"`
	IntegrityStatus   string `json:"integrity_status"`
	ImageDigest       string `json:"image_digest,omitempty"`
	ManifestReference string `json:"manifest_reference,omitempty"`
	BootSource        string `json:"boot_source,omitempty"`
}

// viewProbe is one probe: what it asserted (Description, and Type and Target),
// where it ran, and how it ended. Result is pass, fail or skipped.
type viewProbe struct {
	Index           int     `json:"index"`
	Type            string  `json:"type"`
	Target          string  `json:"target"`
	Description     string  `json:"description"`
	Result          string  `json:"result"`
	Origin          string  `json:"origin,omitempty"`
	DurationSeconds float64 `json:"duration_seconds"`
	Attempts        int     `json:"attempts,omitempty"`
	TimeoutSec      int     `json:"timeout_sec,omitempty"`
	Detail          string  `json:"detail,omitempty"`
	Error           string  `json:"error,omitempty"`
}

type viewSoak struct {
	ConfiguredSec int `json:"configured_sec"`
	Samples       int `json:"samples"`
	FailedSamples int `json:"failed_samples"`
}

type viewTeardown struct {
	VMDestroyed             bool     `json:"vm_stopped_and_destroyed"`
	OverlaysRemoved         int      `json:"overlays_removed"`
	LoopDevicesUnmapped     int      `json:"loop_devices_unmapped"`
	SDN                     string   `json:"sdn"`
	OwnedResourcesClean     bool     `json:"owned_resources_clean"`
	AllCleaned              bool     `json:"all_cleaned"`
	JournalRecoveryVerified bool     `json:"journal_recovery_verified"`
	VerifiedAt              string   `json:"verified_at,omitempty"`
	CleanupErrors           []string `json:"cleanup_errors,omitempty"`
	InitialCleanupErrors    []string `json:"initial_cleanup_errors,omitempty"`
}

// The outcomes of one VM record.
const (
	vmPass       = "pass"
	vmFail       = "fail"
	vmIncomplete = "incomplete"
	vmUnverified = "unverified"
)

// vmOutcome is how one VM record ended. Only a record that passed every probe
// and is marked verified is a pass: incomplete means the VM booted but the run
// ended before its probes finished, and unverified that every probe passed but
// none asserted anything in the guest (or the record does not say it was
// verified), so neither can be read as a pass.
func vmOutcome(record probe.VMValidationRecord) string {
	switch {
	case record.AllPassed && record.VerificationStatus == "verified":
		return vmPass
	case record.VerificationStatus == "incomplete":
		return vmIncomplete
	case record.AllPassed:
		return vmUnverified
	}
	return vmFail
}

func viewText(value string, limit int) string { return boundedDiagnostic(value, limit) }

// viewDiagnostic is a VM's network diagnostic as the view shows it: every line
// of it, so a reader can see the guest's services and not the first 300
// characters. It is made safe like any text of a report (control, format and
// private-use characters dropped, every kind of line break made a plain one, a
// tab a space) but its lines stay lines, with their indentation. It is cut at
// maxViewDiagnosticBytes, maxViewDiagnosticLines lines and
// maxViewDiagnosticLineRunes characters a line, and a cut ends with a line that
// says where the whole text is.
func viewDiagnostic(value string) string {
	cut := false
	if len(value) > maxViewDiagnosticBytes {
		value, cut = strings.ToValidUTF8(value[:maxViewDiagnosticBytes], ""), true
	}
	value = strings.NewReplacer("\r\n", "\n", "\r", "\n", "\v", "\n", "\f", "\n", "\u0085", "\n", "\u2028", "\n", "\u2029", "\n").Replace(value)
	var lines []string
	for _, line := range strings.Split(value, "\n") {
		var clean []rune
		for _, r := range line {
			switch {
			case r == '\t' || unicode.Is(unicode.Zs, r):
				r = ' '
			case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r) || unicode.Is(unicode.Cs, r):
				continue
			}
			clean = append(clean, r)
		}
		text := strings.TrimRight(string(clean), " ")
		if len([]rune(text)) > maxViewDiagnosticLineRunes {
			text, cut = string([]rune(text)[:maxViewDiagnosticLineRunes])+"…", true
		}
		lines = append(lines, text)
	}
	if len(lines) > maxViewDiagnosticLines {
		lines, cut = lines[:maxViewDiagnosticLines], true
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for len(lines) > 0 && lines[0] == "" {
		lines = lines[1:]
	}
	text := strings.Join(lines, "\n")
	if cut && text != "" {
		text += "\n[cut here: the whole text is the network_recovery_diagnostic of this VM in the report file]"
	}
	return text
}

// reportPhases lists the report's phase timings in the order a run takes them.
func reportPhases(timings *attest.PhaseTimings) []viewPhase {
	if timings == nil {
		return nil
	}
	return []viewPhase{
		{"admission_check_sec", "Host admission", timings.AdmissionCheckSec},
		{"sdn_provisioning_sec", "SDN sandbox setup", timings.SDNProvisioningSec},
		{"pbs_mapping_sec", "PBS image mapping", timings.PBSMappingSec},
		{"overlay_creation_sec", "Overlay creation", timings.OverlayCreationSec},
		{"cow_guest_network_recovery_sec", "Guest network preparation", timings.COWGuestNetworkRecoverySec},
		{"integrity_verification_sec", "Image integrity scan", timings.IntegrityVerificationSec},
		{"vm_registration_sec", "VM registration", timings.VMRegistrationSec},
		{"vm_start_sec", "VM start and boot", timings.VMStartSec},
		{"qmp_running_wait_sec", "QMP running wait", timings.QMPRunningWaitSec},
		{"startup_grace_period_sec", "Startup grace", timings.StartupGracePeriodSec},
		{"probes_execution_sec", "Probes", timings.ProbesExecutionSec},
		{"soak_time_sec", "Tier soak", timings.SoakTimeSec},
		{"teardown_sec", "Teardown (after the RTO)", timings.TeardownSec},
		{"total_rto_sec", "Total", timings.TotalRTOSec},
	}
}

// buildReportView makes the view of a decoded report. signature says how far
// the report was checked; acceptance is nil when it was not.
func buildReportView(report *attest.Report, signature viewSignature, acceptance *viewAcceptance) *reportView {
	view := &reportView{ViewVersion: reportViewVersion, Signature: signature, Acceptance: acceptance}
	r := &view.Report
	r.ReportID = viewText(report.ReportID, maxViewNameRunes)
	r.RunID = viewText(report.RunID, maxViewNameRunes)
	r.SchemaVersion = viewText(report.ReportSchemaVersion, maxVersionRunes)
	r.Timestamp = viewText(report.Timestamp, maxVersionRunes)
	r.PlanID = viewText(report.PlanID, maxViewNameRunes)
	r.PlanName = viewText(report.PlanName, maxViewTextRunes)
	r.Environment = viewText(report.Environment, maxViewNameRunes)
	r.Node = viewText(report.NodeFQDN, maxViewNameRunes)
	r.Outcome = "fail"
	if report.AllPassed {
		r.Outcome = "pass"
	}
	r.FailureReason = boundedDiagnostic(report.FailureReason, maxFailureReasonRunes)
	r.ValidationMode = viewText(report.ValidationMode, maxViewNameRunes)
	r.TestMode = report.ValidationMode == attest.ValidationModeTestSkipIntegrity
	r.ModeSupported = report.ValidationMode == attest.ValidationModeFullIntegrity || r.TestMode
	r.Engine = viewEngine{
		Version:      viewText(report.EngineVersion, maxVersionRunes),
		Commit:       viewText(report.GitCommit, maxVersionRunes),
		BuildDate:    viewText(report.BuildDate, maxVersionRunes),
		WorkerSHA256: viewText(report.WorkerSHA256, 80),
	}
	if report.PVEVersion != "" || report.PBSVersion != "" || report.PBSClientVersion != "" || report.VersionSupport != "" {
		r.Proxmox = &viewProxmox{
			PVE: viewText(report.PVEVersion, maxVersionRunes), PBS: viewText(report.PBSVersion, maxVersionRunes),
			PBSClient: viewText(report.PBSClientVersion, maxVersionRunes), VersionSupport: viewText(report.VersionSupport, maxVersionRunes),
		}
	}
	r.Frameworks = make([]string, 0, len(report.Frameworks))
	for _, framework := range report.Frameworks {
		r.Frameworks = append(r.Frameworks, viewText(framework, maxViewNameRunes))
	}
	r.RetentionDays = report.RetentionDays
	r.PBSNamespace = viewText(report.PBSNamespace, maxViewNameRunes)
	r.RTO = viewRTO{Seconds: report.RTOSeconds}
	if report.RTOTargetSeconds != nil && accept.SchemaMinor(report.ReportSchemaVersion) >= accept.PolicyEvidenceSchemaMinor {
		target := *report.RTOTargetSeconds
		met := report.RTOSeconds <= target
		r.RTO.TargetSeconds, r.RTO.TargetMet = &target, &met
	}
	r.Phases = reportPhases(report.PhaseTimings)
	if admitted := report.Admission; admitted != nil {
		r.AdmissionPolicy = &viewAdmission{
			MaxHostRAMPercent: admitted.MaxHostRAMPercent, MaxHostIOWaitPercent: admitted.MaxHostIOWaitPercent,
			RecoveryReservationMiB: admitted.RecoveryReservationMiB, RecoveryReservationVMs: admitted.RecoveryReservationVMs,
		}
		if admitted.Evaluation != nil {
			r.AdmissionPolicy.Decision = viewText(admitted.Evaluation.Decision, maxViewNameRunes)
		}
	}
	r.VMs = make([]viewVM, 0, len(report.VMRecords))
	for _, record := range report.VMRecords {
		r.VMs = append(r.VMs, buildVMView(record))
	}
	if evidence := report.TeardownEvidence; evidence != nil {
		r.Teardown = &viewTeardown{
			VMDestroyed: evidence.VMStoppedAndDestroyed, OverlaysRemoved: len(evidence.OverlayFilesRemoved),
			LoopDevicesUnmapped: len(evidence.LoopDevicesUnmapped), OwnedResourcesClean: evidence.OrphanSweepClean,
			AllCleaned: evidence.AllCleaned, JournalRecoveryVerified: evidence.JournalRecoveryVerified,
			VerifiedAt: viewText(evidence.VerifiedAt, maxVersionRunes), SDN: describeSDN(evidence),
			CleanupErrors: boundedDiagnostics(evidence.CleanupErrors), InitialCleanupErrors: boundedDiagnostics(evidence.InitialCleanupErrors),
		}
		if len(r.Teardown.CleanupErrors) == 0 {
			r.Teardown.CleanupErrors = nil
		}
		if len(r.Teardown.InitialCleanupErrors) == 0 {
			r.Teardown.InitialCleanupErrors = nil
		}
	}
	return view
}

// describeSDN says what the run did with the sandbox network it used.
func describeSDN(evidence *attest.TeardownEvidence) string {
	if evidence.SDNProvisioning == "preprovisioned" {
		return fmt.Sprintf("kept (platform-owned): zone %s, VNet %s, validated and not modified",
			viewText(evidence.SDNZoneValidated, maxViewNameRunes), viewText(evidence.SDNVNetValidated, maxViewNameRunes))
	}
	zone, vnet := viewText(evidence.SDNZoneRemoved, maxViewNameRunes), viewText(evidence.SDNVNetRemoved, maxViewNameRunes)
	if zone == "" && vnet == "" {
		return "none was created"
	}
	return fmt.Sprintf("removed: zone %s, VNet %s", orNone(zone), orNone(vnet))
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func buildVMView(record probe.VMValidationRecord) viewVM {
	seconds := record.BootDurationSeconds
	if seconds == 0 && record.BootDuration > 0 {
		seconds = record.BootDuration.Seconds()
	}
	vm := viewVM{
		VMID: record.VMID, SourceVMID: record.SourceVMID, Name: viewText(record.Name, maxViewNameRunes),
		Outcome: vmOutcome(record), VerificationStatus: viewText(record.VerificationStatus, maxViewNameRunes),
		SourceSnapshot: viewText(record.SourceSnapshot, maxViewTextRunes), CryptMode: viewText(record.SourceCryptMode, maxViewNameRunes),
		SignatureVerified: record.SourceSignatureVerified, Consistency: viewText(record.SourceConsistency, maxViewNameRunes),
		ConsistencyDetail: viewText(record.SourceConsistencyDetail, maxViewTextRunes), CopiedBeforeBoot: record.CopiedBeforeBoot,
		BootSeconds: seconds,
		NetworkRecovery: viewNetworkRecovery{
			Strategy: viewText(record.NetworkRecoveryStrategy, maxViewNameRunes), Address: viewText(record.NetworkRecoveryAddress, maxViewNameRunes),
			Seconds: record.NetworkRecoverySeconds, Diagnostic: viewDiagnostic(record.NetworkRecoveryDiagnostic),
		},
		PBSVerifyStatus: viewText(record.PBSVerifyStatus, maxViewTextRunes),
		OmittedDisks:    viewTexts(record.OmittedSourceDisks), ExcludedDisks: viewTexts(record.ExcludedSourceDisks), OmittedNICs: viewTexts(record.OmittedNICs),
		Disks:  make([]viewDisk, 0, len(record.SourceDisks)),
		Probes: make([]viewProbe, 0, len(record.ProbeResults)),
	}
	for _, disk := range record.SourceDisks {
		vm.Disks = append(vm.Disks, viewDisk{
			Slot: viewText(disk.Slot, maxViewNameRunes), Archive: viewText(disk.Archive, maxViewNameRunes),
			IntegrityStatus: viewText(disk.IntegrityStatus, maxViewNameRunes), ImageDigest: viewText(disk.ImageDigest, 80),
			ManifestReference: viewText(disk.ManifestReference, maxViewNameRunes), BootSource: viewText(disk.BootSource, maxViewNameRunes),
		})
	}
	if hardware := record.RestoredHardware; hardware != nil {
		vm.Hardware = describeHardware(hardware)
	}
	for index, result := range record.ProbeResults {
		outcome := "pass"
		switch {
		case result.Skipped:
			outcome = "skipped"
		case !result.Passed:
			outcome = "fail"
		}
		vm.Probes = append(vm.Probes, viewProbe{
			Index: index + 1, Type: viewText(result.Type, 40), Target: viewText(result.Target, maxViewTextRunes),
			Description: viewText(result.Description, maxViewTextRunes), Result: outcome, Origin: viewText(result.Origin, 40),
			DurationSeconds: result.Duration.Seconds(), Attempts: result.Attempts, TimeoutSec: result.TimeoutSec,
			Detail: viewText(result.Detail, maxDiagnosticRunes), Error: viewText(result.Error, maxDiagnosticRunes),
		})
	}
	if soak := record.Soak; soak != nil {
		vm.Soak = &viewSoak{ConfiguredSec: soak.ConfiguredSec, Samples: soak.Samples, FailedSamples: soak.FailedSamples}
	}
	return vm
}

func viewTexts(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	if len(values) > maxDiagnosticItems {
		values = values[:maxDiagnosticItems]
	}
	texts := make([]string, len(values))
	for index, value := range values {
		texts[index] = viewText(value, maxViewNameRunes)
	}
	return texts
}

func describeHardware(hardware *probe.RestoredHardware) string {
	parts := []string{fmt.Sprintf("%d socket(s) x %d core(s)", max(hardware.Sockets, 1), hardware.Cores), fmt.Sprintf("%d MiB", hardware.MemoryMB)}
	if hardware.CPU != "" {
		parts = append(parts, "cpu "+viewText(hardware.CPU, maxViewNameRunes))
	}
	if hardware.BootDisk != "" {
		parts = append(parts, "boot disk "+viewText(hardware.BootDisk, maxViewNameRunes))
	}
	if hardware.FromBackupConfig {
		parts = append(parts, "hardware from the backup's configuration")
	}
	return strings.Join(parts, ", ")
}

// humanDuration writes a number of seconds the way a person reads a recovery
// time: "0.50 s", "33.1 s", "5m 43s", "1h 02m".
func humanDuration(seconds float64) string {
	switch {
	case math.IsNaN(seconds) || math.IsInf(seconds, 0):
		return "unknown"
	case seconds < 0:
		return "unknown"
	case seconds < 1:
		return fmt.Sprintf("%.2f s", seconds)
	case seconds < 60:
		return fmt.Sprintf("%.1f s", seconds)
	case seconds < 3600:
		whole := int(math.Round(seconds))
		return fmt.Sprintf("%dm %02ds", whole/60, whole%60)
	}
	whole := int(math.Round(seconds / 60))
	return fmt.Sprintf("%dh %02dm", whole/60, whole%60)
}

// textRows writes labelled rows with the labels in a column.
type textRows struct {
	out   io.Writer
	label int
}

func (r textRows) row(label, format string, args ...any) {
	fmt.Fprintf(r.out, "%-*s %s\n", r.label, label, fmt.Sprintf(format, args...))
}

func (r textRows) cont(format string, args ...any) {
	fmt.Fprintf(r.out, "%-*s %s\n", r.label, "", fmt.Sprintf(format, args...))
}

func upperOutcome(outcome string) string { return strings.ToUpper(outcome) }

// renderReportView writes the terminal summary of a view.
func renderReportView(out io.Writer, view *reportView) {
	r := &view.Report
	fmt.Fprintf(out, "CertiStack report %s\n", orNone(r.ReportID))
	switch {
	case r.TestMode:
		fmt.Fprintln(out, "\n*** TEST-MODE REPORT: full mapped-image integrity verification was SKIPPED. This is not production evidence. ***")
	case !r.ModeSupported:
		fmt.Fprintf(out, "\n*** UNSUPPORTED VALIDATION MODE %q: this report cannot be accepted as evidence. ***\n", r.ValidationMode)
	}
	fmt.Fprintln(out)

	rows := textRows{out: out, label: 14}
	signature := view.Signature
	if signature.Status == "valid" {
		rows.row("Signature:", "VALID, by a trusted signer (%s)", signature.SignerName)
		if signature.SignerNode != "" {
			rows.cont("signer node %s", signature.SignerNode)
		}
		rows.cont("key %s", signature.SignerKey)
		rows.cont("fingerprint %s", signature.SignerFingerprint)
		rows.cont("trust source %s", signature.TrustSource)
		if signature.SignatureTimestamp != nil {
			note := signature.SignatureTimestamp.Note
			if note == "" {
				note = signature.SignatureTimestamp.Status
			}
			rows.cont("signature timestamp: %s", note)
		}
	} else if signature.Status == "unsigned" {
		rows.row("Signature:", "none: this report is unsigned (the Community Edition writes its reports unsigned): its contents are the run's own claim, not authenticated evidence.")
		if outcome, fits := judgedOutcome(r); fits {
			rows.cont("Judge it: certistack verify-report --unsigned --expect-outcome %s <report.json>", outcome)
		} else {
			rows.cont("Judge it: no verify-report outcome accepts it: the run stopped before any restore, and not for capacity (the reason below says why).")
		}
	} else if signature.Status == "malformed" {
		rows.row("Signature:", "MALFORMED: %s.", signature.Note)
		rows.cont("Neither verify-report --unsigned nor verify-report --keyring will accept it: do not rely on its contents.")
	} else {
		rows.row("Signature:", "signature NOT checked (no --keyring): this is what the file says, not verified evidence.")
		if outcome, _ := judgedOutcome(r); outcome == accept.OutcomeDenied {
			rows.cont("Check it: certistack verify-report --keyring <trusted-signers> --expect-outcome denied <report.json>")
		} else {
			rows.cont("Check it: certistack verify-report --keyring <trusted-signers> <report.json>")
		}
	}
	if acceptance := view.Acceptance; acceptance != nil {
		rows.row("Acceptance:", "%s as %s evidence (%s)", strings.ToUpper(acceptance.Verdict), acceptance.ExpectedOutcome, acceptance.Note)
		for index, reason := range acceptance.Reasons {
			if index == maxDiagnosticItems {
				rows.cont("- and %d more (see verify-report)", len(acceptance.Reasons)-maxDiagnosticItems)
				break
			}
			rows.cont("- %s", reason)
		}
		if outcome, _ := judgedOutcome(r); outcome == accept.OutcomeDenied && acceptance.ExpectedOutcome != outcome {
			rows.cont("As a capacity refusal: certistack verify-report --keyring <trusted-signers> --expect-outcome denied <report.json>")
		}
	}
	outcome := upperOutcome(r.Outcome)
	if signature.Status != "valid" {
		outcome += " (as the file states)"
	}
	rows.row("Outcome:", "%s", outcome)
	if r.FailureReason != "" {
		rows.row("Reason:", "%s", r.FailureReason)
	}
	fmt.Fprintln(out)

	rows.row("Plan:", "%s %q", r.PlanID, r.PlanName)
	if r.Environment != "" {
		rows.row("Environment:", "%s", r.Environment)
	}
	rows.row("Node:", "%s", orNone(r.Node))
	when := orNone(r.Timestamp)
	if r.RunID != "" {
		when += " (" + r.RunID + ")"
	}
	rows.row("When:", "%s", when)
	engine := orNone(r.Engine.Version)
	if r.Engine.Commit != "" {
		engine += ", commit " + r.Engine.Commit
	}
	if r.Engine.BuildDate != "" {
		engine += ", built " + r.Engine.BuildDate
	}
	rows.row("Engine:", "%s", engine)
	if proxmox := r.Proxmox; proxmox != nil {
		line := fmt.Sprintf("PVE %s, PBS %s, proxmox-backup-client %s", orUnknown(proxmox.PVE), orUnknown(proxmox.PBS), orUnknown(proxmox.PBSClient))
		if proxmox.VersionSupport != "" {
			line += " (" + proxmox.VersionSupport + ")"
		}
		rows.row("Proxmox:", "%s", line)
	}
	switch {
	case r.ValidationMode == attest.ValidationModeFullIntegrity && len(r.VMs) == 0:
		rows.row("Validation:", "full_integrity, but no disk image was read: the run stopped before any restore")
	case r.ValidationMode == attest.ValidationModeFullIntegrity:
		rows.row("Validation:", "full_integrity: every mapped disk image was read back and checksummed")
	case r.TestMode:
		rows.row("Validation:", "TEST MODE (test_skip_integrity): the integrity scan was skipped")
	default:
		rows.row("Validation:", "%q (not a supported mode)", r.ValidationMode)
	}
	rows.row("Frameworks:", "%s (labels, not a certification; retention %d days)", strings.Join(r.Frameworks, ", "), r.RetentionDays)
	rows.row("Schema:", "%s", orNone(r.SchemaVersion))
	fmt.Fprintln(out)

	rto := humanDuration(r.RTO.Seconds) + fmt.Sprintf(" (%.2f s)", r.RTO.Seconds)
	switch {
	case len(r.VMs) == 0:
		// Nothing was restored, so there is no recovery time, whatever an
		// older report recorded; the phases say where the time went.
		rto = "none: no VM was restored"
	case r.RTO.TargetSeconds != nil && r.RTO.TargetMet != nil && *r.RTO.TargetMet:
		rto += fmt.Sprintf("; objective %s, met", humanDuration(*r.RTO.TargetSeconds))
	case r.RTO.TargetSeconds != nil:
		rto += fmt.Sprintf("; objective %s, EXCEEDED", humanDuration(*r.RTO.TargetSeconds))
	case accept.SchemaMinor(r.SchemaVersion) >= accept.PolicyEvidenceSchemaMinor:
		rto += "; no objective set"
	default:
		rto += "; objective not recorded (older schema)"
	}
	rows.row("RTO:", "%s", rto)
	var shown int
	for _, phase := range r.Phases {
		if phase.Seconds <= 0 || (phase.Key == "total_rto_sec" && len(r.VMs) == 0) {
			continue
		}
		label := phase.Label
		if phase.Key == "total_rto_sec" {
			label += " (the RTO)"
		}
		if shown == 0 {
			fmt.Fprintln(out, "  Where the time went:")
		}
		shown++
		fmt.Fprintf(out, "    %-28s %s\n", label, humanDuration(phase.Seconds))
	}
	if admitted := r.AdmissionPolicy; admitted != nil {
		// The memory is reserved only when admission granted the run; a refusal,
		// or a run that stopped before admission, reserved none.
		line := fmt.Sprintf("limits RAM %.1f%%, I/O wait %.1f%%; ", admitted.MaxHostRAMPercent, admitted.MaxHostIOWaitPercent)
		reservation := fmt.Sprintf("%d MiB for %d VM(s)", admitted.RecoveryReservationMiB, admitted.RecoveryReservationVMs)
		switch {
		case admitted.Decision == admission.DecisionGranted, admitted.Decision == "" && len(r.VMs) > 0:
			line += "reserved " + reservation
		case admitted.Decision == "":
			line += "needs " + reservation + ", not reserved: the run stopped before admission"
		default:
			line += "needs " + reservation + ", not reserved"
		}
		if admitted.Decision != "" {
			line += "; " + admitted.Decision
		}
		rows.row("Admission:", "%s", line)
	}

	fmt.Fprintf(out, "\nVMs (%d):\n", len(r.VMs))
	if len(r.VMs) == 0 {
		fmt.Fprintln(out, "  none: the report records no VM, so no recovery was validated.")
	}
	for index, vm := range r.VMs {
		if index == maxViewVMs {
			fmt.Fprintf(out, "\n  ... and %d more VM(s); use --json for all of them.\n", len(r.VMs)-maxViewVMs)
			break
		}
		renderVMView(out, vm)
	}

	if teardown := r.Teardown; teardown != nil {
		fmt.Fprintln(out, "\nTeardown:")
		state := "cleanup verified"
		if !teardown.AllCleaned {
			state = "CLEANUP NOT VERIFIED"
		}
		fmt.Fprintf(out, "  %s (at %s)\n", state, orNone(teardown.VerifiedAt))
		// A VM's record exists from the start of its restore, before its VM
		// is made: a report with none made no sandbox VM.
		vm := "sandbox VM destroyed: " + plainYesNo(teardown.VMDestroyed)
		if len(r.VMs) == 0 {
			vm = "sandbox VM: none was created"
		}
		fmt.Fprintf(out, "  %s; %d overlay disk(s) removed; %d loop device(s) unmapped\n", vm, teardown.OverlaysRemoved, teardown.LoopDevicesUnmapped)
		fmt.Fprintf(out, "  sandbox network: %s\n", teardown.SDN)
		fmt.Fprintf(out, "  every resource the run owned confirmed removed: %s; confirmed from the node's journal: %s\n", yesNo(teardown.OwnedResourcesClean), yesNo(teardown.JournalRecoveryVerified))
		for _, list := range []struct {
			title  string
			errors []string
		}{{"cleanup errors", teardown.CleanupErrors}, {"cleanup errors before the run", teardown.InitialCleanupErrors}} {
			for _, text := range list.errors {
				fmt.Fprintf(out, "  %s: %s\n", list.title, text)
			}
		}
	} else {
		fmt.Fprintln(out, "\nTeardown: the report has no teardown evidence, so cleanup of the run's temporary resources is unknown.")
	}
}

// judgedOutcome is the verify-report outcome a report is judged as, and
// whether one fits it: pass for a run that records a pass, and denied for a run
// refused for capacity before any VM was restored. Any other run that stopped
// before a restore fits none. A run that failed with its VMs is judged as a
// pass, which it is not: the verdict says why.
func judgedOutcome(r *viewReport) (string, bool) {
	switch {
	case r.Outcome == "pass":
		return accept.OutcomePass, true
	case len(r.VMs) == 0 && accept.CapacityDenial(r.FailureReason):
		return accept.OutcomeDenied, true
	case len(r.VMs) == 0:
		return "", false
	}
	return accept.OutcomePass, true
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func plainYesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "NO"
}

func renderVMView(out io.Writer, vm viewVM) {
	title := fmt.Sprintf("VM %d %q", vm.VMID, vm.Name)
	fmt.Fprintf(out, "\n  %s  %s\n", title, vmOutcomeLabel(vm))
	rows := textRows{out: out, label: 18}
	indent := func(label, format string, args ...any) {
		fmt.Fprintf(out, "    %-*s %s\n", rows.label, label, fmt.Sprintf(format, args...))
	}
	source := "source VM not recorded"
	if vm.SourceVMID > 0 {
		source = fmt.Sprintf("source VM %d", vm.SourceVMID)
	}
	if vm.SourceSnapshot != "" {
		source += ", snapshot " + vm.SourceSnapshot
	} else {
		source += ", snapshot not recorded"
	}
	indent("Restored from:", "%s", source)
	if vm.CryptMode != "" || vm.Consistency != "" {
		backup := []string{}
		if vm.CryptMode != "" {
			protection := "crypt mode " + vm.CryptMode
			if vm.SignatureVerified {
				protection += ", manifest signature verified"
			}
			backup = append(backup, protection)
		}
		if vm.Consistency != "" {
			consistency := vm.Consistency
			if vm.ConsistencyDetail != "" {
				consistency += " (" + vm.ConsistencyDetail + ")"
			}
			backup = append(backup, consistency)
		}
		indent("Backup:", "%s", strings.Join(backup, "; "))
	}
	recovery := vm.NetworkRecovery
	switch {
	case recovery.Strategy == "":
		indent("Network recovery:", "none recorded (no network profile was written into the guest's overlay)")
	default:
		line := recovery.Strategy
		if recovery.Address != "" {
			line += ", sandbox address " + recovery.Address
		}
		if recovery.Seconds > 0 {
			line += ", " + humanDuration(recovery.Seconds) + " of offline preparation"
		}
		indent("Network recovery:", "%s", line)
	}
	if vm.Hardware != "" {
		indent("Hardware:", "%s", vm.Hardware)
	}
	if vm.BootSeconds > 0 {
		indent("Boot:", "%s to hypervisor readiness", humanDuration(vm.BootSeconds))
	}
	if len(vm.Disks) == 0 {
		indent("Integrity:", "NO disk evidence recorded")
	}
	for index, disk := range vm.Disks {
		if index == maxViewDisksPerVM {
			indent("", "... and %d more disk(s)", len(vm.Disks)-maxViewDisksPerVM)
			break
		}
		label := ""
		if index == 0 {
			label = "Integrity:"
		}
		line := fmt.Sprintf("%s %s", disk.Slot, disk.IntegrityStatus)
		if disk.ImageDigest != "" {
			line += ", sha256 " + disk.ImageDigest
		}
		if disk.BootSource == "local-copy" {
			line += ", booted from a verified local copy"
		}
		indent(label, "%s", line)
	}
	if status := digestSuffix.ReplaceAllString(vm.PBSVerifyStatus, ""); status != "" {
		indent("", "%s", status)
	}
	if len(vm.OmittedDisks) > 0 {
		indent("NOT restored:", "disk(s) %s (the plan chose not to restore them)", strings.Join(vm.OmittedDisks, ", "))
	}
	if len(vm.ExcludedDisks) > 0 {
		indent("NOT in the backup:", "disk(s) %s (excluded from backups)", strings.Join(vm.ExcludedDisks, ", "))
	}
	if len(vm.OmittedNICs) > 0 {
		indent("NOT attached:", "NIC(s) %s", strings.Join(vm.OmittedNICs, ", "))
	}
	fmt.Fprintf(out, "    Probes (%d):\n", len(vm.Probes))
	for index, result := range vm.Probes {
		if index == maxViewProbesPerVM {
			fmt.Fprintf(out, "      ... and %d more probe(s); use --json for all of them.\n", len(vm.Probes)-maxViewProbesPerVM)
			break
		}
		where := probeOriginLabel(result.Origin)
		took := humanDuration(result.DurationSeconds)
		switch {
		case result.Attempts == 1:
			took += ", 1 attempt"
		case result.Attempts > 1:
			took += fmt.Sprintf(", %d attempts", result.Attempts)
		}
		fmt.Fprintf(out, "      %-4s %s %s  (%s, %s)\n", strings.ToUpper(result.Result), result.Type, result.Target, where, took)
		fmt.Fprintf(out, "           asserts: %s\n", orNone(result.Description))
		if result.Detail != "" {
			fmt.Fprintf(out, "           result:  %s\n", result.Detail)
		}
		if result.Error != "" {
			fmt.Fprintf(out, "           error:   %s\n", result.Error)
		}
	}
	if soak := vm.Soak; soak != nil {
		indent("Soak:", "%d service check(s) over %d s, %d failed", soak.Samples, soak.ConfiguredSec, soak.FailedSamples)
	}
	if recovery.Diagnostic != "" {
		fmt.Fprintln(out, "    Network diagnostic (taken inside the guest):")
		for _, line := range strings.Split(recovery.Diagnostic, "\n") {
			if line == "" {
				fmt.Fprintln(out)
				continue
			}
			fmt.Fprintf(out, "      %s\n", line)
		}
	}
}

// digestSuffix is the image digest the PBS verification status ends with, which
// the per-disk lines already print.
var digestSuffix = regexp.MustCompile(`;? ?SHA-256 [0-9a-f]{64}$`)

// probeOriginLabel says where a probe's assertion ran, in the words of the
// report's origin member.
func probeOriginLabel(origin string) string {
	switch origin {
	case "worker_host":
		return "from the worker host over the sandbox network"
	case "guest_qga":
		return "inside the guest, through the guest agent"
	case "hypervisor_qmp":
		return "at the hypervisor"
	case "":
		return "origin not recorded"
	}
	return origin
}

func vmOutcomeLabel(vm viewVM) string {
	switch vm.Outcome {
	case vmPass:
		return "PASS"
	case vmIncomplete:
		return "INCOMPLETE (the run ended before its probes finished)"
	case vmUnverified:
		return "NOT VERIFIED (status " + orNone(vm.VerificationStatus) + ": nothing was asserted in the guest, or it is not marked verified)"
	}
	return "FAIL"
}

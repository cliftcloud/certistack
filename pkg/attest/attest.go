// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/google/uuid"
	"github.com/gowebpki/jcs"
)

// PhaseTimings provides granular duration measurements explaining the end-to-end RTO.
type PhaseTimings struct {
	AdmissionCheckSec  float64 `json:"admission_check_sec"`
	SDNProvisioningSec float64 `json:"sdn_provisioning_sec"`
	PBSMappingSec      float64 `json:"pbs_mapping_sec"`
	OverlayCreationSec float64 `json:"overlay_creation_sec"`
	// COWGuestNetworkRecoverySec is offline guestfs work performed only on
	// disposable overlays to make the isolated recovery NIC usable. Keeping it
	// separate prevents a large, legitimate compatibility cost from being
	// misattributed to mapping, VM boot, or unexplained RTO overhead.
	COWGuestNetworkRecoverySec float64 `json:"cow_guest_network_recovery_sec"`
	VMRegistrationSec          float64 `json:"vm_registration_sec"`
	VMStartSec                 float64 `json:"vm_start_sec"`
	QMPRunningWaitSec          float64 `json:"qmp_running_wait_sec"`
	// IntegrityVerificationSec is the full mapped-image SHA-256 scan. On a
	// full_integrity run it is usually the largest single phase.
	IntegrityVerificationSec float64 `json:"integrity_verification_sec,omitempty"`
	StartupGracePeriodSec    float64 `json:"startup_grace_period_sec"`
	ProbesExecutionSec       float64 `json:"probes_execution_sec"`
	SoakTimeSec              float64 `json:"soak_time_sec,omitempty"`
	TeardownSec              float64 `json:"teardown_sec"`
	TotalRTOSec              float64 `json:"total_rto_sec"`
}

// TeardownEvidence provides verifiable proof that ephemeral testing artifacts were cleanly destroyed.
type TeardownEvidence struct {
	VMStoppedAndDestroyed bool     `json:"vm_stopped_and_destroyed"`
	OverlayFilesRemoved   []string `json:"overlay_files_removed"`
	LoopDevicesUnmapped   []string `json:"loop_devices_unmapped"`
	// SDNProvisioning records whether the run owned an ephemeral sandbox or
	// validated a platform-owned preprovisioned sandbox.
	SDNProvisioning    string `json:"sdn_provisioning,omitempty"`
	SDNVNetRemoved     string `json:"sdn_vnet_removed"`
	SDNZoneRemoved     string `json:"sdn_zone_removed"`
	SDNVNetValidated   string `json:"sdn_vnet_validated,omitempty"`
	SDNZoneValidated   string `json:"sdn_zone_validated,omitempty"`
	SDNClusterReloaded bool   `json:"sdn_cluster_reloaded"`
	// OrphanSweepClean keeps its historical name for schema compatibility. It
	// records that every resource this run recorded as owned was cleaned; no
	// host-wide sweep exists (verify-report labels it "Owned Resources Clean").
	OrphanSweepClean     bool     `json:"orphan_sweep_clean"`
	AllCleaned           bool     `json:"all_cleaned"`
	CleanupErrors        []string `json:"cleanup_errors,omitempty"`
	InitialCleanupErrors []string `json:"initial_cleanup_errors,omitempty"`
	// JournalRecoveryVerified records that the controller independently
	// checked (and, if necessary, forced) reconciliation of the worker's
	// durable resource journal after the run, rather than trusting AllCleaned
	// as reported by the worker. It is set after that check completes
	// successfully, whether or not the worker's own report already claimed
	// AllCleaned: true.
	JournalRecoveryVerified bool   `json:"journal_recovery_verified,omitempty"`
	VerifiedAt              string `json:"verified_at"`
}

// CurrentReportSchemaVersion defines the active JSON schema specification for audit certificates.
//
// Every minor change is additive, and a verifier accepts 1.0 through the
// highest minor it knows, so an older verifier refuses a newer report loudly
// (cmd/certistack reportSchemaProblem) rather than judge evidence it cannot
// read. 1.6 adds, all omitempty: report run_id (the run's node journal ID, chosen
// by the controller), plan_sha256 and worker_sha256; probe
// result server_name, source_interface, source_address, require_qga,
// timeout_sec, retries, attempts and image_sha256; and restored_hardware
// cpu_weight. A VM record also
// names its backup from the start of its restore, with the integrity_status
// values not_attempted, mapped, map_failed, verification_failed and
// restore_failed beside verified and skipped_test_mode. 1.7 adds the
// policy a run is judged by: the report's rto_target_seconds (the recovery time
// objective; absent means the plan set none) and admission (the host admission
// limits, the recovery memory reserved and what the last admission check
// measured and decided), so a pass states the objective and the limits it
// passed under; and, omitempty, a VM record's soak: what the
// tier's soak period established about the VM's services, checked by
// repeating their probes and not only by asking PVE whether the VM still
// runs, with the status_reads, status_read_failures and first_status_error of
// PVE's answers about the VM.
// 1.7 also adds validated_plan_sha256, resolved_plan_sha256 and
// plan_digest_format for complete canonical worker policy before and after
// backup resolution; required_available_mib with the
// preflight_denied_memory decision for an early memory refusal; and, all
// omitempty, restored_hardware boot_order (the sandbox VM's whole boot order,
// as sent to PVE, beside boot_disk), the report's pve_version, pbs_version,
// pbs_client_version and version_support (the Proxmox versions the run read
// on its node and whether that pair is a tested one), and the optional
// signature_timestamp, a trusted timestamp over the signature that is carried
// beside it and is not signed (see timestamp.go).
const CurrentReportSchemaVersion = "1.7"

// ErrInvalidSignature indicates that a report was well-formed but its
// cryptographic signature did not authenticate the canonical payload.
var ErrInvalidSignature = errors.New("invalid report signature")

// ErrReportUnsigned is what VerifyReport and VerifyReportSignatureOnly return for
// a report with no signature. The Community Edition writes its reports unsigned,
// so a caller that expects one (DecodeUnsignedReport) says so; every other caller
// refuses it, because a signature taken off a report must never read as a report
// that was verified.
var ErrReportUnsigned = errors.New("report is unsigned (no signature present)")

const (
	// ValidationModeFullIntegrity is the default production validation mode. Every
	// mapped PBS image is read and verified before the service probes run.
	ValidationModeFullIntegrity = "full_integrity"
	// ValidationModeTestSkipIntegrity records the explicitly requested lab-only
	// shortcut. It is signed evidence that this result is not a full integrity
	// validation and must not be used as production compliance evidence.
	ValidationModeTestSkipIntegrity = "test_skip_integrity"
)

// Report represents a non-repudiable audit certificate for disaster recovery compliance.
type Report struct {
	ReportSchemaVersion string `json:"report_schema_version,omitempty"` // Schema specification version
	ReportID            string `json:"report_id"`                       // UUIDv4
	RunID               string `json:"run_id,omitempty"`                // The run's node journal ID, chosen by the controller
	Timestamp           string `json:"timestamp"`                       // RFC 3339 UTC
	PlanID              string `json:"plan_id"`
	PlanName            string `json:"plan_name"`
	PlanSHA256          string `json:"plan_sha256,omitempty"`           // SHA-256 of the plan file as the controller read it; set by the controller before it signs
	ValidatedPlanSHA256 string `json:"validated_plan_sha256,omitempty"` // v1 canonical worker plan, before backup resolution
	ResolvedPlanSHA256  string `json:"resolved_plan_sha256,omitempty"`  // v1 canonical worker plan after backup resolution; worker observation
	PlanDigestFormat    string `json:"plan_digest_format,omitempty"`
	Environment         string `json:"environment,omitempty"`
	PBSFingerprint      string `json:"pbs_fingerprint,omitempty"`
	PBSNamespace        string `json:"pbs_namespace,omitempty"`
	ValidationMode      string `json:"validation_mode"` // full_integrity or test_skip_integrity
	NodeFQDN            string `json:"node_fqdn"`
	EngineVersion       string `json:"engine_version,omitempty"`
	GitCommit           string `json:"git_commit,omitempty"`
	BuildDate           string `json:"build_date,omitempty"`
	// PVEVersion, PBSVersion and PBSClientVersion are the Proxmox VE version,
	// the PBS server's and the proxmox-backup-client's the run read on the
	// node, as the node wrote them; a version the run could not read is
	// absent. VersionSupport is what internal/support made of them: "tested",
	// "untested", or "unknown" when one of the three could not be read. A run
	// of an unsupported pair is refused before it creates anything, so only
	// the report of that refusal, which records no VM, says "unsupported". A
	// report that records none of the four (an older build, or a refusal
	// before the versions were read) says nothing of the versions.
	PVEVersion       string `json:"pve_version,omitempty"`
	PBSVersion       string `json:"pbs_version,omitempty"`
	PBSClientVersion string `json:"pbs_client_version,omitempty"`
	VersionSupport   string `json:"version_support,omitempty"`
	// WorkerSHA256 is the SHA-256 of the executable the controller uploaded and
	// ran as the node worker. The version, commit and build date above are
	// labels stamped into it; this digest is the executable itself, and for a
	// release it is the digest published for the release. Empty in a report
	// written before it was recorded.
	WorkerSHA256     string                     `json:"worker_sha256,omitempty"`
	Frameworks       []string                   `json:"frameworks"`
	RetentionDays    int                        `json:"retention_days"`
	VMRecords        []probe.VMValidationRecord `json:"vm_records"`
	PhaseTimings     *PhaseTimings              `json:"phase_timings,omitempty"`
	TeardownEvidence *TeardownEvidence          `json:"teardown_evidence,omitempty"`
	RTOSeconds       float64                    `json:"rto_seconds"`
	// RTOTargetSeconds is the recovery time objective the run was held to, the
	// plan's compliance.rto_target_seconds; absent when the plan set none. A pass
	// has an RTOSeconds within it.
	RTOTargetSeconds *float64 `json:"rto_target_seconds,omitempty"`
	// Admission is the host admission policy the run was held to and the check
	// that decided it (see AdmissionEvidence).
	Admission *AdmissionEvidence `json:"admission,omitempty"`
	AllPassed bool               `json:"all_passed"`
	// FailureReason is a bounded, redacted explanation for failures that occur
	// before a VM-specific probe record exists (for example admission, sandbox,
	// mapping, or cleanup failures). It is signed with the rest of the report.
	FailureReason     string `json:"failure_reason,omitempty"`
	FailureArtifact   string `json:"failure_artifact,omitempty"`   // Base64 PNG screenshot if failed
	PublicKey         string `json:"public_key,omitempty"`         // Hex-encoded Ed25519 public key
	SignerFingerprint string `json:"signer_fingerprint,omitempty"` // SHA-256 key fingerprint
	Signature         string `json:"signature,omitempty"`          // Hex-encoded Ed25519 signature
	// SignatureTimestamp is an optional trusted timestamp over the signature
	// (see TimestampToken). It is carried beside the signature and is not part
	// of the signed bytes, so it is added after signing and a report with and
	// without it has the same canonical form. The report's Timestamp above is
	// a different thing: when the report was built, and signed.
	SignatureTimestamp *TimestampToken `json:"signature_timestamp,omitempty"`
}

// BuildReport constructs a Report from plan metadata and execution results.
func BuildReport(plan *config.Plan, nodeFQDN string, rto time.Duration, allPassed bool, vmRecords []probe.VMValidationRecord, failureArtifact string) *Report {
	if nodeFQDN == "" {
		h, err := os.Hostname()
		if err == nil {
			nodeFQDN = h
		} else {
			nodeFQDN = "unknown-node"
		}
	}

	reportID := uuid.New().String()
	timestamp := time.Now().UTC().Format(time.RFC3339)

	for i := range vmRecords {
		if vmRecords[i].BootDurationSeconds == 0 && vmRecords[i].BootDuration > 0 {
			vmRecords[i].BootDurationSeconds = vmRecords[i].BootDuration.Seconds()
		}
	}

	planDigest, _ := config.CanonicalWorkerPlanSHA256(plan)
	return &Report{
		ReportSchemaVersion: CurrentReportSchemaVersion,
		ReportID:            reportID,
		Timestamp:           timestamp,
		PlanID:              plan.PlanID,
		PlanName:            plan.Name,
		ValidatedPlanSHA256: planDigest,
		ResolvedPlanSHA256:  planDigest,
		PlanDigestFormat:    config.WorkerPlanDigestFormat,
		Environment:         plan.Environment,
		PBSFingerprint:      plan.Storage.PBSFingerprint,
		PBSNamespace:        plan.Storage.PBSNamespace,
		ValidationMode:      ValidationModeFullIntegrity,
		NodeFQDN:            nodeFQDN,
		Frameworks:          plan.Compliance.Frameworks,
		RetentionDays:       plan.Compliance.RetentionDays,
		VMRecords:           vmRecords,
		RTOSeconds:          rto.Seconds(),
		RTOTargetSeconds:    RTOObjective(plan),
		Admission:           NewAdmissionEvidence(plan),
		AllPassed:           allPassed,
		FailureArtifact:     failureArtifact,
	}
}

// CanonicalizeReportJSON canonicalizes arbitrary report JSON bytes deterministically using RFC 8785 (JCS)
// while removing only the unsigned members, "signature", "public_key", "signer_fingerprint" and
// "signature_timestamp" (UnsignedReportMembers).
// This preserves all existing and future fields in the canonical payload.
// A report over the byte or structure limits of MaxReportFileBytes and its companions is refused
// (ErrReportLimit) before it is decoded.
func CanonicalizeReportJSON(reportBytes []byte) ([]byte, error) {
	rawMap, err := decodeReportDocument(reportBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode report JSON: %w", err)
	}
	return canonicalizeDecoded(rawMap)
}

// decodeReportDocument is the one place a report's bytes become a generic
// document. It first checks them in a single pass that decodes nothing (size,
// nesting, member and element counts, name and string lengths, value count,
// repeated member names, integers of 2^53 or more; see scanJSON), so a report
// that is too large or too complex is refused before any of it is decoded, and
// then decodes it once.
func decodeReportDocument(reportBytes []byte) (map[string]interface{}, error) {
	if err := checkReportDocument(reportBytes); err != nil {
		return nil, err
	}
	var rawMap map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(reportBytes))
	dec.UseNumber()
	if err := dec.Decode(&rawMap); err != nil {
		return nil, err
	}
	return rawMap, nil
}

// canonicalizeDecoded removes the unsigned members (unsignedReportMembers: the
// signature, the public key, the signer fingerprint and the signature's
// timestamp) from a decoded report and returns the rest in RFC 8785 form. It
// changes rawMap.
func canonicalizeDecoded(rawMap map[string]interface{}) ([]byte, error) {
	for _, member := range unsignedReportMembers {
		delete(rawMap, member)
	}

	rawWithoutSig, err := json.Marshal(rawMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal canonical report payload: %w", err)
	}

	canonical, err := jcs.Transform(rawWithoutSig)
	if err != nil {
		return nil, fmt.Errorf("RFC 8785 JSON canonicalization failed: %w", err)
	}

	return canonical, nil
}

// checkReportDocument checks a report's bytes in one pass, without decoding them: it fails on a
// document that is not one JSON value, that exceeds a limit of MaxReportFileBytes and its
// companions, on an object, at any depth, that repeats a member name, and on an integer the
// signature could not cover exactly (see maxSignedInteger). RFC 8785 canonicalization keeps only
// the last of a duplicated member, while encoding/json merges duplicated objects into one struct
// field, so a report with a prepended duplicate could carry values its signature never covered.
func checkReportDocument(data []byte) error {
	return scanJSON(data, reportLimits)
}

// maxSignedInteger is 2^53. RFC 8785 canonicalizes every number as an IEEE-754
// double, and from 2^53 on a double stands for several integers: 2^53 and
// 2^53+1 both canonicalize to 9007199254740992. A report holding such an
// integer would verify with the integer replaced by a neighbour that rounds to
// the same double, so the signature would not cover it exactly. Such a report
// is refused, when it is signed and when it is verified.
const maxSignedInteger = 1 << 53

// Save writes the JSON report to the specified file path, creating parent directories if needed.
func (r *Report) Save(path string) error {
	return r.SaveWithForce(path, false)
}

// SaveWithForce writes the JSON report, overwriting an existing file only when
// force is true. The report is written in full under <path>.new, synced, and
// renamed into place, so path never holds a partly written report and a
// forced overwrite never truncates the previous report before the new one
// is complete. The file is mode 0600, or on Windows owner-only by ACL.
func (r *Report) SaveWithForce(path string, force bool) error {
	dir := filepath.Dir(path)
	if err := ensureReportDirectory(dir); err != nil {
		return fmt.Errorf("secure report directory %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report JSON: %w", err)
	}
	if err := checkSavableReportSize(len(data)); err != nil {
		return fmt.Errorf("failed to write report file %s: %w", path, err)
	}
	// The verifier's own checks, the one function it applies before it decodes a
	// byte: a report it would refuse is not written, so that a run cannot pass and
	// leave a file that verify-report and report show cannot read. Signing
	// would enforce the same limits, but the Community Edition has no Signer.
	if err := checkReportDocument(data); err != nil {
		return fmt.Errorf("failed to write report file %s: the report is one verify-report would refuse to read, so it was not written: %w", path, err)
	}

	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("failed to write report file %s: output path is a symbolic link", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("failed to write report file %s: output path is not a regular file", path)
		}
		if !force {
			return fmt.Errorf("failed to write report file %s: a report already exists there", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect report file %s: %w", path, err)
	}
	staged, err := stageFile(path, data, 0600, true)
	if err != nil {
		return fmt.Errorf("failed to write report file %s: %w", path, err)
	}
	if err := staged.publish(force); err != nil {
		staged.discard()
		return fmt.Errorf("failed to write report file %s: %w", path, err)
	}

	return nil
}

// checkSavableReportSize refuses a report the verifier could not read back:
// verify-report and VerifyReport read at most MaxReportFileBytes, so a file
// larger than that would be evidence nobody can check. The controller's worker
// result is bounded at half the limit, which leaves room for the indentation
// saved files carry, so a report the product writes is never refused here.
func checkSavableReportSize(size int) error {
	if size > savedReportLimit {
		return fmt.Errorf("the report is %d bytes, more than the %d bytes verify-report reads, so it was not written", size, savedReportLimit)
	}
	return nil
}

// savedReportLimit is the size above which a report is not saved. It is
// MaxReportFileBytes; tests lower it to reach the refusal with a small report.
var savedReportLimit = MaxReportFileBytes

func ensureReportDirectory(dir string) error {
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("path is not a directory")
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(dir, 0700)
}

// DefaultReportPath returns the standard archive path: /var/lib/certistack/reports/<plan_id>/<report_id>.json
func DefaultReportPath(reportsBaseDir, planID, reportID string) string {
	if reportsBaseDir == "" {
		reportsBaseDir = "/var/lib/certistack/reports"
	}
	return filepath.Join(reportsBaseDir, planID, fmt.Sprintf("%s.json", reportID))
}

// VerifyReport parses an audit JSON report and verifies its embedded Ed25519 signature against a
// trusted signer set. It canonicalizes the original raw JSON bytes while removing strictly the unsigned
// members, "signature", "public_key", "signer_fingerprint" and "signature_timestamp", ensuring forward
// compatibility with reports generated with future schema fields.
//
// A report's signature_timestamp, when it has one, is read after the signature has verified, and a
// malformed one is an error (the member is unsigned, so it is read strictly). The returned report
// carries it as SignatureTimestamp; the signature does not depend on it and verification does not
// judge it. EvaluateTimestamp does that.
//
// The trusted signer sets are a signer policy: the signer's public key must be in the union of the
// sets given, so an empty set (for example a keyring that is empty, holds no valid keys, or had its
// last key removed) accepts no report at all, and so does calling VerifyReport with no set, as
// VerifyReport(data, sets...) does when the caller collected none. To check only that a report is
// intact under its own embedded key, which says nothing about who signed it, call
// VerifyReportSignatureOnly. A report whose embedded key cannot anchor trust (a small-order or
// non-curve point, for which signatures can be forged) is refused either way.
func VerifyReport(reportBytes []byte, trustedKeys ...[]ed25519.PublicKey) (*Report, bool, error) {
	if len(trustedKeys) == 0 {
		return nil, false, fmt.Errorf("untrusted signer: no trusted signer set was given, so no report is accepted (VerifyReportSignatureOnly checks integrity alone)")
	}
	return verifyReport(reportBytes, trustedKeys)
}

// VerifyReportSignatureOnly verifies that a report is intact under its own embedded public key. It
// does not say who signed the report: anyone can sign a report under a key of their own. It is for
// integrity checks where the signer is established some other way; use VerifyReport to accept a
// report from a trusted signer.
func VerifyReportSignatureOnly(reportBytes []byte) (*Report, bool, error) {
	return verifyReport(reportBytes, nil)
}

func verifyReport(reportBytes []byte, trustedKeys [][]ed25519.PublicKey) (*Report, bool, error) {
	rawMap, err := decodeReportDocument(reportBytes)
	if err != nil {
		return nil, false, fmt.Errorf("invalid report JSON: %w", err)
	}

	sigHex, _ := rawMap["signature"].(string)
	carried := carriedSignatureMembers(rawMap)
	if sigHex == "" {
		if len(carried) == 0 {
			return nil, false, ErrReportUnsigned
		}
		// A signature member that holds no usable signature is not a missing
		// signature: the report is neither signed nor unsigned, and sending its
		// reader to --unsigned would be advice that command refuses.
		return nil, false, fmt.Errorf("the report carries a signature member (%s) but no usable signature: the \"signature\" member must be a non-empty hex string, so this is neither a signed report nor an unsigned one", quoteMembers(carried))
	}
	for _, name := range carried {
		if !isExactSignatureMember(name) {
			// The decoder would read it as the signature member and the canonical
			// form would sign it as content: refused, not verified.
			return nil, false, fmt.Errorf("the report has a member %q that is spelled like a signature member in another letter case; the signature members are written in lower case, exactly (signature, public_key, signer_fingerprint, signature_timestamp)", name)
		}
	}
	pubKeyHex, _ := rawMap["public_key"].(string)
	if pubKeyHex == "" {
		return nil, false, fmt.Errorf("report is missing public key")
	}

	signerFpHex, _ := rawMap["signer_fingerprint"].(string)

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, false, fmt.Errorf("invalid hex public key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, false, fmt.Errorf("invalid public key size: %d", len(pubKeyBytes))
	}
	// Go's ed25519.Verify accepts signatures forged without a private key under a small-order key,
	// so a report that embeds one cannot be accepted whatever the trust set holds.
	if err := checkPublicKey(pubKeyBytes); err != nil {
		return nil, false, fmt.Errorf("report signer key is not a usable Ed25519 public key: %w", err)
	}
	expectedFingerprint := Fingerprint(ed25519.PublicKey(pubKeyBytes))
	if signerFpHex != "" && signerFpHex != expectedFingerprint {
		return nil, false, fmt.Errorf("report signer fingerprint does not match embedded public key")
	}

	// A supplied trust set is authoritative even when it is empty: "no trusted
	// keys" means trust nobody, never "skip the signer check".
	if trustedKeys != nil {
		trusted, configured := false, 0
		for _, set := range trustedKeys {
			configured += len(set)
			for _, tk := range set {
				if bytes.Equal(pubKeyBytes, tk) {
					trusted = true
				}
			}
		}
		if configured == 0 {
			return nil, false, fmt.Errorf("untrusted signer: the trusted signer set is empty, so no report is accepted")
		}
		if !trusted {
			return nil, false, fmt.Errorf("untrusted signer: public key %s is not in trusted keyring", pubKeyHex)
		}
	}

	// The timestamp of the signature is unsigned: take it from the document before the
	// canonical form drops it, and judge its shape only once the signature is known good.
	timestampValue, hasTimestamp := rawMap[TimestampMember]

	// Canonicalize the document decoded above (the original JSON, which was checked and decoded
	// once) while removing only the unsigned members (unsignedReportMembers).
	canonicalBytes, err := canonicalizeDecoded(rawMap)
	rawMap = nil // the decoded document is not needed again: let it go before the typed decode
	if err != nil {
		return nil, false, fmt.Errorf("failed to canonicalize report: %w", err)
	}

	valid, err := VerifyCanonical(canonicalBytes, sigHex, ed25519.PublicKey(pubKeyBytes))
	if err != nil {
		return nil, false, fmt.Errorf("signature verification error: %w", err)
	}
	if !valid {
		return nil, false, ErrInvalidSignature
	}

	var timestamp *TimestampToken
	if hasTimestamp {
		if timestamp, err = parseTimestampMember(timestampValue); err != nil {
			return nil, false, err
		}
	}

	// Decode the result from the exact bytes whose signature was verified,
	// not from the submitted document, so every value a caller reads (probe
	// outcomes, skipped flags, all_passed) is one the signature covered.
	var r Report
	if err := json.Unmarshal(canonicalBytes, &r); err != nil {
		return nil, valid, fmt.Errorf("failed to parse report struct: %w", err)
	}
	r.Signature = sigHex
	r.PublicKey = pubKeyHex
	r.SignerFingerprint = expectedFingerprint
	r.SignatureTimestamp = timestamp

	return &r, valid, nil
}

// quoteMembers lists member names, each in quotes, for a message.
func quoteMembers(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = strconv.Quote(name)
	}
	return strings.Join(quoted, ", ")
}

// LoadKeyring reads trusted Ed25519 public keys from a JSON keyring or newline-delimited hex file,
// with the checks of LoadKeyringFile. A keyring with no entries returns no keys, which
// VerifyReport treats as a trust set that accepts no report.
func LoadKeyring(path string) ([]ed25519.PublicKey, error) {
	kr, err := LoadKeyringFile(path)
	if err != nil {
		return nil, err
	}
	return kr.PublicKeys(), nil
}

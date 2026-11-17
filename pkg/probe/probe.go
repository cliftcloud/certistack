// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package probe defines the deterministic verification hierarchy for CertiStack.
package probe

import (
	"context"
	"fmt"
	"time"
)

// Result represents the outcome of an individual deterministic probe evaluation.
type Result struct {
	Type        string `json:"type"`        // "qmp", "tcp", "http", "dns", "ldap", "mssql", "smb", "qga"
	Target      string `json:"target"`      // IP:Port, endpoint path, or command
	Description string `json:"description"` // Human-readable audit intent
	// Origin identifies where the assertion ran. Synthetic TCP/HTTP/DNS/LDAP
	// probes run on the worker host through the isolated VNet; only QGA probes
	// execute inside the guest.
	Origin string `json:"origin,omitempty"`
	// ServerName is the identity an http or mssql probe asserted: the TLS
	// server name (SNI, and the name the certificate must carry) and, for http,
	// the Host header. Empty means the plan named none. An http probe then
	// asserted the address itself: no SNI is sent for an IP address, the Host
	// header is the address and port, and the certificate must carry the IP. An
	// mssql probe then did not verify the certificate at all.
	ServerName string `json:"server_name,omitempty"`
	// SourceInterface and SourceAddress are the sandbox VNet interface and the
	// host probe address a wire probe was bound to, which is the source
	// identity a guest firewall sees. Empty on probes that do not leave the
	// worker over the VNet (qmp, qga, screendump).
	SourceInterface string `json:"source_interface,omitempty"`
	SourceAddress   string `json:"source_address,omitempty"`
	// RequireQGA is the policy a qga probe ran under: true when the plan
	// required the guest agent (an unreachable agent failed the probe), absent
	// when it was optional (an unreachable agent skips the probe).
	RequireQGA bool `json:"require_qga,omitempty"`
	// TimeoutSec, Retries and Attempts are the policy the probe ran under and
	// its attempt history. TimeoutSec is the total readiness budget in seconds
	// (the plan's timeout_sec). Retries is the plan's retries value: a positive
	// number caps the additional executions, and absent means the probe was
	// polled automatically until the budget ran out. Attempts is how many
	// times the probe was executed before this result. The tcp and http
	// probers, and dns over UDP, also poll inside one execution until the
	// budget ends, so for them Duration shows how long the service took to
	// answer; for a prober that checks once per execution (qga, qmp, ldap,
	// mssql, smb) more than one attempt is a service that failed checks
	// before it answered.
	TimeoutSec int  `json:"timeout_sec,omitempty"`
	Retries    int  `json:"retries,omitempty"`
	Attempts   int  `json:"attempts,omitempty"`
	Passed     bool `json:"passed"`            // True if assertion succeeded
	Skipped    bool `json:"skipped,omitempty"` // True if probe was skipped (e.g. QGA missing)
	// Duration is the time the probe took, in nanoseconds.
	Duration time.Duration `json:"duration"`
	Detail   string        `json:"detail,omitempty"` // Response summary or stdout
	// ImageSHA256 is, for a screendump probe, the SHA-256 of the console image
	// it captured (the PNG encoded from the frame). The image itself is not
	// kept: neither the report nor the sandbox's scratch directory holds it
	// after the probe.
	ImageSHA256 string `json:"image_sha256,omitempty"`
	Error       string `json:"error,omitempty"` // Error message if failed
}

// Prober is the common interface implemented by all deterministic verification probes.
type Prober interface {
	Probe(ctx context.Context) Result
}

// ProberFunc is an adapter to allow use of ordinary functions as Probers.
type ProberFunc func(ctx context.Context) Result

func (f ProberFunc) Probe(ctx context.Context) Result {
	return f(ctx)
}

// Expired reports why an answer received now no longer counts: ctx was
// canceled, or its deadline has passed, even if ctx's own timer has not
// fired yet. A probe checks it before it accepts a success, so an answer
// that arrives after its budget or after an interruption never passes.
func Expired(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// VMValidationRecord records the complete audit trace for a VM in the DR test.
type VMValidationRecord struct {
	VMID                int           `json:"vmid"`
	SourceVMID          int           `json:"source_vmid,omitempty"`
	Name                string        `json:"name"`
	BootDuration        time.Duration `json:"boot_duration"`
	BootDurationSeconds float64       `json:"boot_duration_seconds"`
	SourceSnapshot      string        `json:"source_snapshot,omitempty"`
	// SourceCryptMode is how the backup's disks are protected in PBS: the
	// weakest crypt mode among them (encrypt, sign-only or none).
	SourceCryptMode string `json:"source_crypt_mode,omitempty"`
	// SourceSignatureVerified is true when the PBS client verified the
	// snapshot manifest's signature with the configured key.
	SourceSignatureVerified bool `json:"source_signature_verified,omitempty"`
	// SourceConsistency is how consistent the backed-up disks were, from the
	// backup's own log: quiesced (the guest agent froze the file systems),
	// crash-consistent, powered-off, or unknown. SourceConsistencyDetail
	// says why. The log is stored with the snapshot but outside its
	// manifest, so it is not covered by the manifest's signature.
	SourceConsistency       string `json:"source_consistency,omitempty"`
	SourceConsistencyDetail string `json:"source_consistency_detail,omitempty"`
	// CopiedBeforeBoot is true when the scan also copied the VM's disks to
	// local storage and the sandbox booted from the copies, as a restore
	// does, rather than from the PBS map through the page cache.
	CopiedBeforeBoot bool `json:"copied_before_boot,omitempty"`
	// ExcludedSourceDisks are source disks excluded from backups (backup=0):
	// no restore can include them, so the VM is never whole without them.
	ExcludedSourceDisks     []string `json:"excluded_source_disks,omitempty"`
	SourceDrive             string   `json:"source_drive,omitempty"`
	SourceManifestReference string   `json:"source_manifest_reference,omitempty"`
	// SourceChunkHashes is retained for backward compatibility. New reports
	// use SourceImageDigest: CertiStack calculates a whole mapped-image SHA-256,
	// not a PBS manifest/chunk-tree root.
	SourceChunkHashes []string             `json:"source_chunk_hashes,omitempty"`
	SourceImageDigest string               `json:"source_image_digest,omitempty"`
	SourceDisks       []SourceDiskEvidence `json:"source_disks,omitempty"`
	// OmittedSourceDisks are backed-up disks the plan chose not to restore,
	// so a partial restore is never presented as the whole VM.
	OmittedSourceDisks []string `json:"omitted_source_disks,omitempty"`
	// OmittedNICs are source NICs after net0 that the sandbox VM did not
	// get (network_recovery.attach_all_nics is off).
	OmittedNICs             []string `json:"omitted_nics,omitempty"`
	SourceTags              []string `json:"source_tags,omitempty"`
	PBSVerifyStatus         string   `json:"pbs_verify_status,omitempty"`
	NetworkRecoveryStrategy string   `json:"network_recovery_strategy,omitempty"`
	NetworkRecoveryAddress  string   `json:"network_recovery_address,omitempty"`
	// NetworkRecoverySeconds records the COW-only offline compatibility work
	// for this VM. It is separate from boot time because it happens before the
	// sandbox VM exists and can dominate a multi-guest RTO.
	NetworkRecoverySeconds    float64  `json:"network_recovery_seconds,omitempty"`
	NetworkRecoveryFiles      []string `json:"network_recovery_files,omitempty"`
	NetworkRecoveryDiagnostic string   `json:"network_recovery_diagnostic,omitempty"`
	ProbeResults              []Result `json:"probe_results"`
	// VerificationStatus distinguishes a completed pass from a VM that booted
	// but never reached deterministic probes (for example, an interrupted
	// controller session). It is intentionally explicit so an absent probe
	// matrix cannot be misread as a successful validation.
	VerificationStatus string `json:"verification_status,omitempty"`
	// RestoredHardware is the virtual hardware the sandbox VM was created
	// with, so a reviewer can confirm what was inherited from the backup.
	RestoredHardware *RestoredHardware `json:"restored_hardware,omitempty"`
	// Soak is what the tier's soak period established about this VM's services:
	// how often their probes were repeated while the tier was held, how many of
	// those checks failed and how slow the slowest was. Absent when the tier has
	// no soak or the run ended before the soak. Reports before schema 1.7 do not
	// record it.
	Soak            *SoakEvidence `json:"soak,omitempty"`
	AllPassed       bool          `json:"all_passed"`
	FailureArtifact string        `json:"failure_artifact,omitempty"` // Base64 screenshot if failed
}

// SoakEvidence is the bounded record of a tier's soak for one VM. The soak
// holds the tier's passing VMs for tiers[].soak_time_sec and, from schema 1.7,
// repeats each VM's service probes (the wire and guest-agent probes; not qmp
// or screendump, which show only that QEMU runs the VM) every IntervalSec
// seconds, and once more when the period ends. A check is one run of every
// repeated probe under the policy the plan gives it, so a probe that retries
// or polls inside its own timeout_sec does so in a check too. One failed
// check fails the VM, so a recorded pass has FailedSamples 0. The summary is
// the same size however long the soak was: the number of checks, when the
// first and the last ran, and for each probe how its checks ended and how long
// the slowest took.
type SoakEvidence struct {
	// ConfiguredSec is the tier's soak_time_sec, and IntervalSec the cadence of
	// the checks.
	ConfiguredSec int `json:"configured_sec"`
	IntervalSec   int `json:"interval_sec"`
	// StartedAt is when the soak began, FirstSampleAt and LastSampleAt when
	// its first and last check began, all RFC 3339 UTC. A soak that ran its
	// whole period has LastSampleAt at least ConfiguredSec after StartedAt:
	// the last check is the one that ends the soak.
	StartedAt     string `json:"started_at"`
	FirstSampleAt string `json:"first_sample_at,omitempty"`
	LastSampleAt  string `json:"last_sample_at,omitempty"`
	// Samples is how many checks ran, FailedSamples how many of them failed.
	Samples       int `json:"samples"`
	FailedSamples int `json:"failed_samples"`
	// Probes has one entry per repeated probe, in the plan's order.
	Probes []SoakProbeEvidence `json:"probes"`
	// StatusReads is how many times the soak read the VM's state from PVE, and
	// StatusReadFailures how many of those reads failed, with FirstStatusError
	// the first failure's error, bounded. A read that fails is not a sign that
	// the VM runs: a VM whose state could not be read for too long fails the
	// soak, and a pass has at least one read that succeeded.
	StatusReads        int    `json:"status_reads"`
	StatusReadFailures int    `json:"status_read_failures,omitempty"`
	FirstStatusError   string `json:"first_status_error,omitempty"`
}

// SoakProbeEvidence is how one probe's checks ended during the soak. Passed,
// Skipped and Failed add up to the soak's Samples (a check that ended before
// it reached this probe counts it as failed).
type SoakProbeEvidence struct {
	// Probe is the probe's position in the VM's plan, counting from 1.
	Probe       int    `json:"probe"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Passed      int    `json:"passed"`
	// Skipped counts the checks of an optional guest-agent probe that was
	// skipped, which is allowed only for a probe that was skipped in the
	// probe stage too.
	Skipped int `json:"skipped,omitempty"`
	Failed  int `json:"failed,omitempty"`
	// WorstDuration is the longest any one execution took, in nanoseconds,
	// over every check.
	WorstDuration time.Duration `json:"worst_duration"`
	// FirstError is the first failure's error, cut to a bounded length.
	FirstError string `json:"first_error,omitempty"`
}

// RestoredHardware records the sandbox VM's requested virtual hardware.
// FromBackupConfig is true when use_backup_config supplied it from the exact
// PBS snapshot configuration; otherwise it came from the plan and defaults.
type RestoredHardware struct {
	FromBackupConfig bool   `json:"from_backup_config"`
	Cores            int    `json:"cores"`
	Sockets          int    `json:"sockets"`
	MemoryMB         int    `json:"memory_mb"`
	BalloonMB        int    `json:"balloon_mb,omitempty"`
	CPU              string `json:"cpu"`
	// CPUWeight is the relative CPU weight the sandbox VM was created with,
	// PVE's cpuunits (the plan's hardware_overrides.cpu_weight, or the backup's
	// cpuunits under use_backup_config). Omitted when no weight was requested
	// and PVE applied its own default. Reports before schema 1.6 do not record
	// it.
	CPUWeight int    `json:"cpu_weight,omitempty"`
	Machine   string `json:"machine,omitempty"`
	BIOS      string `json:"bios,omitempty"`
	SCSIHW    string `json:"scsihw"`
	OSType    string `json:"ostype"`
	NICModel  string `json:"nic_model"`
	MAC       string `json:"mac,omitempty"`
	// NoBalloon is true when the sandbox VM, like its source, has no memory
	// balloon device.
	NoBalloon bool `json:"no_balloon,omitempty"`
	// RunningMachine is the machine version the sandbox VM ran, as PVE
	// resolved Machine at start, for example "pc-q35-11.0+pve0".
	RunningMachine string `json:"running_machine,omitempty"`
	// SMBIOSUUID is the backup's SMBIOS UUID, which the sandbox VM kept as a
	// restore does; empty when it got a new one.
	SMBIOSUUID string `json:"smbios_uuid,omitempty"`
	// EmptyCDROMs are the CD-ROM drives the sandbox VM has, without media,
	// where its source has drives.
	EmptyCDROMs []string `json:"empty_cdroms,omitempty"`
	// BootDisk is the slot the sandbox VM booted: the first restored disk of
	// the source boot order.
	BootDisk string `json:"boot_disk,omitempty"`
	// BootOrder is the sandbox VM's whole boot order, as sent to PVE
	// ("order=scsi0;scsi1"): the source boot order restricted to the restored
	// disks, in the source's order, so the first entry is BootDisk. A guest
	// that reads /boot from a second disk boots only if that disk is in it.
	// Reports written before it was recorded lack it, and their VM booted
	// BootDisk alone.
	BootOrder []string `json:"boot_order,omitempty"`
	// AdditionalNICs are the NICs after net0, "<slot> <model> <MAC>", all
	// on the isolated VNet.
	AdditionalNICs []string `json:"additional_nics,omitempty"`
	// FirmwareDisks lists the firmware state restored with a UEFI VM, one
	// "<slot> <options>" entry each, for example
	// "efidisk0 efitype=4m,pre-enrolled-keys=1" and "tpmstate0 version=v2.0".
	FirmwareDisks []string `json:"firmware_disks,omitempty"`
}

// The integrity_status values of a restored disk. A VM record lists every disk
// its restore was asked for from its first moment, so a run that fails early
// still says which backup and which disks it was to restore, and how far each
// got. A disk's status only moves forward: not_attempted, then mapped (or
// map_failed), then verified, skipped_test_mode or verification_failed; a
// firmware disk goes from not_attempted to verified or restore_failed. Only
// verified, and skipped_test_mode in the lab-only test mode, mean the disk's
// image was read back and checked; every other value is how far a failed
// restore got, and no VM with such a disk is a pass.
// verification_failed means the integrity scan, or the copy before boot made
// with it, did not finish; the failure reason says which.
const (
	DiskNotAttempted       = "not_attempted"
	DiskMapped             = "mapped"
	DiskMapFailed          = "map_failed"
	DiskVerificationFailed = "verification_failed"
	DiskRestoreFailed      = "restore_failed"
	DiskVerified           = "verified"
	DiskSkippedTestMode    = "skipped_test_mode"
)

// KnownDiskStatus reports whether status is one of the integrity_status values
// a worker of this build writes.
func KnownDiskStatus(status string) bool {
	switch status {
	case DiskNotAttempted, DiskMapped, DiskMapFailed, DiskVerificationFailed, DiskRestoreFailed, DiskVerified, DiskSkippedTestMode:
		return true
	}
	return false
}

// SourceDiskEvidence records the immutable PBS evidence for one restored disk.
// The legacy SourceDrive fields in VMValidationRecord retain the boot disk's
// evidence (scsi0 on most VMs) for older report consumers.
type SourceDiskEvidence struct {
	Slot              string `json:"slot"`
	Archive           string `json:"archive"`
	ManifestReference string `json:"manifest_reference"`
	// IntegrityStatus is "verified" after a full mapped-image checksum pass or
	// "skipped_test_mode" when the explicit lab-only shortcut was requested.
	// Only those two mean the disk's image was read back and checked; any
	// other value (see DiskNotAttempted and the values beside it) is how far a
	// failed restore got with this disk, and no VM with such a disk is a pass.
	IntegrityStatus string   `json:"integrity_status"`
	ChunkHashes     []string `json:"chunk_hashes,omitempty"` // Legacy compatibility only.
	ImageDigest     string   `json:"image_digest,omitempty"`
	// BootSource is "local-copy" when the sandbox booted this disk from a
	// verified local copy; empty when it booted from the PBS map.
	BootSource string `json:"boot_source,omitempty"`
}

// FormatError formats probe failure information for logging.
func (r *Result) String() string {
	status := "PASSED"
	if r.Skipped {
		status = "SKIPPED"
	} else if !r.Passed {
		status = "FAILED"
	}
	return fmt.Sprintf("[%s] %s (%s): %s", status, r.Type, r.Target, r.Detail)
}

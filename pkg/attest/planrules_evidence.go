// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// More of the rules that hold a report's VM records to their plan (see
// planrules.go): the backup a record says it restored from, and the policy its
// probes say they ran under. The controller applies them before it signs, and
// verify-report to the report it is given, from this one implementation.

// ExpectedSourceVMID is the source VM a planned VM restores: its explicit
// source_vmid, or the group of a vm/<id>/... snapshot selector. Zero means the
// plan does not name one.
func ExpectedSourceVMID(vm config.VM) int {
	if vm.SourceVMID > 0 {
		return vm.SourceVMID
	}
	id, ok := snapshotGroup(vm.SourcePBS.Snapshot, false)
	if !ok {
		return 0
	}
	return id
}

// snapshotGroup is the VM ID of the vm/<id>/... path a snapshot or a selector
// starts with, written as a canonical positive decimal. With whole, the path
// must be a whole snapshot, vm/<id>/<RFC 3339 time>, as the PBS client
// resolves one.
func snapshotGroup(path string, whole bool) (int, bool) {
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] != "vm" {
		return 0, false
	}
	id, err := strconv.Atoi(parts[1])
	if err != nil || id <= 0 || strconv.Itoa(id) != parts[1] {
		return 0, false
	}
	if !whole {
		return id, true
	}
	if len(parts) != 3 {
		return 0, false
	}
	if _, err := time.Parse(time.RFC3339, parts[2]); err != nil {
		return 0, false
	}
	return id, true
}

// SourceProblems is what contradicts the plan, or the record itself, in the
// backup one VM record says it restored. Every record has it, a failed or an
// incomplete one as well as a pass: a restore that ended at its first guard
// still names the snapshot it was given, so two failures of different backups
// are never one certificate. The record must name a whole snapshot of
// the source VM it names, the plan's own snapshot when the plan pins one or a
// snapshot of the plan's source VM when it selects the latest, and its disks
// may only be in a status a worker of this build writes.
func SourceProblems(record probe.VMValidationRecord, planned *config.VM) []string {
	var problems []string
	problem := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	snapshotVM, whole := snapshotGroup(record.SourceSnapshot, true)
	switch {
	case record.SourceSnapshot == "":
		problem("VM %d records no source snapshot, so it does not say which backup it restored", record.VMID)
	case !whole:
		problem("VM %d records source snapshot %q, which is not a PBS snapshot path (vm/<id>/<time>)", record.VMID, record.SourceSnapshot)
	case record.SourceVMID > 0 && snapshotVM != record.SourceVMID:
		problem("VM %d records source snapshot %q, a backup of VM %d, and source VM %d", record.VMID, record.SourceSnapshot, snapshotVM, record.SourceVMID)
	}
	if planned != nil && whole {
		pinned := strings.TrimSpace(planned.SourcePBS.Snapshot)
		if _, isPinned := snapshotGroup(pinned, true); isPinned {
			if record.SourceSnapshot != pinned {
				problem("VM %d records source snapshot %q; the plan pins %q", record.VMID, record.SourceSnapshot, pinned)
			}
		} else if want := ExpectedSourceVMID(*planned); want > 0 && snapshotVM != want {
			problem("VM %d records source snapshot %q, a backup of VM %d; the plan restores source VM %d", record.VMID, record.SourceSnapshot, snapshotVM, want)
		}
	}
	for _, disk := range record.SourceDisks {
		if !probe.KnownDiskStatus(disk.IntegrityStatus) {
			problem("VM %d disk %q records integrity_status %q, which no worker of this build writes", record.VMID, disk.Slot, disk.IntegrityStatus)
		}
	}
	return problems
}

// ProbePolicyProblems is what contradicts the plan in the policy each probe
// result of one VM says it ran under, and in the evidence it carries, for a
// report whose schema records them (1.6 and later; the caller decides). The
// timeout and retries a probe ran under, whether a guest-agent probe was
// required, the virtual host an http probe asserted and the source a wire probe
// was bound to each change what a pass means: a one-second and a three-minute
// readiness budget, a required and an optional agent check, another virtual
// host on the same address, or another source address are different
// assertions, and a report of one is not evidence of the other.
//
// plan is the plan planned belongs to (its network gives the source a wire
// probe is bound to); both may be nil, as for a report checked without one, and
// then the results are held only to what they say of themselves: a result that
// says its guest-agent probe was required cannot be a skip, and a result
// cannot carry a negative count, a screendump digest that is not a SHA-256, or
// a passed screendump without one (it is the only record of which image was
// captured, since the image is not kept).
func ProbePolicyProblems(record probe.VMValidationRecord, planned *config.VM, plan *config.Plan) []string {
	var problems []string
	for index, result := range record.ProbeResults {
		problem := func(format string, args ...any) {
			problems = append(problems, fmt.Sprintf("VM %d probe %d (%s %q) %s", record.VMID, index+1, result.Type, result.Description, fmt.Sprintf(format, args...)))
		}
		var configured *config.Probe
		if planned != nil && index < len(planned.Probes) {
			configured = &planned.Probes[index]
		}
		// The policy is held to the probe the plan configures there only when
		// the result is that probe's (ProbeProblems says when it is not).
		if configured != nil && result.Type == configured.Type && result.Description == configured.Description {
			if want, carried := ExpectedProbeTarget(*configured); !carried || result.Target == want {
				policyMismatches(result, *configured, plan, problem)
			}
		}
		plannedOptional := configured == nil || ProbeIsOptional(*configured)
		if result.RequireQGA && result.Passed && result.Skipped && plannedOptional {
			problem("is required but was skipped")
		}
		if result.TimeoutSec < 0 || result.Retries < 0 || result.Attempts < 0 {
			problem("records a negative timeout, retries or attempts count")
		}
		if result.ImageSHA256 != "" && !IsSHA256Hex(result.ImageSHA256) {
			problem("records an image_sha256 that is not a SHA-256 digest")
		}
		if result.Type == "screendump" && result.Passed && !result.Skipped && result.ImageSHA256 == "" {
			problem("passed without recording the SHA-256 of the image it captured")
		}
	}
	return problems
}

// policyMismatches reports, through problem, each way the policy a result
// says it ran under is not the one its configured probe sets.
func policyMismatches(result probe.Result, configured config.Probe, plan *config.Plan, problem func(string, ...any)) {
	if configured.TimeoutSec > 0 && result.TimeoutSec != configured.TimeoutSec {
		problem("ran under a timeout of %d s; the plan configures %d s", result.TimeoutSec, configured.TimeoutSec)
	}
	retries := max(configured.Retries, 0)
	if result.Retries != retries {
		problem("records retries %d; the plan configures %d", result.Retries, retries)
	}
	if retries > 0 && result.Attempts > retries+1 {
		problem("records %d attempts, more than the plan's retries %d allow (%d)", result.Attempts, retries, retries+1)
	}
	if result.Type == "qga" && result.RequireQGA != configured.RequireQGA {
		if configured.RequireQGA {
			problem("is not recorded as requiring the guest agent; the plan sets require_qga")
		} else {
			problem("is recorded as requiring the guest agent; the plan makes it optional")
		}
	}
	if result.Type == "http" && result.ServerName != configured.ServerName {
		problem("asserted virtual host %q; the plan configures %q (none means the address itself)", result.ServerName, configured.ServerName)
	}
	if result.Type == "mssql" && result.ServerName != configured.ServerName {
		problem("verified the certificate for server name %q; the plan configures %q (none means the certificate is not verified)", result.ServerName, configured.ServerName)
	}
	if config.IsWireProbe(result.Type) && plan != nil {
		wantAddress, wantInterface := strings.TrimSpace(plan.Network.ProbeIP), plan.Network.VNetID
		if wantAddress != "" && wantInterface != "" && (result.SourceAddress != wantAddress || result.SourceInterface != wantInterface) {
			problem("was bound to source %q on interface %q; the plan's sandbox probes from %q on %q", result.SourceAddress, result.SourceInterface, wantAddress, wantInterface)
		}
	}
}

// IsSHA256Hex reports whether value is a lower-case hex SHA-256 digest.
func IsSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

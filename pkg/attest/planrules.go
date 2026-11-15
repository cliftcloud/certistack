// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/internal/httptarget"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// The rules in this file and in planrules_evidence.go hold a report's VM
// records to the plan they were requested from: the probes and disks they
// record, the backup they name, and the policy their probes ran under. The
// controller applies them before it signs a worker's report, and verify-report
// applies them to a report it is given: one implementation, so what one
// refuses the other refuses. What needs the report's schema or only the
// verifier's expectations (the plan's digest, the build, the outcome) stays in
// cmd/certistack.

// ProbeIsGuestLevel reports whether a probe type asserts something about the
// guest: a wire probe from the worker to a service in it, or a guest-agent
// probe inside it. QMP and screendump only observe the hypervisor's view.
func ProbeIsGuestLevel(probeType string) bool {
	return probeType == "qga" || config.IsWireProbe(probeType)
}

// ProbeIsOptional reports whether a configured probe may be skipped: only a
// guest-agent probe that does not require the agent.
func ProbeIsOptional(configured config.Probe) bool {
	return configured.Type == "qga" && !configured.RequireQGA
}

// ExpectedProbeTarget is the target a probe of this configuration records in a
// report, built the way the prober builds it (pkg/probe/synthetic and
// pkg/probe/qga); a test runs each real prober to keep the two in step. It
// reports false for probes whose recorded target does not come from the plan
// (QMP and screendump record the VM's socket path). The report does not carry
// a probe's expected status or output, TLS settings, timeout or retries, so
// those are not compared.
func ExpectedProbeTarget(p config.Probe) (string, bool) {
	port := func(fallback int) int {
		if p.Port <= 0 {
			return fallback
		}
		return p.Port
	}
	switch p.Type {
	case "tcp":
		return net.JoinHostPort(p.TargetIP, strconv.Itoa(p.Port)), true
	case "http":
		scheme := "http"
		if p.TLS {
			scheme = "https"
		}
		path := p.Path
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		// The prober records the request target as the server receives it
		// (httptarget.Sent: percent-encoded as Go's client sends it) behind a
		// host:port that brackets an IPv6 address.
		return fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(p.TargetIP, strconv.Itoa(p.Port)), httptarget.Sent(path)), true
	case "dns":
		transport := strings.ToLower(strings.TrimSpace(p.Transport))
		if transport == "" {
			transport = "udp"
		}
		return fmt.Sprintf("%s://%s", transport, net.JoinHostPort(p.TargetIP, strconv.Itoa(port(53)))), true
	case "ldap":
		return net.JoinHostPort(p.TargetIP, strconv.Itoa(port(389))), true
	case "mssql":
		return net.JoinHostPort(p.TargetIP, strconv.Itoa(port(1433))), true
	case "smb":
		return net.JoinHostPort(p.TargetIP, strconv.Itoa(port(445))), true
	case "qga":
		return p.Command, true
	}
	return "", false
}

// ProbeProblems is what contradicts a pass in one VM's probe results, in words
// for an operator; none means the results are the plan's. With the planned VM,
// the results must be the plan's probes in order: the same type, description,
// and, where the report carries it, target (see ExpectedProbeTarget). A
// required probe must have run and passed, and only an optional guest-agent
// probe may be skipped. expectedFailure is the index of the one probe allowed
// to fail (the fault drill's injected failure), or -1. A VM that does not fail
// must have at least one guest-level assertion that ran and passed: QMP and
// screendump probes show that the VM is running, not that a service in it
// works, so they never count as one.
func ProbeProblems(record probe.VMValidationRecord, planned *config.VM, expectedFailure int) []string {
	var problems []string
	problem := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	results := record.ProbeResults
	if len(results) == 0 {
		return []string{fmt.Sprintf("VM %d records no probe result", record.VMID)}
	}
	if planned != nil && len(results) != len(planned.Probes) {
		problem("VM %d records %d probe result(s); the plan configures %d", record.VMID, len(results), len(planned.Probes))
	}
	guestAsserted, failed := false, 0
	for index, result := range results {
		optional := result.Type == "qga"
		if planned != nil && index < len(planned.Probes) {
			configured := planned.Probes[index]
			if result.Type != configured.Type || result.Description != configured.Description {
				problem("VM %d probe %d is %s %q; the plan configures %s %q", record.VMID, index+1, result.Type, result.Description, configured.Type, configured.Description)
			} else if want, carried := ExpectedProbeTarget(configured); carried && result.Target != want {
				problem("VM %d probe %d (%s %q) targeted %q; the plan configures %q", record.VMID, index+1, result.Type, result.Description, result.Target, want)
			}
			optional = ProbeIsOptional(configured)
		}
		switch {
		case !result.Passed:
			failed++
			if index != expectedFailure {
				problem("VM %d probe %d (%s %q) failed", record.VMID, index+1, result.Type, result.Description)
			}
		case result.Skipped && !optional:
			problem("VM %d probe %d (%s %q) is required but was skipped", record.VMID, index+1, result.Type, result.Description)
		case !result.Skipped && ProbeIsGuestLevel(result.Type):
			guestAsserted = true
		}
	}
	if !guestAsserted && failed == 0 {
		problem("VM %d has no guest-level assertion that ran: only QMP or screendump probes passed, or every guest-agent probe was skipped, which shows the VM is running, not that its service works", record.VMID)
	}
	return problems
}

// firmwareSlot reports whether a recorded disk is firmware state (an EFI
// vars disk or a TPM state image), which the backup's layout adds to the
// disks a plan names.
func firmwareSlot(slot string) bool {
	return strings.HasPrefix(slot, "efidisk") || strings.HasPrefix(slot, "tpmstate")
}

// DiskProblems is what contradicts the plan in one VM's recorded disks: a slot
// recorded twice, and, when the plan names the drives it restores (a plan
// that takes them from the backup's configuration cannot say what the layout
// should be), a named drive that is not recorded or is recorded from another
// archive, and a disk the plan does not restore, firmware state aside.
func DiskProblems(record probe.VMValidationRecord, planned *config.VM) []string {
	var problems []string
	recorded := make(map[string]probe.SourceDiskEvidence, len(record.SourceDisks))
	for _, disk := range record.SourceDisks {
		if _, twice := recorded[disk.Slot]; twice {
			problems = append(problems, fmt.Sprintf("VM %d records disk %q more than once", record.VMID, disk.Slot))
		}
		recorded[disk.Slot] = disk
	}
	if planned == nil {
		return problems
	}
	named := make(map[string]bool)
	for _, drive := range planned.SourcePBS.RestoreDrives() {
		named[drive.Slot] = true
		disk, present := recorded[drive.Slot]
		switch {
		case !present:
			problems = append(problems, fmt.Sprintf("VM %d records no integrity evidence for disk %q, which the plan restores", record.VMID, drive.Slot))
		case drive.Archive != "" && disk.Archive != drive.Archive:
			problems = append(problems, fmt.Sprintf("VM %d records disk %q from archive %q; the plan restores archive %q", record.VMID, drive.Slot, disk.Archive, drive.Archive))
		}
	}
	if len(named) > 0 {
		for _, disk := range record.SourceDisks {
			if !named[disk.Slot] && !firmwareSlot(disk.Slot) {
				problems = append(problems, fmt.Sprintf("VM %d records disk %q, which the plan does not restore", record.VMID, disk.Slot))
			}
		}
	}
	return problems
}

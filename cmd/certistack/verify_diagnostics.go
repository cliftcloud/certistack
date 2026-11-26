// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// A report keeps why a run failed: the top-level failure reason, each failed
// probe's error and detail, and the cleanup errors. verify-report shows them,
// so the default view says why a run failed and not only that it did. They are
// the report's own words, which a signature does not make safe: a probe's
// detail can be text a guest or a service produced. Every
// one is flattened to one line with control and format characters removed
// (sanitizeVerifyText) and cut to a length, and no more than maxDiagnosticItems
// of a kind are listed, with a count of the rest, so a hostile or merely huge
// report cannot flood a terminal or a log.
const (
	// maxFailureReasonRunes bounds the top-level reason, which joins the
	// failures of a run.
	maxFailureReasonRunes = 1000
	// maxDiagnosticRunes bounds a probe's error or detail and one cleanup error.
	maxDiagnosticRunes = 300
	// maxDiagnosticItems bounds the failed probes and the cleanup errors listed.
	maxDiagnosticItems = 20
)

// boundedDiagnostic makes a value of a report fit on a line: control and
// format characters removed, line breaks flattened, at most limit characters.
func boundedDiagnostic(value string, limit int) string {
	value = sanitizeVerifyText(value)
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	return string([]rune(value)[:limit]) + "…"
}

// boundedDiagnostics is the first maxDiagnosticItems of values, each bounded.
func boundedDiagnostics(values []string) []string {
	if len(values) > maxDiagnosticItems {
		values = values[:maxDiagnosticItems]
	}
	bounded := make([]string, len(values))
	for index, value := range values {
		bounded[index] = boundedDiagnostic(value, maxDiagnosticRunes)
	}
	return bounded
}

// maxVersionRunes bounds a Proxmox version or version_support of a report.
const maxVersionRunes = 64

// writeProxmoxVersions prints the Proxmox versions a report records and
// whether the run's release had tested them; nothing for a report that
// records none.
func writeProxmoxVersions(out io.Writer, report *attest.Report) {
	if report.PVEVersion == "" && report.PBSVersion == "" && report.PBSClientVersion == "" && report.VersionSupport == "" {
		return
	}
	version := func(value string) string {
		if value == "" {
			return "unknown"
		}
		return boundedDiagnostic(value, maxVersionRunes)
	}
	line := fmt.Sprintf("PVE %s, PBS %s, proxmox-backup-client %s", version(report.PVEVersion), version(report.PBSVersion), version(report.PBSClientVersion))
	if report.VersionSupport != "" {
		line += " (" + boundedDiagnostic(report.VersionSupport, maxVersionRunes) + ")"
	}
	fmt.Fprintf(out, "  Proxmox:     %s\n", line)
}

// writeFailureReason prints the top-level failure reason, beside the
// verdict it explains.
func writeFailureReason(out io.Writer, report *attest.Report) {
	if report.FailureReason != "" {
		fmt.Fprintf(out, "  Failure:     %s\n", boundedDiagnostic(report.FailureReason, maxFailureReasonRunes))
	}
}

// writeFailureDiagnostics prints which probes failed and with what error and
// detail, and the cleanup errors, of a report that records any.
func writeFailureDiagnostics(out io.Writer, report *attest.Report) {
	type failure struct {
		vmid   int
		name   string
		result string
		error  string
		detail string
	}
	var failures []failure
	for _, vm := range report.VMRecords {
		for _, result := range vm.ProbeResults {
			if result.Passed || result.Skipped {
				continue
			}
			failures = append(failures, failure{
				vmid: vm.VMID, name: boundedDiagnostic(vm.Name, 80),
				result: fmt.Sprintf("%s %s %q", boundedDiagnostic(result.Type, 40), boundedDiagnostic(result.Target, 200), boundedDiagnostic(result.Description, 200)),
				error:  boundedDiagnostic(result.Error, maxDiagnosticRunes), detail: boundedDiagnostic(result.Detail, maxDiagnosticRunes),
			})
		}
	}
	if len(failures) > 0 {
		fmt.Fprintf(out, "\n  Failed Probes (%d):\n", len(failures))
		for index, item := range failures {
			if index == maxDiagnosticItems {
				fmt.Fprintf(out, "    - and %d more (see the report)\n", len(failures)-maxDiagnosticItems)
				break
			}
			fmt.Fprintf(out, "    - VM %d (%s): %s\n", item.vmid, item.name, item.result)
			if item.error != "" {
				fmt.Fprintf(out, "        error:  %s\n", item.error)
			}
			if item.detail != "" {
				fmt.Fprintf(out, "        detail: %s\n", item.detail)
			}
		}
	}
	if evidence := report.TeardownEvidence; evidence != nil {
		for _, list := range []struct {
			title  string
			errors []string
		}{{"Cleanup Errors", evidence.CleanupErrors}, {"Cleanup Errors Before the Run", evidence.InitialCleanupErrors}} {
			if len(list.errors) == 0 {
				continue
			}
			fmt.Fprintf(out, "\n  %s (%d):\n", list.title, len(list.errors))
			for _, text := range boundedDiagnostics(list.errors) {
				fmt.Fprintf(out, "    - %s\n", text)
			}
			if len(list.errors) > maxDiagnosticItems {
				fmt.Fprintf(out, "    - and %d more (see the report)\n", len(list.errors)-maxDiagnosticItems)
			}
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/progress"
)

// troubleshootingGuide is where the usual causes of a failed run, and their
// fixes, are written down.
const troubleshootingGuide = "https://certistack.dev/docs/troubleshooting/"

// runNextSteps are the lines that end a run's output, after the verdict and the
// saved-report line: what to read next. They are only commands and the address
// of the documentation, and name the report only when it was saved. A run that was
// stopped (Ctrl-C) says nothing: the operator knows.
//
//   - A pass: read the report. The Community Edition's report is unsigned, so
//     there is no signature to verify; report show says how to judge it.
//   - A report that does not record a pass (the validation failed, the node's
//     cleanup was not verified, the node stopped the run): read it, since it
//     shows which probe failed and why (or, when no probe ran, why the run
//     stopped), then the troubleshooting guide.
//   - An error before any report: the troubleshooting guide.
//   - A report that could not be saved: nothing, since the error says where its
//     copy went.
func runNextSteps(result *controller.Result, runErr error) []string {
	saved := result != nil && result.ReportPath != ""
	switch {
	case saved && runErr == nil && result.Report != nil && result.Report.AllPassed:
		path := nextStepPath(result.ReportPath)
		return []string{
			"Next: certistack report show " + path,
		}
	case saved:
		return []string{
			"Next: certistack report show " + nextStepPath(result.ReportPath) + "   (" + reportShows(result) + ")",
			"Next: " + troubleshootingGuide + " lists the usual causes of a failed run and their fixes",
		}
	case result != nil && result.Report != nil:
		return nil
	case runErr != nil && !errors.Is(runErr, context.Canceled):
		return []string{"Next: " + troubleshootingGuide + " lists the usual causes of a failed run and their fixes"}
	}
	return nil
}

// reportShows says what `report show` will show of a report that does not
// record a pass: which probe failed when one ran, and otherwise why the run
// stopped (a refusal before any VM, or a VM that never got to its probes),
// where no probe can be named.
func reportShows(result *controller.Result) string {
	if result.Report != nil {
		probeRan := false
		for _, vm := range result.Report.VMRecords {
			probeRan = probeRan || len(vm.ProbeResults) > 0
		}
		if !probeRan {
			return "shows why the run stopped"
		}
	}
	return "shows which probe failed, and why"
}

// writeRunNextSteps writes runNextSteps to w, which is standard error: the
// progress is there, and standard output holds only the saved-report line. A
// write that fails changes nothing: the verdict is already out.
func writeRunNextSteps(w io.Writer, result *controller.Result, runErr error) {
	for _, line := range runNextSteps(result, runErr) {
		_, _ = fmt.Fprintln(w, line)
	}
}

// nextStepPath is a report path as one word of a command line a person can paste:
// as it is when it holds only characters a shell leaves alone, else in single
// quotes. A line break or another control character is not a character of a
// path worth printing, and is flattened like any text the run shows.
func nextStepPath(path string) string {
	path = progress.SingleLine(path)
	if path != "" && strings.Trim(path, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./:@%+=,-") == "" {
		return path
	}
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

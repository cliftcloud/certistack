// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/pkg/progress"
)

// A worker result the controller refuses is not lost with the node workspace:
// the controller keeps the bytes the worker returned, so that the operator can
// see what it said, as a file that is not evidence in any way a tool could
// mistake it for one. It is not a report: it is never signed,
// counted or verified, and it is kept where nothing that reads reports looks.
//
//   - It is in a subdirectory of the report directory of its own (RefusedDirName),
//     never in the report directory's root and never beside a plan's reports.
//   - Its name ends in RefusedResultSuffix, not in .json, so a glob or a walk for
//     *.json (verify-report's callers, an evidence hub's import, the Enterprise
//     daemon's scan and its hub push) does not match it in any letter case.
//   - It starts with RefusedBanner, which is not JSON, so a tool that is handed
//     the file by name refuses it as "not valid JSON" instead of reading it.
//   - It is private to its owner, like a report: the worker's result holds the
//     same guest text and screenshots a report does.
const (
	// RefusedDirName is the subdirectory of the report directory that holds the
	// refused results. A plan whose plan_id is "refused" has its reports in a
	// directory of that name too; the two cannot be mistaken for each other,
	// because the files differ in name (<report-id>.json against
	// <run-id>.refused.txt).
	RefusedDirName = "refused"
	// RefusedResultSuffix ends the name of every kept refused result.
	RefusedResultSuffix = ".refused.txt"
	// RefusedBanner is the first line of every kept refused result.
	RefusedBanner = "REFUSED, NOT EVIDENCE: this worker result failed the controller's checks and was never signed"
	// UnsignedResultBanner is the first line of a kept worker result that passed
	// every check of the controller but could not be signed: the run happened and
	// its resources are gone, and no report was written in the place of the one
	// that could not be signed. It opens as RefusedBanner does, so that whatever
	// looks for a kept result finds it, and then says what is true of this one.
	UnsignedResultBanner = "REFUSED, NOT EVIDENCE: this worker result passed the controller's checks, but the report could not be signed, so no report was written"
	// RefusedRawMarker is the line after the refusal reason; the worker's bytes
	// follow it unchanged.
	RefusedRawMarker = "--- the worker's raw result follows, unsigned and untrusted ---"

	// maxRefusedReasonBytes bounds the reason line: the controller's list of
	// contradictions is bounded already, and what the worker wrote is quoted
	// in it, so the line is cut here whatever it holds.
	maxRefusedReasonBytes = 8 << 10
)

// refusedResultLimit is the size above which the worker's bytes are cut when a
// refused result is kept: MaxReportFileBytes, the limit of a saved report. The
// controller accepts at most half of it from a worker, so this only holds for
// a caller that passes more; tests lower it to reach the cut with a small result.
var refusedResultLimit = MaxReportFileBytes

// refusedRunIDPattern is the form of a run ID that may name a file: the
// controller's own ("run-" and a UUID), letters, digits, '-' and '_'.
var refusedRunIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// DefaultRefusedPath returns the path a refused result of the run is kept at:
// <reports>/refused/<run_id>.refused.txt, with the same default report
// directory as DefaultReportPath.
func DefaultRefusedPath(reportsBaseDir, runID string) (string, error) {
	if !refusedRunIDPattern.MatchString(runID) {
		return "", fmt.Errorf("run ID %q cannot name a refused result: use letters, digits, '-' and '_'", boundedRefusedText(runID, 64))
	}
	if reportsBaseDir == "" {
		reportsBaseDir = "/var/lib/certistack/reports"
	}
	return filepath.Join(reportsBaseDir, RefusedDirName, runID+RefusedResultSuffix), nil
}

// SaveRefusedResult keeps a worker result the controller refused, unsigned and
// marked as not evidence, at DefaultRefusedPath, and returns that path. The
// file is, in order: RefusedBanner, the reason on one line, RefusedRawMarker,
// and raw, byte for byte. A result whose file would be larger than a report
// may be is cut, and the file says how much was kept. It never replaces a file
// and never writes through a symbolic link, and the file is private to its
// owner (mode 0600, or on Windows an ACL for the owner only).
func SaveRefusedResult(reportsBaseDir, runID, reason string, raw []byte) (string, error) {
	return saveKeptResult(RefusedBanner, reportsBaseDir, runID, reason, raw)
}

// SaveUnsignedResult keeps a worker result that passed the controller's checks
// but whose report could not be signed, in the same place and form as
// SaveRefusedResult, under UnsignedResultBanner instead of RefusedBanner: it was
// not refused for what it says, the signer failed (review R1-07).
func SaveUnsignedResult(reportsBaseDir, runID, reason string, raw []byte) (string, error) {
	return saveKeptResult(UnsignedResultBanner, reportsBaseDir, runID, reason, raw)
}

func saveKeptResult(banner, reportsBaseDir, runID, reason string, raw []byte) (string, error) {
	path, err := DefaultRefusedPath(reportsBaseDir, runID)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(path)
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing the refused-results directory %s: it is a symbolic link", dir)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("the refused-results path %s is not a directory", dir)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("inspect the refused-results directory %s: %w", dir, err)
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create the refused-results directory %s: %w", dir, err)
	}
	// A name taken is an error: a run keeps one refused result, and an earlier
	// file is never replaced.
	if _, err := checkDestination(path, "refused result", false); err != nil {
		return "", err
	}

	data := keptResultBytes(banner, reason, raw, refusedResultLimit)
	staged, err := stageFile(path, data, 0o600, true)
	if err != nil {
		return "", fmt.Errorf("failed to write refused result %s: %w", path, err)
	}
	if err := staged.publish(false); err != nil {
		staged.discard()
		return "", fmt.Errorf("failed to write refused result %s: %w", path, err)
	}
	return path, nil
}

// refusedResultBytes assembles the file, cutting the worker's bytes so that it
// is not larger than limit.
func refusedResultBytes(reason string, raw []byte, limit int) []byte {
	return keptResultBytes(RefusedBanner, reason, raw, limit)
}

func keptResultBytes(banner, reason string, raw []byte, limit int) []byte {
	header := banner + "\n" +
		"Reason: " + boundedRefusedText(progress.SingleLine(reason), maxRefusedReasonBytes) + "\n" +
		RefusedRawMarker + "\n"
	out := make([]byte, 0, len(header)+len(raw)+refusedCutNoteBytes)
	out = append(out, header...)
	room := limit - len(out)
	if len(raw) <= room {
		return append(out, raw...)
	}
	// The note names two byte counts and fits in refusedCutNoteBytes, which is
	// held back from the room, so the file never passes the limit.
	keep := max(room-refusedCutNoteBytes, 0)
	out = append(out, raw[:keep]...)
	return fmt.Appendf(out, "\n--- cut here: the first %d of the worker's %d bytes are kept ---\n", keep, len(raw))
}

// refusedCutNoteBytes is the room held back for the line that says a result
// was cut: its text and two 64-bit counts take under 100 bytes.
const refusedCutNoteBytes = 128

// boundedRefusedText cuts text to at most limit bytes at a character boundary.
func boundedRefusedText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "..."
}

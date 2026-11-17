// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// The messages that leave a newcomer without usable overlay storage (init, and
// plan's overlay-storage refusal) end with one command, from one constant. The
// command is the one the manual setup page gives, character for character, so
// a change in the one place is a failure in the other.
func TestOverlayStorageCommandOfTheMessagesIsTheOneTheGuidesGive(t *testing.T) {
	for _, page := range []struct{ file, heading string }{
		{"manual-setup.md", "Set up by hand"},
	} {
		body := section(t, page.file, page.heading)
		found := false
		for _, command := range pvesmCommands(body) {
			if !strings.Contains(command, "...") { // a guide may abbreviate it
				found = true
				if command != pve.CreateOverlayStorageCommand {
					t.Errorf("the %q section of docs/%s gives\n  %s\nand the messages say\n  %s", page.heading, page.file, command, pve.CreateOverlayStorageCommand)
				}
			}
		}
		if !found {
			t.Errorf("the %q section of docs/%s has no `pvesm add ...` command in code", page.heading, page.file)
		}
	}
}

// pvesmCommands are the `pvesm add ...` commands a text gives: in inline code,
// or alone on a line (as in a code block).
func pvesmCommands(text string) []string {
	var found []string
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "pvesm add ") {
			found = append(found, trimmed)
		}
		for _, m := range inlineCode.FindAllStringSubmatch(line, -1) {
			if strings.HasPrefix(m[1], "pvesm add ") {
				found = append(found, m[1])
			}
		}
	}
	return found
}

// Wherever else a page gives the command, it is the same one.
func TestEveryPvesmAddCommandInTheGuidesIsTheOneTheMessagesGive(t *testing.T) {
	seen := 0
	for _, file := range documentationFiles(t) {
		for _, line := range markdownLines(t, file) {
			for _, command := range pvesmCommands(line.text) {
				if !strings.Contains(command, "...") {
					seen++
					if command != pve.CreateOverlayStorageCommand {
						t.Errorf("%s gives `%s`, and the messages say `%s`", line.where(), command, pve.CreateOverlayStorageCommand)
					}
				}
			}
		}
	}
	if seen < 1 {
		t.Errorf("found the command %d times in the guides, want it at least in the steps of docs/manual-setup.md", seen)
	}
}

// The hint says where the storage is added ("quickstart, step 2", where
// certistack setup does it), and the init note points at the Plans page:
// both pages and the setting must exist under those names.
func TestOverlayStorageHintNamesRealDocumentation(t *testing.T) {
	if !strings.HasSuffix(pve.CreateOverlayStorageHint, "(quickstart, step 2)") {
		t.Fatalf("the hint = %q; this test reads where it sends the reader", pve.CreateOverlayStorageHint)
	}
	setup := section(t, "quickstart.md", "2. Run the setup") // fails when the heading is gone
	if !strings.Contains(setup, "overlay storage") {
		t.Error("step 2 of docs/quickstart.md does not mention the overlay storage, which the hint sends the reader there for")
	}
	reference := markdownText(t, filepath.Join(docRoot, "docs", "plan-reference.md"))
	if !strings.HasPrefix(reference, "# Plans\n") {
		t.Errorf("docs/plan-reference.md is not titled \"Plans\", the name init's note gives it")
	}
	if !strings.Contains(reference, "`overlay_storage`") {
		t.Error("docs/plan-reference.md does not document overlay_storage, which init's note points at")
	}
}

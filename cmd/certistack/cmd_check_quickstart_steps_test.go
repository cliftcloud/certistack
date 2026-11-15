// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// quickstartStepNumber is the number of the quickstart's step whose heading
// contains words ("## 3. Write your first plan"), read from the page, so that
// the step check names is whatever the page numbers it.
func quickstartStepNumber(t *testing.T, words string) int {
	t.Helper()
	heading := regexp.MustCompile(`(?m)^## (\d+)\. (.+)$`)
	found := 0
	for _, m := range heading.FindAllStringSubmatch(markdownText(t, filepath.Join(docRoot, "docs", "quickstart.md")), -1) {
		if strings.Contains(strings.ToLower(m[2]), words) {
			if found != 0 {
				t.Fatalf("two steps of docs/quickstart.md have %q in their heading", words)
			}
			found, _ = strconv.Atoi(m[1])
		}
	}
	if found == 0 {
		t.Fatalf("docs/quickstart.md has no numbered step with %q in its heading", words)
	}
	return found
}

// check sends the reader to a quickstart step by number in four places: the
// setup that writes the environment file it asks for (layer 1, twice) and the
// SSH key it asks to be authorized (layer 2), and the first plan it asks for
// (the next-step line, and layer 7). It said step 3 for the file and step 4
// for the plan, which were steps 2 and 3 in the quickstart (CR2-08), and the
// numbers moved from the page without anything noticing. They are read from the
// page's headings here.
func TestCheckNamesTheQuickstartStepsByTheirNumbers(t *testing.T) {
	setup := fmt.Sprintf("(quickstart step %d)", quickstartStepNumber(t, "run the setup"))
	planning := fmt.Sprintf("(quickstart step %d)", quickstartStepNumber(t, "first plan"))
	byHand := `(docs/manual-setup.md, "Set up by hand")`

	t.Run("layer 2 sends a missing key to the setup, and by hand to the guide", func(t *testing.T) {
		c := readyController(t)
		if err := os.Remove(c.identity); err != nil {
			t.Fatal(err)
		}
		out, _ := failsAt(t, c)
		if !strings.Contains(out, "Run certistack setup "+setup+": it creates the key and has the node authorize it.") {
			t.Errorf("layer 2 does not name %s:\n%s", setup, out)
		}
		if !strings.Contains(out, "on the node "+byHand+".") {
			t.Errorf("layer 2 does not send the by-hand reader to %s:\n%s", byHand, out)
		}
	})

	t.Run("the next step after a passing check is to write a plan", func(t *testing.T) {
		c := readyController(t)
		withNode(t, &nodeStub{})
		out, err := runRootWithInput(t, "", "check", "--env-file", c.env)
		if err != nil {
			t.Fatalf("check: %v\n%s", err, out)
		}
		if !strings.Contains(out, "Next: write a first plan with certistack init --env-file "+c.env+" "+planning+",") {
			t.Errorf("the next-step line does not name %s:\n%s", planning, out)
		}
	})

	t.Run("layer 7 sends a missing plan to the step that writes one", func(t *testing.T) {
		c := readyController(t)
		withNode(t, &nodeStub{})
		out, _ := failsAt(t, c, filepath.Join(c.dir, "no-such-plan.yaml"))
		if !strings.Contains(out, "write one with certistack init --env-file "+c.env+" "+planning+".") {
			t.Errorf("layer 7 does not name %s:\n%s", planning, out)
		}
	})

	t.Run("layer 1 sends a missing environment file to the setup, and by hand to the guide", func(t *testing.T) {
		c := readyController(t)
		out, _ := failsAt(t, controllerDir{env: filepath.Join(c.dir, "missing.env"), dir: c.dir})
		if !strings.Contains(out, "Run certistack setup "+setup+": it asks for a directory and writes controller.env there. Or write the file by hand "+byHand+":") {
			t.Errorf("layer 1 (missing file) does not name %s and %s:\n%s", setup, byHand, out)
		}
	})

	t.Run("layer 1 sends missing variables to the guide and to the setup", func(t *testing.T) {
		dir := t.TempDir()
		env := filepath.Join(dir, "controller.env")
		if err := os.WriteFile(env, []byte("PVE_URL=https://pve-node-01.example.com:8006\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out, _ := failsAt(t, controllerDir{env: env, dir: dir})
		if !strings.Contains(out, "as NAME=value lines "+byHand+", or run certistack setup "+setup+" to write the file.") {
			t.Errorf("layer 1 (missing variables) does not name %s and %s:\n%s", byHand, setup, out)
		}
	})
}

// The by-hand pages check names are headings that exist: the manual setup page
// has a section called "Set up by hand", and it holds the file check asks for.
func TestCheckSendsAHandWrittenSetupToTheGuide(t *testing.T) {
	const heading = "Set up by hand"
	guide := markdownText(t, filepath.Join(docRoot, "docs", "manual-setup.md"))
	if !regexp.MustCompile(`(?m)^## ` + heading + `( \{#[^}]*\})?$`).MatchString(guide) {
		t.Fatalf("docs/manual-setup.md has no heading %q", heading)
	}
	if setupByHandGuide != `(docs/manual-setup.md, "`+heading+`")` {
		t.Errorf("setupByHandGuide = %q, which does not name the %q section", setupByHandGuide, heading)
	}
}

// A non-root account without the sudoers entries is sent to the subsection of
// the manual setup page that gives the rule. check said "(quickstart: set up SSH
// access)", a section no page has (L3). The page and the heading are read from
// the docs here, and the heading must be the one that holds the rule.
func TestCheckSendsANonRootAccountToTheSudoersRule(t *testing.T) {
	const heading = "The sudoers rule for a non-root account"
	guide := markdownText(t, filepath.Join(docRoot, "docs", "manual-setup.md"))
	if !regexp.MustCompile(`(?m)^###? ` + heading + `$`).MatchString(guide) {
		t.Fatalf("docs/manual-setup.md has no heading %q", heading)
	}
	for _, text := range []string{"create protected node workspace: SSH command on pve: ssh failed: exit status 1: sudo: a password is required", "install: cannot create directory '/var/lib/certistack': Permission denied"} {
		c := readyController(t)
		withNode(t, &nodeStub{stagingError: errors.New(text)})
		out, _ := failsAt(t, c)
		if want := `CERTISTACK_SSH_SUDO=true (docs/manual-setup.md, "` + heading + `").`; !strings.Contains(out, want) {
			t.Errorf("the fix for %q does not end %q:\n%s", text, want, out)
		}
		if strings.Contains(out, "quickstart: set up SSH access") {
			t.Errorf("the fix still names a quickstart section that does not exist:\n%s", out)
		}
	}
}

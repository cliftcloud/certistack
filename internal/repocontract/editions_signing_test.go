// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Report signing and key generation are the Enterprise Edition's; Community
// writes the report unsigned and keeps the verifier. These tests hold the
// documentation to that boundary (no_signing_code_test.go holds the code).

// The Community feature list names the verifier and no signing command or
// flag, and no page offers Community a signing step.
func TestCommunityDocsOfferNoSigningStep(t *testing.T) {
	doc := readRepoText(t, "docs", "editions.md")

	list := section(t, doc, "Community feature list")
	var commands, flags string
	for _, line := range strings.Split(list, "\n") {
		if rest, ok := strings.CutPrefix(line, "- Commands: "); ok {
			commands = rest
		}
		if rest, ok := strings.CutPrefix(line, "- Flags: "); ok {
			flags = rest
		}
	}
	if commands == "" || flags == "" {
		t.Fatal("docs/editions.md lists no commands or no flags under \"Community feature list\"")
	}
	if strings.Contains(commands, "`keygen`") {
		t.Error("docs/editions.md lists `keygen` as a Community command")
	}
	for _, signing := range []string{"`--key`", "`--private`", "`--public`", "`--signing-key`"} {
		if strings.Contains(flags, signing) {
			t.Errorf("docs/editions.md lists the signing flag %s as Community's", signing)
		}
	}
	// The verifier and its flags are listed.
	for _, kept := range []string{"`verify-report`", "`report`"} {
		if !strings.Contains(commands, kept) {
			t.Errorf("docs/editions.md does not list %s", kept)
		}
	}
	for _, kept := range []string{"`--keyring`", "`--public-key`", "`--trusted-key`", "`--expect-outcome`"} {
		if !strings.Contains(flags, kept) {
			t.Errorf("docs/editions.md does not list the verifier's %s", kept)
		}
	}

	// No page offers Community a signing command or setting. reports.md is the
	// exception: its Enterprise section shows how anyone verifies a signed report.
	enterpriseSection := map[string]bool{"reports.md": true}
	offered := regexp.MustCompile("certistack keygen|CERTISTACK_SIGN_KEY|`--signing-key`|controller-signing|trusted-signers\\.pub --expect")
	var files []string
	for _, pattern := range []string{"README.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md", "LICENSING-FAQ.md", "CHANGELOG.md", "docs/*.md", "examples/*.md", "examples/*.yaml"} {
		matches, err := filepath.Glob(repoFile(filepath.FromSlash(pattern)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	for _, root := range []string{"deploy", "terraform"} {
		err := filepath.WalkDir(repoFile(root), func(path string, entry fs.DirEntry, err error) error {
			if err == nil && !entry.IsDir() && (strings.HasSuffix(path, ".md") || strings.HasSuffix(path, ".example")) {
				files = append(files, path)
			}
			return err
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if len(files) < 20 {
		t.Fatalf("found only %d documents to check", len(files))
	}
	for _, file := range files {
		if enterpriseSection[filepath.Base(file)] {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(data), "\n") {
			if offered.MatchString(line) {
				t.Errorf("%s:%d offers Community a signing step, which is the Enterprise Edition's: %s", filepath.ToSlash(file), number+1, strings.TrimSpace(line))
			}
		}
	}
}

// The comparison tables (the README's and docs/editions.md's, which another test
// holds identical) say that the Enterprise Edition produces the signed attestation
// and that Community writes the report of the run and lets anyone verify a signed one.
func TestEditionTablesSayWhoSignsAndWhoVerifies(t *testing.T) {
	for _, page := range [][]string{{"README.md"}, {"docs", "editions.md"}} {
		text := readRepoText(t, page...)
		rows := map[string]string{}
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "| Signed attestations") || strings.HasPrefix(line, "| The report of every run") || strings.HasPrefix(line, "| The verifier (") {
				rows[strings.SplitN(line, " |", 2)[0]] = line
			}
		}
		name := filepath.ToSlash(filepath.Join(page...))
		sign := rows["| Signed attestations: the report signed with an Ed25519 key that the `certistackd` service keeps in a root-only file"]
		if !strings.HasSuffix(sign, "| No | Yes |") {
			t.Errorf("%s: the signed attestations row is %q, want Community No and Enterprise Yes", name, sign)
		}
		report := rows["| The report of every run: JSON (its RFC 8785 canonical form is what a signature covers), with the cleanup record, read in the terminal with `report show`"]
		if !strings.Contains(report, "Yes, written unsigned") {
			t.Errorf("%s: the report row is %q, want Community to write it unsigned", name, report)
		}
		verifier := rows["| The verifier (`verify-report`, which anyone can run with no license)"]
		if !strings.HasSuffix(verifier, "| Yes | Yes |") {
			t.Errorf("%s: the verifier row is %q, want Yes in both editions", name, verifier)
		}
		if strings.Contains(text, "| Signed JSON evidence, the verifier") {
			t.Errorf("%s has a row that gives Community signed evidence", name)
		}
	}
}

// The README quickstart has no signing step: no key is made, none is named, and
// the commands end with reading the report.
func TestReadmeQuickstartHasNoSigningStepAndEndsReadingTheReport(t *testing.T) {
	readme := readRepoText(t, "README.md")
	quickstart := section(t, readme, "Quickstart")
	block := regexp.MustCompile("(?s)```bash\n(.*?)```").FindStringSubmatch(quickstart)
	if block == nil {
		t.Fatal("the README quickstart has no bash block")
	}
	var last string
	for _, line := range strings.Split(block[1], "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "keygen") || strings.Contains(line, "--key") || strings.Contains(line, "controller-signing") {
			t.Errorf("the README quickstart has a signing step: %s", line)
		}
		last = line
	}
	if last != "certistack report show" && !strings.HasPrefix(last, "certistack report show ") {
		t.Errorf("the README quickstart ends with %q, want certistack report show", last)
	}
	if strings.Contains(block[1], "verify-report") {
		t.Error("the README quickstart ends with verify-report")
	}
}

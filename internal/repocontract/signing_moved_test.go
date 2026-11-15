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

// Report signing and key generation moved from the Community Edition to the
// Enterprise Edition on 2026-10-08, before the first release. These tests hold
// the documentation to it (no_signing_code_test.go holds the code).

// docs/community-commitments.md says, with the date, that signing moved to the
// Enterprise Edition before the first release and that nothing which shipped
// has moved; and no list of what Community offers still names the command, the
// flag or the variable that went.
func TestReportSigningMovedToEnterpriseIsStatedAndNotOffered(t *testing.T) {
	doc := readRepoText(t, "docs", "community-commitments.md")

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
		t.Fatal("docs/community-commitments.md lists no commands or no flags under \"Community feature list\"")
	}
	if strings.Contains(commands, "`keygen`") {
		t.Error("docs/community-commitments.md still lists `keygen` as a Community command")
	}
	for _, gone := range []string{"`--key`", "`--private`", "`--public`", "`--signing-key`"} {
		if strings.Contains(flags, gone) {
			t.Errorf("docs/community-commitments.md still lists the flag %s as Community's", gone)
		}
	}
	// What stays is listed: the verifier and its flags.
	for _, kept := range []string{"`verify-report`", "`report`"} {
		if !strings.Contains(commands, kept) {
			t.Errorf("docs/community-commitments.md no longer lists %s", kept)
		}
	}
	for _, kept := range []string{"`--keyring`", "`--public-key`", "`--trusted-key`", "`--expect-outcome`"} {
		if !strings.Contains(flags, kept) {
			t.Errorf("docs/community-commitments.md no longer lists the verifier's %s", kept)
		}
	}

	// The page wraps its lines: compare what it says, not where it breaks.
	flat := strings.Join(strings.Fields(doc), " ")
	moved := regexp.MustCompile(`2026-10-08.{0,300}report signing and key generation.{0,400}Enterprise Edition`).FindString(flat)
	if moved == "" {
		t.Error("docs/community-commitments.md does not say, with the date 2026-10-08, that report signing and key generation moved to the Enterprise Edition")
	}
	for _, want := range []string{"The verifier stays in Community", "unsigned", "was never in a release either", "nothing that shipped in a release has moved"} {
		if !strings.Contains(flat, want) {
			t.Errorf("docs/community-commitments.md does not say %q about the move of report signing", want)
		}
	}

	// Everywhere else: no page offers the command or the setting that went. The
	// pages that say they are gone are the exceptions.
	offered := regexp.MustCompile("certistack keygen|CERTISTACK_SIGN_KEY|`--signing-key`|controller-signing|trusted-signers\\.pub --expect")
	says := map[string]bool{"community-commitments.md": true, "CHANGELOG.md": true, "reports.md": true}
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
		if says[filepath.Base(file)] {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(data), "\n") {
			if offered.MatchString(line) {
				t.Errorf("%s:%d offers a signing step the Community Edition no longer has: %s", filepath.ToSlash(file), number+1, strings.TrimSpace(line))
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
		verifier := rows["| The verifier (`verify-report`, which anyone can run with no licence) and a script that verifies a signed report without CertiStack"]
		if !strings.HasSuffix(verifier, "| Yes | Yes |") {
			t.Errorf("%s: the verifier row is %q, want Yes in both editions", name, verifier)
		}
		if strings.Contains(text, "| Signed JSON evidence, the verifier") {
			t.Errorf("%s still has the old row that gives Community signed evidence", name)
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
			t.Errorf("the README quickstart still has a signing step: %s", line)
		}
		last = line
	}
	if !strings.HasPrefix(last, "certistack report show ") {
		t.Errorf("the README quickstart ends with %q, want certistack report show", last)
	}
	if strings.Contains(block[1], "verify-report") {
		t.Error("the README quickstart still ends with verify-report")
	}
}

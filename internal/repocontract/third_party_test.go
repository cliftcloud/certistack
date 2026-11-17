// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The compiled program carries third-party code, and the BSD, MIT and Apache
// licenses of that code require their notices to travel with a distribution of
// it. THIRD-PARTY-NOTICES.md holds them; a module added or bumped in go.mod
// without regenerating it (scripts/gen-third-party-notices.py) leaves a
// release shipping a notice for another version, or none.
func TestThirdPartyNoticesCoverEveryModuleInGoMod(t *testing.T) {
	gomod, err := os.ReadFile(repoFile("go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	notices, err := os.ReadFile(repoFile("THIRD-PARTY-NOTICES.md"))
	if err != nil {
		t.Fatalf("THIRD-PARTY-NOTICES.md is missing: %v", err)
	}
	requirement := regexp.MustCompile(`(?m)^\s+(\S+)\s+(v\S+)`)
	found := 0
	inRequire := false
	for _, line := range strings.Split(string(gomod), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "require ("):
			inRequire = true
			continue
		case trimmed == ")":
			inRequire = false
			continue
		case !inRequire:
			continue
		}
		m := requirement.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		found++
		if heading := "## " + m[1] + " " + m[2] + "\n"; !strings.Contains(string(notices), heading) {
			t.Errorf("THIRD-PARTY-NOTICES.md has no section %q: run python3 scripts/gen-third-party-notices.py", strings.TrimSpace(heading))
		}
	}
	if found == 0 {
		t.Fatal("no module requirement found in go.mod: the test does not read it")
	}
	notice, err := os.ReadFile(repoFile("NOTICE"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(notice), "THIRD-PARTY-NOTICES.md") {
		t.Error("NOTICE does not point to THIRD-PARTY-NOTICES.md")
	}
}

// The released controller image carries the license files, not only the
// executable: a BSD or Apache license asks for its notice in a distribution.
func TestControllerImageCarriesTheLicenseFiles(t *testing.T) {
	dockerfile, err := os.ReadFile(repoFile("deploy", "controller", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "COPY LICENSE NOTICE THIRD-PARTY-NOTICES.md /usr/share/doc/certistack/"
	if !strings.Contains(string(dockerfile), want) {
		t.Errorf("the Dockerfile lacks %q", want)
	}
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.md"} {
		if _, err := os.Stat(repoFile(name)); err != nil {
			t.Errorf("%s is missing from the repository root, so the image build cannot copy it: %v", name, err)
		}
	}
}

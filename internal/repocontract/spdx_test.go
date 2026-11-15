// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	communityID = "AGPL-3.0-or-later"
	// spdxWindow is how far into a file the SPDX line must appear: after a
	// shebang, never later.
	spdxWindow = 8
)

// spdxChecked reports whether a repository file must carry a licence header,
// by its name. Generated lock files and data are not source. A script with
// no known name is found by its first line instead (beginsWithShebang).
func spdxChecked(name string) bool {
	switch name {
	case "Makefile", "Dockerfile", "compose.yaml", "compose.yml":
		return true
	case ".terraform.lock.hcl":
		return false
	}
	// Dockerfile.prod and prod.Dockerfile are Dockerfiles too.
	if strings.HasPrefix(name, "Dockerfile.") || strings.EqualFold(filepath.Ext(name), ".dockerfile") {
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".go", ".sh", ".py", ".yml", ".yaml", ".tf", ".hcl":
		return true
	}
	return false
}

// beginsWithShebang reports whether the file at path is an executable script
// by its first two bytes, whatever it is called: the appliance's
// certistack-controller wrapper is installed under that name, with no
// extension.
func beginsWithShebang(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	first := make([]byte, 2)
	if _, err := io.ReadFull(file, first); err != nil {
		return false
	}
	return bytes.Equal(first, []byte("#!"))
}

// spdxSkippedDir lists directories that hold data, generated output or
// someone else's files rather than the project's source. .lab is the
// operator's own lab and is never part of the public release.
func spdxSkippedDir(name string) bool {
	switch name {
	case ".git", ".lab", "node_modules", "vendor", "testdata", ".terraform", "dist", "bin", "cases":
		return true
	}
	return false
}

func spdxOf(text string) string {
	for i, line := range strings.Split(text, "\n") {
		if i >= spdxWindow {
			break
		}
		if _, after, ok := strings.Cut(line, "SPDX-License-Identifier:"); ok {
			return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(after), "-->"))
		}
	}
	return ""
}

// licenceProblems walks root and returns one line for each source file whose
// licence header is missing or names another licence, and how many files it
// checked.
func licenceProblems(root string) (problems []string, checked int, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && spdxSkippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !spdxChecked(d.Name()) && !(d.Type().IsRegular() && beginsWithShebang(path)) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		switch got := spdxOf(string(raw)); got {
		case communityID:
		case "":
			problems = append(problems, fmt.Sprintf("%s has no SPDX-License-Identifier in its first %d lines (want %s)", path, spdxWindow, communityID))
		default:
			problems = append(problems, fmt.Sprintf("%s declares %q, want %s", path, got, communityID))
		}
		return nil
	})
	return problems, checked, err
}

// TestEverySourceFileCarriesTheCommunityHeader is the open-core licence guard
// for the public repository: a source file with no SPDX line, or one that names
// another licence (an Enterprise identifier here would put proprietary terms on
// AGPL code, or the reverse), fails with the file's name. A source file is one
// with a source file's name or one that begins with a shebang.
func TestEverySourceFileCarriesTheCommunityHeader(t *testing.T) {
	problems, checked, err := licenceProblems(repoFile())
	if err != nil {
		t.Fatal(err)
	}
	for _, problem := range problems {
		t.Error(problem)
	}
	if checked < 250 {
		t.Fatalf("only %d files were checked; the scan is not looking at the repository", checked)
	}
}

// The guard knew sources by their names, and a shipped script with no
// extension (deploy/appliance/files/certistack-controller, a #!/bin/sh
// wrapper) had no header and was never looked at. The same scan, over a tree
// that holds each kind of file.
func TestLicenceGuardTakesScriptsByTheirShebangAndDockerfilesByTheirNames(t *testing.T) {
	root := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const header = "# SPDX-License-Identifier: AGPL-3.0-or-later\n"
	write("deploy/wrapper", "#!/bin/sh\necho no header\n")                  // a script with no extension and no header: reported
	write("deploy/wrapper-ok", "#!/bin/sh\n"+header+"echo header\n")        // the same with a header: clean
	write("deploy/wrapper-ee", "#!/bin/sh\n# SPDX-License-Identifier: X\n") // another licence: reported
	write("deploy/notes", "plain text with no header\n")                    // not a script: not checked
	write("deploy/testdata/fixture", "#!/bin/sh\necho a fixture\n")         // under testdata: skipped
	write("images/Dockerfile.prod", "FROM scratch\n")                       // a Dockerfile by a longer name: reported
	write("images/app.Dockerfile", "FROM scratch\n")                        // and by an extension: reported
	write("images/Dockerfile", header+"FROM scratch\n")                     // the plain name, with a header: clean
	write("lock/.terraform.lock.hcl", "# generated\n")                      // a generated file: not source
	problems, checked, err := licenceProblems(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		filepath.Join(root, "deploy", "wrapper"):         true,
		filepath.Join(root, "deploy", "wrapper-ee"):      true,
		filepath.Join(root, "images", "Dockerfile.prod"): true,
		filepath.Join(root, "images", "app.Dockerfile"):  true,
	}
	reported := map[string]bool{}
	for _, problem := range problems {
		path, _, _ := strings.Cut(problem, " ")
		reported[path] = true
		if !want[path] {
			t.Errorf("reported a file that is fine: %s", problem)
		}
	}
	for path := range want {
		if !reported[path] {
			t.Errorf("did not report %s", path)
		}
	}
	if checked != 6 {
		t.Errorf("checked %d files, want 6 (the four reported, wrapper-ok and the plain Dockerfile)", checked)
	}
}

func TestLicenseIsTheAGPL(t *testing.T) {
	raw, err := os.ReadFile(repoFile("LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "GNU AFFERO GENERAL PUBLIC LICENSE") || !strings.Contains(string(raw), "Version 3") {
		t.Errorf("LICENSE is not the GNU Affero General Public License, version 3")
	}
}

func TestSPDXOfParsing(t *testing.T) {
	for _, tc := range []struct{ name, text, want string }{
		{"go", "// SPDX-License-Identifier: AGPL-3.0-or-later\n", communityID},
		{"shebang", "#!/bin/sh\n# SPDX-License-Identifier: AGPL-3.0-or-later\n", communityID},
		{"other", "# SPDX-License-Identifier: LicenseRef-CertiStack-EE\n", "LicenseRef-CertiStack-EE"},
		{"too late", "1\n2\n3\n4\n5\n6\n7\n8\n# SPDX-License-Identifier: AGPL-3.0-or-later\n", ""},
		{"none", "package x\n", ""},
	} {
		if got := spdxOf(tc.text); got != tc.want {
			t.Errorf("%s: spdxOf = %q, want %q", tc.name, got, tc.want)
		}
	}
}

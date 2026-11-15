// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// enterpriseModule is the import path of the proprietary product. The
// dependency runs one way: Enterprise imports this module, never the reverse.
const enterpriseModule = "github.com/cliftcloud/certistack-msp"

// TestCommunityStandsAlone holds the open-core boundary: this repository must
// build, test and run with the Enterprise repository absent, so nothing in it
// may require or import Enterprise. The Go toolchain already refuses an import
// of a module that is not in go.mod; this makes the rule explicit, so a stray
// "replace" or a vendored copy of the module fails here with a sentence that
// names the rule rather than with a build error somewhere else.
func TestCommunityStandsAlone(t *testing.T) {
	goMod, err := os.ReadFile(repoFile("go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(goMod), enterpriseModule) {
		t.Errorf("go.mod mentions %s: Community must not require, replace or exclude the Enterprise module", enterpriseModule)
	}

	root := repoFile()
	fset := token.NewFileSet()
	checked := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			// A file that does not parse is another test's problem; it cannot
			// import anything here.
			return nil
		}
		checked++
		for _, spec := range file.Imports {
			imported := strings.Trim(spec.Path.Value, `"`)
			if imported == enterpriseModule || strings.HasPrefix(imported, enterpriseModule+"/") {
				t.Errorf("%s imports %s: Community must never import Enterprise", path, imported)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 100 {
		t.Fatalf("only %d Go files were checked; the scan is not looking at the repository", checked)
	}
}

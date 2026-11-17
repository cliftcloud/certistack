// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Report signing and key generation are the Enterprise Edition's. The Community
// source has no code that makes a signature, generates a key pair or reads a
// private key; what it has is the verifier. These tests hold the tree to it.

// productSources lists the Go files of the shipped program and its libraries:
// everything under cmd, pkg and internal that is not a test, and not the
// test-only helper that makes signed reports for tests.
func productSources(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, root := range []string{"cmd", "pkg", "internal"} {
		err := filepath.WalkDir(repoFile(root), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			slashed := filepath.ToSlash(path)
			if entry.IsDir() && strings.HasSuffix(slashed, "pkg/attest/attesttest") {
				return filepath.SkipDir
			}
			if !entry.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) < 100 {
		t.Fatalf("found only %d product source files", len(files))
	}
	return files
}

func TestCommunityProductCodeMakesNoSignatureAndReadsNoPrivateKey(t *testing.T) {
	forbidden := regexp.MustCompile(`ed25519\.Sign\(|ed25519\.GenerateKey\(|ed25519\.NewKeyFromSeed\(|ParsePKCS8PrivateKey|MarshalPKCS8PrivateKey|LoadPrivateKeyFromFile|SavePrivateKey|SaveKeyPair|SaveKeyToFile|GenerateKeyPair\(|SignCanonical\(|ed25519\.PrivateKey\b`)
	for _, file := range productSources(t) {
		// The one legitimate use of a key made from a seed: a public key nobody
		// holds the private half of, offered to a known_hosts file to learn
		// whether it has a line for a host. It signs nothing.
		if filepath.ToSlash(file) == "../../internal/nodesetup/hostkey.go" {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue // a comment that explains what is not there
			}
			if forbidden.MatchString(line) {
				t.Errorf("%s:%d is product code that handles a private key or makes a signature (the Enterprise Edition does that): %s", filepath.ToSlash(file), number+1, trimmed)
			}
		}
	}
}

// The code has no signing-key setting and no keygen command. Only the
// controller's refusal of a file that sets the signing variable may name it.
func TestCommunityProductCodeHasNoSigningKeySetting(t *testing.T) {
	for _, file := range productSources(t) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if filepath.Base(file) != "environment.go" && strings.Contains(text, "CERTISTACK_SIGN_KEY") {
			t.Errorf("%s names CERTISTACK_SIGN_KEY, which the Community controller does not read", filepath.ToSlash(file))
		}
		if strings.Contains(text, `"signing-key"`) || regexp.MustCompile(`Use:\s+"keygen`).MatchString(text) {
			t.Errorf("%s declares a signing-key flag or a keygen command", filepath.ToSlash(file))
		}
	}
}

// No product package imports attest/attesttest, the test-only helper that makes
// signed reports: it would put a signing path into a shipped binary.
func TestNoProductPackageImportsTheTestSigningHelper(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("needs the go tool")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-f", "{{.ImportPath}}: {{join .Imports \" \"}}", "./...")
	cmd.Dir = repoFile()
	out, err := cmd.Output()
	if err != nil {
		// With the go tool on the PATH this check must run: a build that does not
		// list would otherwise drop the only test that no product package imports
		// the signing helper, and report a pass.
		t.Fatalf("go list failed, so the imports cannot be checked: %v", err)
	}
	checked := 0
	for _, line := range strings.Split(string(out), "\n") {
		importer, imports, found := strings.Cut(line, ": ")
		if !found {
			continue
		}
		checked++
		if strings.HasSuffix(importer, "/pkg/attest/attesttest") {
			continue
		}
		for _, imported := range strings.Fields(imports) {
			if strings.HasSuffix(imported, "/pkg/attest/attesttest") {
				t.Errorf("%s imports pkg/attest/attesttest, which is for tests only", importer)
			}
		}
	}
	if checked < 30 {
		t.Fatalf("go list gave %d packages; the test cannot see the imports", checked)
	}
}

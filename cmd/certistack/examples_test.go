// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// privateAddress matches RFC 1918 addresses. Shipped plans must use RFC 5737
// documentation ranges so that a copied example points at no production
// network until it is edited.
var privateAddress = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)

// TestShippedPlansValidateAndUseDocumentationAddresses keeps every plan a new
// user might copy (examples/ and the maintained testdata fixtures) loadable by
// the current schema, free of private addresses, and free of credential
// material that belongs in the protected environment file.
func TestShippedPlansValidateAndUseDocumentationAddresses(t *testing.T) {
	var paths []string
	for _, pattern := range []string{
		filepath.Join("..", "..", "examples", "*.yaml"),
		filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"),
		filepath.Join("..", "..", "testdata", "plans", "multi_tier_sandbox.yaml"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, matches...)
	}
	if len(paths) < 3 {
		t.Fatalf("expected at least one example plan and two fixtures, found %v", paths)
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := config.LoadFromFile(path); err != nil {
				t.Fatalf("%s must validate: %v", path, err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for lineNumber, line := range strings.Split(string(raw), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				if match := privateAddress.FindString(trimmed); match != "" {
					t.Errorf("%s:%d uses private address %s; shipped plans use RFC 5737 documentation addresses", path, lineNumber+1, match)
				}
				for _, forbidden := range []string{"pbs_repository", "pbs_password", "root@pam"} {
					if strings.Contains(trimmed, forbidden) {
						t.Errorf("%s:%d contains %q; credentials and repository strings belong in the protected environment file", path, lineNumber+1, forbidden)
					}
				}
			}
		})
	}
}

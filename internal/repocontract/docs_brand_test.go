// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"regexp"
	"testing"
)

// The documentation carries CertiStack's own icon, not the theme's generic one:
// mkdocs.yml names a logo and a favicon, and both are files in docs/.
func TestDocsThemeNamesAnExistingLogoAndFavicon(t *testing.T) {
	config := readRepoText(t, "mkdocs.yml")
	for _, key := range []string{"logo", "favicon"} {
		match := regexp.MustCompile(`(?m)^  ` + key + `:\s*(\S+)\s*$`).FindStringSubmatch(config)
		if match == nil {
			t.Errorf("mkdocs.yml sets no theme %s: the docs fall back to the generic theme icon", key)
			continue
		}
		info, err := os.Stat(repoFile("docs", match[1]))
		if err != nil || info.Size() == 0 {
			t.Errorf("theme %s %q is not a file in docs/: %v", key, match[1], err)
		}
	}
}

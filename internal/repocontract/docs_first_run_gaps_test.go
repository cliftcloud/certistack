// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"strings"
	"testing"
)

// squash is a text with every run of white space made one space, so that a
// sentence is found whichever way a page wraps its lines.
func squash(text string) string { return strings.Join(strings.Fields(text), " ") }

// A newcomer who followed the first-run pages to the letter reached these
// places and found the page silent (live cold read, second pass). Each
// sentence below is what the page must keep saying.
func TestFirstRunPagesKeepWhatTheSecondColdReadFound(t *testing.T) {
	quickstart := squash(readRepoText(t, "docs", "quickstart.md"))
	manualSetup := squash(readRepoText(t, "docs", "manual-setup.md"))
	readme := squash(readRepoText(t, "README.md"))
	goingFurther := squash(readRepoText(t, "docs", "going-further.md"))

	for _, tc := range []struct {
		finding, page, text, want string
	}{
		{"CR2-01 going-further: another directory means rewriting the paths", "docs/going-further.md", goingFurther,
			"replace `/secure/certistack` by your directory in every command in these pages, and pass `--known-hosts YOUR_DIR/known_hosts` to `certistack setup trust-node`"},
		{"CR2-01 README: the no-sudo reader is sent to the page that says it", "README.md", readme,
			"No `sudo`? See [Install without sudo](docs/going-further.md#install-without-sudo)"},
		{"CR2-01 manual setup", "docs/manual-setup.md", manualSetup,
			"replace `/secure/certistack` by it in every command below, and pass `--known-hosts YOUR_DIR/known_hosts` to `certistack setup trust-node`"},
		{"CR2-02 nftables is on some stock versions", "docs/manual-setup.md", manualSetup,
			"lacks `libguestfs-tools` (`guestfish`), and on some versions `nftables` (`nft`); this installs what is missing and leaves the rest"},
		{"CR2-03 the numbered order's rbac commands take the namespace (now the steps by hand)", "docs/manual-setup.md", manualSetup,
			"If your backups are in a PBS namespace, add `--pbs-namespace NAME` to the `--part pbs` command; without it the PBS user can read the whole datastore"},
		{"CR2-03 the setup asks for the namespace", "docs/quickstart.md", quickstart,
			"When you name the PBS yourself and your backups are in a PBS namespace, give it. An empty answer asks `Continue?` (the default is no), because the PBS user can then read every namespace of the datastore"},
		{"CR2-04 which part of the printed table is the secret (now the steps by hand)", "docs/manual-setup.md", manualSetup,
			"The secret is the long string in the `value` row, between the `│` characters: copy only that string into `PVE_TOKEN_SECRET`"},
		{"CR2-10 doctor section: the plan of the quickstart", "docs/manual-setup.md", manualSetup,
			"doctor /root/my-first-plan.yaml --env-file /root/doctor.env"},
		{"CR2-10 doctor section: a source build", "docs/manual-setup.md", manualSetup,
			"for your own build, name `bin/certistack-linux-amd64` in the clone instead"},
	} {
		if !strings.Contains(tc.text, tc.want) {
			t.Errorf("%s: %s no longer says %q", tc.finding, tc.page, tc.want)
		}
	}
	if strings.Contains(manualSetup, "lacks `libguestfs-tools` (`guestfish`) and `nftables` (`nft`)") {
		t.Error("CR2-02: manual-setup.md says again that a stock node lacks nftables")
	}
}

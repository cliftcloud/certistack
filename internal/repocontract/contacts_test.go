// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The product has one domain, certistack.dev, and exactly five mailboxes. No
// other address, and no product URL at another domain, may stand in a text the
// repository ships or publishes: a customer, a researcher or an auditor who
// writes to an address the text names must reach someone.
const contactDomain = "certistack.dev"

// contactMailboxes are the five. Each has one purpose: security (vulnerability
// reports), sales (buying, quotes, MSP, resellers), licensing (licenses,
// renewals, revocation, the CLA and license questions), conduct (code of
// conduct reports), privacy (telemetry deletion and personal data).
var contactMailboxes = map[string]bool{
	"security":  true,
	"sales":     true,
	"licensing": true,
	"conduct":   true,
	"privacy":   true,
}

var (
	// addressPattern is an e-mail address: a name, an @ and a dotted host with an
	// alphabetic last label (so module versions such as name@v1.2.3 are not one).
	addressPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`)
	// mailtoPattern is a mailto: link with a literal target. A mailto: that is
	// followed by a quote or a variable (a script building the link) is not one.
	mailtoPattern = regexp.MustCompile(`(?i)mailto:([A-Za-z0-9][^\s"'<>)?&]*)`)
	// mailboxNamePattern is one of the five names followed by an at sign,
	// whatever follows it: a name with no domain, or at another domain, is wrong.
	mailboxNamePattern = regexp.MustCompile(`(?i)\b(?:security|sales|licensing|conduct|privacy)@([A-Za-z0-9.\-]*)`)
	// otherDomainPattern is the product's name at a domain that is not its own.
	otherDomainPattern = regexp.MustCompile(`(?i)certistack\.(?:com|net|org|io|app|cloud|co|ai|xyz|us|eu|info|biz|me)\b`)
	// labDomainPattern is the operator's own domain, which names lab hosts and is
	// never a product address.
	labDomainPattern = regexp.MustCompile(`(?i)clift\.cloud\b`)
)

// placeholderHost reports whether a host is reserved for examples and tests
// (RFC 2606, RFC 6761, .internal), a private name or the name of a systemd
// instance unit (container@web.service): such an "address" is a
// fixture, an ssh target, a PBS user id or a unit, never a contact.
func placeholderHost(host string) bool {
	labels := strings.Split(strings.ToLower(host), ".")
	switch labels[len(labels)-1] {
	case "example", "test", "invalid", "localhost", "internal", "local", "lab":
		return true
	case "service", "timer", "socket", "target", "path", "mount", "slice", "scope":
		return true
	}
	if len(labels) >= 2 {
		switch strings.Join(labels[len(labels)-2:], ".") {
		case "example.com", "example.org", "example.net":
			return true
		}
	}
	return false
}

// contactLineProblems returns what one line of text breaks.
func contactLineProblems(line string) []string {
	var problems []string
	for _, address := range addressPattern.FindAllString(line, -1) {
		name, host, _ := strings.Cut(strings.ToLower(address), "@")
		switch {
		case host == contactDomain:
			if !contactMailboxes[name] {
				problems = append(problems, fmt.Sprintf("%s is not one of the five mailboxes", address))
			}
		case strings.Contains(host, "certistack"):
			problems = append(problems, fmt.Sprintf("%s: the only product domain is %s", address, contactDomain))
		case !placeholderHost(host):
			problems = append(problems, fmt.Sprintf("%s is not one of the five mailboxes", address))
		}
	}
	for _, match := range mailtoPattern.FindAllStringSubmatch(line, -1) {
		name, host, ok := strings.Cut(strings.ToLower(match[1]), "@")
		if !ok || host != contactDomain || !contactMailboxes[name] {
			problems = append(problems, fmt.Sprintf("mailto:%s is not one of the five mailboxes", match[1]))
		}
	}
	for _, match := range mailboxNamePattern.FindAllStringSubmatch(line, -1) {
		if strings.ToLower(strings.TrimRight(match[1], ".")) != contactDomain {
			problems = append(problems, fmt.Sprintf("%q names a mailbox with no %s after it", match[0], contactDomain))
		}
	}
	for _, found := range otherDomainPattern.FindAllString(line, -1) {
		problems = append(problems, fmt.Sprintf("%s: the only product domain is %s", found, contactDomain))
	}
	for _, found := range labDomainPattern.FindAllString(line, -1) {
		problems = append(problems, fmt.Sprintf("%s is the operator's lab domain, not a product address or URL", found))
	}
	return problems
}

// contactSkippedDir lists what is not the project's own text: version control,
// the local .lab directory, dependencies and build output.
func contactSkippedDir(name string) bool {
	switch name {
	case ".git", ".lab", "node_modules", "vendor", "dist", "bin", ".terraform":
		return true
	}
	return false
}

// contactProblems walks root and returns one line for each place in a text file
// that names an address or product URL outside the contract, and how many text
// files it read. go.sum is hashes, not text.
func contactProblems(root string) (problems []string, scanned int, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && contactSkippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.sum" || !d.Type().IsRegular() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(raw, 0) >= 0 {
			return nil
		}
		scanned++
		rel, _ := filepath.Rel(root, path)
		for number, line := range strings.Split(string(raw), "\n") {
			for _, problem := range contactLineProblems(line) {
				problems = append(problems, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(rel), number+1, problem))
			}
		}
		return nil
	})
	return problems, scanned, err
}

// Every text of the repository names the five mailboxes at certistack.dev and
// no other address, no product URL at another domain, and no lab host. An
// example address (example.com, .example, .test, .invalid, .internal) is a
// fixture and stays.
func TestNoTextNamesAnAddressOutsideTheFiveMailboxes(t *testing.T) {
	problems, scanned, err := contactProblems(repoFile())
	if err != nil {
		t.Fatal(err)
	}
	for _, problem := range problems {
		t.Error(problem)
	}
	if scanned < 300 {
		t.Fatalf("only %d text files were read; the scan is not looking at the repository", scanned)
	}
}

// mailboxAddress is the address of one of the five.
func mailboxAddress(name string) string { return name + "@" + contactDomain }

// The rule itself, over lines that break it and lines that must stay. The
// fixtures are assembled from parts so that this file passes its own scan.
func TestContactRuleSeparatesTheFiveMailboxesFromEverythingElse(t *testing.T) {
	at, dev, mt := "@", "certistack.dev", "mailto"+":"
	other := "certistack." + "com"
	lab := "clift." + "cloud"
	bad := []string{
		"write to info" + at + dev,                              // a sixth mailbox
		"write to support" + at + dev,                           // another sixth
		mt + "jdoe" + at + "gmail.com",                          // a personal address
		"contact sales" + at + "example.com",                    // a mailbox name at another domain
		"contact licensing" + at,                                // no domain at all
		"licensing" + at + " certistack.dev",                    // a space in the middle
		"sales" + at + other,                                    // the wrong domain
		"sales" + at + "mail." + dev,                            // a subdomain
		"sales" + at + dev + ".example",                         // the product's name inside another host
		"https://" + other + "/docs",                            // a product URL at the wrong domain
		"https://www." + other,                                  // the same with a subdomain
		"<a href=\"" + mt + "help" + at + dev + "\">",           // a link to a sixth mailbox
		mt + "sales",                                            // a link with no address
		"eval" + at + lab,                                       // the evaluation marker at the lab domain
		"ssh pve1." + lab,                                       // a lab host in a product text
		"Questions: Licensing" + at + "Certistack.example.org.", // a mailbox name at another host
	}
	for _, line := range bad {
		if got := contactLineProblems(line); len(got) == 0 {
			t.Errorf("not reported: %q", line)
		}
	}
	good := []string{
		"write to security" + at + dev,
		"[sales" + at + dev + "](" + mt + "sales" + at + dev + "?subject=x)",
		"licensing" + at + dev + ".",
		"conduct" + at + dev + ", or privacy" + at + dev,
		"Send the ID to us at `privacy" + at + dev + "` with a subject",
		"ssh root" + at + "pve-node-01.example.com uname -m",
		"PBS_REPOSITORY=backup" + at + "pbs.example:store",
		"ops" + at + "example.org, a" + at + "b.example.invalid, x" + at + "host.test",
		"PBS_REPOSITORY=u" + at + "pbs!tok" + at + "pbs.internal:store",
		"systemctl start container" + at + "web.service",
		"getty" + at + "tty1.service redis-server" + at + "a.service",
		"golang.org/x/sys" + at + "v0.30.0 and name" + at + "v1.2.3",
		"https://" + dev + "/docs/ and https://github.com/cliftcloud/certistack",
		"the file certistack.yaml and certistack.service",
		"a mailto: link built by a script: 'mailto:' + address",
		"Clift Cloud LLC",
	}
	for _, line := range good {
		if got := contactLineProblems(line); len(got) != 0 {
			t.Errorf("reported a line that is fine: %q: %v", line, got)
		}
	}
}

// The scan reads text files in the tree, leaves out what is not the project's
// text (.lab, version control, dependencies, build output, hashes, binary
// files) and names the file and line of each problem.
func TestContactScanReadsTextAndLeavesOutTheLab(t *testing.T) {
	root := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	at := "@"
	write("docs/a.md", "fine\nwrite to info"+at+"certistack.dev\n")
	write("cmd/b.go", "var x = \"https://certistack."+"com/x\"\n")
	write(".lab/notes.md", "pve1.clift."+"cloud and info"+at+"certistack.dev\n")
	write("vendor/m/m.go", "info"+at+"certistack.dev\n")
	write("go.sum", "info"+at+"certistack.dev h1:abc\n")
	write("img.png", "info"+at+"certistack.dev\x00\x01")
	write("ok.md", "security"+at+"certistack.dev\n")
	problems, scanned, err := contactProblems(root)
	if err != nil {
		t.Fatal(err)
	}
	if scanned != 3 {
		t.Errorf("read %d text files, want 3 (docs/a.md, cmd/b.go and ok.md)", scanned)
	}
	if len(problems) != 2 {
		t.Fatalf("got %d problems %v, want one in docs/a.md and one in cmd/b.go", len(problems), problems)
	}
	joined := strings.Join(problems, "\n")
	for _, want := range []string{"docs/a.md:2:", "cmd/b.go:1:"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no problem at %s in %v", want, problems)
		}
	}
}

// Each mailbox is the one that serves its purpose, where the repository tells a
// reader whom to write to.
func TestEachMailboxServesItsPurpose(t *testing.T) {
	for _, tc := range []struct{ file, mailbox, purpose string }{
		{"SECURITY.md", "security", "vulnerability reports"},
		{"CODE_OF_CONDUCT.md", "conduct", "code of conduct reports"},
		{"SUPPORT.md", "sales", "support beyond best effort"},
		{"CLA.md", "licensing", "questions about the CLA"},
		{"docs/telemetry.md", "privacy", "telemetry deletion"},
	} {
		if !strings.Contains(readRepoText(t, strings.Split(tc.file, "/")...), mailboxAddress(tc.mailbox)) {
			t.Errorf("%s does not name %s for %s", tc.file, mailboxAddress(tc.mailbox), tc.purpose)
		}
	}
	// Buying is sales; the license terms of the FAQ answer it.
	buy := section(t, readRepoText(t, "LICENSING-FAQ.md"), "Where do I buy a commercial license?")
	if !strings.Contains(buy, mailboxAddress("sales")) || strings.Contains(buy, mailboxAddress("licensing")) {
		t.Errorf("LICENSING-FAQ.md answers \"Where do I buy a commercial license?\" with another mailbox than %s:\n%s", mailboxAddress("sales"), buy)
	}
}

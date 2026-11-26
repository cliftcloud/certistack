// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The values of the controller environment file are checked for their shape
// when the file is read, by every command that reads it, and `check` layer 1
// reports every wrong one at once. Before, only names, syntax, the mode and
// the required variables were checked; a PVE_URL without a scheme, a token
// with a pasted prefix or a repository in URL form passed layer 1 and failed
// layers 3 to 6, after the newcomer had done the SSH steps, as "exit status
// 255 (client output withheld)" or a bare 401.

// baseEnvironment is a controller file every shape of which is right: the
// lines of the exploratory environment-file sweep's good file.
var baseEnvironment = []string{
	"PVE_URL=https://pve.example.invalid:8006",
	"PVE_TOKEN_ID=certistack@pve!automation",
	"PVE_TOKEN_SECRET=00000000-0000-0000-0000-000000000000",
	"PBS_REPOSITORY=backup@pbs@pbs.example.invalid:store",
	"PBS_PASSWORD=secret",
	"CERTISTACK_NODE=pve1",
	"CERTISTACK_SSH_HOST=pve1.example.invalid",
	"CERTISTACK_SSH_USER=root",
}

// environmentWith is the base file with the named variables set to the given
// values (a value of "-" removes the variable); NAME=VALUE lines are appended
// for names the base does not have.
func environmentWith(changes ...string) string {
	set := map[string]string{}
	var order []string
	for _, change := range changes {
		name, value, _ := strings.Cut(change, "=")
		if _, seen := set[name]; !seen {
			order = append(order, name)
		}
		set[name] = value
	}
	var lines []string
	used := map[string]bool{}
	for _, line := range baseEnvironment {
		name, _, _ := strings.Cut(line, "=")
		if value, changed := set[name]; changed {
			used[name] = true
			if value != "-" {
				lines = append(lines, name+"="+value)
			}
			continue
		}
		lines = append(lines, line)
	}
	for _, name := range order {
		if !used[name] && set[name] != "-" {
			lines = append(lines, name+"="+set[name])
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

type environmentCase struct {
	name string
	// text is the file's content.
	text string
	// pass is true when layer 1 must pass; otherwise it must fail, with every
	// fragment of want in the output and none of notWant.
	pass    bool
	want    []string
	notWant []string
}

// secretValues are in the cases below, and must never be printed.
var secretValues = []string{"s3cr3t-token-value", "hunter2-password", "userinfo-password"}

var environmentCases = []environmentCase{
	// The cases of the exploratory environment-file sweep.
	{name: "baseline", text: environmentWith(), pass: true},
	{name: "CRLF line ends", text: strings.ReplaceAll(environmentWith(), "\n", "\r\n"), pass: true},
	{name: "a byte order mark", text: "\xef\xbb\xbf" + environmentWith(), pass: true},
	{name: "export in front of a name", text: "export " + environmentWith(),
		want: []string{"✗ 1. Environment file", "line 1", `remove the word "export"`, "PVE_URL=VALUE"}},
	{name: "quoted values", text: strings.NewReplacer("=", "=\"", "\n", "\"\n").Replace(environmentWith()), pass: true},
	{name: "spaces around the equals sign", text: strings.Replace(environmentWith(), "PVE_URL=", "PVE_URL = ", 1), pass: true},
	{name: "a misspelled name", text: environmentWith("PVE_TOKEN_SECERT=x", "PVE_TOKEN_SECRET=-"),
		want: []string{`unsupported controller environment variable "PVE_TOKEN_SECERT" on line`, "did you mean PVE_TOKEN_SECRET?"}},
	{name: "a lower-case name", text: strings.Replace(environmentWith(), "PVE_URL=", "pve_url=", 1),
		want: []string{"line 1", "variable names are written in capitals: use PVE_URL"}, notWant: []string{"pve_url"}},
	{name: "a line with no equals sign", text: environmentWith() + "just-a-secret-pasted-alone\n",
		want: []string{"invalid controller environment line 9", "a line is NAME=VALUE"}, notWant: []string{"just-a-secret-pasted-alone"}},
	{name: "PVE_URL without a scheme", text: environmentWith("PVE_URL=pve.example.invalid:8006"),
		want: []string{"✗ 1. Environment file", `line 1, PVE_URL:`, "has no scheme: start it with https://", "https://pve1.example.com:8006"}},
	{name: "PVE_URL with http", text: environmentWith("PVE_URL=http://pve.example.invalid:8006"),
		want: []string{`line 1, PVE_URL:`, "uses http://", "https://HOST:8006", "loopback"}},
	{name: "PVE_URL with http on loopback", text: environmentWith("PVE_URL=http://127.0.0.1:8006"), pass: true},
	{name: "PVE_URL with http on localhost", text: environmentWith("PVE_URL=http://localhost:8006"), pass: true},
	{name: "PVE_URL with another scheme", text: environmentWith("PVE_URL=ssh://pve.example.invalid"),
		want: []string{`line 1, PVE_URL:`, "uses a scheme other than https://", "https://HOST:8006"}},
	{name: "PVE_URL with the API path", text: environmentWith("PVE_URL=https://pve.example.invalid:8006/api2/json"),
		want: []string{`line 1, PVE_URL:`, "/api2/", "remove the path", "address of the web interface", "adds /api2/json itself"}},
	{name: "PVE_URL with another path", text: environmentWith("PVE_URL=https://pve.example.invalid:8006/pve"),
		want: []string{`line 1, PVE_URL:`, "has a path after the host: remove it", "https://HOST[:PORT]"}},
	{name: "PVE_URL with a trailing slash", text: environmentWith("PVE_URL=https://pve.example.invalid:8006/"), pass: true},
	{name: "PVE_URL with two trailing slashes", text: environmentWith("PVE_URL=https://pve.example.invalid:8006//"),
		want: []string{`line 1, PVE_URL:`, "has a path after the host"}},
	{name: "PVE_URL with a query", text: environmentWith("PVE_URL=https://pve.example.invalid:8006/?x=1"),
		want: []string{`line 1, PVE_URL:`, "has a query (?...): remove it"}},
	{name: "PVE_URL as the browser shows it", text: environmentWith("PVE_URL=https://pve.example.invalid:8006/#v1:0:18:4:::::::"),
		want: []string{`line 1, PVE_URL:`, "has a fragment (#...)", "#v1:...", "remove it"}},
	{name: "PVE_URL with credentials", text: environmentWith("PVE_URL=https://root:userinfo-password@pve.example.invalid:8006"),
		want: []string{`line 1, PVE_URL:`, "contains a user name or password", "PVE_TOKEN_ID and PVE_TOKEN_SECRET"}, notWant: []string{"userinfo-password"}},
	{name: "PVE_URL without a port", text: environmentWith("PVE_URL=https://pve.example.invalid"), pass: true,
		want: []string{"Note: line 1 (PVE_URL) has no port", "443", "8006"}},
	{name: "PVE_URL on the SSH port", text: environmentWith("PVE_URL=https://10.0.0.5:22"),
		want: []string{`line 1, PVE_URL:`, "uses port 22, which is SSH", "PVE's API is on 8006 (or the port your reverse proxy listens on)"}},
	{name: "PVE_URL on the PBS port", text: environmentWith("PVE_URL=https://10.0.0.5:8007"),
		want: []string{`line 1, PVE_URL:`, "uses port 8007", "Proxmox Backup Server", "PVE's API is on 8006 (or the port your reverse proxy listens on)"}},
	{name: "PVE_URL with a port out of range", text: environmentWith("PVE_URL=https://pve.example.invalid:99999"),
		want: []string{`line 1, PVE_URL:`, "port that is not a number from 1 to 65535"}},
	{name: "PVE_URL with no host", text: environmentWith("PVE_URL=https://:8006"),
		want: []string{`line 1, PVE_URL:`, "has no host name"}},
	{name: "PVE_URL with a space", text: environmentWith("PVE_URL=https://pve.example.invalid:8006 /x"),
		want: []string{`line 1, PVE_URL:`, "contains a space or a quote"}},
	{name: "PVE_URL with an IPv6 address", text: environmentWith("PVE_URL=https://[fd00::1]:8006"), pass: true},
	{name: "PVE_URL with a trailing comment", text: environmentWith("PVE_URL=https://pve.example.invalid:8006 # my node"),
		want: []string{`line 1, PVE_URL:`, "has a comment on the same line", "values are literal", "line of its own"}},
	{name: "PVE_TOKEN_ID that is a user", text: environmentWith("PVE_TOKEN_ID=root@pam"),
		want: []string{`line 2, PVE_TOKEN_ID:`, "is a user, not an API token", "user@realm!tokenname", "certistack setup rbac"}},
	{name: "PVE_TOKEN_ID with the Authorization prefix", text: environmentWith("PVE_TOKEN_ID=PVEAPIToken=certistack@pve!automation=s3cr3t-token-value"),
		want: []string{`line 2, PVE_TOKEN_ID:`, "remove PVEAPIToken=", "the secret goes in PVE_TOKEN_SECRET"}, notWant: []string{"s3cr3t-token-value"}},
	{name: "PVE_TOKEN_ID with the Authorization prefix and no secret", text: environmentWith("PVE_TOKEN_ID=PVEAPIToken=certistack@pve!automation"),
		want: []string{`line 2, PVE_TOKEN_ID:`, "remove PVEAPIToken=", "the secret goes in PVE_TOKEN_SECRET"}},
	{name: "PVE_TOKEN_ID with the secret after it", text: environmentWith("PVE_TOKEN_ID=certistack@pve!automation=s3cr3t-token-value"),
		want: []string{`line 2, PVE_TOKEN_ID:`, `contains "="`, "remove everything from the \"=\" on", "the secret goes in PVE_TOKEN_SECRET"}, notWant: []string{"s3cr3t-token-value"}},
	{name: "PVE_TOKEN_ID with no token name", text: environmentWith("PVE_TOKEN_ID=certistack@pve!"),
		want: []string{`line 2, PVE_TOKEN_ID:`, `no token name after "!"`}},
	{name: "PVE_TOKEN_ID with no realm", text: environmentWith("PVE_TOKEN_ID=certistack!automation"),
		want: []string{`line 2, PVE_TOKEN_ID:`, "is not shaped like user@realm!tokenname", "certistack@pve!automation"}},
	{name: "PVE_TOKEN_ID with a space", text: environmentWith("PVE_TOKEN_ID=certistack@pve!auto mation"),
		want: []string{`line 2, PVE_TOKEN_ID:`, "contains a space or a quote"}},
	{name: "PVE_TOKEN_SECRET with a space inside", text: environmentWith("PVE_TOKEN_SECRET=s3cr3t-token-value and more"),
		want: []string{`line 3, PVE_TOKEN_SECRET:`, "contains a space, tab or quote", "the UUID PVE showed once"}, notWant: []string{"s3cr3t-token-value"}},
	{name: "PVE_TOKEN_SECRET with quotes inside", text: environmentWith("PVE_TOKEN_SECRET='\"s3cr3t-token-value\"'"),
		want: []string{`line 3, PVE_TOKEN_SECRET:`, "contains a space, tab or quote"}, notWant: []string{"s3cr3t-token-value"}},
	{name: "PVE_TOKEN_SECRET that is not a UUID", text: environmentWith("PVE_TOKEN_SECRET=not-a-uuid-but-accepted"), pass: true},
	{name: "PVE_TOKEN_SECRET with a space after it", text: environmentWith("PVE_TOKEN_SECRET=00000000-0000-0000-0000-000000000000 "), pass: true},
	{name: "PBS_REPOSITORY with no datastore and no user", text: environmentWith("PBS_REPOSITORY=pbs.example.invalid"),
		want: []string{`line 4, PBS_REPOSITORY:`, "has no user: add user@realm!tokenname@ in front", "has no datastore: add :DATASTORE at the end"}},
	{name: "PBS_REPOSITORY with a user and no datastore", text: environmentWith("PBS_REPOSITORY=backup@pbs@pbs.example.invalid"),
		want: []string{`line 4, PBS_REPOSITORY:`, "has no datastore: add :DATASTORE at the end"}, notWant: []string{"has no user"}},
	{name: "PBS_REPOSITORY with a host and port and no datastore", text: environmentWith("PBS_REPOSITORY=backup@pbs@pbs.example.invalid:"),
		want: []string{`line 4, PBS_REPOSITORY:`, "has no datastore"}},
	// A port and nothing after it is not a datastore named 8007: layer 1 says
	// the datastore is missing, before the SSH steps.
	{name: "PBS_REPOSITORY with a port and no datastore", text: environmentWith("PBS_REPOSITORY=backup@pbs!tok@pbs.example.invalid:8007"),
		want: []string{`line 4, PBS_REPOSITORY:`, "has no datastore", "the number after the host looks like a port", "add :DATASTORE after it", "HOST:PORT:DATASTORE"}},
	{name: "PBS_REPOSITORY with an IPv6 host, a port and no datastore", text: environmentWith("PBS_REPOSITORY=backup@pbs!tok@[fd00::5]:8007"),
		want: []string{`line 4, PBS_REPOSITORY:`, "has no datastore", "the number after the host looks like a port"}},
	{name: "PBS_REPOSITORY with a datastore named like a port, after the port", text: environmentWith("PBS_REPOSITORY=backup@pbs!tok@pbs.example.invalid:8007:8007"), pass: true},
	{name: "PBS_REPOSITORY with a number that is no port as the datastore", text: environmentWith("PBS_REPOSITORY=backup@pbs!tok@pbs.example.invalid:123456"), pass: true},
	{name: "PBS_REPOSITORY in URL form", text: environmentWith("PBS_REPOSITORY=https://pbs.example.invalid:8007/store"),
		want: []string{`line 4, PBS_REPOSITORY:`, "is a URL", "no scheme and no path", "user@realm!tokenname@HOST:DATASTORE"}},
	{name: "PBS_REPOSITORY in URL form with a password", text: environmentWith("PBS_REPOSITORY=https://backup:hunter2-password@pbs.example.invalid:8007/store"),
		want: []string{`line 4, PBS_REPOSITORY:`, "is a URL"}, notWant: []string{"hunter2-password"}},
	{name: "PBS_REPOSITORY with no user", text: environmentWith("PBS_REPOSITORY=pbs.example.invalid:store"),
		want: []string{`line 4, PBS_REPOSITORY:`, "has no user: add user@realm!tokenname@ in front"}, notWant: []string{"has no datastore"}},
	{name: "PBS_REPOSITORY with a user that has no realm", text: environmentWith("PBS_REPOSITORY=backup@pbs.example.invalid:store"),
		want: []string{`line 4, PBS_REPOSITORY:`, "starts with a user that is not user@realm or user@realm!tokenname"}},
	{name: "PBS_REPOSITORY with a port", text: environmentWith("PBS_REPOSITORY=backup@pbs!tok@pbs.example.invalid:8007:store"), pass: true},
	{name: "PBS_REPOSITORY with a bad port", text: environmentWith("PBS_REPOSITORY=backup@pbs!tok@pbs.example.invalid:99999:store"),
		want: []string{`line 4, PBS_REPOSITORY:`, "port that is not a number from 1 to 65535"}},
	{name: "PBS_REPOSITORY with an IPv6 host", text: environmentWith("PBS_REPOSITORY=backup@pbs!tok@[fd00::5]:8007:store"), pass: true},
	{name: "PBS_REPOSITORY with an IPv6 host that has no brackets", text: environmentWith("PBS_REPOSITORY=backup@pbs!tok@fd00::5:8007:store"),
		want: []string{`line 4, PBS_REPOSITORY:`, "too many"}},
	{name: "PBS_REPOSITORY with an IPv4 host", text: environmentWith("PBS_REPOSITORY=backup@pbs!tok@192.0.2.50:8007:store"), pass: true},
	{name: "PBS_REPOSITORY with a bad datastore", text: environmentWith("PBS_REPOSITORY=backup@pbs!tok@pbs.example.invalid:8007:-store"),
		want: []string{`line 4, PBS_REPOSITORY:`, "datastore name PBS does not allow"}},
	{name: "PBS_REPOSITORY with a space", text: environmentWith("PBS_REPOSITORY=backup@pbs@pbs.example.invalid: store"),
		want: []string{`line 4, PBS_REPOSITORY:`, "contains a space or a quote"}},
	{name: "PBS_FINGERPRINT in the PBS form", text: environmentWith("PBS_FINGERPRINT=" + strings.TrimSuffix(strings.Repeat("aa:", 32), ":")), pass: true},
	{name: "PBS_FINGERPRINT as 64 hex digits", text: environmentWith("PBS_FINGERPRINT=" + strings.Repeat("Ab", 32)), pass: true},
	{name: "PBS_FINGERPRINT with a sha256 prefix", text: environmentWith("PBS_FINGERPRINT=sha256:" + strings.TrimSuffix(strings.Repeat("aa:", 32), ":")), pass: true},
	{name: "PBS_FINGERPRINT with an upper-case SHA256 prefix", text: environmentWith("PBS_FINGERPRINT=SHA256:" + strings.Repeat("ab", 32)), pass: true},
	{name: "PBS_FINGERPRINT that is too short", text: environmentWith("PBS_FINGERPRINT=ab:cd"),
		want: []string{`line 9, PBS_FINGERPRINT:`, "is not a SHA-256 fingerprint", "32 hex bytes separated by colons", "64 hex digits", "Dashboard, Show Fingerprint", "4 hex digits"}},
	{name: "PBS_FINGERPRINT that is a placeholder", text: environmentWith("PBS_FINGERPRINT=replace-with-the-pbs-certificate-fingerprint"),
		want: []string{`line 9, PBS_FINGERPRINT:`, "is not a SHA-256 fingerprint", "Dashboard, Show Fingerprint"}},
	{name: "PBS_FINGERPRINT with a wrong colon layout", text: environmentWith("PBS_FINGERPRINT=" + strings.Repeat("aaa:", 21) + "a"),
		want: []string{`line 9, PBS_FINGERPRINT:`, "is not a SHA-256 fingerprint"}},
	{name: "PBS_NAMESPACE", text: environmentWith("PBS_NAMESPACE=prod/team-a"), pass: true},
	{name: "PBS_NAMESPACE with a leading slash", text: environmentWith("PBS_NAMESPACE=/prod"),
		want: []string{`line 9, PBS_NAMESPACE:`, "without a leading or trailing /"}},
	{name: "PBS_NAMESPACE with a trailing slash", text: environmentWith("PBS_NAMESPACE=prod/"),
		want: []string{`line 9, PBS_NAMESPACE:`, "without a leading or trailing /"}},
	{name: "PBS_NAMESPACE with an empty level", text: environmentWith("PBS_NAMESPACE=prod//team"),
		want: []string{`line 9, PBS_NAMESPACE:`, "empty level"}},
	{name: "PBS_NAMESPACE with a character PBS does not allow", text: environmentWith("PBS_NAMESPACE=prod team"),
		want: []string{`line 9, PBS_NAMESPACE:`, "characters PBS does not allow"}},
	{name: "PBS_NAMESPACE with too many levels", text: environmentWith("PBS_NAMESPACE=a/b/c/d/e/f/g/h"),
		want: []string{`line 9, PBS_NAMESPACE:`, "at most 7 levels"}},
	{name: "CERTISTACK_NODE with a domain", text: environmentWith("CERTISTACK_NODE=pve1.example.invalid"),
		want: []string{`line 6, CERTISTACK_NODE:`, "contains a dot", "the part before the first dot"}},
	{name: "CERTISTACK_NODE in capitals", text: environmentWith("CERTISTACK_NODE=PVE1"), pass: true},
	{name: "CERTISTACK_NODE with an underscore", text: environmentWith("CERTISTACK_NODE=pve_1"),
		want: []string{`line 6, CERTISTACK_NODE:`, "letters, digits and hyphens only"}},
	{name: "CERTISTACK_NODE that ends in a hyphen", text: environmentWith("CERTISTACK_NODE=pve1-"),
		want: []string{`line 6, CERTISTACK_NODE:`, "letters, digits and hyphens only"}},
	{name: "CERTISTACK_SSH_HOST as a URL", text: environmentWith("CERTISTACK_SSH_HOST=ssh://root@pve1.example.invalid"),
		want: []string{`line 7, CERTISTACK_SSH_HOST:`, "is a URL", "only the host name or address"}},
	{name: "CERTISTACK_SSH_HOST with a user", text: environmentWith("CERTISTACK_SSH_HOST=root@pve1.example.invalid"),
		want: []string{`line 7, CERTISTACK_SSH_HOST:`, "contains a user name (user@host)", "CERTISTACK_SSH_USER"}},
	{name: "CERTISTACK_SSH_HOST with a port", text: environmentWith("CERTISTACK_SSH_HOST=pve1.example.invalid:2222"),
		want: []string{`line 7, CERTISTACK_SSH_HOST:`, "ends in a :port", "put the port in CERTISTACK_SSH_PORT"}},
	{name: "CERTISTACK_SSH_HOST with an IPv6 address", text: environmentWith("CERTISTACK_SSH_HOST=fd00::36"), pass: true},
	// Layer 2 and every connection refuse a host that does not start with a
	// letter or a digit, brackets included (an IPv6 address is written without
	// them); layer 1 refuses it too.
	{name: "CERTISTACK_SSH_HOST with a bracketed IPv6 address", text: environmentWith("CERTISTACK_SSH_HOST=[fd00::36]"),
		want: []string{`line 7, CERTISTACK_SSH_HOST:`, "is not a host name or address", "written without brackets"}},
	{name: "CERTISTACK_SSH_PORT of zero", text: environmentWith("CERTISTACK_SSH_PORT=0"),
		want: []string{`line 9, CERTISTACK_SSH_PORT:`, "is not a port", "1 to 65535"}},
	{name: "CERTISTACK_SSH_PORT above 65535", text: environmentWith("CERTISTACK_SSH_PORT=70000"),
		want: []string{`line 9, CERTISTACK_SSH_PORT:`, "is not a port"}},
	{name: "CERTISTACK_SSH_PORT that is not a number", text: environmentWith("CERTISTACK_SSH_PORT=ssh"),
		want: []string{`line 9, CERTISTACK_SSH_PORT:`, "is not a port"}},
	{name: "CERTISTACK_SSH_PORT", text: environmentWith("CERTISTACK_SSH_PORT=2222"), pass: true},
	{name: "an empty required value", text: environmentWith("PBS_PASSWORD="),
		want: []string{"required variable(s) not set: PBS_PASSWORD", "line 5 has no value"}},
	{name: "a repeated variable", text: environmentWith() + "PVE_URL=https://other.example.invalid:8006\n",
		want: []string{`duplicate controller environment variable "PVE_URL" on line 9`, "already set on line 1"}},
	{name: "an empty file", text: "",
		want: []string{"required variable(s) not set: PVE_URL, PBS_REPOSITORY, PBS_PASSWORD, CERTISTACK_NODE, CERTISTACK_SSH_HOST"}},
	{name: "a quoted value with a comment after the closing quote", text: environmentWith(`PVE_URL="https://pve.example.invalid:8006" # my node`),
		want: []string{`"PVE_URL" on line 1`, "text after the closing quote", "line of its own"}},
	{name: "an unterminated quote", text: environmentWith(`PBS_PASSWORD="abc`),
		want: []string{`"PBS_PASSWORD" on line 5`, "unterminated quoted value"}, notWant: []string{"abc"}},

	// The cases of the exploratory live sweep that the shape of a value decides.
	{name: "live: PVE_URL as host and port", text: environmentWith("PVE_URL=pve-node-01.lab.example.invalid:8006"),
		want: []string{"has no scheme"}},
	{name: "live: PVE_URL with an unknown host", text: environmentWith("PVE_URL=https://pve-node-01x.lab.example.invalid:8006"), pass: true},
	{name: "live: a token that is the wrong one", text: environmentWith("PVE_TOKEN_ID=certistack-svc@pam!automation"), pass: true},
	{name: "live: a token with another name", text: environmentWith("PVE_TOKEN_ID=certistack-svc@pve!other"), pass: true},
	{name: "live: a wrong PBS password", text: environmentWith("PBS_PASSWORD=wrong-password"), pass: true},
	{name: "live: a wrong datastore", text: environmentWith("PBS_REPOSITORY=backup@pbs!tok@pbs.example.invalid:8007:nosuchstore"), pass: true},
	{name: "live: a 32-byte fingerprint that is not the server's", text: environmentWith("PBS_FINGERPRINT=" + strings.TrimSuffix(strings.Repeat("aa:", 32), ":")), pass: true},
	{name: "live: a namespace that does not exist", text: environmentWith("PBS_NAMESPACE=nosuchnamespace"), pass: true},
	{name: "live: a node other than the host's", text: environmentWith("CERTISTACK_NODE=pve-node-02"), pass: true},
	{name: "live: the SSH host as an address", text: environmentWith("CERTISTACK_SSH_HOST=10.42.20.36"), pass: true},
	{name: "live: an account that does not exist", text: environmentWith("CERTISTACK_SSH_USER=nobody"), pass: true},
}

func runLayer1(t *testing.T, text string, mode os.FileMode) (string, error) {
	t.Helper()
	stub := &nodeStub{}
	withNode(t, stub)
	dir := t.TempDir()
	// No known_hosts file of the machine the test runs on: a file that passes
	// layer 1 stops at layer 2, whatever that machine has recorded.
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	path := filepath.Join(dir, "controller.env")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	out, err := runRootWithInput(t, "", "check", "--env-file", path)
	if stub.machineCalls != 0 || len(stub.staged) != 0 {
		t.Errorf("a layer after layer 1 was tried although it failed (ssh %d, node %d)", stub.machineCalls, len(stub.staged))
	}
	// On Windows the separator after the directory is a backslash.
	return strings.ReplaceAll(strings.ReplaceAll(out, dir, "<dir>"), "<dir>\\", "<dir>/"), err
}

func TestEnvironmentFileValueShapesAreCheckedByLayer1(t *testing.T) {
	for _, tc := range environmentCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runLayer1(t, tc.text, 0o600)
			layer1Passed := strings.Contains(out, "✓ 1. Environment file")
			switch {
			case tc.pass && !layer1Passed:
				t.Fatalf("layer 1 failed for a file whose shapes are right (err %v):\n%s", err, out)
			case !tc.pass && layer1Passed:
				t.Fatalf("layer 1 passed for a wrong value:\n%s", out)
			case !tc.pass && exitCodeForError(err) != exitCodeInfrastructure:
				t.Errorf("exit status %d, want %d (%v)", exitCodeForError(err), exitCodeInfrastructure, err)
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			for _, unwanted := range append(tc.notWant, secretValues...) {
				if strings.Contains(out, unwanted) {
					t.Errorf("output holds %q, which must not be printed:\n%s", unwanted, out)
				}
			}
		})
	}
}

// A file that is not there, a directory where the file should be, and no
// --env-file at all: the cases of the exploratory environment-file sweep that no file content makes.
func TestCheckLayer1WhenThereIsNoUsableFile(t *testing.T) {
	stub := &nodeStub{}
	withNode(t, stub)
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	out, err := runRootWithInput(t, "", "check", "--env-file", filepath.Join(dir, "nonexistent.env"))
	if err == nil || exitCodeForError(err) != exitCodeInfrastructure || !strings.Contains(out, "✗ 1. Environment file") || !strings.Contains(out, "nonexistent.env does not exist") || !strings.Contains(out, "Run certistack setup (quickstart step 2)") {
		t.Errorf("a missing file: %v\n%s", err, out)
	}

	directory := filepath.Join(dir, "adir")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err = runRootWithInput(t, "", "check", "--env-file", directory)
	if err == nil || exitCodeForError(err) != exitCodeInfrastructure || !strings.Contains(out, "adir is not a regular file") || !strings.Contains(out, "Point --env-file at the environment file itself") {
		t.Errorf("a directory: %v\n%s", err, out)
	}

	out, err = runRootWithInput(t, "", "check")
	if err == nil || exitCodeForError(err) != exitCodeInfrastructure || !strings.Contains(err.Error(), `required flag(s) "env-file" not set`) {
		t.Errorf("no --env-file: %v\n%s", err, out)
	}
	if stub.machineCalls != 0 || len(stub.staged) != 0 {
		t.Errorf("a later layer was tried (ssh %d, node %d)", stub.machineCalls, len(stub.staged))
	}
}

func TestEnvironmentFileModeStillStopsLayer1(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not an ACL check on Windows")
	}
	for _, mode := range []os.FileMode{0o644, 0o666, 0o640} {
		out, err := runLayer1(t, environmentWith(), mode)
		if err == nil || !strings.Contains(out, fmt.Sprintf("has mode %04o, so other users can read the secrets in it", mode)) || !strings.Contains(out, "Fix: chmod 600 ") {
			t.Errorf("mode %04o: err %v\n%s", mode, err, out)
		}
	}
}

// Layer 1 reports every wrong shape in one go, each with its line and its fix,
// so that a newcomer corrects the file once.
func TestCheckLayer1ReportsEveryShapeProblemAtOnce(t *testing.T) {
	text := environmentWith(
		"PVE_URL=pve.example.invalid:8006",
		"PVE_TOKEN_ID=root@pam",
		"PBS_REPOSITORY=https://pbs.example.invalid/store",
		"CERTISTACK_NODE=pve1.example.invalid",
		"CERTISTACK_SSH_PORT=0",
		"PBS_FINGERPRINT=ab:cd",
	)
	out, err := runLayer1(t, text, 0o600)
	if err == nil {
		t.Fatalf("check passed:\n%s", out)
	}
	for _, want := range []string{
		"6 values in <dir>/controller.env are not shaped as they should be",
		"line 1, PVE_URL:", "line 2, PVE_TOKEN_ID:", "line 4, PBS_REPOSITORY:", "line 6, CERTISTACK_NODE:", "line 9, CERTISTACK_SSH_PORT:", "line 10, PBS_FINGERPRINT:",
		"Fix: Correct the lines above in <dir>/controller.env", "https://certistack.dev/docs/configuration/#variables",
		"- 2. SSH files", "not checked: an earlier layer failed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// A single problem is said in the singular.
	out, _ = runLayer1(t, environmentWith("PVE_URL=pve.example.invalid:8006"), 0o600)
	if !strings.Contains(out, "1 value in <dir>/controller.env is not shaped as it should be") || !strings.Contains(out, "Fix: Correct the line above in <dir>/controller.env") {
		t.Errorf("singular:\n%s", out)
	}
}

// Every command that reads the controller file refuses a wrong shape, with the
// message `check` gives, before it does anything else.
func TestEveryCommandThatReadsTheControllerFileChecksItsShapes(t *testing.T) {
	plan := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(plan, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const asError, inLayer1 = `"PVE_URL" on line 1`, "line 1, PVE_URL:"
	for _, command := range []struct {
		name  string
		args  []string
		where string
	}{
		{"check", []string{"check"}, inLayer1},
		{"validate", []string{"validate", plan}, asError},
		{"plan", []string{"plan", plan}, asError},
		{"run", []string{"run", plan}, asError},
		{"doctor", []string{"doctor"}, asError},
		{"init", []string{"init"}, asError},
		{"setup pve-ca", []string{"setup", "pve-ca"}, asError},
	} {
		t.Run(command.name, func(t *testing.T) {
			withNode(t, &nodeStub{})
			env := writeEnvFile(t, environmentWith("PVE_URL=pve.example.invalid:8006"))
			out, err := runRootWithInput(t, "", append(command.args, "--env-file", env)...)
			text := out
			if err != nil {
				text += err.Error()
			}
			if err == nil {
				t.Fatalf("the command accepted a PVE_URL without a scheme:\n%s", text)
			}
			for _, want := range []string{command.where, "has no scheme: start it with https://"} {
				if !strings.Contains(text, want) {
					t.Errorf("output lacks %q:\n%s", want, text)
				}
			}
		})
	}
}

// What a value is changed to when it is accepted: a trailing slash is not part
// of PVE_URL, and a fingerprint reaches the PBS client in its colon form.
func TestEnvironmentFileNormalizesAcceptedValues(t *testing.T) {
	colons := strings.TrimSuffix(strings.Repeat("ab:", 32), ":")
	for _, tc := range []struct{ name, line, variable, want string }{
		{"a trailing slash", "PVE_URL=https://pve.example.invalid:8006/", "PVE_URL", "https://pve.example.invalid:8006"},
		{"no trailing slash", "PVE_URL=https://pve.example.invalid:8006", "PVE_URL", "https://pve.example.invalid:8006"},
		{"64 hex digits", "PBS_FINGERPRINT=" + strings.Repeat("ab", 32), "PBS_FINGERPRINT", colons},
		{"a sha256 prefix", "PBS_FINGERPRINT=sha256:" + colons, "PBS_FINGERPRINT", colons},
		{"an upper-case prefix and bare digits", "PBS_FINGERPRINT=SHA256:" + strings.Repeat("ab", 32), "PBS_FINGERPRINT", colons},
		{"the colon form as it is", "PBS_FINGERPRINT=" + colons, "PBS_FINGERPRINT", colons},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeEnvFile(t, tc.line+"\n")
			values, err := loadControllerEnvironment(path)
			if err != nil {
				t.Fatal(err)
			}
			if values[tc.variable] != tc.want {
				t.Errorf("%s = %q, want %q", tc.variable, values[tc.variable], tc.want)
			}
		})
	}
}

// A trailing " # comment" is part of the value, because values are literal. A
// value whose shape it breaks is refused; one it does not (a password) passes
// layer 1 with a note, which never carries the value.
func TestCheckLayer1NotesATrailingCommentInAValueThatStillPasses(t *testing.T) {
	out, err := runLayer1(t, environmentWith("PBS_PASSWORD=hunter2-password # the backup user"), 0o600)
	if !strings.Contains(out, "✓ 1. Environment file") {
		t.Fatalf("layer 1 failed (%v):\n%s", err, out)
	}
	for _, want := range []string{"Note: line 5 (PBS_PASSWORD) contains \" #\"", "values are literal", "part of the value", "its own line"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunter2-password") || strings.Contains(out, "the backup user") {
		t.Errorf("the note carries the value:\n%s", out)
	}
	// No note when nothing is wrong.
	out, _ = runLayer1(t, environmentWith(), 0o600)
	if strings.Contains(out, "Note:") {
		t.Errorf("a note for a file that is right:\n%s", out)
	}
}

// The worker's file is written by the controller from values that were
// checked, so it is not shape-checked again.
func TestWorkerEnvironmentFileIsNotShapeChecked(t *testing.T) {
	path := writeEnvFile(t, "PVE_URL=pve.example.invalid:8006\n")
	if _, err := loadWorkerEnvironment(path); err != nil {
		t.Fatalf("the worker's file was shape-checked: %v", err)
	}
}

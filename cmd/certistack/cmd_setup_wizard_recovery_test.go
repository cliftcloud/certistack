// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Failures after a token is created: its secret is kept in
// controller.env.partial at once, and the next run, even unattended, uses it
// instead of stopping at a token it cannot read.

func unattended(t *testing.T, extra setupWizardOptions) setupWizardOptions {
	t.Helper()
	extra.NodeHost, extra.Yes, extra.Fingerprint = "pve1.example.com", true, fixedHostKey(t, 7).Fingerprint
	// --yes stops at an empty namespace: the root one, which lets the PBS user
	// read the whole datastore, is asked for by name.
	if extra.PBSNamespace == "" {
		extra.PBSNamespace = "/"
	}
	return extra
}

func TestTheWizardKeepsANewTokensSecretWhenTheRunStopsLater(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.pbsFails = true, true
	f.tools = []string{"guestfish", "nft"}
	f.storageCfg = "dir: certistack-scratch\n\tpath /var/lib/vz/certistack-scratch\n\tcontent images\n"
	// The PVE token is made, then ssh to the PBS fails: unattended, the
	// paste fallback is no way out.
	out, err := runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}))
	if err == nil || !strings.Contains(err.Error(), "--pbs-ssh") {
		t.Fatalf("first run: %v\n%s", err, out)
	}
	partial := filepath.Join(dir, partialEnvName)
	if info, err := os.Stat(partial); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%s: %v %v", partial, info, err)
	}
	if values, _ := loadControllerEnvironment(partial); values["PVE_TOKEN_SECRET"] != wizardPVESecret || values["CERTISTACK_NODE"] != "pve1" {
		t.Fatalf("partial = %v", values)
	}
	if strings.Contains(out, wizardPVESecret) {
		t.Fatal("the secret was shown")
	}
	// The PBS answers now: the run again keeps the secret (the token is not
	// replaced, --yes could not), finishes, and removes the partial file.
	f.pbsFails, f.changes = false, nil
	out, err = runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}))
	if err != nil {
		t.Fatalf("run again: %v\n%s", err, out)
	}
	if strings.Contains(strings.Join(f.changes, "|"), "pve token remove") || !strings.Contains(out, "(left by a setup that did not finish)") {
		t.Errorf("changes = %q\n%s", f.changes, out)
	}
	values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env"))
	if values["PVE_TOKEN_SECRET"] != wizardPVESecret || values["PBS_PASSWORD"] != wizardPBSSecret {
		t.Errorf("values = %v", values)
	}
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Errorf("the partial file is still there: %v", err)
	}
}

func TestTheWizardKeepsTheSecretOfAPartThatFailedAfterTheToken(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.pveFailACL = true, true
	f.tools = []string{"guestfish", "nft"}
	f.storageCfg = "dir: certistack-scratch\n\tpath /var/lib/vz/certistack-scratch\n\tcontent images\n"
	out, err := runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}))
	if err == nil || !strings.Contains(err.Error(), "acl modify failed") || !strings.Contains(out, "The token's secret is kept in") {
		t.Fatalf("%v\n%s", err, out)
	}
	if values, _ := loadControllerEnvironment(filepath.Join(dir, partialEnvName)); values["PVE_TOKEN_SECRET"] != wizardPVESecret {
		t.Fatalf("partial = %v", values)
	}
	f.pveFailACL = false
	if out, err := runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"})); err != nil {
		t.Fatalf("run again: %v\n%s", err, out)
	}
}

// A secret kept for another node: the default is no, so --yes stops rather
// than write a secret that may be another cluster's.
func TestTheWizardDoesNotKeepAnotherNodesSecretUnasked(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized = true
	if out, err := runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"})); err != nil {
		t.Fatalf("first run: %v\n%s", err, out)
	}
	f.nodeName = "pve7"
	out, err := runWizard(t, f, dir, unattended(t, setupWizardOptions{}))
	if err == nil || !strings.Contains(err.Error(), "secret is needed") || !strings.Contains(out, `keeps that secret for node "pve1", not pve7`) {
		t.Fatalf("%v\n%s", err, out)
	}
}

// The same PBS, another datastore: the secret is kept, and the PBS part runs
// again for the new grant.
func TestTheWizardGrantsANewDatastoreWithTheKeptSecret(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized = true
	if out, err := runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"})); err != nil {
		t.Fatalf("first run: %v\n%s", err, out)
	}
	f.changes = nil
	out, err := runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore2"}))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(strings.Join(f.changes, "|"), "pbs access on root@pbs.example.com") || strings.Contains(strings.Join(f.changes, "|"), "delete-token") {
		t.Errorf("changes = %q: the PBS part runs for the new grant and keeps the token", f.changes)
	}
	values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env"))
	if values["PBS_REPOSITORY"] != "certistack-ro@pbs!ro@pbs.example.com:8007:datastore2" || values["PBS_PASSWORD"] != wizardPBSSecret {
		t.Errorf("values = %v", values)
	}
}

// The package lists are refreshed after a yes, before the preview, so that
// the preview is of what the install does; the install does not refresh again.
// A no to the refresh stops with the commands for the node, changing nothing.
func TestTheWizardRefreshesThePackageListsBeforeItPreviews(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.aptStale = true, true
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes", "n")
	if err == nil || !strings.Contains(err.Error(), "apt update; apt install --no-upgrade libguestfs-tools nftables") || len(f.changes) != 1 {
		t.Fatalf("a no to the refresh: %v, changes %q\n%s", err, f.changes, out)
	}
	if strings.Contains(out, "apt-get would install") {
		t.Errorf("a preview was shown from lists that were not refreshed:\n%s", out)
	}
	f.changes = nil
	out, err = runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.HasPrefix(strings.Join(f.changes, "|"), "apt update|apt install") || !strings.Contains(out, "apt-get would install 3 package(s)") || strings.Contains(out, "install 2 package(s)") {
		t.Errorf("changes = %q: the preview is not of the refreshed lists\n%s", f.changes, out)
	}
	if !strings.Contains(out, "It would remove no installed package.") {
		t.Errorf("the preview does not say that nothing is removed:\n%s", out)
	}
}

// An install that would remove a package says which, in capitals, and the
// question defaults to no: a yes is needed, and --yes does not give it.
func TestTheWizardAsksBeforeAnInstallThatRemovesPackages(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized = true
	f.aptRemoves = []string{"proxmox-ve", "pve-manager"}
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes", "", "")
	if err == nil || !strings.Contains(err.Error(), "apt-get would remove proxmox-ve, pve-manager") {
		t.Fatalf("the default answer: %v\n%s", err, out)
	}
	if !strings.Contains(out, "It would REMOVE: proxmox-ve, pve-manager.") || !strings.Contains(out, "and remove those packages? [y/N]") {
		t.Errorf("the removal is not shown, or the question does not default to no:\n%s", out)
	}
	if strings.Contains(strings.Join(f.changes, "|"), "apt install") {
		t.Errorf("changes = %q: packages were installed on the default answer", f.changes)
	}

	f2, dir2 := newWizardWorld(t)
	f2.authorized = true
	f2.aptRemoves = []string{"proxmox-ve"}
	out, err = runWizard(t, f2, dir2, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}))
	if err == nil || !strings.Contains(err.Error(), "--yes does not give it") || strings.Contains(strings.Join(f2.changes, "|"), "apt install") {
		t.Fatalf("--yes took the removal: %v, changes %q\n%s", err, f2.changes, out)
	}

	f3, dir3 := newWizardWorld(t)
	f3.authorized = true
	f3.aptRemoves = []string{"proxmox-ve"}
	if out, err := runWizard(t, f3, dir3, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes", "", "y", "", "", "", "pbs.example.com", "datastore1", "", "y", ""); err != nil || !strings.Contains(strings.Join(f3.changes, "|"), "apt install") {
		t.Fatalf("a yes to the removal: %v, changes %q\n%s", err, f3.changes, out)
	}
}

// An existing storage defined for other nodes only is not reused silently.
func TestTheWizardRefusesAStorageOfOtherNodes(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.cluster = true, true
	f.tools = []string{"guestfish", "nft"}
	f.storageCfg = "dir: certistack-scratch\n\tpath /mnt/s\n\tcontent images\n\tnodes pve2\n"
	_, err := runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}))
	if err == nil || !strings.Contains(err.Error(), "limited to node(s) pve2, not pve1") || strings.Join(f.changes, "|") != "keygen id_ed25519" {
		t.Fatalf("%v, changes %q", err, f.changes)
	}
}

// Only a refused key leads to ssh-copy-id: a changed host key is not a
// missing authorization.
func TestTheWizardStopsOnAnSSHFailureThatIsNotTheKey(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.loginErr = "SSH command on node: exit status 255: Host key verification failed."
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes")
	if err == nil || !strings.Contains(err.Error(), "not because the key is not authorized") || strings.Contains(out, "ssh-copy-id?") {
		t.Fatalf("%v\n%s", err, out)
	}
}

// A node whose API certificate an administrator installed: the cluster CA is
// not set as the one to trust, an earlier CA file is carried over, and
// PVE_URL names a host the certificate is for.
func TestTheWizardLeavesACustomCertificateToItsOwnCA(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.customCert = true, true
	out, err := runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env"))
	if values["CERTISTACK_PVE_CA_SOURCE"] != "" || !strings.Contains(out, "not signed by its cluster CA") {
		t.Errorf("CA source = %q\n%s", values["CERTISTACK_PVE_CA_SOURCE"], out)
	}
	if _, err := os.Stat(filepath.Join(dir, defaultCAFileName)); err == nil {
		t.Error("the cluster CA was fetched for a certificate it does not sign")
	}
	names := []string{"*.example.com", "pve.example.com"}
	if got := pveURLHost(names, "192.0.2.10", "pve1"); got != "pve.example.com" {
		t.Errorf("ACME names, an IP to ssh to: %q", got)
	}
	if got := pveURLHost(names, "pve1.example.com", "pve1"); got != "pve1.example.com" {
		t.Errorf("a wildcard: %q", got)
	}
}

func TestTheWizardRefusesFlagsItCannotUse(t *testing.T) {
	f, dir := newWizardWorld(t)
	for opts, want := range map[*setupWizardOptions]string{
		{PBSManual: true, Yes: true, Fingerprint: fixedHostKey(t, 7).Fingerprint}: "--pbs-manual",
		{PBSStorage: "backups", PBSHost: "pbs.example.com"}:                       "not both",
		{PBSHost: "https://pbs.example.com:8007"}:                                 "--pbs-host",
		{PBSDatastore: "a b"}:                                  "--pbs-datastore",
		{PBSNamespace: "a b"}:                                  "--pbs-namespace",
		{PBSFingerprint: "ab:cd"}:                              "--pbs-fingerprint",
		{OverlayStorage: "1 bad"}:                              "--overlay-storage",
		{OverlayPath: "/a b"}:                                  "--overlay-path",
		{Dir: "/tmp/with space", NodeHost: "pve1.example.com"}: "space",
	} {
		_, err := runWizard(t, f, dir, *opts)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", *opts, err, want)
		}
	}
	if len(f.changes) != 0 {
		t.Errorf("changes = %q", f.changes)
	}
	if listed, err := tokenListed(nil, "u@pve", "t"); err != nil || listed {
		t.Errorf("an empty token list: %v %v", listed, err)
	}
}

// Unattended, a key the node does not accept yet: one sign-in test, no
// ssh-copy-id (no terminal for the password), and the line to add. Retries
// would earn the controller OpenSSH 10's PerSourcePenalties on the node, which
// then refuses its connections for minutes.
func TestTheWizardUnattendedStopsAtTheFirstRefusedKey(t *testing.T) {
	f, dir := newWizardWorld(t)
	out, err := runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}))
	if err == nil || !strings.Contains(err.Error(), "append this line to /root/.ssh/authorized_keys on pve1.example.com") ||
		!strings.Contains(err.Error(), "ssh-ed25519 AAAAtest certistack-controller") {
		t.Fatalf("%v\n%s", err, out)
	}
	if f.logins != 1 || strings.Contains(strings.Join(f.changes, "|"), "ssh-copy-id") {
		t.Errorf("sign-in tests = %d, changes = %q: one test and no ssh-copy-id", f.logins, f.changes)
	}
	if hint := sshPenaltyHint(errors.New("ssh: exit status 255: Connection reset by 10.42.71.177 port 22")); !strings.Contains(hint, "PerSourcePenalties") {
		t.Errorf("hint = %q", hint)
	}
	if hint := sshPenaltyHint(errors.New("Permission denied (publickey)")); hint != "" {
		t.Errorf("a refused key got the penalty hint: %q", hint)
	}
}

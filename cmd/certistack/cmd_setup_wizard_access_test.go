// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The question that authorizes the controller's key says what the key becomes:
// root on the node, and, because a cluster shares root's authorized_keys, root
// on every node of the cluster. The node cannot be read before the key works,
// so the question says both.
func TestTheSSHCopyIDQuestionSaysWhatTheKeyGrants(t *testing.T) {
	f, dir := newWizardWorld(t)
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes", "n", "")
	if err == nil {
		t.Fatalf("the setup went on with no key authorized:\n%s", out)
	}
	flat := strings.Join(strings.Fields(out), " ")
	for _, want := range []string{
		"Authorize it for root with ssh-copy-id?",
		"The key then signs in as root on this node.",
		"If the node is in a cluster, root's authorized_keys is shared by all its nodes, so the key signs in as root on every node of the cluster.",
		"ssh-copy-id asks for root's password on the node once",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("the question lacks %q:\n%s", want, out)
		}
	}
}

// On a cluster node setup says once what every run costs the cluster, and how a
// plan avoids it; on a standalone node it says nothing of the kind.
func TestTheWizardSaysWhatARunDoesToTheNetworkOfAClusterNode(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.cluster = true, true
	f.tools = []string{"guestfish", "nft"}
	f.storageCfg = "dir: certistack-scratch\n\tpath /mnt/s\n\tcontent images\n"
	out, err := runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	flat := strings.Join(strings.Fields(out), " ")
	const note = "Every run applies SDN twice, and PVE reloads the network on all 3 nodes each time. network.lifecycle: preprovisioned in the plan avoids it (https://certistack.dev/docs/plan-reference/#use-a-pre-provisioned-sandbox)."
	if strings.Count(flat, note) != 1 || !strings.Contains(flat, "in a cluster of 3 nodes") {
		t.Errorf("the cluster note is not said once, with the node count:\n%s", out)
	}

	f2, dir2 := newWizardWorld(t)
	f2.authorized = true
	f2.tools = []string{"guestfish", "nft"}
	f2.storageCfg = f.storageCfg
	out, err = runWizard(t, f2, dir2, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}))
	if err != nil || strings.Contains(out, "applies SDN twice") {
		t.Errorf("a standalone node: %v\n%s", err, out)
	}
}

// settledNode is a node that has what a run needs and an overlay storage, so
// that a test reaches the PBS step with the fewest answers.
func settledNode(t *testing.T) (*fakeWizardWorld, string) {
	t.Helper()
	f, dir := newWizardWorld(t)
	f.authorized = true
	f.tools = []string{"guestfish", "nft"}
	f.storageCfg = "dir: certistack-scratch\n\tpath /var/lib/vz/certistack-scratch\n\tcontent images\n"
	return f, dir
}

// An empty namespace answer is every namespace of the datastore: it is a
// question of its own, and the answer is no unless it is yes.
func TestAnEmptyPBSNamespaceAnswerAsksBeforeItGrantsTheWholeDatastore(t *testing.T) {
	f, dir := settledNode(t)
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"},
		"", "", "yes", // directory, node, host key
		"", // create the PVE access
		"pbs.example.com", "datastore1",
		"",     // an empty namespace
		"",     // Continue? the default
		"prod", // asked again: a namespace
		"",     // over ssh
		"",     // the fingerprint read over ssh: the dashboard shows it
	)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	const question = "The PBS user can then read every namespace of datastore datastore1. Continue? [y/N]"
	if strings.Count(out, question) != 1 {
		t.Errorf("the question is not asked once:\n%s", out)
	}
	if strings.Count(out, "The PBS namespace of the backups") != 2 {
		t.Errorf("a no does not ask for the namespace again:\n%s", out)
	}
	if values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env")); values["PBS_NAMESPACE"] != "prod" {
		t.Errorf("PBS_NAMESPACE = %q, want prod", values["PBS_NAMESPACE"])
	}

	f, dir = settledNode(t)
	out, err = runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"},
		"", "", "yes", "", "pbs.example.com", "datastore1", "/", "y", "", "")
	if err != nil {
		t.Fatalf("a yes: %v\n%s", err, out)
	}
	if values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env")); values["PBS_NAMESPACE"] != "" {
		t.Errorf("a yes to the whole datastore: PBS_NAMESPACE = %q", values["PBS_NAMESPACE"])
	}

	// --pbs-namespace / is the root namespace asked for by name: no question.
	f, dir = settledNode(t)
	out, err = runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", PBSNamespace: "/"},
		"", "", "yes", "", "pbs.example.com", "datastore1", "", "")
	if err != nil || strings.Contains(out, "Continue?") {
		t.Errorf("--pbs-namespace /: %v\n%s", err, out)
	}
}

// Unattended, the namespace is given by flag or by the earlier controller.env,
// and when neither names one --yes stops before anything on a host is changed.
func TestUnattendedSetupStopsAtAPBSNamespaceNobodyNamed(t *testing.T) {
	f, dir := settledNode(t)
	opts := unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"})
	opts.PBSNamespace = ""
	out, err := runWizard(t, f, dir, opts)
	if err == nil || !strings.Contains(err.Error(), "--pbs-namespace NAMESPACE") || !strings.Contains(err.Error(), "datastore1") {
		t.Fatalf("an unnamed namespace under --yes: %v\n%s", err, out)
	}
	// The flags decide it, so it stops before step 1: not even the
	// controller's own key is made.
	if len(f.changes) != 0 {
		t.Errorf("changes = %q: the stop came after a change", f.changes)
	}

	// The earlier file names one: the rerun keeps working.
	opts.PBSNamespace = "prod"
	if out, err := runWizard(t, f, dir, opts); err != nil {
		t.Fatalf("with --pbs-namespace: %v\n%s", err, out)
	}
	opts.PBSNamespace = ""
	f.changes = nil
	if out, err := runWizard(t, f, dir, opts); err != nil {
		t.Fatalf("the earlier controller.env names prod: %v\n%s", err, out)
	}
	if values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env")); values["PBS_NAMESPACE"] != "prod" {
		t.Errorf("PBS_NAMESPACE = %q, want the earlier prod", values["PBS_NAMESPACE"])
	}
}

const pbsStoragesCfg = "dir: certistack-scratch\n\tpath /var/lib/vz/certistack-scratch\n\tcontent images\n\n" +
	"pbs: backups\n\tserver 10.42.10.5\n\tdatastore pbs-data\n\tfingerprint 1B:FB:2F:B9:9C:66:ED:63:D5:0D:53:DF:91:7C:AA:97:17:D5:CD:D7:24:82:18:03:CD:2E:68:C3:3F:93:1E:86\n\n" +
	"pbs: cold\n\tserver 10.42.10.6\n\tdatastore cold\n\tnamespace old\n"

// The node's PBS storage list marks the default, and a storage that backs up
// to the root namespace gets the same question as an empty answer.
func TestThePBSStorageListMarksTheDefaultAndAsksAboutTheRootNamespace(t *testing.T) {
	f, dir := settledNode(t)
	f.storageCfg = pbsStoragesCfg
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"},
		"", "", "yes", "",
		"1", // backups: no namespace
		"",  // Continue? no: back to the list
		"2", // archive: namespace old
		"",  // over ssh
		"",  // the fingerprint read over ssh: the dashboard shows it
	)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "1. backups: 10.42.10.5:8007, datastore pbs-data (default)\n") || strings.Contains(out, "2. cold: 10.42.10.6:8007, datastore cold, namespace old (default)") {
		t.Errorf("the list does not mark the first storage as the default:\n%s", out)
	}
	if !strings.Contains(out, "The PBS user can then read every namespace of datastore pbs-data. Continue? [y/N]") || strings.Count(out, "Which one holds the backups to test") != 2 {
		t.Errorf("a storage without a namespace is not asked about, or a no does not return to the list:\n%s", out)
	}
	if values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env")); values["PBS_NAMESPACE"] != "old" {
		t.Errorf("PBS_NAMESPACE = %q, want old", values["PBS_NAMESPACE"])
	}

	// Unattended, the default storage has no namespace: --yes stops and names the flag.
	f, dir = settledNode(t)
	f.storageCfg = pbsStoragesCfg
	opts := unattended(t, setupWizardOptions{})
	opts.PBSNamespace = ""
	if out, err := runWizard(t, f, dir, opts); err == nil || !strings.Contains(err.Error(), "--pbs-namespace") || strings.Join(f.changes, "|") != "keygen id_ed25519" {
		t.Errorf("--yes took the whole datastore: %v, changes %q\n%s", err, f.changes, out)
	}
}

// The key of an encrypted storage decrypts every backup in it: the question
// says so and defaults to no, which --yes takes.
func TestTheEncryptionKeyIsCopiedOnlyAfterAYes(t *testing.T) {
	cfg := "dir: certistack-scratch\n\tpath /var/lib/vz/certistack-scratch\n\tcontent images\n\n" +
		"pbs: backups\n\tserver 10.42.10.5\n\tdatastore pbs-data\n\tnamespace prod\n\tfingerprint 1B:FB:2F:B9:9C:66:ED:63:D5:0D:53:DF:91:7C:AA:97:17:D5:CD:D7:24:82:18:03:CD:2E:68:C3:3F:93:1E:86\n\tencryption-key 44:a5\n"
	f, dir := settledNode(t)
	f.storageCfg = cfg
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes", "", "1", "", "", "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "The key decrypts every backup in the storage backups. Copy it to "+filepath.Join(dir, "backups.enc")+" (mode 0600)? [y/N]") {
		t.Errorf("the question does not say what the key decrypts, or does not default to no:\n%s", out)
	}
	if strings.Contains(strings.Join(f.changes, "|"), "read key") {
		t.Errorf("changes = %q: the key was copied on the default answer", f.changes)
	}
	if values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env")); values["CERTISTACK_PBS_KEYFILE"] != "" {
		t.Errorf("CERTISTACK_PBS_KEYFILE = %q after a no", values["CERTISTACK_PBS_KEYFILE"])
	}

	f, dir = settledNode(t)
	f.storageCfg = cfg
	out, err = runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSStorage: "backups"}))
	if err != nil || strings.Contains(strings.Join(f.changes, "|"), "read key") || !strings.Contains(out, "Not copied: set CERTISTACK_PBS_KEYFILE") {
		t.Errorf("--yes copied the key, or did not say it did not: %v, changes %q\n%s", err, f.changes, out)
	}
}

// The questions that replace a token say what the old secret's holders meet.
func TestTheReplaceTokenQuestionsSayWhatStopsWorking(t *testing.T) {
	const holders = "The old secret stops working: anything still using it (a scheduled job, another controller) fails until it gets the new one [y/N]"
	f, dir := settledNode(t)
	f.pveToken = true
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes", "n")
	if err == nil || !strings.Contains(out, holders) || !strings.Contains(out, "PVE cannot show its secret again. Replace it with a new one?") {
		t.Errorf("the PVE question: %v\n%s", err, out)
	}

	f, dir = settledNode(t)
	f.pbsToken = true
	out, err = runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", PBSNamespace: "/"},
		"", "", "yes", "", "pbs.example.com", "datastore1", "", "", "n")
	if err == nil || !strings.Contains(out, holders) || !strings.Contains(out, "PBS cannot show its secret again. Replace it with a new one?") {
		t.Errorf("the PBS question: %v\n%s", err, out)
	}
}

// --fingerprint is refused, before anything is asked or connected to, when it
// is not in the form ssh-keygen prints; so is --pbs-fingerprint.
func TestTheWizardRefusesAMalformedFingerprintBeforeItConnects(t *testing.T) {
	for _, tc := range []struct {
		opts setupWizardOptions
		want string
	}{
		{setupWizardOptions{Fingerprint: "SHA256:abc"}, "--fingerprint"},
		{setupWizardOptions{Fingerprint: "1b:fb:2f:b9:9c:66:ed:63:d5:0d:53:df:91:7c:aa:97"}, "--fingerprint"},
		{setupWizardOptions{Fingerprint: "MD5:00:11"}, "--fingerprint"},
		{setupWizardOptions{PBSFingerprint: "SHA256:abc"}, "--pbs-fingerprint"},
		{setupWizardOptions{PBSFingerprint: "not a fingerprint"}, "--pbs-fingerprint"},
	} {
		f, dir := newWizardWorld(t)
		asked := withHostKey(t, fixedHostKey(t, 7), nil)
		tc.opts.NodeHost = "pve1.example.com"
		out, err := runWizard(t, f, dir, tc.opts)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v\n%s", tc.opts, err, out)
		}
		if len(*asked) != 0 || out != "" || len(f.changes) != 0 {
			t.Errorf("%+v: the wizard went on (host keys asked for %q, output %q, changes %q)", tc.opts, *asked, out, f.changes)
		}
		if _, statErr := os.Stat(dir); statErr == nil {
			t.Errorf("%+v: the directory %s was made before the flag was refused", tc.opts, dir)
		}
	}
}

// An error that asks for --fingerprint says where the fingerprint comes from,
// and does not show SHA256:... as if it were a value to type.
func TestFingerprintErrorsSayWhereTheFingerprintComesFrom(t *testing.T) {
	const from = "the fingerprint that ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub prints on the node"
	f, dir := newWizardWorld(t)
	_, wizardErr := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", Yes: true})
	withHostKey(t, fixedHostKey(t, 7), nil)
	known := filepath.Join(t.TempDir(), "known_hosts")
	_, yesErr := runRootWithInput(t, "", "setup", "trust-node", "--host", "pve.example", "--known-hosts", known, "--yes")
	_, declinedErr := runRootWithInput(t, "no\n", "setup", "trust-node", "--host", "pve.example", "--known-hosts", known)
	_, malformedErr := runRootWithInput(t, "", "setup", "trust-node", "--host", "pve.example", "--known-hosts", known, "--fingerprint", "SHA256:abc")
	for name, err := range map[string]error{"wizard --yes": wizardErr, "trust-node --yes": yesErr, "trust-node declined": declinedErr, "malformed": malformedErr} {
		if err == nil || !strings.Contains(err.Error(), from) || strings.Contains(err.Error(), "SHA256:...") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

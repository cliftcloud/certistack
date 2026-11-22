// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fingerprintQuestion = "Does the PBS dashboard (Dashboard > Show Fingerprint) show this fingerprint? [Y/n]"

// pbsFingerprintSources are the three places setup takes the PBS certificate's
// fingerprint from itself, each as a settled node whose PBS part has not run:
// the node's PBS storage, an earlier controller.env, and the PBS over ssh. Each
// has the answers that lead to the fingerprint question, the flags that do the
// same under --yes, and the source setup names.
func pbsFingerprintSources(t *testing.T) map[string]func(t *testing.T) (*fakeWizardWorld, string, []string, setupWizardOptions, string) {
	t.Helper()
	return map[string]func(t *testing.T) (*fakeWizardWorld, string, []string, setupWizardOptions, string){
		"storage": func(t *testing.T) (*fakeWizardWorld, string, []string, setupWizardOptions, string) {
			f, dir := settledNode(t)
			f.storageCfg += "\npbs: backups\n\tserver 10.42.10.5\n\tdatastore pbs-data\n\tnamespace prod\n\tfingerprint " + strings.ToUpper(wizardPBSPrint) + "\n"
			return f, dir, []string{"", "", "yes", "", "1"}, setupWizardOptions{PBSStorage: "backups", PBSNamespace: "prod"}, "from the node's storage backups"
		},
		"earlier controller.env": func(t *testing.T) (*fakeWizardWorld, string, []string, setupWizardOptions, string) {
			f, dir := settledNode(t)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			earlier := "PBS_REPOSITORY=certistack-ro@pbs!ro@pbs.example.com:8007:datastore1\nPBS_NAMESPACE=prod\nPBS_FINGERPRINT=" + wizardPBSPrint + "\n"
			if err := os.WriteFile(filepath.Join(dir, "controller.env"), []byte(earlier), 0o600); err != nil {
				t.Fatal(err)
			}
			return f, dir, []string{"", "", "yes", "", "", "", ""}, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1", PBSNamespace: "prod"},
				"from the earlier environment file " + filepath.Join(dir, "controller.env")
		},
		"ssh": func(t *testing.T) (*fakeWizardWorld, string, []string, setupWizardOptions, string) {
			f, dir := settledNode(t)
			return f, dir, []string{"", "", "yes", "", "pbs.example.com", "datastore1", "prod", ""}, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1", PBSNamespace: "prod"},
				"read from the PBS over ssh (proxmox-backup-manager cert info)"
		},
	}
}

// pbsChanged reports the changes made on the PBS.
func pbsChanged(f *fakeWizardWorld) []string {
	var changed []string
	for _, c := range f.changes {
		if strings.HasPrefix(c, "pbs ") {
			changed = append(changed, c)
		}
	}
	return changed
}

// A fingerprint setup takes itself is shown, with where it came from, and asked
// about before anything changes on the PBS. A no stops setup there: nothing is
// created on the PBS, no controller.env is written, and the error says how to
// go on.
func TestTheWizardAsksAboutTheFingerprintItTookBeforeItChangesThePBS(t *testing.T) {
	for name, source := range pbsFingerprintSources(t) {
		t.Run(name, func(t *testing.T) {
			f, dir, answers, _, from := source(t)
			before, _ := os.ReadFile(filepath.Join(dir, "controller.env"))
			out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, append(answers, "n")...)
			if err == nil || !strings.Contains(err.Error(), "setup stopped before it changed anything on the PBS or wrote controller.env: ") ||
				!strings.Contains(err.Error(), "--pbs-fingerprint and the fingerprint the dashboard shows") {
				t.Fatalf("a no to the fingerprint: %v\n%s", err, out)
			}
			if fix := "correct the storage's fingerprint first (Datacenter > Storage > backups)"; strings.Contains(err.Error(), fix) != (name == "storage") {
				t.Errorf("the storage's fix is named only for a fingerprint from the storage: %v", err)
			}
			if !strings.Contains(out, "PBS certificate fingerprint, "+from+":\n  "+wizardPBSPrint+"\n"+fingerprintQuestion+": ") {
				t.Errorf("the fingerprint and its source are not shown before the question:\n%s", out)
			}
			if changed := pbsChanged(f); len(changed) != 0 {
				t.Errorf("the PBS was changed after a no: %q", changed)
			}
			for _, script := range f.pbsScripts {
				if script != pbsFingerprintReadScript {
					t.Errorf("the PBS was given more than the read of its fingerprint:\n%s", script)
				}
			}
			if after, _ := os.ReadFile(filepath.Join(dir, "controller.env")); string(after) != string(before) {
				t.Errorf("controller.env was written after a no:\n%s", after)
			}
			if _, err := os.Stat(filepath.Join(dir, "pbs-access.sh")); err == nil {
				t.Error("the PBS part was written to paste after a no")
			}
		})
	}
}

// Enter (yes) goes on with the PBS part and pins the fingerprint; --yes takes
// it without the question and says so in one line.
func TestTheWizardUsesTheFingerprintItTookAfterAYesOrUnderYes(t *testing.T) {
	for name, source := range pbsFingerprintSources(t) {
		t.Run(name, func(t *testing.T) {
			f, dir, answers, _, _ := source(t)
			out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, append(answers, "", "")...)
			if err != nil {
				t.Fatalf("a yes to the fingerprint: %v\n%s", err, out)
			}
			if i, j := strings.Index(out, fingerprintQuestion), strings.Index(out, "PBS user certistack-ro@pbs created."); i < 0 || j < i {
				t.Errorf("the question does not come before the PBS part:\n%s", out)
			}
			if values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env")); values["PBS_FINGERPRINT"] != wizardPBSPrint {
				t.Errorf("PBS_FINGERPRINT = %q", values["PBS_FINGERPRINT"])
			}

			f, dir, _, flags, from := source(t)
			out, err = runWizard(t, f, dir, unattended(t, flags))
			if err != nil {
				t.Fatalf("--yes: %v\n%s", err, out)
			}
			accepted := "PBS certificate fingerprint, " + from + ":\n  " + wizardPBSPrint + "\n" +
				"--yes accepts it without asking: compare it with the PBS dashboard (Dashboard > Show Fingerprint), or give --pbs-fingerprint to have setup compare it.\n"
			if !strings.Contains(out, accepted) || strings.Contains(out, fingerprintQuestion) {
				t.Errorf("--yes does not say it took the fingerprint, or asks:\n%s", out)
			}
			if changed := pbsChanged(f); len(changed) != 1 || !strings.HasPrefix(changed[0], "pbs access on ") {
				t.Errorf("--yes: PBS changes %q", changed)
			}
			if values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env")); values["PBS_FINGERPRINT"] != wizardPBSPrint {
				t.Errorf("--yes: PBS_FINGERPRINT = %q", values["PBS_FINGERPRINT"])
			}
		})
	}
}

// A --pbs-fingerprint that differs from the one the node's storage or the PBS
// reports is refused before the PBS is changed, interactive or not. The
// earlier controller.env's is not compared: a renewed certificate has a new
// one, and the flag is how to give it (the PBS, read over ssh, must agree).
func TestTheWizardRefusesAGivenPBSFingerprintThatDiffersBeforeItChangesThePBS(t *testing.T) {
	other := "00" + wizardPBSPrint[2:]
	for name, source := range pbsFingerprintSources(t) {
		for _, yes := range []bool{false, true} {
			f, dir, answers, flags, _ := source(t)
			if name == "earlier controller.env" {
				f.pbsPrint = other // the PBS's renewed certificate, which ssh reads
			}
			opts := setupWizardOptions{NodeHost: "pve1.example.com", PBSFingerprint: other}
			if yes {
				flags.PBSFingerprint = other
				opts, answers = unattended(t, flags), nil
			}
			out, err := runWizard(t, f, dir, opts, append(answers, "", "")...)
			if name == "earlier controller.env" {
				values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env"))
				if err != nil || values["PBS_FINGERPRINT"] != other || strings.Contains(out, fingerprintQuestion) {
					t.Errorf("%s, --yes %v: the flag over the earlier file's: %v, PBS_FINGERPRINT %q\n%s", name, yes, err, values["PBS_FINGERPRINT"], out)
				}
				continue
			}
			if err == nil || !strings.Contains(err.Error(), "is not the fingerprint the PBS storage or the PBS reports") {
				t.Errorf("%s, --yes %v: a --pbs-fingerprint that differs: %v\n%s", name, yes, err, out)
			}
			if changed := pbsChanged(f); len(changed) != 0 {
				t.Errorf("%s, --yes %v: the PBS was changed before the refusal: %q", name, yes, changed)
			}
			if _, err := os.Stat(filepath.Join(dir, "controller.env")); err == nil {
				t.Errorf("%s, --yes %v: controller.env was written", name, yes)
			}
		}
	}
}

// When setup must read the fingerprint over ssh and that ssh fails, nothing
// has changed on the PBS: interactive, setup falls back to the paste and asks
// for the fingerprint; under --yes it stops and names --pbs-ssh.
func TestTheWizardFallsBackWhenTheFingerprintCannotBeReadOverSSH(t *testing.T) {
	f, dir := settledNode(t)
	f.pbsFails = true
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"},
		"", "", "yes", "", "pbs.example.com", "datastore1", "prod", "", wizardPBSPrint)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "The PBS certificate's fingerprint could not be read over ssh") || !strings.Contains(out, "pbs-access.sh") {
		t.Errorf("the failed read, then the paste:\n%s", out)
	}
	if values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env")); values["PBS_FINGERPRINT"] != wizardPBSPrint {
		t.Errorf("PBS_FINGERPRINT = %q", values["PBS_FINGERPRINT"])
	}

	f, dir = settledNode(t)
	f.pbsFails = true
	out, err = runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}))
	if err == nil || !strings.Contains(err.Error(), "--pbs-ssh") || len(pbsChanged(f)) != 0 {
		t.Errorf("--yes with no ssh to the PBS: %v, PBS changes %q\n%s", err, pbsChanged(f), out)
	}
}

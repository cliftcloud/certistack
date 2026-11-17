// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/nodesetup"
	"github.com/cliftcloud/certistack/pkg/controller"
)

const (
	wizardPVESecret = "11111111-2222-4333-8444-555555555555"
	wizardPBSSecret = "66666666-7777-4888-9999-aaaaaaaaaaaa"
	wizardPBSPrint  = "1b:fb:2f:b9:9c:66:ed:63:d5:0d:53:df:91:7c:aa:97:17:d5:cd:d7:24:82:18:03:cd:2e:68:c3:3f:93:1e:86"
)

// fakeWizardWorld is a node and a PBS that answer the wizard's scripts as
// stock hosts would, and record every change they are asked to make.
type fakeWizardWorld struct {
	t          *testing.T
	authorized bool
	tools      []string
	storageCfg string
	cluster    bool
	pveToken   bool     // the PVE token exists already
	pbsToken   bool     // the PBS token exists already
	pbsFails   bool     // ssh to the PBS fails
	pbsWider   string   // who still holds the grant on the whole datastore, as the PBS part reports it
	pbsScripts []string // every script run on the PBS
	customCert bool     // the API certificate is not signed by the cluster CA
	aptStale   bool     // the package lists do not know the packages until apt-get update
	aptRemoves []string // what apt-get says installing would remove
	aptUpdated bool     // apt-get update ran: only then does the preview list every package
	pveFailACL bool     // the PVE part fails after it created the token
	nodeName   string
	loginErr   string // what ssh says when the key is not accepted
	logins     int    // sign-in tests (each failed one counts against the controller on OpenSSH 10)
	changes    []string
	checked    string
	ca         []byte
}

func (f *fakeWizardWorld) deps(t *testing.T, dir string) setupWizardDeps {
	return setupWizardDeps{
		sshKeygen: func(_ context.Context, path string) error {
			f.changes = append(f.changes, "keygen "+filepath.Base(path))
			if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
				return err
			}
			return os.WriteFile(path+".pub", []byte("ssh-ed25519 AAAAtest certistack-controller\n"), 0o644)
		},
		sshCopyID: func(_ context.Context, cfg controller.SSHConfig) error {
			f.changes = append(f.changes, "ssh-copy-id "+cfg.User+"@"+cfg.Host)
			f.authorized = true
			return nil
		},
		nodeScript: f.nodeScript,
		nodeFile: func(_ context.Context, _ controller.SSHConfig, path string, _ int) ([]byte, error) {
			switch {
			case path == nodesetup.PVERootCAPath:
				return f.ca, nil
			case strings.HasSuffix(path, ".enc"):
				f.changes = append(f.changes, "read key "+path)
				return []byte("{\"kdf\":null}"), nil
			}
			return nil, errors.New("no such file: " + path)
		},
		pbsScript: func(_ context.Context, target string, _ int, script string, stderr io.Writer) ([]byte, error) {
			if f.pbsFails {
				return nil, errors.New("ssh: connect to host: Connection refused")
			}
			f.pbsScripts = append(f.pbsScripts, script)
			if strings.Contains(script, "--delete true") && !strings.Contains(script, "PART 2") {
				f.changes = append(f.changes, "pbs remove grant on "+target)
				f.pbsWider = ""
				return nil, nil
			}
			if strings.HasPrefix(script, "proxmox-backup-manager user delete-token") {
				f.changes = append(f.changes, "pbs delete-token")
				f.pbsToken = false
			}
			if !strings.Contains(script, "PART 2") || !strings.Contains(script, ">&3") {
				f.t.Fatalf("the PBS was given something other than the capture-mode PBS part:\n%s", script)
			}
			f.changes = append(f.changes, "pbs access on "+target)
			io.WriteString(stderr, "PBS user certistack-ro@pbs created.\n")
			out := ""
			if !f.pbsToken {
				// generate-token's own output on PBS 4.2: "Result: " and the object.
				out = "Result: {\n  \"tokenid\": \"certistack-ro@pbs!ro\",\n  \"value\": \"" + wizardPBSSecret + "\"\n}\n"
				f.pbsToken = true
			}
			if f.pbsWider != "" && strings.Contains(script, "wider_grant") {
				out += `{"wider_grant":"` + f.pbsWider + `"}` + "\n"
			}
			return []byte(out + `{"fingerprint":"` + wizardPBSPrint + `"}` + "\n"), nil
		},
		check: func(_ context.Context, envPath string, w io.Writer) error {
			f.checked = envPath
			io.WriteString(w, "✓ Every layer passed.\n")
			return nil
		},
		// The per-user directory of this test, not the account's.
		envPointer: func() (string, error) { return wizardPointerPath(dir), nil },
		readSecret: func(context.Context, string, io.Writer) (string, error) { return wizardPBSSecret, nil },
		isTerminal: func() bool { return true },
		now:        func() time.Time { return time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC) },
		reportsDir: filepath.Join(dir, "no-such-reports-dir"),
	}
}

func (f *fakeWizardWorld) nodeScript(_ context.Context, cfg controller.SSHConfig, script string, stderr io.Writer) ([]byte, error) {
	if cfg.User != "root" || cfg.KnownHostsFile == "" || cfg.IdentityFile == "" {
		f.t.Fatalf("the node was reached without the controller's strict access: %+v", cfg)
	}
	if script == "true" {
		f.logins++
	}
	if !f.authorized {
		if f.loginErr != "" {
			return nil, errors.New(f.loginErr)
		}
		return nil, errors.New("SSH command on node: exit status 255: root@node: Permission denied (publickey)")
	}
	switch {
	case script == "true":
		return nil, nil
	case script == nodesetup.NodeFactsScript:
		name := f.nodeName
		if name == "" {
			name = "pve1"
		}
		ca := "cert_cluster_ca=1"
		if f.customCert {
			ca = "cert_cluster_ca=0"
		}
		lines := []string{"pve_local=nodes/" + name, ca, "pve_version=pve-manager/9.2.2/b9984c6d90a4bd80 (running kernel: 7.0.2-6-pve)", "kvm=1", "arch=x86_64",
			"root_source=/dev/sda2", "vz_source=/dev/sda2", "vz_avail=107374182400",
			"storage_cfg=" + base64.StdEncoding.EncodeToString([]byte(f.storageCfg)),
			"cert_names=IPAddress:127.0.0.1,DNS:localhost,IPAddress:192.0.2.10,DNS:pve1,DNS:pve1.example.com"}
		if f.cluster {
			lines = append(lines, "cluster=1", "cluster_nodes=3")
		} else {
			lines = append(lines, "cluster=0")
		}
		for _, t := range append([]string{"qemu-img", "proxmox-backup-client", "ip", "apt-get", "pvesm", "pveum"}, f.tools...) {
			lines = append(lines, "tool="+t)
		}
		return []byte(strings.Join(append(lines, "facts_end=1"), "\n") + "\n"), nil
	case strings.Contains(script, "apt-get -s"):
		if f.aptStale {
			return []byte("preview_error=E: Unable to locate package libguestfs-tools\npreview_end=1\n"), nil
		}
		// Before a refresh the lists are old: they know two of the three
		// packages the install would add.
		out := "inst=libguestfs-tools\ninst=nftables\n"
		if f.aptUpdated {
			out = "inst=libguestfs-tools\ninst=supermin\ninst=nftables\n"
		}
		for _, name := range f.aptRemoves {
			out += "rem=" + name + "\n"
		}
		return []byte(out + "preview_end=1\n"), nil
	case script == nodesetup.PackagesUpdateScript:
		f.changes = append(f.changes, "apt update")
		f.aptStale, f.aptUpdated = false, true
		return nil, nil
	case strings.Contains(script, "probe_end=1"):
		// /var/lib/vz and /root are on the root disk (sda2); /mnt is not.
		source := "/dev/sda2"
		if strings.Contains(script, "\np=/mnt/") {
			source = "/dev/sdb1"
		}
		return []byte("source=" + source + "\navail=107374182400\nprobe_end=1\n"), nil
	case strings.Contains(script, "apt-get -y --no-upgrade install"):
		f.changes = append(f.changes, "apt install")
		return nil, nil
	case strings.Contains(script, "pvesm add dir"):
		f.changes = append(f.changes, "storage: "+strings.TrimSpace(script[strings.Index(script, "pvesm"):]))
		return nil, nil
	case strings.HasPrefix(script, "pveum user token list"):
		if f.pveToken {
			return []byte(`[{"expire":0,"privsep":1,"tokenid":"automation"}]`), nil
		}
		return []byte("[]"), nil
	case strings.HasPrefix(script, "pveum user token remove"):
		f.changes = append(f.changes, "pve token remove")
		f.pveToken = false
		return nil, nil
	case strings.Contains(script, "PART 1") && strings.Contains(script, ">&3"):
		f.changes = append(f.changes, "pve access")
		io.WriteString(stderr, "Role CertiStackRole created.\n")
		if f.pveToken {
			return nil, nil
		}
		f.pveToken = true
		created := []byte(`{"full-tokenid":"certistack-svc@pve!automation","info":{"privsep":"1"},"value":"` + wizardPVESecret + `"}` + "\n")
		if f.pveFailACL {
			// As RunNodeScript returns it: the output with the error.
			return created, errors.New("SSH command on node: exit status 255: acl modify failed")
		}
		return created, nil
	}
	f.t.Fatalf("the node was given a script the wizard does not send:\n%s", script)
	return nil, nil
}

// wizardPointerPath is where the fake world's setup, whose directory is dir,
// records the environment file: beside dir, in the test's own directory.
func wizardPointerPath(dir string) string {
	return filepath.Join(filepath.Dir(dir), "config", "certistack", envFilePointerName)
}

func newWizardWorld(t *testing.T) (*fakeWizardWorld, string) {
	t.Helper()
	withHostKey(t, fixedHostKey(t, 7), nil)
	dir := filepath.Join(t.TempDir(), "secure")
	return &fakeWizardWorld{t: t, ca: pveTestCA(t, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), true)}, dir
}

func runWizard(t *testing.T, f *fakeWizardWorld, dir string, opts setupWizardOptions, answers ...string) (string, error) {
	t.Helper()
	if opts.Dir == "" {
		opts.Dir = dir
	}
	var out strings.Builder
	err := runSetupWizard(context.Background(), &out, strings.NewReader(strings.Join(answers, "\n")+"\n"), opts, f.deps(t, dir))
	return out.String(), err
}

// A stock node that backs up to nothing yet, a PBS reached over ssh: every
// change is asked for, done once, and the secrets go only into the file.
func TestTheWizardSetsUpAStockNodeFromNothing(t *testing.T) {
	t.Setenv("PVE_URL", "")
	f, dir := newWizardWorld(t)
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"},
		"",                // directory: the default (the flag's)
		"",                // node address: the flag's
		"yes",             // the host key matches
		"",                // authorize with ssh-copy-id: yes
		"",                // refresh the package lists: yes
		"",                // install the packages: yes
		"",                // storage directory: the default
		"",                // add the storage: yes
		"",                // create the PVE access: yes
		"pbs.example.com", // the PBS host
		"datastore1",      // its datastore
		"",                // the root namespace
		"y",               // yes, the PBS user may read every namespace of the datastore
		"",                // run the PBS part over ssh: yes
	)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := []string{"keygen id_ed25519", "ssh-copy-id root@pve1.example.com", "apt update", "apt install",
		"storage: pvesm add dir certistack-scratch --path /var/lib/vz/certistack-scratch --content images --shared 0",
		"pve access", "pbs access on root@pbs.example.com"}
	if strings.Join(f.changes, "|") != strings.Join(want, "|") {
		t.Errorf("changes = %q\nwant      %q", f.changes, want)
	}
	if strings.Contains(out, wizardPVESecret) || strings.Contains(out, wizardPBSSecret) {
		t.Fatalf("a secret was shown:\n%s", out)
	}
	envPath := filepath.Join(dir, "controller.env")
	if f.checked != envPath {
		t.Errorf("check ran on %q", f.checked)
	}
	info, err := os.Stat(envPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("env file: %v %v", info, err)
	}
	values, err := loadControllerEnvironment(envPath)
	if err != nil {
		t.Fatalf("the written file does not load: %v", err)
	}
	for name, want := range map[string]string{
		"PVE_URL": "https://pve1.example.com:8006", "PVE_TOKEN_ID": "certistack-svc@pve!automation", "PVE_TOKEN_SECRET": wizardPVESecret,
		"PBS_REPOSITORY": "certistack-ro@pbs!ro@pbs.example.com:8007:datastore1", "PBS_PASSWORD": wizardPBSSecret, "PBS_FINGERPRINT": wizardPBSPrint,
		"CERTISTACK_NODE": "pve1", "CERTISTACK_SSH_HOST": "pve1.example.com", "CERTISTACK_SSH_USER": "root",
		"CERTISTACK_SSH_IDENTITY": filepath.Join(dir, "id_ed25519"), "CERTISTACK_SSH_KNOWN_HOSTS": filepath.Join(dir, "known_hosts"),
		"CERTISTACK_PVE_CA_SOURCE": filepath.Join(dir, "pve-root-ca.pem"), "CERTISTACK_OVERLAY_STORAGE": "certistack-scratch",
	} {
		if values[name] != want {
			t.Errorf("%s = %q, want %q", name, values[name], want)
		}
	}
	if values["PBS_NAMESPACE"] != "" || values["CERTISTACK_PBS_KEYFILE"] != "" {
		t.Errorf("unexpected values: %v", values)
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %04o", info.Mode().Perm())
	}
	if kh, _ := os.ReadFile(filepath.Join(dir, "known_hosts")); !strings.HasPrefix(string(kh), "pve1.example.com ssh-ed25519 ") {
		t.Errorf("known_hosts = %q", kh)
	}
	// check names the next step (certistack init ...); setup does not repeat
	// it, and ends with the one line on the file the commands now use.
	pointer := wizardPointerPath(dir)
	last := "Commands now use " + envPath + " when not given --env-file (recorded in " + pointer + "); --env-file chooses another file.\n"
	if f.checked != envPath || !strings.HasSuffix(out, "✓ Every layer passed.\nSetup is done.\n"+last) {
		t.Errorf("check on %q, then the end:\n%s", f.checked, out)
	}
	if recorded, err := os.ReadFile(pointer); err != nil || string(recorded) != envPath+"\n" {
		t.Errorf("the pointer holds %q (%v), want %q and a newline", recorded, err, envPath)
	}
}

// A node that backs up to an encrypted PBS storage already: the PBS, its
// namespace and fingerprint are offered, and the key is copied after a yes.
func TestTheWizardOffersTheNodesOwnPBSStorage(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized = true
	f.tools = []string{"guestfish", "nft"}
	f.storageCfg = "dir: local\n\tpath /var/lib/vz\n\tcontent iso\n\n" +
		"dir: certistack-scratch\n\tpath /var/lib/vz/certistack-scratch\n\tcontent images\n\n" +
		"pbs: backups\n\tserver 10.42.10.5\n\tdatastore pbs-data\n\tnamespace prod\n\tfingerprint 1B:FB:2F:B9:9C:66:ED:63:D5:0D:53:DF:91:7C:AA:97:17:D5:CD:D7:24:82:18:03:CD:2E:68:C3:3F:93:1E:86\n\tencryption-key 44:a5\n"
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte("private"), 0o600)
	os.WriteFile(filepath.Join(dir, "id_ed25519.pub"), []byte("ssh-ed25519 AAAAtest\n"), 0o644)
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "192.0.2.10"},
		"", "", "yes",
		"",  // create the PVE access
		"1", // the node's PBS storage
		"",  // run over ssh
		"y", // copy the key (the default is no)
	)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Join(f.changes, "|") != "pve access|pbs access on root@10.42.10.5|read key /etc/pve/priv/storage/backups.enc" {
		t.Errorf("changes = %q: nothing is installed or added on a node that has it all", f.changes)
	}
	values, err := loadControllerEnvironment(filepath.Join(dir, "controller.env"))
	if err != nil {
		t.Fatal(err)
	}
	if values["PBS_REPOSITORY"] != "certistack-ro@pbs!ro@10.42.10.5:8007:pbs-data" || values["PBS_NAMESPACE"] != "prod" || values["PBS_FINGERPRINT"] != wizardPBSPrint ||
		values["CERTISTACK_PBS_KEYFILE"] != filepath.Join(dir, "backups.enc") || values["PVE_URL"] != "https://192.0.2.10:8006" {
		t.Errorf("values = %v", values)
	}
	if info, _ := os.Stat(filepath.Join(dir, "backups.enc")); info == nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v", info)
	}
	if !strings.Contains(out, "Using the existing storage certistack-scratch") {
		t.Errorf("the existing storage is not reused:\n%s", out)
	}
}

// Run again on a node set up already: nothing is created twice, the secrets
// the file holds are kept, and the old file is kept as a copy.
func TestTheWizardRunAgainReusesWhatExists(t *testing.T) {
	f, dir := newWizardWorld(t)
	answers := []string{"", "", "yes", "", "", "", "", "", "", "pbs.example.com", "datastore1", "", "y", ""}
	if out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, answers...); err != nil {
		t.Fatalf("first run: %v\n%s", err, out)
	}
	// Lines the operator added by hand after the first run.
	envPath := filepath.Join(dir, "controller.env")
	first, _ := loadControllerEnvironment(envPath)
	file, err := os.OpenFile(envPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(file, "CERTISTACK_STATE_DIR=/srv/certistack-state\nCERTISTACK_SSH_SUDO=true\nPBS_ENCRYPTION_PASSWORD=hand-added-passphrase\n")
	file.Close()
	f.changes = nil
	f.tools = []string{"guestfish", "nft"}
	f.storageCfg = "dir: certistack-scratch\n\tpath /var/lib/vz/certistack-scratch\n\tcontent images\n"
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"},
		"", "",
		"",         // keep the PVE secret the file holds
		"",         // update the PVE access
		"", "", "", // the PBS host, datastore and namespace the file names
		"y", // the root namespace: every namespace of the datastore
		"",  // keep the PBS secret the file holds
	)
	if err != nil {
		t.Fatalf("second run: %v\n%s", err, out)
	}
	if strings.Join(f.changes, "|") != "pve access" {
		t.Errorf("changes = %q: only the PVE grants are set again", f.changes)
	}
	if !strings.Contains(out, "already holds exactly this key") {
		t.Errorf("the host key is asked again:\n%s", out)
	}
	values, err := loadControllerEnvironment(envPath)
	if err != nil {
		t.Fatalf("the rewritten file does not load: %v", err)
	}
	if values["PVE_TOKEN_SECRET"] != wizardPVESecret || values["PBS_PASSWORD"] != wizardPBSSecret {
		t.Errorf("the secrets were not kept: %v", values)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "controller.env.bak-*"))
	if len(matches) != 1 {
		t.Errorf("backups = %v", matches)
	}
	// The hand-added lines are carried over, except sudo (setup connects as
	// root); the report directory of the first run stays; no value is shown.
	if values["CERTISTACK_STATE_DIR"] != "/srv/certistack-state" || values["PBS_ENCRYPTION_PASSWORD"] != "hand-added-passphrase" ||
		values["CERTISTACK_SSH_SUDO"] != "" || values["CERTISTACK_OUTPUT_DIR"] == "" || values["CERTISTACK_OUTPUT_DIR"] != first["CERTISTACK_OUTPUT_DIR"] {
		t.Errorf("carried over: %v", values)
	}
	if !strings.Contains(out, "Not carried over from the earlier file: CERTISTACK_SSH_SUDO (setup connects as root).") ||
		!strings.Contains(out, "Carried over from the earlier file: CERTISTACK_OUTPUT_DIR, CERTISTACK_STATE_DIR, PBS_ENCRYPTION_PASSWORD.") ||
		strings.Contains(out, "hand-added-passphrase") {
		t.Errorf("what setup said about the earlier file's lines:\n%s", out)
	}
}

// A rerun that names the same PBS and datastore by flag keeps the earlier
// file's namespace: the unattended rerun the commands page shows must not move
// the controller to the root namespace, or grant the PBS user the whole
// datastore. Only --pbs-namespace / does that.
func TestTheWizardRunAgainKeepsTheNamespace(t *testing.T) {
	f, dir := newWizardWorld(t)
	answers := []string{"", "", "yes", "", "", "", "", "", "", "pbs.example.com", "datastore1", "prod", ""}
	if out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, answers...); err != nil {
		t.Fatalf("first run: %v\n%s", err, out)
	}
	envPath := filepath.Join(dir, "controller.env")
	if values, _ := loadControllerEnvironment(envPath); values["PBS_NAMESPACE"] != "prod" {
		t.Fatalf("first run: PBS_NAMESPACE = %q", values["PBS_NAMESPACE"])
	}
	f.tools = []string{"guestfish", "nft"}
	f.storageCfg = "dir: certistack-scratch\n\tpath /var/lib/vz/certistack-scratch\n\tcontent images\n"
	unattended := setupWizardOptions{NodeHost: "pve1.example.com", Yes: true, Fingerprint: fixedHostKey(t, 7).Fingerprint,
		PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}
	if out, err := runWizard(t, f, dir, unattended); err != nil {
		t.Fatalf("unattended rerun: %v\n%s", err, out)
	}
	if values, _ := loadControllerEnvironment(envPath); values["PBS_NAMESPACE"] != "prod" {
		t.Errorf("unattended rerun with the same PBS: PBS_NAMESPACE = %q, want the earlier prod", values["PBS_NAMESPACE"])
	}
	unattended.PBSNamespace = "/"
	// The fake clock does not move, and the earlier copy would take the name.
	backups, _ := filepath.Glob(filepath.Join(dir, "controller.env.bak-*"))
	for _, b := range backups {
		os.Remove(b)
	}
	if out, err := runWizard(t, f, dir, unattended); err != nil {
		t.Fatalf("rerun with --pbs-namespace /: %v\n%s", err, out)
	}
	if values, _ := loadControllerEnvironment(envPath); values["PBS_NAMESPACE"] != "" {
		t.Errorf("--pbs-namespace /: PBS_NAMESPACE = %q, want the root namespace", values["PBS_NAMESPACE"])
	}
}

// --pbs-fingerprint gives the fingerprint setup cannot read (here the PBS part
// is pasted by hand), and one that differs from what the PBS reports is refused.
func TestTheWizardTakesThePBSFingerprintFlag(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.pbsFails = true, true
	f.tools = []string{"guestfish", "nft"}
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", PBSFingerprint: strings.ToUpper(wizardPBSPrint)},
		"", "", "yes", "", "", "", "pbs.example.com", "datastore1", "", "y", "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env"))
	if values["PBS_FINGERPRINT"] != wizardPBSPrint || strings.Contains(out, "SHA-256 fingerprint (PBS dashboard") {
		t.Errorf("PBS_FINGERPRINT = %q, or it was asked although the flag gave it:\n%s", values["PBS_FINGERPRINT"], out)
	}

	f, dir = newWizardWorld(t)
	f.authorized = true
	f.tools = []string{"guestfish", "nft"}
	other := "00" + wizardPBSPrint[2:]
	out, err = runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", PBSFingerprint: other},
		"", "", "yes", "", "", "", "pbs.example.com", "datastore1", "", "y", "")
	if err == nil || !strings.Contains(err.Error(), "is not the fingerprint the PBS storage or the PBS reports") {
		t.Fatalf("a --pbs-fingerprint the PBS contradicts: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "controller.env")); err == nil {
		t.Error("an environment file was written with a fingerprint the PBS contradicts")
	}
}

// A token that exists with no secret on file is replaced only after a yes.
func TestTheWizardReplacesAnExistingTokenOnlyAfterAYes(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.pveToken = true, true
	f.tools = []string{"guestfish", "nft"}
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes", "", "", "n")
	if err == nil || !strings.Contains(err.Error(), "secret is needed") {
		t.Fatalf("declined replacement: %v\n%s", err, out)
	}
	for _, c := range f.changes {
		if c == "pve token remove" || c == "pve access" {
			t.Fatalf("changes = %q after a no", f.changes)
		}
	}
	f.changes = nil
	out, err = runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", PBSHost: "pbs.example.com", PBSDatastore: "datastore1"},
		"", "", // directory, node
		"", "", // storage directory, add it
		"y",        // replace the token
		"",         // create the access
		"", "", "", // PBS host, datastore, namespace (the flags')
		"y", // every namespace of the datastore
		"",  // over ssh
	)
	if err != nil {
		t.Fatalf("accepted replacement: %v\n%s", err, out)
	}
	joined := strings.Join(f.changes, "|")
	if !strings.Contains(joined, "pve token remove|pve access") {
		t.Errorf("changes = %q, want the old token removed right before the access is set up", f.changes)
	}
}

// A yes to replacing the token, then a no to setting up the access: the old
// token is still there, because it goes only after the second yes.
func TestTheWizardKeepsTheOldTokenAfterANoToTheAccess(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.pveToken = true, true
	f.tools = []string{"guestfish", "nft"}
	f.storageCfg = "dir: certistack-scratch\n\tpath /var/lib/vz/certistack-scratch\n\tcontent images\n"
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes", "y", "n")
	if err == nil || !strings.Contains(err.Error(), "a run needs the PVE token") {
		t.Fatalf("%v\n%s", err, out)
	}
	if !f.pveToken || strings.Join(f.changes, "|") != "keygen id_ed25519" {
		t.Errorf("token there = %v, changes = %q: the no must leave the old token (only the controller's own new key)", f.pveToken, f.changes)
	}
}

// A no to the packages stops the setup: nothing after it is done.
func TestTheWizardStopsAtANo(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized = true
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes", "", "n")
	if err == nil || !strings.Contains(err.Error(), "libguestfs-tools") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Join(f.changes, "|") != "keygen id_ed25519|apt update" {
		t.Errorf("changes after a no = %q: only the controller's own new key and the refresh of apt's lists the yes allowed", f.changes)
	}
	if _, err := os.Stat(filepath.Join(dir, "controller.env")); err == nil {
		t.Error("an environment file was written")
	}
}

// When ssh to the PBS fails, the PBS part is written to a file to paste, and
// the secret is read at the hidden prompt.
func TestTheWizardFallsBackToPastingThePBSPart(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.pbsFails = true, true
	f.tools = []string{"guestfish", "nft"}
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"},
		"", "", "yes", "", "", "", "pbs.example.com", "datastore1", "", "y", "", wizardPBSPrint)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	part, err := os.ReadFile(filepath.Join(dir, "pbs-access.sh"))
	if err != nil || !strings.Contains(string(part), "PART 2") || strings.Contains(string(part), ">&3") {
		t.Errorf("pbs-access.sh = %v, %q", err, part)
	}
	values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env"))
	if values["PBS_PASSWORD"] != wizardPBSSecret || values["PBS_FINGERPRINT"] != wizardPBSPrint {
		t.Errorf("values = %v", values)
	}
	if strings.Contains(out, wizardPBSSecret) {
		t.Error("the pasted secret was shown")
	}
}

// On a cluster node the overlays must not go to the root disk.
func TestTheWizardKeepsAClusterNodesOverlaysOffTheRootDisk(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.cluster = true, true
	f.tools = []string{"guestfish", "nft"}
	// Asked: the answer is refused and asked again (here the input ends).
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes", "/var/lib/vz/certistack-scratch")
	if err == nil || !strings.Contains(out, "/var/lib/vz/certistack-scratch is on the root disk of a cluster node (/dev/sda2)") {
		t.Fatalf("root disk on a cluster: %v\n%s", err, out)
	}
	// Any directory on the root disk, not only /var/lib/vz, given as a flag:
	// an error, before any change.
	f.changes = nil
	if _, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", OverlayPath: "/root/scratch"}, "", "", ""); err == nil || !strings.Contains(err.Error(), "/root/scratch is on the root disk of a cluster node") {
		t.Fatalf("/root on a cluster: %v", err)
	}
	if len(f.changes) != 0 {
		t.Fatalf("changes = %q before the refusal", f.changes)
	}
	f.changes = nil
	out, err = runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", PBSHost: "pbs.example.com", PBSDatastore: "datastore1"},
		"", "", // directory, node
		"/mnt/scratch/certistack-scratch", "", // storage directory, add it
		"",         // create the PVE access
		"", "", "", // PBS host, datastore, namespace
		"y", // every namespace of the datastore
		"",  // over ssh
	)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if f.changes[0] != "storage: pvesm add dir certistack-scratch --path /mnt/scratch/certistack-scratch --content images --shared 0 --nodes pve1" {
		t.Errorf("storage = %q", f.changes[0])
	}
}

// Unattended: --yes needs the fingerprint, and a terminal is needed without it.
func TestTheWizardUnattended(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized = true
	if _, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", Yes: true}); err == nil || !strings.Contains(err.Error(), "--fingerprint") {
		t.Errorf("--yes without --fingerprint: %v", err)
	}
	deps := f.deps(t, dir)
	deps.isTerminal = func() bool { return false }
	if err := runSetupWizard(context.Background(), io.Discard, strings.NewReader(""), setupWizardOptions{Dir: dir, NodeHost: "pve1.example.com"}, deps); err == nil || !strings.Contains(err.Error(), "needs a terminal") {
		t.Errorf("no terminal: %v", err)
	}
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", Yes: true, Fingerprint: fixedHostKey(t, 7).Fingerprint,
		PBSHost: "pbs.example.com", PBSDatastore: "datastore1", PBSNamespace: "/", PBSSSH: "root@pbs-admin.example.com"})
	if err != nil {
		t.Fatalf("unattended: %v\n%s", err, out)
	}
	if !strings.Contains(strings.Join(f.changes, "|"), "pbs access on root@pbs-admin.example.com") {
		t.Errorf("changes = %q", f.changes)
	}
}

func TestPVEURLHostIsANameTheCertificateHas(t *testing.T) {
	names := []string{"127.0.0.1", "::1", "localhost", "192.0.2.10", "pve1", "pve1.example.com"}
	for _, c := range []struct{ ssh, node, want string }{
		{"pve1.example.com", "pve1", "pve1.example.com"},
		{"PVE1.example.com", "pve1", "PVE1.example.com"},
		{"jump-alias", "pve1", "pve1"},
		{"jump-alias", "other", "127.0.0.1"},
		{"192.0.2.10", "pve1", "192.0.2.10"},
	} {
		if got := pveURLHost(names, c.ssh, c.node); got != c.want {
			t.Errorf("pveURLHost(%q, %q) = %q, want %q", c.ssh, c.node, got, c.want)
		}
	}
	if got := pveURLHost(nil, "x.example.com", "pve1"); got != "x.example.com" {
		t.Errorf("without names = %q", got)
	}
	if got := pveURLHost([]string{"2001:db8::1"}, "2001:db8:0::1", "n"); got != "[2001:db8:0::1]" {
		t.Errorf("IPv6 = %q", got)
	}
}

// --yes takes each question's default, and the default of replacing a token is
// no: an unattended run never destroys a token another controller may use.
func TestTheWizardUnattendedNeverReplacesAToken(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized, f.pveToken = true, true
	f.tools = []string{"guestfish", "nft"}
	f.storageCfg = "dir: certistack-scratch\n\tpath /var/lib/vz/certistack-scratch\n\tcontent images\n"
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", Yes: true, Fingerprint: fixedHostKey(t, 7).Fingerprint,
		PBSHost: "pbs.example.com", PBSDatastore: "datastore1", PBSNamespace: "/"})
	if err == nil || !strings.Contains(err.Error(), "secret is needed") {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, c := range f.changes {
		if strings.HasPrefix(c, "pve") {
			t.Fatalf("changes = %q: the existing token was touched", f.changes)
		}
	}
}

// Under --yes each question is printed with the value it takes, and ": " sets
// the two apart, as a prompt does: "Directory /secure" reads as one phrase.
func TestTheWizardUnattendedSeparatesEachQuestionFromItsValue(t *testing.T) {
	f, dir := newWizardWorld(t)
	f.authorized = true
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", Yes: true, Fingerprint: fixedHostKey(t, 7).Fingerprint,
		PBSHost: "pbs.example.com", PBSDatastore: "datastore1", PBSNamespace: "/"})
	if err != nil {
		t.Fatalf("unattended: %v\n%s", err, out)
	}
	for _, want := range []string{
		"\nDirectory: " + dir + "\n",
		"\nThe node's DNS name or IP address, as this controller reaches it over SSH: pve1.example.com\n",
		"\nDirectory for the storage certistack-scratch: /var/lib/vz/certistack-scratch\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the output has no line %q:\n%s", strings.TrimSpace(want), out)
		}
	}
}

// --yes refuses a PBS the flags leave without a datastore or a namespace before
// step 1 creates anything: on a new directory the refusal must not come only
// after setup has made the directory, known_hosts and a key that the node does
// not accept yet, and the next run has to be the one that names the flag.
func TestTheWizardUnattendedRefusesAMissingNamespaceBeforeItCreatesAnything(t *testing.T) {
	for _, c := range []struct {
		name string
		opts setupWizardOptions
		want string
	}{
		{"no namespace", setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1"}, "no PBS namespace was given"},
		{"no datastore", setupWizardOptions{PBSHost: "pbs.example.com", PBSNamespace: "prod"}, "--pbs-datastore"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, dir := newWizardWorld(t) // the node does not accept the controller's key yet
			opts := c.opts
			opts.NodeHost, opts.Yes, opts.Fingerprint = "pve1.example.com", true, fixedHostKey(t, 7).Fingerprint
			out, err := runWizard(t, f, dir, opts)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one with %q\n%s", err, c.want, out)
			}
			if len(f.changes) != 0 || f.logins != 0 {
				t.Errorf("changes = %q, sign-ins = %d before the refusal", f.changes, f.logins)
			}
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the setup directory was created before the refusal (%v):\n%s", err, out)
			}
		})
	}

	// An earlier controller.env that names the namespace for the same PBS and
	// datastore is enough: the run goes on to the node.
	f, dir := newWizardWorld(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	earlier := "PBS_REPOSITORY=certistack-ro@pbs!ro@pbs.example.com:8007:datastore1\nPBS_NAMESPACE=prod\n"
	if err := os.WriteFile(filepath.Join(dir, "controller.env"), []byte(earlier), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com", Yes: true, Fingerprint: fixedHostKey(t, 7).Fingerprint,
		PBSHost: "pbs.example.com", PBSDatastore: "datastore1"})
	if err == nil || !strings.Contains(err.Error(), "the controller's key is not authorized on the node") {
		t.Fatalf("with the earlier file's namespace: %v\n%s", err, out)
	}
}

// A setup that grants the PBS user one namespace, where an earlier setup
// granted it the whole datastore, finds that grant (the namespace grant does
// not take it back) and offers to remove it; yes is the default, and --yes
// takes it. Only setup's own grant, for the user and the token, is removed.
func TestTheWizardOffersToRemoveAnEarlierGrantOnTheWholeDatastore(t *testing.T) {
	const question = "The PBS user can still read every namespace of datastore datastore1 (granted by an earlier setup). Remove that grant? [Y/n]"
	interactive := []string{"", "", "yes", "", "pbs.example.com", "datastore1", "prod", ""}
	removal := "proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id certistack-ro@pbs --delete true >&2\n" +
		"proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id 'certistack-ro@pbs!ro' --delete true >&2\n"

	// Enter: removed, over the same ssh.
	f, dir := settledNode(t)
	f.pbsWider = "certistack-ro@pbs certistack-ro@pbs!ro"
	out, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, append(interactive, "")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Count(out, question) != 1 || !strings.Contains(out, "Removed the earlier grant on /datastore/datastore1") {
		t.Errorf("the question, or what followed the yes:\n%s", out)
	}
	if got := strings.Join(f.changes, "|"); !strings.HasSuffix(got, "|pve access|pbs access on root@pbs.example.com|pbs remove grant on root@pbs.example.com") {
		t.Errorf("changes = %q", got)
	}
	if last := f.pbsScripts[len(f.pbsScripts)-1]; last != "set -eu\n"+removal {
		t.Errorf("the removal run on the PBS:\n%s", last)
	}
	if values, _ := loadControllerEnvironment(filepath.Join(dir, "controller.env")); values["PBS_NAMESPACE"] != "prod" {
		t.Errorf("PBS_NAMESPACE = %q", values["PBS_NAMESPACE"])
	}

	// No: kept, and the commands that remove it are printed.
	f, dir = settledNode(t)
	f.pbsWider = "certistack-ro@pbs!ro"
	out, err = runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, append(interactive, "n")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "Kept the grant on /datastore/datastore1") || !strings.Contains(out, "\n  proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id 'certistack-ro@pbs!ro' --delete true\n") ||
		strings.Contains(out, "--auth-id certistack-ro@pbs --delete") {
		t.Errorf("after a no:\n%s", out)
	}
	for _, c := range f.changes {
		if strings.HasPrefix(c, "pbs remove grant") {
			t.Errorf("changes = %q after a no", f.changes)
		}
	}

	// --yes removes it.
	f, dir = settledNode(t)
	f.pbsWider = "certistack-ro@pbs certistack-ro@pbs!ro"
	out, err = runWizard(t, f, dir, unattended(t, setupWizardOptions{PBSHost: "pbs.example.com", PBSDatastore: "datastore1", PBSNamespace: "prod"}))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(strings.Join(f.changes, "|"), "pbs remove grant on root@pbs.example.com") {
		t.Errorf("--yes: changes = %q\n%s", f.changes, out)
	}

	// No namespace, or no wider grant: no question.
	f, dir = settledNode(t)
	out, err = runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, interactive...)
	if err != nil || strings.Contains(out, "Remove that grant?") {
		t.Errorf("without a wider grant: %v\n%s", err, out)
	}
}

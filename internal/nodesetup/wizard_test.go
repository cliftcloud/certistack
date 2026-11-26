// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A storage.cfg as a typical node has it: a dir storage, an lvmthin, PBS storages
// with and without a namespace, an encrypted one with a master key, and a
// fingerprint in either letter case.
const labStorageCfg = `dir: local
	path /var/lib/vz
	content iso,backup,vztmpl,import

lvmthin: local-lvm
	thinpool data
	vgname pve
	content images,rootdir

pbs: pbs-backup
	datastore pbs-data
	server 10.42.10.5
	content backup
	encryption-key 44:a5:79:dc:35:84:ed:59:79:de:2f:92:8f:50:73:92:1a:14:be:07:d0:e9:1f:66:10:6a:95:9f:fe:d2:c6:a2
	fingerprint 1b:fb:2f:b9:9c:66:ed:63:d5:0d:53:df:91:7c:aa:97:17:d5:cd:d7:24:82:18:03:cd:2e:68:c3:3f:93:1e:86
	prune-backups keep-all=1
	username pbs@pbs

pbs: certistack-lab
	datastore pbs-data
	server 10.42.10.5
	content backup
	fingerprint 1B:FB:2F:B9:9C:66:ED:63:D5:0D:53:DF:91:7C:AA:97:17:D5:CD:D7:24:82:18:03:CD:2E:68:C3:3F:93:1E:86
	namespace certistack-lab
	port 8007
	username backup@pbs!ci-token

pbs: certistack-lab-enc-mk
	datastore pbs-data
	server pbs.example.com
	content backup
	encryption-key 0e:8f:88:75:69:31:65:6e:c0:10:91:32:bb:c1:0b:cc:9b:a9:d6:d0:51:e6:8a:c3:cc:ff:67:be:c2:d8:66:7f
	master-pubkey 1
	namespace certistack-lab
	port 8017
	username backup@pbs!ci-token

dir: certistack-scratch
	path /var/lib/vz/certistack-scratch
	content images
	shared 0
	nodes pve1
`

func TestStorageConfigReadsAsPVEWritesIt(t *testing.T) {
	sections, err := ParseStorageConfig([]byte(labStorageCfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(sections) != 6 || sections[0].Type != "dir" || sections[0].ID != "local" || sections[0].Props["path"] != "/var/lib/vz" {
		t.Fatalf("sections = %+v", sections)
	}
	pbs := PBSStorages(sections)
	if len(pbs) != 3 {
		t.Fatalf("pbs = %+v", pbs)
	}
	byID := map[string]PBSStorage{}
	for _, s := range pbs {
		byID[s.ID] = s
	}
	plain := byID["certistack-lab"]
	if plain.Server != "10.42.10.5" || plain.Port != 8007 || plain.Datastore != "pbs-data" || plain.Namespace != "certistack-lab" || plain.Encrypted {
		t.Errorf("certistack-lab = %+v", plain)
	}
	if got := plain.Repository(PBSTokenID); got != "certistack-ro@pbs!ro@10.42.10.5:8007:pbs-data" {
		t.Errorf("repository = %q", got)
	}
	enc := byID["certistack-lab-enc-mk"]
	if !enc.Encrypted || !enc.MasterKey || enc.Port != 8017 || enc.EncryptionKeyPath() != "/etc/pve/priv/storage/certistack-lab-enc-mk.enc" {
		t.Errorf("certistack-lab-enc-mk = %+v", enc)
	}
	if byID["pbs-backup"].Port != 8007 {
		t.Errorf("a storage without a port line gets PBS's default port: %+v", byID["pbs-backup"])
	}
	for _, s := range pbs {
		if s.Fingerprint == "" {
			continue
		}
		if f, err := NormalizeFingerprint(s.Fingerprint); err != nil || f != "1b:fb:2f:b9:9c:66:ed:63:d5:0d:53:df:91:7c:aa:97:17:d5:cd:d7:24:82:18:03:cd:2e:68:c3:3f:93:1e:86" {
			t.Errorf("%s fingerprint = %q, %v", s.ID, f, err)
		}
	}
	dirs := DirStorages(sections)
	if len(dirs) != 2 || dirs[1].ID != "certistack-scratch" || !dirs[1].HasContent("images") || dirs[1].Shared || len(dirs[1].Nodes) != 1 || dirs[0].HasContent("images") {
		t.Errorf("dirs = %+v", dirs)
	}
	if !StorageIDTaken(sections, "local-lvm") || StorageIDTaken(sections, "nope") {
		t.Error("StorageIDTaken")
	}
}

func TestStorageConfigThatDoesNotReadAsPVEWritesItIsRefused(t *testing.T) {
	for _, bad := range []string{
		"\tpath /x\n",            // a property before any storage
		"dir local\n\tpath /x\n", // a header without its colon
		"dir: two words\n",       // an ID with a space
	} {
		if _, err := ParseStorageConfig([]byte(bad)); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if s, err := ParseStorageConfig([]byte("# comment\n\n")); err != nil || len(s) != 0 {
		t.Errorf("comments and blank lines: %v %v", s, err)
	}
	if _, err := NormalizeFingerprint("ab:cd"); err == nil {
		t.Error("a short fingerprint was accepted")
	}
}

func factsOutput(storage string, extra ...string) []byte {
	lines := []string{
		"pve_local=nodes/pve1",
		"pve_version=pve-manager/9.2.2/b9984c6d90a4bd80 (running kernel: 7.0.2-6-pve)",
		"cluster=0", "kvm=1", "arch=x86_64",
		"tool=qemu-img", "tool=proxmox-backup-client", "tool=ip", "tool=apt-get", "tool=pvesm", "tool=pveum",
		"root_source=/dev/mapper/pve-root", "vz_source=/dev/mapper/pve-root", "vz_avail=73365700608",
		"storage_cfg=" + base64.StdEncoding.EncodeToString([]byte(storage)),
		"cert_names=IPAddress:127.0.0.1,IPAddress:0:0:0:0:0:0:0:1,DNS:localhost,IPAddress:10.42.71.172,DNS:pve1,DNS:PVE1.example.com",
	}
	lines = append(lines, extra...)
	lines = append(lines, "facts_end=1")
	return []byte(strings.Join(lines, "\n") + "\n")
}

func TestNodeFactsAreReadFromTheScriptsLines(t *testing.T) {
	facts, err := ParseNodeFacts(factsOutput(labStorageCfg))
	if err != nil {
		t.Fatal(err)
	}
	if facts.Name != "pve1" || facts.Cluster || !facts.KVM || facts.Arch != "x86_64" || !facts.VZOnRootDisk() || facts.VZAvail != 73365700608 {
		t.Errorf("facts = %+v", facts)
	}
	if got := strings.Join(facts.MissingPackages(), ","); got != "libguestfs-tools,nftables" {
		t.Errorf("missing packages = %q", got)
	}
	if len(facts.MissingTools()) != 0 || len(facts.Storage) != 6 {
		t.Errorf("tools %v, storage %d", facts.MissingTools(), len(facts.Storage))
	}
	if got := strings.Join(facts.CertNames, ","); got != "127.0.0.1,::1,localhost,10.42.71.172,pve1,pve1.example.com" {
		t.Errorf("cert names = %q", got)
	}
	full, _ := ParseNodeFacts(factsOutput("", "tool=guestfish", "tool=nft"))
	if len(full.MissingPackages()) != 0 {
		t.Errorf("a node with guestfish and nft lacks %v", full.MissingPackages())
	}
}

// The node count of a cluster is read from corosync.conf's node entries, and
// stays 0 where it is not known.
func TestNodeFactsCountTheNodesOfACluster(t *testing.T) {
	facts, err := ParseNodeFacts(factsOutput("", "cluster=1", "cluster_nodes=5"))
	if err != nil || !facts.Cluster || facts.ClusterNodes != 5 {
		t.Errorf("facts = %+v, %v", facts, err)
	}
	for _, bad := range []string{"cluster_nodes=", "cluster_nodes=x", "cluster_nodes=0", "cluster_nodes=-3"} {
		facts, err := ParseNodeFacts(factsOutput("", "cluster=1", bad))
		if err != nil || facts.ClusterNodes != 0 {
			t.Errorf("%s: facts = %+v, %v", bad, facts, err)
		}
	}
	if facts, _ := ParseNodeFacts(factsOutput("")); facts.ClusterNodes != 0 {
		t.Errorf("a standalone node has %d cluster nodes", facts.ClusterNodes)
	}

	// The script's count, run on a corosync.conf as PVE writes it.
	conf := filepath.Join(t.TempDir(), "corosync.conf")
	text := "logging {\n  debug: off\n}\n\nnodelist {\n  node {\n    name: pve1\n    nodeid: 1\n    ring0_addr: 10.0.0.1\n  }\n  node {\n    name: pve2\n    nodeid: 2\n    ring0_addr: 10.0.0.2\n  }\n  node {\n    name: pve3\n    nodeid: 3\n    ring0_addr: 10.0.0.3\n  }\n}\n\ntotem {\n  cluster_name: lab\n  version: 2\n}\n"
	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(NodeFactsScript, "\n") {
		if strings.HasPrefix(l, "if [ -e /etc/pve/corosync.conf ]") {
			line = strings.ReplaceAll(l, "/etc/pve/corosync.conf", conf)
		}
	}
	if line == "" {
		t.Fatal("the facts script has no cluster line")
	}
	out, err := exec.Command("/bin/sh", "-c", line).Output()
	if err != nil || string(out) != "cluster=1\ncluster_nodes=3\n" {
		t.Errorf("the script says %q, %v", out, err)
	}
}

func TestNodeFactsThatAreIncompleteAreRefused(t *testing.T) {
	cut := factsOutput(labStorageCfg)
	cut = cut[:len(cut)-len("facts_end=1\n")]
	if _, err := ParseNodeFacts(cut); err == nil {
		t.Error("output without its end line was accepted")
	}
	noNode := strings.Replace(string(factsOutput("")), "pve_local=nodes/pve1", "pve_local=", 1)
	if _, err := ParseNodeFacts([]byte(noNode)); err == nil || !strings.Contains(err.Error(), "not a Proxmox VE node") {
		t.Errorf("a host without /etc/pve/local: %v", err)
	}
	badStorage := strings.Replace(string(factsOutput("")), "storage_cfg=", "storage_cfg=!!", 1)
	if _, err := ParseNodeFacts([]byte(badStorage)); err == nil {
		t.Error("an undecodable storage.cfg was accepted")
	}
}

func TestTheTokenSecretIsReadFromTheCreatingCommandsJSON(t *testing.T) {
	const secret = "3f0c8a5e-6b1d-4e2a-9c47-0d5e1b7a92f4"
	for name, out := range map[string]string{
		"pveum":     `{"full-tokenid":"certistack-svc@pve!automation","info":{"privsep":"1"},"value":"` + secret + `"}` + "\n",
		"bare JSON": "{\n  \"tokenid\": \"certistack-ro@pbs!ro\",\n  \"value\": \"" + secret + "\"\n}\n",
		// What proxmox-backup-manager user generate-token prints on PBS 4.2.0:
		// "Result: " and the object; it has no --output-format.
		"proxmox-backup-manager": "Result: {\n  \"tokenid\": \"certistack-ro@pbs!ro\",\n  \"value\": \"" + secret + "\"\n}\n",
	} {
		got, err := ParseTokenSecret([]byte(out))
		if err != nil || got != secret {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	if _, err := ParseTokenSecret([]byte("  \n")); !errors.Is(err, ErrTokenExists) {
		t.Errorf("no output = %v, want ErrTokenExists", err)
	}
	for name, out := range map[string]string{
		"not JSON":      "Result: value " + secret,
		"no value":      `{"tokenid":"x"}`,
		"a quote in it": `{"value":"'` + secret + `"}`,
		"a newline":     `{"value":"abc\ndefghij"}`,
	} {
		_, err := ParseTokenSecret([]byte(out))
		if err == nil {
			t.Errorf("%s was accepted", name)
		} else if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "defghij") {
			t.Errorf("%s: the error shows the secret: %v", name, err)
		}
	}
}

// The capture-mode part, run by a real shell against fake pveum and
// proxmox-backup-manager: its standard output is the token's JSON and nothing
// else, and nothing it shows the operator holds the secret.
func TestACaptureModePartPrintsOnlyTheTokenOnStandardOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the parts are POSIX shell")
	}
	const secret = "7d3c9e1a-0b2f-4c58-a6e4-93f1d2b0c7aa"
	bin := t.TempDir()
	fake := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fake("pveum", `case "$1 $2 $3" in
"user token list") echo '[]';;
"user token add") echo '{"full-tokenid":"certistack-svc@pve!automation","info":{"privsep":"1"},"value":"`+secret+`"}';;
"user token permissions") echo 'Permissions of the token on /vms: VM.Audit (*)';;
"role list --output-format"|"user list --output-format") echo '[]';;
*) echo "pveum $*: done";;
esac
`)
	fake("proxmox-backup-manager", `case "$1 $2" in
"user list"|"user list-tokens") echo '[]';;
"user generate-token")
  # As PBS 4.2.0 does: generate-token takes no --output-format.
  case "$*" in *--output-format*) echo "Error: parameter verification failed - 'output-format': schema does not allow additional properties." >&2; exit 255;; esac
  printf 'Result: {\n  "tokenid": "certistack-ro@pbs!ro",\n  "value": "%s"\n}\n' "`+secret+`";;
*) echo "proxmox-backup-manager $*: done";;
esac
`)
	for _, part := range []string{PartPVE, PartPBS} {
		script, err := RBACScript(RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch", PBSDatastore: "datastore1", Part: part, Capture: true})
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		stdout, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v\n%s", part, err, stderr.String())
		}
		got, err := ParseTokenSecret(stdout)
		if err != nil || got != secret {
			t.Fatalf("%s: stdout %q gave %q, %v", part, stdout, got, err)
		}
		if strings.Contains(stderr.String(), secret) {
			t.Errorf("%s: the secret reached standard error, which the operator sees:\n%s", part, stderr.String())
		}
		if !strings.Contains(stderr.String(), "certistack setup reads its secret") {
			t.Errorf("%s: standard error does not say what happens to the secret:\n%s", part, stderr.String())
		}
	}
	if _, err := RBACScript(RBACParams{Node: "pve1", OverlayStorage: "s1", PBSDatastore: "ds1", Capture: true}); err == nil {
		t.Error("a capture script with both parts was accepted")
	}
	plain, _ := RBACScript(RBACParams{Node: "pve1", OverlayStorage: "s1", Part: PartPVE})
	if strings.Contains(plain, ">&3") || strings.Contains(plain, "--output-format json >&3") {
		t.Error("the printed (manual) script captures the secret")
	}
}

func TestThePackageAndStorageScripts(t *testing.T) {
	preview, err := PackagesPreviewScript([]string{"libguestfs-tools", "nftables"})
	if err != nil || !strings.Contains(preview, "apt-get -s -y --no-upgrade install libguestfs-tools nftables") {
		t.Fatalf("preview = %q, %v", preview, err)
	}
	got, err := ParsePackagesPreview([]byte("inst=libguestfs-tools\ninst=supermin\nupg=libc6\npreview_end=1\n"))
	if err != nil || strings.Join(got.Install, ",") != "libguestfs-tools,supermin" || strings.Join(got.Upgrade, ",") != "libc6" || got.Error != "" {
		t.Errorf("preview = %+v, %v", got, err)
	}
	got, err = ParsePackagesPreview([]byte("inst=libguestfs-tools\nrem=proxmox-ve\nrem=pve-manager\npreview_end=1\n"))
	if err != nil || strings.Join(got.Remove, ",") != "proxmox-ve,pve-manager" || got.Error != "" {
		t.Errorf("preview with removals = %+v, %v", got, err)
	}
	if _, err := ParsePackagesPreview([]byte("inst=x\n")); err == nil {
		t.Error("a preview without its end was accepted")
	}
	if got, _ := ParsePackagesPreview([]byte("preview_end=1\n")); got.Error == "" {
		t.Error("a preview that would install nothing was taken for one that can")
	}
	if _, err := PackagesInstallScript([]string{"x; rm -rf /"}); err == nil {
		t.Error("a package name with shell syntax was accepted")
	}
	// The install does what the preview showed: it does not refresh the lists
	// the preview was made from.
	if install, err := PackagesInstallScript([]string{"nftables"}); err != nil || strings.Contains(install, "apt-get update") || !strings.Contains(install, "apt-get -y --no-upgrade install nftables") {
		t.Errorf("install = %q, %v", install, err)
	}
	s, err := StorageScript("certistack-scratch", "/var/lib/vz/certistack-scratch", "pve1", false)
	if err != nil || !strings.Contains(s, "pvesm add dir certistack-scratch --path /var/lib/vz/certistack-scratch --content images --shared 0\n") {
		t.Errorf("standalone = %q, %v", s, err)
	}
	s, err = StorageScript("certistack-scratch", "/mnt/scratch/c", "pve1", true)
	if err != nil || !strings.HasSuffix(s, "--shared 0 --nodes pve1\n") {
		t.Errorf("cluster = %q, %v", s, err)
	}
	for _, path := range []string{"relative", "/", "/a/../b", "/a b", "/a;b"} {
		if _, err := StorageScript("s1", path, "pve1", false); err == nil {
			t.Errorf("path %q was accepted", path)
		}
	}
	if _, err := StorageScript("s1", "/x", "pve1;reboot", true); err == nil {
		t.Error("a node name with shell syntax was accepted")
	}
}

func TestTheEnvironmentFileIsWrittenPrivatelyAndAnOldOneIsKept(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "controller.env")
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	env := EnvFile{
		PVEURL: "https://pve1.example.com:8006", PVETokenID: PVETokenID, PVETokenSecret: "s-pve-0000",
		PBSRepository: "certistack-ro@pbs!ro@pbs.example.com:8007:datastore1", PBSPassword: "s-pbs-0000",
		PBSFingerprint: strings.Repeat("ab:", 31) + "ab", Node: "pve1", SSHHost: "pve1.example.com", SSHPort: 22, SSHUser: "root",
		SSHIdentity: filepath.Join(dir, "id_ed25519"), SSHKnownHosts: filepath.Join(dir, "known_hosts"), PVECASource: filepath.Join(dir, "pve-root-ca.pem"),
	}
	data, err := env.Render(now)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"PVE_TOKEN_SECRET=s-pve-0000\n", "PBS_PASSWORD=s-pbs-0000\n", "CERTISTACK_NODE=pve1\n", "CERTISTACK_PVE_CA_SOURCE=" + env.PVECASource + "\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("file lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "CERTISTACK_SSH_PORT") || strings.Contains(text, "PBS_NAMESPACE") || strings.Contains(text, "CERTISTACK_OUTPUT_DIR") {
		t.Errorf("unset or default values are written:\n%s", text)
	}
	if backup, err := WriteEnvFile(path, data, now); err != nil || backup != "" {
		t.Fatalf("first write: %q, %v", backup, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %04o", info.Mode().Perm())
	}
	backup, err := WriteEnvFile(path, []byte("NEW=1\n"), now)
	if err != nil || backup != path+".bak-20261106T120000Z" {
		t.Fatalf("second write: %q, %v", backup, err)
	}
	if old, _ := os.ReadFile(backup); string(old) != text {
		t.Error("the backup is not the previous file")
	}
	if info, _ := os.Stat(backup); info.Mode().Perm() != 0o600 {
		t.Errorf("backup mode = %04o", info.Mode().Perm())
	}
	if _, err := (EnvFile{PVETokenSecret: "x\ny"}).Render(now); err == nil {
		t.Error("a value with a newline was rendered")
	}
	// Carried-over lines come last, under one comment; one that setup writes
	// itself, or that cannot be written literally, is refused.
	kept := env
	kept.OverlayStorage = "certistack-scratch"
	kept.Kept = []EnvVar{{"CERTISTACK_STATE_DIR", "/srv/state"}, {"CERTISTACK_SSH_SUDO", ""}, {"PBS_ENCRYPTION_PASSWORD", "p"}}
	keptData, err := kept.Render(now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(keptData), "CERTISTACK_OVERLAY_STORAGE=certistack-scratch\n# Carried over from the earlier file; setup does not set these.\nCERTISTACK_STATE_DIR=/srv/state\nPBS_ENCRYPTION_PASSWORD=p\n") {
		t.Errorf("carried-over lines:\n%s", keptData)
	}
	for _, bad := range []EnvVar{{"CERTISTACK_NODE", "other"}, {"CERTISTACK_STATE_DIR", "'quoted'"}} {
		dup := env
		dup.Kept = []EnvVar{bad}
		if _, err := dup.Render(now); err == nil {
			t.Errorf("carried over %v", bad)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link.env")); err == nil {
		if _, err := WriteEnvFile(filepath.Join(dir, "link.env"), data, now); err == nil {
			t.Error("a symbolic link was written through")
		}
	}
	if err := WriteSecretFile(filepath.Join(dir, "key.enc"), []byte("k")); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(filepath.Join(dir, "key.enc")); info.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %04o", info.Mode().Perm())
	}
}

// The preview and the path probe run in a real /bin/sh against fake apt-get,
// findmnt and df: what they print for a stock node, a node whose package
// lists do not know the packages, and a directory that does not exist yet.
func TestThePreviewAndProbeScriptsInAShell(t *testing.T) {
	bin := t.TempDir()
	fake := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := func(script string) string {
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("script failed: %v\n%s", err, script)
		}
		return string(out)
	}
	preview, _ := PackagesPreviewScript([]string{"libguestfs-tools", "nftables"})
	fake("apt-get", `echo "NOTE: This is only a simulation!"
echo "Inst libc6 [2.36-9] (2.36-9+deb12u10 Debian:12.11/stable [amd64])"
echo "Inst supermin (5.2.2-4 Debian:12.11/stable [amd64])"
echo "Inst libguestfs-tools (1:1.48.6-2 Debian:12.11/stable [amd64])"
echo "Conf supermin (5.2.2-4 Debian:12.11/stable [amd64])"
`)
	got, err := ParsePackagesPreview([]byte(run(preview)))
	if err != nil || strings.Join(got.Install, ",") != "supermin,libguestfs-tools" || strings.Join(got.Upgrade, ",") != "libc6" || got.Error != "" {
		t.Errorf("stock node: %+v, %v", got, err)
	}
	// An install that would remove a package says which: apt-get -s prints a
	// "Remv" line for each.
	fake("apt-get", `echo "Inst libguestfs-tools (1:1.48.6-2 Debian:12.11/stable [amd64])"
echo "Remv proxmox-ve [8.4.0]"
echo "Remv pve-manager [8.4.1] [pve-enterprise:amd64]"
`)
	removing := run(preview)
	if !strings.Contains(removing, "rem=proxmox-ve\n") || !strings.Contains(removing, "rem=pve-manager\n") {
		t.Errorf("the preview of an install that removes packages does not name them:\n%s", removing)
	}
	fake("apt-get", `echo "Reading package lists..."
echo "E: Unable to locate package libguestfs-tools"
exit 100
`)
	got, err = ParsePackagesPreview([]byte(run(preview)))
	if err != nil || got.Error != "E: Unable to locate package libguestfs-tools" {
		t.Errorf("unknown package: %+v, %v", got, err)
	}

	fake("findmnt", `case "$5" in /mnt/scratch) echo /dev/sdb1 ;; *) echo rpool/ROOT/pve-1 ;; esac
`)
	fake("df", `echo "    Avail"; echo " 53687091200"
`)
	probe, err := PathProbeScript("/mnt/scratch/certistack-scratch/deeper")
	if err != nil {
		t.Fatal(err)
	}
	// /mnt/scratch does not exist here either: the probe walks up to /mnt or /.
	source, avail, err := ParsePathProbe([]byte(run(probe)))
	if err != nil || source == "" || avail != 53687091200 {
		t.Errorf("probe = %q, %d, %v", source, avail, err)
	}
	if _, err := PathProbeScript("/a b"); err == nil {
		t.Error("a path with a space was probed")
	}
}

func TestSameDiskKnowsZFSAndBtrfs(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"/dev/mapper/pve-root", "/dev/mapper/pve-root", true},
		{"rpool/ROOT/pve-1", "rpool/var-lib-vz", true},
		{"rpool/ROOT/pve-1", "tank/scratch", false},
		{"/dev/sda2[/@]", "/dev/sda2[/@var]", true},
		{"/dev/sda2", "/dev/sdb1", false},
		{"", "", false},
	} {
		if got := SameDisk(c.a, c.b); got != c.same {
			t.Errorf("SameDisk(%q, %q) = %v", c.a, c.b, got)
		}
	}
	sections, _ := ParseStorageConfig([]byte("dir: s1\n\tpath /x\n\tcontent images\n\tnodes pve2,pve3\n\tdisable\n\ndir: s2\n\tpath /y\n\tcontent images\n"))
	dirs := DirStorages(sections)
	if !dirs[0].Disabled || dirs[0].OnNode("pve1") || !dirs[0].OnNode("pve3") || dirs[1].Disabled || !dirs[1].OnNode("pve1") {
		t.Errorf("dir storages = %+v", dirs)
	}
	for _, bad := range []string{"ab", "-x", ".x", "a b", "x/y"} {
		if CheckDatastore(bad) == nil {
			t.Errorf("datastore %q accepted", bad)
		}
	}
	// PBS allows a leading underscore, as the shape check of PBS_REPOSITORY does.
	if CheckDatastore("_backup") != nil || CheckDatastore("data.store-1_") != nil {
		t.Error("a datastore name PBS allows was refused")
	}
	if CheckDatastore("datastore1") != nil || CheckNamespace("") != nil || CheckNamespace("prod/web") != nil || CheckNamespace("a b") == nil {
		t.Error("the datastore or namespace checks are wrong")
	}
}

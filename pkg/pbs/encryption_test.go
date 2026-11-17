// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const encryptedFiles = `[
  {"filename":"index.json.blob","crypt-mode":"sign-only","size":652},
  {"filename":"qemu-server.conf.blob","crypt-mode":"encrypt","size":480},
  {"filename":"drive-scsi0.img.fidx","crypt-mode":"encrypt","size":34359738368}
]`

func TestParseSnapshotCryptMode(t *testing.T) {
	for want, files := range map[string]string{
		CryptModeEncrypt:  encryptedFiles,
		CryptModeSignOnly: `[{"filename":"drive-scsi0.img.fidx","crypt-mode":"sign-only"},{"filename":"qemu-server.conf.blob","crypt-mode":"none"}]`,
		CryptModeNone:     `[{"filename":"drive-scsi0.img.fidx","crypt-mode":"none"},{"filename":"index.json.blob"}]`,
	} {
		if got, err := ParseSnapshotCryptMode([]byte(files)); err != nil || got != want {
			t.Errorf("crypt mode = %q, %v; want %q", got, err, want)
		}
	}
	if _, err := ParseSnapshotCryptMode([]byte("not json")); err == nil {
		t.Error("malformed listing accepted")
	}
}

func TestDiskCryptModeIsTheWeakestDisk(t *testing.T) {
	for want, files := range map[string]string{
		CryptModeEncrypt:  encryptedFiles,
		CryptModeNone:     `[{"filename":"drive-scsi0.img.fidx","crypt-mode":"encrypt"},{"filename":"drive-scsi1.img.fidx","crypt-mode":"none"},{"filename":"qemu-server.conf.blob","crypt-mode":"encrypt"}]`,
		CryptModeSignOnly: `[{"filename":"drive-scsi0.img.fidx","crypt-mode":"sign-only"},{"filename":"index.json.blob","crypt-mode":"encrypt"}]`,
	} {
		if got, err := ParseSnapshotDiskCryptMode([]byte(files)); err != nil || got != want {
			t.Errorf("disk crypt mode = %q, %v; want %q for %s", got, err, want, files)
		}
	}
}

func TestLayoutEvidence(t *testing.T) {
	fakeBackupClient(t, encryptedFiles, "scsi0: pbs:vm-7011-disk-0\nscsi1: pbs:vm-7011-disk-1,backup=0\nide2: none,media=cdrom\n")
	layout, err := (&Client{cfg: Config{Keyfile: testKey(t, "")}}).LoadVMLayout(context.Background(), "vm/7011/2026-09-27T03:00:00Z", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !layout.SignatureVerified || layout.CryptMode != CryptModeEncrypt || len(layout.ExcludedDisks) != 1 || layout.ExcludedDisks[0] != "scsi1" {
		t.Fatalf("layout evidence: verified %v, mode %q, excluded %v", layout.SignatureVerified, layout.CryptMode, layout.ExcludedDisks)
	}
}

func TestEncryptedSnapshotNeedsAKey(t *testing.T) {
	_, err := (&Client{}).checkSnapshotKey("vm/7011/2026-09-27T03:00:00Z", []byte(encryptedFiles))
	if err == nil || !strings.Contains(err.Error(), "CERTISTACK_PBS_KEYFILE") || !strings.Contains(err.Error(), "is encrypted") {
		t.Fatalf("err = %v, want an actionable key requirement", err)
	}
	mode, err := (&Client{cfg: Config{Keyfile: testKey(t, "")}}).checkSnapshotKey("vm/7011/2026-09-27T03:00:00Z", []byte(encryptedFiles))
	if err != nil || mode != CryptModeEncrypt {
		t.Fatalf("with a key: %q, %v", mode, err)
	}
}

func TestBuildEnvPassesTheKeyPassphrase(t *testing.T) {
	env := strings.Join((&Client{cfg: Config{EncryptionPassword: "key-passphrase"}}).buildEnv(), "\n")
	if !strings.Contains(env, "PBS_ENCRYPTION_PASSWORD=key-passphrase") {
		t.Fatalf("environment %q lacks the key passphrase", env)
	}
	if env := strings.Join((&Client{}).buildEnv(), "\n"); strings.Contains(env, "PBS_ENCRYPTION_PASSWORD") {
		t.Fatalf("environment %q carries an empty key passphrase", env)
	}
}

func TestValidateKeyfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("key paths and permissions are Linux node semantics")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "pbs.enc")
	if err := os.WriteFile(key, []byte(`{"kdf":"none","data":"AAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeyfile(key); err != nil {
		t.Fatalf("owner-only key: %v", err)
	}
	link := filepath.Join(dir, "link.enc")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(dir, "shared.enc")
	if err := os.WriteFile(shared, []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o644); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.enc")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"relative path":      "pbs.enc",
		"missing":            filepath.Join(dir, "missing.enc"),
		"symlink":            link,
		"readable by others": shared,
		"empty":              empty,
		"directory":          dir,
	} {
		if err := ValidateKeyfile(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// fakeBackupClient installs a proxmox-backup-client that answers
// `snapshot files` with files, restores config for qemu-server.conf.blob,
// and logs every invocation's arguments, one line each.
func fakeBackupClient(t *testing.T, files, config string) string {
	t.Helper()
	return fakeBackupClientWithList(t, files, config, "[]")
}

// testKey writes a PBS key file recording fingerprint (none when empty)
// and returns its path.
func testKey(t *testing.T, fingerprint string) string {
	t.Helper()
	key := filepath.Join(t.TempDir(), "pbs.enc")
	body := `{"kdf":null,"data":"AAAA"}`
	if fingerprint != "" {
		body = `{"kdf":null,"data":"AAAA","fingerprint":"` + fingerprint + `"}`
	}
	if err := os.WriteFile(key, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return key
}

// fakeBackupClientWithList also answers `snapshot list` with list.
func fakeBackupClientWithList(t *testing.T, files, config, list string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	if err := os.WriteFile(filepath.Join(dir, "files.json"), []byte(files), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "qemu-server.conf"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "list.json"), []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	// Behave like the real client where it matters: `snapshot files` and
	// `snapshot list` take no --keyfile (schema error), a restore of an
	// encrypted snapshot needs the key, and with a key configured an
	// unsigned snapshot's restore fails its manifest signature check.
	mode := "none"
	if strings.Contains(files, `"encrypt"`) {
		mode = "encrypt"
	} else if strings.Contains(files, `"sign-only"`) {
		mode = "sign-only"
	}
	script := "#!/bin/sh\n" +
		"echo \"$*\" >> " + log + "\n" +
		"MODE=" + mode + "\n" +
		"case \"$*\" in *--keyfile*) KEY=1 ;; *) KEY= ;; esac\n" +
		"for last; do :; done\n" +
		"case \"$1 $2\" in\n" +
		"  'snapshot files'|'snapshot list')\n" +
		"    if [ -n \"$KEY\" ]; then echo 'schema does not allow additional properties' >&2; exit 2; fi\n" +
		"    if [ \"$2\" = list ]; then cat " + filepath.Join(dir, "list.json") + "; else cat " + filepath.Join(dir, "files.json") + "; fi ;;\n" +
		"  restore*)\n" +
		"    if [ -n \"$KEY\" ] && [ \"$MODE\" = none ]; then echo 'manifest has no signature' >&2; exit 1; fi\n" +
		"    if [ -z \"$KEY\" ] && [ \"$MODE\" = encrypt ]; then echo 'missing key' >&2; exit 1; fi\n" +
		"    case \"$*\" in\n" +
		"      *qemu-server.conf.blob*) cp " + filepath.Join(dir, "qemu-server.conf") + " \"$last\" ;;\n" +
		"      *) printf 'firmware-image' > \"$last\" ;;\n" +
		"    esac ;;\n" +
		"  *) exit 1 ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return log
}

func TestLoadVMLayoutRefusesAnEncryptedSnapshotBeforeRestoring(t *testing.T) {
	log := fakeBackupClient(t, encryptedFiles, "scsi0: pbs:vm-7011-disk-0\n")
	_, err := (&Client{}).LoadVMLayout(context.Background(), "vm/7011/2026-09-27T03:00:00Z", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "is encrypted") {
		t.Fatalf("err = %v, want the key requirement", err)
	}
	calls, _ := os.ReadFile(log)
	if strings.Contains(string(calls), "restore") {
		t.Fatalf("a restore ran without the key: %s", calls)
	}
}

func TestLoadVMLayoutPassesTheKeyAndRecordsTheCryptMode(t *testing.T) {
	log := fakeBackupClient(t, encryptedFiles, "boot: order=scsi0\nscsi0: pbs:vm-7011-disk-0\n")
	client := &Client{cfg: Config{Keyfile: testKey(t, "")}}
	layout, err := client.LoadVMLayout(context.Background(), "vm/7011/2026-09-27T03:00:00Z", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if layout.CryptMode != CryptModeEncrypt || len(layout.Disks) != 1 || layout.Disks[0] != "scsi0" {
		t.Fatalf("layout = %+v", layout)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "restore --keyfile "+client.cfg.Keyfile+" vm/7011/2026-09-27T03:00:00Z qemu-server.conf.blob") {
		t.Fatalf("config restore did not pass the key: %s", calls)
	}
}

func TestTheKeyGoesOnlyToRestoresOfProtectedSnapshots(t *testing.T) {
	for mode, files := range map[string]string{
		CryptModeNone:     `[{"filename":"drive-scsi0.img.fidx","crypt-mode":"none"},{"filename":"qemu-server.conf.blob","crypt-mode":"none"}]`,
		CryptModeSignOnly: `[{"filename":"drive-scsi0.img.fidx","crypt-mode":"sign-only"},{"filename":"qemu-server.conf.blob","crypt-mode":"sign-only"}]`,
		CryptModeEncrypt:  encryptedFiles,
	} {
		t.Run(mode, func(t *testing.T) {
			log := fakeBackupClient(t, files, "scsi0: pbs:vm-7011-disk-0\n")
			// One client with a key serves every VM of a plan: encrypted and
			// unencrypted snapshots alike.
			client := &Client{cfg: Config{Keyfile: testKey(t, "")}}
			snapshot := "vm/7011/2026-09-27T03:00:00Z"
			if _, err := client.LoadVMLayout(context.Background(), snapshot, t.TempDir()); err != nil {
				t.Fatalf("layout: %v", err)
			}
			target := filepath.Join(t.TempDir(), "efi.raw")
			if err := client.RestoreImage(context.Background(), snapshot, "drive-efidisk0", target); err != nil {
				t.Fatalf("firmware restore: %v", err)
			}
			calls, _ := os.ReadFile(log)
			for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
				keyed := strings.Contains(line, "--keyfile")
				switch {
				case strings.HasPrefix(line, "snapshot") && keyed:
					t.Errorf("key passed to %q", line)
				case strings.HasPrefix(line, "restore") && keyed != (mode != CryptModeNone):
					t.Errorf("%s snapshot: key passed=%v in %q", mode, keyed, line)
				}
			}
		})
	}
}

func TestLoadVMLayoutRefusesADiskMissingFromTheSnapshot(t *testing.T) {
	fakeBackupClient(t, `[{"filename":"qemu-server.conf.blob","crypt-mode":"none"},{"filename":"drive-scsi0.img.fidx","crypt-mode":"none"}]`, "scsi0: pbs:vm-1-disk-0\nscsi1: pbs:vm-1-disk-1\n")
	_, err := (&Client{}).LoadVMLayout(context.Background(), "vm/1/2026-09-27T03:00:00Z", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "scsi1") {
		t.Fatalf("err = %v, want the missing scsi1 archive", err)
	}
}

// listWithFingerprint is `snapshot list` for vm/7011 with one encrypted
// snapshot made with key fingerprint fp.
func listWithFingerprint(fp string) string {
	return `[{"backup-type":"vm","backup-id":"7011","backup-time":1790478000,"fingerprint":"` + fp + `","files":[{"filename":"index.json.blob"}]}]`
}

func TestAWrongKeyIsRefusedBeforeAnyRestore(t *testing.T) {
	// 1790478000 is 2026-09-27T03:00:00Z.
	snapshot := "vm/7011/2026-09-27T03:00:00Z"
	const backupKey = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
	const otherKey = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"

	log := fakeBackupClientWithList(t, encryptedFiles, "scsi0: pbs:vm-7011-disk-0\n", listWithFingerprint(backupKey))
	_, err := (&Client{cfg: Config{Keyfile: testKey(t, otherKey)}}).LoadVMLayout(context.Background(), snapshot, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "is not this backup's key") || !strings.Contains(err.Error(), backupKey) || !strings.Contains(err.Error(), otherKey) {
		t.Fatalf("wrong key: err %v", err)
	}
	if calls, _ := os.ReadFile(log); strings.Contains(string(calls), "restore") {
		t.Fatalf("a restore ran with the wrong key: %s", calls)
	}

	for name, key := range map[string]string{
		"the right key (uppercase, same bytes)": strings.ToUpper(backupKey),
		"a key file without a fingerprint":      "",
	} {
		fakeBackupClientWithList(t, encryptedFiles, "scsi0: pbs:vm-7011-disk-0\n", listWithFingerprint(backupKey))
		if _, err := (&Client{cfg: Config{Keyfile: testKey(t, key)}}).LoadVMLayout(context.Background(), snapshot, t.TempDir()); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A listing without fingerprints leaves the decision to PBS.
	fakeBackupClient(t, encryptedFiles, "scsi0: pbs:vm-7011-disk-0\n")
	if _, err := (&Client{cfg: Config{Keyfile: testKey(t, otherKey)}}).LoadVMLayout(context.Background(), snapshot, t.TempDir()); err != nil {
		t.Errorf("no snapshot fingerprint: %v", err)
	}
}

func TestValidateKeyfileRefusesSomethingThatIsNotAKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("key paths and permissions are Linux node semantics")
	}
	paperkey := filepath.Join(t.TempDir(), "paperkey.txt")
	if err := os.WriteFile(paperkey, []byte("-----BEGIN PROXMOX BACKUP KEY-----\nabc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeyfile(paperkey); err == nil || !strings.Contains(err.Error(), "not a PBS key file") {
		t.Fatalf("paperkey text: err %v", err)
	}
}

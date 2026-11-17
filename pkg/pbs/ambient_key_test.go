// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeUpstreamClient installs a proxmox-backup-client that models what
// Proxmox Backup Server's crypto_parameters does with keys (client source at
// 4404a84, pbs-client/src/tools/key_source.rs), and logs each call's
// arguments and configuration environment:
//   - with --keyfile the client uses that key;
//   - with --crypt-mode=none it uses no key, whatever else exists;
//   - with neither (and `map` takes no --crypt-mode) it looks for a default
//     encryption-key.json under proxmox-backup in $XDG_CONFIG_HOME (else
//     $HOME/.config), then in $XDG_CONFIG_DIRS (else /etc/xdg), uses one it
//     finds, and then requires a signed manifest, which the plaintext
//     snapshot of these tests does not have.
func fakeUpstreamClient(t *testing.T) (calls string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	dir := t.TempDir()
	calls = filepath.Join(dir, "calls.log")
	files := `[{"filename":"index.json.blob","crypt-mode":"none"},{"filename":"qemu-server.conf.blob","crypt-mode":"none"},{"filename":"drive-scsi0.img.fidx","crypt-mode":"none"}]`
	if err := os.WriteFile(filepath.Join(dir, "files.json"), []byte(files), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
printf 'HOME=%s XDG_CONFIG_HOME=%s XDG_CONFIG_DIRS=%s ARGS=%s\n' "$HOME" "$XDG_CONFIG_HOME" "$XDG_CONFIG_DIRS" "$*" >> ` + calls + `
default_key_found() {
  home="${XDG_CONFIG_HOME:-$HOME/.config}"
  [ -f "$home/proxmox-backup/encryption-key.json" ] && return 0
  dirs="${XDG_CONFIG_DIRS:-/etc/xdg}"
  old="$IFS"; IFS=:
  for d in $dirs; do
    [ -f "$d/proxmox-backup/encryption-key.json" ] && { IFS="$old"; return 0; }
  done
  IFS="$old"
  return 1
}
unkeyed_with_default_key() {
  case "$*" in *--keyfile*|*"--crypt-mode none"*|*--crypt-mode=none*) return 1 ;; esac
  default_key_found
}
case "$1 $2" in
  'snapshot files') cat ` + filepath.Join(dir, "files.json") + ` ;;
  restore*)
    for last; do :; done
    if unkeyed_with_default_key "$@"; then echo 'manifest has no signature, but an encryption key is set' >&2; exit 41; fi
    printf 'boot: order=scsi0\nscsi0: pbs:vm-7011-disk-0\n' > "$last" ;;
  map*)
    if unkeyed_with_default_key "$@"; then echo 'manifest has no signature, but an encryption key is set' >&2; exit 41; fi
    echo 'Image "drive-scsi0" of "vm/7011/x" mapped on /dev/loop7' ;;
  *) exit 42 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return calls
}

// ambientHome is a home directory that holds a default PBS encryption key.
func ambientHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	key := filepath.Join(home, ".config", "proxmox-backup", "encryption-key.json")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(`{"kdf":null,"data":"AAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// Given neither a key nor a crypt mode, the PBS client uses its default key
// when the service account's home holds one, and then fails on a snapshot that
// is not signed. An unkeyed restore therefore asks for no encryption, and the
// client runs with no configuration to find, so a plaintext snapshot restores
// the same from any home.
func TestAnAmbientDefaultKeyDoesNotChangeAnUnkeyedRestore(t *testing.T) {
	calls := fakeUpstreamClient(t)
	const snapshot = "vm/7011/2026-09-27T03:00:00Z"
	for name, home := range map[string]string{"clean home": t.TempDir(), "home with a default key": ambientHome(t)} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			t.Setenv("XDG_CONFIG_DIRS", filepath.Join(home, ".config"))
			layout, err := (&Client{}).LoadVMLayout(context.Background(), snapshot, t.TempDir())
			if err != nil || layout.CryptMode != CryptModeNone || len(layout.Disks) != 1 {
				t.Fatalf("layout = %+v, %v", layout, err)
			}
			target := filepath.Join(t.TempDir(), "efi.raw")
			if err := (&Client{}).RestoreImage(context.Background(), snapshot, "drive-efidisk0", target); err != nil {
				t.Fatalf("firmware restore: %v", err)
			}
			if device, err := (&Client{}).Map(context.Background(), snapshot, "drive-scsi0"); err != nil || device != "/dev/loop7" {
				t.Fatalf("map = %q, %v", device, err)
			}
		})
	}
	log, _ := os.ReadFile(calls)
	for _, line := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		args := line[strings.Index(line, "ARGS=")+len("ARGS="):]
		switch {
		case strings.HasPrefix(args, "restore"):
			if !strings.Contains(args, "--crypt-mode none") || strings.Contains(args, "--keyfile") {
				t.Errorf("an unkeyed restore does not ask for no encryption: %s", line)
			}
		case strings.HasPrefix(args, "map"):
			// map has no --crypt-mode: only the isolated environment protects it.
			if strings.Contains(args, "--crypt-mode") {
				t.Errorf("map was given --crypt-mode, which its command does not accept: %s", line)
			}
		}
		for _, want := range []string{"HOME=/dev/null ", "XDG_CONFIG_HOME=/dev/null ", "XDG_CONFIG_DIRS=/dev/null "} {
			if !strings.Contains(line, want) {
				t.Errorf("call lacks %q: %s", want, line)
			}
		}
	}
}

// The client's environment points its configuration lookup at
// nothing, which keeps an ambient key away from `map` (it cannot be told a
// crypt mode), and leaves the connection settings and the runtime directory.
func TestTheClientEnvironmentHasNoConfigurationToFind(t *testing.T) {
	home := ambientHome(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CONFIG_DIRS", filepath.Join(home, ".config"))
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/0")
	env := strings.Join((&Client{cfg: Config{Repository: "user@pbs!tok@pbs.example:store", Password: "secret"}}).buildEnv(), "\n")
	for _, want := range []string{"HOME=/dev/null", "XDG_CONFIG_HOME=/dev/null", "XDG_CONFIG_DIRS=/dev/null", "XDG_RUNTIME_DIR=/run/user/0", "PBS_PASSWORD=secret"} {
		if !strings.Contains(env, want) {
			t.Errorf("environment lacks %q:\n%s", want, strings.ReplaceAll(env, "secret", "***"))
		}
	}
	if strings.Contains(env, home) {
		t.Errorf("the service account's home reaches the PBS client:\n%s", env)
	}
	// Each name is set once.
	seen := map[string]int{}
	for _, entry := range (&Client{}).buildEnv() {
		name, _, _ := strings.Cut(entry, "=")
		seen[name]++
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("%s is set %d times", name, n)
		}
	}
}

// A keyed restore still passes only the configured key, and a
// signed snapshot's restore is not given --crypt-mode none.
func TestAKeyedRestoreDoesNotAskForNoEncryption(t *testing.T) {
	log := fakeBackupClient(t, encryptedFiles, "boot: order=scsi0\nscsi0: pbs:vm-7011-disk-0\n")
	client := &Client{cfg: Config{Keyfile: testKey(t, "")}}
	if _, err := client.LoadVMLayout(context.Background(), "vm/7011/2026-09-27T03:00:00Z", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(log)
	for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
		if strings.HasPrefix(line, "restore") && (!strings.Contains(line, "--keyfile") || strings.Contains(line, "--crypt-mode")) {
			t.Errorf("keyed restore: %s", line)
		}
	}
}

// A snapshot whose file list claims a signature that its manifest
// lacks, or that the key does not verify, is what a tampered backup looks
// like. The client's refusal is named in CertiStack's words, without its
// output.
func TestATamperedManifestRefusalIsNamed(t *testing.T) {
	for output, want := range map[string]string{
		"Error: manifest has no signature, but an encryption key is set - refusing to trust a potentially tampered, unsigned backup": "carries no signature although its file list claims one",
		"Error: wrong signature in manifest":                                        "signature does not verify",
		"Error: wrong key - manifest's key aa:bb does not match provided key cc:dd": "is not the key this snapshot's manifest was made with",
		"Error: missing key - manifest was created with key aa:bb":                  "although its file list says it is not protected",
	} {
		err := commandFailure("restore PBS VM configuration", errors.New("exit status 255"), []byte(output))
		if !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "aa:bb") || strings.Contains(err.Error(), "withheld") {
			t.Errorf("%q: %v, want %q and nothing of the client's output", output, err, want)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build linux

package guestnet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Through the real runner: a fake guestfish on PATH behaves as the real one
// does on an encrypted guest. With keys on standard input (which the worker
// gives it empty) it prints its prompt and stops with "could not read key from
// user"; without the flag the real one opens /dev/tty and waits for a person,
// which the fake reports as a failure of its own.

const fakeGuestfishScript = `#!/bin/sh
dir=$(dirname "$0")
case " $* " in *" --version "*) echo "guestfish 1.54.1"; exit 0;; esac
echo "$*" >> "$dir/log"
inspect=no; keys=no; ro=no; rw=no; names=no; types=no
for arg in "$@"; do
  case "$arg" in
    -i) inspect=yes;; --keys-from-stdin) keys=yes;; --ro) ro=yes;; --rw) rw=yes;; list-devices) names=yes;; vfs-type) types=yes;;
  esac
done
if [ "$names" = yes ] || [ "$types" = yes ]; then
  if [ "$inspect" = yes ] || [ "$rw" = yes ] || [ "$ro" != yes ] || [ "$keys" != yes ]; then
    echo "FAKE: the volume probes must be read-only, read keys only from stdin and must not inspect" >&2; exit 3
  fi
  if [ "$names" = yes ]; then cut -d' ' -f1 "$dir/volumes" || exit 4; exit 0; fi
  for arg in "$@"; do
    case "$arg" in
      vol=*) want=${arg#vol=}; echo "$arg"; while read -r name type; do [ "$name" = "$want" ] && echo "$type"; done < "$dir/volumes";;
    esac
  done
  exit 0
fi
case "$(cat "$dir/guest")" in
  luks-root)
    if [ "$keys" != yes ]; then echo "FAKE: guestfish opened /dev/tty and waited for a passphrase" >&2; exit 9; fi
    printf 'Enter key or passphrase ("/dev/sda3"): '
    read -r key || { echo "guestfish: could not read key from user" >&2; exit 1; }
    ;;
  no-os)
    echo "guestfish: no operating system was found on this disk" >&2; exit 1 ;;
esac
exit 0
`

// installFakeGuestfish puts a fake guestfish first on PATH. guest is "luks-root"
// or "no-os"; volumes is one "name type" line per device, partition or logical
// volume, as list-devices : list-partitions : lvs and vfs-type would give them
// (a missing file when empty, so the probes fail). It returns the directory
// holding its log.
func installFakeGuestfish(t *testing.T, guest, volumes string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{"guestfish": fakeGuestfishScript, "guest": guest}
	if volumes != "" {
		files["volumes"] = volumes
	}
	for name, contents := range files {
		mode := os.FileMode(0o600)
		if name == "guestfish" {
			mode = 0o700
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	return dir
}

func calls(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "log"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func applyWithRealGuestfish(t *testing.T) error {
	t.Helper()
	started := time.Now()
	_, err := New(t.TempDir()).Apply(context.Background(), multiDiskConfig(bootOverlayPath))
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Errorf("the refusal took %v: guestfish waited for something", elapsed)
	}
	return err
}

func TestEncryptedRootIsRefusedAtOnceWithoutWaitingForAPassphrase(t *testing.T) {
	dir := installFakeGuestfish(t, "luks-root", "")
	err := applyWithRealGuestfish(t)
	requireEncryptedRefusal(t, err, "LUKS")
	if strings.Contains(err.Error(), "FAKE") {
		t.Fatalf("guestfish was left to prompt on the terminal: %v", err)
	}
	if !strings.Contains(err.Error(), "guestfish: could not read key from user") {
		t.Errorf("the refusal drops guestfish's own words: %v", err)
	}
	for _, call := range calls(t, dir) {
		if !strings.Contains(" "+call+" ", " --keys-from-stdin ") {
			t.Errorf("guestfish call %q can read a key from the terminal", call)
		}
		if strings.Contains(" "+call+" ", " --rw ") {
			t.Errorf("a writing call ran on an encrypted guest: %q", call)
		}
	}
	// One failing inspection is the whole refusal; a second appliance
	// boot asking whether a directory exists would only fail the same way.
	if got := calls(t, dir); len(got) != 1 {
		t.Errorf("%d guestfish calls before refusing an encrypted root, want 1: %q", len(got), got)
	}
}

// A whole disk that is one LUKS container, or a BitLocker system disk, ends in
// "no operating system was found" (checked against libguestfs 1.54.1 on a PVE 9
// node: a LUKS partition or logical volume makes guestfish -i ask for a key and
// fail with "could not read key from user" instead, handled above). Two
// read-only calls on the same disks, neither with -i, then name what the
// volumes hold: one lists the devices, partitions and logical volumes, one asks
// vfs-type of each. list-filesystems is not used: libguestfs 1.54 leaves
// crypto_LUKS out of it.
func TestNoOperatingSystemOnAnEncryptedVolumeIsRefusedAsEncrypted(t *testing.T) {
	for name, tc := range map[string]struct {
		volumes string
		kind    string
	}{
		"a whole disk that is a LUKS container": {"/dev/sda crypto_LUKS\n", "LUKS"},
		"LUKS on a logical volume":              {"/dev/sda ext4\n/dev/sda2 LVM2_member\n/dev/vg/root crypto_LUKS\n", "LUKS"},
		"a BitLocker system disk":               {"/dev/sda ntfs\n/dev/sda2 BitLocker\n", "BitLocker"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := installFakeGuestfish(t, "no-os", tc.volumes)
			err := applyWithRealGuestfish(t)
			requireEncryptedRefusal(t, err, tc.kind)
			if !strings.Contains(err.Error(), "no operating system was found on this disk") {
				t.Errorf("the refusal drops guestfish's own words: %v", err)
			}
			// The failed inspection is followed by one read-only call naming the
			// volumes and one asking each its type; nothing unlocks or writes.
			inspections, namings, typings := 0, 0, 0
			for _, call := range calls(t, dir) {
				padded := " " + call + " "
				switch {
				case strings.Contains(padded, " --rw "):
					t.Errorf("a writing call ran on an encrypted guest: %q", call)
				case strings.Contains(padded, " -i "):
					inspections++
				case strings.HasPrefix(call, "--ro --keys-from-stdin ") && strings.Contains(padded, " list-devices "):
					namings++
				case strings.HasPrefix(call, "--ro --keys-from-stdin ") && strings.Contains(padded, " vfs-type "):
					typings++
				default:
					t.Errorf("unexpected guestfish call %q", call)
				}
			}
			if inspections != 1 || namings != 1 || typings != 1 {
				t.Errorf("%d inspections, %d namings and %d typings, want one of each", inspections, namings, typings)
			}
		})
	}
}

// A guest with no inspectable system and no encrypted volume keeps the
// non-Linux message, and probes that fail change nothing.
func TestNoOperatingSystemOnPlainVolumesKeepsItsOwnMessage(t *testing.T) {
	for name, volumes := range map[string]string{
		"plain volumes":                    "/dev/sda ntfs\n/dev/sda1 ntfs\n",
		"probes that fail":                 "",
		"an unrelated type name":           "/dev/sda ext4\n/dev/sda2 swap\n",
		"a name that is not a device path": "sda1 crypto_LUKS\n/dev/sda;1 crypto_LUKS\n",
	} {
		t.Run(name, func(t *testing.T) {
			installFakeGuestfish(t, "no-os", volumes)
			err := applyWithRealGuestfish(t)
			if err == nil || !strings.Contains(err.Error(), "no inspectable Linux installation") || strings.Contains(err.Error(), "encrypted") {
				t.Fatalf("Apply = %v, want the no-operating-system message", err)
			}
		})
	}
}

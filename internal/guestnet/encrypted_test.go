// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// A guest whose root filesystem is LUKS-encrypted (such as Rocky 9 with a key
// file in its initramfs, so it boots unattended) makes guestfish say only
// "could not read key from user", which says nothing about encryption or what
// to do. The refusal names LUKS and the remedy, like the multi-boot refusal.

// liveLUKSFailure is the error such a run reports, word for word.
const liveLUKSFailure = "command failed with exit code 1: exit status 1: guestfish: could not read key from user"

// requireEncryptedRefusal fails unless err is the refusal for an encrypted
// volume of the given kind, with the remedy in it.
func requireEncryptedRefusal(t *testing.T, err error, kind string) {
	t.Helper()
	if err == nil {
		t.Fatal("no error")
	}
	message := err.Error()
	for _, want := range []string{
		kind,
		"CertiStack cannot read an encrypted root",
		"network_recovery.mode: preserve",
		"boots if it unlocks unattended",
		"restore the VM without network recovery",
		"leave it out of the plan's restored disks",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("refusal %q lacks %q", message, want)
		}
	}
	if strings.Contains(message, "libguestfs-tools") || strings.Contains(message, "no inspectable Linux installation") {
		t.Errorf("refusal blames a missing dependency or a non-Linux guest: %q", message)
	}
}

func TestLUKSRootRefusalNamesLUKSAndTheRemedy(t *testing.T) {
	requireEncryptedRefusal(t, dependencyError("inspect", errors.New(liveLUKSFailure)), "LUKS")

	// The other ways libguestfs says it met an encrypted volume.
	for name, failure := range map[string]string{
		"the passphrase prompt":   `guestfish: Enter key or passphrase ("/dev/sda3"): exit status 1`,
		"a LUKS filesystem type":  "guestfish: no operating system was found on this disk: /dev/sda2 is crypto_LUKS",
		"a LUKS open failure":     "libguestfs: error: luks_open: /dev/sda3: cryptsetup luksOpen: exit status 2",
		"a lowercase key message": "exit status 1: guestfish: could not read key from user",
		"a decorated key message": "exit status 1: guestfish: Could Not Read Key From User (stdin)",
	} {
		err := dependencyError("inspect", errors.New(failure))
		if err == nil || !strings.Contains(err.Error(), "LUKS") || !strings.Contains(err.Error(), "network_recovery.mode: preserve") {
			t.Errorf("%s: %v, want the LUKS refusal", name, err)
		}
	}
}

func TestBitLockerRefusalNamesBitLocker(t *testing.T) {
	err := dependencyError("inspect", errors.New("exit status 1: guestfish: no operating system was found on this disk: /dev/sda2 is BitLocker"))
	requireEncryptedRefusal(t, err, "BitLocker")
}

// Two appliance guests the adapter cannot prepare, Home Assistant OS (a
// read-only root) and OPNsense (a partition table libguestfs cannot read), are
// refusals that name the remedy, like every other such guest.
func TestUnadaptableApplianceGuestsAreRefusalsNamingPreserve(t *testing.T) {
	for name, failure := range map[string]string{
		"Home Assistant OS": "command failed with exit code 1: exit status 1: *stdin*:0: libguestfs: error: upload: /etc/NetworkManager/system-connections/90-certistack-recovery.nmconnection: Read-only file system",
		"OPNsense":          "command failed with exit code 1: exit status 1: libguestfs: error: inspect_os: parted exited with status 1: Error: Invalid partition table - recursive partition on /dev/sda.",
	} {
		err := dependencyError("inspect", errors.New(failure))
		if !isGuestRefusal(err) {
			t.Errorf("%s: %v is not a guest refusal", name, err)
		}
		for _, want := range []string{"unsupported guest network layout", "network_recovery.mode: preserve", failure} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal lacks %q: %v", name, want, err)
			}
		}
		if strings.Contains(err.Error(), "libguestfs-tools") || strings.Contains(err.Error(), "encrypted") {
			t.Errorf("%s: wrong remedy in %v", name, err)
		}
	}
	// A failure of another kind stays as it was.
	if err := dependencyError("inspect", errors.New("exit status 1: libguestfs: error: mount: /dev/sda1: wrong fs type")); isGuestRefusal(err) {
		t.Errorf("an unrelated mount failure became a refusal: %v", err)
	}
}

// Only an encrypted volume gets the encryption message: the refusals for the
// other layouts, and any other failure, keep theirs.
func TestOtherGuestfishFailuresKeepTheirOwnMessages(t *testing.T) {
	for failure, want := range map[string]string{
		"exit status 1: guestfish: no operating system was found on this disk":                        "no inspectable Linux installation",
		"exit status 1: guestfish: multi-boot operating systems are not supported by the -i option":   "more than one restored disk holds an operating system",
		"exit status 1: guestfish: /var/lib/certistack/luks-overlay.qcow2: No such file or directory": "",
		"exit status 1: libguestfs: error: mount: /dev/sda1: wrong fs type":                           "",
	} {
		err := dependencyError("inspect", errors.New(failure))
		message := err.Error()
		if strings.Contains(message, "encrypted") || strings.Contains(message, "unlocks unattended") {
			t.Errorf("%q got the encryption message: %q", failure, message)
		}
		if want != "" && !strings.Contains(message, want) {
			t.Errorf("%q lost its own message %q: %q", failure, want, message)
		}
	}
}

// Apply fails closed on an encrypted guest: nothing is written, and the error
// is the refusal, from whichever guestfish call meets the volume first.
func TestApplyRefusesAnEncryptedGuestBeforeWritingAnything(t *testing.T) {
	guest := newMemGuest(t, map[string]string{networkManagerDir + "/existing.nmconnection": "[connection]\n"}, networkManagerDir)
	adapter := guest.adapter()
	adapter.run = func(context.Context, ...string) (string, error) { return "", errors.New(liveLUKSFailure) }
	_, err := adapter.Apply(context.Background(), multiDiskConfig(bootOverlayPath))
	requireEncryptedRefusal(t, err, "LUKS")
	if !strings.Contains(err.Error(), liveLUKSFailure) {
		t.Errorf("the refusal drops guestfish's own words: %v", err)
	}
	if guest.mutated() {
		t.Fatal("a profile was written although the guest could not be read")
	}
}

// guestfish asks for a key on the terminal it runs under unless told to read
// keys from standard input, which a worker gives it empty: every call, the
// writing batch included, must never wait for a person.
func TestEveryGuestfishCallReadsKeysOnlyFromStdin(t *testing.T) {
	overlays := []string{bootOverlayPath, rootOverlayPath}
	for name, args := range map[string][]string{
		"read":  guestfishReadArgs(overlays, "is-dir", "/etc"),
		"batch": guestfishBatchArgs(overlays, [][]string{{"mkdir-p", "/etc/x"}}),
		"query": guestfishQueryArgs(overlays, [][]string{{"is-dir", "/etc"}, {"is-file", "/etc/fstab"}}),
	} {
		if !slices.Contains(args, "--keys-from-stdin") {
			t.Errorf("%s call %v can prompt on the terminal for a passphrase", name, args)
		}
		// The flag is an option: it stays in front of -i and the commands.
		if at, inspect := slices.Index(args, "--keys-from-stdin"), slices.Index(args, "-i"); at < 0 || inspect < at {
			t.Errorf("%s call %v puts --keys-from-stdin after -i", name, args)
		}
	}
}

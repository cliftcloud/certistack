// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/cliftcloud/certistack/internal/sysutil"
)

// Encrypted guests. guestfish -i unlocks nothing on its own: for each LUKS
// volume it finds it asks for a key or passphrase, and CertiStack has none to
// give, so network recovery cannot read the guest's disks. The refusal says
// that, in terms of what to do, instead of passing on guestfish's "could not
// read key from user".

// keysFromStdin makes guestfish read a key or passphrase only from standard
// input, which a worker gives it empty. Without it guestfish opens /dev/tty and
// waits there for a person, which a worker run from a terminal would let it do
// for as long as the call's timeout.
const keysFromStdin = "--keys-from-stdin"

// Signals in guestfish's output (lower case) that it met an encrypted volume.
// "could not read key from user" and the prompt are what guestfish -i prints
// for a LUKS volume it cannot unlock; crypto_LUKS and BitLocker are the
// filesystem types a listing gives such volumes.
var (
	luksSignals      = []string{"could not read key", "enter key or passphrase", "crypto_luks", "luks_open", "luksopen"}
	bitLockerSignals = []string{"bitlocker"}
)

// encryptedVolume names the kind of encrypted volume text says guestfish met,
// "LUKS" or "BitLocker", or is empty when it says none.
func encryptedVolume(text string) string {
	lower := strings.ToLower(text)
	for _, signal := range luksSignals {
		if strings.Contains(lower, signal) {
			return "LUKS"
		}
	}
	for _, signal := range bitLockerSignals {
		if strings.Contains(lower, signal) {
			return "BitLocker"
		}
	}
	return ""
}

// encryptedGuestError is the refusal for a guest with an encrypted volume. It
// keeps guestfish's own words and adds what they mean and what to do, as the
// multi-boot refusal does.
func encryptedGuestError(action string, err error, kind string) error {
	return fmt.Errorf("%s isolated guest network profile with guestfish: %w (a restored disk holds a %s-encrypted volume, and CertiStack cannot read an encrypted root to prepare the guest's network: guestfish would need its passphrase, which CertiStack never asks for; use network_recovery.mode: preserve, under which the guest keeps its own network configuration and boots if it unlocks unattended, for example from a key file in its initramfs, or restore the VM without network recovery, with probes that need no guest network; if only a data disk the guest does not need is encrypted, leave it out of the plan's restored disks)", action, err, kind)
}

// guestRefusal marks the refusal of a guest guestfish cannot open or prepare (an
// encrypted root, no inspectable system, several systems). The same disks fail
// the same way on every further call, so a caller that would try another way
// of asking returns it at once.
type guestRefusal struct{ error }

func (r guestRefusal) Unwrap() error { return r.error }

func isGuestRefusal(err error) bool {
	var refusal guestRefusal
	return errors.As(err, &refusal)
}

// volumeName is what a device or logical volume name may contain; anything
// else in a listing is the guest's text and is not repeated.
var volumeName = regexp.MustCompile(`^[A-Za-z0-9/_.+-]{1,128}$`)

// maxProbedVolumes bounds the volumes the follow-up asks about: a guest with
// more block devices, partitions and logical volumes than this is not a guest
// whose root is a bare encrypted volume.
const maxProbedVolumes = 64

// volumeNames lists the devices, partitions and logical volumes of the restored
// disks, as guestfish names them, without a key: only names that are plain
// device paths are returned, because they are written into the next command.
func volumeNames(ctx context.Context, drives []string) []string {
	command := append(slices.Clone(drives), "--", "run", ":", "lvm-scan", "true", ":", "list-devices", ":", "list-partitions", ":", "lvs")
	result, _ := sysutil.Run(ctx, guestfishTimeout, "guestfish", command...)
	if result == nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		name := strings.TrimSpace(line)
		if strings.HasPrefix(name, "/dev/") && volumeName.MatchString(name) && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) > maxProbedVolumes {
		names = names[:maxProbedVolumes]
	}
	return names
}

// withEncryptedVolume adds to a failed inspection that found no operating
// system what the disks hold, when that is an encrypted volume. guestfish -i
// asks for a key (and fails with "could not read key from user") for a LUKS
// volume on a partition or a logical volume, but a whole disk that is one LUKS
// container or a BitLocker system disk ends as "no operating system was
// found", which says nothing about encryption. vfs-type names a volume's
// content without a key, which list-filesystems does not for LUKS (libguestfs
// 1.54 leaves crypto_LUKS out of its listing): one boot names the devices,
// partitions and logical volumes, a second asks for each one's type. Both are
// read-only, run on the same disks, and change nothing when they find no
// encrypted volume or fail.
func withEncryptedVolume(ctx context.Context, args []string, err error) error {
	message := err.Error()
	if encryptedVolume(message) != "" || !strings.Contains(message, "no operating system was found") || ctx.Err() != nil {
		return err
	}
	inspect := slices.Index(args, "-i")
	if inspect < 1 {
		return err
	}
	drives := append([]string{"--ro"}, args[1:inspect]...)
	names := volumeNames(ctx, drives)
	if len(names) == 0 {
		return err
	}
	probe := append(slices.Clone(drives), "--", "run", ":", "lvm-scan", "true")
	for _, name := range names {
		probe = append(probe, ":", "echo", "vol="+name, ":", "vfs-type", name)
	}
	// A volume vfs-type fails on stops the chain, but what it printed before is
	// still read.
	result, _ := sysutil.Run(ctx, guestfishTimeout, "guestfish", probe...)
	if result == nil {
		return err
	}
	current := ""
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(line, "vol="); ok {
			current = name
			continue
		}
		if current == "" {
			continue
		}
		switch strings.ToLower(line) {
		case "crypto_luks":
			return fmt.Errorf("%w: restored volume %s is crypto_LUKS", err, current)
		case "bitlocker":
			return fmt.Errorf("%w: restored volume %s is BitLocker", err, current)
		}
		if line != "" {
			current = ""
		}
	}
	return err
}

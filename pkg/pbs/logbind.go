// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// errLogRefused marks the backup log of an encrypted snapshot that was
// fetched but is not one CertiStack will classify: it is not in an encrypted
// form, or it does not say it is this snapshot's own.
var errLogRefused = errors.New("the backup log of an encrypted backup cannot be trusted")

var (
	logStartedVM   = regexp.MustCompile(`^Starting Backup of VM ([0-9]+)(?: |$)`)
	logArchiveName = regexp.MustCompile(`^creating Proxmox Backup Server archive '([^']*)'`)
)

// isEncryptedBlob reports whether raw is a PBS blob in an encrypted form.
func isEncryptedBlob(raw []byte) bool {
	if len(raw) < 8 {
		return false
	}
	var magic [8]byte
	copy(magic[:], raw[:8])
	return magic == encryptedBlobMagic || magic == encryptedCompressedBlobMagic
}

// bindLogToSnapshot requires the decrypted log to say it is the log of
// snapshot: vzdump's own first line names the VM ("Starting Backup of VM
// 7011 (qemu)"), and a PBS backup names its archive ("creating Proxmox
// Backup Server archive 'vm/7011/2026-09-27T03:00:09Z'"). AES-GCM proves the
// log was written with the backup's key, but binds it to no snapshot (the
// additional data is empty), so a genuine encrypted log of another VM, or of
// another backup of this one, would otherwise be accepted for this one. A
// log that does not name both, or names anything else, is refused.
func bindLogToSnapshot(content []byte, snapshot string) error {
	parts := strings.Split(snapshot, "/")
	if len(parts) != 3 {
		return fmt.Errorf("%w: %q is not a snapshot path", errLogRefused, snapshot)
	}
	var vms, archives []string
	for _, line := range strings.Split(string(content), "\n") {
		level, message := backupLogMessage(line)
		if level != "INFO" {
			continue
		}
		if match := logStartedVM.FindStringSubmatch(message); match != nil {
			vms = append(vms, match[1])
		} else if match := logArchiveName.FindStringSubmatch(message); match != nil {
			archives = append(archives, match[1])
		}
	}
	if len(vms) == 0 || len(archives) == 0 {
		return fmt.Errorf("%w: the log does not say which VM and which archive it is of, so it cannot be tied to snapshot %s", errLogRefused, snapshot)
	}
	for _, vm := range vms {
		if vm != parts[1] {
			return fmt.Errorf("%w: the log is of VM %s, not of snapshot %s", errLogRefused, boundedLogText(vm), snapshot)
		}
	}
	for _, archive := range archives {
		if archive != snapshot {
			return fmt.Errorf("%w: the log is of archive %s, not of snapshot %s", errLogRefused, boundedLogText(archive), snapshot)
		}
	}
	return nil
}

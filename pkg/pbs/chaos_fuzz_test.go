// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"testing"
)

// FuzzClientOutputParsers feeds what proxmox-backup-client and PBS print to
// every parser that reads it: any output either parses or is an error, never
// a panic.
func FuzzClientOutputParsers(f *testing.F) {
	for _, seed := range []string{
		uefiConfig,
		encryptedFiles,
		abortedNewestSnapshotList,
		largeGroups,
		signOnlyFiles,
		`[{"backup-type":"vm","backup-id":"100","last-backup":1790273656,"backup-count":3,"files":["qemu-server.conf.blob","drive-scsi0.img.fidx"]}]`,
		"scsi0: local:vm-100-disk-0,size=32G\nnet0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0\nsmbios1: uuid=7c0d4b4e-1a2b-4c3d-8e9f-0a1b2c3d4e5f\nmeta: creation-qemu=9.0.2,ctime=1790273656\n",
		"proxmox-backup-client 4.2.1 (UNKNOWN)\nproxmox-backup-server 4.2.0\n",
		"INFO: issuing guest-agent 'fs-freeze' command\nINFO: issuing guest-agent 'fs-thaw' command\n",
		"[]",
		"null",
		"{}",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseVMProfile(data)
		_, _ = ParseVMLayout(data)
		_, _ = ParseVMBackupsJSON(data)
		_, _ = ParseLatestSnapshotJSON(data, "vm/7144")
		_, _, _ = latestCompleteSnapshot(data, "vm/100")
		_ = ParseSnapshotImageBytes(data)
		_, _ = ParseSnapshotFirmwareJSON(data)
		_, _ = ParseSnapshotDrivesJSON(data)
		_, _ = ParseSnapshotCryptMode(data)
		_, _ = ParseSnapshotDiskCryptMode(data)
		_, _ = parseSnapshotFingerprints(data, "vm/100")
		_, _ = listedSnapshots(data, "vm/100")
		_, _ = ParseSnapshotConfigBytes(data)
		_ = ParseBackupLog(string(data))
		_, _ = classifyClientFailure(data)
		_, _ = ParseVersionOutput(data)
		_ = bindLogToSnapshot(data, "vm/100/2026-09-27T03:12:59Z")
		_, _ = decodeBlob(data, nil, 1<<16)
		var key [32]byte
		_, _ = decodeBlob(data, &key, 1<<16)
	})
}

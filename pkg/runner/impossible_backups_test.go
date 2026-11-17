// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// impossibleBackup puts a stand-in proxmox-backup-client on PATH that lists
// files as the snapshot's files and restores config as its qemu-server.conf
// (none when config is nil: the restore fails as the real client does for a
// blob the snapshot does not hold), to stand for backups no PVE VM could have.
func impossibleBackup(t *testing.T, files string, config []byte) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "files.json"), []byte(files), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := `echo "Error: unable to read blob" >&2; exit 255`
	if config != nil {
		if err := os.WriteFile(filepath.Join(dir, "qemu-server.conf"), config, 0o600); err != nil {
			t.Fatal(err)
		}
		restore = `cp "` + filepath.Join(dir, "qemu-server.conf") + `" "$last"`
	}
	script := "#!/bin/sh\nfor last; do :; done\ncase \"$1 $2\" in\n" +
		"  'snapshot files') cat " + filepath.Join(dir, "files.json") + " ;;\n" +
		"  restore*) " + restore + " ;;\n  *) exit 1 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// planRefusal is what plan, doctor and run say about the one VM of a plan
// that restores snapshot, for each way of taking the hardware: the steps are
// the run's own (checkSources), and it is read before anything is made.
func planRefusal(t *testing.T, snapshot string, useBackupConfig bool) string {
	t.Helper()
	vmid := 9906
	plan := &config.Plan{UseBackupConfig: useBackupConfig, Network: config.Network{IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"}, Tiers: []config.Tier{{Level: 1, VMs: []config.VM{{
		VMID: 4917906, Name: "chaos", SourceVMID: vmid,
		SourcePBS: config.SourcePBS{Snapshot: snapshot, Drives: []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}},
	}}}}}
	if useBackupConfig {
		plan.Tiers[0].VMs[0].SourcePBS.Drives = nil
	}
	client := pbs.New(pbs.Config{})
	checks := checkSources(context.Background(), plan, &fakeSnapshotResolver{resolved: map[string]string{snapshot + ":9906": snapshot}}, client, t.TempDir(), "")
	if len(checks) != 1 {
		t.Fatalf("checks = %+v", checks)
	}
	if checks[0].Status != SourceFailed {
		t.Fatalf("the backup is not refused: %+v", checks[0])
	}
	return checks[0].Detail
}

// 4 KiB of random bytes as the configuration, and one disk archive. Read as a
// configuration with no keys, the restored VM would boot the disk on hardware
// the backup never had: plan and run refuse it, with the reason, before
// anything is made.
func TestABackupWhoseConfigurationIsRandomBytesIsRefusedWithTheReason(t *testing.T) {
	data := make([]byte, 4096)
	rand.New(rand.NewSource(9906)).Read(data)
	const snapshot = "vm/9906/2026-11-15T12:00:00Z"
	impossibleBackup(t, `[{"filename":"qemu-server.conf.blob","crypt-mode":"none","size":4096},{"filename":"drive-scsi0.img.fidx","crypt-mode":"none","size":67108864}]`, data)
	for _, useBackupConfig := range []bool{true, false} {
		detail := planRefusal(t, snapshot, useBackupConfig)
		if !strings.Contains(detail, "is not a Proxmox VE configuration: it holds binary data") {
			t.Errorf("use_backup_config %v: refused for %q, want the binary configuration named", useBackupConfig, detail)
		}
	}
}

// A snapshot with no qemu-server.conf.blob. The snapshot's file list says it
// holds no configuration, and so does the refusal, rather than the client's
// bare "exit status 255", which names no cause.
func TestABackupWithoutAConfigurationIsRefusedWithTheReason(t *testing.T) {
	const snapshot = "vm/9906/2026-11-15T12:00:00Z"
	impossibleBackup(t, `[{"filename":"drive-scsi0.img.fidx","crypt-mode":"none","size":67108864}]`, nil)
	for _, useBackupConfig := range []bool{true, false} {
		detail := planRefusal(t, snapshot, useBackupConfig)
		if !strings.Contains(detail, "the backup holds no VM configuration (qemu-server.conf): it is not a backup PVE made of a VM") || strings.Contains(detail, "withheld") {
			t.Errorf("use_backup_config %v: refused for %q, want the missing configuration named", useBackupConfig, detail)
		}
	}
}

// A container's backup under vm/, a root.pxar and a pct configuration. plan
// and run say what the backup is, not "unsupported source net0 model "name""
// (from the container's network line), which names neither the cause nor the
// way out.
func TestAContainerBackupUnderVMIsRefusedAsAContainer(t *testing.T) {
	const snapshot = "vm/9906/2026-11-15T12:00:00Z"
	impossibleBackup(t, `[{"filename":"qemu-server.conf.blob","crypt-mode":"none","size":200},{"filename":"root.pxar.didx","crypt-mode":"none","size":1048576},{"filename":"index.json.blob","crypt-mode":"none","size":300}]`,
		[]byte("arch: amd64\nhostname: ct9911\nnet0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=dhcp\nostype: debian\n"))
	for _, useBackupConfig := range []bool{true, false} {
		detail := planRefusal(t, snapshot, useBackupConfig)
		if !strings.Contains(detail, "the backup holds a container's file archive (root.pxar), not a VM disk: CertiStack restore-tests VMs only") {
			t.Errorf("use_backup_config %v: refused for %q, want the container named", useBackupConfig, detail)
		}
	}
}

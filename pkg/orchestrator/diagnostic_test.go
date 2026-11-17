// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A nofail data mount whose device does not appear in time is skipped, and
// redis-server stays "inactive (dependency)" with no unit failed. The
// failed-VM diagnostic lists inactive mounts and the boot journal's
// dependency and device failures, so it shows the cause.
func TestFailedVMDiagnosticNamesSkippedMounts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the diagnostic is a guest shell script")
	}
	bin := t.TempDir()
	fakes := map[string]string{
		"systemctl": `case "$*" in
*list-units*) printf '%s\n' \
  '  -.mount                   loaded    active   mounted Root Mount' \
  '  boot.mount                loaded    active   mounted /boot' \
  '  var-lib-redis.mount       loaded    inactive dead    /var/lib/redis' \
  '● srv-data.mount            loaded    failed   failed  /srv/data' ;;
esac`,
		"journalctl": `printf '%s\n' \
  '[    2.100000] host kernel: sd 2:0:0:1: [sdb] Attached SCSI disk' \
  '[    2.200000] host kernel: virtio_blk virtio3: [vdb] 16777216 512-byte logical blocks (8.59 GB/8.00 GiB)' \
  '[   12.000000] host systemd[1]: Started ssh.service.' \
  '[   33.000000] host systemd-udevd[312]: sdb: Worker [320] processing SEQNUM=2451 is taking a long time' \
  '[   41.000000] host systemd[1]: dev-disk-by\x2duuid-20ab.device: Job dev-disk-by\x2duuid-20ab.device/start timed out.' \
  '[   41.000000] host systemd[1]: Timed out waiting for device /dev/disk/by-uuid/20ab.' \
  '[   41.000000] host systemd[1]: Dependency failed for /var/lib/redis.' \
  '[   41.000000] host systemd[1]: Dependency failed for redis-server.service - Advanced key-value store.'`,
	}
	for _, name := range []string{"ip", "ss", "networkctl", "nmcli"} {
		fakes[name] = "true"
	}
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("/bin/sh", "-c", guestNetworkDiagnosticCommand)
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("diagnostic failed: %v\n%s", err, output)
	}
	for _, want := range []string{
		"[mounts not active]\n  var-lib-redis.mount       loaded    inactive dead    /var/lib/redis\n● srv-data.mount            loaded    failed   failed  /srv/data\n[dependency",
		"Timed out waiting for device /dev/disk/by-uuid/20ab.",
		"Dependency failed for redis-server.service",
		"start timed out.",
		"[sdb] Attached SCSI disk",
		"[vdb] 16777216 512-byte logical blocks",
		"sdb: Worker [320] processing SEQNUM=2451 is taking a long time",
	} {
		if !strings.Contains(string(output), want) {
			t.Errorf("diagnostic lacks %q:\n%s", want, output)
		}
	}
	if strings.Contains(string(output), "Started ssh.service") || strings.Contains(string(output), "Root Mount") || strings.Contains(string(output), "/boot") {
		t.Errorf("diagnostic includes healthy units:\n%s", output)
	}
}

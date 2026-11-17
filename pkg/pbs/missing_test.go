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

// fakePrunedClient installs a proxmox-backup-client that answers `snapshot
// files` and `restore` as client 4.2.5 does for a snapshot PBS has no
// directory for ("Error: ENOENT: No such file or directory", exit 255), and
// `snapshot list` with list.
func fakePrunedClient(t *testing.T, list string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "list.json"), []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"case \"$1 $2\" in\n" +
		"  'snapshot list') cat " + filepath.Join(dir, "list.json") + " ;;\n" +
		"  *) echo 'Error: ENOENT: No such file or directory' >&2; exit 255 ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

// For a pinned snapshot that PBS retention pruned, the snapshot-files call
// names what is missing from a new listing of the group, in CertiStack's words
// and without the repository, instead of a bare "exit status 255".
func TestPrunedPinnedSnapshotIsNamed(t *testing.T) {
	const pinned = "vm/7011/2026-09-20T03:00:09Z"
	// 1790478000 is 2026-09-27T03:00:00Z, 1790564400 2026-09-28T03:00:00Z.
	withManifest := `"files":[{"filename":"index.json.blob"}]`
	for _, tc := range []struct {
		name, list string
		want       []string
	}{
		{"group has newer snapshots", `[{"backup-type":"vm","backup-id":"7011","backup-time":1790478000,` + withManifest + `},{"backup-type":"vm","backup-id":"7011","backup-time":1790564400,` + withManifest + `}]`,
			[]string{pinned + " no longer exists", "retention may have pruned it", "newest snapshot of vm/7011 is vm/7011/2026-09-28T03:00:00Z", "snapshot: latest"}},
		{"group is gone", `[]`,
			[]string{pinned + " does not exist", "backup group vm/7011 has no snapshots", "check source_vmid"}},
		{"only aborted snapshots left", `[{"backup-type":"vm","backup-id":"7011","backup-time":1790478000,"files":[{"filename":"drive-scsi0.img.fidx"}]}]`,
			[]string{pinned + " no longer exists", "no complete snapshot"}},
		{"listed yet missing", `[{"backup-type":"vm","backup-id":"7011","backup-time":1789873209,` + withManifest + `}]`,
			[]string{"lists snapshot " + pinned, "pruned while CertiStack read it"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakePrunedClient(t, tc.list)
			client := New(Config{Repository: "certistack@pbs!restore@pbs.lab.example:backup-store", Namespace: "certistack-test"})
			_, err := client.LoadVMLayout(context.Background(), pinned, t.TempDir())
			if err == nil {
				t.Fatal("a missing snapshot loaded")
			}
			for _, want := range append(tc.want, `namespace "certistack-test"`) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error lacks %q: %v", want, err)
				}
			}
			for _, secret := range []string{"pbs.lab.example", "certistack@pbs", "backup-store", "withheld"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error names %q: %v", secret, err)
				}
			}
		})
	}
}

// The ENOENT reading is the snapshot-files call's alone: the same client
// words from a restore mean something else and stay withheld.
func TestENOENTOutsideSnapshotFilesStaysGeneric(t *testing.T) {
	fakePrunedClient(t, `[]`)
	target := filepath.Join(t.TempDir(), "efi.raw")
	err := New(Config{}).RestoreImage(context.Background(), "vm/7011/2026-09-20T03:00:09Z", "drive-efidisk0", target)
	if err == nil || !strings.Contains(err.Error(), "client output withheld") || strings.Contains(err.Error(), "pruned") {
		t.Fatalf("restore ENOENT: %v", err)
	}
}

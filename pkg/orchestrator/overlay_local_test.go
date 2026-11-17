// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pve"
)

const sampleStorageCfg = `# a comment
dir: local
	path /var/lib/vz
	content iso,vztmpl,backup
	shared 0

nfs: nas
	export /volume1/pve
	path /mnt/pve/nas
	server 192.0.2.20
	content images,backup

dir: usbscratch
	path /mnt/usb-scratch
	content images,rootdir
	is_mountpoint 1
	nodes pve1,pve2
	disable 0
`

// The node reads a storage's configuration from storage.cfg.
func TestParseStorageConfig(t *testing.T) {
	for id, want := range map[string]localStorage{
		"local":      {Type: "dir", Path: "/var/lib/vz", Content: "iso,vztmpl,backup"},
		"nas":        {Type: "nfs", Path: "/mnt/pve/nas", Content: "images,backup"},
		"usbscratch": {Type: "dir", Path: "/mnt/usb-scratch", Content: "images,rootdir", IsMountpoint: "1", Nodes: "pve1,pve2", Disable: "0"},
	} {
		got, found, err := parseStorageConfig(strings.NewReader(sampleStorageCfg), id)
		if err != nil || !found || got != want {
			t.Errorf("%s: %+v, found %v, err %v; want %+v", id, got, found, err, want)
		}
	}
	if _, found, err := parseStorageConfig(strings.NewReader(sampleStorageCfg), "absent"); found || err != nil {
		t.Errorf("absent storage: found %v, err %v", found, err)
	}
	if _, _, err := parseStorageConfig(strings.NewReader(sampleStorageCfg+"\ndir: local\n\tpath /x\n"), "local"); err == nil {
		t.Error("a storage configured twice was accepted")
	}
}

// A storage PVE disabled shows as a bare "disable" line, which read as an
// empty value, that is, as enabled, so the overlay fallback accepted a disabled
// storage's directory. A flag with no value is set; a value still decides.
func TestABareDisableLineMeansDisabled(t *testing.T) {
	cfg := func(line string) string {
		return "dir: scratch\n\tpath /mnt/scratch\n\tcontent images\n" + line + "\ndir: other\n\tpath /mnt/other\n"
	}
	for name, tc := range map[string]struct {
		line     string
		disabled bool
	}{
		"a bare flag":                     {"\tdisable", true},
		"a bare flag with trailing space": {"\tdisable  ", true},
		"disable 1":                       {"\tdisable 1", true},
		"disable yes":                     {"\tdisable yes", true},
		"disable 0":                       {"\tdisable 0", false},
		"disable no":                      {"\tdisable no", false},
		"no disable line":                 {"\tshared 0", false},
	} {
		storage, found, err := parseStorageConfig(strings.NewReader(cfg(tc.line)), "scratch")
		if err != nil || !found {
			t.Fatalf("%s: found %v, err %v", name, found, err)
		}
		o := New(&config.Plan{}, Options{NodeName: "pve1", StateDir: t.TempDir()}, nil, nil)
		o.storageConfigFn = func(string) (localStorage, error) { return storage, nil }
		o.mountPointFn = func(string) (bool, error) { return true, nil }
		_, err = o.confirmLocalOverlayStorage("scratch", "/mnt/scratch")
		if disabled := err != nil && strings.Contains(err.Error(), "disabled"); disabled != tc.disabled {
			t.Errorf("%s: disabled = %v (err %v), want %v", name, disabled, err, tc.disabled)
		}
	}
	// The next section's lines are not this storage's.
	storage, _, _ := parseStorageConfig(strings.NewReader(cfg("\tshared 0")+"\tdisable\n"), "scratch")
	if storage.Disable != "" {
		t.Errorf("the next section's disable flag was read as this storage's: %q", storage.Disable)
	}
}

// When PVE's status of a storage does not answer, a directory that exists and
// has 5 GiB free is not enough: beneath an absent mount it is an ordinary
// directory of the file system underneath, and the overlays, firmware copies
// and disk copies would be written there. The fallback confirms the storage's
// configuration and mount on the node.
func TestOverlayFallbackRefusesADirectoryBeneathAnAbsentMount(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the node worker needs Linux host memory and mount-table semantics")
	}
	parent := t.TempDir()
	missingMount := filepath.Join(parent, "intended-storage-mount")
	if err := os.Mkdir(missingMount, 0o700); err != nil {
		t.Fatal(err)
	}
	newOrchestrator := func(cfg localStorage, mounted func(string) (bool, error)) *Orchestrator {
		o := New(&config.Plan{}, Options{NodeName: "pve1", OverlayStorage: "audit-storage", StateDir: t.TempDir()}, nil, nil)
		o.validateOverlayStorageFn = func(context.Context) error { return &pve.APIError{StatusCode: 596, Message: "status unavailable"} }
		o.overlayVolumePathFn = func(_ context.Context, volume string) (string, error) {
			return filepath.Join(missingMount, "images", "1", "certistack-storage-check.qcow2"), nil
		}
		o.freeBytesFn = func(string) (int64, error) { return 100 << 30, nil }
		o.storageConfigFn = func(string) (localStorage, error) { return cfg, nil }
		o.mountPointFn = mounted
		return o
	}
	realMounts := sysutil.IsMountPoint
	notMounted := func(string) (bool, error) { return false, nil }
	mounted := func(string) (bool, error) { return true, nil }
	dirStorage := localStorage{Type: "dir", Path: missingMount, Content: "images,rootdir"}

	for _, tc := range []struct {
		name    string
		cfg     localStorage
		mounts  func(string) (bool, error)
		wantErr string // "" for accepted
	}{
		{"is_mountpoint with nothing mounted", localStorage{Type: "dir", Path: missingMount, Content: "images", IsMountpoint: "yes"}, notMounted, "nothing is mounted there"},
		{"is_mountpoint with the real mount table", localStorage{Type: "dir", Path: missingMount, Content: "images", IsMountpoint: "1"}, realMounts, "nothing is mounted there"},
		{"is_mountpoint naming another path", localStorage{Type: "dir", Path: missingMount, Content: "images", IsMountpoint: "/mnt/elsewhere"}, notMounted, "mounted at /mnt/elsewhere"},
		{"network storage that is not mounted", localStorage{Type: "nfs", Path: missingMount, Content: "images"}, notMounted, "nothing is mounted there"},
		{"is_mountpoint with the mount present", localStorage{Type: "dir", Path: missingMount, Content: "images", IsMountpoint: "1"}, mounted, ""},
		{"network storage that is mounted", localStorage{Type: "nfs", Path: missingMount, Content: "images"}, mounted, ""},
		{"plain directory storage", dirStorage, notMounted, ""},
		{"disabled", localStorage{Type: "dir", Path: missingMount, Content: "images", Disable: "1"}, mounted, "disabled"},
		{"disable spelled oddly", localStorage{Type: "dir", Path: missingMount, Content: "images", Disable: "maybe"}, mounted, "disabled"},
		{"no images content", localStorage{Type: "dir", Path: missingMount, Content: "backup"}, mounted, "does not allow disk images"},
		{"not file-based", localStorage{Type: "lvmthin", Path: missingMount, Content: "images"}, mounted, "must be file-based"},
		{"limited to other nodes", localStorage{Type: "dir", Path: missingMount, Content: "images", Nodes: "pve2,pve3"}, mounted, "limited to nodes"},
		{"configured elsewhere than pvesm says", localStorage{Type: "dir", Path: "/mnt/other", Content: "images"}, mounted, "pvesm resolves it to"},
		{"is_mountpoint that is not a path", localStorage{Type: "dir", Path: missingMount, Content: "images", IsMountpoint: "relative/dir"}, mounted, "neither a boolean nor an absolute path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warning, err := newOrchestrator(tc.cfg, tc.mounts).checkOverlayStorage(context.Background())
			if tc.wantErr == "" {
				if err != nil || !strings.Contains(warning, "did not answer") || !strings.Contains(warning, "has not confirmed it is active") {
					t.Fatalf("warning %q, err %v", warning, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || warning != "" {
				t.Fatalf("err = %v, warning %q, want a refusal naming %q", err, warning, tc.wantErr)
			}
		})
	}

	// The storage's configuration unreadable: nothing confirms the directory.
	o := newOrchestrator(dirStorage, mounted)
	o.storageConfigFn = func(string) (localStorage, error) { return localStorage{}, errors.New("permission denied") }
	if _, err := o.checkOverlayStorage(context.Background()); err == nil || !strings.Contains(err.Error(), "cannot be confirmed to be the storage") {
		t.Fatalf("unreadable configuration: %v", err)
	}
	// A mount table that cannot be read leaves the mount unconfirmed.
	o = newOrchestrator(localStorage{Type: "dir", Path: missingMount, Content: "images", IsMountpoint: "1"}, func(string) (bool, error) { return false, errors.New("no /proc") })
	if _, err := o.checkOverlayStorage(context.Background()); err == nil || !strings.Contains(err.Error(), "could not be checked") {
		t.Fatalf("unreadable mount table: %v", err)
	}
	// A definite answer from PVE still stands and never falls back.
	o = newOrchestrator(dirStorage, mounted)
	o.validateOverlayStorageFn = func(context.Context) error { return errors.New("overlay storage is not active") }
	if _, err := o.checkOverlayStorage(context.Background()); err == nil || strings.Contains(err.Error(), "on the node instead") {
		t.Fatalf("an explicit inactive answer: %v", err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractLoopDevice(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    string
		wantErr bool
	}{
		{
			name:   "standard pbs output",
			output: "Image 'vm/100/2026-03-30T02:00:00Z drive-scsi0.img.fidx' mapped to '/dev/loop0'",
			want:   "/dev/loop0",
		},
		{
			// proxmox-backup-client 4.2.x wording, observed on PVE 9.2.
			name:   "pbs client 4.2 output",
			output: "Image 'certistack@pbs!ro@192.0.2.5:8007:pbs-data:vm/7011/2026-09-23T03:00:08Z/drive-scsi0.img' mapped on /dev/loop0    ",
			want:   "/dev/loop0",
		},
		{
			name:   "loop with quotes",
			output: "Image archive mapped to \"/dev/loop12\"",
			want:   "/dev/loop12",
		},
		{
			name:   "nbd device",
			output: "Image archive mapped to /dev/nbd3",
			want:   "/dev/nbd3",
		},
		{
			name:   "ignores unrelated device mentions",
			output: "warning: existing /dev/loop99 is still attached\nImage archive mapped to '/dev/loop3'",
			want:   "/dev/loop3",
		},
		{
			name:    "no loop device in output",
			output:  "Error: failed to connect to repository",
			wantErr: true,
		},
		{
			name:    "rejects path suffix after device",
			output:  "mapped to /dev/loop0/other",
			wantErr: true,
		},
		{
			name:    "rejects non-numeric device suffix",
			output:  "Image archive mapped to /dev/nbdtest",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractLoopDevice(tt.output)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExtractLoopDevice() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ExtractLoopDevice() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractLoopDeviceErrorWithholdsClientOutput(t *testing.T) {
	secretOutput := "repository=backup@pbs!automation password=must-not-log"
	_, err := ExtractLoopDevice(secretOutput)
	if err == nil {
		t.Fatal("ExtractLoopDevice unexpectedly accepted client output without a device")
	}
	if got := err.Error(); strings.Contains(got, "automation") || strings.Contains(got, "must-not-log") || strings.Contains(got, secretOutput) {
		t.Fatalf("ExtractLoopDevice error exposed client output: %q", got)
	}
}

func TestLoopBackingRejectsUnknownDevice(t *testing.T) {
	if _, err := LoopBacking("/dev/certistack-loop-does-not-exist"); err == nil {
		t.Fatal("LoopBacking accepted a non-existent loop device")
	}
}

func TestValidMappedDevice(t *testing.T) {
	for _, device := range []string{"/dev/loop0", "/dev/loop12", "/dev/nbd0"} {
		if !ValidMappedDevice(device) {
			t.Errorf("ValidMappedDevice(%q) = false", device)
		}
	}
	for _, device := range []string{"", "/dev/loop", "/dev/loop0/other", "/dev/loop-1", "/dev/sda", "--help"} {
		if ValidMappedDevice(device) {
			t.Errorf("ValidMappedDevice(%q) = true", device)
		}
	}
}

func TestBlockDeviceBytes(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "loop3"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "loop3", "size"), []byte("83886080\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, err := blockDeviceBytes(root, "/dev/loop3"); err != nil || n != 40<<30 {
		t.Fatalf("blockDeviceBytes = %d, %v; want 40 GiB", n, err)
	}
	if _, err := blockDeviceBytes(root, "/dev/sda"); err == nil {
		t.Fatal("accepted a non-mapped device")
	}
}

// fakeSysBlock points LoopBacking at a private sysfs tree with the given
// loop devices (name to backing file, "" for a device with no backing) and
// returns its root.
func fakeSysBlock(t *testing.T, loops map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, backing := range loops {
		if err := os.MkdirAll(filepath.Join(root, name, "loop"), 0o755); err != nil {
			t.Fatal(err)
		}
		if backing != "" {
			if err := os.WriteFile(filepath.Join(root, name, "loop", "backing_file"), []byte(backing+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	old := SysBlockDir
	t.Cleanup(func() { SysBlockDir = old })
	SysBlockDir = root
	return root
}

// A loop device is the run's only while the kernel says it is
// attached to the file recorded when it was mapped. Gone, still the run's,
// reused by another file, and not known are four different answers.
func TestCheckLoopComparesTheBackingWithTheRecordedOne(t *testing.T) {
	const recorded = "/run/pbs-loopdev/owned-map.img"
	fakeSysBlock(t, map[string]string{
		"loop1": recorded,
		"loop2": "/run/pbs-loopdev/foreign-map.img",
		"loop3": recorded + " (deleted)",
		"loop4": "", // a directory without a backing file: not attached
	})
	// A device whose backing cannot be read at all: its sysfs entry is a directory.
	if err := os.MkdirAll(filepath.Join(SysBlockDir, "loop5", "loop", "backing_file"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		device, recorded string
		want             LoopState
		wantErr          bool
	}{
		{"/dev/loop1", recorded, LoopRecorded, false},
		{"/dev/loop1", recorded + " (deleted)", LoopRecorded, false},
		{"/dev/loop2", recorded, LoopReused, false},
		{"/dev/loop3", recorded, LoopRecorded, false}, // its file was unlinked since
		{"/dev/loop4", recorded, LoopGone, false},
		{"/dev/loop9", recorded, LoopGone, false},
		{"/dev/loop9", "", LoopGone, false}, // nothing to detach: identity is not needed
		{"/dev/loop1", "", 0, true},         // present, and no identity recorded: not known
		{"/dev/loop2", "  ", 0, true},
		{"/dev/loop5", recorded, 0, true}, // unreadable: not known
		{"/dev/sda", recorded, 0, true},
		{"/dev/loop1/../x", recorded, 0, true},
	} {
		got, err := CheckLoop(tc.device, tc.recorded)
		if (err != nil) != tc.wantErr || (err == nil && got != tc.want) {
			t.Errorf("CheckLoop(%q, %q) = %v, %v; want %v (error %v)", tc.device, tc.recorded, got, err, tc.want, tc.wantErr)
		}
		if err != nil && strings.Contains(err.Error(), "foreign-map") {
			t.Errorf("the error names another file's backing: %v", err)
		}
	}
}

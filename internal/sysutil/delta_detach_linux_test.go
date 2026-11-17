//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// toolShims puts private `qemu-img` and `losetup` first on PATH. Each logs its
// arguments to <dir>/calls, and fails (exit 1, a message on stderr) when
// <dir>/fail-<tool> exists. qemu-img create makes its last argument as a
// 0644 file, as the real one does, unless <dir>/nofile exists. Nothing on the
// host is touched.
func toolShims(t *testing.T) (dir string, calls func() string) {
	t.Helper()
	dir = t.TempDir()
	script := func(tool, extra string) string {
		return "#!/bin/sh\n" +
			"echo \"" + tool + " $*\" >> \"" + dir + "/calls\"\n" +
			"if [ -e \"" + dir + "/fail-" + tool + "\" ]; then echo '" + tool + ": refused' >&2; exit 1; fi\n" +
			extra
	}
	create := "if [ \"$1\" = create ] && [ ! -e \"" + dir + "/nofile\" ]; then for last; do :; done; : > \"$last\"; chmod 644 \"$last\"; fi\nexit 0\n"
	for tool, body := range map[string]string{
		"qemu-img": script("qemu-img", create),
		"losetup":  script("losetup", "exit 0\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, tool), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir, func() string {
		data, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return string(data)
	}
}

func TestCreateDeltaOverlayRunsQemuImgAndSecuresTheFile(t *testing.T) {
	_, calls := toolShims(t)
	parent := filepath.Join(t.TempDir(), "w")
	delta := filepath.Join(parent, "scsi0.qcow2")
	if err := CreateDeltaOverlay(context.Background(), "/dev/loop3", delta); err != nil {
		t.Fatal(err)
	}
	if want := "qemu-img " + strings.Join(deltaOverlayArgs("/dev/loop3", delta), " "); !strings.Contains(calls(), want) {
		t.Fatalf("calls:\n%s\nwant %q", calls(), want)
	}
	info, err := os.Stat(delta)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("overlay %v, %v; want mode 600 (qemu-img made it 644)", info, err)
	}
	dirInfo, err := os.Stat(parent)
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("overlay directory %v, %v; want it created private (700)", dirInfo, err)
	}
}

func TestCreateDeltaOverlayFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("empty arguments run nothing", func(t *testing.T) {
		_, calls := toolShims(t)
		if err := CreateDeltaOverlay(ctx, "", "/x/y.qcow2"); err == nil {
			t.Error("an empty backing device was accepted")
		}
		if err := CreateDeltaOverlay(ctx, "/dev/loop3", ""); err == nil {
			t.Error("an empty delta path was accepted")
		}
		if calls() != "" {
			t.Errorf("qemu-img ran for an invalid request:\n%s", calls())
		}
	})
	t.Run("qemu-img fails", func(t *testing.T) {
		dir, _ := toolShims(t)
		if err := os.WriteFile(filepath.Join(dir, "fail-qemu-img"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		delta := filepath.Join(t.TempDir(), "w", "scsi0.qcow2")
		err := CreateDeltaOverlay(ctx, "/dev/loop3", delta)
		if err == nil || !strings.Contains(err.Error(), delta) {
			t.Fatalf("error = %v, want it to name the overlay path", err)
		}
		if _, statErr := os.Stat(delta); statErr == nil {
			t.Error("a failed creation left an overlay file")
		}
	})
	t.Run("the file is not there to secure", func(t *testing.T) {
		dir, _ := toolShims(t)
		if err := os.WriteFile(filepath.Join(dir, "nofile"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		err := CreateDeltaOverlay(ctx, "/dev/loop3", filepath.Join(t.TempDir(), "w", "scsi0.qcow2"))
		if err == nil || !strings.Contains(err.Error(), "secure") {
			t.Fatalf("error = %v, want the failure to secure the overlay", err)
		}
	})
	t.Run("the directory is not private", func(t *testing.T) {
		_, calls := toolShims(t)
		open := filepath.Join(t.TempDir(), "open")
		if err := os.Mkdir(open, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(open, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := CreateDeltaOverlay(ctx, "/dev/loop3", filepath.Join(open, "scsi0.qcow2")); err == nil {
			t.Error("an overlay was created in a directory others can write to")
		}
		if calls() != "" {
			t.Errorf("qemu-img ran although the directory was refused:\n%s", calls())
		}
	})
}

func TestDetachLoop(t *testing.T) {
	ctx := context.Background()
	t.Run("detaches exactly the device named", func(t *testing.T) {
		_, calls := toolShims(t)
		if err := DetachLoop(ctx, "/dev/loop12"); err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(calls()); got != "losetup -d /dev/loop12" {
			t.Fatalf("calls = %q, want exactly `losetup -d /dev/loop12`", got)
		}
	})
	t.Run("refuses anything that is not a numbered loop device, running nothing", func(t *testing.T) {
		_, calls := toolShims(t)
		for _, device := range []string{"", "/dev/loop", "/dev/loopx", "loop3", "/dev/nbd3", "/dev/loop3; rm -rf /", "/dev/loop3/../sda", "/dev/loop-1", "/dev/../dev/loop3"} {
			if err := DetachLoop(ctx, device); err == nil {
				t.Errorf("DetachLoop(%q) was accepted", device)
			}
		}
		if calls() != "" {
			t.Errorf("losetup ran for an invalid device:\n%s", calls())
		}
	})
	t.Run("a failed detach is an error naming the device", func(t *testing.T) {
		dir, _ := toolShims(t)
		if err := os.WriteFile(filepath.Join(dir, "fail-losetup"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := DetachLoop(ctx, "/dev/loop3"); err == nil || !strings.Contains(err.Error(), "/dev/loop3") {
			t.Fatalf("error = %v, want it to name /dev/loop3", err)
		}
	})
}

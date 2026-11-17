// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// With PBS replies delayed, PVE's status read of a local overlay
// storage stalled 2 min 19 s and failed with HTTP 596, failing the run.
// When PVE's check doesn't answer, the storage is checked on the node; any
// definite answer from PVE still stands.
func TestCheckOverlayStorageFallsBackOnlyWhenPVEDoesNotAnswer(t *testing.T) {
	var resolved []string
	o := New(&config.Plan{}, Options{NodeName: "pve1", OverlayStorage: "certistack-scratch", StateDir: t.TempDir()}, nil, nil)
	o.overlayVolumePathFn = func(_ context.Context, volume string) (string, error) {
		resolved = append(resolved, volume)
		return "/var/lib/vz/certistack-scratch/images/1/certistack-storage-check.qcow2", nil
	}
	// The storage is a plain directory storage, so no mount is expected.
	o.storageConfigFn = func(string) (localStorage, error) {
		return localStorage{Type: "dir", Path: "/var/lib/vz/certistack-scratch", Content: "images,rootdir"}, nil
	}
	free := int64(200 << 30)
	var checkedDir string
	o.freeBytesFn = func(dir string) (int64, error) { checkedDir = dir; return free, nil }

	for name, tc := range map[string]struct {
		pveErr   error
		freeGiB  int64
		wantErr  string
		fallback bool
	}{
		"PVE answers ok":          {},
		"PVE lost the request":    {pveErr: &pve.APIError{StatusCode: 596, Message: "lost in transit"}, freeGiB: 200, fallback: true},
		"PVE timed out":           {pveErr: context.DeadlineExceeded, freeGiB: 200, fallback: true},
		"lost, and no room":       {pveErr: &pve.APIError{StatusCode: 596}, freeGiB: 1, fallback: true, wantErr: "checked on the node"},
		"PVE says not file-based": {pveErr: errors.New(`overlay storage "certistack-scratch" is type "lvmthin"`), wantErr: "lvmthin"},
		"PVE says forbidden":      {pveErr: &pve.APIError{StatusCode: 403, Message: "permission denied"}, wantErr: "permission denied"},
	} {
		resolved, checkedDir = nil, ""
		free = tc.freeGiB << 30
		pveErr := tc.pveErr
		o.validateOverlayStorageFn = func(context.Context) error { return pveErr }
		warning, err := o.checkOverlayStorage(context.Background())
		if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.wantErr)
		}
		if wantWarning := tc.fallback && tc.wantErr == ""; (warning != "") != wantWarning || (wantWarning && !strings.Contains(warning, "did not answer")) {
			t.Errorf("%s: warning %q, want one: %v", name, warning, wantWarning)
		}
		if fellBack := checkedDir != ""; fellBack != tc.fallback {
			t.Errorf("%s: checked on the node %v, want %v", name, fellBack, tc.fallback)
		}
		if tc.fallback && (checkedDir != "/var/lib/vz/certistack-scratch" || len(resolved) != 1 || !strings.HasPrefix(resolved[0], "certistack-scratch:1/")) {
			t.Errorf("%s: checked %q via %v", name, checkedDir, resolved)
		}
	}
}

func TestLocalOverlayStorageDirRefusesAnOddPath(t *testing.T) {
	o := New(&config.Plan{}, Options{NodeName: "pve1", StateDir: t.TempDir()}, nil, nil)
	o.overlayVolumePathFn = func(context.Context, string) (string, error) { return "/dev/pve/vm-1-disk-0", nil }
	if _, err := o.localOverlayStorageDir(context.Background(), "local-lvm"); err == nil {
		t.Fatal("a block storage resolved to a directory")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakePVEVersion is a PVE API that answers /version with version.
func fakePVEVersion(t *testing.T, version string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/version") {
			requests.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"version": version, "release": "x", "repoid": "y"}})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

// fakeBackupClient puts a proxmox-backup-client on PATH that writes script's
// output; the version command is the only one it answers.
func fakeBackupClient(t *testing.T, output string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n[ \"$1\" = version ] || exit 2\nprintf '%s' '" + output + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func versionOptions(t *testing.T, url string, worker bool) Options {
	t.Helper()
	return Options{ScratchDir: t.TempDir(), StateDir: t.TempDir(), PVEURL: url, PVETokenID: "certistack@pve!doctor", PVETokenSecret: "s", RequirePVEConnectivity: worker}
}

// doctor and the node worker (run) both print the pair's status, from the
// versions PVE and the client report.
func TestCheckReportsTheProxmoxVersions(t *testing.T) {
	for _, tc := range []struct {
		name, pve, client string
		status, support   string
		detail            []string
	}{
		{"tested", "9.1.1", "client version: 4.2.5\nserver version: 4.2.7\n", "passed", "tested", []string{"PVE 9.1.1", "PBS 4.2.7", "proxmox-backup-client 4.2.5", "tested"}},
		{"untested", "8.3.5", "client version: 3.3.7\nserver version: 3.4.0\n", "warning", "untested", []string{"PVE 8.3.5", "PBS 3.4.0", "proxmox-backup-client 3.3.7", "not covered by the release evidence"}},
		{"unsupported", "7.4-20", "client version: 4.2.5\nserver version: 4.2.7\n", "failed", "unsupported", []string{"PVE 7.4-20", "PBS 4.2.7", "unsupported", "older than PVE 8"}},
		{"unsupported PBS", "9.1.1", "client version: 2.4.1\nserver version: 2.4.7\n", "failed", "unsupported", []string{"PBS 2.4.7", "older than PBS 3"}},
		{"server not reached", "9.1.1", "client version: 4.2.5\n", "warning", "unknown", []string{"PBS unknown", "could not be read"}},
		{"garbage", "9.1.1", "no versions here\n", "warning", "unknown", []string{"PBS unknown", "proxmox-backup-client unknown"}},
	} {
		for _, worker := range []bool{false, true} {
			name := tc.name + ", doctor"
			if worker {
				name = tc.name + ", node worker"
			}
			t.Run(name, func(t *testing.T) {
				server, _ := fakePVEVersion(t, tc.pve)
				fakeBackupClient(t, tc.client)
				result := Check(context.Background(), nil, versionOptions(t, server.URL, worker))
				item := checkItem(result, "version_support")
				if item == nil {
					t.Fatalf("no version_support line: %+v", result.Checks)
				}
				if item.Status != tc.status {
					t.Errorf("status = %q (%s), want %q", item.Status, item.Detail, tc.status)
				}
				for _, want := range tc.detail {
					if !strings.Contains(item.Detail, want) {
						t.Errorf("detail %q lacks %q", item.Detail, want)
					}
				}
				if result.Versions == nil || result.Versions.Support != tc.support || result.Versions.PVE == "" {
					t.Errorf("versions = %+v, want support %q", result.Versions, tc.support)
				}
				if tc.support == "unsupported" && result.Ready {
					t.Error("an unsupported pair left the host ready")
				}
			})
		}
	}
}

// The PVE version comes from the request that proves connectivity: reading
// it sends no second request.
func TestVersionCheckSendsNoExtraPVERequest(t *testing.T) {
	server, requests := fakePVEVersion(t, "9.1.1")
	fakeBackupClient(t, "client version: 4.2.5\nserver version: 4.2.7\n")
	Check(context.Background(), nil, versionOptions(t, server.URL, true))
	if got := requests.Load(); got != 1 {
		t.Fatalf("preflight sent %d /version requests, want the one connectivity check", got)
	}
}

// A version that cannot be read is unknown: a warning, and never a reason by
// itself for the host not to be ready.
func TestUnreadableVersionsDoNotMakeTheHostNotReady(t *testing.T) {
	fakeBackupClient(t, "client version: 4.2.5\nserver version: 4.2.7\n")
	tested, _ := fakePVEVersion(t, "9.1.1")
	garbage, _ := fakePVEVersion(t, "<<not a version>>")
	reference := Check(context.Background(), nil, versionOptions(t, tested.URL, false))

	for name, url := range map[string]string{"garbage": garbage.URL, "no PVE configured": "", "unreachable": "http://127.0.0.1:1"} {
		// A refused connection is retried for 17 seconds; the test ends the wait.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		result := Check(ctx, nil, versionOptions(t, url, false))
		item := checkItem(result, "version_support")
		if item == nil || item.Status != "warning" || result.Versions == nil || result.Versions.Support != "unknown" || result.Versions.PVE != "unknown" {
			t.Errorf("%s: version_support = %+v, versions = %+v; want a warning and unknown", name, item, result.Versions)
		}
		if result.Ready != reference.Ready {
			t.Errorf("%s: an unreadable PVE version changed Ready from %v to %v", name, reference.Ready, result.Ready)
		}
	}
}

// With no proxmox-backup-client at all the client and server are unknown;
// the missing tool is the executable check's failure, not this one's.
func TestNoBackupClientLeavesItsVersionsUnknown(t *testing.T) {
	server, _ := fakePVEVersion(t, "9.1.1")
	t.Setenv("PATH", t.TempDir())
	result := Check(context.Background(), nil, versionOptions(t, server.URL, false))
	item := checkItem(result, "version_support")
	if item == nil || item.Status != "warning" || !strings.Contains(item.Detail, "proxmox-backup-client unknown") {
		t.Fatalf("version_support = %+v", item)
	}
	if exe := checkItem(result, "proxmox-backup-client"); exe == nil || exe.Status != "failed" {
		t.Fatalf("proxmox-backup-client check = %+v", exe)
	}
}

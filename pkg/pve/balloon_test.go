// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every Windows test source has balloon: 0, but PVE adds a balloon
// device to a VM created without the option, so the sandbox VM showed the
// guest hardware its source never had.
func TestCreateVMLeavesOutTheBalloonDeviceLikeTheSource(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cfg       VMConfig
		want      interface{}
		hardware  bool
		qmBalloon string
	}{
		{"source without balloon", VMConfig{NoBalloon: true}, float64(0), true, "0"},
		{"plan floor wins", VMConfig{NoBalloon: true, BalloonMB: 1024}, float64(1024), false, "1024"},
		{"source with balloon", VMConfig{}, nil, false, ""},
	} {
		var body map[string]interface{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:1:2:3:qmcreate:17011:tok:"`)})
		}))
		cfg := tc.cfg
		cfg.VMID, cfg.Name, cfg.Bridge = 17011, "balloon", "csVn70"
		cfg.DiskOverlays = []DiskOverlay{{Slot: "scsi0", Path: "/var/lib/vz/certistack-scratch/images/17011/x.qcow2", Volume: testOverlayVolume}}
		if _, err := NewClient(Config{BaseURL: server.URL}).CreateVM(context.Background(), "pve1", cfg); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		server.Close()
		if got, present := body["balloon"]; got != tc.want || (tc.want == nil && present) {
			t.Fatalf("%s: balloon = %v (present %v), want %v", tc.name, got, present, tc.want)
		}
		if hw := cfg.EffectiveHardware(); hw.NoBalloon != tc.hardware {
			t.Fatalf("%s: evidence NoBalloon = %v, want %v", tc.name, hw.NoBalloon, tc.hardware)
		}
		args := strings.Join(localQMCreateArgs(cfg, "win10", 2, 1, 2048, "virtio-scsi-single", "t", "d", "virtio=BC:24:11:00:00:01,bridge=csVn70", cfg.DiskOverlays), " ")
		if tc.qmBalloon == "" && strings.Contains(args, "--balloon") || tc.qmBalloon != "" && !strings.Contains(args, "--balloon "+tc.qmBalloon) {
			t.Fatalf("%s: local qm args %q, want balloon %q", tc.name, args, tc.qmBalloon)
		}
	}
}

// The sandbox VM keeps the backup's SMBIOS identity, as a restore does;
// without one PVE generates a new identity as before.
func TestCreateVMKeepsTheSourceSMBIOSIdentity(t *testing.T) {
	const smbios1 = "uuid=8b0e2d6a-4f1c-4c3e-9a55-0d2b8c6e7f10,base64=1,manufacturer=UVVFTVU="
	for _, want := range []string{smbios1, ""} {
		var body map[string]interface{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:1:2:3:qmcreate:17011:tok:"`)})
		}))
		cfg := VMConfig{VMID: 17011, Name: "smbios", Bridge: "csVn70", SMBIOS1: want,
			DiskOverlays: []DiskOverlay{{Slot: "scsi0", Path: "/var/lib/vz/certistack-scratch/images/17011/x.qcow2", Volume: testOverlayVolume}}}
		if _, err := NewClient(Config{BaseURL: server.URL}).CreateVM(context.Background(), "pve1", cfg); err != nil {
			t.Fatal(err)
		}
		server.Close()
		got, present := body["smbios1"]
		if want == "" && present || want != "" && got != want {
			t.Fatalf("smbios1 = %v (present %v), want %q", got, present, want)
		}
		args := strings.Join(localQMCreateArgs(cfg, "win10", 2, 1, 2048, "virtio-scsi-single", "t", "d", "virtio=BC:24:11:00:00:01,bridge=csVn70", cfg.DiskOverlays), " ")
		if want == "" && strings.Contains(args, "--smbios1") || want != "" && !strings.Contains(args, "--smbios1 "+want) {
			t.Fatalf("local qm args %q, want smbios1 %q", args, want)
		}
	}
}

// The sandbox VM gets the source's CD-ROM drives empty, never in place of a
// restored disk; a token without VM.Config.CDROM falls back to root's local
// qm, or else creates the VM without them.
func TestCreateVMAttachesEmptyCDROMs(t *testing.T) {
	cfg := VMConfig{VMID: 17011, Name: "cd", Bridge: "csVn70", EmptyCDROMs: []string{"sata0", "scsi0", "virtio1", "ide2"},
		DiskOverlays: []DiskOverlay{{Slot: "scsi0", Path: "/var/lib/vz/certistack-scratch/images/17011/x.qcow2", Volume: testOverlayVolume}}}
	var bodies []map[string]interface{}
	refuse := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		if refuse > 0 {
			refuse--
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(APIResponse{Message: "Permission check failed (/vms/17011, VM.Config.CDROM)"})
			return
		}
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:1:2:3:qmcreate:17011:tok:"`)})
	}))
	defer server.Close()

	if _, err := NewClient(Config{BaseURL: server.URL}).CreateVM(context.Background(), "pve1", cfg); err != nil {
		t.Fatal(err)
	}
	if bodies[0]["sata0"] != "none,media=cdrom" || bodies[0]["ide2"] != "none,media=cdrom" || bodies[0]["virtio1"] != nil ||
		!strings.HasPrefix(bodies[0]["scsi0"].(string), testOverlayVolume) {
		t.Fatalf("create body = %v", bodies[0])
	}
	args := strings.Join(localQMCreateArgs(cfg, "win10", 2, 1, 2048, "virtio-scsi-single", "t", "d", "virtio=BC:24:11:00:00:01,bridge=csVn70", cfg.DiskOverlays), " ")
	if !strings.Contains(args, "--sata0 none,media=cdrom") || !strings.Contains(args, "--ide2 none,media=cdrom") || strings.Contains(args, "--scsi0 none") {
		t.Fatalf("local qm args %q", args)
	}

	// Refused, no local qm: created again without the CD-ROM drives.
	bodies, refuse = nil, 1
	if _, err := NewClient(Config{BaseURL: server.URL}).CreateVM(context.Background(), "pve1", cfg); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || bodies[1]["sata0"] != nil || bodies[1]["ide2"] != nil || bodies[1]["scsi0"] == nil {
		t.Fatalf("retry bodies = %v", bodies)
	}
	// Refused, root on the node: local qm attaches them.
	bodies, refuse = nil, 1
	client := NewClient(Config{BaseURL: server.URL})
	client.isRootFn = func() bool { return true }
	client.isLocalNodeFn = func(string) bool { return true }
	var qmArgs []string
	client.runQMFn = func(_ context.Context, args []string) error { qmArgs = args; return nil }
	if upid, err := client.CreateVM(context.Background(), "pve1", cfg); err != nil || !strings.HasPrefix(upid, localQMTaskPrefix) ||
		!strings.Contains(strings.Join(qmArgs, " "), "--sata0 none,media=cdrom") {
		t.Fatalf("local fallback: %q, %v, %v", upid, err, qmArgs)
	}
}

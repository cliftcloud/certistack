// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// limitsServer counts the requests that reach it and answers a create.
func limitsServer(t *testing.T) (*Client, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:1:2:3:qmcreate:9101:tok:"`)})
	}))
	t.Cleanup(server.Close)
	return NewClient(Config{BaseURL: server.URL}), &requests
}

func limitsConfig(vmid int) VMConfig {
	volume := fmt.Sprintf("certistack-scratch:%d/certistack-delta-vm%d-scsi0-1790184983835370240-0.qcow2", vmid, vmid)
	return VMConfig{
		VMID: vmid, Name: "limits", Bridge: "csVn70",
		DiskOverlays: []DiskOverlay{{Slot: "scsi0", Path: "/var/lib/vz/certistack-scratch/images/x.qcow2", Volume: volume}},
	}
}

// A VM ID outside 100..999999999 is not one PVE has, and init never
// allocates one; the client used to send any positive number.
func TestClientRefusesAVMIDOutsideProxmoxsRange(t *testing.T) {
	for _, vmid := range []int{-1, 0, 1, 99, 1000000000} {
		client, requests := limitsServer(t)
		ctx := context.Background()
		for operation, call := range map[string]func() error{
			"create":  func() error { _, err := client.CreateVM(ctx, "pve1", limitsConfig(vmid)); return err },
			"start":   func() error { _, err := client.StartVM(ctx, "pve1", vmid); return err },
			"stop":    func() error { _, err := client.StopVM(ctx, "pve1", vmid); return err },
			"destroy": func() error { _, err := client.DestroyVM(ctx, "pve1", vmid); return err },
			"status":  func() error { _, err := client.GetVMStatus(ctx, "pve1", vmid); return err },
			"config":  func() error { _, err := client.GetVMConfig(ctx, "pve1", vmid); return err },
			"in use":  func() error { _, err := client.IsVMIDInUse(ctx, vmid); return err },
		} {
			if err := call(); err == nil || !strings.Contains(err.Error(), "invalid VMID") {
				t.Errorf("%s with VMID %d: error = %v", operation, vmid, err)
			}
		}
		if got := requests.Load(); got != 0 {
			t.Errorf("VMID %d reached PVE %d time(s)", vmid, got)
		}
	}
	for _, vmid := range []int{100, 999999999} {
		client, requests := limitsServer(t)
		if _, err := client.CreateVM(context.Background(), "pve1", limitsConfig(vmid)); err != nil {
			t.Errorf("VMID %d refused: %v", vmid, err)
		}
		if requests.Load() == 0 {
			t.Errorf("VMID %d never reached PVE", vmid)
		}
	}
}

// A VM is created only with hardware inside the ranges a backup's configuration
// is held to. A negative balloon used to stay in the recorded hardware while
// the create request left it out, and values above the maxima were sent as they
// were.
func TestCreateVMRefusesHardwareOutsideItsRanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*VMConfig)
	}{
		{"negative cores", func(c *VMConfig) { c.Cores = -1 }},
		{"cores above 256", func(c *VMConfig) { c.Cores = 257 }},
		{"negative sockets", func(c *VMConfig) { c.Sockets = -2 }},
		{"sockets above 16", func(c *VMConfig) { c.Sockets = 17 }},
		{"negative memory", func(c *VMConfig) { c.MemoryMB = -3 }},
		{"memory above 4 TiB", func(c *VMConfig) { c.MemoryMB = 4194305 }},
		{"negative balloon", func(c *VMConfig) { c.BalloonMB = -4 }},
		{"balloon above 4 TiB", func(c *VMConfig) { c.BalloonMB = 4194305 }},
		{"negative CPU weight", func(c *VMConfig) { c.CPUWeight = -5 }},
		{"CPU weight above 262144", func(c *VMConfig) { c.CPUWeight = 262145 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, requests := limitsServer(t)
			cfg := limitsConfig(9101)
			tc.mutate(&cfg)
			if _, err := client.CreateVM(context.Background(), "pve1", cfg); err == nil || !strings.Contains(err.Error(), "must be between") {
				t.Fatalf("error = %v", err)
			}
			if _, err := cfg.CreateParams(); err == nil {
				t.Fatal("the plan preview shows a create request the run would refuse")
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("reached PVE %d time(s)", got)
			}
		})
	}
	// Each maximum, and unset, are still created.
	client, _ := limitsServer(t)
	cfg := limitsConfig(9101)
	cfg.Cores, cfg.Sockets, cfg.MemoryMB, cfg.BalloonMB, cfg.CPUWeight = 256, 16, 4194304, 4194304, 262144
	if _, err := client.CreateVM(context.Background(), "pve1", cfg); err != nil {
		t.Fatalf("the maxima were refused: %v", err)
	}
	if _, err := client.CreateVM(context.Background(), "pve1", limitsConfig(9101)); err != nil {
		t.Fatalf("unset hardware was refused: %v", err)
	}
}

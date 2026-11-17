// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// The sandbox VM's boot order is the source's order restricted to the disks it
// was given, not its boot disk alone. A guest with /boot on a second disk (a
// Rocky 9 VM with "boot: order=scsi0;scsi1" at the source) restored with
// "order=scsi0" never comes up: SeaBIOS exposes only the disks in the order,
// and GRUB cannot read /boot on scsi1.

func bootOrderConfig(slots []string, bootDisk string, order []string) VMConfig {
	cfg := VMConfig{VMID: 7615, Name: "boot-order", Bridge: "csVn70", BootDisk: bootDisk, BootOrder: order}
	for _, slot := range slots {
		cfg.DiskOverlays = append(cfg.DiskOverlays, DiskOverlay{Slot: slot, Volume: fmt.Sprintf("certistack-scratch:7615/certistack-delta-vm7615-%s-1-0.qcow2", slot)})
	}
	return cfg
}

// cliBootArg is the value the local qm fallback passes to --boot.
func cliBootArg(t *testing.T, cfg VMConfig) string {
	t.Helper()
	req, err := cfg.createRequest()
	if err != nil {
		t.Fatal(err)
	}
	args := localQMCreateArgs(cfg, req.ostype, req.cores, req.sockets, req.memory, req.scsiHW, req.tags, req.desc, req.netStr, req.disks)
	for i, arg := range args {
		if arg == "--boot" && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatalf("qm args %v carry no --boot", args)
	return ""
}

func TestSandboxBootOrderIsTheSourceOrderOfTheRestoredDisks(t *testing.T) {
	for name, tc := range map[string]struct {
		slots    []string
		bootDisk string
		order    []string
		want     string
	}{
		"one disk":                            {[]string{"scsi0"}, "scsi0", []string{"scsi0"}, "order=scsi0"},
		"two disks, boot disk first":          {[]string{"scsi0", "scsi1"}, "scsi0", []string{"scsi0", "scsi1"}, "order=scsi0;scsi1"},
		"two disks, second disk first":        {[]string{"scsi0", "scsi1"}, "scsi1", []string{"scsi1", "scsi0"}, "order=scsi1;scsi0"},
		"disks on three buses":                {[]string{"sata1", "scsi0", "virtio0"}, "virtio0", []string{"virtio0", "scsi0", "sata1"}, "order=virtio0;scsi0;sata1"},
		"cdrom and network are not disks":     {[]string{"scsi0", "scsi1"}, "scsi0", []string{"scsi0", "ide2", "net0"}, "order=scsi0"},
		"network between disks":               {[]string{"scsi0", "scsi1"}, "scsi0", []string{"scsi0", "net0", "scsi1"}, "order=scsi0;scsi1"},
		"a disk the plan left out":            {[]string{"scsi0", "scsi2"}, "scsi0", []string{"scsi0", "scsi1", "scsi2"}, "order=scsi0;scsi2"},
		"the first disk left out":             {[]string{"scsi0"}, "scsi0", []string{"scsi1", "scsi0"}, "order=scsi0"},
		"duplicates collapse":                 {[]string{"scsi0", "scsi1"}, "scsi0", []string{"scsi0", "scsi0", "scsi1"}, "order=scsi0;scsi1"},
		"boot disk leads a disagreeing order": {[]string{"scsi0", "scsi1"}, "scsi1", []string{"scsi0", "scsi1"}, "order=scsi1;scsi0"},
		"order names none: the boot disk":     {[]string{"scsi0", "scsi1"}, "scsi1", []string{"net0"}, "order=scsi1"},
		"no order: the boot disk alone":       {[]string{"scsi0", "scsi1"}, "scsi1", nil, "order=scsi1"},
		"no order, no boot disk: PVE first":   {[]string{"scsi1", "scsi0"}, "", nil, "order=scsi0"},
		"order without a boot disk":           {[]string{"scsi0", "scsi1"}, "", []string{"scsi1", "scsi0"}, "order=scsi1;scsi0"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := bootOrderConfig(tc.slots, tc.bootDisk, tc.order)
			params, err := cfg.CreateParams()
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := params["boot"].(string); got != tc.want {
				t.Errorf("REST create body boot = %q, want %q", got, tc.want)
			}
			if got := cliBootArg(t, cfg); got != tc.want {
				t.Errorf("qm create --boot = %q, want %q", got, tc.want)
			}
			if got := strings.Join(cfg.EffectiveHardware().BootOrder, ";"); "order="+got != tc.want {
				t.Errorf("EffectiveHardware boot order %q is not what the request sends (%q)", got, tc.want)
			}
		})
	}
}

// A UEFI guest's efidisk0 and tpmstate0 are firmware state, never part of the
// boot order, whatever the order handed in says.
func TestSandboxBootOrderLeavesFirmwareStateOut(t *testing.T) {
	cfg := uefiVMConfig()
	cfg.DiskOverlays = append(cfg.DiskOverlays, DiskOverlay{Slot: "scsi1", Volume: "certistack-scratch:17301/certistack-delta-vm17301-scsi1-1-0.qcow2"})
	cfg.BootDisk, cfg.BootOrder = "scsi0", []string{"efidisk0", "scsi0", "tpmstate0", "scsi1", "net0"}
	params, err := cfg.CreateParams()
	if err != nil {
		t.Fatal(err)
	}
	if params["boot"] != "order=scsi0;scsi1" || params["efidisk0"] == nil || params["tpmstate0"] == nil {
		t.Fatalf("UEFI create body boot %v, efidisk0 %v, tpmstate0 %v; want order=scsi0;scsi1 with both firmware volumes attached", params["boot"], params["efidisk0"], params["tpmstate0"])
	}
	if got := cliBootArg(t, cfg); got != "order=scsi0;scsi1" {
		t.Errorf("qm create --boot = %q, want order=scsi0;scsi1", got)
	}
}

// Over the wire: the REST body PVE receives carries both disks in the source
// order, and the local qm fallback (used when PVE refuses an arbitrary path)
// passes the same order as one argument.
func TestCreateVMSendsBothDisksInTheSourceBootOrder(t *testing.T) {
	var createBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&createBody)
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:1:2:3:qmcreate:7615:tok:"`)})
	}))
	defer server.Close()
	cfg := bootOrderConfig([]string{"scsi0", "scsi1"}, "scsi0", []string{"scsi0", "scsi1"})
	if _, err := NewClient(Config{BaseURL: server.URL}).CreateVM(context.Background(), "pve1", cfg); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if got, _ := createBody["boot"].(string); got != "order=scsi0;scsi1" {
		t.Errorf("boot = %q, want order=scsi0;scsi1 (the VM's /boot is on scsi1, which SeaBIOS exposes only when it is in the order)", got)
	}

	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"data":null,"message":"Only root can pass arbitrary filesystem paths."}`))
	}))
	defer denied.Close()
	client := NewClient(Config{BaseURL: denied.URL})
	client.isRootFn = func() bool { return true }
	client.isLocalNodeFn = func(string) bool { return true }
	var gotArgs []string
	client.runQMFn = func(_ context.Context, args []string) error {
		gotArgs = append([]string(nil), args...)
		return nil
	}
	cfg.DiskOverlays = []DiskOverlay{
		{Slot: "scsi0", Path: "/var/lib/certistack/scsi0.qcow2"},
		{Slot: "scsi1", Path: "/var/lib/certistack/scsi1.qcow2"},
	}
	if _, err := client.CreateVM(context.Background(), "pve1", cfg); err != nil {
		t.Fatalf("CreateVM through local qm: %v", err)
	}
	if !strings.Contains(strings.Join(gotArgs, " "), "--boot order=scsi0;scsi1") {
		t.Errorf("qm args %q do not carry --boot order=scsi0;scsi1", gotArgs)
	}
}

func TestBootOrderRefusesABootDiskTheVMDoesNotHave(t *testing.T) {
	cfg := bootOrderConfig([]string{"scsi0", "scsi1"}, "scsi2", []string{"scsi2", "scsi0"})
	if _, err := cfg.CreateParams(); err == nil || !strings.Contains(err.Error(), "not one of the VM's disks") {
		t.Fatalf("a boot disk outside the VM: err %v", err)
	}
}

func TestEffectiveBootOrderIsACopy(t *testing.T) {
	order := []string{"scsi0", "scsi1"}
	cfg := bootOrderConfig([]string{"scsi0", "scsi1"}, "scsi0", order)
	hw := cfg.EffectiveHardware()
	hw.BootOrder[0] = "tampered"
	if !reflect.DeepEqual(order, []string{"scsi0", "scsi1"}) || cfg.BootOrder[0] != "scsi0" {
		t.Fatalf("the hardware's boot order aliases the configuration's: %v", order)
	}
}

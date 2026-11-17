// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDurableOwnershipRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "active.json")

	orig := Record{
		RunID:       "run-12345",
		Phase:       "probing",
		UpdatedAt:   time.Now().UTC().Truncate(time.Second),
		Scratch:     dir,
		LoopDevice:  "/dev/loop42",
		LoopBacking: "vm/100/2026-01-01T00:00:00Z/drive-scsi0.img",
		Mapper: Process{
			PID:        1001,
			StartTicks: "998877",
		},
		QEMU: Process{
			PID:        1002,
			StartTicks: "998899",
		},
	}

	orig.AddLoop("/dev/loop42", "vm/100/2026-01-01T00:00:00Z/drive-scsi0.img")
	orig.AddLoop("/dev/loop43", "vm/101/2026-01-01T00:00:00Z/drive-scsi0.img")
	orig.AddVM(9100, "node1", 1002, "998899")
	orig.AddVM(9101, "node1", 1003, "998900")
	orig.AddSDNZone("cs_sb_run123")
	orig.AddSDNVNet("cs_vn_run123")
	orig.AddHostAddress("cs_vn_run123", "10.100.0.1/24")
	orig.AddHostAddress("cs_vn_run123", "10.100.0.1/24")
	orig.AddDeltaFile(filepath.Join(dir, "certistack-delta-vm9100-1.qcow2"))

	if err := Write(path, orig); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.RunID != orig.RunID {
		t.Errorf("RunID mismatch: got %s, want %s", loaded.RunID, orig.RunID)
	}
	if loaded.LoopDevice != orig.LoopDevice {
		t.Errorf("LoopDevice mismatch: got %s, want %s", loaded.LoopDevice, orig.LoopDevice)
	}
	if len(loaded.Loops) != 2 {
		t.Errorf("expected 2 loops, got %d", len(loaded.Loops))
	}
	if len(loaded.VMs) != 2 {
		t.Errorf("expected 2 VMs, got %d", len(loaded.VMs))
	}
	if len(loaded.SDNZones) != 1 || loaded.SDNZones[0] != "cs_sb_run123" {
		t.Errorf("expected SDN zone cs_sb_run123, got %v", loaded.SDNZones)
	}
	if len(loaded.DeltaFiles) != 1 {
		t.Errorf("expected 1 delta file, got %d", len(loaded.DeltaFiles))
	}
	if len(loaded.HostAddresses) != 1 || loaded.HostAddresses[0].CIDR != "10.100.0.1/24" {
		t.Errorf("expected one host probe address, got %v", loaded.HostAddresses)
	}
}

func TestLoadRejectsOversizedJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxJournalBytes+1); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), path+" is larger than 1048576 bytes") {
		t.Fatalf("Load oversized journal error = %v", err)
	}
}

func TestMapIntentsResolveAndSurviveARoundTrip(t *testing.T) {
	var r Record
	at := time.Date(2026, 9, 27, 13, 0, 0, 0, time.FixedZone("CDT", -5*3600))
	first := r.AddMapIntent("vm/1/2026-09-27T03:00:00Z", "drive-scsi0.img", `\x3avm-1`, at)
	second := r.AddMapIntent("vm/1/2026-09-27T03:00:00Z", "drive-scsi1.img", `\x3avm-1b`, at)
	r.ResolveMapIntent(first, "/dev/loop3")
	r.ResolveMapIntent(99, "/dev/loop9") // out of range: ignored
	open := r.UnresolvedMapIntents()
	if len(open) != 1 || open[0].Archive != "drive-scsi1.img" || second != 1 {
		t.Fatalf("unresolved = %+v", open)
	}
	path := filepath.Join(t.TempDir(), "active.json")
	if err := Write(path, r); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.MapIntents) != 2 || back.MapIntents[0].Device != "/dev/loop3" || !back.MapIntents[1].At.Equal(at) || back.MapIntents[1].At.Location() != time.UTC {
		t.Fatalf("round trip = %+v", back.MapIntents)
	}
}

// A map intent records what it maps from, the token its processes
// carry, and the processes recovery proves are its own; recovery changes
// the record's intents in place. The fields are additive: a journal
// without them loads with none, and an intent without them is written
// without them.
func TestMapIntentOwnershipIsAdditive(t *testing.T) {
	var r Record
	at := time.Date(2026, 9, 27, 13, 0, 0, 0, time.UTC)
	first := r.AddMapIntent("vm/1/2026-09-27T03:00:00Z", "drive-scsi0.img", `\x3avm-1`, at)
	r.AddMapIntent("vm/1/2026-09-27T03:00:00Z", "drive-scsi1.img", `\x3avm-1b`, at)
	r.SetMapIntentIdentity(first, "0123abcd", "feedface")
	r.SetMapIntentIdentity(7, "ignored", "ignored")
	r.ResolveMapIntent(1, "/dev/loop4")
	open := r.OpenMapIntents()
	if len(open) != 1 || open[0] != &r.MapIntents[0] {
		t.Fatalf("open = %v", open)
	}
	open[0].AddProcess(Process{PID: 4242, StartTicks: "99"})
	open[0].AddProcess(Process{PID: 4242, StartTicks: "99"})
	path := filepath.Join(t.TempDir(), "active.json")
	if err := Write(path, r); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := back.MapIntents[0]
	if got.Owner != "0123abcd" || got.Token != "feedface" || len(got.Processes) != 1 || got.Processes[0] != (Process{PID: 4242, StartTicks: "99"}) {
		t.Fatalf("intent = %+v", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), `"owner"`) != 1 || strings.Count(string(data), `"token"`) != 1 || strings.Count(string(data), `"processes"`) != 1 {
		t.Fatalf("a legacy-shaped intent gained fields:\n%s", data)
	}

	legacy := `{"run_id":"run-earlier-1","phase":"mapping","map_intents":[{"snapshot":"vm/1/2026-09-27T03:00:00Z","archive":"drive-scsi0.img","name_suffix":"x","at":"2026-09-27T13:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := Load(path)
	if err != nil || len(old.OpenMapIntents()) != 1 || old.MapIntents[0].Owner != "" || old.MapIntents[0].Token != "" || old.MapIntents[0].Processes != nil {
		t.Fatalf("journal without the fields = %+v, %v", old, err)
	}
}

// A delta file's identity round-trips, is dropped with its path, and a
// journal without identities loads with none.
func TestDeltaFileIdentityRoundTripsAndOldJournalsHaveNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	rec := Record{RunID: "run-identity", Phase: "running", UpdatedAt: time.Now().UTC()}
	rec.AddDeltaFile("/scratch/staging.part-0123")
	rec.SetDeltaFile("/scratch/overlay.qcow2", FileIdentity{Dev: 66305, Ino: 1234567, BtimeNS: 1780000000123456789})
	if err := Write(path, rec); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := loaded.DeltaIdentity("/scratch/overlay.qcow2")
	if !ok || id.Dev != 66305 || id.Ino != 1234567 || id.BtimeNS != 1780000000123456789 {
		t.Fatalf("identity after a round trip = %+v, %v", id, ok)
	}
	if _, ok := loaded.DeltaIdentity("/scratch/staging.part-0123"); ok || len(loaded.DeltaFiles) != 2 {
		t.Fatalf("a path without an identity gained one, or paths were lost: %+v", loaded)
	}

	loaded.DropDeltaFile("/scratch/overlay.qcow2")
	if len(loaded.DeltaFiles) != 1 || loaded.DeltaFiles[0] != "/scratch/staging.part-0123" || len(loaded.DeltaIdentities) != 0 {
		t.Fatalf("after dropping the file: %+v", loaded)
	}
	loaded.DropDeltaFile("/scratch/never-there")

	old := `{"run_id":"run-earlier-1","phase":"running","updated_at":"2026-09-28T00:00:00Z","scratch":"/scratch","delta_files":["/scratch/certistack-delta-vm9100-1.qcow2"]}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.DeltaIdentity("/scratch/certistack-delta-vm9100-1.qcow2"); ok || len(loaded.DeltaFiles) != 1 {
		t.Fatalf("a journal without identities loaded as %+v", loaded)
	}
}

// A host address record carries the kernel identities of the interface
// and containment table, drops when its removal is confirmed, and a record
// without them loads with none.
func TestHostAddressIdentityRoundTripsAndDrops(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	rec := Record{RunID: "run-identity", Phase: "running", UpdatedAt: time.Now().UTC()}
	rec.AddHostAddress("csVn01", "10.100.0.1/24")
	rec.AddHostContainment("csVn02", "10.100.1.1/24")
	rec.SetHostAddressIdentity("csVn01", "10.100.0.1/24", 5, 41)
	rec.SetHostAddressIdentity("csVn02", "10.100.1.1/24", 0, 42) // an unreadable index leaves none
	if err := Write(path, rec); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.HostAddresses) != 2 || loaded.HostAddresses[0].IfIndex != 5 || loaded.HostAddresses[0].TableHandle != 41 ||
		loaded.HostAddresses[1].IfIndex != 0 || loaded.HostAddresses[1].TableHandle != 42 || !loaded.HostAddresses[1].ContainmentOnly {
		t.Fatalf("host addresses after a round trip = %+v", loaded.HostAddresses)
	}
	loaded.DropHostAddress("csVn01", "10.100.0.1/24")
	if len(loaded.HostAddresses) != 1 || loaded.HostAddresses[0].Interface != "csVn02" {
		t.Fatalf("after dropping one: %+v", loaded.HostAddresses)
	}
	loaded.DropHostAddress("csVn09", "10.9.9.1/24") // not registered: nothing happens

	old := `{"run_id":"run-earlier-1","phase":"running","updated_at":"2026-09-28T00:00:00Z","scratch":"/scratch","host_addresses":[{"interface":"csVn01","cidr":"10.100.0.1/24"}]}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err = Load(path)
	if err != nil || len(loaded.HostAddresses) != 1 || loaded.HostAddresses[0].IfIndex != 0 || loaded.HostAddresses[0].TableHandle != 0 {
		t.Fatalf("a journal without identities loaded as %+v, %v", loaded.HostAddresses, err)
	}
}

// An address whose removal went through while its containment table's did not
// is kept as a containment-only record, with the identities it had, so the
// retry removes the table and does not delete the address again. A record that
// matches nothing is left as it is, and so is another address of the interface.
func TestSetHostContainmentOnlyKeepsTheIdentitiesAndTouchesOneRecord(t *testing.T) {
	rec := Record{RunID: "run-containment-only"}
	rec.AddHostAddress("csVn01", "10.100.0.1/24")
	rec.AddHostAddress("csVn01", "10.100.1.1/24")
	rec.SetHostAddressIdentity("csVn01", "10.100.0.1/24", 5, 41)
	rec.SetHostContainmentOnly("csVn01", "10.100.0.1/24")
	rec.SetHostContainmentOnly("csVn09", "10.9.9.1/24") // not registered: nothing happens
	want := []TrackedHostAddress{
		{Interface: "csVn01", CIDR: "10.100.0.1/24", ContainmentOnly: true, IfIndex: 5, TableHandle: 41},
		{Interface: "csVn01", CIDR: "10.100.1.1/24"},
	}
	if len(rec.HostAddresses) != 2 || rec.HostAddresses[0] != want[0] || rec.HostAddresses[1] != want[1] {
		t.Fatalf("host addresses = %+v, want %+v", rec.HostAddresses, want)
	}
}

// A host address record carries the boot its identities were captured in; the
// boot is kept when the record becomes containment-only, an empty boot leaves
// what is recorded, and a journal without the boot loads with none.
func TestHostAddressBootRoundTripsAndIsKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	rec := Record{RunID: "run-boot", Phase: "running", UpdatedAt: time.Now().UTC()}
	rec.AddHostAddress("csVn01", "10.100.0.1/24")
	rec.AddHostAddress("csVn01", "10.100.1.1/24")
	rec.SetHostAddressIdentity("csVn01", "10.100.0.1/24", 5, 41)
	rec.SetHostAddressBoot("csVn01", "10.100.0.1/24", "boot-one")
	rec.SetHostAddressBoot("csVn01", "10.100.0.1/24", "") // an unreadable boot leaves what is recorded
	rec.SetHostAddressBoot("csVn09", "10.9.9.1/24", "boot-one")
	rec.SetHostContainmentOnly("csVn01", "10.100.0.1/24")
	if err := Write(path, rec); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []TrackedHostAddress{
		{Interface: "csVn01", CIDR: "10.100.0.1/24", ContainmentOnly: true, IfIndex: 5, TableHandle: 41, BootID: "boot-one"},
		{Interface: "csVn01", CIDR: "10.100.1.1/24"},
	}
	if len(loaded.HostAddresses) != 2 || loaded.HostAddresses[0] != want[0] || loaded.HostAddresses[1] != want[1] {
		t.Fatalf("host addresses after a round trip = %+v, want %+v", loaded.HostAddresses, want)
	}

	old := `{"run_id":"run-earlier-1","phase":"running","updated_at":"2026-09-28T00:00:00Z","scratch":"/scratch","host_addresses":[{"interface":"csVn01","cidr":"10.100.0.1/24","ifindex":5,"nft_handle":41}]}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded, err = Load(path); err != nil || len(loaded.HostAddresses) != 1 || loaded.HostAddresses[0].BootID != "" || loaded.HostAddresses[0].IfIndex != 5 {
		t.Fatalf("a journal without the boot loaded as %+v, %v", loaded.HostAddresses, err)
	}
}

func leftoverTempFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".certistack-write-") {
			left = append(left, entry.Name())
		}
	}
	return left
}

// AtomicWrite either replaces the file whole or fails and leaves the old one and
// no temporary file behind.
func TestAtomicWriteFailurePathsLeaveTheOldFileAndNoTemp(t *testing.T) {
	t.Run("replaces whole", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "active.json")
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := AtomicWrite(path, []byte("new")); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(path); string(got) != "new" {
			t.Fatalf("file = %q", got)
		}
		if left := leftoverTempFiles(t, dir); len(left) != 0 {
			t.Fatalf("temporary files left: %v", left)
		}
	})
	t.Run("the target is a directory: rename fails, temp removed", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "active.json")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		err := AtomicWrite(path, []byte("data"))
		if err == nil || !strings.Contains(err.Error(), "rename") {
			t.Fatalf("AtomicWrite = %v, want a rename failure", err)
		}
		if info, statErr := os.Stat(path); statErr != nil || !info.IsDir() {
			t.Fatalf("the directory at the target was disturbed: %v", statErr)
		}
		if left := leftoverTempFiles(t, dir); len(left) != 0 {
			t.Fatalf("temporary files left after a failed write: %v", left)
		}
	})
	t.Run("the parent cannot be created", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "file")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := AtomicWrite(filepath.Join(blocker, "sub", "active.json"), []byte("data"))
		if err == nil || !strings.Contains(err.Error(), "failed to create directory") {
			t.Fatalf("AtomicWrite = %v, want the directory failure", err)
		}
	})
}

func TestScreenshotFilesAreRecordedOnceAndDropped(t *testing.T) {
	var r Record
	r.AddScreenshotFiles("/s/a.ppm", "/s/a.png")
	r.AddScreenshotFiles("/s/a.png", "/s/b.ppm") // a path already recorded is not recorded again
	if len(r.ScreenshotFiles) != 3 {
		t.Fatalf("recorded %v, want three distinct paths", r.ScreenshotFiles)
	}
	r.DropScreenshotFiles("/s/a.ppm", "/s/unknown")
	if len(r.ScreenshotFiles) != 2 || r.ScreenshotFiles[0] != "/s/a.png" || r.ScreenshotFiles[1] != "/s/b.ppm" {
		t.Fatalf("after a drop: %v", r.ScreenshotFiles)
	}
	r.DropScreenshotFiles("/s/a.png", "/s/b.ppm")
	if len(r.ScreenshotFiles) != 0 {
		t.Fatalf("after dropping all: %v", r.ScreenshotFiles)
	}
	// It survives a write and a load.
	r.AddScreenshotFiles("/s/c.png")
	path := filepath.Join(t.TempDir(), "active.json")
	if err := Write(path, r); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || len(loaded.ScreenshotFiles) != 1 || loaded.ScreenshotFiles[0] != "/s/c.png" {
		t.Fatalf("loaded %+v, %v", loaded.ScreenshotFiles, err)
	}
}

// A recorded QEMU process keeps the boot it was recorded in, next to its PID
// and start time (which name a process only within one boot), for the VM's
// record and for the legacy QEMU field that mirrors the first VM. A journal
// without the boot loads without one, and a record without it is written
// without it.
func TestAVMProcessKeepsItsBootAndALegacyRecordHasNone(t *testing.T) {
	var r Record
	r.AddVMProcess(9100, "node1", Process{PID: 1002, StartTicks: "998899", BootID: "boot-a"})
	r.AddVM(9101, "node1", 1003, "998900")
	path := filepath.Join(t.TempDir(), "active.json")
	if err := Write(path, r); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Process{PID: 1002, StartTicks: "998899", BootID: "boot-a"}); back.VMs[0].Process != want || back.QEMU != want {
		t.Fatalf("VM 9100 = %+v, QEMU = %+v; want %+v for both", back.VMs[0].Process, back.QEMU, want)
	}
	if want := (Process{PID: 1003, StartTicks: "998900"}); back.VMs[1].Process != want {
		t.Fatalf("a VM added without a boot = %+v, want %+v", back.VMs[1].Process, want)
	}
	// Recording the same VM again replaces its process, boot included.
	back.AddVMProcess(9100, "node1", Process{PID: 2002, StartTicks: "5", BootID: "boot-b"})
	if want := (Process{PID: 2002, StartTicks: "5", BootID: "boot-b"}); back.VMs[0].Process != want {
		t.Fatalf("VM 9100 after a second record = %+v, want %+v", back.VMs[0].Process, want)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), `"boot_id"`) != 2 {
		t.Fatalf("the journal names a boot for each of the VM and the legacy QEMU record and for no other process:\n%s", data)
	}

	legacy := `{"run_id":"run-earlier-1","phase":"running","qemu":{"pid":1002,"start_ticks":"998899"},"vms":[{"vmid":9100,"node":"node1","process":{"pid":1002,"start_ticks":"998899"}}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := Load(path)
	if err != nil || old.QEMU.BootID != "" || old.VMs[0].Process.BootID != "" || old.VMs[0].Process.PID != 1002 {
		t.Fatalf("journal without the boot = %+v, %v", old, err)
	}
}

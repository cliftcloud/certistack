// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// inspectFixture is a node for an inspection: a private sysfs and a
// proxmox-backup-client that maps every disk to /dev/loop7 with a backing
// file of its own (map-1, map-2, ...); a losetup detaches it again. Files
// beside the client change what it does: failmap makes every map fail,
// keepmap makes the detach leave the loop attached.
type inspectFixture struct {
	t       *testing.T
	dir     string
	log     string
	backing string // the backing_file of /dev/loop7
}

func newInspectFixture(t *testing.T) *inspectFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	dir := t.TempDir()
	f := &inspectFixture{t: t, dir: dir, log: filepath.Join(dir, "calls.log"), backing: filepath.Join(dir, "sys", "loop7", "loop", "backing_file")}
	old := sysutil.SysBlockDir
	t.Cleanup(func() { sysutil.SysBlockDir = old })
	sysutil.SysBlockDir = filepath.Join(dir, "sys")
	if err := os.MkdirAll(filepath.Dir(f.backing), 0o755); err != nil {
		t.Fatal(err)
	}
	// PATH holds only this directory, so the script uses shell builtins and
	// /bin/rm by its path.
	client := `#!/bin/sh
printf '%s\n' "$1" >> '` + f.log + `'
case "$1" in
map)
  [ -e '` + filepath.Join(dir, "failmap") + `' ] && { echo 'map failed' >&2; exit 1; }
  n=0
  [ -e '` + filepath.Join(dir, "count") + `' ] && read n < '` + filepath.Join(dir, "count") + `'
  n=$((n + 1))
  echo "$n" > '` + filepath.Join(dir, "count") + `'
  case "$*" in *vm/100/*) id=100;; *vm/101/*) id=101;; esac
  printf '%s\n' "/run/pbs-loopdev/certistack-test-map-$n"'\x3avm-'"$id"'-2026\x2d10\x2d01T02\x3a00\x3a00Z-drive\x2dscsi0.img' > '` + f.backing + `'
  echo 'Image mapped to /dev/loop7'
  exit 0;;
unmap)
  [ -e '` + filepath.Join(dir, "keepmap") + `' ] || /bin/rm -f '` + f.backing + `'
  exit 0;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(client), 0o755); err != nil {
		t.Fatal(err)
	}
	// The release is losetup -d (the client's unmap is never run), which takes the
	// loop away as the kernel would unless keepmap says it stays.
	losetup := "#!/bin/sh\nprintf 'losetup %s\\n' \"$*\" >> '" + f.log + "'\n[ -e '" + filepath.Join(dir, "keepmap") + "' ] || /bin/rm -f '" + f.backing + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "losetup"), []byte(losetup), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	attempts, interval := loopSettleAttempts, loopSettleInterval
	t.Cleanup(func() { loopSettleAttempts, loopSettleInterval = attempts, interval })
	loopSettleAttempts, loopSettleInterval = 2, 10*time.Millisecond
	return f
}

func (f *inspectFixture) set(name string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), nil, 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// calls is what the fake commands were asked, one word each, the release of
// /dev/loop7 (losetup -d) as "detach": "unmap" would be the client's command.
func (f *inspectFixture) calls() string {
	data, _ := os.ReadFile(f.log)
	return strings.ReplaceAll(strings.Join(strings.Fields(string(data)), " "), "losetup -d /dev/loop7", "detach")
}

// inspector is an orchestrator for an inspection, as runner.Inspect makes
// one, and the journal it writes.
func inspector(t *testing.T) (*Orchestrator, string) {
	t.Helper()
	stateDir := t.TempDir()
	o := New(&config.Plan{}, Options{NodeName: "pve1", StateDir: stateDir, ScratchDir: t.TempDir(), RunID: "run-inspect-test"}, pbs.New(pbs.Config{Repository: "u@pbs!tok@pbs.example:store"}), nil)
	return o, filepath.Join(stateDir, "active.json")
}

func inspectTarget(vmid int) InspectTarget {
	return InspectTarget{SourceVMID: vmid, Snapshot: "vm/" + strconv.Itoa(vmid) + "/2026-10-01T02:00:00Z", Drives: []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}}
}

func loadJournal(t *testing.T, path string) journal.Record {
	t.Helper()
	record, err := journal.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// Each VM's backup is mapped through the run's own map, read, and released
// before the next one is mapped. While a backup is read, the journal holds
// exactly what a run's journal holds for its maps (the intent with its owner
// and token, the loop with its backing identity, phase running), so a worker
// killed then is recovered by the node's next run like any interrupted run.
// Once a map is shown released the journal forgets it: the second VM's map
// gets the same loop number and is journaled with its own backing, not the
// first one's.
func TestInspectionMapsEachBackupInTurnUnderTheRunsJournal(t *testing.T) {
	f := newInspectFixture(t)
	o, journalPath := inspector(t)
	var read [][]string
	outcomes, cleanup, err := o.InspectBackups(context.Background(), []InspectTarget{inspectTarget(100), inspectTarget(101)}, nil, func(_ context.Context, target InspectTarget, devices []string) error {
		read = append(read, devices)
		record := loadJournal(t, journalPath)
		if record.Phase != "running" || record.RunID != "run-inspect-test" {
			t.Errorf("while VM %d is read the journal is %q of %q, want running of the inspection", target.SourceVMID, record.Phase, record.RunID)
		}
		if len(record.MapIntents) != 1 || record.MapIntents[0].Token == "" || record.MapIntents[0].Owner == "" || record.MapIntents[0].Device != "/dev/loop7" || record.MapIntents[0].Snapshot != target.Snapshot {
			t.Errorf("while VM %d is read the journal's intents are %+v, want only its own map's, with owner, token and device", target.SourceVMID, record.MapIntents)
		}
		suffix, err := pbs.MapNameSuffix(target.Snapshot, "drive-scsi0")
		if err != nil {
			t.Fatal(err)
		}
		wantBacking := "/run/pbs-loopdev/certistack-test-map-" + strconv.Itoa(len(read)) + suffix
		if len(record.Loops) != 1 || record.Loops[0].Device != "/dev/loop7" || record.Loops[0].Backing != wantBacking {
			t.Errorf("while VM %d is read the journal's loops are %+v, want /dev/loop7 backed by %s", target.SourceVMID, record.Loops, wantBacking)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 2 || outcomes[0].Err != nil || outcomes[1].Err != nil || outcomes[0].Skipped != "" || outcomes[1].Skipped != "" {
		t.Fatalf("outcomes = %+v", outcomes)
	}
	if len(read) != 2 || strings.Join(read[0], ",") != "/dev/loop7" || strings.Join(read[1], ",") != "/dev/loop7" {
		t.Fatalf("read was handed %v", read)
	}
	if got := f.calls(); got != "map detach map detach" {
		t.Fatalf("calls %q, want each map released before the next is made", got)
	}
	if !cleanup.Verified || len(cleanup.Errors) != 0 {
		t.Fatalf("cleanup = %+v", cleanup)
	}
	record := loadJournal(t, journalPath)
	if record.Phase != "cleaned" || len(record.Loops) != 0 || len(record.MapIntents) != 0 || record.LoopDevice != "" {
		t.Fatalf("final journal = %+v, want cleaned with nothing recorded", record)
	}
}

// The maps are released whatever the read did: a failure, and an
// interruption, which also stops the inspection before the next VM.
func TestInspectionReleasesTheMapsWhenTheReadFailsOrIsInterrupted(t *testing.T) {
	t.Run("read fails", func(t *testing.T) {
		f := newInspectFixture(t)
		o, journalPath := inspector(t)
		readErr := errors.New("guestfish could not open the disks")
		outcomes, cleanup, err := o.InspectBackups(context.Background(), []InspectTarget{inspectTarget(100), inspectTarget(101)}, nil, func(context.Context, InspectTarget, []string) error {
			return readErr
		})
		if err != nil || len(outcomes) != 2 || !errors.Is(outcomes[0].Err, readErr) || !errors.Is(outcomes[1].Err, readErr) {
			t.Fatalf("outcomes %+v, err %v; want each VM's read error and both inspected", outcomes, err)
		}
		if got := f.calls(); got != "map detach map detach" {
			t.Fatalf("calls %q", got)
		}
		if record := loadJournal(t, journalPath); !cleanup.Verified || record.Phase != "cleaned" {
			t.Fatalf("cleanup %+v, journal %q", cleanup, record.Phase)
		}
	})
	t.Run("interrupted", func(t *testing.T) {
		f := newInspectFixture(t)
		o, journalPath := inspector(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		outcomes, cleanup, _ := o.InspectBackups(ctx, []InspectTarget{inspectTarget(100), inspectTarget(101)}, nil, func(ctx context.Context, _ InspectTarget, _ []string) error {
			cancel()
			return ctx.Err()
		})
		if len(outcomes) != 2 || !errors.Is(outcomes[0].Err, context.Canceled) || outcomes[1].Skipped == "" {
			t.Fatalf("outcomes %+v; want the first read stopped and the second VM skipped", outcomes)
		}
		if got := f.calls(); got != "map detach" {
			t.Fatalf("calls %q; want the first map released and no second map", got)
		}
		if record := loadJournal(t, journalPath); !cleanup.Verified || record.Phase != "cleaned" {
			t.Fatalf("cleanup %+v, journal %q", cleanup, record.Phase)
		}
	})
}

// A map the client fails to make is released through its intent, as a run's
// is, and nothing is read.
func TestInspectionReleasesAFailedMapThroughItsIntent(t *testing.T) {
	f := newInspectFixture(t)
	f.set("failmap")
	o, journalPath := inspector(t)
	var released []string
	o.unmapLeakedMapsFn = func(intents []*journal.MapIntent, _ map[string]bool, _ func() error) error {
		for _, intent := range intents {
			released = append(released, intent.Snapshot)
		}
		return nil
	}
	read := false
	outcomes, cleanup, err := o.InspectBackups(context.Background(), []InspectTarget{inspectTarget(100)}, nil, func(context.Context, InspectTarget, []string) error {
		read = true
		return nil
	})
	if err != nil || len(outcomes) != 1 || outcomes[0].Err == nil || !strings.Contains(outcomes[0].Err.Error(), "PBS map error for scsi0") {
		t.Fatalf("outcomes %+v, err %v; want the map error", outcomes, err)
	}
	if read || strings.Join(released, ",") != "vm/100/2026-10-01T02:00:00Z" {
		t.Fatalf("read %v, released %v; want nothing read and the failed map released through its intent", read, released)
	}
	if record := loadJournal(t, journalPath); !cleanup.Verified || record.Phase != "cleaned" || len(record.MapIntents) != 0 {
		t.Fatalf("cleanup %+v, journal %+v", cleanup, record)
	}
}

// A map that cannot be shown released stays in the journal for recovery,
// the journal ends cleanup_failed, and nothing more is mapped.
func TestInspectionStopsWhenAMapCannotBeShownReleased(t *testing.T) {
	f := newInspectFixture(t)
	f.set("keepmap")
	o, journalPath := inspector(t)
	outcomes, cleanup, err := o.InspectBackups(context.Background(), []InspectTarget{inspectTarget(100), inspectTarget(101)}, nil, func(context.Context, InspectTarget, []string) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 2 || !errors.Is(outcomes[0].Err, ErrMapsNotReleased) || outcomes[1].Skipped == "" {
		t.Fatalf("outcomes %+v; want the first VM's maps unreleased and the second skipped", outcomes)
	}
	if got := f.calls(); got != "map detach" {
		t.Fatalf("calls %q; want one map, its release, and no second map", got)
	}
	record := loadJournal(t, journalPath)
	if cleanup.Verified || record.Phase != "cleanup_failed" || len(record.Loops) != 1 || record.Loops[0].Device != "/dev/loop7" || len(record.MapIntents) != 1 || record.MapIntents[0].Token == "" {
		t.Fatalf("cleanup %+v, journal %+v; want cleanup_failed with the map recorded for recovery", cleanup, record)
	}
}

// An inspection the node's admission refuses for a VM maps nothing for it,
// and goes on with the next.
func TestInspectionSkipsAVMAdmissionRefuses(t *testing.T) {
	f := newInspectFixture(t)
	o, journalPath := inspector(t)
	asked := 0
	outcomes, cleanup, err := o.InspectBackups(context.Background(), []InspectTarget{inspectTarget(100), inspectTarget(101)}, func(context.Context) error {
		asked++
		if asked == 1 {
			return errors.New("the node's memory is 93% used, over the 85% limit")
		}
		return nil
	}, func(context.Context, InspectTarget, []string) error { return nil })
	if err != nil || len(outcomes) != 2 || !strings.Contains(outcomes[0].Skipped, "93%") || outcomes[1].Skipped != "" || outcomes[1].Err != nil {
		t.Fatalf("outcomes %+v, err %v", outcomes, err)
	}
	if got := f.calls(); got != "map detach" {
		t.Fatalf("calls %q; want only the admitted VM mapped", got)
	}
	if record := loadJournal(t, journalPath); !cleanup.Verified || record.Phase != "cleaned" {
		t.Fatalf("cleanup %+v, journal %q", cleanup, record.Phase)
	}
}

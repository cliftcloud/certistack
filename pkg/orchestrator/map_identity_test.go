// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pbs"
)

// proxmox-backup-client says which loop device it mapped, and the run reads
// that line. A device it names that is not attached to this map's file
// (another map's, or a host loop) is not the backup: scanning it would
// record another disk's digest as the backup's, booting it would credit the
// backup with another disk's services, and teardown would detach a loop that
// is not the run's. The run refuses the device before it reads or records
// it, and leaves it alone.
func TestAMappedDeviceThatIsNotTheMapsFileIsRefusedAndLeftAlone(t *testing.T) {
	for name, backing := range map[string]string{
		"another map's file":         foreignLoopBacking,
		"a file outside the map dir": "/var/lib/snapd/snaps/core22_1380.snap",
		"the map's name elsewhere":   "/tmp/" + ownedLoopName,
	} {
		t.Run(name, func(t *testing.T) {
			f := newLoopFixture(t, "exit 0")
			f.attach(backing)
			o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
			_, err := o.bootAndVerifyVM(context.Background(), mapTestVM(), 60, nil)
			if err == nil || !strings.Contains(err.Error(), "not this map's file") {
				t.Fatalf("bootAndVerifyVM = %v, want the device refused as not the map's", err)
			}
			if len(o.record.Loops) != 0 {
				t.Fatalf("journaled loops = %+v, want none: the device is not the run's", o.record.Loops)
			}
			if failures := o.cleanup.Unwind(); len(failures) != 0 {
				t.Fatalf("teardown failures = %v", failures)
			}
			if calls := f.calls(); strings.Contains(calls, "/dev/loop7") {
				t.Fatalf("commands ran against a loop that is not the run's:\n%s", calls)
			}
		})
	}
}

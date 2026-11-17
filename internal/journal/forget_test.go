// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

import (
	"testing"
	"time"
)

// An inspection maps one VM's backup after another, and the kernel hands
// the second map the loop number the first one freed. Without forgetting the
// first map, AddLoop kept the first backing for the device, so the second map
// was journaled with the first one's identity and recovery would have left it
// alone as another file's loop.
func TestForgetReleasedMapsLetsTheNextMapOfALoopNumberBeJournaled(t *testing.T) {
	var r Record
	first := r.AddMapIntent("vm/100/2026-10-01T02:00:00Z", "drive-scsi0.img", "a", time.Now())
	r.SetMapIntentIdentity(first, "owner-a", "token-a")
	r.AddLoop("/dev/loop5", "/run/pbs-loopdev/first.img")
	r.ResolveMapIntent(first, "/dev/loop5")

	r.ForgetReleasedMaps(0)
	if len(r.MapIntents) != 0 || len(r.Loops) != 0 || r.LoopDevice != "" || r.LoopBacking != "" {
		t.Fatalf("after forgetting the released map: %+v", r)
	}

	second := r.AddMapIntent("vm/101/2026-10-01T02:00:00Z", "drive-scsi0.img", "b", time.Now())
	r.AddLoop("/dev/loop5", "/run/pbs-loopdev/second.img")
	r.ResolveMapIntent(second, "/dev/loop5")
	if len(r.Loops) != 1 || r.Loops[0].Backing != "/run/pbs-loopdev/second.img" || r.LoopBacking != "/run/pbs-loopdev/second.img" {
		t.Fatalf("the second map of /dev/loop5 is journaled as %+v (legacy %q), want its own backing", r.Loops, r.LoopBacking)
	}
	if got := r.MapIntentOfLoop("/dev/loop5"); got.Snapshot != "vm/101/2026-10-01T02:00:00Z" {
		t.Fatalf("the loop's intent is %+v, want the second map's", got)
	}
}

// Only the maps from the given intent on are forgotten: what was journaled
// before, and every other loop, stays for recovery. An unresolved intent (a
// map that failed and whose leftovers were released) goes with its peers.
func TestForgetReleasedMapsKeepsWhatCameBefore(t *testing.T) {
	var r Record
	kept := r.AddMapIntent("vm/100/2026-10-01T02:00:00Z", "drive-scsi0.img", "a", time.Now())
	r.AddLoop("/dev/loop1", "/run/pbs-loopdev/kept.img")
	r.ResolveMapIntent(kept, "/dev/loop1")
	resolved := r.AddMapIntent("vm/101/2026-10-01T02:00:00Z", "drive-scsi0.img", "b", time.Now())
	r.AddLoop("/dev/loop2", "/run/pbs-loopdev/released.img")
	r.ResolveMapIntent(resolved, "/dev/loop2")
	r.AddMapIntent("vm/101/2026-10-01T02:00:00Z", "drive-scsi1.img", "c", time.Now()) // failed, released

	held := &r.MapIntents[resolved]
	r.ForgetReleasedMaps(resolved)
	if len(r.MapIntents) != 1 || r.MapIntents[0].Device != "/dev/loop1" {
		t.Fatalf("intents = %+v, want only the earlier map's", r.MapIntents)
	}
	if len(r.Loops) != 1 || r.Loops[0].Device != "/dev/loop1" || r.LoopDevice != "/dev/loop1" {
		t.Fatalf("loops = %+v (legacy %q), want only /dev/loop1", r.Loops, r.LoopDevice)
	}
	// What a caller still holds of a forgotten intent is not written over by
	// the next map's.
	r.AddMapIntent("vm/102/2026-10-01T02:00:00Z", "drive-scsi0.img", "d", time.Now())
	if held.Snapshot != "vm/101/2026-10-01T02:00:00Z" {
		t.Fatalf("a held intent became %+v", *held)
	}

	r.ForgetReleasedMaps(10) // past the end: nothing
	r.ForgetReleasedMaps(-1) // everything
	if len(r.MapIntents) != 0 || len(r.Loops) != 0 {
		t.Fatalf("after forgetting all: %+v", r)
	}
}

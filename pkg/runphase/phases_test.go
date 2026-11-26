// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runphase

import (
	"bytes"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

func testPlan(tiers ...config.Tier) *config.Plan {
	return &config.Plan{
		Network: config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		Tiers:   tiers,
	}
}

// adaptable is a VM whose network is prepared offline: it has an address to
// configure.
func adaptable(id int, name string) config.VM {
	return config.VM{VMID: id, Name: name, NetworkRecovery: config.NetworkRecovery{SandboxIP: "10.100.0.10"}}
}

// preserved is a VM that opts out of the preparation.
func preserved(id int, name string) config.VM {
	return config.VM{VMID: id, Name: name, NetworkRecovery: config.NetworkRecovery{Mode: "preserve"}}
}

func tier(level int, vms ...config.VM) config.Tier {
	return config.Tier{Level: level, Name: "tier", VMs: vms}
}

func kindsOf(steps []Step) string {
	names := make([]string, len(steps))
	for i, step := range steps {
		names[i] = step.Kind.String()
	}
	return strings.Join(names, " ")
}

// The list has the phases the plan has, in the order the node worker goes
// through them, and counts no phase that does not apply.
func TestStepsListTheirPhasesInTheOrderOfTheRun(t *testing.T) {
	grace := tier(1, adaptable(9100, "web"))
	grace.StartupGracePeriodSec = 180
	soak := tier(1, adaptable(9100, "web"), adaptable(9101, "db"))
	soak.StartupGracePeriodSec, soak.SoakTimeSec = 30, 600
	copying := adaptable(9100, "web")
	copying.CopyBeforeBoot = config.CopyBeforeBootAlways
	copyNever := adaptable(9100, "web")
	copyNever.CopyBeforeBoot = config.CopyBeforeBootNever
	silent := config.VM{VMID: 9100, Name: "web"} // no sandbox address: nothing to configure
	empty := config.Tier{Level: 1, Name: "empty", StartupGracePeriodSec: 60, SoakTimeSec: 60}

	for _, test := range []struct {
		name string
		plan *config.Plan
		opts Options
		want string
	}{
		{"one VM, every phase", testPlan(tier(1, adaptable(9100, "web"))), Options{},
			"admission network restore guest-network integrity boot probes teardown report"},
		{"mode preserve has no guest network preparation", testPlan(tier(1, preserved(9100, "web"))), Options{},
			"admission network restore integrity boot probes teardown report"},
		{"a VM with no address to configure has none either", testPlan(tier(1, silent)), Options{},
			"admission network restore integrity boot probes teardown report"},
		{"test mode has no integrity scan", testPlan(tier(1, adaptable(9100, "web"))), Options{SkipIntegrity: true},
			"admission network restore guest-network boot probes teardown report"},
		{"test mode that copies before boot still scans", testPlan(tier(1, copying)), Options{SkipIntegrity: true},
			"admission network restore guest-network integrity boot probes teardown report"},
		{"copy_before_boot never does not bring the scan back", testPlan(tier(1, copyNever)), Options{SkipIntegrity: true},
			"admission network restore guest-network boot probes teardown report"},
		{"test mode and preserve", testPlan(tier(1, preserved(9100, "web"))), Options{SkipIntegrity: true},
			"admission network restore boot probes teardown report"},
		{"a grace period waits after the boots, before the probes", testPlan(grace), Options{},
			"admission network restore guest-network integrity boot grace probes teardown report"},
		{"two VMs boot one after the other, then are probed one after the other, and the soak ends the tier", testPlan(soak), Options{},
			"admission network " +
				"restore guest-network integrity boot restore guest-network integrity boot " +
				"grace probes probes soak teardown report"},
		{"tiers go by level, whatever order the plan lists them", testPlan(tier(2, preserved(9101, "db")), tier(1, adaptable(9100, "web"))), Options{},
			"admission network restore guest-network integrity boot probes restore integrity boot probes teardown report"},
		{"a tier with no VM has no grace and no soak", testPlan(empty), Options{},
			"admission network teardown report"},
		{"no tiers", testPlan(), Options{}, "admission network teardown report"},
		{"no plan", nil, Options{}, "admission network teardown report"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := kindsOf(Steps(test.plan, test.opts)); got != test.want {
				t.Errorf("phases:\n got %s\nwant %s", got, test.want)
			}
		})
	}
}

// The VM numbers are the plan's, across tiers, in the order the run takes the
// VMs; a VM that has no phase of a kind is not numbered in it.
func TestStepsNumberTheVMsOfThePlan(t *testing.T) {
	plan := testPlan(tier(2, adaptable(9103, "web")), tier(1, adaptable(9101, "db"), preserved(9102, "app")))
	type vm struct{ id, number, count int }
	got := map[Kind][]vm{}
	for _, step := range Steps(plan, Options{}) {
		if step.VMID != 0 {
			got[step.Kind] = append(got[step.Kind], vm{step.VMID, step.VMNumber, step.VMCount})
		}
	}
	want := map[Kind][]vm{
		Restore:      {{9101, 1, 3}, {9102, 2, 3}, {9103, 3, 3}},
		GuestNetwork: {{9101, 1, 3}, {9103, 3, 3}},
		Integrity:    {{9101, 1, 3}, {9102, 2, 3}, {9103, 3, 3}},
		Boot:         {{9101, 1, 3}, {9102, 2, 3}, {9103, 3, 3}},
		Probes:       {{9101, 1, 3}, {9102, 2, 3}, {9103, 3, 3}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("VM numbers:\n got %v\nwant %v", got, want)
	}
}

// line is a phase as the operator reads it.
func line(a Announcement, note string) string {
	return a.Stage() + " | " + a.Message(note)
}

// The lines of a first run: one VM, nothing left out. This is the text people
// see, so it is held in full.
func TestTheLinesOfOneVMRun(t *testing.T) {
	tracker := NewTracker(Steps(testPlan(tier(1, adaptable(9100, "cs-rocky-web"))), Options{}))
	if tracker.Total() != 9 {
		t.Fatalf("Total = %d, want 9", tracker.Total())
	}
	var got []string
	begin := func(kind Kind, id int, note string) {
		t.Helper()
		a, ok := tracker.Begin(kind, id)
		if !ok {
			t.Fatalf("no phase %v of %d", kind, id)
		}
		got = append(got, line(a, note))
	}
	begin(Admission, 0, "")
	begin(Network, 0, "")
	begin(Restore, 9100, "")
	begin(GuestNetwork, 9100, "")
	begin(Integrity, 9100, "12 GiB to read")
	begin(Boot, 9100, "")
	begin(Probes, 9100, "")
	begin(Teardown, 0, "")
	begin(Signing, 0, "")
	want := []string{
		"Phase 1 of 9 | Admission checks: node support and host capacity",
		"Phase 2 of 9 | Isolated sandbox network",
		"Phase 3 of 9 | Disk restore (PBS map, COW overlays) for VM 9100 (cs-rocky-web)",
		"Phase 4 of 9 | Guest network preparation for VM 9100 (cs-rocky-web): offline image work, often several minutes on a small or nested host",
		"Phase 5 of 9 | Integrity scan for VM 9100 (cs-rocky-web): 12 GiB to read",
		"Phase 6 of 9 | Sandbox boot for VM 9100 (cs-rocky-web)",
		"Phase 7 of 9 | Service probes for VM 9100 (cs-rocky-web)",
		"Phase 8 of 9 | Teardown, then a check that nothing of the run is left",
		"Phase 9 of 9 | Journal check and report",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// With several VMs every per-VM line says which VM it is, of how many, and the
// numbers run on from one VM to the next.
func TestSeveralVMsSayWhichVMEachLineIs(t *testing.T) {
	grace := tier(1, adaptable(9101, "db"), preserved(9102, "app"))
	grace.StartupGracePeriodSec, grace.SoakTimeSec = 90, 300
	tracker := NewTracker(Steps(testPlan(grace, tier(2, adaptable(9103, "web"))), Options{SkipIntegrity: true}))
	var got []string
	for _, begin := range []struct {
		kind Kind
		id   int
	}{
		{Admission, 0}, {Network, 0},
		{Restore, 9101}, {GuestNetwork, 9101}, {Boot, 9101},
		{Restore, 9102}, {Boot, 9102},
		{Grace, 1}, {Probes, 9101}, {Probes, 9102}, {Soak, 1},
		{Restore, 9103}, {GuestNetwork, 9103}, {Boot, 9103}, {Probes, 9103},
		{Teardown, 0}, {Signing, 0},
	} {
		a, ok := tracker.Begin(begin.kind, begin.id)
		if !ok {
			t.Fatalf("no phase %v of %d after %v", begin.kind, begin.id, got)
		}
		got = append(got, line(a, ""))
	}
	want := []string{
		"Phase 1 of 17 | Admission checks: node support and host capacity",
		"Phase 2 of 17 | Isolated sandbox network",
		"Phase 3 of 17 | Disk restore (PBS map, COW overlays) for VM 9101 (db) - VM 1 of 3",
		"Phase 4 of 17 | Guest network preparation for VM 9101 (db) - VM 1 of 3: offline image work, often several minutes on a small or nested host",
		"Phase 5 of 17 | Sandbox boot for VM 9101 (db) - VM 1 of 3",
		"Phase 6 of 17 | Disk restore (PBS map, COW overlays) for VM 9102 (app) - VM 2 of 3",
		"Phase 7 of 17 | Sandbox boot for VM 9102 (app) - VM 2 of 3",
		"Phase 8 of 17 | Start-up grace period for tier 1: 90 s",
		"Phase 9 of 17 | Service probes for VM 9101 (db) - VM 1 of 3",
		"Phase 10 of 17 | Service probes for VM 9102 (app) - VM 2 of 3",
		"Phase 11 of 17 | Soak for tier 1: 300 s",
		"Phase 12 of 17 | Disk restore (PBS map, COW overlays) for VM 9103 (web) - VM 3 of 3",
		"Phase 13 of 17 | Guest network preparation for VM 9103 (web) - VM 3 of 3: offline image work, often several minutes on a small or nested host",
		"Phase 14 of 17 | Sandbox boot for VM 9103 (web) - VM 3 of 3",
		"Phase 15 of 17 | Service probes for VM 9103 (web) - VM 3 of 3",
		"Phase 16 of 17 | Teardown, then a check that nothing of the run is left",
		"Phase 17 of 17 | Journal check and report",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A VM without a name is named by its ID alone.
func TestAVMWithoutANameIsNamedByItsID(t *testing.T) {
	tracker := NewTracker(Steps(testPlan(tier(1, adaptable(9100, ""))), Options{}))
	a, ok := tracker.Begin(Restore, 9100)
	if !ok || !strings.HasSuffix(a.Message(""), "for VM 9100") {
		t.Errorf("message = %q, ok = %v", a.Message(""), ok)
	}
}

// A run that stops short keeps the numbers of the phases it reached: the
// teardown and the report are the last two, wherever the run stopped, and a
// phase the run had passed or the list does not have says nothing.
func TestARunThatStopsShortKeepsTheNumbersOfItsLastPhases(t *testing.T) {
	tracker := NewTracker(Steps(testPlan(tier(1, adaptable(9100, "web"))), Options{}))
	for _, begin := range []struct {
		kind Kind
		id   int
	}{{Admission, 0}, {Network, 0}, {Restore, 9100}, {GuestNetwork, 9100}} {
		if _, ok := tracker.Begin(begin.kind, begin.id); !ok {
			t.Fatalf("no phase %v", begin.kind)
		}
	}
	// The guest network preparation failed: the run goes to its teardown.
	teardown, ok := tracker.Begin(Teardown, 0)
	if !ok || teardown.Index != 8 || teardown.Total != 9 {
		t.Fatalf("teardown = %+v, %v; want phase 8 of 9", teardown, ok)
	}
	if a, ok := tracker.Begin(Teardown, 0); ok {
		t.Errorf("a second teardown is phase %d", a.Index)
	}
	if a, ok := tracker.Begin(Boot, 9100); ok {
		t.Errorf("a boot after the teardown is phase %d", a.Index)
	}
	signing, ok := tracker.Begin(Signing, 0)
	if !ok || signing.Index != 9 || signing.Total != 9 {
		t.Errorf("signing = %+v, %v; want phase 9 of 9", signing, ok)
	}
}

// A phase the plan does not have is not announced, and the phases after it
// keep their numbers.
func TestAPhaseThePlanDoesNotHaveIsNotMadeUp(t *testing.T) {
	tracker := NewTracker(Steps(testPlan(tier(1, preserved(9100, "web"))), Options{}))
	tracker.Begin(Admission, 0)
	tracker.Begin(Network, 0)
	tracker.Begin(Restore, 9100)
	if a, ok := tracker.Begin(GuestNetwork, 9100); ok {
		t.Errorf("a preserved VM has guest network preparation as phase %d", a.Index)
	}
	if a, ok := tracker.Begin(Integrity, 9100); !ok || a.Index != 4 || a.Total != 8 {
		t.Errorf("integrity = %+v, %v; want phase 4 of 8", a, ok)
	}
	if a, ok := tracker.Begin(Restore, 424242); ok {
		t.Errorf("a VM the plan does not have restores as phase %d", a.Index)
	}
	if a, ok := tracker.Begin(Grace, 1); ok {
		t.Errorf("a tier with no grace period has one as phase %d", a.Index)
	}
}

func TestANilTrackerSaysNothing(t *testing.T) {
	var tracker *Tracker
	if a, ok := tracker.Begin(Admission, 0); ok {
		t.Errorf("a nil tracker announced phase %d", a.Index)
	}
	if tracker.Total() != 0 {
		t.Errorf("Total = %d", tracker.Total())
	}
}

func TestIsStageRecognizesOnlyAPhasesStage(t *testing.T) {
	for stage, want := range map[string]bool{
		"Phase 1 of 9":           true,
		"Phase 12 of 120":        true,
		"Phase 0 of 9":           false,
		"Phase 1 of 0":           false,
		"Phase 3":                false,
		"phase 3 of 9":           false,
		"Phase 3 of 9 and more":  false,
		"Phase 3 of 9\nforged":   false,
		"Phase -3 of 9":          false,
		"Phase 1234567 of 9":     false,
		"Storage":                false,
		"":                       false,
		"[Phase 3 of 9]":         false,
		"Phase 3 of 9 \x1b[2Kx":  false,
		" Phase 3 of 9":          false,
		"Phase 3 of 9 ":          false,
		"Phase 3 of 9; Sandbox":  false,
		"Phase ٣ of 9":           false,
		"Phase 3  of 9":          false,
		"Phase 3 of 9, tier one": false,
	} {
		if got := IsStage(stage); got != want {
			t.Errorf("IsStage(%q) = %v, want %v", stage, got, want)
		}
	}
	a := Announcement{Index: 4, Total: 9}
	if !IsStage(a.Stage()) {
		t.Errorf("a phase's own stage %q is not recognized", a.Stage())
	}
}

// The plans a person copies: the totals their runs show, and the controller and
// the node worker (which loads the plan the controller sends it) count the same
// phases of each.
func TestTheShippedPlansAndTheWorkerCountTheSamePhases(t *testing.T) {
	for _, test := range []struct {
		file string
		want int
	}{
		// admission, network, restore, guest network, integrity, boot, probes, teardown, report
		{"minimal-single-vm.yaml", 9},
		// Three tiers of one VM, each with a grace period: 2 + 3*(4 + grace + probes) + 2.
		{"three-tier-app.yaml", 22},
		// preserve everywhere: three VMs (restore, integrity, boot, probes), two grace periods.
		{"windows-domain.yaml", 18},
	} {
		t.Run(test.file, func(t *testing.T) {
			plan, err := config.LoadFromFile(filepath.Join("..", "..", "examples", test.file))
			if err != nil {
				t.Fatal(err)
			}
			steps := Steps(plan, Options{})
			if len(steps) != test.want {
				t.Errorf("%d phases (%s), want %d", len(steps), kindsOf(steps), test.want)
			}
			data, err := config.MarshalWorkerPlan(plan)
			if err != nil {
				t.Fatal(err)
			}
			worker, err := config.LoadFromReaderForWorker(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if got, want := kindsOf(Steps(worker, Options{})), kindsOf(steps); got != want {
				t.Errorf("the node worker counts different phases:\n got %s\nwant %s", got, want)
			}
			if got, want := len(Steps(worker, Options{SkipIntegrity: true})), len(Steps(plan, Options{SkipIntegrity: true})); got != want {
				t.Errorf("in test mode the node worker counts %d phases, the controller %d", got, want)
			}
		})
	}
}

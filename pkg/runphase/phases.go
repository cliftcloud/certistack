// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package runphase numbers the phases of a validation run, so that someone
// reading its progress can tell where the run is, of how many phases.
//
// The list is worked out from the plan and the test-mode flag alone, before
// anything runs, so the controller and the node worker count the same phases
// and a phase that does not apply to the plan (guest network preparation for a
// VM that sets mode: preserve, the integrity scan in test mode) is not counted.
// What the list cannot know is not guessed: the phases are counted, never
// timed, and a time is estimated only where a scan reports how much is done of
// how much (ScanEstimator).
package runphase

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/cliftcloud/certistack/pkg/config"
)

// Kind is one kind of phase, in the order a run goes through them.
type Kind int

const (
	// Admission is the node's own checks and the host capacity check that come
	// before anything is created.
	Admission Kind = iota + 1
	// Network is the isolated sandbox network (SDN zone and VNet).
	Network
	// Restore maps a VM's backup read-only and creates its COW overlays.
	Restore
	// GuestNetwork is the offline preparation of a VM's network inside its
	// disposable overlays. A VM with network_recovery.mode: preserve has none.
	GuestNetwork
	// Integrity is the full read of a VM's mapped images. Test mode has none.
	Integrity
	// Boot registers and starts the sandbox VM and waits for QEMU to run it.
	Boot
	// Grace is a tier's fixed startup_grace_period_sec wait.
	Grace
	// Probes runs a VM's service probes.
	Probes
	// Soak is a tier's soak_time_sec hold.
	Soak
	// Teardown removes what the run created and verifies that it is gone.
	Teardown
	// Signing is the report phase, the last: the controller's check of the
	// node's journal, and the writing and saving of the report. Kind.String
	// calls it "report".
	Signing
)

var kindNames = map[Kind]string{
	Admission: "admission", Network: "network", Restore: "restore", GuestNetwork: "guest-network",
	Integrity: "integrity", Boot: "boot", Grace: "grace", Probes: "probes", Soak: "soak",
	Teardown: "teardown", Signing: "report",
}

func (k Kind) String() string {
	if name, ok := kindNames[k]; ok {
		return name
	}
	return fmt.Sprintf("kind(%d)", int(k))
}

// scope is what identifies a phase besides its kind.
type scope int

const (
	scopeRun scope = iota
	scopeTier
	scopeVM
)

func (k Kind) scope() scope {
	switch k {
	case Restore, GuestNetwork, Integrity, Boot, Probes:
		return scopeVM
	case Grace, Soak:
		return scopeTier
	}
	return scopeRun
}

// Step is one phase of a run.
type Step struct {
	Kind Kind
	// Tier is the level of the tier of a per-VM phase or a tier phase.
	Tier int
	// VMID and Name identify the VM of a per-VM phase.
	VMID int
	Name string
	// VMNumber and VMCount place the VM among all the plan's VMs, in the order
	// the run takes them (tiers by level, then the order of the plan): VM 2 of 3.
	VMNumber, VMCount int
	// Seconds is the configured length of a Grace or Soak phase.
	Seconds int
}

// Options are the facts besides the plan that decide which phases a run has.
type Options struct {
	// SkipIntegrity is the test-only mode that does not scan the images.
	SkipIntegrity bool
}

// Steps is the run's phases in order: admission and the sandbox network, then
// for each tier, by level, each VM's restore, guest network preparation (when
// the VM has one), integrity scan (when the run has one) and boot, the tier's
// grace period (when it has one), each VM's probes and the tier's soak (when it
// has one), and last the teardown and the report. The order is the one the
// node worker goes through.
func Steps(plan *config.Plan, opts Options) []Step {
	steps := []Step{{Kind: Admission}, {Kind: Network}}
	if plan != nil {
		tiers := append([]config.Tier(nil), plan.Tiers...)
		sort.SliceStable(tiers, func(i, j int) bool { return tiers[i].Level < tiers[j].Level })
		count := 0
		for _, tier := range tiers {
			count += len(tier.VMs)
		}
		number := 0
		for _, tier := range tiers {
			vmStep := func(kind Kind, vm config.VM, vmNumber int) Step {
				return Step{Kind: kind, Tier: tier.Level, VMID: vm.VMID, Name: vm.Name, VMNumber: vmNumber, VMCount: count}
			}
			first := number
			for _, vm := range tier.VMs {
				number++
				steps = append(steps, vmStep(Restore, vm, number))
				if _, configured, err := vm.SandboxAddress(plan.Network); err == nil && configured {
					steps = append(steps, vmStep(GuestNetwork, vm, number))
				}
				// A test-mode run scans a VM's images only to copy them before boot.
				if !opts.SkipIntegrity || vm.CopyBeforeBoot == config.CopyBeforeBootAlways {
					steps = append(steps, vmStep(Integrity, vm, number))
				}
				steps = append(steps, vmStep(Boot, vm, number))
			}
			if len(tier.VMs) > 0 && tier.StartupGracePeriodSec > 0 {
				steps = append(steps, Step{Kind: Grace, Tier: tier.Level, Seconds: tier.StartupGracePeriodSec})
			}
			for i, vm := range tier.VMs {
				steps = append(steps, vmStep(Probes, vm, first+i+1))
			}
			if len(tier.VMs) > 0 && tier.SoakTimeSec > 0 {
				steps = append(steps, Step{Kind: Soak, Tier: tier.Level, Seconds: tier.SoakTimeSec})
			}
		}
	}
	return append(steps, Step{Kind: Teardown}, Step{Kind: Signing})
}

// Text is what the phase's line says, without the "Phase N of M" in front of it.
func (s Step) Text() string {
	switch s.Kind {
	case Admission:
		return "Admission checks: node support and host capacity"
	case Network:
		return "Isolated sandbox network"
	case Restore:
		return "Disk restore (PBS map, COW overlays) for " + s.vm()
	case GuestNetwork:
		return "Guest network preparation for " + s.vm() + ": offline image work, often several minutes on a small or nested host"
	case Integrity:
		return "Integrity scan for " + s.vm()
	case Boot:
		return "Sandbox boot for " + s.vm()
	case Grace:
		return fmt.Sprintf("Start-up grace period for tier %d: %d s", s.Tier, s.Seconds)
	case Probes:
		return "Service probes for " + s.vm()
	case Soak:
		return fmt.Sprintf("Soak for tier %d: %d s", s.Tier, s.Seconds)
	case Teardown:
		return "Teardown, then a check that nothing of the run is left"
	case Signing:
		return "Journal check and report"
	}
	return "Unknown phase"
}

// vm names the phase's VM, and which of the plan's VMs it is when there are
// several: "VM 9101 (cs-db) - VM 2 of 3".
func (s Step) vm() string {
	text := fmt.Sprintf("VM %d", s.VMID)
	if s.Name != "" {
		text += " (" + s.Name + ")"
	}
	if s.VMCount > 1 {
		text += fmt.Sprintf(" - VM %d of %d", s.VMNumber, s.VMCount)
	}
	return text
}

// Announcement is a phase that begins: its place in the run and what it is.
type Announcement struct {
	// Index is the phase's place, from 1, and Total the number of phases.
	Index, Total int
	Step         Step
}

// Stage is the progress stage the phase's line is shown under:
// "Phase 3 of 9". IsStage recognizes it.
func (a Announcement) Stage() string {
	return fmt.Sprintf("Phase %d of %d", a.Index, a.Total)
}

// Message is the phase's line; a note is what the phase knows when it begins
// that the plan does not say (the size an integrity scan has to read).
func (a Announcement) Message(note string) string {
	text := a.Step.Text()
	if note = strings.TrimSpace(note); note != "" {
		text += ": " + note
	}
	return text
}

var stageExpr = regexp.MustCompile(`^Phase [1-9][0-9]{0,5} of [1-9][0-9]{0,5}$`)

// IsStage reports whether a progress stage is a phase's ("Phase 3 of 9"), and
// so says when a phase began. It accepts nothing else: a worker's progress is
// shown, and a stage that is not this shape is just a stage.
func IsStage(stage string) bool {
	return stageExpr.MatchString(stage)
}

// Tracker hands out a run's phases in order, as each begins.
type Tracker struct {
	mu    sync.Mutex
	steps []Step
	next  int
}

// NewTracker returns a tracker of steps (see Steps).
func NewTracker(steps []Step) *Tracker {
	return &Tracker{steps: append([]Step(nil), steps...)}
}

// Total is the number of phases the run has.
func (t *Tracker) Total() int {
	if t == nil {
		return 0
	}
	return len(t.steps)
}

// Begin says the phase of this kind begins. id is the VM's ID for a per-VM
// phase and the tier's level for a tier phase; a phase of the whole run has
// none. It finds the first such phase not yet begun, from where the last one
// was, so a run that stops short (a VM that did not boot has no probes) goes on
// from where it is and keeps the numbers of the phases it did reach. It reports
// false for a phase the list does not have; the caller then says nothing, and
// no number is made up. A nil tracker has no phases.
func (t *Tracker) Begin(kind Kind, id int) (Announcement, bool) {
	if t == nil {
		return Announcement{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := t.next; i < len(t.steps); i++ {
		step := t.steps[i]
		if step.Kind != kind {
			continue
		}
		switch kind.scope() {
		case scopeVM:
			if step.VMID != id {
				continue
			}
		case scopeTier:
			if step.Tier != id {
				continue
			}
		}
		t.next = i + 1
		return Announcement{Index: i + 1, Total: len(t.steps), Step: step}, true
	}
	return Announcement{}, false
}

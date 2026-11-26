// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// planText is p as the YAML a plan author's file would hold.
func planText(t *testing.T, p *Plan) string {
	t.Helper()
	data, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// loadText loads plan YAML through the controller loader and the worker
// loader, and fails unless both agree.
func loadText(t *testing.T, text string) (*Plan, error) {
	t.Helper()
	controller, controllerErr := LoadFromReader(strings.NewReader(text))
	_, workerErr := LoadFromReaderForWorker(strings.NewReader(text))
	if (controllerErr == nil) != (workerErr == nil) {
		t.Fatalf("the loaders disagree: controller %v, worker %v", controllerErr, workerErr)
	}
	return controller, controllerErr
}

func mustRefuse(t *testing.T, text string, wants ...string) {
	t.Helper()
	_, err := loadText(t, text)
	if err == nil {
		t.Fatalf("plan loaded, want an error naming %v", wants)
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) && !strings.Contains(validationText(err), want) {
			t.Errorf("error %q lacks %q", validationText(err), want)
		}
	}
}

func validationText(err error) string {
	var text []string
	if errs, ok := err.(ValidationErrors); ok {
		for _, e := range errs {
			text = append(text, e.Error())
		}
	}
	return strings.Join(text, "\n") + err.Error()
}

// A plan that gives the canonical spelling and an alias with different values
// would have one of the two silently ignored. Every alias pair is refused when
// the two disagree, by both loaders.
func TestConflictingAliasSpellingsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Plan)
		want   string
	}{
		// (the legacy drive is refused by its own rule)
		{"admission block ram", func(p *Plan) {
			p.Admission = AdmissionControl{MaxHostRAMPercent: 75, MaxHostIOWaitPercent: 12, DeferRetryIntervalSec: 30, MaxDeferRetries: 10}
		}, "admission.max_host_ram_percent"},
		{"admission block retry interval", func(p *Plan) {
			p.Admission = AdmissionControl{MaxHostRAMPercent: 85, MaxHostIOWaitPercent: 12, DeferRetryIntervalSec: 5, MaxDeferRetries: 10}
		}, "admission.defer_retry_interval_sec"},
		{"admission block concurrent boots", func(p *Plan) {
			p.AdmissionControl.MaxConcurrentBoots = 2
			p.Admission = AdmissionControl{MaxHostRAMPercent: 85, MaxHostIOWaitPercent: 12, DeferRetryIntervalSec: 30, MaxDeferRetries: 10, MaxConcurrentBoots: 8}
		}, "admission.max_concurrent_boots"},
		{"iowait spelling", func(p *Plan) { p.AdmissionControl.MaxHostIOWaitPercentAlt = 99 }, "admission_control.max_host_io_wait_percent"},
		{"iowait spelling in the admission block", func(p *Plan) {
			p.Admission = AdmissionControl{MaxHostRAMPercent: 85, MaxHostIOWaitPercent: 12, MaxHostIOWaitPercentAlt: 60, DeferRetryIntervalSec: 30, MaxDeferRetries: 10}
		}, "admission.max_host_io_wait_percent"},
		{"ip_range and subnet_cidr", func(p *Plan) { p.Network.SubnetCIDR = "10.200.0.0/24" }, "network.subnet_cidr"},
		{"level and tier", func(p *Plan) { p.Tiers[0].Tier = 2 }, "tiers[0].tier"},
		{"vmid and target_vmid", func(p *Plan) { p.Tiers[0].VMs[0].TargetVMID = 9002 }, "tiers[0].vms[0].target_vmid"},
		{"drive and drives", func(p *Plan) {
			p.Tiers[0].VMs[0].SourcePBS.Drives = []SourceDrive{{Slot: "virtio0", Archive: "drive-virtio0"}}
		}, "tiers[0].vms[0].source_pbs.drive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validPlan()
			tc.mutate(p)
			text := planText(t, p)
			if strings.HasSuffix(tc.want, "source_pbs.drive") {
				mustRefuse(t, text, tc.want, "does not restore")
				return
			}
			mustRefuse(t, text, tc.want, "disagrees")
		})
	}
}

// An invalid canonical value is not overwritten by a positive alias before
// validation, so the invalid value the author wrote is refused.
func TestAnAliasDoesNotMaskAnInvalidCanonicalValue(t *testing.T) {
	p := validPlan()
	p.Tiers[0].Level, p.Tiers[0].Tier = -1, 1
	p.Tiers[0].VMs[0].VMID, p.Tiers[0].VMs[0].TargetVMID = -1, 9001
	mustRefuse(t, planText(t, p), "tiers[0].level", "tiers[0].vms[0].vmid", "tiers[0].tier", "tiers[0].vms[0].target_vmid")
	// The same through code that builds a plan without YAML.
	q := validPlan()
	q.Tiers[0].Level, q.Tiers[0].Tier = -1, 1
	q.Tiers[0].VMs[0].VMID, q.Tiers[0].VMs[0].TargetVMID = -1, 9001
	q.Normalize()
	if !hasFieldError(Validate(q), "tiers[0].level") || !hasFieldError(Validate(q), "tiers[0].vms[0].vmid") {
		t.Fatalf("a canonical -1 was replaced by its alias: level %d, vmid %d", q.Tiers[0].Level, q.Tiers[0].VMs[0].VMID)
	}
}

// handwritten is a small plan with its level, vmid and probe timeout left for
// the test to fill in, as the author's own YAML.
func handwritten(level, vmid, timeout string) string {
	return strings.NewReplacer("LEVEL", level, "VMID", vmid, "TIMEOUT", timeout).Replace(`
version: v1
plan_id: handwritten
name: handwritten
compliance: {frameworks: [DORA], retention_days: 90, sign_key_path: /etc/certistack/keys/signing.ed25519}
admission_control: {max_host_ram_percent: 85, max_host_iowait_percent: 12, defer_retry_interval_sec: 30, max_defer_retries: 10}
network: {mode: simple, zone_id: csSb01, vnet_id: csVn01, ip_range: 10.100.0.0/24, probe_ip: 10.100.0.1}
tiers:
  - LEVEL
    name: t
    vms:
      - VMID
        name: dc
        source_pbs: {storage_id: pbs, snapshot: vm/100/latest, drive: drive-scsi0}
        probes:
          - {type: tcp, target_ip: 10.100.0.10, port: 389, description: ldap, TIMEOUT}
`)
}

// A key written as zero is a value the author gave, not a key left
// out, so an alias must not fill it in.
func TestAnExplicitZeroIsNotFilledFromAnAlias(t *testing.T) {
	if _, err := loadText(t, handwritten("level: 1", "vmid: 9001", "timeout_sec: 5")); err != nil {
		t.Fatalf("the base plan does not load: %v", err)
	}
	mustRefuse(t, handwritten("level: 0\n    tier: 2", "vmid: 9001", "timeout_sec: 5"), "tiers[0].tier", "disagrees")
	mustRefuse(t, handwritten("level: 1", "vmid: 0\n        target_vmid: 9001", "timeout_sec: 5"), "tiers[0].vms[0].target_vmid", "disagrees")
	// A key with no value is a key left out, and its alias may stand.
	p, err := loadText(t, handwritten("level:\n    tier: 2", "vmid:\n        target_vmid: 9001", "timeout_sec: 5"))
	if err != nil || p.Tiers[0].Level != 2 || p.Tiers[0].VMs[0].VMID != 9001 {
		t.Fatalf("null keys: %v", err)
	}
}

// An alias with the same value, or an alias standing alone, still
// loads, and the plan a worker reads holds each setting once.
func TestAliasSpellingsThatAgreeStillLoad(t *testing.T) {
	p := validPlan()
	p.Admission = p.AdmissionControl
	p.AdmissionControl.MaxHostIOWaitPercentAlt = p.AdmissionControl.MaxHostIOWaitPercent
	p.Network.SubnetCIDR = "10.100.0.0/24"
	p.Tiers[0].Tier = 1
	p.Tiers[0].VMs[0].TargetVMID = 9001
	loaded, err := loadText(t, planText(t, p))
	if err != nil {
		t.Fatalf("agreeing aliases refused: %v", err)
	}
	worker, err := MarshalWorkerPlan(loaded)
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"subnet_cidr", "target_vmid", "max_host_io_wait_percent", "\nadmission:", "  tier:"} {
		if strings.Contains(string(worker), alias) {
			t.Errorf("the worker's plan still spells %q:\n%s", alias, worker)
		}
	}
	if _, err := LoadFromReaderForWorker(strings.NewReader(string(worker))); err != nil {
		t.Fatalf("the worker cannot read the plan written for it: %v\n%s", err, worker)
	}
}

// The older spellings alone, and a mix of the two blocks where each
// gives what the other leaves out, load with every limit in place.
func TestAliasOnlyAndMixedAdmissionPlansLoad(t *testing.T) {
	const tail = `
network:
  mode: "simple"
  zone_id: "csSb01"
  vnet_id: "csVn01"
  subnet_cidr: "10.100.0.0/24"
  probe_ip: "10.100.0.1"
compliance:
  frameworks: ["DORA"]
  retention_days: 90
  sign_key_path: "/etc/certistack/keys/signing.ed25519"
tiers:
  - tier: 3
    vms:
      - target_vmid: 9001
        name: "cs-test-dc01"
        source_pbs: {storage_id: "pbs", snapshot: "vm/100/latest", drive: "drive-scsi0"}
        probes:
          - {type: tcp, target_ip: "10.100.0.10", port: 389, description: ldap}
`
	for name, admission := range map[string]string{
		"legacy block only": `
admission:
  max_host_ram_percent: 80
  max_host_io_wait_percent: 20
  defer_retry_interval_sec: 15
  max_defer_retries: 4
`,
		"each block gives what the other leaves out": `
admission_control:
  max_host_ram_percent: 80
  defer_retry_interval_sec: 15
admission:
  max_host_iowait_percent: 20
  max_defer_retries: 4
`,
	} {
		t.Run(name, func(t *testing.T) {
			text := "version: v1\nplan_id: legacy\nname: legacy" + admission + tail
			p, err := loadText(t, text)
			if err != nil {
				t.Fatal(err)
			}
			ac := p.AdmissionControl
			if ac.MaxHostRAMPercent != 80 || ac.MaxHostIOWaitPercent != 20 || ac.DeferRetryIntervalSec != 15 || ac.MaxDeferRetries != 4 {
				t.Fatalf("admission_control = %+v", ac)
			}
			if p.Tiers[0].Level != 3 || p.Tiers[0].VMs[0].VMID != 9001 || p.Network.IPRange != "10.100.0.0/24" || p.Tiers[0].Name != "Tier 3" {
				t.Fatalf("aliases not resolved: level %d, vmid %d, ip_range %q, name %q", p.Tiers[0].Level, p.Tiers[0].VMs[0].VMID, p.Network.IPRange, p.Tiers[0].Name)
			}
			worker, err := MarshalWorkerPlan(p)
			if err != nil {
				t.Fatal(err)
			}
			read, err := LoadFromReaderForWorker(strings.NewReader(string(worker)))
			if err != nil {
				t.Fatalf("worker cannot read its plan: %v\n%s", err, worker)
			}
			if read.AdmissionControl != ac || read.Tiers[0].Level != 3 || read.Tiers[0].VMs[0].VMID != 9001 {
				t.Fatalf("the worker's plan differs: %+v", read.AdmissionControl)
			}
		})
	}
	// The same admission limit under both blocks, differing, is refused.
	text := "version: v1\nplan_id: legacy\nname: legacy\nadmission_control: {max_host_ram_percent: 80, max_host_iowait_percent: 20, defer_retry_interval_sec: 15, max_defer_retries: 4}\nadmission: {max_host_ram_percent: 90}\n" + tail
	mustRefuse(t, text, "admission.max_host_ram_percent")
}

// A probe timeout given as zero or negative is refused, not turned into ten
// seconds by normalization before validation sees it. Only a timeout left out
// gets the default.
func TestNonpositiveProbeTimeoutsAreRefused(t *testing.T) {
	base := planText(t, validPlan())
	for _, value := range []string{"0", "-1", "-60"} {
		t.Run(value, func(t *testing.T) {
			mustRefuse(t, strings.Replace(base, "timeout_sec: 30", "timeout_sec: "+value, 1), "tiers[0].vms[0].probes[0].timeout_sec", "leave timeout_sec out")
		})
	}
	// Left out, the default of 10 still applies; a positive value is kept.
	var kept []string
	for _, line := range strings.Split(base, "\n") {
		if !strings.Contains(line, "timeout_sec: 30") {
			kept = append(kept, line)
		}
	}
	without := strings.Join(kept, "\n")
	p, err := loadText(t, without)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Tiers[0].VMs[0].Probes[0].TimeoutSec; got != 10 {
		t.Fatalf("a timeout left out is %d, want the default 10", got)
	}
	if p, err = loadText(t, base); err != nil || p.Tiers[0].VMs[0].Probes[0].TimeoutSec != 30 {
		t.Fatalf("a positive timeout: %v", err)
	}
	// A null value is a key left out.
	if p, err = loadText(t, strings.Replace(base, "timeout_sec: 30", "timeout_sec:", 1)); err != nil || p.Tiers[0].VMs[0].Probes[0].TimeoutSec != 10 {
		t.Fatalf("a null timeout: %v", err)
	}
	// The worker's copy of a plan whose timeout was left out reads back as 10.
	worker, err := MarshalWorkerPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	if read, err := LoadFromReaderForWorker(strings.NewReader(string(worker))); err != nil || read.Tiers[0].VMs[0].Probes[0].TimeoutSec != 10 {
		t.Fatalf("worker plan: %v", err)
	}
	// Code that builds a plan and normalizes it still gets the default.
	q := validPlan()
	q.Tiers[0].VMs[0].Probes[0].TimeoutSec = 0
	q.Normalize()
	if q.Tiers[0].VMs[0].Probes[0].TimeoutSec != 10 {
		t.Fatalf("built plan: %d", q.Tiers[0].VMs[0].Probes[0].TimeoutSec)
	}
	q.Tiers[0].VMs[0].Probes[0].TimeoutSec = -5
	q.Normalize()
	if !hasFieldError(Validate(q), "tiers[0].vms[0].probes[0].timeout_sec") {
		t.Fatal("a built plan's -5 became a default")
	}
}

// The sandbox VM's ID must be one PVE and init allocate from,
// 100 to 999999999, not just positive.
func TestSandboxVMIDMustBeAProxmoxVMID(t *testing.T) {
	for _, tc := range []struct {
		vmid int
		ok   bool
	}{{99, false}, {100, true}, {999999999, true}, {1000000000, false}, {1, false}, {-1, false}, {0, false}} {
		p := validPlan()
		vm := &p.Tiers[0].VMs[0]
		vm.VMID = tc.vmid
		// Keep the source apart from the sandbox ID.
		vm.SourcePBS.Snapshot = "vm/100/2026-03-30T02:00:00Z"
		vm.SourceVMID = 100
		if tc.vmid == 100 {
			vm.SourceVMID = 0
			vm.SourcePBS.Snapshot = "vm/101/2026-03-30T02:00:00Z"
		}
		errs := Validate(p)
		if got := !hasFieldError(errs, "tiers[0].vms[0].vmid"); got != tc.ok {
			t.Errorf("vmid %d: accepted %v, want %v (%v)", tc.vmid, got, tc.ok, errs)
		}
	}
	p := validPlan()
	p.Tiers[0].VMs[0].TargetVMID = 99
	if !hasFieldError(Validate(p), "tiers[0].vms[0].target_vmid") {
		t.Error("target_vmid 99 accepted")
	}
	p = validPlan()
	p.Tiers[0].VMs[0].SourceVMID = -3
	if !hasFieldError(Validate(p), "tiers[0].vms[0].source_vmid") {
		t.Error("source_vmid -3 accepted")
	}
}

// Explicit hardware overrides are held to the ranges the same hardware is held
// to when a backup's configuration gives it. A negative value would suppress
// the backup's value and fall to a default; one above the maximum would go to
// PVE unchecked.
func TestHardwareOverridesAreBounded(t *testing.T) {
	type field struct {
		key      string
		set      func(*HardwareOverrides, int)
		min, max int
	}
	fields := []field{
		{"cores", func(h *HardwareOverrides, n int) { h.Cores = n }, 1, 256},
		{"sockets", func(h *HardwareOverrides, n int) { h.Sockets = n }, 1, 16},
		{"memory_mb", func(h *HardwareOverrides, n int) { h.MemoryMB = n }, 16, 4194304},
		{"balloon_mb", func(h *HardwareOverrides, n int) { h.BalloonMB = n }, 1, 4194304},
		{"cpu_weight", func(h *HardwareOverrides, n int) { h.CPUWeight = n }, 1, 262144},
	}
	for _, useBackup := range []bool{false, true} {
		for _, f := range fields {
			for _, tc := range []struct {
				value int
				ok    bool
			}{{-5, false}, {0, true}, {f.min - 1, f.min-1 == 0}, {f.min, true}, {f.max, true}, {f.max + 1, false}} {
				p := validPlan()
				p.UseBackupConfig = useBackup
				p.Tiers[0].VMs[0].HardwareOverrides = HardwareOverrides{}
				f.set(&p.Tiers[0].VMs[0].HardwareOverrides, tc.value)
				errs := Validate(p)
				want := "tiers[0].vms[0].hardware_overrides." + f.key
				if got := !hasFieldError(errs, want); got != tc.ok {
					t.Errorf("use_backup_config=%v %s=%d: accepted %v, want %v (%v)", useBackup, f.key, tc.value, got, tc.ok, errs)
				}
				// Both loaders refuse it from YAML too.
				if !tc.ok {
					mustRefuse(t, planText(t, p), want)
				}
			}
		}
	}
	// The balloon target cannot exceed the memory it is part of.
	p := validPlan()
	p.Tiers[0].VMs[0].HardwareOverrides = HardwareOverrides{MemoryMB: 2048, BalloonMB: 4096}
	if !hasFieldError(Validate(p), "tiers[0].vms[0].hardware_overrides.balloon_mb") {
		t.Error("balloon_mb above memory_mb accepted")
	}
	p.Tiers[0].VMs[0].HardwareOverrides = HardwareOverrides{MemoryMB: 4096, BalloonMB: 4096}
	if errs := Validate(p); len(errs) != 0 {
		t.Errorf("balloon_mb equal to memory_mb refused: %v", errs)
	}
	// A plan handed to a run without going through the loader is held to
	// the same ranges.
	p.Tiers[0].VMs[0].HardwareOverrides = HardwareOverrides{Cores: 257}
	if !hasFieldError(NumericBoundsErrors(p), "tiers[0].vms[0].hardware_overrides.cores") {
		t.Error("NumericBoundsErrors lets 257 cores through")
	}
}

// Every wire-probe target belongs to exactly one VM, preserve-mode VMs
// included, not only VMs that get a sandbox address: otherwise a preserve-mode
// VM's probe could name another VM's address and its pass be credited to the
// wrong VM.
func TestWireProbeTargetsBelongToOneVM(t *testing.T) {
	vm := func(vmid int, mode string, tcpTargets ...string) VM {
		v := validPlan().Tiers[0].VMs[0]
		v.VMID, v.Name = vmid, "vm-"+intText(vmid)
		v.NetworkRecovery = NetworkRecovery{Mode: mode}
		v.Probes = nil
		for _, target := range tcpTargets {
			v.Probes = append(v.Probes, Probe{Type: "tcp", TargetIP: target, Port: 22, TimeoutSec: 5, Description: "ssh " + target})
		}
		return v
	}
	plan := func(tiers ...[]VM) *Plan {
		p := validPlan()
		p.Tiers = nil
		for i, vms := range tiers {
			p.Tiers = append(p.Tiers, Tier{Level: i + 1, Name: "tier " + intText(i+1), VMs: vms})
		}
		return p
	}
	for _, tc := range []struct {
		name  string
		plan  *Plan
		wants string // the field that must be refused, "" for accepted
	}{
		{"auto and preserve in one tier", plan([]VM{vm(9101, "auto", "10.100.0.10"), vm(9102, "preserve", "10.100.0.10")}), "tiers[0].vms[1].probes[0].target_ip"},
		{"preserve first, auto second", plan([]VM{vm(9102, "preserve", "10.100.0.10"), vm(9101, "auto", "10.100.0.10")}), "tiers[0].vms[1].probes[0].target_ip"},
		{"auto in tier 1, preserve in tier 2", plan([]VM{vm(9101, "auto", "10.100.0.10")}, []VM{vm(9102, "preserve", "10.100.0.10")}), "tiers[1].vms[0].probes[0].target_ip"},
		{"two preserve VMs", plan([]VM{vm(9101, "preserve", "10.100.0.10"), vm(9102, "preserve", "10.100.0.10")}), "tiers[0].vms[1].probes[0].target_ip"},
		{"the same address in another spelling", plan([]VM{vm(9101, "preserve", "10.100.0.10"), vm(9102, "preserve", "::ffff:10.100.0.10")}), "tiers[0].vms[1].probes[0].target_ip"},
		{"one preserve VM with several targets, one shared", plan([]VM{vm(9101, "preserve", "10.100.0.10"), vm(9102, "preserve", "10.100.0.11", "10.100.0.10")}), "tiers[0].vms[1].probes[1].target_ip"},
		{"two auto VMs (control)", plan([]VM{vm(9101, "auto", "10.100.0.10"), vm(9102, "auto", "10.100.0.10")}), "tiers[0].vms[1].network_recovery.sandbox_ip"},
		{"distinct addresses", plan([]VM{vm(9101, "auto", "10.100.0.10"), vm(9102, "preserve", "10.100.0.11")}), ""},
		{"one VM probes its address twice", plan([]VM{vm(9101, "preserve", "10.100.0.10", "10.100.0.10")}), ""},
		{"a preserve VM with several addresses of its own", plan([]VM{vm(9101, "preserve", "10.100.0.10", "10.100.0.12"), vm(9102, "preserve", "10.100.0.11")}), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.plan
			p.Normalize()
			errs := Validate(p)
			if tc.wants == "" {
				if len(errs) != 0 {
					t.Fatalf("refused: %v", errs)
				}
				return
			}
			if !hasFieldError(errs, tc.wants) {
				t.Fatalf("want an error on %s, got %v", tc.wants, errs)
			}
		})
	}
}

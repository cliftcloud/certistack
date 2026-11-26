// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func validPlan() *Plan {
	return &Plan{
		Version: "v1",
		PlanID:  "acme-erp-full-stack-dr",
		Name:    "ACME ERP Full Stack Disaster Recovery Test",
		Compliance: Compliance{
			Frameworks:    []string{"DORA-Article-12", "SOC2-Type2-CC7.4"},
			RetentionDays: 2555,
			SignKeyPath:   "/etc/certistack/keys/signing.ed25519",
		},
		AdmissionControl: AdmissionControl{
			MaxHostRAMPercent:     85.0,
			MaxHostIOWaitPercent:  12.0,
			DeferRetryIntervalSec: 30,
			MaxDeferRetries:       10,
		},
		Network: Network{
			Mode:    "simple",
			ZoneID:  "csSb01",
			VNetID:  "csVn01",
			IPRange: "10.100.0.0/24",
			ProbeIP: "10.100.0.1",
		},
		Tiers: []Tier{
			{
				Level:                 1,
				Name:                  "Identity & Core Infrastructure",
				StartupGracePeriodSec: 45,
				VMs: []VM{
					{
						VMID: 9001,
						Name: "cs-test-dc01",
						SourcePBS: SourcePBS{
							StorageID: "pbs",
							Snapshot:  "vm/100/2026-03-30T02:00:00Z",
							Drive:     "drive-scsi0",
						},
						HardwareOverrides: HardwareOverrides{
							Cores:     2,
							MemoryMB:  4096,
							BalloonMB: 2048,
							CPUWeight: 50,
						},
						Probes: []Probe{
							{
								Type:        "tcp",
								TargetIP:    "10.100.0.10",
								Port:        389,
								TimeoutSec:  30,
								Description: "LDAP TCP handshake on domain controller",
							},
						},
					},
				},
			},
		},
	}
}

func TestLoadValidPlan(t *testing.T) {
	yamlStr := `
version: "v1"
plan_id: "acme-erp-full-stack-dr"
name: "ACME ERP Full Stack Disaster Recovery Test"

compliance:
  frameworks:
    - "DORA-Article-12"
    - "SOC2-Type2-CC7.4"
  retention_days: 2555
  sign_key_path: "/etc/certistack/keys/signing.ed25519"

admission_control:
  max_host_ram_percent: 85.0
  max_host_iowait_percent: 12.0
  defer_retry_interval_sec: 30
  max_defer_retries: 10

network:
  mode: "simple"
  zone_id: "csSb01"
  vnet_id: "csVn01"
  ip_range: "10.100.0.0/24"
  probe_ip: "10.100.0.1"

tiers:
  - level: 1
    name: "Identity & Core Infrastructure"
    startup_grace_period_sec: 45
    vms:
      - vmid: 9001
        name: "cs-test-dc01"
        source_pbs:
          storage_id: "pbs"
          snapshot: "vm/100/2026-03-30T02:00:00Z"
          drive: "drive-scsi0"
        probes:
          - type: "tcp"
            target_ip: "10.100.0.10"
            port: 389
            timeout_sec: 30
            description: "LDAP TCP handshake on domain controller"
`
	p, err := LoadFromReader(strings.NewReader(yamlStr))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if p.Version != "v1" || p.PlanID != "acme-erp-full-stack-dr" {
		t.Errorf("unexpected fields in parsed plan: %+v", p)
	}
}

func TestValidation_VersionMismatch(t *testing.T) {
	p := validPlan()
	p.Version = "v2"
	errs := Validate(p)
	if len(errs) == 0 || errs[0].Field != "version" {
		t.Errorf("expected version error, got %v", errs)
	}
}

func TestValidation_InvalidPlanID(t *testing.T) {
	p := validPlan()
	p.PlanID = "invalid id"
	errs := Validate(p)
	if len(errs) == 0 || errs[0].Field != "plan_id" {
		t.Errorf("expected plan_id error, got %v", errs)
	}
}

// The Community Edition writes its reports unsigned: a plan whose
// compliance.sign_key_path is blank is valid.
func TestValidation_DoesNotRequireAReportSigningKey(t *testing.T) {
	p := validPlan()
	p.Compliance.SignKeyPath = " \t "

	for _, err := range Validate(p) {
		if err.Field == "compliance.sign_key_path" {
			t.Fatalf("a blank sign_key_path was rejected: %v", err)
		}
	}
}

func TestWorkerPlanRedactsControllerSigningKey(t *testing.T) {
	plan := validPlan()
	data, err := MarshalWorkerPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sign_key_path") || strings.Contains(string(data), plan.Compliance.SignKeyPath) {
		t.Fatalf("worker plan contains controller signing configuration: %s", data)
	}
	// The field is optional in every plan, so the normal loader reads the
	// redacted plan too.
	if _, err := LoadFromReader(bytes.NewReader(data)); err != nil {
		t.Fatalf("normal plan loader refused a worker-redacted plan: %v", err)
	}
	workerPlan, err := LoadFromReaderForWorker(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("worker plan was rejected: %v", err)
	}
	if workerPlan.Compliance.SignKeyPath != "" {
		t.Fatalf("worker plan signing key = %q, want empty", workerPlan.Compliance.SignKeyPath)
	}
}

func TestValidation_ProbeRetriesMustBeBounded(t *testing.T) {
	for _, retries := range []int{-1, 11} {
		p := validPlan()
		p.Tiers[0].VMs[0].Probes[0].Retries = retries
		errs := Validate(p)
		found := false
		for _, err := range errs {
			if err.Field == "tiers[0].vms[0].probes[0].retries" {
				found = true
			}
		}
		if !found {
			t.Fatalf("retries=%d validation errors = %v; want retries error", retries, errs)
		}
	}
}

func TestValidation_EmptyName(t *testing.T) {
	p := validPlan()
	p.Name = ""
	errs := Validate(p)
	if len(errs) == 0 || errs[0].Field != "name" {
		t.Errorf("expected name error, got %v", errs)
	}
}

func TestValidation_InvalidFramework(t *testing.T) {
	p := validPlan()
	p.Compliance.Frameworks = []string{"INVALID"}
	errs := Validate(p)
	if len(errs) == 0 || !strings.HasPrefix(errs[0].Field, "compliance.frameworks") {
		t.Errorf("expected compliance.frameworks error, got %v", errs)
	}
}

func TestValidation_InvalidNetworkMode(t *testing.T) {
	p := validPlan()
	p.Network.Mode = "bridge"
	errs := Validate(p)
	if len(errs) == 0 || errs[0].Field != "network.mode" {
		t.Errorf("expected network.mode error, got %v", errs)
	}
}

func TestValidation_RejectsInvalidProxmoxSDNIdentifiers(t *testing.T) {
	p := validPlan()
	p.Network.ZoneID = "cs_lab_01"
	p.Network.VNetID = "cs-vn-01"

	errs := Validate(p)
	var zoneErr, vnetErr bool
	for _, err := range errs {
		zoneErr = zoneErr || err.Field == "network.zone_id"
		vnetErr = vnetErr || err.Field == "network.vnet_id"
	}
	if !zoneErr || !vnetErr {
		t.Fatalf("expected invalid SDN identifiers to be rejected, got %v", errs)
	}
}

func TestValidation_InvalidCIDR(t *testing.T) {
	p := validPlan()
	p.Network.IPRange = "not-a-cidr"
	errs := Validate(p)
	if len(errs) == 0 || errs[0].Field != "network.ip_range" {
		t.Errorf("expected network.ip_range error, got %v", errs)
	}
}

func TestValidation_ProbeIPMustBeUsableSandboxAddress(t *testing.T) {
	p := validPlan()
	p.Network.ProbeIP = "10.100.0.0"
	errs := Validate(p)
	if len(errs) == 0 || errs[0].Field != "network.probe_ip" {
		t.Fatalf("expected reserved probe_ip error, got %v", errs)
	}

	p = validPlan()
	p.Network.ProbeIP = "10.100.1.1"
	errs = Validate(p)
	if len(errs) == 0 || errs[0].Field != "network.probe_ip" {
		t.Fatalf("expected out-of-range probe_ip error, got %v", errs)
	}
}

func TestNetworkProbeAddressCIDR(t *testing.T) {
	network := Network{IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"}
	got, err := network.ProbeAddressCIDR()
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.100.0.1/24" {
		t.Fatalf("ProbeAddressCIDR = %q", got)
	}
}

func TestValidation_NoTiers(t *testing.T) {
	p := validPlan()
	p.Tiers = nil
	errs := Validate(p)
	if len(errs) == 0 || errs[0].Field != "tiers" {
		t.Errorf("expected tiers error, got %v", errs)
	}
}

func TestValidation_DuplicateVMID(t *testing.T) {
	p := validPlan()
	tier2 := p.Tiers[0]
	p.Tiers = append(p.Tiers, tier2)
	errs := Validate(p)
	hasDupErr := false
	for _, e := range errs {
		if strings.HasSuffix(e.Field, ".vmid") {
			hasDupErr = true
		}
	}
	if !hasDupErr {
		t.Errorf("expected duplicate vmid error, got %v", errs)
	}
}

func TestValidation_DuplicateTierLevel(t *testing.T) {
	p := validPlan()
	secondTier := p.Tiers[0]
	secondTier.Name = "Secondary"
	secondTier.VMs[0].VMID++
	p.Tiers = append(p.Tiers, secondTier)
	errList := Validate(p)
	for _, err := range errList {
		if strings.HasSuffix(err.Field, ".level") && strings.Contains(err.Message, "unique") {
			return
		}
	}
	t.Fatalf("expected duplicate tier level error, got %v", errList)
}

func TestValidation_RejectsNegativeBootTimeout(t *testing.T) {
	p := validPlan()
	p.Tiers[0].BootTimeoutSec = -1
	for _, err := range Validate(p) {
		if err.Field == "tiers[0].boot_timeout_sec" {
			return
		}
	}
	t.Fatalf("expected negative boot timeout error, got %v", Validate(p))
}

func TestValidation_InvalidProbeType(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].Probes[0].Type = "snmp"
	errs := Validate(p)
	if len(errs) == 0 || !strings.HasSuffix(errs[0].Field, ".type") {
		t.Errorf("expected probe type error, got %v", errs)
	}
}

func TestValidation_TCPProbeWithoutPort(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].Probes[0].Type = "tcp"
	p.Tiers[0].VMs[0].Probes[0].Port = 0
	errs := Validate(p)
	if len(errs) == 0 || !strings.HasSuffix(errs[0].Field, ".port") {
		t.Errorf("expected probe port error, got %v", errs)
	}
}

func TestValidation_HTTPProbeWithoutStatus(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].Probes[0].Type = "http"
	p.Tiers[0].VMs[0].Probes[0].Port = 80
	p.Tiers[0].VMs[0].Probes[0].TargetIP = "10.100.0.2"
	p.Tiers[0].VMs[0].Probes[0].ExpectedStatus = 0
	errs := Validate(p)
	if len(errs) == 0 || !strings.HasSuffix(errs[0].Field, ".expected_status") {
		t.Errorf("expected probe expected_status error, got %v", errs)
	}
}

func TestValidation_QGAProbeWithoutCommand(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].Probes[0].Type = "qga"
	p.Tiers[0].VMs[0].Probes[0].TargetIP, p.Tiers[0].VMs[0].Probes[0].Port = "", 0
	p.Tiers[0].VMs[0].Probes[0].RequireQGA = true
	p.Tiers[0].VMs[0].Probes[0].Command = ""
	errs := Validate(p)
	if len(errs) == 0 || !strings.HasSuffix(errs[0].Field, ".command") {
		t.Errorf("expected probe command error, got %v", errs)
	}
}

func TestValidation_RejectsArbitraryQGAShellCommand(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].Probes[0].Type = "qga"
	p.Tiers[0].VMs[0].Probes[0].Command = "cat /etc/shadow"
	for _, err := range Validate(p) {
		if strings.HasSuffix(err.Field, ".command") && strings.Contains(err.Message, "arbitrary guest shell commands") {
			return
		}
	}
	t.Fatalf("expected arbitrary QGA command rejection, got %v", Validate(p))
}

func TestValidation_RejectsInsecureProbeTLS(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].Probes[0].Type = "http"
	p.Tiers[0].VMs[0].Probes[0].ExpectedStatus = 200
	p.Tiers[0].VMs[0].Probes[0].InsecureSkipVerify = true
	for _, err := range Validate(p) {
		if strings.HasSuffix(err.Field, ".insecure_skip_verify") {
			return
		}
	}
	t.Fatalf("expected insecure TLS probe rejection, got %v", Validate(p))
}

func TestLoadFromReaderDoesNotExpandProcessEnvironment(t *testing.T) {
	t.Setenv("PVE_TOKEN_SECRET", "must-not-be-expanded")
	plan, err := LoadFromReader(strings.NewReader(`
version: v1
plan_id: no-env-expansion
name: no env expansion
compliance:
  frameworks: ["DORA"]
  retention_days: 90
  sign_key_path: /etc/certistack/keys/signing.ed25519
admission_control:
  max_host_ram_percent: 85
  max_host_iowait_percent: 12
  defer_retry_interval_sec: 1
  max_defer_retries: 1
network:
  mode: simple
  zone_id: csZone
  vnet_id: csVnet
  ip_range: 10.10.0.0/24
  probe_ip: 10.10.0.1
tiers:
  - level: 1
    name: one
    vms:
      - vmid: 9001
        source_vmid: 1
        name: one
        source_pbs:
          storage_id: pbs
          snapshot: latest
          drive: drive-scsi0
        probes:
          - type: qga
            command: hostname
            expected_output: "${PVE_TOKEN_SECRET}"
            require_qga: true
            timeout_sec: 5
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Tiers[0].VMs[0].Probes[0].ExpectedOutput; got != "${PVE_TOKEN_SECRET}" {
		t.Fatalf("plan expanded process environment: %q", got)
	}
}

func TestLoadMultiDiskPlan(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].SourcePBS = SourcePBS{
		StorageID: "pbs",
		Snapshot:  "latest",
		Drives: []SourceDrive{
			{Slot: "scsi0", Archive: "drive-scsi0"},
			{Slot: "scsi1", Archive: "drive-scsi1"},
		},
	}
	p.Tiers[0].VMs[0].SourceVMID = 7031
	p.Normalize()
	if errs := Validate(p); len(errs) != 0 {
		t.Fatalf("expected multi-disk plan to validate, got %v", errs)
	}
	drives := p.Tiers[0].VMs[0].SourcePBS.RestoreDrives()
	if len(drives) != 2 || drives[1].Slot != "scsi1" || drives[1].Archive != "drive-scsi1" {
		t.Fatalf("unexpected normalized drives: %+v", drives)
	}
	if p.Tiers[0].VMs[0].SourcePBS.Drive != "drive-scsi0" {
		t.Fatalf("legacy drive was not normalized from scsi0: %q", p.Tiers[0].VMs[0].SourcePBS.Drive)
	}
}

func TestValidation_BackupConfigDiscoversDiskLayout(t *testing.T) {
	p := validPlan()
	p.UseBackupConfig = true
	p.Tiers[0].VMs[0].SourceVMID = 7011
	p.Tiers[0].VMs[0].SourcePBS = SourcePBS{
		StorageID: "pbs",
		Snapshot:  "latest",
	}

	p.Normalize()
	if drives := p.Tiers[0].VMs[0].SourcePBS.RestoreDrives(); len(drives) != 0 {
		t.Fatalf("backup-config plan unexpectedly declared drives: %+v", drives)
	}
	if errs := Validate(p); len(errs) != 0 {
		t.Fatalf("expected backup-config plan without manual drives to validate, got %v", errs)
	}
}

func TestValidation_RejectsUnsafeOrIncompleteDiskLayout(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].SourcePBS.Drive = ""
	p.Tiers[0].VMs[0].SourcePBS.Drives = []SourceDrive{
		{Slot: "scsi1", Archive: "../drive-scsi1"},
	}
	errs := Validate(p)
	if len(errs) != 1 || errs[0].Field != "tiers[0].vms[0].source_pbs.drives[0].archive" {
		t.Fatalf("errors %v, want only the unsafe archive (the boot disk comes from the backup's boot order)", errs)
	}
	p.Tiers[0].VMs[0].SourcePBS.Drives = []SourceDrive{{Slot: "virtio16", Archive: "drive-virtio16"}, {Slot: "scsi1", Archive: "drive-scsi1"}, {Slot: "scsi1", Archive: "drive-scsi1"}}
	fields := map[string]bool{}
	for _, err := range Validate(p) {
		fields[err.Field] = true
	}
	if !fields["tiers[0].vms[0].source_pbs.drives[0].slot"] || !fields["tiers[0].vms[0].source_pbs.drives[2].slot"] {
		t.Fatalf("want an invalid slot (virtio16) and a duplicate slot rejected, got %v", fields)
	}
}

func TestValidation_AttachAllNICsLetsProbesTargetOtherNICs(t *testing.T) {
	plan := func(attach bool, sandboxIP string, targets ...string) *Plan {
		p := validPlan()
		vm := &p.Tiers[0].VMs[0]
		vm.NetworkRecovery = NetworkRecovery{AttachAllNICs: attach, SandboxIP: sandboxIP}
		vm.Probes = nil
		for _, target := range targets {
			vm.Probes = append(vm.Probes, Probe{Type: "tcp", TargetIP: target, Port: 8080, TimeoutSec: 5, Description: "service on " + target})
		}
		return p
	}
	hasError := func(p *Plan, substring string) bool {
		for _, err := range Validate(p) {
			if strings.Contains(err.Message, substring) {
				return true
			}
		}
		return false
	}
	if errs := Validate(plan(true, "10.100.0.10", "10.100.0.10", "10.100.0.202")); len(errs) != 0 {
		t.Fatalf("attach_all_nics with net0's sandbox_ip and a net1 target: %v", errs)
	}
	if !hasError(plan(false, "10.100.0.10", "10.100.0.10", "10.100.0.202"), "unless attach_all_nics") {
		t.Fatal("a second target without attach_all_nics was accepted")
	}
	if !hasError(plan(true, "", "10.100.0.10", "10.100.0.202"), "declare network_recovery.sandbox_ip (net0's address)") {
		t.Fatal("two targets without sandbox_ip did not ask which address is net0's")
	}

	// A net1 address must not be another VM's sandbox address.
	p := plan(true, "10.100.0.10", "10.100.0.10", "10.100.0.202")
	other := p.Tiers[0].VMs[0]
	other.VMID, other.Name = other.VMID+1, "second"
	other.NetworkRecovery = NetworkRecovery{}
	other.Probes = []Probe{{Type: "tcp", TargetIP: "10.100.0.202", Port: 80, TimeoutSec: 5, Description: "second VM"}}
	p.Tiers[0].VMs = append(p.Tiers[0].VMs, other)
	if !hasError(p, "must be unique") {
		t.Fatal("a net1 address colliding with another VM's address was accepted")
	}
}

func TestValidation_EachArchiveGoesToItsOwnSlotOnce(t *testing.T) {
	for name, drives := range map[string][]SourceDrive{
		"one archive twice":        {{Slot: "scsi0", Archive: "drive-scsi0"}, {Slot: "scsi1", Archive: "drive-scsi0"}},
		"same archive, two spells": {{Slot: "scsi0", Archive: "drive-scsi0"}, {Slot: "scsi1", Archive: "drive-scsi0.img.fidx"}},
		"archive in another slot":  {{Slot: "scsi0", Archive: "drive-scsi1"}},
	} {
		p := validPlan()
		p.Tiers[0].VMs[0].SourcePBS.Drive = ""
		p.Tiers[0].VMs[0].SourcePBS.Drives = drives
		found := false
		for _, err := range Validate(p) {
			found = found || strings.HasSuffix(err.Field, ".archive")
		}
		if !found {
			t.Errorf("%s: accepted %+v", name, drives)
		}
	}
}

func TestValidation_AcceptsDisksOnEveryBus(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].SourcePBS.Drive = ""
	p.Tiers[0].VMs[0].SourcePBS.Drives = []SourceDrive{{Slot: "virtio0", Archive: "drive-virtio0"}, {Slot: "sata1", Archive: "drive-sata1"}, {Slot: "ide0", Archive: "drive-ide0"}}
	if errs := Validate(p); len(errs) != 0 {
		t.Fatalf("disks on virtio, sata and ide: %v", errs)
	}
	if got := (SourcePBS{Drive: "drive-virtio0"}).RestoreDrives(); len(got) != 1 || got[0].Slot != "virtio0" {
		t.Fatalf("drive shorthand for a virtio archive restored %+v, want slot virtio0", got)
	}
}

func TestValidation_DNSAndTLSProbeOptions(t *testing.T) {
	p := validPlan()
	// This unit deliberately validates independent endpoints as one abstract
	// probe collection; preserve avoids asserting that a single recovered VM
	// should be assigned all three sandbox addresses.
	p.Tiers[0].VMs[0].NetworkRecovery.Mode = "preserve"
	p.Tiers[0].VMs[0].Probes = []Probe{
		{
			Type: "http", TargetIP: "10.100.0.15", Port: 443, Path: "/healthz", TLS: true,
			ServerName: "certistack.local", ExpectedStatus: 200, TimeoutSec: 5, Description: "HTTPS SNI",
		},
		{
			Type: "dns", TargetIP: "10.100.0.19", Port: 53, Domain: "healthy.certistack.test",
			Transport: "tcp", TimeoutSec: 5, Description: "DNS over TCP",
		},
		{
			Type: "ldap", TargetIP: "10.100.0.23", Port: 389, BaseDN: "dc=certistack,dc=test",
			TimeoutSec: 5, Description: "LDAP base search",
		},
	}
	if errs := Validate(p); len(errs) != 0 {
		t.Fatalf("expected probe options to validate, got %v", errs)
	}

	p.Tiers[0].VMs[0].Probes[1].Transport = "sctp"
	if errs := Validate(p); len(errs) == 0 {
		t.Fatal("expected invalid DNS transport to be rejected")
	}
}

func TestValidation_RetentionDaysIsBounded(t *testing.T) {
	for days, valid := range map[int]bool{0: false, 1: true, 2555: true, 36500: true, 36501: false, 1_000_000: false, -1: false} {
		p := validPlan()
		p.Compliance.RetentionDays = days
		errs := Validate(p)
		found := false
		for _, err := range errs {
			found = found || err.Field == "compliance.retention_days"
		}
		if found == valid {
			t.Errorf("retention_days %d: errors %v", days, errs)
		}
	}
}

func TestValidation_ProtocolProbes(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].NetworkRecovery.Mode = "preserve"
	p.Tiers[0].VMs[0].Probes = []Probe{
		{Type: "mssql", TargetIP: "10.100.0.25", Port: 1433, TimeoutSec: 5, Description: "SQL Server"},
		{Type: "smb", TargetIP: "10.100.0.25", Port: 445, TimeoutSec: 5, Description: "SMB"},
	}
	if errs := Validate(p); len(errs) != 0 {
		t.Fatalf("expected mssql and smb probes to validate, got %v", errs)
	}
	p.Tiers[0].VMs[0].Probes[0].Port = 0
	p.Tiers[0].VMs[0].Probes[1].TargetIP = "192.0.2.50" // outside network.ip_range
	errs := Validate(p)
	fields := map[string]bool{}
	for _, err := range errs {
		fields[err.Field] = true
	}
	if !fields["tiers[0].vms[0].probes[0].port"] || !fields["tiers[0].vms[0].probes[1].target_ip"] {
		t.Fatalf("errors %v, want a missing mssql port and an smb target outside the sandbox", errs)
	}
}

func TestValidation_WindowsServiceQuery(t *testing.T) {
	for command, valid := range map[string]bool{
		"sc query MSSQL$SQLEXPRESS":           true,
		"sc query W3SVC":                      true,
		"sc query LanmanServer":               true,
		"sc query W3SVC & whoami":             false,
		"sc query W3SVC; shutdown /s":         false,
		"sc query \"W3SVC\"":                  false,
		"sc query":                            false,
		"sc stop W3SVC":                       false,
		"sc query W3SVC\r\nwhoami":            false,
		"powershell.exe -Command Get-Service": false,
	} {
		plan := validPlan()
		plan.Tiers[0].VMs[0].Probes = []Probe{{Type: "qga", Command: command, RequireQGA: true, TimeoutSec: 30, Description: "service"}}
		errs := Validate(plan)
		if got := len(errs) == 0; got != valid {
			t.Errorf("a qga probe running %q validates = %v (%v), want %v", command, got, errs, valid)
		}
	}
}

func TestValidation_DirectoryAssertionOptions(t *testing.T) {
	plan := func(probes ...Probe) *Plan {
		p := validPlan()
		p.Tiers[0].VMs[0].NetworkRecovery.Mode = "preserve"
		p.Tiers[0].VMs[0].Probes = probes
		return p
	}
	ldap := Probe{Type: "ldap", TargetIP: "10.100.0.23", Port: 389, TimeoutSec: 5, Description: "AD naming context"}
	srv := Probe{Type: "dns", TargetIP: "10.100.0.23", Port: 53, Domain: "_ldap._tcp.dc._msdcs.certistack.test", TimeoutSec: 5, Description: "DC locator"}

	valid := ldap
	valid.NamingContext = "DC=certistack, DC=test"
	validSRV := srv
	validSRV.RecordType = "SRV"
	if errs := Validate(plan(valid, validSRV)); len(errs) != 0 {
		t.Fatalf("expected naming_context and an srv record check to validate, got %v", errs)
	}

	for name, tc := range map[string]struct {
		probe Probe
		field string
	}{
		"naming context with base_dn":   {func() Probe { p := valid; p.BaseDN = "dc=certistack,dc=test"; return p }(), "naming_context"},
		"naming context that is no DN":  {func() Probe { p := ldap; p.NamingContext = "certistack.test"; return p }(), "naming_context"},
		"naming context with a newline": {func() Probe { p := ldap; p.NamingContext = "DC=certistack\n,DC=test"; return p }(), "naming_context"},
		"naming context on a dns probe": {func() Probe { p := srv; p.NamingContext = "DC=certistack,DC=test"; return p }(), "naming_context"},
		"srv without a domain":          {func() Probe { p := validSRV; p.Domain = ""; return p }(), "domain"},
		"unknown record type":           {func() Probe { p := srv; p.RecordType = "mx"; return p }(), "record_type"},
		"record type on an ldap probe":  {func() Probe { p := ldap; p.RecordType = "srv"; return p }(), "record_type"},
	} {
		errs := Validate(plan(tc.probe))
		found := false
		for _, err := range errs {
			found = found || strings.HasSuffix(err.Field, "."+tc.field)
		}
		if !found {
			t.Errorf("%s: errors %v, want one on %s", name, errs, tc.field)
		}
	}
}

func TestPlanDoesNotExpandEnvironmentVariables(t *testing.T) {
	t.Setenv("CERTISTACK_TEST_ID", "expanded-id")
	t.Setenv("CERTISTACK_KEY", "/tmp/key")

	yamlStr := `
version: "v1"
plan_id: "${CERTISTACK_TEST_ID}"
name: "Test"
compliance:
  frameworks: ["DORA"]
  sign_key_path: "${CERTISTACK_KEY}"
  retention_days: 1
admission_control:
  max_host_ram_percent: 10
  max_host_iowait_percent: 10
  defer_retry_interval_sec: 1
  max_defer_retries: 1
network:
  mode: "simple"
  zone_id: "z1"
  vnet_id: "v1"
  ip_range: "10.0.0.0/24"
  probe_ip: "10.0.0.2"
tiers:
  - level: 1
    name: "T1"
    vms:
      - vmid: 100
        name: "vm"
        source_pbs:
          storage_id: "s"
          snapshot: "vm/100/2026-09-16T02:00:00Z"
          drive: "d"
        probes:
          - type: "tcp"
            target_ip: "10.0.0.1"
            port: 80
            timeout_sec: 1
            description: "test"
`
	if _, err := LoadFromReader(strings.NewReader(yamlStr)); err == nil || !strings.Contains(err.Error(), "plan_id") {
		t.Fatalf("expected literal environment placeholder to be rejected, got %v", err)
	}
}

func TestValidation_MandatoryProbesEnforced(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].Probes = nil
	errs := Validate(p)
	hasProbeErr := false
	for _, e := range errs {
		if strings.HasSuffix(e.Field, ".probes") {
			hasProbeErr = true
		}
	}
	if !hasProbeErr {
		t.Errorf("expected mandatory probe validation error for VM with 0 probes, got: %v", errs)
	}
}

func TestLoadRejectsPBSSecretInPlan(t *testing.T) {
	plan := `
version: "certistack/v1"
plan_id: "secret-rejection"
name: "Secret rejection"
compliance:
  frameworks: ["DORA"]
  retention_days: 90
admission_control:
  max_host_ram_percent: 80
  max_host_iowait_percent: 10
  defer_retry_interval_sec: 1
  max_defer_retries: 1
network:
  mode: "simple"
  zone_id: "csZone99"
  vnet_id: "csVn99"
  ip_range: "10.99.0.0/24"
  probe_ip: "10.99.0.1"
storage:
  pbs_password: "must-not-be-in-a-plan"
tiers:
  - level: 1
    name: "one"
    vms:
      - vmid: 9099
        name: "test"
        source_pbs:
          storage_id: "pbs"
          snapshot: "vm/1/2026-01-01T00:00:00Z"
          drive: "drive-scsi0"
        probes:
          - type: "qmp"
            timeout_sec: 1
`
	_, err := LoadFromReader(strings.NewReader(plan))
	if err == nil || !strings.Contains(err.Error(), "pbs_password") {
		t.Fatalf("expected pbs_password schema rejection, got %v", err)
	}
}

// A plan written with the alias spellings (the `certistack/v1` version, the
// `admission` block, `subnet_cidr`, `tier` and `target_vmid`) loads as one
// written with the canonical ones.
func TestAPlanInTheAliasSpellingsLoads(t *testing.T) {
	yamlStr := `
version: "certistack/v1"
plan_id: "alias-spellings"
name: "Restore test in alias spellings"

admission:
  max_host_ram_percent: 85.0
  max_host_io_wait_percent: 12.0
  defer_retry_interval_sec: 10
  max_defer_retries: 3

network:
  mode: "simple"
  zone_id: "csLab01"
  vnet_id: "csVn01"
  subnet_cidr: "10.250.0.0/24"
  probe_ip: "10.250.0.2"

storage:
  pbs_repository: "root@pam@10.10.10.50:8007:backup"
  scratch_dir: "/var/lib/certistack/scratch"

tiers:
  - tier: 1
    name: "Reference Tier"
    vms:
      - target_vmid: 9901
        source_vmid: 9000
        name: "ephemeral-golden-test"
        probes:
          - type: "dns"
            target_ip: "10.250.0.1"
            port: 53
            domain: "corp.local"
            timeout_sec: 10
          - type: "ldap"
            target_ip: "10.250.0.1"
            port: 389
            timeout_sec: 10
          - type: "screendump"
            timeout_sec: 10

compliance:
  frameworks: ["DORA", "SOC2", "CIS_V8"]
  retention_days: 2555
  sign_key_path: "/etc/certistack/keys/signing.ed25519"
`
	p, err := LoadFromReader(strings.NewReader(yamlStr))
	if err != nil {
		t.Fatalf("expected the plan in alias spellings to parse and validate successfully, got: %v", err)
	}

	if p.Version != "certistack/v1" {
		t.Errorf("expected version certistack/v1, got %s", p.Version)
	}
	if p.Network.IPRange != "10.250.0.0/24" {
		t.Errorf("expected IPRange normalized from subnet_cidr, got %s", p.Network.IPRange)
	}
	if len(p.Tiers) != 1 || p.Tiers[0].Level != 1 {
		t.Errorf("expected Tier 1 level 1, got %+v", p.Tiers)
	}
	vm := p.Tiers[0].VMs[0]
	if vm.VMID != 9901 {
		t.Errorf("expected VMID normalized from target_vmid, got %d", vm.VMID)
	}
	if len(vm.Probes) != 3 {
		t.Errorf("expected 3 probes, got %d", len(vm.Probes))
	}
}

func TestValidation_RejectsSandboxGateway(t *testing.T) {
	p := validPlan()
	p.Network.Gateway = "10.100.0.1"

	errs := Validate(p)
	for _, err := range errs {
		if err.Field == "network.gateway" && strings.Contains(err.Message, "must be empty") {
			return
		}
	}
	t.Fatalf("expected a no-gateway validation error, got: %v", errs)
}

func TestValidation_RejectsUnimplementedNetworkIPAM(t *testing.T) {
	p := validPlan()
	p.Network.IPAM = "netbox"

	errs := Validate(p)
	for _, err := range errs {
		if err.Field == "network.ipam" && strings.Contains(err.Message, "not implemented") {
			return
		}
	}
	t.Fatalf("expected a not-implemented network.ipam validation error, got: %v", errs)
}

func TestValidation_RejectsUnimplementedNetworkMTU(t *testing.T) {
	p := validPlan()
	p.Network.MTU = 9000

	errs := Validate(p)
	for _, err := range errs {
		if err.Field == "network.mtu" && strings.Contains(err.Message, "not implemented") {
			return
		}
	}
	t.Fatalf("expected a not-implemented network.mtu validation error, got: %v", errs)
}

func TestValidation_RejectsNegativeRTOTargetSeconds(t *testing.T) {
	p := validPlan()
	p.Compliance.RTOTargetSeconds = -1

	errs := Validate(p)
	for _, err := range errs {
		if err.Field == "compliance.rto_target_seconds" {
			return
		}
	}
	t.Fatalf("expected a compliance.rto_target_seconds validation error, got: %v", errs)
}

func TestValidation_RejectsNegativeSoakTimeSec(t *testing.T) {
	p := validPlan()
	p.Tiers[0].SoakTimeSec = -1

	errs := Validate(p)
	for _, err := range errs {
		if err.Field == "tiers[0].soak_time_sec" {
			return
		}
	}
	t.Fatalf("expected a tiers[0].soak_time_sec validation error, got: %v", errs)
}

func TestValidation_RequiresVXLANVNI(t *testing.T) {
	p := validPlan()
	p.Network.Mode = "vxlan"
	p.Network.Tag = 0

	for _, err := range Validate(p) {
		if err.Field == "network.tag" && strings.Contains(err.Message, "VXLAN VNI") {
			return
		}
	}
	t.Fatalf("expected a VXLAN VNI validation error, got: %v", Validate(p))
}

func TestLoadFromReaderRequiresExplicitVXLANVNI(t *testing.T) {
	plan := validPlan()
	plan.Network.Mode = "vxlan"
	plan.Network.Tag = 0
	plan.Network.Peers = "10.0.0.1"
	data, err := yaml.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}

	if _, err := LoadFromReader(bytes.NewReader(data)); err == nil || !strings.Contains(err.Error(), "network.tag") {
		t.Fatalf("LoadFromReader accepted an omitted VXLAN VNI: %v", err)
	}
}

// A simple network's VNet carries no tag, so a plan that sets one is
// refused at load: otherwise `mode: simple` with `tag: 4242` would load, the
// preview would say "tag 4242", and the VNet request would have none. A vxlan
// network's VNI is what `tag` is for.
func TestLoadFromReaderRefusesATagOnASimpleNetwork(t *testing.T) {
	load := func(t *testing.T, mutate func(*Plan)) error {
		t.Helper()
		plan := validPlan()
		mutate(plan)
		data, err := yaml.Marshal(plan)
		if err != nil {
			t.Fatalf("marshal plan: %v", err)
		}
		_, err = LoadFromReader(bytes.NewReader(data))
		return err
	}
	for name, mutate := range map[string]func(*Plan){
		"ephemeral":      func(p *Plan) { p.Network.Tag = 4242 },
		"preprovisioned": func(p *Plan) { p.Network.Tag, p.Network.Lifecycle = 4242, "preprovisioned" },
	} {
		t.Run("simple, "+name, func(t *testing.T) {
			err := load(t, mutate)
			if err == nil || !strings.Contains(err.Error(), "network.tag") || !strings.Contains(err.Error(), "only valid for vxlan") {
				t.Fatalf("LoadFromReader = %v, want network.tag refused as vxlan-only", err)
			}
		})
	}
	t.Run("simple, no tag", func(t *testing.T) {
		if err := load(t, func(p *Plan) { p.Network.Tag = 0 }); err != nil {
			t.Fatalf("LoadFromReader = %v, want a simple network without a tag accepted", err)
		}
	})
	t.Run("vxlan, a VNI", func(t *testing.T) {
		if err := load(t, func(p *Plan) { p.Network.Mode, p.Network.Tag, p.Network.Peers = "vxlan", 4242, "10.0.0.1" }); err != nil {
			t.Fatalf("LoadFromReader = %v, want a vxlan network with its VNI accepted", err)
		}
	})
}

func TestNetworkEffectiveLifecycle(t *testing.T) {
	if got := (Network{}).EffectiveLifecycle(); got != "ephemeral" {
		t.Fatalf("default network lifecycle = %q, want ephemeral", got)
	}
	if got := (Network{Lifecycle: " PreProvisioned "}).EffectiveLifecycle(); got != "preprovisioned" {
		t.Fatalf("normalized network lifecycle = %q, want preprovisioned", got)
	}
}

func TestValidation_RejectsInvalidSandboxLifecycle(t *testing.T) {
	p := validPlan()
	p.Network.Lifecycle = "shared"
	for _, err := range Validate(p) {
		if err.Field == "network.lifecycle" {
			return
		}
	}
	t.Fatalf("expected network.lifecycle validation error")
}

func TestValidation_RejectsLatestWithoutSourceVMID(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].SourceVMID = 0
	p.Tiers[0].VMs[0].SourcePBS.Snapshot = "latest"

	errs := Validate(p)
	for _, err := range errs {
		if err.Field == "tiers[0].vms[0].source_vmid" {
			return
		}
	}
	t.Fatalf("expected source_vmid error, got %v", errs)
}

// An optional QGA probe is skipped when the guest agent does not
// answer. A VM whose every probe is one could pass with nothing checked, so
// its plan is refused; one probe that is sure to assert something in the
// guest is enough (a qmp or screendump probe is not one).
func TestValidation_RejectsAProbeSetThatCanAllBeSkipped(t *testing.T) {
	optional := Probe{Type: "qga", Command: "systemctl is-active postgresql", ExpectedOutput: "active", TimeoutSec: 30, Description: "PostgreSQL unit"}
	required := optional
	required.RequireQGA = true
	ping := Probe{Type: "qga_ping", TimeoutSec: 30, Description: "agent"}
	wire := Probe{Type: "tcp", TargetIP: "10.100.0.10", Port: 5432, TimeoutSec: 30, Description: "PostgreSQL port"}
	running := Probe{Type: "qmp", TimeoutSec: 30, Description: "VM runs"}
	for name, tc := range map[string]struct {
		probes  []Probe
		refused bool
	}{
		"one optional qga":          {[]Probe{optional}, true},
		"optional qga_ping":         {[]Probe{ping}, true},
		"several optional qga":      {[]Probe{optional, ping}, true},
		"required qga":              {[]Probe{required}, false},
		"optional and required qga": {[]Probe{optional, required}, false},
		"optional qga and wire":     {[]Probe{optional, wire}, false},
		"optional qga and qmp":      {[]Probe{optional, running}, true},
	} {
		t.Run(name, func(t *testing.T) {
			p := validPlan()
			p.Tiers[0].VMs[0].Probes = tc.probes
			refused := false
			for _, err := range Validate(p) {
				if err.Field == "tiers[0].vms[0].probes" && strings.Contains(err.Message, "could pass with nothing checked") {
					refused = true
				}
			}
			if refused != tc.refused {
				t.Fatalf("%s: refused=%v, want %v; errors: %v", name, refused, tc.refused, Validate(p))
			}
		})
	}
}

// Qmp says QEMU runs the VM and a screendump only captures a framebuffer: a
// guest in a boot loop or at a "No bootable device" screen passes both. A VM
// with only such probes, or with them beside an optional QGA probe that can be
// skipped, has nothing that asserts anything in the guest, so its plan is
// refused, naming the way out. Any wire probe, or a QGA probe that cannot be
// skipped, is enough.
func TestValidation_RejectsAVMWhoseProbesNeverAssertAnythingInTheGuest(t *testing.T) {
	qmp := Probe{Type: "qmp", TimeoutSec: 30, Description: "VM runs"}
	qmpAlias := Probe{Type: "qmp_status", TimeoutSec: 30, Description: "VM runs"}
	screen := Probe{Type: "screendump", TimeoutSec: 30, Description: "console"}
	optional := Probe{Type: "qga", Command: "ping", TimeoutSec: 30, Description: "agent"}
	required := optional
	required.RequireQGA = true
	for name, tc := range map[string]struct {
		probes  []Probe
		message string // a fragment of the refusal; "" when the plan is valid
	}{
		"qmp only":                 {[]Probe{qmp}, "every probe is a hypervisor-level probe (qmp or screendump)"},
		"qmp_status alias only":    {[]Probe{qmpAlias}, "every probe is a hypervisor-level probe"},
		"screendump only":          {[]Probe{screen}, "every probe is a hypervisor-level probe"},
		"qmp and screendump":       {[]Probe{qmp, screen}, "every probe is a hypervisor-level probe"},
		"qmp and an optional qga":  {[]Probe{qmp, optional}, "no probe is sure to assert something in the guest"},
		"screen and optional qga":  {[]Probe{screen, optional}, "no probe is sure to assert something in the guest"},
		"qmp and a required qga":   {[]Probe{qmp, required}, ""},
		"qmp and a wire probe":     {[]Probe{qmp, {Type: "tcp", TargetIP: "10.100.0.10", Port: 22, TimeoutSec: 30, Description: "ssh"}}, ""},
		"screendump and http_get":  {[]Probe{screen, {Type: "http_get", TargetIP: "10.100.0.10", Port: 80, ExpectedStatus: 200, TimeoutSec: 30, Description: "web"}}, ""},
		"a wire probe alone":       {[]Probe{{Type: "tcp", TargetIP: "10.100.0.10", Port: 22, TimeoutSec: 30, Description: "ssh"}}, ""},
		"a required qga alone":     {[]Probe{required}, ""},
		"an unknown type is named": {[]Probe{{Type: "bogus", TimeoutSec: 30, Description: "x"}}, "must be one of"},
	} {
		t.Run(name, func(t *testing.T) {
			p := validPlan()
			p.Tiers[0].VMs[0].Probes = tc.probes
			var messages []string
			for _, err := range Validate(p) {
				messages = append(messages, err.Field+": "+err.Message)
			}
			joined := strings.Join(messages, "; ")
			if tc.message == "" {
				if len(messages) != 0 {
					t.Fatalf("plan refused, want it valid: %s", joined)
				}
				return
			}
			if !strings.Contains(joined, tc.message) {
				t.Fatalf("errors = %q, want one containing %q", joined, tc.message)
			}
			if tc.message != "must be one of" && !strings.Contains(joined, "tiers[0].vms[0].probes: ") {
				t.Fatalf("errors = %q, want the refusal on the VM's probes", joined)
			}
		})
	}
}

// A QGA ping answers with an empty object, so an expected_output on
// one asserts something the probe cannot check. Both spellings are refused
// with a message naming the way out; a ping without one, and the commands
// that do have output, are unaffected.
func TestValidation_RejectsExpectedOutputOnAQGAPing(t *testing.T) {
	for name, tc := range map[string]struct {
		probe   Probe
		refused bool
	}{
		"qga ping":                    {Probe{Type: "qga", Command: "ping", ExpectedOutput: "IMPOSSIBLE-AUDIT-SUBSTRING"}, true},
		"qga guest-ping":              {Probe{Type: "qga", Command: "guest-ping", ExpectedOutput: "IMPOSSIBLE-AUDIT-SUBSTRING"}, true},
		"qga ping with space":         {Probe{Type: "qga", Command: " ping ", ExpectedOutput: "x"}, true},
		"qga_ping alias":              {Probe{Type: "qga_ping", ExpectedOutput: "IMPOSSIBLE-AUDIT-SUBSTRING"}, true},
		"qga_ping alias with command": {Probe{Type: "qga_ping", Command: "guest-ping", ExpectedOutput: "x"}, true},
		"qga ping without expected":   {Probe{Type: "qga", Command: "ping"}, false},
		"qga_ping without expected":   {Probe{Type: "qga_ping"}, false},
		"hostname with expected":      {Probe{Type: "qga", Command: "hostname", ExpectedOutput: "web"}, false},
		"systemctl with expected":     {Probe{Type: "qga", Command: "systemctl is-active postgresql@16-main", ExpectedOutput: "active"}, false},
		"sc query with expected":      {Probe{Type: "qga", Command: "sc query W3SVC", ExpectedOutput: "RUNNING"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			p := validPlan()
			tc.probe.RequireQGA = true
			tc.probe.TimeoutSec = 30
			tc.probe.Description = "guest agent"
			p.Tiers[0].VMs[0].Probes = append(p.Tiers[0].VMs[0].Probes, tc.probe)
			refused := false
			for _, err := range Validate(p) {
				if err.Field == "tiers[0].vms[0].probes[1].expected_output" && strings.Contains(err.Message, "a QGA ping has no output to match") && strings.Contains(err.Message, "remove expected_output") {
					refused = true
				} else {
					t.Errorf("unexpected error %s: %s", err.Field, err.Message)
				}
			}
			if refused != tc.refused {
				t.Fatalf("refused=%v, want %v", refused, tc.refused)
			}
		})
	}
}

func TestValidation_RejectsUnsafePBSSnapshotSelector(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].SourcePBS.Snapshot = "vm/100/2026-09-16T02:00:00Z/--repository"

	for _, err := range Validate(p) {
		if err.Field == "tiers[0].vms[0].source_pbs.snapshot" {
			return
		}
	}
	t.Fatal("expected unsafe PBS snapshot selector to be rejected")
}

func TestVM_SandboxAddressDefaultsToAutoAndInfersSingleWireProbeAddress(t *testing.T) {
	vm := VM{Probes: []Probe{
		{Type: "http", TargetIP: "10.100.0.10"},
		{Type: "tcp", TargetIP: "10.100.0.10"},
		{Type: "qga"},
	}}
	if got := vm.NetworkRecovery.EffectiveMode(); got != "auto" {
		t.Fatalf("default recovery mode = %q, want auto", got)
	}
	address, configured, err := vm.SandboxAddress(Network{IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"})
	if err != nil || !configured || address != "10.100.0.10" {
		t.Fatalf("SandboxAddress = %q, %v, %v", address, configured, err)
	}
}

func TestValidation_RejectsAmbiguousOverlayNetworkRecovery(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].Probes = append(p.Tiers[0].VMs[0].Probes, Probe{
		Type: "tcp", TargetIP: "10.100.0.11", Port: 80, TimeoutSec: 5, Description: "other guest address",
	})

	errs := Validate(p)
	for _, err := range errs {
		if err.Field == "tiers[0].vms[0].network_recovery" && strings.Contains(err.Message, "multiple guest addresses") {
			return
		}
	}
	t.Fatalf("expected ambiguous network recovery error, got %v", errs)
}

func TestValidation_RejectsDuplicateSandboxRecoveryAddresses(t *testing.T) {
	p := validPlan()
	first := p.Tiers[0].VMs[0]
	first.VMID = 9002
	first.Name = "other"
	first.NetworkRecovery.Mode = "auto"
	p.Tiers[0].VMs[0].NetworkRecovery.Mode = "auto"
	first.NetworkRecovery.SandboxIP = "10.100.0.10"
	p.Tiers[0].VMs[0].NetworkRecovery.SandboxIP = "10.100.0.10"
	p.Tiers[0].VMs = append(p.Tiers[0].VMs, first)

	errs := Validate(p)
	for _, err := range errs {
		if err.Field == "tiers[0].vms[1].network_recovery.sandbox_ip" && strings.Contains(err.Message, "must be unique") {
			return
		}
	}
	t.Fatalf("expected duplicate sandbox address error, got %v", errs)
}

func TestValidation_RejectsUnsafeRecoveryInterfaceName(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].NetworkRecovery = NetworkRecovery{Mode: "auto", InterfaceName: "eth0;bad"}

	errs := Validate(p)
	for _, err := range errs {
		if err.Field == "tiers[0].vms[0].network_recovery.interface_name" {
			return
		}
	}
	t.Fatalf("expected recovery interface name error, got %v", errs)
}

// "." and ".." passed the character allowlist, but the kernel refuses
// both as interface names (RTNETLINK answers: Invalid argument), so a plan that
// names one can never get the recovery address in the guest. The plan
// validator refuses both names, beside the semicolon control.
func TestValidation_RejectsKernelReservedInterfaceNames(t *testing.T) {
	field := "tiers[0].vms[0].network_recovery.interface_name"
	cases := []struct {
		name    string
		invalid bool
	}{
		{".", true},
		{"..", true},
		{"lo", true},
		{"eth0;bad", true},
		{"", false}, // omitted: the field is optional
		{"eth0", false},
		{"eth0.100", false},
		{"...", false},
		{"123456789012345", false},
		{"1234567890123456", true},
		{"a b", true},
		{"a/b", true},
		{"a:b", true},
		{"é", true},
	}
	for _, tc := range cases {
		p := validPlan()
		p.Tiers[0].VMs[0].NetworkRecovery = NetworkRecovery{Mode: "auto", InterfaceName: tc.name}
		var message string
		for _, err := range Validate(p) {
			if err.Field == field {
				message = err.Message
			}
		}
		if (message != "") != tc.invalid {
			t.Errorf("interface_name %q: error %q, want an error: %t", tc.name, message, tc.invalid)
		}
		if tc.invalid && !strings.Contains(message, `not "lo", "." or ".."`) {
			t.Errorf("interface_name %q: error %q does not state the rule", tc.name, message)
		}
	}
}

func TestValidation_RejectsMalformedMACInPreserveMode(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].MAC = "not-a-mac"
	p.Tiers[0].VMs[0].NetworkRecovery.Mode = "preserve"
	for _, err := range Validate(p) {
		if err.Field == "tiers[0].vms[0].mac" {
			return
		}
	}
	t.Fatal("expected malformed MAC to be rejected before preserve-mode execution")
}

func TestLoadFromReader_RejectsUnknownFields(t *testing.T) {
	plan := `
version: v1
plan_id: example
name: Example
unexpected: value
`
	if _, err := LoadFromReader(strings.NewReader(plan)); err == nil {
		t.Fatal("expected unknown YAML field to be rejected")
	}
}

func TestLoadFromReader_RejectsMultipleYAMLDocuments(t *testing.T) {
	plan := `
version: v1
plan_id: example
name: Example
---
version: v1
plan_id: ignored-if-accepted
name: Unsafe second document
`
	_, err := LoadFromReader(strings.NewReader(plan))
	if err == nil || !strings.Contains(err.Error(), "exactly one YAML document") {
		t.Fatalf("multiple YAML documents error = %v, want explicit rejection", err)
	}
}

func validationFields(errs ValidationErrors) string {
	fields := make([]string, 0, len(errs))
	for _, e := range errs {
		fields = append(fields, e.Field+": "+e.Message)
	}
	return strings.Join(fields, "\n")
}

func secondVM(p *Plan) VM {
	vm := p.Tiers[0].VMs[0]
	vm.VMID, vm.Name = 9002, "cs-test-dc02"
	vm.Probes = []Probe{{Type: "tcp", TargetIP: "10.100.0.11", Port: 389, TimeoutSec: 5}}
	return vm
}

func TestValidation_RejectsSelectorsTheRunnerCannotHonor(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate    func(*Plan)
		wantField string
	}{
		"storage id other than pbs": {func(p *Plan) { p.Tiers[0].VMs[0].SourcePBS.StorageID = "certistack-test" }, "source_pbs.storage_id"},
		"mixed namespaces": {func(p *Plan) {
			second := secondVM(p)
			second.SourcePBS.Namespace = "other"
			p.Tiers[0].VMs[0].SourcePBS.Namespace = "certistack-test"
			p.Tiers[0].VMs = append(p.Tiers[0].VMs, second)
		}, "vms[1].source_pbs.namespace"},
		"restore onto its own source":       {func(p *Plan) { p.Tiers[0].VMs[0].SourceVMID = p.Tiers[0].VMs[0].VMID }, "vms[0].vmid"},
		"zone id over 8 characters":         {func(p *Plan) { p.Network.ZoneID = "csSbMin01" }, "network.zone_id"},
		"vnet id over 8 characters":         {func(p *Plan) { p.Network.VNetID = "csVnMin01" }, "network.vnet_id"},
		"vnet id the same as the zone id":   {func(p *Plan) { p.Network.VNetID = p.Network.ZoneID }, "network.vnet_id"},
		"vnet id the zone id in other case": {func(p *Plan) { p.Network.VNetID = strings.ToUpper(p.Network.ZoneID) }, "network.vnet_id"},
		"http probe without port": {func(p *Plan) {
			p.Tiers[0].VMs[0].Probes = []Probe{{Type: "http", TargetIP: "10.100.0.10", ExpectedStatus: 200, TimeoutSec: 5}}
		}, "probes[0].port"},
	} {
		t.Run(name, func(t *testing.T) {
			p := validPlan()
			tc.mutate(p)
			p.Normalize()
			errs := Validate(p)
			if !strings.Contains(validationFields(errs), tc.wantField) {
				t.Fatalf("%s: want an error on %s, got:\n%s", name, tc.wantField, validationFields(errs))
			}
		})
	}
}

func TestValidation_AcceptsOneNamespaceAcrossVMs(t *testing.T) {
	p := validPlan()
	p.Storage.PBSNamespace = "certistack-test"
	p.Tiers[0].VMs = append(p.Tiers[0].VMs, secondVM(p))
	p.Normalize()
	if errs := Validate(p); len(errs) != 0 {
		t.Fatalf("single-namespace plan rejected:\n%s", validationFields(errs))
	}
}

func TestValidation_OverlayStorageMustBeAPVEStorageID(t *testing.T) {
	for id, ok := range map[string]bool{"certistack-scratch": true, "local": true, "cs.scratch_1": true,
		"CertiStack": false, "1scratch": false, "scratch-": false, "a b": false} {
		p := validPlan()
		p.Storage.OverlayStorage = id
		p.Normalize()
		got := !strings.Contains(validationFields(Validate(p)), "storage.overlay_storage")
		if got != ok {
			t.Errorf("overlay_storage %q accepted=%v, want %v", id, got, ok)
		}
	}
}

// A sandbox range in loopback or other host-local space is refused: a TCP probe
// would pass against a listener on the worker host, with no guest present.
func TestValidateRejectsHostLocalSandboxRanges(t *testing.T) {
	for _, tc := range []struct{ ipRange, probeIP, target string }{
		{"127.0.0.0/24", "127.0.0.1", "127.0.0.10"},
		{"169.254.10.0/24", "169.254.10.1", "169.254.10.10"},
		{"0.0.0.0/0", "10.100.0.1", "10.100.0.10"},
		{"224.0.0.0/24", "224.0.0.1", "224.0.0.10"},
	} {
		p := validPlan()
		p.Network.IPRange = tc.ipRange
		p.Network.ProbeIP = tc.probeIP
		p.Tiers[0].VMs[0].Probes[0].TargetIP = tc.target
		if !hasFieldError(Validate(p), "network.ip_range") {
			t.Errorf("ip_range %s was accepted", tc.ipRange)
		}
	}
}

func TestValidateRejectsReservedProbeTargets(t *testing.T) {
	for _, target := range []string{"10.100.0.0", "10.100.0.255"} {
		p := validPlan()
		p.Tiers[0].VMs[0].Probes[0].TargetIP = target
		if !hasFieldError(Validate(p), "tiers[0].vms[0].probes[0].target_ip") {
			t.Errorf("probe target %s was accepted", target)
		}
	}
}

func hasFieldError(errs []ValidationError, field string) bool {
	for _, err := range errs {
		if err.Field == field {
			return true
		}
	}
	return false
}

func TestRequireQuiescedBackupParses(t *testing.T) {
	var p Plan
	if err := yaml.Unmarshal([]byte("tiers:\n  - vms:\n      - vmid: 1\n        require_quiesced_backup: true\n"), &p); err != nil {
		t.Fatal(err)
	}
	if !p.Tiers[0].VMs[0].RequireQuiescedBackup {
		t.Fatal("require_quiesced_backup: true did not parse")
	}
}

func TestCopyBeforeBootIsValidated(t *testing.T) {
	for mode, ok := range map[string]bool{"": true, "auto": true, "always": true, "never": true, "sometimes": false} {
		p := validPlan()
		p.Tiers[0].VMs[0].CopyBeforeBoot = mode
		rejected := false
		for _, e := range Validate(p) {
			if strings.HasSuffix(e.Field, ".copy_before_boot") {
				rejected = true
			}
		}
		if rejected == ok {
			t.Errorf("copy_before_boot %q: rejected %v", mode, rejected)
		}
	}
}

func TestValidateMaxConcurrentBoots(t *testing.T) {
	for _, tc := range []struct {
		limit, settle int
		wantField     string
	}{
		{0, 0, ""},
		{2, 0, ""},
		{2, 300, ""},
		{-1, 0, "admission_control.max_concurrent_boots"},
		{65, 0, "admission_control.max_concurrent_boots"},
		{2, 3601, "admission_control.boot_settle_sec"},
		{0, 120, "admission_control.boot_settle_sec"}, // no effect without a limit
	} {
		p := validPlan()
		p.AdmissionControl.MaxConcurrentBoots, p.AdmissionControl.BootSettleSec = tc.limit, tc.settle
		var fields []string
		for _, e := range Validate(p) {
			fields = append(fields, e.Field)
		}
		got := strings.Join(fields, ",")
		if (tc.wantField == "") != (got == "") || !strings.Contains(got, tc.wantField) {
			t.Errorf("limit %d settle %d: errors %q, want %q", tc.limit, tc.settle, got, tc.wantField)
		}
	}
	if got := (AdmissionControl{}).BootSettle(); got != DefaultBootSettleSec*time.Second {
		t.Errorf("default settle = %s", got)
	}
}

// A plan that leaves out source_pbs.storage_id still gets its
// defaults, but only for what it leaves out: a pinned snapshot and a legacy
// disk it gives are kept, and a malformed one is refused, not replaced.
func TestNormalizeNeverReplacesAGivenSnapshotOrDisk(t *testing.T) {
	const pin = "vm/100/2026-03-30T02:00:00Z"
	for _, tc := range []struct {
		name                    string
		storage                 string
		source                  int
		repository              bool
		backupConfig            bool
		snapshot, drive         string
		wantSnapshot, wantDrive string
		wantErr                 string
	}{
		{name: "explicit storage (control)", storage: "pbs", source: 100, snapshot: pin, drive: "drive-virtio0", wantSnapshot: pin, wantDrive: "drive-virtio0"},
		{name: "storage omitted, source VM", source: 100, snapshot: pin, drive: "drive-virtio0", wantSnapshot: pin, wantDrive: "drive-virtio0"},
		{name: "storage omitted, backup config", source: 100, backupConfig: true, snapshot: pin, drive: "drive-virtio0", wantSnapshot: pin, wantDrive: "drive-virtio0"},
		{name: "storage omitted, repository only", repository: true, snapshot: pin, drive: "drive-virtio0", wantSnapshot: pin, wantDrive: "drive-virtio0"},
		{name: "storage omitted, malformed snapshot", source: 100, snapshot: "not-a-snapshot", drive: "drive-virtio0", wantErr: "source_pbs.snapshot"},
		// What the plan leaves out still defaults, one part at a time.
		{name: "only source VM", source: 100, wantSnapshot: "vm/100/latest", wantDrive: "drive-scsi0"},
		{name: "source VM and a disk", source: 100, drive: "drive-virtio0", wantSnapshot: "vm/100/latest", wantDrive: "drive-virtio0"},
		{name: "source VM and a pin", source: 100, snapshot: pin, wantSnapshot: pin, wantDrive: "drive-scsi0"},
		{name: "repository only, nothing else", repository: true, wantSnapshot: "vm/9001/latest", wantDrive: "drive-scsi0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validPlan()
			p.UseBackupConfig = tc.backupConfig
			if tc.repository {
				p.Storage.PBSRepository = "audit@pbs@192.0.2.254:backup"
			}
			vm := &p.Tiers[0].VMs[0]
			vm.SourceVMID = tc.source
			vm.SourcePBS = SourcePBS{StorageID: tc.storage, Snapshot: tc.snapshot, Drive: tc.drive}
			data, err := yaml.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			// Leave the keys out of the YAML, as a plan author would.
			for _, key := range []string{`storage_id: ""`, `snapshot: ""`, `drive: ""`} {
				data = bytes.Replace(data, []byte(key), []byte("# omitted"), 1)
			}
			loaded, err := LoadFromReader(bytes.NewReader(data))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want a %s error", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := loaded.Tiers[0].VMs[0].SourcePBS
			if got.StorageID != "pbs" || got.Snapshot != tc.wantSnapshot || got.Drive != tc.wantDrive {
				t.Fatalf("source_pbs = %+v, want snapshot %s and drive %s", got, tc.wantSnapshot, tc.wantDrive)
			}
			if drives := got.RestoreDrives(); len(drives) != 1 || drives[0].Archive != tc.wantDrive {
				t.Fatalf("restored drives = %+v, want %s only", drives, tc.wantDrive)
			}
		})
	}
}

// The legacy drive and drives must not disagree; a disk only the
// legacy field names would silently not be restored.
func TestValidation_LegacyDriveMustBeAmongDrives(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].SourcePBS.Drive = "drive-virtio0"
	p.Tiers[0].VMs[0].SourcePBS.Drives = []SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}
	if !hasFieldError(Validate(p), "tiers[0].vms[0].source_pbs.drive") {
		t.Fatal("a legacy drive that drives does not restore was accepted")
	}
	for _, drive := range []string{"drive-scsi0", "drive-scsi0.img.fidx"} {
		p.Tiers[0].VMs[0].SourcePBS.Drive = drive
		if errs := Validate(p); len(errs) != 0 {
			t.Fatalf("legacy drive %s among drives: %v", drive, errs)
		}
	}
}

// source_vmid and an explicit snapshot group must name the same
// VM; either alone, or both agreeing, is accepted.
func TestValidation_SourceVMIDMustMatchTheSnapshotGroup(t *testing.T) {
	for _, tc := range []struct {
		source   int
		snapshot string
		ok       bool
	}{
		{100, "vm/200/2026-09-27T03:00:09Z", false},
		{100, "vm/200/latest", false},
		{100, "vm/100/2026-09-27T03:00:09Z", true},
		{100, "vm/100/latest", true},
		{100, "latest", true},
		{0, "vm/200/2026-09-27T03:00:09Z", true},
	} {
		p := validPlan()
		vm := &p.Tiers[0].VMs[0]
		vm.SourceVMID, vm.SourcePBS.Snapshot = tc.source, tc.snapshot
		rejected := hasFieldError(Validate(p), "tiers[0].vms[0].source_pbs.snapshot")
		if rejected == tc.ok {
			t.Errorf("source_vmid %d with snapshot %s: rejected %v", tc.source, tc.snapshot, rejected)
		}
	}
}

// A VM ID is spelled canonically: "+7001" and "07001" parse as 7001, and
// attest.snapshotGroup refuses both, so a plan that validated with one could
// not be bound to its source VM by verify-report --expect-plan. Validation
// refuses the spelling up front, with or without a source_vmid.
func TestValidation_SnapshotSelectorRefusesNonCanonicalVMIDs(t *testing.T) {
	const when = "2026-09-27T03:00:09Z"
	for _, tc := range []struct {
		snapshot string
		ok       bool
	}{
		{"vm/7001/latest", true},
		{"vm/7001/" + when, true},
		{"vm/+7001/latest", false},
		{"vm/07001/latest", false},
		{"vm/007001/" + when, false},
		{"vm/+7001/" + when, false},
		{"vm/0/latest", false},
		{"vm/-7001/latest", false},
	} {
		for _, source := range []int{0, 7001} {
			p := validPlan()
			vm := &p.Tiers[0].VMs[0]
			vm.SourceVMID, vm.SourcePBS.Snapshot = source, tc.snapshot
			rejected := hasFieldError(Validate(p), "tiers[0].vms[0].source_pbs.snapshot")
			if rejected == tc.ok {
				t.Errorf("source_vmid %d with snapshot %s: rejected %v, want %v", source, tc.snapshot, rejected, !tc.ok)
			}
		}
	}
	for snapshot, want := range map[string]int{"vm/7001/latest": 7001, "vm/+7001/latest": 0, "vm/07001/" + when: 0, "latest": 0} {
		if got, ok := snapshotGroupVMID(snapshot); got != want || ok != (want > 0) {
			t.Errorf("snapshotGroupVMID(%q) = %d, %v; want %d", snapshot, got, ok, want)
		}
	}
}

// Vmid and its alias target_vmid must not name two sandbox VMs.
func TestValidation_TargetVMIDAliasMustAgreeWithVMID(t *testing.T) {
	p := validPlan()
	p.Tiers[0].VMs[0].TargetVMID = 9001
	if errs := Validate(p); len(errs) != 0 {
		t.Fatalf("target_vmid equal to vmid: %v", errs)
	}
	p.Tiers[0].VMs[0].TargetVMID = 9100
	if !hasFieldError(Validate(p), "tiers[0].vms[0].target_vmid") {
		t.Fatal("target_vmid 9100 beside vmid 9001 was accepted")
	}
}

// A plan_id is the name of the report's directory and of the plan in the
// evidence hub, which keeps no report whose plan_id is longer than 128
// characters: such a plan is refused when it is validated, not after a run
// whose report the hub would then refuse for ever.
func TestPlanIDIsBoundedTo128Characters(t *testing.T) {
	for _, tc := range []struct {
		id string
		ok bool
	}{
		{"a", true},
		{strings.Repeat("a", 128), true},
		{strings.Repeat("a", 129), false},
		{strings.Repeat("a", 4096), false},
		{"has space", false},
		{"dot.in.it", false},
		{"", false},
	} {
		plan := validPlan()
		plan.PlanID = tc.id
		errs := Validate(plan)
		got := true
		for _, e := range errs {
			if e.Field == "plan_id" {
				got = false
			}
		}
		if got != tc.ok {
			t.Errorf("plan_id of %d characters %q: accepted=%v, want %v (%v)", len(tc.id), tc.id[:min(len(tc.id), 20)], got, tc.ok, errs)
		}
	}
}

func TestValidateVMName(t *testing.T) {
	for name, ok := range map[string]bool{
		"cs-web-01":             true,
		"web01.example.com":     true,
		"a":                     true,
		strings.Repeat("a", 63): true,
		strings.Repeat("a", 64): false,
		"web 01":                false,
		"web_01":                false,
		"-web":                  false,
		"web-":                  false,
		"web.":                  false,
	} {
		p := validPlan()
		p.Tiers[0].VMs[0].Name = name
		found := false
		for _, e := range Validate(p) {
			if strings.HasSuffix(e.Field, ".name") {
				found = true
			}
		}
		if found == ok {
			t.Errorf("name %q: refused=%v, want %v", name, found, !ok)
		}
	}
}

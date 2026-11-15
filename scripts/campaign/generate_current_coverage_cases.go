// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build ignore

// Run with go run; it shares a directory with the other campaign tool, so
// ordinary builds skip it.
//
// Generate CertiStack recovery cases from the credentials-free current
// coverage-fleet target manifest.  The manifest is an inventory handoff, not
// a CertiStack plan: this tool assigns disposable restore IDs and makes the
// PBS namespace and QGA-only acceptance check explicit.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cliftcloud/certistack/pkg/config"
	"gopkg.in/yaml.v3"
)

const manifestName = "certistack-campaign.manifest"

var allowedNodePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type targetManifest struct {
	SchemaVersion int `yaml:"schema_version"`
	Lab           struct {
		PBSNamespace  string `yaml:"pbs_namespace"`
		SourceNetwork struct {
			VLANID int    `yaml:"vlan_id"`
			CIDR   string `yaml:"cidr"`
		} `yaml:"source_network"`
	} `yaml:"lab"`
	TestBoundary struct {
		SyntheticDataOnly     bool   `yaml:"synthetic_data_only"`
		IntendedTest          string `yaml:"intended_test"`
		WorkloadConfiguration string `yaml:"workload_configuration"`
		Readiness             string `yaml:"readiness"`
	} `yaml:"test_boundary"`
	Targets []target `yaml:"targets"`
}

type target struct {
	VMID         int    `yaml:"vm_id"`
	Name         string `yaml:"name"`
	Address      string `yaml:"address"`
	OSID         string `yaml:"os_id"`
	Workload     string `yaml:"workload"`
	WorkloadType string `yaml:"workload_type"`
	Status       string `yaml:"status"`
}

type scenario struct {
	name string
	vms  []config.VM
}

// isolationAttestation records the boundary which makes it safe to reuse
// source addressing. Matching VLAN tags or IPv4 ranges are only safe when the
// restore VNet is a separate L2 domain; that fact is partly operational and
// cannot be inferred from a plan alone.
type isolationAttestation struct {
	SchemaVersion        int    `yaml:"schema_version"`
	SourceVLANID         int    `yaml:"source_vlan_id"`
	SourceCIDR           string `yaml:"source_cidr"`
	RestoreZoneID        string `yaml:"restore_zone_id"`
	RestoreVNetID        string `yaml:"restore_vnet_id"`
	RestoreVLANID        int    `yaml:"restore_vlan_id"`
	RestoreCIDR          string `yaml:"restore_cidr"`
	L2Isolated           bool   `yaml:"l2_isolated"`
	NoPhysicalUplink     bool   `yaml:"no_physical_uplink"`
	NoGateway            bool   `yaml:"no_gateway"`
	NoSNAT               bool   `yaml:"no_snat"`
	NoRoutedPathToSource bool   `yaml:"no_routed_path_to_source"`
}

func main() {
	targetPath := flag.String("targets", "", "current-coverage-test-targets.yml inventory handoff")
	outDir := flag.String("out", "cases-coverage-fleet-current", "directory for generated CertiStack cases")
	expectedTargets := flag.Int("expected-targets", 0, "exact number of accepted source VMs expected in the inventory (required)")
	storageID := flag.String("storage-id", "pbs", "source_pbs.storage_id for every VM; only pbs (the run's PBS_REPOSITORY endpoint) is accepted")
	zoneID := flag.String("zone-id", "", "preprovisioned isolated PVE SDN zone")
	vnetID := flag.String("vnet-id", "", "preprovisioned isolated PVE SDN VNet")
	vlanTag := flag.Int("vlan-tag", 0, "isolated restore VLAN tag")
	ipRange := flag.String("ip-range", "", "isolated restore subnet CIDR")
	probeIP := flag.String("probe-ip", "", "controller probe IP inside --ip-range")
	isolationAttestationPath := flag.String("isolation-attestation", "", "YAML attestation required when restore VLAN or CIDR reuses source addressing")
	signKeyPath := flag.String("sign-key-path", "", "optional compliance.sign_key_path for the plans: the Enterprise Edition signs reports with that key; the Community Edition writes unsigned reports and ignores it")
	targetOffset := flag.Int("target-vmid-offset", 10000, "add this offset to each source VMID for the disposable restore VM")
	allowedNodesValue := flag.String("allowed-nodes", os.Getenv("CERTISTACK_ALLOWED_NODES"), "comma-separated PVE node names permitted to run the generated campaign (required)")
	flag.Parse()
	allowedNodes, err := parseAllowedNodes(*allowedNodesValue)
	if err != nil {
		fatalf("--allowed-nodes or CERTISTACK_ALLOWED_NODES is required: %v", err)
	}

	if *targetPath == "" {
		fatalf("--targets is required")
	}
	if *expectedTargets <= 0 {
		fatalf("--expected-targets must be a positive exact inventory count; do not treat a partial fleet as release coverage")
	}
	if *targetOffset <= 0 {
		fatalf("--target-vmid-offset must be positive")
	}
	if *zoneID == "" || *vnetID == "" || *vlanTag <= 0 || *ipRange == "" || *probeIP == "" {
		fatalf("--zone-id, --vnet-id, --vlan-tag, --ip-range, and --probe-ip are required")
	}
	// The engine restores every disk through the one PBS endpoint a run is
	// configured with (PBS_REPOSITORY) and rejects any other storage_id.
	if *storageID != "pbs" {
		fatalf("--storage-id must be pbs (got %q): a run restores from the PBS endpoint in PBS_REPOSITORY, not from a named PVE storage; omit the flag", *storageID)
	}
	data, err := os.ReadFile(*targetPath)
	if err != nil {
		fatalf("read targets: %v", err)
	}
	var inventory targetManifest
	if err := yaml.Unmarshal(data, &inventory); err != nil {
		fatalf("parse targets: %v", err)
	}
	if inventory.Lab.PBSNamespace != "coverage-fleet" {
		fatalf("targets must declare the coverage-fleet PBS namespace, got %q", inventory.Lab.PBSNamespace)
	}
	if inventory.SchemaVersion != 1 {
		fatalf("targets schema_version is %d; expected supported version 1", inventory.SchemaVersion)
	}
	if !inventory.TestBoundary.SyntheticDataOnly || inventory.TestBoundary.IntendedTest != "backup_restore" {
		fatalf("targets must be an accepted synthetic backup_restore inventory")
	}
	if inventory.TestBoundary.Readiness != "ready" {
		fatalf("targets readiness is %q; do not generate executable recovery cases until every template has passed OS identity, cloud-init, SSH, and QGA acceptance", inventory.TestBoundary.Readiness)
	}
	if inventory.TestBoundary.WorkloadConfiguration != "ready" && inventory.TestBoundary.WorkloadConfiguration != "pending" {
		fatalf("targets workload_configuration is %q; expected ready or pending", inventory.TestBoundary.WorkloadConfiguration)
	}
	if len(inventory.Targets) == 0 {
		fatalf("targets contains no VM entries")
	}
	if len(inventory.Targets) != *expectedTargets {
		fatalf("targets contains %d VM entries, expected exactly %d; refresh the approved inventory or explicitly narrow the release support boundary", len(inventory.Targets), *expectedTargets)
	}
	attestationData, reusedSourceAddressing := validateRestoreNetwork(inventory, *zoneID, *vnetID, *vlanTag, *ipRange, *probeIP, *isolationAttestationPath)

	vms := make([]config.VM, 0, len(inventory.Targets))
	seenSources := make(map[int]bool, len(inventory.Targets))
	seenTargets := make(map[int]bool, len(inventory.Targets))
	seenAddresses := make(map[string]bool, len(inventory.Targets))
	maxInt := int(^uint(0) >> 1)
	for _, item := range inventory.Targets {
		if item.VMID <= 0 || item.Name == "" || item.OSID == "" || item.Workload == "" || item.WorkloadType == "" {
			fatalf("target %q is missing a VMID, name, OS ID, workload, or workload type", item.Name)
		}
		if !validInventoryToken(item.Name) || !validInventoryToken(item.OSID) || !validInventoryToken(item.Workload) || !validInventoryToken(item.WorkloadType) {
			fatalf("target %q has an unsafe name, OS ID, workload, or workload type", item.Name)
		}
		if item.Status != "running" {
			fatalf("target %s is not running (status %q)", item.Name, item.Status)
		}
		address := net.ParseIP(item.Address)
		if address == nil || address.To4() == nil {
			fatalf("target %s has an invalid IPv4 address %q", item.Name, item.Address)
		}
		if seenAddresses[address.String()] {
			fatalf("target address %s appears more than once", address)
		}
		if seenSources[item.VMID] {
			fatalf("source VMID %d appears more than once", item.VMID)
		}
		if item.VMID > maxInt-*targetOffset {
			fatalf("source VMID %d plus restore offset %d overflows", item.VMID, *targetOffset)
		}
		restoreVMID := item.VMID + *targetOffset
		if seenTargets[restoreVMID] || restoreVMID == item.VMID {
			fatalf("restore VMID allocation %d is not unique", restoreVMID)
		}
		seenSources[item.VMID] = true
		seenTargets[restoreVMID] = true
		seenAddresses[address.String()] = true

		vms = append(vms, config.VM{
			VMID:       restoreVMID,
			SourceVMID: item.VMID,
			Name:       "cs-restore-" + item.Name,
			NetworkRecovery: config.NetworkRecovery{
				Mode:               "auto",
				CaptureDiagnostics: true,
			},
			SourcePBS: config.SourcePBS{
				StorageID: *storageID,
				Snapshot:  "latest",
				Namespace: inventory.Lab.PBSNamespace,
			},
			// The inventory says workload_configuration is pending.  A required
			// QGA ping proves boot and guest-agent recovery without claiming a
			// service-level assertion that has not yet been configured.
			Probes: []config.Probe{{
				Type:        "qga",
				Command:     "ping",
				RequireQGA:  true,
				TimeoutSec:  60,
				Description: "Required QGA guest-ping; service workload configuration pending",
			}},
		})
	}

	base := &config.Plan{
		Version:         "v1",
		PlanID:          "certistack-coverage-fleet-current",
		Name:            "CertiStack Coverage Fleet — Current Backup/Restore",
		Environment:     "coverage-fleet",
		UseBackupConfig: true,
		// A plan must name a framework and a positive retention; these runs map to
		// none in particular, so the generator names one.
		Compliance: config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90, SignKeyPath: *signKeyPath},
		AdmissionControl: config.AdmissionControl{
			MaxHostRAMPercent:     80,
			MaxHostIOWaitPercent:  15,
			DeferRetryIntervalSec: 30,
			MaxDeferRetries:       10,
		},
		// The VNet is preprovisioned and carries its own VLAN tag: a simple
		// network refuses a tag in the plan, which would never reach PVE. --vlan-tag
		// only checks the isolation and goes in the README.
		Network: config.Network{
			Mode: "simple", Lifecycle: "preprovisioned", ZoneID: *zoneID, VNetID: *vnetID,
			IPRange: *ipRange, ProbeIP: *probeIP,
		},
		Storage: config.Storage{PBSNamespace: inventory.Lab.PBSNamespace},
		Tiers: []config.Tier{{
			Level: 1, Name: "Current coverage-fleet backup/restore checks", StartupGracePeriodSec: 180,
			VMs: vms,
		}},
	}

	scenarios := buildScenarios(vms, inventory.Targets)
	if err := os.MkdirAll(*outDir, 0700); err != nil {
		fatalf("create output directory: %v", err)
	}
	if len(attestationData) > 0 {
		attestationDestination := filepath.Join(*outDir, "restore-isolation-attestation.yaml")
		if err := writeNewFile(attestationDestination, attestationData); err != nil {
			fatalf("preserve source-address-reuse isolation attestation: %v", err)
		}
	}
	for _, candidate := range scenarios {
		path := filepath.Join(*outDir, candidate.name+".yaml")
		if _, err := os.Stat(path); err == nil {
			fatalf("refusing to overwrite %s", path)
		} else if !os.IsNotExist(err) {
			fatalf("inspect %s: %v", path, err)
		}
		plan := subset(base, candidate)
		if errs := config.Validate(plan); errs != nil {
			fatalf("generated %s is invalid: %v", path, errs)
		}
		encoded, err := yaml.Marshal(plan)
		if err != nil {
			fatalf("encode %s: %v", path, err)
		}
		if err := os.WriteFile(path, encoded, 0600); err != nil {
			fatalf("write %s: %v", path, err)
		}
	}
	if err := writeManifest(*outDir, scenarios, allowedNodes); err != nil {
		fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "README.txt"), []byte(readme(*targetPath, *targetOffset, *storageID, *zoneID, *vnetID, *vlanTag, *ipRange, *probeIP, inventory.TestBoundary.WorkloadConfiguration, reusedSourceAddressing, len(vms), len(scenarios))), 0600); err != nil {
		fatalf("write README: %v", err)
	}
	fmt.Printf("generated %d cases for %d current coverage-fleet targets in %s (%d default singles; %d selective groups)\n", len(scenarios), len(vms), *outDir, len(vms), len(scenarios)-len(vms))
}

func validInventoryToken(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			if i == 0 && (r == '.' || r == '_' || r == '-') {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func validateRestoreNetwork(inventory targetManifest, zoneID, vnetID string, vlanTag int, ipRange, probeIP, attestationPath string) ([]byte, bool) {
	_, restoreNet, err := net.ParseCIDR(ipRange)
	if err != nil || restoreNet.IP.To4() == nil {
		fatalf("--ip-range must be a valid IPv4 CIDR")
	}
	probe := net.ParseIP(probeIP)
	if probe == nil || !restoreNet.Contains(probe) {
		fatalf("--probe-ip must be within --ip-range")
	}
	_, sourceNet, err := net.ParseCIDR(inventory.Lab.SourceNetwork.CIDR)
	if err != nil || sourceNet.IP.To4() == nil {
		fatalf("target manifest source network is not a valid IPv4 CIDR")
	}
	reusedSourceAddressing := vlanTag == inventory.Lab.SourceNetwork.VLANID || sourceNet.Contains(restoreNet.IP) || restoreNet.Contains(sourceNet.IP)
	if !reusedSourceAddressing {
		if attestationPath != "" {
			fatalf("--isolation-attestation is only valid when restore VLAN or CIDR reuses source addressing")
		}
		return nil, false
	}
	if attestationPath == "" {
		fatalf("restore VLAN/CIDR reuses source addressing; --isolation-attestation is required to record a separate L2 domain with no physical uplink, gateway, SNAT, or routed path to source")
	}
	data, err := os.ReadFile(attestationPath)
	if err != nil {
		fatalf("read isolation attestation: %v", err)
	}
	var attestation isolationAttestation
	if err := yaml.Unmarshal(data, &attestation); err != nil {
		fatalf("parse isolation attestation: %v", err)
	}
	if attestation.SchemaVersion != 1 {
		fatalf("isolation attestation schema_version is %d; expected 1", attestation.SchemaVersion)
	}
	if attestation.SourceVLANID != inventory.Lab.SourceNetwork.VLANID || normalizedAttestationCIDR(attestation.SourceCIDR) != sourceNet.String() {
		fatalf("isolation attestation source VLAN/CIDR does not match the target inventory")
	}
	if attestation.RestoreZoneID != zoneID || attestation.RestoreVNetID != vnetID || attestation.RestoreVLANID != vlanTag || normalizedAttestationCIDR(attestation.RestoreCIDR) != restoreNet.String() {
		fatalf("isolation attestation restore zone, VNet, VLAN, or CIDR does not match the requested plan")
	}
	if !attestation.L2Isolated || !attestation.NoPhysicalUplink || !attestation.NoGateway || !attestation.NoSNAT || !attestation.NoRoutedPathToSource {
		fatalf("isolation attestation must affirm l2_isolated, no_physical_uplink, no_gateway, no_snat, and no_routed_path_to_source")
	}
	return data, true
}

func normalizedAttestationCIDR(cidr string) string {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	return network.String()
}

func writeNewFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func buildScenarios(vms []config.VM, targets []target) []scenario {
	bySource := make(map[int]config.VM, len(vms))
	byOS, byWorkload := make(map[string][]config.VM), make(map[string][]config.VM)
	for _, vm := range vms {
		bySource[vm.SourceVMID] = vm
	}
	for _, item := range targets {
		vm := bySource[item.VMID]
		byOS[item.OSID] = append(byOS[item.OSID], vm)
		byWorkload[item.Workload] = append(byWorkload[item.Workload], vm)
	}
	scenarios := []scenario{{name: "all", vms: append([]config.VM(nil), vms...)}}
	for _, vm := range vms {
		scenarios = append(scenarios, scenario{name: fmt.Sprintf("single-%d", vm.SourceVMID), vms: []config.VM{vm}})
	}
	for _, name := range sortedKeys(byOS) {
		scenarios = append(scenarios, scenario{name: "os-" + name, vms: byOS[name]})
	}
	for _, name := range sortedKeys(byWorkload) {
		scenarios = append(scenarios, scenario{name: "workload-" + name, vms: byWorkload[name]})
	}
	sort.Slice(scenarios, func(i, j int) bool { return scenarios[i].name < scenarios[j].name })
	return scenarios
}

func sortedKeys(groups map[string][]config.VM) []string {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func subset(base *config.Plan, candidate scenario) *config.Plan {
	copy := *base
	copy.PlanID = base.PlanID + "-" + candidate.name
	copy.Name = base.Name + " — " + strings.ReplaceAll(candidate.name, "-", " ")
	tier := base.Tiers[0]
	tier.VMs = append([]config.VM(nil), candidate.vms...)
	copy.Tiers = []config.Tier{tier}
	return &copy
}

func writeManifest(outDir string, scenarios []scenario, allowedNodes []string) error {
	var data strings.Builder
	data.WriteString("format=2\n")
	fmt.Fprintf(&data, "allowed_nodes\t%s\n", strings.Join(allowedNodes, ","))
	for _, candidate := range scenarios {
		mode := "selective"
		if strings.HasPrefix(candidate.name, "single-") {
			mode = "positive"
		}
		fmt.Fprintf(&data, "%s\t%s.yaml\n", mode, candidate.name)
	}
	return os.WriteFile(filepath.Join(outDir, manifestName), []byte(data.String()), 0600)
}

func parseAllowedNodes(raw string) ([]string, error) {
	seen := make(map[string]struct{})
	var nodes []string
	for _, value := range strings.Split(raw, ",") {
		node := strings.TrimSpace(value)
		if !allowedNodePattern.MatchString(node) {
			return nil, fmt.Errorf("invalid PVE node name %q", node)
		}
		if _, exists := seen[node]; exists {
			return nil, fmt.Errorf("PVE node %q is listed more than once", node)
		}
		seen[node] = struct{}{}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("at least one PVE node is required")
	}
	return nodes, nil
}

func readme(targetPath string, offset int, storageID, zoneID, vnetID string, vlanTag int, ipRange, probeIP, workloadConfiguration string, reusedSourceAddressing bool, targets, cases int) string {
	networkBoundary := "The restore VLAN/CIDR does not overlap source addressing."
	if reusedSourceAddressing {
		networkBoundary = "The restore VLAN/CIDR reuses source addressing. restore-isolation-attestation.yaml records the required separate L2 domain, no physical uplink, no gateway, no SNAT, and no routed path to source."
	}
	return fmt.Sprintf("Generated from: %s\nTargets: %d\nCases: %d (%d default single-target cases; %d selective group/full-fleet cases)\n\nThe Community Edition writes its reports unsigned and needs no signing key; the Enterprise Edition signs them with the key a plan names in compliance.sign_key_path (generate with --sign-key-path for that), which should be a mode-0600 key outside a shared or Windows-mounted workspace.\n\nRestore VMIDs are source VMIDs + %d (for example 7111 -> 17111). CertiStack checks occupancy before creating each restore VM; verify this disposable range is available before a run.\n\nThe inventory declares workload_configuration: %s. These plans intentionally require QGA guest-ping only; they do not make HTTP, PostgreSQL, MariaDB, or Redis service-level claims without a declared, per-workload probe contract.\n\nEvery VM uses storage_id %s: disks are restored from the PBS endpoint in PBS_REPOSITORY, namespace coverage-fleet. Current source snapshots must exist there before a run. Run with PBS_NAMESPACE=coverage-fleet (or unset a conflicting inherited value).\n\nThe plans use the preprovisioned isolated SDN zone/VNet %s/%s on VLAN %d, subnet %s, probe address %s. %s Confirm the supplied SDN objects are the disposable sandbox, never the source-network attachment, before running.\n", targetPath, targets, cases, targets, cases-targets, offset, workloadConfiguration, storageID, zoneID, vnetID, vlanTag, ipRange, probeIP, networkBoundary)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "coverage cases: "+format+"\n", args...)
	os.Exit(1)
}

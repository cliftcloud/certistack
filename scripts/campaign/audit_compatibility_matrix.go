// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build ignore

// Run with go run; it shares a directory with the other campaign tool, so
// ordinary builds skip it.
//
// Audit an accepted lab inventory against the declared CertiStack
// compatibility contract. It is intentionally read-only: a release campaign
// may be generated only after this audit proves every implemented OS/workload
// cell in the requested suite is represented by an accepted target.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type compatibilityContract struct {
	SchemaVersion int `yaml:"schema_version"`
	Platforms     struct {
		Pairs []platformPair `yaml:"pairs"`
	} `yaml:"platforms"`
	GuestOS        []string `yaml:"guest_os"`
	Recipes        []recipe `yaml:"recipes"`
	TestDimensions struct {
		StorageProfiles []dimension `yaml:"storage_profiles"`
		GuestProfiles   []dimension `yaml:"guest_profiles"`
		BackupProfiles  []dimension `yaml:"backup_profiles"`
		RestoreProfiles []dimension `yaml:"restore_profiles"`
	} `yaml:"test_dimensions"`
	TestSuites map[string]struct {
		PlatformPair    *platformPair `yaml:"platform_pair"`
		PlatformPairs   any           `yaml:"platform_pairs"`
		GuestOS         any           `yaml:"guest_os"`
		Lifecycles      []string      `yaml:"lifecycles"`
		StorageProfiles any           `yaml:"storage_profiles"`
		GuestProfiles   any           `yaml:"guest_profiles"`
		BackupProfiles  any           `yaml:"backup_profiles"`
		RestoreProfiles any           `yaml:"restore_profiles"`
	} `yaml:"test_suites"`
}

type platformPair struct {
	PVEMajor int `yaml:"pve_major"`
	PBSMajor int `yaml:"pbs_major"`
}

type dimension struct {
	ID     string `yaml:"id"`
	Status string `yaml:"status"`
}

type recipe struct {
	ID               string   `yaml:"id"`
	Lifecycle        string   `yaml:"lifecycle"`
	WorkloadType     string   `yaml:"workload_type"`
	SupportedGuestOS []string `yaml:"supported_guest_os"`
}

type inventoryManifest struct {
	SchemaVersion int `yaml:"schema_version"`
	TestBoundary  struct {
		SyntheticDataOnly     bool   `yaml:"synthetic_data_only"`
		IntendedTest          string `yaml:"intended_test"`
		WorkloadConfiguration string `yaml:"workload_configuration"`
		Readiness             string `yaml:"readiness"`
	} `yaml:"test_boundary"`
	Qualification struct {
		PlatformPairs   []platformPair `yaml:"platform_pairs"`
		StorageProfiles []string       `yaml:"storage_profiles"`
		GuestProfiles   []string       `yaml:"guest_profiles"`
		BackupProfiles  []string       `yaml:"backup_profiles"`
		RestoreProfiles []string       `yaml:"restore_profiles"`
	} `yaml:"qualification"`
	Targets []struct {
		VMID         int    `yaml:"vm_id"`
		OSID         string `yaml:"os_id"`
		WorkloadType string `yaml:"workload_type"`
		Status       string `yaml:"status"`
	} `yaml:"targets"`
}

func main() {
	contractPath := flag.String("contract", "", "compatibility-matrix.yml contract")
	targetsPath := flag.String("targets", "", "accepted current-coverage-test-targets.yml inventory")
	suiteName := flag.String("suite", "release_candidate", "test_suites entry to audit")
	flag.Parse()
	if *contractPath == "" || *targetsPath == "" {
		fatalf("--contract and --targets are required")
	}

	var contract compatibilityContract
	readYAML(*contractPath, &contract)
	if contract.SchemaVersion != 2 {
		fatalf("contract schema_version is %d; expected supported version 2", contract.SchemaVersion)
	}
	suite, ok := contract.TestSuites[*suiteName]
	if !ok {
		fatalf("contract has no %q test suite", *suiteName)
	}
	guests := resolveGuests(contract.GuestOS, suite.GuestOS)
	if len(guests) == 0 {
		fatalf("suite %q selects no supported guest OS entries", *suiteName)
	}
	lifecycles := makeSet(suite.Lifecycles)
	if !lifecycles["implemented"] {
		fatalf("suite %q does not include implemented recipes", *suiteName)
	}

	var inventory inventoryManifest
	readYAML(*targetsPath, &inventory)
	if inventory.SchemaVersion != 1 {
		fatalf("inventory schema_version is %d; expected supported version 1", inventory.SchemaVersion)
	}
	if !inventory.TestBoundary.SyntheticDataOnly || inventory.TestBoundary.IntendedTest != "backup_restore" {
		fatalf("inventory is not declared synthetic backup_restore evidence")
	}
	if inventory.TestBoundary.Readiness != "ready" {
		fatalf("inventory readiness is %q; image acceptance is required before compatibility evidence", inventory.TestBoundary.Readiness)
	}
	if inventory.TestBoundary.WorkloadConfiguration != "ready" {
		fatalf("inventory workload_configuration is %q; QGA-only targets cannot prove service compatibility", inventory.TestBoundary.WorkloadConfiguration)
	}
	verifySelectedDimensions(contract, suite, inventory.Qualification)

	actual := make(map[string][]int)
	for _, target := range inventory.Targets {
		if target.VMID <= 0 || target.Status != "running" {
			continue
		}
		actual[cell(target.OSID, target.WorkloadType)] = append(actual[cell(target.OSID, target.WorkloadType)], target.VMID)
	}

	missing := make([]string, 0)
	planned := make([]string, 0)
	for _, item := range contract.Recipes {
		if !lifecycles[item.Lifecycle] {
			continue
		}
		for _, guest := range guests {
			if !contains(item.SupportedGuestOS, guest) {
				continue
			}
			key := cell(guest, item.WorkloadType)
			if item.Lifecycle != "implemented" {
				planned = append(planned, key+" ("+item.ID+")")
				continue
			}
			if len(actual[key]) == 0 {
				missing = append(missing, key+" ("+item.ID+")")
			}
		}
	}
	sort.Strings(missing)
	sort.Strings(planned)
	if len(missing) != 0 {
		fatalf("suite %q is missing %d implemented compatibility cell(s): %s", *suiteName, len(missing), strings.Join(missing, ", "))
	}

	fmt.Printf("compatibility matrix audit passed: suite=%s implemented_cells_covered=%d planned_cells_not_claimed=%d\n", *suiteName, lenImplementedCells(contract, guests, lifecycles), len(planned))
	if len(planned) != 0 {
		fmt.Printf("planned cells remain outside the supported release claim: %s\n", strings.Join(planned, ", "))
	}
}

func verifySelectedDimensions(contract compatibilityContract, suite struct {
	PlatformPair    *platformPair `yaml:"platform_pair"`
	PlatformPairs   any           `yaml:"platform_pairs"`
	GuestOS         any           `yaml:"guest_os"`
	Lifecycles      []string      `yaml:"lifecycles"`
	StorageProfiles any           `yaml:"storage_profiles"`
	GuestProfiles   any           `yaml:"guest_profiles"`
	BackupProfiles  any           `yaml:"backup_profiles"`
	RestoreProfiles any           `yaml:"restore_profiles"`
}, actual struct {
	PlatformPairs   []platformPair `yaml:"platform_pairs"`
	StorageProfiles []string       `yaml:"storage_profiles"`
	GuestProfiles   []string       `yaml:"guest_profiles"`
	BackupProfiles  []string       `yaml:"backup_profiles"`
	RestoreProfiles []string       `yaml:"restore_profiles"`
}) {
	if suite.PlatformPair != nil {
		if !containsPair(contract.Platforms.Pairs, *suite.PlatformPair) {
			fatalf("suite selects undeclared platform pair pve=%d/pbs=%d", suite.PlatformPair.PVEMajor, suite.PlatformPair.PBSMajor)
		}
		verifyPairCoverage([]platformPair{*suite.PlatformPair}, actual.PlatformPairs)
	} else if suite.PlatformPairs != nil {
		selected := resolvePairs(contract.Platforms.Pairs, suite.PlatformPairs)
		if len(selected) == 0 {
			fatalf("suite selects no declared platform pairs")
		}
		verifyPairCoverage(selected, actual.PlatformPairs)
	}
	verifyDimensionCoverage("storage_profiles", contract.TestDimensions.StorageProfiles, suite.StorageProfiles, actual.StorageProfiles)
	verifyDimensionCoverage("guest_profiles", contract.TestDimensions.GuestProfiles, suite.GuestProfiles, actual.GuestProfiles)
	verifyDimensionCoverage("backup_profiles", contract.TestDimensions.BackupProfiles, suite.BackupProfiles, actual.BackupProfiles)
	verifyDimensionCoverage("restore_profiles", contract.TestDimensions.RestoreProfiles, suite.RestoreProfiles, actual.RestoreProfiles)
}

func verifyPairCoverage(expected, actual []platformPair) {
	actualSet := make(map[string]bool, len(actual))
	for _, pair := range actual {
		actualSet[pairKey(pair)] = true
	}
	missing := make([]string, 0)
	for _, pair := range expected {
		if !actualSet[pairKey(pair)] {
			missing = append(missing, pairKey(pair))
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		fatalf("inventory lacks accepted evidence for selected platform pair(s): %s", strings.Join(missing, ", "))
	}
}

func verifyDimensionCoverage(name string, catalog []dimension, selector any, actual []string) {
	if selector == nil {
		return
	}
	selected := resolveDimensionIDs(catalog, selector)
	if len(selected) == 0 {
		fatalf("suite selects no declared %s", name)
	}
	actualSet := makeSet(actual)
	missing := make([]string, 0)
	for _, id := range selected {
		item, ok := findDimension(catalog, id)
		if !ok {
			fatalf("suite selects undeclared %s entry %q", name, id)
		}
		if item.Status != "available" {
			// Planned dimensions remain visible in the full contract but cannot
			// become release support claims until they are available.
			continue
		}
		if !actualSet[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		fatalf("inventory lacks accepted evidence for selected %s: %s", name, strings.Join(missing, ", "))
	}
}

func resolvePairs(all []platformPair, selector any) []platformPair {
	if value, ok := selector.(string); ok && value == "all" {
		return append([]platformPair(nil), all...)
	}
	values, ok := selector.([]interface{})
	if !ok {
		return nil
	}
	result := make([]platformPair, 0, len(values))
	for _, value := range values {
		entry, ok := value.(map[string]interface{})
		if !ok {
			return nil
		}
		pve, pveOK := entry["pve_major"].(int)
		pbs, pbsOK := entry["pbs_major"].(int)
		pair := platformPair{PVEMajor: pve, PBSMajor: pbs}
		if !pveOK || !pbsOK || !containsPair(all, pair) {
			return nil
		}
		result = append(result, pair)
	}
	return result
}

func resolveDimensionIDs(catalog []dimension, selector any) []string {
	all := make([]string, 0, len(catalog))
	for _, item := range catalog {
		all = append(all, item.ID)
	}
	return resolveGuests(all, selector)
}

func findDimension(catalog []dimension, id string) (dimension, bool) {
	for _, item := range catalog {
		if item.ID == id {
			return item, true
		}
	}
	return dimension{}, false
}

func containsPair(pairs []platformPair, wanted platformPair) bool {
	for _, pair := range pairs {
		if pair == wanted {
			return true
		}
	}
	return false
}

func pairKey(pair platformPair) string {
	return fmt.Sprintf("pve=%d/pbs=%d", pair.PVEMajor, pair.PBSMajor)
}

func readYAML(path string, destination any) {
	data, err := os.ReadFile(path)
	if err != nil {
		fatalf("read %s: %v", path, err)
	}
	if err := yaml.Unmarshal(data, destination); err != nil {
		fatalf("parse %s: %v", path, err)
	}
}

func resolveGuests(all []string, selector any) []string {
	if value, ok := selector.(string); ok && value == "all" {
		return append([]string(nil), all...)
	}
	values, ok := selector.([]interface{})
	if !ok {
		return nil
	}
	guests := make([]string, 0, len(values))
	for _, value := range values {
		guest, ok := value.(string)
		if !ok || guest == "" || !contains(all, guest) {
			return nil
		}
		guests = append(guests, guest)
	}
	return guests
}

func lenImplementedCells(contract compatibilityContract, guests []string, lifecycles map[string]bool) int {
	count := 0
	for _, item := range contract.Recipes {
		if item.Lifecycle != "implemented" || !lifecycles[item.Lifecycle] {
			continue
		}
		for _, guest := range guests {
			if contains(item.SupportedGuestOS, guest) {
				count++
			}
		}
	}
	return count
}

func makeSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func cell(osID, workloadType string) string {
	return osID + "/" + workloadType
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "compatibility audit: "+format+"\n", args...)
	os.Exit(1)
}

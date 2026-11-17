// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/ifname"
	"github.com/cliftcloud/certistack/internal/macaddr"
)

// verdicts are what the loader and the schema each say of one plan document:
// the loader's refusal (the fields it names, or "(decode)"), and the schema's
// problems.
func verdicts(t *testing.T, doc any) (loader map[string]string, schema []string) {
	t.Helper()
	return loaderErrors(t, doc), schemaProblems(doc)
}

// agree fails unless the loader and the schema reach the same verdict on doc,
// and, for a plan both refuse, the loader names field when one is given.
func agree(t *testing.T, doc any, accepted bool, field string) {
	t.Helper()
	loader, schema := verdicts(t, doc)
	if accepted && (loader != nil || len(schema) > 0) {
		t.Errorf("both should accept it: the loader says %v, the schema says %v", loader, schema)
	}
	if !accepted {
		if loader == nil || len(schema) == 0 {
			t.Errorf("both should refuse it: the loader says %v, the schema says %v", loader, schema)
		}
		if field != "" && loader != nil && loader[field] == "" {
			t.Errorf("the loader refuses it, but not at %s: %v", field, loader)
		}
	}
}

// The schema is as strict as `validate` on every rule a JSON Schema can state,
// so an editor flags what validate refuses: a value validate refuses is refused
// by the schema, and a value validate accepts is accepted by it (a schema that
// flags a plan the loader accepts is worse than none). What spans keys is not
// here, and is the part of validate the plan reference says the schema leaves
// out.
func TestPlanSchemaIsAsStrictAsValidate(t *testing.T) {
	type edit func(t *testing.T, doc any)
	set := func(path string, value any) edit {
		return func(t *testing.T, doc any) {
			if dot := strings.LastIndex(path, "."); dot >= 0 {
				ensureMap(t, doc, path[:dot])
			}
			setPath(doc, path, value)
		}
	}
	remove := func(path string) edit { return func(t *testing.T, doc any) { deletePath(doc, path) } }
	several := func(edits ...edit) edit {
		return func(t *testing.T, doc any) {
			for _, e := range edits {
				e(t, doc)
			}
		}
	}
	const vm = "tiers[0].vms[0]."
	const hardware = "tiers[0].vms[0].hardware_overrides."
	const recovery = "tiers[0].vms[0].network_recovery."
	admissionBlock := func(keys ...string) map[string]any {
		values := map[string]any{"max_host_ram_percent": 85.0, "max_host_iowait_percent": 12.0, "defer_retry_interval_sec": 30, "max_defer_retries": 10}
		block := map[string]any{}
		for _, key := range keys {
			block[key] = values[key]
		}
		return block
	}
	moveAdmission := func(t *testing.T, doc any) {
		deletePath(doc, "admission_control")
		setPath(doc, "admission", admissionBlock("max_host_ram_percent", "max_host_iowait_percent", "defer_retry_interval_sec", "max_defer_retries"))
	}

	for _, tc := range []struct {
		name     string
		edit     edit
		accepted bool
		field    string // the key the loader names, when it refuses
	}{
		// memory_mb: 0 inherits, otherwise 16 (PVE's minimum) to 4 TiB.
		{"memory_mb 1", set(hardware+"memory_mb", 1), false, "tiers[0].vms[0].hardware_overrides.memory_mb"},
		{"memory_mb 15", set(hardware+"memory_mb", 15), false, "tiers[0].vms[0].hardware_overrides.memory_mb"},
		{"memory_mb -1", set(hardware+"memory_mb", -1), false, "tiers[0].vms[0].hardware_overrides.memory_mb"},
		{"memory_mb 0", set(hardware+"memory_mb", 0), true, ""},
		{"memory_mb 16", set(hardware+"memory_mb", 16), true, ""},
		{"memory_mb 2048", set(hardware+"memory_mb", 2048), true, ""},
		{"memory_mb 4194304", set(hardware+"memory_mb", 4194304), true, ""},
		{"memory_mb 4194305", set(hardware+"memory_mb", 4194305), false, "tiers[0].vms[0].hardware_overrides.memory_mb"},

		// admission_control: the four limits are required, under either spelling.
		{"admission_control without max_host_ram_percent", remove("admission_control.max_host_ram_percent"), false, "admission_control.max_host_ram_percent"},
		{"admission_control without max_host_iowait_percent", remove("admission_control.max_host_iowait_percent"), false, "admission_control.max_host_iowait_percent"},
		{"admission_control without defer_retry_interval_sec", remove("admission_control.defer_retry_interval_sec"), false, "admission_control.defer_retry_interval_sec"},
		{"admission_control without max_defer_retries", remove("admission_control.max_defer_retries"), false, "admission_control.max_defer_retries"},
		{"admission_control with no limit", set("admission_control", map[string]any{}), false, "admission_control.max_host_ram_percent"},
		{"admission_control with only the optional keys", set("admission_control", map[string]any{"max_concurrent_boots": 2}), false, "admission_control.max_defer_retries"},
		{"a limit of 0", set("admission_control.max_defer_retries", 0), false, "admission_control.max_defer_retries"},
		{"the I/O wait limit by its other name", several(remove("admission_control.max_host_iowait_percent"), set("admission_control.max_host_io_wait_percent", 12.0)), true, ""},
		{"the older admission block, whole", moveAdmission, true, ""},
		{"the older admission block, without a limit", several(moveAdmission, remove("admission.max_defer_retries")), false, "admission_control.max_defer_retries"},
		{"the limits split between the two blocks", several(
			remove("admission_control.defer_retry_interval_sec"), remove("admission_control.max_defer_retries"),
			set("admission", admissionBlock("defer_retry_interval_sec", "max_defer_retries"))), true, ""},
		{"both blocks, neither with the limit", several(remove("admission_control.max_defer_retries"), set("admission", admissionBlock("max_host_ram_percent"))), false, "admission_control.max_defer_retries"},
		{"neither block", remove("admission_control"), false, ""},

		// storage.overlay_storage: a PVE storage ID, or none.
		{"overlay_storage of one letter", set("storage.overlay_storage", "a"), false, "storage.overlay_storage"},
		{"overlay_storage with a capital", set("storage.overlay_storage", "Local"), false, "storage.overlay_storage"},
		{"overlay_storage that starts with a digit", set("storage.overlay_storage", "9local"), false, "storage.overlay_storage"},
		{"overlay_storage that ends with a hyphen", set("storage.overlay_storage", "local-"), false, "storage.overlay_storage"},
		{"overlay_storage that ends with a dot", set("storage.overlay_storage", "local."), false, "storage.overlay_storage"},
		{"overlay_storage with a space", set("storage.overlay_storage", "local lvm"), false, "storage.overlay_storage"},
		{"overlay_storage with a slash", set("storage.overlay_storage", "local/lvm"), false, "storage.overlay_storage"},
		{"overlay_storage left empty", set("storage.overlay_storage", ""), true, ""},
		{"overlay_storage of two letters", set("storage.overlay_storage", "ab"), true, ""},
		{"overlay_storage local-lvm", set("storage.overlay_storage", "local-lvm"), true, ""},
		{"overlay_storage a.b_c-d", set("storage.overlay_storage", "a.b_c-d"), true, ""},

		// machine, ostype, bios and scsihw: PVE's values. The schema states what a
		// pattern or an enum can say; validate also judges a machine's options.
		// An empty value is "not set" to the loader, so the schema takes it too.
		{"nic_model empty", set(vm+"nic_model", ""), true, ""},
		{"ostype empty", set(vm+"ostype", ""), true, ""},
		{"bios empty", set(vm+"bios", ""), true, ""},
		{"scsihw empty", set(vm+"scsihw", ""), true, ""},
		{"machine q35", set(vm+"machine", "q35"), true, ""},
		{"machine pc-q35-9.2+pve1", set(vm+"machine", "pc-q35-9.2+pve1"), true, ""},
		{"machine with an option", set(vm+"machine", "type=q35,viommu=virtio"), true, ""},
		{"machine left empty", set(vm+"machine", ""), true, ""},
		{"machine q36", set(vm+"machine", "q36"), false, "tiers[0].vms[0].machine"},
		{"machine in upper case", set(vm+"machine", "Q35"), false, "tiers[0].vms[0].machine"},
		{"machine pc-q35 without a version", set(vm+"machine", "pc-q35"), false, "tiers[0].vms[0].machine"},
		{"ostype l26", set(vm+"ostype", "l26"), true, ""},
		{"ostype linux", set(vm+"ostype", "linux"), false, "tiers[0].vms[0].ostype"},
		{"bios ovmf", set(vm+"bios", "ovmf"), true, ""},
		{"bios uefi", set(vm+"bios", "uefi"), false, "tiers[0].vms[0].bios"},
		{"scsihw pvscsi", set(vm+"scsihw", "pvscsi"), true, ""},
		{"scsihw virtio", set(vm+"scsihw", "virtio"), false, "tiers[0].vms[0].scsihw"},

		// network_recovery.interface_name: ifname.Valid, or none.
		{"interface_name lo", set(recovery+"interface_name", "lo"), false, "tiers[0].vms[0].network_recovery.interface_name"},
		{"interface_name .", set(recovery+"interface_name", "."), false, "tiers[0].vms[0].network_recovery.interface_name"},
		{"interface_name ..", set(recovery+"interface_name", ".."), false, "tiers[0].vms[0].network_recovery.interface_name"},
		{"interface_name of 16 characters", set(recovery+"interface_name", strings.Repeat("a", 16)), false, "tiers[0].vms[0].network_recovery.interface_name"},
		{"interface_name with a space", set(recovery+"interface_name", "eth 0"), false, "tiers[0].vms[0].network_recovery.interface_name"},
		{"interface_name with a slash", set(recovery+"interface_name", "eth/0"), false, "tiers[0].vms[0].network_recovery.interface_name"},
		{"interface_name with a colon", set(recovery+"interface_name", "eth0:1"), false, "tiers[0].vms[0].network_recovery.interface_name"},
		{"interface_name with a non-ASCII letter", set(recovery+"interface_name", "ethé"), false, "tiers[0].vms[0].network_recovery.interface_name"},
		{"interface_name left empty", set(recovery+"interface_name", ""), true, ""},
		{"interface_name of 15 characters", set(recovery+"interface_name", strings.Repeat("a", 15)), true, ""},
		{"interface_name eth0", set(recovery+"interface_name", "eth0"), true, ""},
		{"interface_name LO", set(recovery+"interface_name", "LO"), true, ""},
		{"interface_name ens3.100", set(recovery+"interface_name", "ens3.100"), true, ""},
		{"interface_name _-", set(recovery+"interface_name", "_-"), true, ""},

		// name: the plan's and the VM's may not be empty; a tier's is defaulted.
		{"an empty plan name", set("name", ""), false, "name"},
		{"an empty VM name", set("tiers[0].vms[0].name", ""), false, "tiers[0].vms[0].name"},
		{"an empty tier name", set("tiers[0].name", ""), true, ""},
		{"a plan name of a space", set("name", " "), true, ""},

		// mac: a usable address, or none.
		{"the all-zero mac", set("tiers[0].vms[0].mac", "00:00:00:00:00:00"), false, "tiers[0].vms[0].mac"},
		{"the all-zero mac with hyphens", set("tiers[0].vms[0].mac", "00-00-00-00-00-00"), false, "tiers[0].vms[0].mac"},
		{"the all-zero mac in dotted groups", set("tiers[0].vms[0].mac", "0000.0000.0000"), false, "tiers[0].vms[0].mac"},
		{"the broadcast mac", set("tiers[0].vms[0].mac", "ff:ff:ff:ff:ff:ff"), false, "tiers[0].vms[0].mac"},
		{"a multicast mac", set("tiers[0].vms[0].mac", "01:00:5e:00:00:01"), false, "tiers[0].vms[0].mac"},
		{"a multicast mac in dotted groups", set("tiers[0].vms[0].mac", "0100.5e00.0001"), false, "tiers[0].vms[0].mac"},
		{"a mac of five octets", set("tiers[0].vms[0].mac", "02:00:00:00:01"), false, "tiers[0].vms[0].mac"},
		{"a mac of seven octets", set("tiers[0].vms[0].mac", "02:00:00:00:00:00:01"), false, "tiers[0].vms[0].mac"},
		{"a mac that is not hexadecimal", set("tiers[0].vms[0].mac", "02:00:00:00:00:0g"), false, "tiers[0].vms[0].mac"},
		{"a mac with mixed separators", set("tiers[0].vms[0].mac", "02:00-00:00:00:01"), false, "tiers[0].vms[0].mac"},
		{"a mac with a space", set("tiers[0].vms[0].mac", "02:00:00:00:00:01 "), false, "tiers[0].vms[0].mac"},
		{"a mac with dots between octets", set("tiers[0].vms[0].mac", "02.00.00.00.00.01"), false, "tiers[0].vms[0].mac"},
		{"a mac that is a word", set("tiers[0].vms[0].mac", "not-a-mac"), false, "tiers[0].vms[0].mac"},
		{"a mac left empty", set("tiers[0].vms[0].mac", ""), true, ""},
		{"a mac with colons", set("tiers[0].vms[0].mac", "02:00:00:00:00:01"), true, ""},
		{"a mac in lower case", set("tiers[0].vms[0].mac", "bc:24:11:aa:bb:cc"), true, ""},
		{"a mac in upper case", set("tiers[0].vms[0].mac", "BC:24:11:AA:BB:CC"), true, ""},
		{"a mac with hyphens", set("tiers[0].vms[0].mac", "02-00-00-00-00-01"), true, ""},
		{"a mac in dotted groups", set("tiers[0].vms[0].mac", "0200.0000.0001"), true, ""},
		{"a mac that ends in zeros", set("tiers[0].vms[0].mac", "02:00:00:00:00:00"), true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := examplePlan(t)
			tc.edit(t, doc)
			agree(t, doc, tc.accepted, tc.field)
		})
	}

	// Every plan the repository ships passes both, as written.
	for _, pattern := range []string{filepath.Join("..", "..", "examples", "*.yaml"), filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml")} {
		paths, err := filepath.Glob(pattern)
		if err != nil || len(paths) == 0 {
			t.Fatalf("%s: %v %v", pattern, paths, err)
		}
		for _, path := range paths {
			agree(t, readPlanDocument(t, path), true, "")
		}
	}
}

// The enums the loader reads in any letter case are accepted in any letter case
// by the schema, in the canonical spelling too, and a value that is no spelling
// of one is refused by both; the canonical values stay in the schema as
// examples, which is what an editor offers.
func TestPlanSchemaReadsFoldedEnumsInAnyLetterCase(t *testing.T) {
	dnsProbe := func(t *testing.T, doc any) {
		addProbe(t, doc, map[string]any{"type": "dns", "target_ip": "192.0.2.10", "port": 53, "domain": "example.com"})
	}
	contexts := map[string]struct {
		path string
		prep func(t *testing.T, doc any)
		trim bool // the loader also trims white space from the value
	}{
		"Network.lifecycle": {"network.lifecycle", nil, true},
		"NetworkRecovery.mode": {"tiers[0].vms[0].network_recovery.mode", func(t *testing.T, doc any) {
			ensureMap(t, doc, "tiers[0].vms[0].network_recovery")
		}, true},
		"Probe.record_type": {"tiers[0].vms[0].probes[1].record_type", dnsProbe, false},
	}
	found := 0
	for entry, note := range planSchemaNotes {
		if note.FoldedEnum == nil {
			continue
		}
		found++
		c, covered := contexts[entry]
		if !covered {
			t.Errorf("%s reads its values in any letter case and has no context in this test", entry)
			continue
		}
		if note.FoldedTrim != c.trim {
			t.Errorf("%s: the note says white space is trimmed: %v; the loader's rule: %v", entry, note.FoldedTrim, c.trim)
		}
		property := schemaProperty(t, entry)
		if _, hasEnum := property["enum"]; hasEnum {
			t.Errorf("%s states an enum, which would refuse the other letter cases", entry)
		}
		if examples, _ := property["examples"].([]any); !sameValue(examples, note.FoldedEnum) {
			t.Errorf("%s: the examples are %v, want the canonical values %v", entry, examples, note.FoldedEnum)
		}
		t.Run(entry, func(t *testing.T) {
			attempt := func(value any) (loader string, schema []string) {
				doc := examplePlan(t)
				if c.prep != nil {
					c.prep(t, doc)
				}
				setPath(doc, c.path, value)
				return loaderErrors(t, doc)[c.path], problemsAt(schemaProblems(doc), c.path)
			}
			for _, value := range note.FoldedEnum {
				canonical := value.(string)
				spellings := []string{canonical, strings.ToUpper(canonical), strings.ToUpper(canonical[:1]) + canonical[1:], alternateCase(canonical)}
				if c.trim {
					spellings = append(spellings, " "+canonical, "\t"+strings.ToUpper(canonical)+"\n")
				}
				for _, spelling := range spellings {
					if loader, schema := attempt(spelling); loader != "" || len(schema) > 0 {
						t.Errorf("%q: the loader says %q, the schema says %v; both should accept it", spelling, loader, schema)
					}
				}
				misses := []string{canonical + "x", "x" + canonical, canonical + "-x", strings.Repeat(canonical, 2)}
				if len(canonical) > 1 {
					misses = append(misses, canonical[:len(canonical)-1])
				}
				if !c.trim {
					misses = append(misses, " "+canonical, canonical+" ")
				}
				for _, miss := range misses {
					if loader, schema := attempt(miss); loader == "" || len(schema) == 0 {
						t.Errorf("%q: the loader says %q, the schema says %v; both should refuse it", miss, loader, schema)
					}
				}
			}
		})
	}
	if found != len(contexts) {
		t.Errorf("%d notes read their values in any letter case; this test covers %d", found, len(contexts))
	}
}

// alternateCase is s with every other letter in upper case ("eFcFg").
func alternateCase(s string) string {
	out := []byte(s)
	for i := range out {
		if i%2 == 1 && out[i] >= 'a' && out[i] <= 'z' {
			out[i] -= 'a' - 'A'
		}
	}
	return string(out)
}

// schemaProperty is the published schema of the key a note names ("Type.key").
func schemaProperty(t *testing.T, entry string) map[string]any {
	t.Helper()
	goType, key, _ := strings.Cut(entry, ".")
	object := publishedSchema()
	if goType != "Plan" {
		object, _ = publishedSchema()["$defs"].(map[string]any)[goType].(map[string]any)
	}
	properties, _ := object["properties"].(map[string]any)
	property, ok := properties[key].(map[string]any)
	if !ok {
		t.Fatalf("the schema has no %s", entry)
	}
	return property
}

// Beyond the cases above, the schema's MAC pattern and the loader's rule
// (internal/macaddr) agree on every first octet, in the three spellings and both
// letter cases, and on addresses that differ from a good one by one character.
func TestPlanSchemaMACPatternIsTheLoadersRule(t *testing.T) {
	mac := schemaProperty(t, "VM.mac")
	check := func(value string) {
		t.Helper()
		schemaAccepts := len(schemaValidator{root: publishedSchema()}.check(mac, value, "mac")) == 0
		// A key left empty is a key left out, which both accept.
		if want := value == "" || macaddr.Valid(value); schemaAccepts != want {
			t.Errorf("%q: the loader accepts it: %v; the schema: %v", value, want, schemaAccepts)
		}
	}
	for first := 0; first < 256; first++ {
		for _, spelling := range []string{
			"%02x:00:00:00:00:01", "%02X:AB:cd:00:00:01", "%02x-00-00-00-00-01", "%02x00.0000.0001", "%02X00.ABCD.EF01", "%02x:00:00:00:00:00",
		} {
			check(fmt.Sprintf(spelling, first))
		}
	}
	good := "02:1a:2B:3c:4D:5e"
	for position := range good {
		for _, replacement := range []string{"0", "g", "-", ":", ".", " ", ""} {
			check(good[:position] + replacement + good[position+1:])
		}
	}
	for _, value := range []string{"", " ", "02:1a:2B:3c:4D", "02:1a:2B:3c:4D:5e:6f", "021a.2B3c.4D5e", "021a.2B3c.4D5", "021a.2B3c.4D5ef", "021a:2B3c:4D5e"} {
		check(value)
	}
}

// The same for interface_name and overlay_storage: over every string of a small
// alphabet up to a few characters, the schema and the loader's own rule agree.
func TestPlanSchemaNamePatternsAreTheLoadersRules(t *testing.T) {
	interfaceName := schemaProperty(t, "NetworkRecovery.interface_name")
	overlay := schemaProperty(t, "Storage.overlay_storage")
	validator := schemaValidator{root: publishedSchema()}
	alphabet := []string{"a", "l", "o", "A", "9", "_", "-", ".", ":", "/", " ", "é"}
	var walk func(prefix string, depth int)
	walk = func(prefix string, depth int) {
		if got, want := len(validator.check(interfaceName, prefix, "interface_name")) == 0, prefix == "" || ifname.Valid(prefix); got != want {
			t.Errorf("interface_name %q: the loader accepts it: %v; the schema: %v", prefix, want, got)
		}
		if got, want := len(validator.check(overlay, prefix, "overlay_storage")) == 0, prefix == "" || ValidPVEStorageID(prefix); got != want {
			t.Errorf("overlay_storage %q: the loader accepts it: %v; the schema: %v", prefix, want, got)
		}
		if depth == 0 {
			return
		}
		for _, letter := range alphabet {
			walk(prefix+letter, depth-1)
		}
	}
	walk("", 3)
	for _, name := range []string{"lo", "..", ".", strings.Repeat("a", 15), strings.Repeat("a", 16), "ens3.100", "LO", "lo0", "eth0:1"} {
		walk(name, 0)
	}
	for _, id := range []string{"local", "local-lvm", "a", "ab", "a-", "a_", "zfs.pool", strings.Repeat("a", 200)} {
		walk(id, 0)
	}
}

// The admission limits the schema requires are the ones the loader refuses a
// plan for lacking, each named by the table of where a limit may be written.
func TestPlanSchemaAdmissionLimitsAreTheLoadersLimits(t *testing.T) {
	if len(planSchemaAdmissionLimits) != 4 {
		t.Fatalf("the schema requires %v, and the plan reference says four limits", planSchemaAdmissionLimits)
	}
	for _, limit := range planSchemaAdmissionLimits {
		doc := examplePlan(t)
		deletePath(doc, "admission_control."+limit)
		if limit == "max_host_iowait_percent" {
			deletePath(doc, "admission_control.max_host_io_wait_percent")
		}
		if loader := loaderErrors(t, doc)["admission_control."+limit]; loader == "" {
			t.Errorf("the loader accepts a plan without %s", limit)
		}
		if len(schemaProblems(doc)) == 0 {
			t.Errorf("the schema accepts a plan without %s", limit)
		}
	}
	// The optional ones are not required: a plan without them loads.
	for _, optional := range []string{"max_concurrent_boots", "boot_settle_sec"} {
		doc := examplePlan(t)
		deletePath(doc, "admission_control."+optional)
		agree(t, doc, true, "")
	}
}

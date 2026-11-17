// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

// goldenUpdateEnvironment rewrites the golden schema instead of comparing it.
const goldenUpdateEnvironment = "CERTISTACK_UPDATE_GOLDEN"

// publishedSchema is the schema as a user receives it (decoded from the JSON
// `certistack schema` prints), so the tests judge what an editor reads and not
// the Go values it was built from.
var publishedSchema = sync.OnceValue(func() map[string]any {
	var schema map[string]any
	if err := json.Unmarshal(PlanSchemaJSON(), &schema); err != nil {
		panic(err)
	}
	return schema
})

func schemaProblems(doc any) []string {
	schema := publishedSchema()
	return schemaValidator{root: schema}.check(schema, doc, "")
}

// problemsAt are the violations reported at path itself or below it.
func problemsAt(problems []string, path string) []string {
	var at []string
	for _, problem := range problems {
		if strings.HasPrefix(problem, path+":") || strings.HasPrefix(problem, path+".") || strings.HasPrefix(problem, path+"[") {
			at = append(at, problem)
		}
	}
	return at
}

// examplePlan is the smallest shipped plan, decoded for editing.
func examplePlan(t *testing.T) any {
	t.Helper()
	return readPlanDocument(t, filepath.Join("..", "..", "examples", "minimal-single-vm.yaml"))
}

func readPlanDocument(t *testing.T, path string) any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// loaderErrors are the fields the plan loader refuses a document for, with its
// reasons; nil when it loads. A document the decoder refuses (an unknown key, a
// value of the wrong type) is reported under the field "(decode)".
func loaderErrors(t *testing.T, doc any) map[string]string {
	t.Helper()
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadFromReader(bytes.NewReader(data))
	if err == nil {
		return nil
	}
	var invalid ValidationErrors
	if !errors.As(err, &invalid) {
		return map[string]string{"(decode)": err.Error()}
	}
	fields := map[string]string{}
	for _, problem := range invalid {
		fields[problem.Field] = problem.Message
	}
	return fields
}

func ensureMap(t *testing.T, doc any, path string) {
	t.Helper()
	if existing, ok := getPath(doc, path); ok {
		if _, isMap := existing.(map[string]any); isMap {
			return
		}
	}
	setPath(doc, path, map[string]any{})
}

func addProbe(t *testing.T, doc any, probe map[string]any) {
	t.Helper()
	probes, _ := getPath(doc, "tiers[0].vms[0].probes")
	setPath(doc, "tiers[0].vms[0].probes", append(probes.([]any), probe))
}

// The schema is a pure function of the plan types and the notes: two calls
// agree, it is valid JSON, and it is the golden file, so a change to the plan,
// to a note or to a rule shows in review.
func TestPlanSchemaIsStableAndMatchesTheGoldenFile(t *testing.T) {
	first, second := PlanSchemaJSON(), PlanSchemaJSON()
	if !bytes.Equal(first, second) {
		t.Fatal("two calls give different schemas")
	}
	if !json.Valid(first) || !bytes.HasSuffix(first, []byte("}\n")) {
		t.Fatal("the schema is not one JSON document ending in a newline")
	}
	schema := publishedSchema()
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["type"] != "object" {
		t.Errorf("the schema declares %v / %v", schema["$schema"], schema["type"])
	}
	golden := filepath.Join("testdata", "plan.schema.json")
	if os.Getenv(goldenUpdateEnvironment) != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, first, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (create it with %s=1)", err, goldenUpdateEnvironment)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), first) {
		t.Errorf("the schema differs from %s: if the change is intended, rewrite it with %s=1 go test ./pkg/config/ -run TestPlanSchemaIsStable", golden, goldenUpdateEnvironment)
	}
}

// A key the loader accepts must be in the schema, and a key the schema offers
// must be one the loader accepts. The loader's own table of accepted keys
// (planSections, which names them in its "unknown key" errors) is the
// reference, independent of the reflection the schema is built with; and every
// annotation names a key that exists, so a renamed key cannot leave a stale note.
func TestPlanSchemaHasExactlyTheKeysTheLoaderAccepts(t *testing.T) {
	schema := publishedSchema()
	defs := schema["$defs"].(map[string]any)
	covered := map[string]bool{}
	for goType, section := range planSections {
		name := strings.TrimPrefix(goType, "config.")
		object := schema
		if name != "Plan" {
			var ok bool
			if object, ok = defs[name].(map[string]any); !ok {
				t.Errorf("%s (%q in the plan) has no definition in the schema", name, section.path)
				continue
			}
		}
		covered[name] = true
		properties, _ := object["properties"].(map[string]any)
		var offered []string
		for key := range properties {
			offered = append(offered, key)
		}
		sort.Strings(offered)
		if want := append([]string(nil), section.keys...); !equalStrings(offered, sortedCopy(want)) {
			t.Errorf("%s: the schema offers %v, the loader accepts %v", name, offered, sortedCopy(want))
		}
		if object["additionalProperties"] != false {
			t.Errorf("%s: the schema does not refuse an unknown key, as the loader does", name)
		}
	}
	for name := range defs {
		if !covered[name] {
			t.Errorf("the schema defines %s, which is no section of the plan", name)
		}
	}

	keysOf := func(name string) map[string]bool {
		keys := map[string]bool{}
		for goType, section := range planSections {
			if strings.TrimPrefix(goType, "config.") == name {
				for _, key := range section.keys {
					keys[key] = true
				}
			}
		}
		return keys
	}
	check := func(owner, entry string) {
		goType, key, _ := strings.Cut(entry, ".")
		if !keysOf(goType)[key] {
			t.Errorf("%s names %s, which is not a key of a plan", owner, entry)
		}
	}
	for entry := range planSchemaNotes {
		check("planSchemaNotes", entry)
	}
	for goType, keys := range planSchemaRequired {
		for _, key := range keys {
			check("planSchemaRequired", goType+"."+key)
		}
	}
	for goType, groups := range planSchemaOneOf {
		for _, group := range groups {
			for _, key := range group {
				check("planSchemaOneOf", goType+"."+key)
			}
		}
	}
}

func sortedCopy(values []string) []string {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return sorted
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

// Every plan the repository ships loads, and so the schema must accept it: a
// schema that flags a plan the loader accepts is worse than none.
func TestPlanSchemaAcceptsEveryShippedPlan(t *testing.T) {
	var paths []string
	for _, pattern := range []string{
		filepath.Join("..", "..", "examples", "*.yaml"),
		filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"),
		filepath.Join("..", "..", "testdata", "plans", "multi_tier_sandbox.yaml"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, matches...)
	}
	if len(paths) < 5 {
		t.Fatalf("found only %v", paths)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := LoadFromFile(path); err != nil {
				t.Fatalf("the loader refuses %s: %v", path, err)
			}
			if problems := schemaProblems(readPlanDocument(t, path)); len(problems) > 0 {
				t.Errorf("the schema refuses %s:\n  %s", path, strings.Join(problems, "\n  "))
			}
		})
	}
}

// The validator has teeth: each mistake below is refused by the schema, so the
// tests that say "the schema accepts" are not vacuous.
func TestSchemaValidatorRejectsWhatItShould(t *testing.T) {
	if problems := schemaProblems(examplePlan(t)); len(problems) != 0 {
		t.Fatalf("the unchanged example is refused: %v", problems)
	}
	for _, tc := range []struct {
		name string
		edit func(doc any)
		want string
	}{
		{"an unknown top-level key", func(d any) { setPath(d, "grace", 5) }, `grace: this is not allowed`},
		{"an unknown key in a tier", func(d any) { setPath(d, "tiers[0].grace", 5) }, `tiers[0].grace`},
		{"an unknown key in a probe", func(d any) { setPath(d, "tiers[0].vms[0].probes[0].tiemout_sec", 5) }, `tiemout_sec`},
		{"a number given as a string", func(d any) { setPath(d, "compliance.retention_days", "90") }, `must be integer`},
		{"a list given as a string", func(d any) { setPath(d, "compliance.frameworks", "SOC2") }, `must be array`},
		{"a framework that is not one", func(d any) { setPath(d, "compliance.frameworks", []any{"CHANGE"}) }, `compliance.frameworks[0]`},
		{"a mode that is not one", func(d any) { setPath(d, "network.mode", "complex") }, `network.mode`},
		{"a retention out of range", func(d any) { setPath(d, "compliance.retention_days", 0) }, `compliance.retention_days`},
		{"a missing required key", func(d any) { deletePath(d, "network.probe_ip") }, `"probe_ip" is required`},
		{"neither spelling of a key", func(d any) { deletePath(d, "admission_control") }, `anyOf`},
		{"a tier with no VM", func(d any) { setPath(d, "tiers[0].vms", []any{}) }, `tiers[0].vms`},
		{"a gateway", func(d any) { setPath(d, "network.gateway", "192.0.2.254") }, `network.gateway`},
		{"a certificate bypass", func(d any) { setPath(d, "tiers[0].vms[0].probes[0].tls_skip_verify", true) }, `tls_skip_verify`},
		{"a key the probe type does not read", func(d any) { setPath(d, "tiers[0].vms[0].probes[0].expected_status", 200) }, `expected_status`},
		{"a zone ID that is too long", func(d any) { setPath(d, "network.zone_id", "csZoneTooLong") }, `network.zone_id`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := examplePlan(t)
			tc.edit(doc)
			problems := schemaProblems(doc)
			if len(problems) == 0 {
				t.Fatal("the schema accepts it")
			}
			if joined := strings.Join(problems, "\n"); !strings.Contains(joined, tc.want) {
				t.Errorf("the problems %q do not mention %q", joined, tc.want)
			}
		})
	}
}

// One enum value at a time, the schema and the loader agree: every value the
// schema offers is accepted at that key, and a value outside it is refused by
// both.
func TestPlanSchemaEnumsAreTheValuesTheLoaderAccepts(t *testing.T) {
	type context struct {
		path string
		prep func(t *testing.T, doc any)
	}
	dnsProbe := func(t *testing.T, doc any) {
		addProbe(t, doc, map[string]any{"type": "dns", "target_ip": "192.0.2.10", "port": 53, "domain": "example.com"})
	}
	contexts := map[string]context{
		"Plan.version":          {"version", nil},
		"Compliance.frameworks": {"compliance.frameworks[0]", nil},
		"Network.mode":          {"network.mode", nil},
		"Network.lifecycle":     {"network.lifecycle", nil},
		"VM.nic_model":          {"tiers[0].vms[0].nic_model", nil},
		"VM.copy_before_boot":   {"tiers[0].vms[0].copy_before_boot", nil},
		"VM.ostype":             {"tiers[0].vms[0].ostype", nil},
		"VM.bios":               {"tiers[0].vms[0].bios", nil},
		"VM.scsihw":             {"tiers[0].vms[0].scsihw", nil},
		"NetworkRecovery.mode": {"tiers[0].vms[0].network_recovery.mode", func(t *testing.T, doc any) {
			ensureMap(t, doc, "tiers[0].vms[0].network_recovery")
		}},
		"SourcePBS.storage_id": {"tiers[0].vms[0].source_pbs.storage_id", nil},
		"Probe.type": {"tiers[0].vms[0].probes[1].type", func(t *testing.T, doc any) {
			addProbe(t, doc, map[string]any{"description": "probe under test"})
		}},
		"Probe.transport":   {"tiers[0].vms[0].probes[1].transport", dnsProbe},
		"Probe.record_type": {"tiers[0].vms[0].probes[1].record_type", dnsProbe},
	}
	notes := 0
	for entry, note := range planSchemaNotes {
		if note.Enum == nil {
			continue
		}
		notes++
		c, covered := contexts[entry]
		if !covered {
			t.Errorf("%s has an enum and no context in this test: add one, so the loader is asked about every value", entry)
			continue
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
			for _, value := range note.Enum {
				if loader, schema := attempt(value); loader != "" || len(schema) > 0 {
					t.Errorf("the schema offers %v: the loader says %q, the schema says %v", value, loader, schema)
				}
			}
			if loader, schema := attempt("zz-not-a-value"); loader == "" || len(schema) == 0 {
				t.Errorf("a value outside the enum: the loader says %q, the schema says %v", loader, schema)
			}
		})
	}
	if notes == 0 {
		t.Fatal("no note has an enum")
	}
}

// The bounds the schema states are the loader's: each limit is accepted, and
// one step beyond it is refused by both. A key whose 0 means "not set" and whose
// bound starts above it (memory_mb: 0, or 16 and up) is held to both.
func TestPlanSchemaRangesAreTheBoundsTheLoaderEnforces(t *testing.T) {
	type context struct {
		path string
		// prep makes the document one in which only the key's own range can
		// fail; low and high are used for the lower and the upper bound when a
		// bound needs a different setting (a port of 0 is "not set" only on a
		// probe that does not read it).
		prep, low, high func(t *testing.T, doc any)
	}
	tier := func(key string) context { return context{path: "tiers[0]." + key} }
	hardware := func(key string, prep func(t *testing.T, doc any)) context {
		return context{path: "tiers[0].vms[0].hardware_overrides." + key, prep: func(t *testing.T, doc any) {
			ensureMap(t, doc, "tiers[0].vms[0].hardware_overrides")
			if prep != nil {
				prep(t, doc)
			}
		}}
	}
	probe := func(key string, prep func(t *testing.T, doc any)) context {
		return context{path: "tiers[0].vms[0].probes[1]." + key, prep: prep}
	}
	extraProbe := func(probeType string, fields map[string]any) func(t *testing.T, doc any) {
		return func(t *testing.T, doc any) {
			p := map[string]any{"type": probeType, "description": "probe under test"}
			for key, value := range fields {
				p[key] = value
			}
			addProbe(t, doc, p)
		}
	}
	vxlan := func(t *testing.T, doc any) {
		setPath(doc, "network.mode", "vxlan")
		setPath(doc, "network.peers", "192.0.2.200")
	}
	contexts := map[string]context{
		"Compliance.retention_days":                 {path: "compliance.retention_days"},
		"Compliance.rto_target_seconds":             {path: "compliance.rto_target_seconds"},
		"AdmissionControl.max_host_ram_percent":     {path: "admission_control.max_host_ram_percent"},
		"AdmissionControl.max_host_iowait_percent":  {path: "admission_control.max_host_iowait_percent"},
		"AdmissionControl.defer_retry_interval_sec": {path: "admission_control.defer_retry_interval_sec"},
		"AdmissionControl.max_defer_retries":        {path: "admission_control.max_defer_retries"},
		"AdmissionControl.max_concurrent_boots":     {path: "admission_control.max_concurrent_boots"},
		"AdmissionControl.boot_settle_sec": {path: "admission_control.boot_settle_sec", prep: func(t *testing.T, doc any) {
			setPath(doc, "admission_control.max_concurrent_boots", 1)
		}},
		"Network.tag":                   {path: "network.tag", high: vxlan},
		"Storage.max_copy_gib":          {path: "storage.max_copy_gib"},
		"Tier.level":                    tier("level"),
		"Tier.startup_grace_period_sec": tier("startup_grace_period_sec"),
		"Tier.boot_timeout_sec":         tier("boot_timeout_sec"),
		"Tier.soak_time_sec":            tier("soak_time_sec"),
		"VM.vmid": {path: "tiers[0].vms[0].vmid", prep: func(t *testing.T, doc any) {
			setPath(doc, "tiers[0].vms[0].source_vmid", 7)
		}},
		"VM.source_vmid": {path: "tiers[0].vms[0].source_vmid", low: func(t *testing.T, doc any) {
			// A source VM of 0 is "not named", which `latest` cannot do without.
			setPath(doc, "tiers[0].vms[0].source_pbs.snapshot", "vm/5/latest")
		}},
		"HardwareOverrides.cores":      hardware("cores", nil),
		"HardwareOverrides.sockets":    hardware("sockets", nil),
		"HardwareOverrides.memory_mb":  hardware("memory_mb", nil),
		"HardwareOverrides.cpu_weight": hardware("cpu_weight", nil),
		"HardwareOverrides.balloon_mb": hardware("balloon_mb", func(t *testing.T, doc any) {
			// The balloon is part of the memory, so the memory must be at least as large.
			setPath(doc, "tiers[0].vms[0].hardware_overrides.memory_mb", 4194304)
		}),
		"Probe.timeout_sec": probe("timeout_sec", extraProbe("qmp", nil)),
		"Probe.retries":     probe("retries", extraProbe("qmp", nil)),
		"Probe.port": {path: "tiers[0].vms[0].probes[1].port",
			low:  extraProbe("qmp", nil),
			high: extraProbe("tcp", map[string]any{"target_ip": "192.0.2.10"})},
		"Probe.expected_status": {path: "tiers[0].vms[0].probes[1].expected_status",
			low:  extraProbe("qmp", nil),
			high: extraProbe("http", map[string]any{"target_ip": "192.0.2.10", "port": 80})},
	}
	// Aliases of a key share its bound by construction; they are named so that
	// a bound added to a new key is not skipped silently.
	aliases := map[string]string{
		"AdmissionControl.max_host_io_wait_percent": "AdmissionControl.max_host_iowait_percent",
		"Tier.tier":      "Tier.level",
		"VM.target_vmid": "VM.vmid",
	}

	for entry, note := range planSchemaNotes {
		if note.Min == nil && note.Max == nil && note.ExclusiveMin == nil {
			continue
		}
		if _, isAlias := aliases[entry]; isAlias {
			continue
		}
		c, covered := contexts[entry]
		if !covered {
			t.Errorf("%s has a bound and no context in this test: add one, so the loader is asked about it", entry)
			continue
		}
		t.Run(entry, func(t *testing.T) {
			attempt := func(value float64, prep func(t *testing.T, doc any)) (loader string, schema []string) {
				doc := examplePlan(t)
				if c.prep != nil {
					c.prep(t, doc)
				}
				if prep != nil {
					prep(t, doc)
				}
				var typed any = value
				if value == float64(int64(value)) {
					typed = int(value)
				}
				setPath(doc, c.path, typed)
				return loaderErrors(t, doc)[c.path], problemsAt(schemaProblems(doc), c.path)
			}
			expectAccepted := func(value float64, prep func(t *testing.T, doc any)) {
				t.Helper()
				if loader, schema := attempt(value, prep); loader != "" || len(schema) > 0 {
					t.Errorf("%v: the loader says %q, the schema says %v; both should accept it", value, loader, schema)
				}
			}
			expectRefused := func(value float64, prep func(t *testing.T, doc any)) {
				t.Helper()
				if loader, schema := attempt(value, prep); loader == "" || len(schema) == 0 {
					t.Errorf("%v: the loader says %q, the schema says %v; both should refuse it", value, loader, schema)
				}
			}
			switch {
			case note.Min != nil:
				expectAccepted(*note.Min, c.low)
				if note.OrZero {
					expectAccepted(0, c.low)
					expectRefused(*note.Min-1, c.low)
					expectRefused(1, c.low)
					break
				}
				expectRefused(*note.Min-1, c.low)
			case note.ExclusiveMin != nil:
				expectAccepted(*note.ExclusiveMin+0.5, c.low)
				expectRefused(*note.ExclusiveMin, c.low)
			}
			if note.Max != nil {
				expectAccepted(*note.Max, c.high)
				expectRefused(*note.Max+1, c.high)
			}
		})
	}
	for alias, target := range aliases {
		if planSchemaNotes[alias].Min != planSchemaNotes[target].Min || planSchemaNotes[alias].Max != planSchemaNotes[target].Max ||
			planSchemaNotes[alias].ExclusiveMin != planSchemaNotes[target].ExclusiveMin {
			if !sameBounds(planSchemaNotes[alias], planSchemaNotes[target]) {
				t.Errorf("%s does not state the bounds of %s", alias, target)
			}
		}
	}
}

func sameBounds(a, b fieldNote) bool {
	equal := func(x, y *float64) bool { return (x == nil && y == nil) || (x != nil && y != nil && *x == *y) }
	return equal(a.Min, b.Min) && equal(a.Max, b.Max) && equal(a.ExclusiveMin, b.ExclusiveMin)
}

// The required keys of each section are keys the loader requires: taking one
// out of a plan the loader accepts makes it refuse the plan, and the schema
// refuses it too. A key with an alias is required in one of its spellings, and
// the alias alone is as good as the key.
func TestPlanSchemaRequiredKeysAreTheLoadersRequiredKeys(t *testing.T) {
	sections := map[string]string{
		"Plan": "", "Compliance": "compliance", "Network": "network", "Tier": "tiers[0]", "VM": "tiers[0].vms[0]",
		"SourceDrive": "tiers[0].vms[0].source_pbs.drives[0]", "Probe": "tiers[0].vms[0].probes[0]",
	}
	base := func(t *testing.T) any {
		doc := examplePlan(t)
		setPath(doc, "tiers[0].vms[0].source_pbs.drives", []any{map[string]any{"slot": "scsi0", "archive": "drive-scsi0"}})
		return doc
	}
	if errs := loaderErrors(t, base(t)); errs != nil {
		t.Fatalf("the base plan is refused: %v", errs)
	}
	if problems := schemaProblems(base(t)); len(problems) != 0 {
		t.Fatalf("the base plan is refused by the schema: %v", problems)
	}
	prefix := func(section, key string) string {
		if sections[section] == "" {
			return key
		}
		return sections[section] + "." + key
	}
	for section, keys := range planSchemaRequired {
		if _, known := sections[section]; !known {
			t.Errorf("%s has required keys and no path in this test", section)
			continue
		}
		for _, key := range keys {
			t.Run(section+"."+key, func(t *testing.T) {
				doc := base(t)
				deletePath(doc, prefix(section, key))
				if loaderErrors(t, doc) == nil {
					t.Error("the loader accepts a plan without it")
				}
				if problems := schemaProblems(doc); len(problems) == 0 {
					t.Error("the schema accepts a plan without it")
				}
			})
		}
	}
	// The alternatives: either spelling alone is accepted by both, neither is refused by both.
	for section, groups := range planSchemaOneOf {
		for _, group := range groups {
			for _, spelling := range group {
				t.Run(section+" "+spelling+" alone", func(t *testing.T) {
					doc := base(t)
					canonical := group[0]
					if spelling != canonical {
						moved, _ := getPath(doc, prefix(section, canonical))
						if section == "Plan" && canonical == "admission_control" {
							// The older block carries the same limits.
							moved = moved.(map[string]any)
						}
						deletePath(doc, prefix(section, canonical))
						setPath(doc, prefix(section, spelling), moved)
					}
					if errs := loaderErrors(t, doc); errs != nil {
						t.Errorf("the loader refuses %s alone: %v", spelling, errs)
					}
					if problems := schemaProblems(doc); len(problems) > 0 {
						t.Errorf("the schema refuses %s alone: %v", spelling, problems)
					}
				})
			}
			t.Run(section+" none of "+strings.Join(group, "/"), func(t *testing.T) {
				doc := base(t)
				for _, spelling := range group {
					deletePath(doc, prefix(section, spelling))
				}
				if loaderErrors(t, doc) == nil {
					t.Error("the loader accepts a plan with none of them")
				}
				if problems := schemaProblems(doc); len(problems) == 0 {
					t.Error("the schema accepts a plan with none of them")
				}
			})
		}
	}
}

// Which keys a probe reads, and which it needs, are the loader's rules (the
// probeFields table the loader refuses a misplaced key with): a key a type does
// not read is refused by both, a key it reads is refused by neither, and a key
// it needs is needed by both.
func TestPlanSchemaProbeRulesAreTheLoadersRules(t *testing.T) {
	sample := map[string]any{
		"target_ip": "192.0.2.10", "port": 80, "url": "http://192.0.2.10/", "path": "/", "tls": true, "server_name": "example.com",
		"expected_status": 200, "domain": "example.com", "transport": "udp", "record_type": "a", "base_dn": "auto",
		"naming_context": "DC=example,DC=com", "command": "hostname", "expected_output": "x", "require_qga": true,
	}
	// A probe of each type that the loader accepts, to add beside the example's.
	minimal := map[string]map[string]any{
		"tcp":        {"target_ip": "192.0.2.10", "port": 22},
		"http":       {"target_ip": "192.0.2.10", "port": 80, "expected_status": 200},
		"dns":        {"target_ip": "192.0.2.10", "port": 53},
		"ldap":       {"target_ip": "192.0.2.10", "port": 389},
		"mssql":      {"target_ip": "192.0.2.10", "port": 1433},
		"smb":        {"target_ip": "192.0.2.10", "port": 445},
		"qga":        {"command": "hostname"},
		"qmp":        {},
		"screendump": {},
	}
	build := func(t *testing.T, probeType string, edit func(probe map[string]any)) (doc any, field func(key string) string) {
		probe := map[string]any{"type": probeType, "description": "probe under test"}
		for key, value := range minimal[probeType] {
			probe[key] = value
		}
		if edit != nil {
			edit(probe)
		}
		doc = examplePlan(t)
		addProbe(t, doc, probe)
		return doc, func(key string) string { return "tiers[0].vms[0].probes[1]." + key }
	}
	for _, probeType := range probeTypes {
		if _, ok := minimal[probeType]; !ok {
			t.Fatalf("no minimal probe for the type %s", probeType)
		}
		doc, _ := build(t, probeType, nil)
		if errs := loaderErrors(t, doc); errs != nil {
			t.Fatalf("the minimal %s probe is refused: %v", probeType, errs)
		}
		if problems := schemaProblems(doc); len(problems) != 0 {
			t.Fatalf("the minimal %s probe is refused by the schema: %v", probeType, problems)
		}
	}
	for _, probeType := range probeTypes {
		for _, field := range probeFields {
			if _, present := minimal[probeType][field.key]; present {
				continue
			}
			t.Run(probeType+" "+field.key, func(t *testing.T) {
				doc, path := build(t, probeType, func(probe map[string]any) { probe[field.key] = sample[field.key] })
				loader := loaderErrors(t, doc)[path(field.key)]
				schema := problemsAt(schemaProblems(doc), path(field.key))
				if field.readBy(probeType) {
					if len(schema) > 0 {
						t.Errorf("a %s probe reads %s: the schema refuses it: %v", probeType, field.key, schema)
					}
					return
				}
				if loader == "" || len(schema) == 0 {
					t.Errorf("a %s probe does not read %s: the loader says %q, the schema says %v; both should refuse it", probeType, field.key, loader, schema)
				}
			})
		}
		// An unread key at its zero value is "not set", and both accept it.
		t.Run(probeType+" a key at its zero value", func(t *testing.T) {
			doc, path := build(t, probeType, func(probe map[string]any) { probe["tls"] = false; probe["expected_output"] = "" })
			if probeType == "http" || probeType == "qga" {
				return // these types read those keys
			}
			if loader := loaderErrors(t, doc)[path("tls")]; loader != "" {
				t.Errorf("the loader refuses tls: false: %s", loader)
			}
			if schema := problemsAt(schemaProblems(doc), path("tls")); len(schema) > 0 {
				t.Errorf("the schema refuses tls: false: %v", schema)
			}
		})
		for key := range minimal[probeType] {
			// An http probe may take its address and port from a url, so the
			// schema does not require them of it; the loader does when there is none.
			needed := key == "expected_status" || key == "command" || (probeType != "http" && (key == "target_ip" || key == "port"))
			if needed {
				t.Run(probeType+" without "+key, func(t *testing.T) {
					doc, path := build(t, probeType, func(probe map[string]any) { delete(probe, key) })
					if loaderErrors(t, doc)[path(key)] == "" {
						t.Errorf("the loader accepts a %s probe without %s", probeType, key)
					}
					if joined := strings.Join(schemaProblems(doc), "\n"); !strings.Contains(joined, `"`+key+`" is required`) {
						t.Errorf("the schema accepts a %s probe without %s: %s", probeType, key, joined)
					}
				})
			}
		}
	}
	// The aliases of a type are held to its rules: a qga_ping needs no command
	// (it defaults to ping), a tcp_handshake needs a port.
	t.Run("aliases", func(t *testing.T) {
		doc, path := build(t, "qmp", func(probe map[string]any) { probe["type"] = "qga_ping" })
		if errs := loaderErrors(t, doc); errs != nil {
			t.Fatalf("qga_ping with no command is refused: %v", errs)
		}
		if problems := schemaProblems(doc); len(problems) != 0 {
			t.Errorf("the schema refuses qga_ping with no command: %v", problems)
		}
		doc, path = build(t, "tcp", func(probe map[string]any) { probe["type"] = "tcp_handshake"; delete(probe, "port") })
		if loaderErrors(t, doc)[path("port")] == "" || len(problemsAt(schemaProblems(doc), path("port")))+len(schemaProblems(doc)) == 0 {
			t.Error("a tcp_handshake without a port is accepted")
		}
	})
	// The status range of an http probe is 200 to 599, not the 0 to 599 of the key.
	for status, accepted := range map[int]bool{199: false, 200: true, 599: true, 600: false} {
		doc, path := build(t, "http", func(probe map[string]any) { probe["expected_status"] = status })
		loader := loaderErrors(t, doc)[path("expected_status")] == ""
		schema := len(problemsAt(schemaProblems(doc), path("expected_status"))) == 0
		if loader != accepted || schema != accepted {
			t.Errorf("expected_status %d: loader accepts %v, schema accepts %v, want %v", status, loader, schema, accepted)
		}
	}
}

// A plan that carries one of the keys the loader rejects (a gateway, an MTU, an
// IPAM plugin, a certificate bypass) is refused by the schema too.
func TestPlanSchemaFlagsTheKeysTheLoaderRejects(t *testing.T) {
	for path, value := range map[string]any{
		"network.gateway": "192.0.2.254",
		"network.ipam":    "dhcp",
		"network.mtu":     9000,
		"tiers[0].vms[0].probes[0].tls_skip_verify":      true,
		"tiers[0].vms[0].probes[0].insecure_skip_verify": true,
	} {
		doc := examplePlan(t)
		setPath(doc, path, value)
		if loaderErrors(t, doc) == nil {
			t.Errorf("%s: the loader accepts it", path)
		}
		if len(problemsAt(schemaProblems(doc), path)) == 0 {
			t.Errorf("%s: the schema accepts it", path)
		}
	}
}

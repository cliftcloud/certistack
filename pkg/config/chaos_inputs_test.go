// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// loaderAcceptsSchemaFlags fails when the loader accepts the plan text and the
// schema flags it.
func loaderAcceptsSchemaFlags(t *testing.T, text string) {
	t.Helper()
	if _, err := LoadFromReader(strings.NewReader(text)); err != nil {
		t.Fatalf("the loader refuses the plan: %v", err)
	}
	var document any
	if err := yaml.Unmarshal([]byte(text), &document); err != nil {
		t.Fatal(err)
	}
	if problems := schemaProblems(document); len(problems) > 0 {
		t.Errorf("validate accepts the plan, and the schema flags it: %s", strings.Join(problems, "; "))
	}
}

// examplePlanText is the smallest shipped plan with one edit.
func examplePlanText(t *testing.T, edit func(doc any)) string {
	t.Helper()
	doc := examplePlan(t)
	edit(doc)
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A number or a YAML 1.1 yes or no written into a text or boolean key
// (name: 2026, use_backup_config: yes) is read by the loader as its text or
// as the boolean, and the schema must accept it too, not flag it as the wrong
// type.
func TestPlanSchemaAcceptsTheScalarsTheLoaderAccepts(t *testing.T) {
	loaderAcceptsSchemaFlags(t, examplePlanText(t, func(doc any) { setPath(doc, "name", 2026) }))
	loaderAcceptsSchemaFlags(t, examplePlanText(t, func(doc any) { setPath(doc, "use_backup_config", "yes") }))
}

// A key written with no value ("storage:" with every line under it commented
// out) is a key left out for the loader, and for the schema, which must not
// flag it as null. A required key given no value is still refused by both.
func TestPlanSchemaAcceptsAKeyGivenNoValue(t *testing.T) {
	text := examplePlanText(t, func(doc any) { deletePath(doc, "storage") }) + "storage:\n  # overlay_storage: certistack-scratch\n"
	loaderAcceptsSchemaFlags(t, text)
	for _, path := range []string{"network", "tiers[0].vms[0].probes[0].port", "admission_control"} {
		doc := examplePlan(t)
		setPath(doc, path, nil)
		if loader, schema := verdicts(t, doc); loader == nil || len(schema) == 0 {
			t.Errorf("%s given no value: the loader says %v, the schema says %v; both should refuse it", path, loader, schema)
		}
	}
}

// A control character (an ANSI escape, a carriage return, NUL) or a
// bidirectional override in a plan's name, a tier's name or a probe's
// description would reach the terminal raw through validate, plan, run and
// report show. validate refuses it, naming the key; a description or expected
// output may still run over lines.
func TestValidateRefusesControlCharactersInText(t *testing.T) {
	for path, value := range map[string]string{
		"name":                                  "Nightly\x1b]0;owned\x07",
		"tiers[0].name":                         "Tier\r\x1b[2K",
		"tiers[0].vms[0].probes[0].description": "SSH \u202eokay",
		"environment":                           "prod\x00",
	} {
		text := examplePlanText(t, func(doc any) { setPath(doc, path, value) })
		_, err := LoadFromReader(bytes.NewReader([]byte(text)))
		if err == nil || !strings.Contains(err.Error(), path+": holds a") {
			t.Errorf("%s %q: %v, want it refused at the key", path, value, err)
		}
	}
	for path, value := range map[string]string{
		"tiers[0].vms[0].probes[0].description": "SSH answers\n\tafter the boot\n",
		"name":                                  "Nightly – café ✓",
	} {
		text := examplePlanText(t, func(doc any) { setPath(doc, path, value) })
		if _, err := LoadFromReader(bytes.NewReader([]byte(text))); err != nil {
			t.Errorf("%s %q is refused: %v", path, value, err)
		}
	}
}

// A VM's sandbox vmid may not be another VM's source_vmid in the same plan
// (vmid 100 beside a VM restored from VM 100's backups). While VM 100 exists a
// run refuses it only on the node; once VM 100 is deleted (its backups still
// tested), the sandbox VM would take the ID that names those backups. validate
// refuses it, as it refuses a VM's own source_vmid.
func TestASandboxVMIDIsNoSourceVMIDOfThePlan(t *testing.T) {
	plan := validPlan()
	other := plan.Tiers[0].VMs[0]
	other.VMID, other.SourceVMID, other.Name = 9002, 9001, "cs-test-dc02"
	other.SourcePBS.Snapshot = "vm/9001/latest"
	other.Probes = []Probe{{Type: "tcp", TargetIP: "10.100.0.11", Port: 22, TimeoutSec: 10, Description: "ssh"}}
	plan.Tiers[0].VMs = append(plan.Tiers[0].VMs, other)
	for _, problem := range Validate(plan) {
		if problem.Field == "tiers[0].vms[0].vmid" {
			return
		}
	}
	t.Errorf("vmid 9001 is accepted beside a VM that restores the backups of VM 9001: %v", Validate(plan))
}

// The schema refuses in each free-text key what validate refuses there, and
// accepts what it accepts.
func TestPlanSchemaRefusesTheControlCharactersValidateRefuses(t *testing.T) {
	qga := func(t *testing.T, doc any) {
		addProbe(t, doc, map[string]any{"type": "qga", "command": "hostname", "require_qga": true})
	}
	dns := func(t *testing.T, doc any) {
		addProbe(t, doc, map[string]any{"type": "dns", "target_ip": "192.0.2.10", "port": 53})
	}
	contexts := map[string]struct {
		path string
		prep func(t *testing.T, doc any)
	}{
		"Plan.name": {"name", nil}, "Plan.environment": {"environment", nil}, "Tier.name": {"tiers[0].name", nil},
		"Storage.pbs_repository": {"storage.pbs_repository", nil}, "Storage.pbs_namespace": {"storage.pbs_namespace", nil},
		"SourcePBS.namespace":   {"tiers[0].vms[0].source_pbs.namespace", nil},
		"Probe.description":     {"tiers[0].vms[0].probes[0].description", nil},
		"Probe.expected_output": {"tiers[0].vms[0].probes[1].expected_output", qga},
		"Probe.domain":          {"tiers[0].vms[0].probes[1].domain", dns},
	}
	if len(contexts) != len(planTextKeys) {
		t.Fatalf("%d free-text keys, %d contexts", len(planTextKeys), len(contexts))
	}
	for entry, multiLine := range planTextKeys {
		c, ok := contexts[entry]
		if !ok {
			t.Errorf("%s has no context", entry)
			continue
		}
		for value, refused := range map[string]bool{"a\x1bb": true, "a\u202eb": true, "a\u0085b": true, "a\rb": true, "a\nb": !multiLine, "a\tb": !multiLine, "ab": false} {
			doc := examplePlan(t)
			if c.prep != nil {
				c.prep(t, doc)
			}
			if entry == "Storage.pbs_namespace" || entry == "SourcePBS.namespace" {
				ensureMap(t, doc, "storage")
			}
			setPath(doc, c.path, value)
			loader, schema := verdicts(t, doc)
			schema = problemsAt(schema, c.path)
			if refused && (loader[c.path] == "" || len(schema) == 0) || !refused && (loader[c.path] != "" || len(schema) > 0) {
				t.Errorf("%s %q: the loader says %q, the schema says %v; want refused = %v", c.path, value, loader[c.path], schema, refused)
			}
		}
	}
}

// A text key with a pattern (plan_id, a VM's name, a disk slot...) takes text
// only, in the loader and in the schema: a schema cannot hold the text of a
// number to a pattern (the schema would accept name: -1, which validate
// refuses). An unquoted number or true is refused by both, naming the key
// and the quoted form; the quoted text is judged by the pattern.
func TestATextKeyWithAPatternTakesOnlyQuotedText(t *testing.T) {
	drives := func(t *testing.T, doc any) {
		setPath(doc, "tiers[0].vms[0].source_pbs.drives", []any{map[string]any{"slot": "scsi0", "archive": "drive-scsi0"}})
	}
	contexts := map[string]struct {
		path string
		prep func(t *testing.T, doc any)
	}{
		"Plan.plan_id": {"plan_id", nil}, "Network.zone_id": {"network.zone_id", nil}, "Network.vnet_id": {"network.vnet_id", nil},
		"Storage.overlay_storage": {"storage.overlay_storage", nil},
		"VM.name":                 {"tiers[0].vms[0].name", nil}, "VM.mac": {"tiers[0].vms[0].mac", nil}, "VM.machine": {"tiers[0].vms[0].machine", nil},
		"NetworkRecovery.interface_name": {"tiers[0].vms[0].network_recovery.interface_name", func(t *testing.T, doc any) {
			ensureMap(t, doc, "tiers[0].vms[0].network_recovery")
		}},
		"SourcePBS.snapshot":  {"tiers[0].vms[0].source_pbs.snapshot", nil},
		"SourceDrive.slot":    {"tiers[0].vms[0].source_pbs.drives[0].slot", drives},
		"SourceDrive.archive": {"tiers[0].vms[0].source_pbs.drives[0].archive", drives},
	}
	if len(contexts) != len(quotedTextKeys) {
		t.Fatalf("%d keys take quoted text only, %d have a context here", len(quotedTextKeys), len(contexts))
	}
	for entry := range quotedTextKeys {
		c, ok := contexts[entry]
		if !ok {
			t.Errorf("%s has no context", entry)
			continue
		}
		if kind := schemaProperty(t, entry)["type"]; kind != "string" && !sameValue(kind, []any{"string", "null"}) {
			t.Errorf("%s: the schema's type is %v, want text only", entry, kind)
		}
		for _, value := range []any{2026, -1, 1.5, true} {
			doc := examplePlan(t)
			if c.prep != nil {
				c.prep(t, doc)
			}
			setPath(doc, c.path, value)
			loader, schema := verdicts(t, doc)
			if !strings.Contains(loader["(decode)"], c.path+" takes text") || !strings.Contains(loader["(decode)"], "quote it") || len(problemsAt(schema, c.path)) == 0 {
				t.Errorf("%s: %v: the loader says %v, the schema says %v; both should refuse it", c.path, value, loader, schema)
			}
		}
	}
	// Quoted, the text is judged as it always was.
	for path, value := range map[string]string{"plan_id": "2026", "tiers[0].vms[0].name": "2026"} {
		doc := examplePlan(t)
		setPath(doc, path, value)
		if loader, schema := verdicts(t, doc); loader != nil || len(schema) > 0 {
			t.Errorf("%s %q: the loader says %v, the schema says %v; both should accept it", path, value, loader, schema)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/macaddr"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

func flatDoc(t *testing.T, parts ...string) string {
	t.Helper()
	data, err := os.ReadFile(repoFile(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(string(data)), " ")
}

// The guides quote the refusals the code gives for an unusable or shared MAC, a
// replaced preserve identity and a shared wire target, and state the rules. A
// change to a message or a rule fails here until the guide follows.
func TestMACIdentityDocumentationQuotesWhatTheCodeSays(t *testing.T) {
	troubleshooting := flatDoc(t, "docs", "troubleshooting.md")
	reference := flatDoc(t, "docs", "plan-reference.md")

	// What the code says of an address no interface can hold.
	for _, mac := range []string{"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01"} {
		if _, err := macaddr.Parse(mac); err == nil {
			t.Fatalf("%s is accepted", mac)
		}
	}
	_, multicast := macaddr.Parse("33:33:00:00:00:01")
	for _, quoted := range []string{"a multicast (group) address cannot name an interface"} {
		if multicast == nil || !strings.Contains(multicast.Error(), quoted) {
			t.Errorf("the code no longer says %q: %v", quoted, multicast)
		}
		if !strings.Contains(troubleshooting, quoted) {
			t.Errorf("docs/troubleshooting.md does not quote %q", quoted)
		}
	}
	for _, rule := range []string{"not all zeros", "broadcast address", "not a multicast address", "lowest bit of the first octet"} {
		if !strings.Contains(reference, rule) {
			t.Errorf("docs/plan-reference.md no longer states the rule %q", rule)
		}
	}

	// The loader's and the resolved plan's messages, built from the product.
	plan := &config.Plan{Tiers: []config.Tier{{VMs: []config.VM{
		{VMID: 9900, MAC: "00:11:22:33:44:55"},
		{VMID: 9901, MAC: "00-11-22-33-44-55"},
		{VMID: 9902, MAC: "01:00:5E:00:00:01"},
	}}}}
	err := config.CheckNICIdentities(plan)
	if err == nil {
		t.Fatal("a plan with a shared and a multicast MAC passed")
	}
	for _, quoted := range []string{"VM 9901 net0 and VM 9900 net0 both use 00:11:22:33:44:55", "(VM 9902 net0) is not a usable MAC address"} {
		if !strings.Contains(err.Error(), quoted) {
			t.Errorf("the code no longer says %q: %v", quoted, err)
		}
	}
	for _, quoted := range []string{"VM 9901 net0 and VM 9900 net0 both use 00:11:22:33:44:55", "is not a usable MAC address", "VM 9900 net1 and VM 9900 net0"} {
		if !strings.Contains(reference+" "+troubleshooting, quoted) {
			t.Errorf("the guides do not quote %q", quoted)
		}
	}

	// The wire-target refusals: the report rule is an exported message; the
	// orchestrator's and the runner's are read from their source.
	records := []probe.VMValidationRecord{
		{VMID: 9001, ProbeResults: []probe.Result{{Type: "tcp", Target: "192.0.2.10:389", Passed: true}}},
		{VMID: 9002, ProbeResults: []probe.Result{{Type: "tcp", Target: "192.0.2.10:389", Passed: true}}},
	}
	problems := attest.SharedWireTargetProblems(records)
	if len(problems) != 1 || !strings.Contains(problems[0], "VMs 9001, 9002 each record a passing wire probe of 192.0.2.10") {
		t.Fatalf("the report rule says %q", problems)
	}
	if !strings.Contains(troubleshooting, "each record a passing wire probe of") {
		t.Error("docs/troubleshooting.md does not quote the report rule")
	}
	for file, quoted := range map[string][2]string{
		"orchestrator": {"pkg/orchestrator/resolved_inputs.go", "wire probe target %s is named by VMs %s"},
		"runner":       {"pkg/runner/nic_identity.go", "keeps its guest's network as backed up (network_recovery.mode preserve)"},
	} {
		source, err := os.ReadFile(repoFile(strings.Split(quoted[0], "/")...))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(source), quoted[1]) {
			t.Errorf("%s no longer says %q", file, quoted[1])
		}
	}
	for _, quoted := range []string{
		"wire probe target 192.0.2.10 is named by VMs 9001, 9002",
		"keeps its guest's network as backed up (network_recovery.mode preserve)",
	} {
		if !strings.Contains(troubleshooting, quoted) {
			t.Errorf("docs/troubleshooting.md does not quote %q", quoted)
		}
	}

	// What the plan reference states of preserve and of the rules' layers.
	for _, want := range []string{
		"#### NIC MAC addresses",
		"takes the backup's `net0` MAC and model when the plan sets none, whether or not `use_backup_config` is set",
		"a `mac` or `nic_model` that differs from the backup's is refused",
		"a report in which passing wire probes of two VM records name one address is refused by the controller (no report is written) and rejected by `verify-report` as pass evidence even without `--expect-plan`",
	} {
		if !strings.Contains(reference, want) {
			t.Errorf("docs/plan-reference.md no longer says %q", want)
		}
	}
}

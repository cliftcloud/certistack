// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/nodecheck"
)

// wireProbeEntry is one tcp or http probe of the valid test plan, up to the
// next probe.
var wireProbeEntry = regexp.MustCompile(`(?m)^          - type: "(tcp|http)"\n(?:            .*\n)+`)

func writePlanWithoutWireProbes(t *testing.T, c controllerDir) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	stripped := wireProbeEntry.ReplaceAllString(string(data), "")
	// A plan whose probes are all agent probes needs one that must answer.
	stripped = strings.ReplaceAll(stripped, `- type: "qga"`+"\n", `- type: "qga"`+"\n            require_qga: true\n")
	if strings.Contains(stripped, `type: "tcp"`) || strings.Contains(stripped, `type: "http"`) || !strings.Contains(stripped, `type: "qga"`) {
		t.Fatalf("the plan still has wire probes, or lost its agent probes:\n%s", stripped)
	}
	path := filepath.Join(c.dir, "agent-only-plan.yaml")
	if err := os.WriteFile(path, []byte(stripped), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The worker is told whether the plan has a wire probe, because only such a plan
// needs nft: with no plan, or one that has them, nft is required.
func TestCheckTellsTheWorkerWhetherThePlanNeedsNft(t *testing.T) {
	c := readyController(t)
	for name, tc := range map[string]struct {
		plan string
		want bool
	}{
		"no plan":                       {"", false},
		"a plan with wire probes":       {writeCheckedPlan(t, c), false},
		"a plan with only agent probes": {writePlanWithoutWireProbes(t, c), true},
	} {
		stub := &nodeStub{}
		withNode(t, stub)
		args := []string{"check", "--env-file", c.env}
		if tc.plan != "" {
			args = append(args, tc.plan)
		}
		if out, err := runRootWithInput(t, "", args...); err != nil {
			t.Fatalf("%s: check: %v\n%s", name, err, out)
		}
		if len(stub.staged) != 1 {
			t.Fatalf("%s: the node was asked %d times", name, len(stub.staged))
		}
		if got := stub.staged[0].NoWireProbes; got != tc.want {
			t.Errorf("%s: the worker was told NoWireProbes = %v, want %v", name, got, tc.want)
		}
	}

	// A plan that does not validate says nothing: nft stays required.
	stub := &nodeStub{}
	withNode(t, stub)
	broken := filepath.Join(c.dir, "broken.yaml")
	if err := os.WriteFile(broken, []byte("version: v1\ntiers: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = runRootWithInput(t, "", "check", "--env-file", c.env, broken)
	if len(stub.staged) != 1 || stub.staged[0].NoWireProbes {
		t.Errorf("a plan that does not validate told the worker it needs no nft: %+v", stub.staged)
	}
}

// A node without nft or ip is told which package to install.
func TestCheckLayer4NamesNftAndIPWithTheirPackages(t *testing.T) {
	c := readyController(t)
	stub := &nodeStub{report: nodecheck.Report{Layers: []nodecheck.Layer{{
		Name: nodecheck.LayerTools, Status: nodecheck.StatusFailed, Code: nodecheck.CodeToolsMissing,
		Detail: "not installed on the node (or not on its PATH): ip, nft",
		Missing: []nodecheck.Tool{
			{Name: "ip", Package: "iproute2"},
			{Name: "nft", Package: "nftables", WireProbesOnly: true},
		},
	}}}}
	withNode(t, stub)
	out, _ := failsAt(t, c)
	for _, want := range []string{"✗ 4. Node tools", "ip, nft", "Fix: Run certistack setup", "By hand, on the node as root: apt update; apt install --no-upgrade iproute2 nftables", "nft contains the sandbox probe address", "certistack doctor"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

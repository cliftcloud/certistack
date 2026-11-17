// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// The controller refuses to sign a passing VM whose probe results break the
// policy rules (attest.ProbePolicyProblems), so a worker that really runs a
// plan must satisfy them, or every honest run would be refused. This runs the
// real probe stage for probes that carry a policy (a timeout, retries, a
// virtual host, a required and an optional guest-agent check) and holds what it
// records to the rules the controller applies, with the plan the worker ran.
func TestTheRealProbeStageSatisfiesThePolicyRulesTheControllerAppliesBeforeSigning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, _ := net.SplitHostPort(parsed.Host)
	httpPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	const vmid = 9931
	dir := shortSocketDir(t)
	fakeQGA(t, dir, vmid, map[string]any{"guest-ping": map[string]any{"return": map[string]any{}}}, nil)
	vm := config.VM{VMID: vmid, Name: "restore", Probes: []config.Probe{
		{Type: "tcp", TargetIP: "127.0.0.1", Port: acceptingPort(t), Description: "service readiness", TimeoutSec: 3, Retries: 2},
		{Type: "http", TargetIP: host, Port: httpPort, Path: "/", ServerName: "app.example.com", ExpectedStatus: 200, TimeoutSec: 2, Description: "virtual host"},
		{Type: "http", TargetIP: host, Port: httpPort, Path: "/", ExpectedStatus: 200, TimeoutSec: 2, Description: "bare address"},
		{Type: "qga", Command: "ping", RequireQGA: true, TimeoutSec: 2, Retries: 1, Description: "agent required"},
		{Type: "qga", Command: "ping", TimeoutSec: 2, Description: "agent optional"},
	}}
	plan := &config.Plan{Tiers: []config.Tier{{Level: 1, VMs: []config.VM{vm}}}}
	o := &Orchestrator{opts: Options{QGASocketDir: dir}, plan: plan}
	results, passed, err := o.runProbes(context.Background(), vm)
	if !passed || err != nil || len(results) != len(vm.Probes) {
		t.Fatalf("runProbes = %+v, passed %v, err %v; want every probe passed", results, passed, err)
	}
	record := probe.VMValidationRecord{VMID: vmid, VerificationStatus: "verified", AllPassed: true, ProbeResults: results}
	if problems := attest.ProbePolicyProblems(record, &vm, plan); len(problems) != 0 {
		t.Errorf("the policy rules refuse what the real probe stage recorded: %q", problems)
	}
	if problems := attest.ProbeProblems(record, &vm, -1); len(problems) != 0 {
		t.Errorf("the probe rules refuse what the real probe stage recorded: %q", problems)
	}
	// The rules are not vacuous: the same record with one policy member changed
	// is refused.
	for name, mutate := range map[string]func(*probe.Result){
		"a timeout": func(r *probe.Result) { r.TimeoutSec++ },
		"retries":   func(r *probe.Result) { r.Retries++ },
	} {
		changed := record
		changed.ProbeResults = append([]probe.Result(nil), results...)
		mutate(&changed.ProbeResults[0])
		if len(attest.ProbePolicyProblems(changed, &vm, plan)) == 0 {
			t.Errorf("a record with %s changed passes the policy rules", name)
		}
	}
}

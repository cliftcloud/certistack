// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// probePlan is validPlan with one VM that keeps its own addresses and holds
// the probe under test first, followed by a tcp probe so that the VM always
// has a guest-level assertion: what the tests look at is the probe.
func probePlan(probe Probe) *Plan {
	p := validPlan()
	vm := &p.Tiers[0].VMs[0]
	vm.NetworkRecovery = NetworkRecovery{Mode: "preserve"}
	vm.Probes = []Probe{probe, {Type: "tcp", TargetIP: "10.100.0.10", Port: 22, TimeoutSec: 5, Description: "anchor"}}
	return p
}

// baseProbes are valid probes, one for each canonical type.
func baseProbes() map[string]Probe {
	wire := func(kind string, port int) Probe {
		return Probe{Type: kind, TargetIP: "10.100.0.10", Port: port, TimeoutSec: 5, Description: kind + " probe"}
	}
	http := wire("http", 80)
	http.ExpectedStatus = 200
	return map[string]Probe{
		"tcp":        wire("tcp", 22),
		"http":       http,
		"dns":        wire("dns", 53),
		"ldap":       wire("ldap", 389),
		"mssql":      wire("mssql", 1433),
		"smb":        wire("smb", 445),
		"qga":        {Type: "qga", Command: "hostname", RequireQGA: true, TimeoutSec: 5, Description: "qga probe"},
		"qmp":        {Type: "qmp", TimeoutSec: 5, Description: "qmp probe"},
		"screendump": {Type: "screendump", TimeoutSec: 5, Description: "screendump probe"},
	}
}

// aFieldValue sets the probe field named key to a value that is valid where
// the type reads it.
func aFieldValue(t *testing.T, p *Probe, key string) {
	t.Helper()
	switch key {
	case "target_ip":
		p.TargetIP = "10.100.0.10"
	case "port":
		p.Port = 22
	case "url":
		p.URL = "http://10.100.0.10:22/x"
	case "path":
		p.Path = "/x"
	case "tls":
		p.TLS = true
	case "server_name":
		p.ServerName = "a.example.com"
	case "expected_status":
		p.ExpectedStatus = 200
	case "domain":
		p.Domain = "a.example.com"
	case "transport":
		p.Transport = "tcp"
	case "record_type":
		p.RecordType = "a"
	case "base_dn":
		p.BaseDN = "auto"
	case "naming_context":
		p.NamingContext = "DC=a,DC=b"
	case "command":
		p.Command = "hostname"
	case "expected_output":
		p.ExpectedOutput = "x"
	case "require_qga":
		p.RequireQGA = true
	default:
		t.Fatalf("no sample value for probe field %q", key)
	}
}

// The reported case. A tcp probe carried eleven fields that only other probe
// types read, the loaders accepted all of them, and the run made a plain TCP
// connection: the plan claimed TLS, a status, an output and a directory lookup
// that never happened. Every one is refused, by both loaders, with its own
// path.
func TestATCPProbeCannotCarryTheFieldsOfOtherTypes(t *testing.T) {
	probe := baseProbes()["tcp"]
	probe.URL = "https://ignored.invalid/health"
	probe.Path = "/ignored-http-path"
	probe.TLS = true
	probe.ServerName = "ignored.invalid"
	probe.ExpectedStatus = 599
	probe.Command = "systemctl is-active nonexistent"
	probe.ExpectedOutput = "must-never-match"
	probe.RequireQGA = true
	probe.Domain = "ignored.invalid"
	probe.Transport = "sctp"
	probe.BaseDN = "DC=ignored,DC=invalid"
	p := probePlan(probe)

	if _, err := loadText(t, planText(t, p)); err == nil {
		t.Fatal("a tcp probe carrying url, path, tls, server_name, expected_status, command, expected_output, require_qga, domain, transport and base_dn loaded")
	}
	errs := Validate(p)
	for _, field := range []string{"url", "path", "tls", "server_name", "expected_status", "command", "expected_output", "require_qga", "domain", "transport", "base_dn"} {
		if !hasFieldError(errs, "tiers[0].vms[0].probes[0]."+field) {
			t.Errorf("no error on %s of a tcp probe: %v", field, errs)
		}
	}
	for _, err := range errs {
		if err.Field == "tiers[0].vms[0].probes[0].tls" && !strings.Contains(err.Message, "only http probes use it") {
			t.Errorf("the tls error does not say which probe reads it: %q", err.Message)
		}
	}
}

// Every probe field against every probe type, under each spelling of the type.
// A field a type reads is accepted; a field it does not read is refused. The
// valid control has no errors at all.
func TestEveryProbeFieldIsAcceptedOnlyWhereItIsRead(t *testing.T) {
	spellings := map[string][]string{
		"tcp": {"tcp", "tcp_handshake"}, "http": {"http", "http_get"}, "qga": {"qga", "qga_ping"}, "qmp": {"qmp", "qmp_status"},
		"dns": {"dns"}, "ldap": {"ldap"}, "mssql": {"mssql"}, "smb": {"smb"}, "screendump": {"screendump"},
	}
	for _, canonical := range probeTypes {
		for _, spelling := range spellings[canonical] {
			base := baseProbes()[canonical]
			base.Type = spelling
			if errs := Validate(probePlan(base)); len(errs) != 0 {
				t.Fatalf("the control %s probe does not validate: %v", spelling, errs)
			}
			for _, field := range probeFields {
				probe := base
				aFieldValue(t, &probe, field.key)
				if field.key == "url" {
					// A url says where the request goes; the target must agree.
					probe.URL = "http://10.100.0.10:80/"
				}
				refused := hasFieldError(Validate(probePlan(probe)), "tiers[0].vms[0].probes[0]."+field.key)
				if want := !field.readBy(canonical); refused != want {
					t.Errorf("%s probe with %s: refused = %v, want %v", spelling, field.key, refused, want)
				}
			}
		}
	}
}

// The table that refuses fields is the one the dispatcher reads from.
// Each field a probe type reads is exactly one the dispatcher passes on; a
// field missing here is one the table would refuse although a prober uses it.
func TestTheFieldTableCoversEveryProbeField(t *testing.T) {
	typ := reflect.TypeOf(Probe{})
	covered := map[string]bool{}
	for _, field := range probeFields {
		covered[field.key] = true
	}
	// Fields every type has, and the two certificate-check bypasses, which no
	// type may carry.
	universal := map[string]bool{"type": true, "timeout_sec": true, "retries": true, "description": true, "tls_skip_verify": true, "insecure_skip_verify": true}
	for i := 0; i < typ.NumField(); i++ {
		key := strings.Split(typ.Field(i).Tag.Get("yaml"), ",")[0]
		if !covered[key] && !universal[key] {
			t.Errorf("probe field %q is in neither probeFields nor the universal list", key)
		}
	}
}

// No probe of any type may carry a certificate-check bypass, not only
// the type that would read it.
func TestNoProbeTypeMayCarryACertificateBypass(t *testing.T) {
	for kind, base := range baseProbes() {
		for _, bypass := range []func(*Probe){
			func(p *Probe) { p.InsecureSkipVerify = true },
			func(p *Probe) { p.TLSSkipVerify = true },
		} {
			probe := base
			bypass(&probe)
			if !hasFieldError(Validate(probePlan(probe)), "tiers[0].vms[0].probes[0].insecure_skip_verify") {
				t.Errorf("a %s probe with a TLS verification bypass validates", kind)
			}
		}
	}
}

// An http probe that gives a url and a different target_ip loaded, the
// url was ignored, and the run made the request the plan did not show.
func TestAnHTTPURLMustAgreeWithTheProbesOwnTarget(t *testing.T) {
	probe := func(edit func(*Probe)) Probe {
		p := Probe{Type: "http", ExpectedStatus: 200, TimeoutSec: 5, Description: "health"}
		edit(&p)
		return p
	}
	for name, tc := range map[string]struct {
		probe Probe
		want  string // the text the refusal has, "" if the probe is accepted
	}{
		"the reporter's disagreement": {probe(func(p *Probe) {
			p.URL, p.TargetIP, p.Port, p.Path = "https://10.100.0.10:8443/health", "10.100.0.11", 80, "/"
		}), "names host 10.100.0.10, but target_ip is 10.100.0.11"},
		"the host alone differs": {probe(func(p *Probe) {
			p.URL, p.TargetIP, p.Port = "http://10.100.0.10:80/", "10.100.0.11", 80
		}), "names host 10.100.0.10, but target_ip is 10.100.0.11"},
		"the port differs": {probe(func(p *Probe) {
			p.URL, p.TargetIP, p.Port = "http://10.100.0.10:8080/", "10.100.0.10", 80
		}), "names port 8080, but port is 80"},
		"the path differs": {probe(func(p *Probe) {
			p.URL, p.TargetIP, p.Port, p.Path = "http://10.100.0.10/a", "10.100.0.10", 80, "/b"
		}), `names path "/a", but path is "/b"`},
		"a url and a target_ip that agree": {probe(func(p *Probe) {
			p.URL, p.TargetIP = "https://10.100.0.10:8443/health", "10.100.0.10"
		}), ""},
		"a url alone": {probe(func(p *Probe) { p.URL = "https://10.100.0.10:8443/health" }), ""},
	} {
		t.Run(name, func(t *testing.T) {
			p := probePlan(tc.probe)
			p.Normalize()
			errs := Validate(p)
			var urlErr string
			for _, err := range errs {
				if err.Field == "tiers[0].vms[0].probes[0].url" {
					urlErr = err.Message
				}
			}
			switch {
			case tc.want == "" && len(errs) != 0:
				t.Fatalf("refused: %v", errs)
			case tc.want != "" && !strings.Contains(urlErr, tc.want):
				t.Fatalf("url error %q (all: %v), want one with %q", urlErr, errs, tc.want)
			}
			if tc.want == "" {
				got := p.Tiers[0].VMs[0].Probes[0]
				if got.TargetIP != "10.100.0.10" || got.Port == 0 || got.Path == "" {
					t.Errorf("the accepted url was not expanded: %+v", got)
				}
			}
		})
	}
}

func TestSameProbeHost(t *testing.T) {
	for _, tc := range []struct {
		target, host string
		want         bool
	}{
		{"10.100.0.10", "10.100.0.10", true},
		{" 10.100.0.10 ", "10.100.0.10", true},
		{"::ffff:10.100.0.10", "10.100.0.10", true},
		{"fd00::10", "FD00:0:0:0:0:0:0:10", true},
		{"10.100.0.10", "10.100.0.11", false},
		{"10.100.0.10", "", false},
		{"Service.Example.com", "service.example.com", true},
		{"service.example.com", "other.example.com", false},
	} {
		if got := sameProbeHost(tc.target, tc.host); got != tc.want {
			t.Errorf("sameProbeHost(%q, %q) = %v, want %v", tc.target, tc.host, got, tc.want)
		}
	}
}

// The reported case. The valid plan fixture with a probe changed to
// the qga_ping alias running `printf ...` passed a direct Validate, because the
// allowlist was applied only to the canonical name, and the dispatcher then
// sent /bin/sh -c to the guest. Now both spellings are held to it, and the
// alias is held to everything its canonical type is.
func TestQGAPingAliasIsHeldToTheCommandAllowlist(t *testing.T) {
	data, err := os.ReadFile("../../testdata/plans/valid_plan.yaml")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := LoadFromReader(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("the known-valid plan does not load: %v", err)
	}
	probe := &plan.Tiers[0].VMs[0].Probes[0]
	probe.Type = "qga_ping"
	probe.Command = "printf audit-qga-alias-marker"
	probe.ExpectedOutput = "audit-qga-alias-marker"
	probe.RequireQGA = true
	probe.TimeoutSec = 2
	probe.Description = "audit alias validation boundary"

	for name, validate := range map[string]func(*Plan) []ValidationError{"Validate": Validate, "ValidateForWorker": ValidateForWorker} {
		found := false
		for _, err := range validate(plan) {
			found = found || (err.Field == "tiers[0].vms[0].probes[0].command" && strings.Contains(err.Message, "arbitrary guest shell commands are not permitted"))
		}
		if !found {
			t.Errorf("%s accepts a qga_ping probe running printf: %v", name, validate(plan))
		}
	}
	if errs := ProbeCommandErrors(plan); len(errs) != 1 || errs[0].Field != "tiers[0].vms[0].probes[0].command" {
		t.Errorf("ProbeCommandErrors = %v, want the one command", errs)
	}
	// The loader path, which normalises first, was always protected.
	if _, err := LoadFromReader(strings.NewReader(planText(t, plan))); err == nil || !strings.Contains(err.Error()+validationText(err), "arbitrary guest shell commands are not permitted") {
		t.Errorf("the loader accepts it: %v", err)
	}
}

// Every alias is validated as its canonical type does. For each
// spelling of each type, and commands good and bad, a direct Validate (no
// Normalize) gives the errors Validate of the normalised copy gives.
func TestEveryProbeAliasValidatesAsItsCanonicalType(t *testing.T) {
	commands := []string{"", "ping", "guest-ping", "hostname", "printf x", "rm -rf /", "systemctl is-active ssh", "systemctl is-active ssh; id", "sc query W3SVC", "sc query W3SVC & whoami", " id "}
	for alias, canonical := range probeTypeAliases {
		base := baseProbes()[canonical]
		base.Type = alias
		for _, command := range commands {
			for _, require := range []bool{false, true} {
				probe := base
				probe.Command, probe.RequireQGA = command, require
				if canonical != "qga" {
					if command != "" {
						continue // a command is not read by this type: covered by the field matrix
					}
					probe.Command = ""
				}
				if canonical == "qga" {
					probe.Description = "qga probe"
				}
				direct := probePlan(probe)
				normalised := probePlan(probe)
				normalised.Normalize()
				if got, want := errorText(Validate(direct)), errorText(Validate(normalised)); !reflect.DeepEqual(got, want) {
					t.Errorf("%s with command %q (require_qga %v):\n  direct Validate:     %v\n  after Normalize:     %v", alias, command, require, got, want)
				}
			}
		}
	}
}

func errorText(errs []ValidationError) []string {
	var text []string
	for _, err := range errs {
		text = append(text, err.Error())
	}
	sort.Strings(text)
	return text
}

// The same allowlist holds for a plan that never went through the
// loader, for either spelling.
func TestProbeCommandErrorsCoversBothQGASpellings(t *testing.T) {
	for _, tc := range []struct {
		kind, command string
		refused       bool
	}{
		{"qga", "ping", false}, {"qga_ping", "ping", false}, {"qga_ping", "", false},
		{"qga", "printf x", true}, {"qga_ping", "printf x", true}, {"qga", "", true},
		{"tcp", "printf x", false}, // not a guest command: the field matrix refuses it
	} {
		p := probePlan(Probe{Type: tc.kind, Command: tc.command, TimeoutSec: 5, Description: "x"})
		if got := len(ProbeCommandErrors(p)) > 0; got != tc.refused {
			t.Errorf("ProbeCommandErrors for %s running %q: refused = %v, want %v", tc.kind, tc.command, got, tc.refused)
		}
	}
}

// The reference carries the table of fields by probe type, generated
// from the list the validation reads; a field added to one and not the other
// fails here.
func TestTheReferenceListsTheFieldsEachProbeTypeReads(t *testing.T) {
	data, err := os.ReadFile("../../docs/plan-reference.md")
	if err != nil {
		t.Fatal(err)
	}
	if want := probeFieldsByType(); !strings.Contains(string(data), want) {
		t.Fatalf("docs/plan-reference.md lacks the table of fields by probe type; it must contain, verbatim:\n\n%s", want)
	}
}

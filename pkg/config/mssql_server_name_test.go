// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"strings"
	"testing"
)

// An mssql probe may name the server whose certificate it verifies. Both
// loaders accept a valid DNS name and keep it, so the worker's prober gets what
// the plan wrote.
func TestAnMSSQLProbeMayCarryAServerName(t *testing.T) {
	probe := baseProbes()["mssql"]
	probe.ServerName = "sql.example.com"
	p := probePlan(probe)
	if errs := Validate(p); len(errs) != 0 {
		t.Fatalf("an mssql probe with a server_name does not validate: %v", errs)
	}
	text := planText(t, p)
	if !strings.Contains(text, "server_name: sql.example.com") {
		t.Fatalf("the plan text does not carry server_name:\n%s", text)
	}
	loaded, err := loadText(t, text)
	if err != nil {
		t.Fatalf("both loaders refuse an mssql probe with a server_name: %v", err)
	}
	if got := loaded.Tiers[0].VMs[0].Probes[0]; got.Type != "mssql" || got.ServerName != "sql.example.com" {
		t.Fatalf("the loaded probe is %+v", got)
	}
}

// The name rule is the http probe's: a DNS name, as a TLS server name.
func TestAnMSSQLServerNameMustBeAValidDNSName(t *testing.T) {
	for _, name := range []string{"sql example.com", "sql_example.com", "-sql.example.com", "sql-.example.com", "sql..example.com", "sql.example.com.", "sql.example.com:1433", "sql/example", strings.Repeat("a", 64) + ".example.com", strings.Repeat("a.", 127) + "a"} {
		for _, kind := range []string{"mssql", "http"} {
			probe := baseProbes()[kind]
			probe.ServerName = name
			p := probePlan(probe)
			errs := Validate(p)
			if !hasFieldError(errs, "tiers[0].vms[0].probes[0].server_name") {
				t.Errorf("a %s probe with server_name %q validates: %v", kind, name, errs)
				continue
			}
			for _, err := range errs {
				if err.Field == "tiers[0].vms[0].probes[0].server_name" && !strings.Contains(err.Message, "valid DNS hostname") {
					t.Errorf("the %s server_name error for %q is %q", kind, name, err.Message)
				}
			}
			if _, err := loadText(t, planText(t, p)); err == nil {
				t.Errorf("both loaders accept a %s probe with server_name %q", kind, name)
			}
		}
	}
}

// server_name is read by http and mssql probes only; every other type refuses
// it, and the refusal says which types read it.
func TestOnlyHTTPAndMSSQLProbesReadAServerName(t *testing.T) {
	for _, kind := range []string{"tcp", "dns", "ldap", "smb", "qga", "qmp", "screendump"} {
		probe := baseProbes()[kind]
		probe.ServerName = "sql.example.com"
		errs := Validate(probePlan(probe))
		found := false
		for _, err := range errs {
			if err.Field == "tiers[0].vms[0].probes[0].server_name" {
				found = true
				if !strings.Contains(err.Message, "only http and mssql probes use it") {
					t.Errorf("the %s refusal is %q", kind, err.Message)
				}
			}
		}
		if !found {
			t.Errorf("a %s probe with a server_name validates: %v", kind, errs)
		}
	}
}

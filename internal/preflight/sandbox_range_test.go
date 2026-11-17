// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

func rangePlan(cidr string) *config.Plan {
	return &config.Plan{Network: config.Network{IPRange: cidr}}
}

// A PBS server or PVE API inside the sandbox range is cut off from the node the
// moment the probe address is assigned (a PBS map then fails with "client error
// (Connect)"). The run refuses before anything starts.
func TestCheckSandboxRangeRefusesAServerInsideTheRange(t *testing.T) {
	hosts := map[string][]string{"pbs.example.test": {"198.51.100.20"}, "pve.example.test": {"10.60.71.5"}}
	lookup := func(_ context.Context, host string) ([]string, error) {
		if a, ok := hosts[host]; ok {
			return a, nil
		}
		return nil, errors.New("no such host")
	}
	for _, tc := range []struct {
		name, cidr, pveURL, repository, want string
	}{
		{"PBS address inside", "10.60.70.0/23", "https://192.0.2.10:8006", "certistack-ro@pbs!ro@10.60.71.162:8007:pbs-data", "the PBS server"},
		{"PVE address inside", "10.60.70.0/23", "https://10.60.70.40:8006/", "ro@pbs!t@198.51.100.20:pbs-data", "the PVE API"},
		{"PVE name resolving inside", "10.60.70.0/23", "https://pve.example.test:8006", "", "the PVE API"},
		{"both outside", "10.60.70.0/23", "https://192.0.2.10:8006", "u@pbs!t@198.51.100.20:8007:store", ""},
		{"PBS name outside", "10.60.70.0/23", "https://192.0.2.10:8006", "u@pbs!t@pbs.example.test:store", ""},
		{"local datastore", "10.60.70.0/23", "", "store", ""},
		{"nothing known", "10.60.70.0/23", "", "", ""},
		{"IPv6 PBS outside", "10.60.70.0/23", "", "u@pbs!t@[2001:db8::1]:8007:store", ""},
		{"unresolvable name is not a finding", "10.60.70.0/23", "https://unknown.example.test", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSandboxRange(context.Background(), rangePlan(tc.cidr), tc.pveURL, tc.repository, lookup)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("error = %v, want none", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
	if err := CheckSandboxRange(context.Background(), nil, "https://10.60.70.40:8006", "", lookup); err != nil {
		t.Fatalf("a nil plan is not this check's business: %v", err)
	}
}

// By address only: a literal inside the range is refused, a name is left to the
// node, and a name that is localhost-like or unresolvable is not looked up.
func TestCheckSandboxRangeByAddressDoesNotResolveNames(t *testing.T) {
	plan := rangePlan("10.60.70.0/23")
	if err := CheckSandboxRangeByAddress(context.Background(), plan, "https://10.60.70.40:8006", ""); err == nil || !strings.Contains(err.Error(), "the PVE API") {
		t.Errorf("PVE API address inside: %v", err)
	}
	if err := CheckSandboxRangeByAddress(context.Background(), plan, "", "u@pbs!t@10.60.71.162:8007:store"); err == nil || !strings.Contains(err.Error(), "the PBS server") {
		t.Errorf("PBS server address inside: %v", err)
	}
	for _, host := range []string{"localhost", "pve.example.test", "pbs.invalid"} {
		if err := CheckSandboxRangeByAddress(context.Background(), plan, "https://"+host+":8006", "u@pbs!t@"+host+":store"); err != nil {
			t.Errorf("name %s: %v", host, err)
		}
	}
	if err := CheckSandboxRangeByAddress(context.Background(), nil, "https://10.60.70.40:8006", ""); err != nil {
		t.Errorf("nil plan: %v", err)
	}
}

// A server named by its address is listed once, not as "(10.42.71.172,
// 10.42.71.172)". A server named by a host name shows the name and the address
// it resolved to.
func TestCheckSandboxRangeListsAnAddressOnce(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]string, error) {
		if host == "pve.example.test" {
			return []string{"10.60.71.5", "10.60.71.6"}, nil
		}
		return nil, errors.New("no such host")
	}
	for _, tc := range []struct {
		name, pveURL, repository string
		want                     string
	}{
		{"PVE by address", "https://10.60.71.172:8006", "", "contains the PVE API (10.60.71.172). Once"},
		{"PBS by address", "https://192.0.2.10:8006", "u@pbs!t@10.60.71.162:8007:store", "contains the PBS server (10.60.71.162). Once"},
		{"PVE by name", "https://pve.example.test:8006", "", "contains the PVE API (pve.example.test, 10.60.71.5). Once"},
	} {
		err := CheckSandboxRange(context.Background(), rangePlan("10.60.70.0/23"), tc.pveURL, tc.repository, lookup)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want it to contain %q", tc.name, err, tc.want)
			continue
		}
		if strings.Contains(err.Error(), "10.60.71.172, 10.60.71.172") || strings.Contains(err.Error(), "10.60.71.162, 10.60.71.162") {
			t.Errorf("%s: the address is listed twice: %v", tc.name, err)
		}
	}
}

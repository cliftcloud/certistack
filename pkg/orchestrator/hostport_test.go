// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// `certistack plan` shows an IPv6 probe target the way the prober
// dials it, with the address in brackets.
func TestPlanProbeDetailBracketsAnIPv6Target(t *testing.T) {
	for _, tc := range []struct {
		probe config.Probe
		want  string
	}{
		{config.Probe{Type: "tcp", TargetIP: "192.0.2.10", Port: 22, TimeoutSec: 30}, "192.0.2.10:22"},
		{config.Probe{Type: "tcp", TargetIP: "fd00:99::10", Port: 22, TimeoutSec: 30}, "[fd00:99::10]:22"},
		{config.Probe{Type: "ldap", TargetIP: "fd00:99::20", Port: 389, TimeoutSec: 30}, "[fd00:99::20]:389"},
	} {
		if detail := probeDetail(tc.probe); !strings.Contains(detail, tc.want) || strings.Contains(detail, "::10:22") || strings.Contains(detail, "::20:389") {
			t.Errorf("probeDetail(%s %s) = %q, want %q", tc.probe.Type, tc.probe.TargetIP, detail, tc.want)
		}
	}
}

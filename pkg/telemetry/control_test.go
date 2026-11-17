// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import "testing"

func envOf(pairs ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return func(k string) string { return m[k] }
}

// Strongest first: DO_NOT_TRACK, then CERTISTACK_TELEMETRY off, then on. An
// unrecognised value never turns anything on.
func TestEnvControlPrecedenceMatrix(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		want Control
	}{
		{"nothing set", nil, ControlNone},
		{"DO_NOT_TRACK=1", []string{"DO_NOT_TRACK", "1"}, ControlOff},
		{"DO_NOT_TRACK=true", []string{"DO_NOT_TRACK", "true"}, ControlOff},
		{"DO_NOT_TRACK=yes", []string{"DO_NOT_TRACK", "yes"}, ControlOff},
		{"DO_NOT_TRACK=anything else", []string{"DO_NOT_TRACK", "please"}, ControlOff},
		{"DO_NOT_TRACK=0 is no preference", []string{"DO_NOT_TRACK", "0"}, ControlNone},
		{"DO_NOT_TRACK=false is no preference", []string{"DO_NOT_TRACK", "false"}, ControlNone},
		{"DO_NOT_TRACK empty", []string{"DO_NOT_TRACK", ""}, ControlNone},
		{"DO_NOT_TRACK beats CERTISTACK_TELEMETRY=1", []string{"DO_NOT_TRACK", "1", "CERTISTACK_TELEMETRY", "1"}, ControlOff},
		{"DO_NOT_TRACK beats CERTISTACK_TELEMETRY=on", []string{"DO_NOT_TRACK", "1", "CERTISTACK_TELEMETRY", "on"}, ControlOff},
		{"DO_NOT_TRACK=0 lets CERTISTACK_TELEMETRY=1 through", []string{"DO_NOT_TRACK", "0", "CERTISTACK_TELEMETRY", "1"}, ControlOn},
		{"CERTISTACK_TELEMETRY=0", []string{"CERTISTACK_TELEMETRY", "0"}, ControlOff},
		{"CERTISTACK_TELEMETRY=off", []string{"CERTISTACK_TELEMETRY", "off"}, ControlOff},
		{"CERTISTACK_TELEMETRY=OFF", []string{"CERTISTACK_TELEMETRY", "OFF"}, ControlOff},
		{"CERTISTACK_TELEMETRY=false", []string{"CERTISTACK_TELEMETRY", "false"}, ControlOff},
		{"CERTISTACK_TELEMETRY=no", []string{"CERTISTACK_TELEMETRY", "No"}, ControlOff},
		{"CERTISTACK_TELEMETRY=1", []string{"CERTISTACK_TELEMETRY", "1"}, ControlOn},
		{"CERTISTACK_TELEMETRY=on", []string{"CERTISTACK_TELEMETRY", "on"}, ControlOn},
		{"CERTISTACK_TELEMETRY=TRUE", []string{"CERTISTACK_TELEMETRY", "TRUE"}, ControlOn},
		{"CERTISTACK_TELEMETRY=yes", []string{"CERTISTACK_TELEMETRY", "yes"}, ControlOn},
		{"CERTISTACK_TELEMETRY padded", []string{"CERTISTACK_TELEMETRY", " yes "}, ControlOn},
		{"CERTISTACK_TELEMETRY empty", []string{"CERTISTACK_TELEMETRY", ""}, ControlNone},
		{"CERTISTACK_TELEMETRY garbage fails closed", []string{"CERTISTACK_TELEMETRY", "maybe"}, ControlOff},
		{"CERTISTACK_TELEMETRY=2 fails closed", []string{"CERTISTACK_TELEMETRY", "2"}, ControlOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := EnvControl(envOf(tc.env...))
			if got != tc.want {
				t.Fatalf("EnvControl = %v, want %v", got, tc.want)
			}
			if (got == ControlNone) != (reason == "") {
				t.Fatalf("reason %q does not match control %v", reason, got)
			}
		})
	}
}

func TestBusinessEnvironmentOnlyCountsAnExplicitOne(t *testing.T) {
	for value, want := range map[string]bool{"1": true, "true": true, "yes": true, "on": true, "0": false, "": false, "no": false, "maybe": false} {
		if got := EnvBusiness(envOf("CERTISTACK_TELEMETRY_BUSINESS", value)); got != want {
			t.Errorf("CERTISTACK_TELEMETRY_BUSINESS=%q -> %v, want %v", value, got, want)
		}
	}
}

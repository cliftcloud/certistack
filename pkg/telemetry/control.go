// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import "strings"

// Environment variables the report honors.
const (
	// VarDoNotTrack is the console do-not-track convention (DO_NOT_TRACK=1).
	VarDoNotTrack = "DO_NOT_TRACK"
	// VarTelemetry turns the report off (0, off, false, no) or on (1, on, true,
	// yes) without storing an answer: the install is kept in the state file.
	VarTelemetry = "CERTISTACK_TELEMETRY"
	// VarBusiness is the business_use answer for a run enabled by
	// VarTelemetry, which stores no answers.
	VarBusiness = "CERTISTACK_TELEMETRY_BUSINESS"
	// VarURL replaces the endpoint: https, or http for a loopback host.
	VarURL = "CERTISTACK_TELEMETRY_URL"
)

// Control is what the environment says, strongest source first.
type Control int

const (
	// ControlNone: the environment says nothing; the stored answer decides.
	ControlNone Control = iota
	// ControlOff: forced off, whatever the stored answer.
	ControlOff
	// ControlOn: on, with no answer stored (the install is kept, if it can be).
	ControlOn
)

func (c Control) String() string {
	switch c {
	case ControlOff:
		return "off"
	case ControlOn:
		return "on"
	}
	return "none"
}

func isFalse(v string) bool {
	switch v {
	case "0", "off", "false", "no":
		return true
	}
	return false
}

func isTrue(v string) bool {
	switch v {
	case "1", "on", "true", "yes":
		return true
	}
	return false
}

func envValue(getenv func(string) string, name string) string {
	return strings.ToLower(strings.TrimSpace(getenv(name)))
}

// EnvControl reads the environment: DO_NOT_TRACK forces off (any value but a
// plain no), then CERTISTACK_TELEMETRY off, then CERTISTACK_TELEMETRY on. A
// value it does not recognize fails closed, to off. The reason is "" only for
// ControlNone.
func EnvControl(getenv func(string) string) (Control, string) {
	if dnt := envValue(getenv, VarDoNotTrack); dnt != "" && !isFalse(dnt) {
		return ControlOff, VarDoNotTrack + " is set"
	}
	switch value := envValue(getenv, VarTelemetry); {
	case value == "":
		return ControlNone, ""
	case isFalse(value):
		return ControlOff, VarTelemetry + "=" + value
	case isTrue(value):
		return ControlOn, VarTelemetry + "=" + value
	default:
		return ControlOff, VarTelemetry + " has a value that is not recognized, so it counts as off"
	}
}

// EnvBusiness is the business_use answer of a process the environment enabled:
// true only for an explicit yes in CERTISTACK_TELEMETRY_BUSINESS.
func EnvBusiness(getenv func(string) string) bool {
	return isTrue(envValue(getenv, VarBusiness))
}

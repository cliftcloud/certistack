// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"fmt"
	"strings"
)

// probeTypes are the canonical probe types, in the order the reference lists
// them. probeTypeAliases are the other spellings a plan may use.
var probeTypes = []string{"tcp", "http", "dns", "ldap", "mssql", "smb", "qga", "qmp", "screendump"}

var probeTypeAliases = map[string]string{
	"tcp_handshake": "tcp",
	"http_get":      "http",
	"qga_ping":      "qga",
	"qmp_status":    "qmp",
}

// canonicalProbeType is the type a probe of this name runs as: an alias stands
// for its canonical type, and any other name is its own (an unknown type is
// reported where it is checked).
func canonicalProbeType(name string) string {
	if canonical, ok := probeTypeAliases[name]; ok {
		return canonical
	}
	return name
}

// validProbeType reports whether name is a probe type or one of its aliases.
func validProbeType(name string) bool {
	if _, ok := probeTypeAliases[name]; ok {
		return true
	}
	for _, t := range probeTypes {
		if t == name {
			return true
		}
	}
	return false
}

// canonicalProbe is p as a run sees it once its type alias is resolved: the
// canonical type, and for qga_ping the ping command it defaults to. Normalize
// applies it, and validate applies it to a probe it was handed without
// Normalize, so an alias is never checked less strictly than its type.
func canonicalProbe(p Probe) Probe {
	if p.Type == "qga_ping" && p.Command == "" {
		p.Command = "ping"
	}
	p.Type = canonicalProbeType(p.Type)
	return p
}

// probeField is one probe field that only some probe types read, with the
// types that read it. Every other field (type, timeout_sec, retries,
// description) belongs to all of them.
type probeField struct {
	key   string
	types []string
	set   func(Probe) bool
}

var wireTypes = []string{"tcp", "http", "dns", "ldap", "mssql", "smb"}

// probeFields is the one record of which probe types read which field. The
// dispatcher (pkg/orchestrator runProbes) builds each prober from exactly
// these fields, so a field set on any other type is never looked at: validate
// refuses it, and the reference's table of fields by probe type is checked
// against this list.
//
// tls_skip_verify and insecure_skip_verify are not listed: no type may carry
// a true one. A dns probe reads path only as the domain it is given when
// domain is left out.
var probeFields = []probeField{
	{"target_ip", wireTypes, func(p Probe) bool { return p.TargetIP != "" }},
	{"port", wireTypes, func(p Probe) bool { return p.Port != 0 }},
	{"url", []string{"http"}, func(p Probe) bool { return p.URL != "" }},
	{"path", []string{"http", "dns"}, func(p Probe) bool { return p.Path != "" }},
	{"tls", []string{"http"}, func(p Probe) bool { return p.TLS }},
	{"server_name", []string{"http", "mssql"}, func(p Probe) bool { return p.ServerName != "" }},
	{"expected_status", []string{"http"}, func(p Probe) bool { return p.ExpectedStatus != 0 }},
	{"domain", []string{"dns"}, func(p Probe) bool { return p.Domain != "" }},
	{"transport", []string{"dns"}, func(p Probe) bool { return p.Transport != "" }},
	{"record_type", []string{"dns"}, func(p Probe) bool { return p.RecordType != "" }},
	{"base_dn", []string{"ldap"}, func(p Probe) bool { return p.BaseDN != "" }},
	{"naming_context", []string{"ldap"}, func(p Probe) bool { return p.NamingContext != "" }},
	{"command", []string{"qga"}, func(p Probe) bool { return p.Command != "" }},
	{"expected_output", []string{"qga"}, func(p Probe) bool { return p.ExpectedOutput != "" }},
	{"require_qga", []string{"qga"}, func(p Probe) bool { return p.RequireQGA }},
}

func (f probeField) readBy(probeType string) bool {
	for _, t := range f.types {
		if t == probeType {
			return true
		}
	}
	return false
}

// unusedProbeFieldErrors refuses each field probe gives that its type does
// not read. probe must be canonical; a probe of an unknown type is reported
// on its own.
func unusedProbeFieldErrors(prefix string, probe Probe) []ValidationError {
	if !validProbeType(probe.Type) {
		return nil
	}
	var errors []ValidationError
	for _, field := range probeFields {
		if field.set(probe) && !field.readBy(probe.Type) {
			errors = append(errors, ValidationError{
				Field: prefix + "." + field.key,
				Message: fmt.Sprintf("is not read by a %s probe (only %s probes use it), so the plan would claim a check the run never makes; remove it",
					probe.Type, joinWords(field.types)),
			})
		}
	}
	return errors
}

// joinWords lists words as "a", "a and b", or "a, b and c".
func joinWords(words []string) string {
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

// probeFieldsByType renders, from probeFields, the fields each probe type reads
// besides type, timeout_sec, retries and description. A test holds the probe
// types table of docs/plan-reference.md to it.
func probeFieldsByType() string {
	var b strings.Builder
	b.WriteString("| Probe type | Fields it reads besides `type`, `timeout_sec`, `retries` and `description` |\n")
	b.WriteString("| :--- | :--- |\n")
	for _, t := range probeTypes {
		var keys []string
		for _, field := range probeFields {
			if field.readBy(t) {
				keys = append(keys, "`"+field.key+"`")
			}
		}
		cell := "none"
		if len(keys) > 0 {
			cell = strings.Join(keys, ", ")
		}
		fmt.Fprintf(&b, "| `%s` | %s |\n", t, cell)
	}
	return b.String()
}

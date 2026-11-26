// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import "fmt"

// A plan's free text (its name, a tier's name, a probe's description and
// expected output, the names it gives PBS) is printed by validate, plan, run
// and report show, and recorded in reports. A control character in it (an
// escape sequence, a carriage return, a NUL) or a bidirectional control would
// reach the terminal that prints it, where it can recolor, retitle or
// rewrite what the operator reads, so validate refuses it. A description and
// an expected output may run over lines: they may hold line feeds and tabs.

// planTextKeys are the free-text keys, as the schema's notes name them, and
// whether each may run over lines. textControlErrors checks each of them.
var planTextKeys = map[string]bool{
	"Plan.name": false, "Plan.environment": false, "Tier.name": false,
	"Storage.pbs_repository": false, "Storage.pbs_namespace": false, "SourcePBS.namespace": false,
	"Probe.description": true, "Probe.expected_output": true, "Probe.domain": false,
}

// textPattern is the schema pattern of a free-text key: no control
// character, and no line feed or tab unless the text may run over lines. It is
// an ECMA-262 expression, as a JSON Schema pattern is.
func textPattern(multiLine bool) string {
	controls := `\u0000-\u0008\u000a-\u001f`
	if multiLine {
		controls = `\u0000-\u0008\u000b-\u001f`
	} else {
		controls += `\u0009`
	}
	return `^[^` + controls + `\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]*$`
}

// textControlProblem is why text may not be printed as it is, or "".
// multiLine allows line feeds and tabs.
func textControlProblem(text string, multiLine bool) string {
	position := 0
	for _, r := range text {
		position++
		if multiLine && (r == '\n' || r == '\t') {
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiControl(r) || r == '\u2028' || r == '\u2029' {
			what := "a control character"
			if isBidiControl(r) {
				what = "a bidirectional control"
			}
			return fmt.Sprintf("holds %s (U+%04X) at character %d: plan text is printed to terminals and recorded in reports, so it may hold no escape sequence or other control character", what, r, position)
		}
	}
	return ""
}

// isBidiControl reports the Unicode bidirectional formatting characters,
// which reorder the text around them on display.
func isBidiControl(r rune) bool {
	return r == '\u061c' || r == '\u200e' || r == '\u200f' || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}

// textControlErrors are the free-text keys of p that textControlProblem
// refuses.
func textControlErrors(p *Plan) []ValidationError {
	var errors []ValidationError
	check := func(field, text string, multiLine bool) {
		if problem := textControlProblem(text, multiLine); problem != "" {
			errors = append(errors, ValidationError{Field: field, Message: problem})
		}
	}
	check("name", p.Name, false)
	check("environment", p.Environment, false)
	check("storage.pbs_repository", p.Storage.PBSRepository, false)
	check("storage.pbs_namespace", p.Storage.PBSNamespace, false)
	for i, tier := range p.Tiers {
		tierPath := fmt.Sprintf("tiers[%d]", i)
		check(tierPath+".name", tier.Name, false)
		for j, vm := range tier.VMs {
			vmPath := fmt.Sprintf("%s.vms[%d]", tierPath, j)
			check(vmPath+".source_pbs.namespace", vm.SourcePBS.Namespace, false)
			for k, probe := range vm.Probes {
				probePath := fmt.Sprintf("%s.probes[%d]", vmPath, k)
				check(probePath+".description", probe.Description, true)
				check(probePath+".expected_output", probe.ExpectedOutput, true)
				check(probePath+".domain", probe.Domain, false)
			}
		}
	}
	return errors
}

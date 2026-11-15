// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// An int key of a plan takes a whole number. The YAML decoder would take a
// decimal into one and cut it (2555.9 becomes 2555), so a plan that says
// "retention_days: 2555.9" or "boot_timeout_sec: 0.5" would run with a value
// the author did not write. A number written with a fraction or an exponent is
// accepted when it is whole (2555.0, 2.555e3: the decoder reads them as 2555
// exactly, and a JSON Schema calls them integers too), and refused when it is
// not, in any int key at any depth: the plan's blocks, the tiers, their VMs
// and the VMs' probes, drives and hardware overrides.

// planField is one key of a plan section and the Go type its value decodes into.
type planField struct {
	key string
	typ reflect.Type
}

// planFields are the keys each plan struct decodes, by the same yaml tags the
// decoder reads (planSections names them for the unknown-key errors).
var planFields = func() map[reflect.Type][]planField {
	fields := map[reflect.Type][]planField{}
	collectPlanFields(reflect.TypeOf(Plan{}), fields)
	return fields
}()

func collectPlanFields(t reflect.Type, fields map[reflect.Type][]planField) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	if _, seen := fields[t]; seen {
		return
	}
	fields[t] = nil
	var list []planField
	var add func(reflect.Type)
	add = func(st reflect.Type) {
		for i := 0; i < st.NumField(); i++ {
			field := st.Field(i)
			if !field.IsExported() {
				continue
			}
			name, options, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			if name == "-" {
				continue
			}
			if strings.Contains(options, "inline") {
				add(field.Type)
				continue
			}
			if name == "" {
				name = strings.ToLower(field.Name)
			}
			list = append(list, planField{key: name, typ: field.Type})
			collectPlanFields(field.Type, fields)
		}
	}
	add(t)
	fields[t] = list
}

// wholeNumberProblem is one int key whose value is not a whole number.
type wholeNumberProblem struct {
	line  int
	path  string
	value string
	// unquoted is set for a number or a true or false written unquoted in a
	// key that takes text of a form (a pattern), instead of a fraction.
	unquoted bool
}

// wholeNumberError is nil when every int key of the plan holds a whole number,
// else one error that names each offender by its line, its path in the plan
// (tiers[0].vms[1].probes[0].timeout_sec) and the value as written, in the
// order they appear in the file. The decoder has already accepted the document.
func wholeNumberError(document *yaml.Node) error {
	if document == nil || len(document.Content) == 0 {
		return nil
	}
	walk := wholeNumberWalk{budget: maxPresenceNodes}
	if err := walk.visit(document.Content[0], reflect.TypeOf(Plan{}), ""); err != nil {
		return err
	}
	if len(walk.problems) == 0 {
		return nil
	}
	sort.SliceStable(walk.problems, func(i, j int) bool { return walk.problems[i].line < walk.problems[j].line })
	lines := make([]string, len(walk.problems))
	for i, problem := range walk.problems {
		lines[i] = fmt.Sprintf("line %d: %s must be a whole number, not %s", problem.line, problem.path, problem.value)
		if problem.unquoted {
			key := problem.path[strings.LastIndex(problem.path, ".")+1:]
			lines[i] = fmt.Sprintf("line %d: %s takes text, and %s is written as a number or true or false: quote it (%s: \"%s\")", problem.line, problem.path, problem.value, key, problem.value)
		}
	}
	return fmt.Errorf("invalid plan:\n  %s", strings.Join(lines, "\n  "))
}

type wholeNumberWalk struct {
	budget   int
	problems []wholeNumberProblem
}

func (w *wholeNumberWalk) visit(node *yaml.Node, t reflect.Type, path string) error {
	for node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	if w.budget--; w.budget < 0 {
		return fmt.Errorf("plan has too many YAML nodes to check its numbers")
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if node.Kind == yaml.ScalarNode && !wholeNumber(node) {
			w.problems = append(w.problems, wholeNumberProblem{line: node.Line, path: path, value: node.Value})
		}
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			return nil
		}
		values := make(map[string]*yaml.Node)
		if err := mappingValues(node, values, 0); err != nil {
			if path == "" {
				return err
			}
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, field := range planFields[t] {
			value, given := values[field.key]
			if !given {
				continue
			}
			child := field.key
			if path != "" {
				child = path + "." + field.key
			}
			if field.typ.Kind() == reflect.String && quotedTextKeys[t.Name()+"."+field.key] && unquotedScalar(value) {
				w.problems = append(w.problems, wholeNumberProblem{line: value.Line, path: child, value: value.Value, unquoted: true})
				continue
			}
			if err := w.visit(value, field.typ, child); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if node.Kind != yaml.SequenceNode {
			return nil
		}
		for i, item := range node.Content {
			if err := w.visit(item, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// wholeNumber reports whether a scalar the decoder takes into an int key is a
// whole number. Only a scalar the decoder reads as a float can be anything
// else: it is whole when its text, exactly (not as the nearest float64), has no
// fractional part, which is what keeps "2555.0000000000000001" from passing as
// 2555. .inf, -.inf and .nan are not whole.
func wholeNumber(node *yaml.Node) bool {
	var value any
	if err := node.Decode(&value); err != nil {
		return true // the decoder has accepted this node, so it cannot be the one that fails here
	}
	number, isFloat := value.(float64)
	if !isFloat {
		return true
	}
	if math.IsNaN(number) || math.IsInf(number, 0) || number != math.Trunc(number) {
		return false
	}
	exact, ok := new(big.Rat).SetString(strings.ReplaceAll(node.Value, "_", ""))
	return !ok || exact.IsInt()
}

// quotedTextKeys are the text keys whose value has a form the schema states as
// a pattern (plan_id, a VM's name and MAC, a snapshot, a disk slot...). A
// JSON Schema pattern cannot judge the text of a number, so these keys take
// text only, in the loader as in the schema: 2026 or true written unquoted is
// refused, with the quoted form to write instead.
var quotedTextKeys = func() map[string]bool {
	keys := map[string]bool{}
	for entry, note := range planSchemaNotes {
		if note.Pattern != "" {
			keys[entry] = true
		}
	}
	return keys
}()

// unquotedScalar reports a scalar the YAML reads as a number or a boolean.
func unquotedScalar(node *yaml.Node) bool {
	for node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	if node.Kind != yaml.ScalarNode {
		return false
	}
	switch node.ShortTag() {
	case "!!int", "!!float", "!!bool":
		return true
	}
	return false
}

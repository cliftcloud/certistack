// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// schemaValidator checks a decoded YAML document against a JSON Schema. It is
// a test helper: the product has no JSON Schema library, and the schema
// PlanSchema writes uses a small part of the vocabulary, which this implements
// (and which TestSchemaValidatorRejectsWhatItShould holds to account, so a gap
// here cannot make the schema tests pass vacuously). A keyword it does not know
// is an error, not a pass.
type schemaValidator struct {
	root map[string]any
}

var knownSchemaKeywords = map[string]bool{
	"$schema": true, "$defs": true, "$ref": true, "title": true, "description": true, "deprecated": true, "default": true, "examples": true,
	"type": true, "enum": true, "const": true, "pattern": true, "maxLength": true, "minLength": true,
	"minimum": true, "maximum": true, "exclusiveMinimum": true, "exclusiveMaximum": true,
	"properties": true, "required": true, "additionalProperties": true, "items": true, "minItems": true,
	"allOf": true, "anyOf": true, "not": true, "if": true, "then": true, "else": true,
}

// check returns every violation of schema by value, each with the path it is at.
func (v schemaValidator) check(schema any, value any, path string) []string {
	switch s := schema.(type) {
	case bool:
		if s {
			return nil
		}
		return []string{fmt.Sprintf("%s: this is not allowed", display(path))}
	case map[string]any:
		return v.checkObject(s, value, path)
	}
	return []string{fmt.Sprintf("%s: the schema %v is neither a boolean nor an object", display(path), schema)}
}

func display(path string) string {
	if path == "" {
		return "(the plan)"
	}
	return path
}

func (v schemaValidator) checkObject(schema map[string]any, value any, path string) []string {
	var problems []string
	fail := func(format string, args ...any) {
		problems = append(problems, display(path)+": "+fmt.Sprintf(format, args...))
	}
	for keyword := range schema {
		if !knownSchemaKeywords[keyword] {
			fail("the schema uses the keyword %q, which the test validator does not implement", keyword)
		}
	}
	if ref, ok := schema["$ref"].(string); ok {
		name, found := strings.CutPrefix(ref, "#/$defs/")
		target, defined := map[string]any(nil), false
		if found {
			defs, _ := v.root["$defs"].(map[string]any)
			target, defined = defs[name].(map[string]any)
		}
		if !defined {
			fail("the reference %q does not resolve", ref)
		} else {
			problems = append(problems, v.checkObject(target, value, path)...)
		}
	}
	if kinds := stringList(schema["type"]); len(kinds) > 0 || schema["type"] != nil {
		if kind, ok := schema["type"].(string); ok {
			kinds = []string{kind}
		}
		matched := false
		for _, kind := range kinds {
			matched = matched || hasType(kind, value)
		}
		if !matched {
			fail("must be %s, not %s", strings.Join(kinds, " or "), describeValue(value))
			return problems // the keywords below assume the type
		}
	}
	if enum, ok := schema["enum"].([]any); ok && !containsValue(enum, value) {
		fail("%s is not one of %v", describeValue(value), enum)
	}
	if enum, ok := schema["enum"].([]string); ok {
		options := make([]any, len(enum))
		for index, option := range enum {
			options[index] = option
		}
		if !containsValue(options, value) {
			fail("%s is not one of %v", describeValue(value), enum)
		}
	}
	if constant, ok := schema["const"]; ok && !sameValue(constant, value) {
		fail("must be %v", constant)
	}
	switch typed := value.(type) {
	case string:
		if pattern, ok := schema["pattern"].(string); ok && !ecmaPattern(pattern).MatchString(typed) {
			fail("%q does not match %s", typed, pattern)
		}
		if limit, ok := toInt(schema["maxLength"]); ok && utf8.RuneCountInString(typed) > limit {
			fail("is longer than %d characters", limit)
		}
		if limit, ok := toInt(schema["minLength"]); ok && utf8.RuneCountInString(typed) < limit {
			fail("is shorter than %d characters", limit)
		}
	case int, int64, float64:
		number := toFloat(typed)
		for keyword, violated := range map[string]func(limit float64) bool{
			"minimum":          func(limit float64) bool { return number < limit },
			"maximum":          func(limit float64) bool { return number > limit },
			"exclusiveMinimum": func(limit float64) bool { return number <= limit },
			"exclusiveMaximum": func(limit float64) bool { return number >= limit },
		} {
			if limit, ok := schema[keyword]; ok && violated(toFloat(limit)) {
				fail("%v violates %s %v", typed, keyword, limit)
			}
		}
	case []any:
		if limit, ok := toInt(schema["minItems"]); ok && len(typed) < limit {
			fail("has %d item(s), fewer than %d", len(typed), limit)
		}
		if items, ok := schema["items"]; ok {
			for index, item := range typed {
				problems = append(problems, v.check(items, item, fmt.Sprintf("%s[%d]", path, index))...)
			}
		}
	case map[string]any:
		properties, _ := schema["properties"].(map[string]any)
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := key
			if path != "" {
				child = path + "." + key
			}
			if property, known := properties[key]; known {
				problems = append(problems, v.check(property, typed[key], child)...)
			} else if additional, present := schema["additionalProperties"]; present {
				problems = append(problems, v.check(additional, typed[key], child)...)
			}
		}
		for _, name := range stringList(schema["required"]) {
			if _, present := typed[name]; !present {
				fail("the key %q is required", name)
			}
		}
	}
	for _, sub := range anyList(schema["allOf"]) {
		problems = append(problems, v.check(sub, value, path)...)
	}
	if options := anyList(schema["anyOf"]); len(options) > 0 {
		satisfied := false
		for _, option := range options {
			if len(v.check(option, value, path)) == 0 {
				satisfied = true
				break
			}
		}
		if !satisfied {
			fail("matches none of the %d alternatives of anyOf", len(options))
		}
	}
	if forbidden, ok := schema["not"]; ok && len(v.check(forbidden, value, path)) == 0 {
		fail("is %s, which this key does not allow", describeValue(value))
	}
	if condition, ok := schema["if"]; ok {
		if len(v.check(condition, value, path)) == 0 {
			if then, ok := schema["then"]; ok {
				problems = append(problems, v.check(then, value, path)...)
			}
		} else if otherwise, ok := schema["else"]; ok {
			problems = append(problems, v.check(otherwise, value, path)...)
		}
	}
	return problems
}

// toInt reads a count out of a schema that was decoded from JSON (a float64)
// or built in code (an int).
func toInt(value any) (int, bool) {
	switch number := value.(type) {
	case int:
		return number, true
	case float64:
		return int(number), number == math.Trunc(number)
	}
	return 0, false
}

func anyList(value any) []any {
	switch list := value.(type) {
	case []any:
		return list
	case []map[string]any:
		out := make([]any, len(list))
		for index, item := range list {
			out[index] = item
		}
		return out
	}
	return nil
}

func stringList(value any) []string {
	switch list := value.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, len(list))
		for index, item := range list {
			out[index], _ = item.(string)
		}
		return out
	}
	return nil
}

func hasType(kind string, value any) bool {
	switch kind {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "integer":
		switch number := value.(type) {
		case int, int64:
			return true
		case float64:
			return number == math.Trunc(number)
		}
	case "number":
		switch value.(type) {
		case int, int64, float64:
			return true
		}
	case "null":
		return value == nil
	}
	return false
}

func describeValue(value any) string {
	if value == nil {
		return "null"
	}
	return fmt.Sprintf("%v (%T)", value, value)
}

func toFloat(value any) float64 {
	switch number := value.(type) {
	case int:
		return float64(number)
	case int64:
		return float64(number)
	case float64:
		return number
	}
	panic(fmt.Sprintf("not a number: %v", value))
}

func isNumber(value any) bool {
	switch value.(type) {
	case int, int64, float64:
		return true
	}
	return false
}

// sameValue is JSON equality: numbers by value, other values deeply.
func sameValue(a, b any) bool {
	if isNumber(a) && isNumber(b) {
		return toFloat(a) == toFloat(b)
	}
	return reflect.DeepEqual(a, b)
}

func containsValue(options []any, value any) bool {
	for _, option := range options {
		if sameValue(option, value) {
			return true
		}
	}
	return false
}

// pathStep is one step of a plan path such as tiers[0].vms[0].probes[1].port.
type pathStep struct {
	key   string
	index int // -1 for a key
}

var pathStepPattern = regexp.MustCompile(`([^.\[\]]+)|\[([0-9]+)\]`)

func parsePath(path string) []pathStep {
	var steps []pathStep
	for _, match := range pathStepPattern.FindAllStringSubmatch(path, -1) {
		if match[1] != "" {
			steps = append(steps, pathStep{key: match[1], index: -1})
			continue
		}
		index, _ := strconv.Atoi(match[2])
		steps = append(steps, pathStep{index: index})
	}
	return steps
}

// getPath, setPath and deletePath read and change a decoded plan by path.
func getPath(document any, path string) (any, bool) {
	current := document
	for _, step := range parsePath(path) {
		if step.index >= 0 {
			list, ok := current.([]any)
			if !ok || step.index >= len(list) {
				return nil, false
			}
			current = list[step.index]
			continue
		}
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		if current, ok = object[step.key]; !ok {
			return nil, false
		}
	}
	return current, true
}

func setPath(document any, path string, value any) {
	steps := parsePath(path)
	parent, ok := getPath(document, joinSteps(steps[:len(steps)-1]))
	if !ok {
		panic(fmt.Sprintf("setPath %s: the parent does not exist", path))
	}
	last := steps[len(steps)-1]
	if last.index >= 0 {
		list := parent.([]any)
		if last.index == len(list) {
			panic("setPath cannot grow a list: append to it with the parent's key")
		}
		list[last.index] = value
		return
	}
	parent.(map[string]any)[last.key] = value
}

func deletePath(document any, path string) {
	steps := parsePath(path)
	parent, ok := getPath(document, joinSteps(steps[:len(steps)-1]))
	if !ok {
		return
	}
	if object, ok := parent.(map[string]any); ok {
		delete(object, steps[len(steps)-1].key)
	}
}

func joinSteps(steps []pathStep) string {
	var builder strings.Builder
	for _, step := range steps {
		if step.index >= 0 {
			fmt.Fprintf(&builder, "[%d]", step.index)
			continue
		}
		if builder.Len() > 0 {
			builder.WriteByte('.')
		}
		builder.WriteString(step.key)
	}
	return builder.String()
}

// ecmaWhiteSpace is what \s matches in a JSON Schema pattern, an ECMA-262
// expression: more than in Go's, which has no \v and no Unicode spaces.
const ecmaWhiteSpace = `[\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`

// ecmaPattern compiles a schema pattern as an editor reads it. The patterns
// the schema writes use \s only outside a character class.
func ecmaPattern(pattern string) *regexp.Regexp {
	pattern = ecmaCodeUnit.ReplaceAllString(pattern, `\x{$1}`)
	return regexp.MustCompile(strings.ReplaceAll(pattern, `\s`, ecmaWhiteSpace))
}

// ecmaCodeUnit is an ECMA-262 \uHHHH escape, which Go writes \x{HHHH}.
var ecmaCodeUnit = regexp.MustCompile(`\\u([0-9A-Fa-f]{4})`)

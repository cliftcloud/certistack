// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// planSection is one mapping in a plan: where it sits and the keys it
// accepts.
type planSection struct {
	path string
	keys []string
}

// planSections maps each struct a plan decodes into, by the Go type name
// yaml.v3 reports ("config.Tier"), to its place in the plan.
var planSections = func() map[string]planSection {
	sections := map[string]planSection{}
	collectPlanSections(reflect.TypeOf(Plan{}), "", sections)
	return sections
}()

func collectPlanSections(t reflect.Type, path string, sections map[string]planSection) {
	switch t.Kind() {
	case reflect.Pointer:
		collectPlanSections(t.Elem(), path, sections)
		return
	case reflect.Slice, reflect.Array:
		collectPlanSections(t.Elem(), path+"[]", sections)
		return
	case reflect.Map:
		collectPlanSections(t.Elem(), path+".*", sections)
		return
	case reflect.Struct:
	default:
		return
	}
	if _, seen := sections[t.String()]; seen {
		return
	}
	section := planSection{path: path}
	sections[t.String()] = section
	var addFields func(reflect.Type)
	addFields = func(st reflect.Type) {
		for i := 0; i < st.NumField(); i++ {
			field := st.Field(i)
			if !field.IsExported() {
				continue
			}
			name, opts, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			if name == "-" {
				continue
			}
			if strings.Contains(opts, "inline") {
				addFields(field.Type)
				continue
			}
			if name == "" {
				name = strings.ToLower(field.Name)
			}
			section.keys = append(section.keys, name)
			child := name
			if path != "" {
				child = path + "." + name
			}
			collectPlanSections(field.Type, child, sections)
		}
	}
	addFields(t)
	sort.Strings(section.keys)
	sections[t.String()] = section
}

var unknownFieldError = regexp.MustCompile(`^line (\d+): field (.+) not found in type (\S+)$`)

// planDecodeError explains a plan the YAML decoder rejected. yaml.v3 names
// an unknown key's Go type ("field grace not found in type config.Tier");
// the operator needs the plan section, the keys it accepts and the key they
// probably meant.
func planDecodeError(err error, data []byte) error {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) || len(typeErr.Errors) == 0 {
		return fmt.Errorf("failed to unmarshal yaml: %w", err)
	}
	lines := make([]string, 0, len(typeErr.Errors))
	for _, msg := range typeErr.Errors {
		if explained := explainScalarForList(msg, data); explained != "" {
			lines = append(lines, explained)
			continue
		}
		lines = append(lines, explainUnknownKey(msg))
	}
	return fmt.Errorf("invalid plan:\n  %s", strings.Join(lines, "\n  "))
}

// scalarForList is the decoder's refusal of a single value where the plan
// takes a list of strings ("frameworks: NONE").
var scalarForList = regexp.MustCompile(`^line (\d+): cannot unmarshal !!(?:str|int|float|bool) .* into \[\]string$`)

// explainScalarForList says, for a key written as one value where the plan
// takes a list, that it is a list and how to write it: "frameworks is a list:
// write [NONE]". It returns "" when msg is another error, or the key cannot be
// found. The key and value are read from the plan itself, since the decoder
// names neither.
func explainScalarForList(msg string, data []byte) string {
	m := scalarForList.FindStringSubmatch(msg)
	if m == nil {
		return ""
	}
	line, err := strconv.Atoi(m[1])
	if err != nil {
		return ""
	}
	document, err := parsePlanDocument(data)
	if err != nil || len(document.Content) == 0 {
		return ""
	}
	budget := maxPresenceNodes
	key, value, found := scalarAtLine(document.Content[0], line, &budget)
	if !found {
		return ""
	}
	return fmt.Sprintf("line %d: %s is a list: write %s", line, key, listSpelling(value))
}

// scalarAtLine finds the key of a mapping whose single value is written on
// line, and that value. It does not follow aliases, and stops after budget
// nodes.
func scalarAtLine(node *yaml.Node, line int, budget *int) (key, value string, found bool) {
	if *budget--; *budget < 0 || node == nil {
		return "", "", false
	}
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			k, v := node.Content[i], node.Content[i+1]
			if v.Kind == yaml.ScalarNode && v.Line == line {
				return k.Value, v.Value, true
			}
			if key, value, found = scalarAtLine(v, line, budget); found {
				return key, value, true
			}
		}
	case yaml.SequenceNode, yaml.DocumentNode:
		for _, child := range node.Content {
			if key, value, found = scalarAtLine(child, line, budget); found {
				return key, value, true
			}
		}
	}
	return "", "", false
}

// listSpelling is value as a one-line list: "NONE" is "[NONE]", and
// "DORA, SOC2" is "[DORA, SOC2]". Nothing to go on is the example the plan
// reference gives.
func listSpelling(value string) string {
	items := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(items) == 0 {
		return "[NONE], or the labels you want in brackets"
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func explainUnknownKey(msg string) string {
	m := unknownFieldError.FindStringSubmatch(msg)
	if m == nil {
		return msg
	}
	line, key := m[1], m[2]
	section, known := planSections[m[3]]
	if !known {
		return fmt.Sprintf("line %s: unknown key %q", line, key)
	}
	where := "at the top level of the plan"
	if section.path != "" {
		where = "in " + section.path
	}
	text := fmt.Sprintf("line %s: unknown key %q %s", line, key, where)
	if suggestions := nearestKeys(key, section.keys); len(suggestions) > 0 {
		quoted := make([]string, len(suggestions))
		for i, s := range suggestions {
			quoted[i] = fmt.Sprintf("%q", s)
		}
		text += "; did you mean " + strings.Join(quoted, " or ") + "?"
	} else {
		text += "."
	}
	return text + " Keys there: " + strings.Join(section.keys, ", ")
}

// nearestKeys returns at most three keys the operator probably meant: the
// same key but for case or separators (bootTimeoutSec), else keys that
// contain it or that it contains (grace, startup_grace_period_sec), else the
// keys within a small edit distance (tiemout_sec).
func nearestKeys(unknown string, keys []string) []string {
	u := normalizeKey(unknown)
	if u == "" {
		return nil
	}
	var same, containing, near []string
	bestDistance := max(2, len(u)/3) + 1
	for _, key := range keys {
		k := normalizeKey(key)
		switch {
		case k == u:
			same = append(same, key)
		case (len(u) >= 3 && strings.Contains(k, u)) || (len(k) >= 3 && strings.Contains(u, k)):
			containing = append(containing, key)
		default:
			if d := editDistance(u, k); d < bestDistance {
				bestDistance, near = d, []string{key}
			} else if d == bestDistance && near != nil {
				near = append(near, key)
			}
		}
	}
	for _, found := range [][]string{same, containing, near} {
		if len(found) > 0 {
			if len(found) > 3 {
				found = found[:3]
			}
			return found
		}
	}
	return nil
}

func normalizeKey(key string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToLower(key))
}

func editDistance(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}

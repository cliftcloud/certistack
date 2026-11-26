// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// planLoadBound is how long one plan may take to load. A plan is at most
// MaxPlanBytes, and nothing in it may make the loader work without bound: an
// alias or merge bomb is refused, not expanded.
const planLoadBound = 10 * time.Second

// seedPlanFiles are the plans the fuzz targets start from: the shipped
// examples and the test fixtures.
func seedPlanFiles(f *testing.F) [][]byte {
	f.Helper()
	var seeds [][]byte
	for _, pattern := range []string{
		filepath.Join("..", "..", "examples", "*.yaml"),
		filepath.Join("..", "..", "testdata", "plans", "*.yaml"),
	} {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			f.Fatal(err)
		}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				f.Fatal(err)
			}
			seeds = append(seeds, data)
		}
	}
	if len(seeds) == 0 {
		f.Fatal("no seed plans found")
	}
	return seeds
}

// FuzzPlanLoad holds the plan loader to its contract on any input: it never
// panics and ends in bounded time, and a plan it accepts is one every other
// reader of plans accepts as the same plan. The worker loader must take the
// plan the controller sends it and see the same plan (the canonical digest the
// report records is unchanged by the trip), and the JSON schema an editor
// checks the plan with must not flag a plan validate accepts.
func FuzzPlanLoad(f *testing.F) {
	for _, seed := range seedPlanFiles(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		start := time.Now()
		plan, err := LoadFromReader(bytes.NewReader(data))
		if took := time.Since(start); took > planLoadBound {
			t.Fatalf("loading a %d-byte plan took %s", len(data), took)
		}
		if err != nil {
			return
		}
		checkAcceptedPlan(t, data, plan)
	})
}

// checkAcceptedPlan holds a plan the controller loader accepted to the
// properties every accepted plan has.
func checkAcceptedPlan(t *testing.T, data []byte, plan *Plan) {
	t.Helper()
	digest, err := CanonicalWorkerPlanSHA256(plan)
	if err != nil {
		t.Fatalf("the canonical digest of an accepted plan fails: %v", err)
	}
	workerData, err := MarshalWorkerPlan(plan)
	if err != nil {
		t.Fatalf("an accepted plan cannot be marshaled for the worker: %v", err)
	}
	worker, err := LoadFromReaderForWorker(bytes.NewReader(workerData))
	if err != nil {
		t.Fatalf("the worker refuses the plan the controller accepted and sends it: %v\nplan:\n%s\nworker plan:\n%s", err, data, workerData)
	}
	workerDigest, err := CanonicalWorkerPlanSHA256(worker)
	if err != nil {
		t.Fatalf("the canonical digest of the worker's plan fails: %v", err)
	}
	if workerDigest != digest {
		again, _ := MarshalWorkerPlan(worker)
		t.Fatalf("the worker sees another plan than the controller sent:\nsent:\n%s\nworker's:\n%s", workerData, again)
	}
	var document any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("the loader accepted a plan that YAML cannot decode: %v", err)
	}
	if problems := schemaProblems(document); len(problems) > 0 {
		t.Fatalf("validate accepts the plan, but the schema flags it:\n  %s\nplan:\n%s", strings.Join(problems, "\n  "), data)
	}
}

// schemaKeysOf are the property names the published schema allows in the
// object schema s (following its $ref), and the schema of each.
func schemaKeysOf(s map[string]any) map[string]map[string]any {
	root := publishedSchema()
	for {
		ref, ok := s["$ref"].(string)
		if !ok {
			break
		}
		defs, _ := root["$defs"].(map[string]any)
		s, _ = defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
	}
	properties, _ := s["properties"].(map[string]any)
	keys := make(map[string]map[string]any, len(properties))
	for key, value := range properties {
		if property, ok := value.(map[string]any); ok {
			keys[key] = property
		}
	}
	return keys
}

// editablePaths are the paths of doc a field fuzzer may set: every key the
// schema allows on every object the document has, given or not, so a value
// reaches the validation of keys a plan usually leaves out.
func editablePaths(doc any) []string {
	var paths []string
	var walk func(node any, schema map[string]any, path string)
	walk = func(node any, schema map[string]any, path string) {
		switch value := node.(type) {
		case map[string]any:
			keys := schemaKeysOf(schema)
			names := make([]string, 0, len(keys))
			for key := range keys {
				names = append(names, key)
			}
			sort.Strings(names)
			for _, key := range names {
				child := key
				if path != "" {
					child = path + "." + key
				}
				paths = append(paths, child)
				if existing, given := value[key]; given {
					walk(existing, keys[key], child)
				}
			}
		case []any:
			items, _ := schema["items"].(map[string]any)
			for i, item := range value {
				walk(item, items, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(doc, publishedSchema(), "")
	return paths
}

// fuzzValue is the value one field edit puts in the plan.
func fuzzValue(kind uint8, text string, number float64) (value any, remove bool) {
	switch kind % 8 {
	case 0:
		return text, false
	case 1:
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return text, false
		}
		return int64(number), false
	case 2:
		return number, false
	case 3:
		return number != 0, false
	case 4:
		return nil, false
	case 5:
		return nil, true
	case 6:
		return []any{text}, false
	default:
		return map[string]any{text: number}, false
	}
}

// FuzzPlanFields edits one or two keys of a shipped plan with a hostile value
// (any string, number, NaN, Inf, a list, a map, null, or the key removed),
// and holds the loader to the same contract as FuzzPlanLoad. Mutating the
// YAML text seldom yields a plan that gets as far as validate; editing its
// keys reaches every rule.
func FuzzPlanFields(f *testing.F) {
	var documents []any
	for _, seed := range seedPlanFiles(f) {
		var doc any
		if err := yaml.Unmarshal(seed, &doc); err != nil {
			f.Fatal(err)
		}
		if _, err := LoadFromReader(bytes.NewReader(seed)); err != nil {
			continue // only plans the loader accepts are edited
		}
		documents = append(documents, doc)
	}
	f.Add(uint8(0), uint16(0), uint8(0), "v1", 0.0, uint16(1), uint8(5), "", 0.0)
	f.Add(uint8(1), uint16(40), uint8(1), "", 65536.0, uint16(7), uint8(2), "", math.NaN())
	f.Add(uint8(2), uint16(90), uint8(0), "\x1b[31mred", 0.0, uint16(91), uint8(6), "SOC2", 0.0)
	f.Fuzz(func(t *testing.T, which uint8, first uint16, firstKind uint8, firstText string, firstNumber float64,
		second uint16, secondKind uint8, secondText string, secondNumber float64) {
		data, err := yaml.Marshal(documents[int(which)%len(documents)])
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		for _, edit := range []struct {
			selector uint16
			kind     uint8
			text     string
			number   float64
		}{{first, firstKind, firstText, firstNumber}, {second, secondKind, secondText, secondNumber}} {
			paths := editablePaths(doc)
			path := paths[int(edit.selector)%len(paths)]
			value, remove := fuzzValue(edit.kind, edit.text, edit.number)
			if remove {
				deletePath(doc, path)
			} else {
				setPath(doc, path, value)
			}
		}
		edited, err := yaml.Marshal(doc)
		if err != nil {
			return
		}
		start := time.Now()
		plan, err := LoadFromReader(bytes.NewReader(edited))
		if took := time.Since(start); took > planLoadBound {
			t.Fatalf("loading the plan took %s", took)
		}
		if err != nil {
			return
		}
		checkAcceptedPlan(t, edited, plan)
	})
}

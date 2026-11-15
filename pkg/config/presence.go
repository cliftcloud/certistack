// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// maxPresenceNodes bounds the YAML nodes walked to record which keys a plan
// gives. The plan decoder has already refused anything with excessive
// aliasing; this only keeps the walk finite if that ever changes.
const maxPresenceNodes = 1 << 20

// planKeys returns the path of every key a plan's YAML gives a value, such as
// "admission_control.max_host_ram_percent" or "tiers[0].vms[1].vmid". A key
// with no value (a YAML null) counts as left out.
//
// The struct a plan decodes into cannot tell a key written as zero from a key
// left out, and the plan's alias spellings and defaults hinge on exactly
// that: a tier that says "level: 0" and "tier: 2" gives two answers, and a
// probe that says "timeout_sec: 0" asked for no time at all, not for the
// default.
func planKeys(data []byte) (map[string]bool, error) {
	document, err := parsePlanDocument(data)
	if err != nil {
		return nil, err
	}
	return planKeysOf(document)
}

// parsePlanDocument is the plan's YAML as a node tree, for the checks that
// need to know what the author wrote (which keys, which spelling of a number)
// and not only what the decoder made of it.
func parsePlanDocument(data []byte) (*yaml.Node, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("read plan keys: %w", err)
	}
	return &document, nil
}

// planKeysOf is planKeys for a document parsePlanDocument returned.
func planKeysOf(document *yaml.Node) (map[string]bool, error) {
	keys := make(map[string]bool)
	if len(document.Content) == 0 {
		return keys, nil
	}
	budget := maxPresenceNodes
	if err := collectKeys(document.Content[0], "", keys, &budget); err != nil {
		return nil, err
	}
	return keys, nil
}

func collectKeys(node *yaml.Node, path string, keys map[string]bool, budget *int) error {
	for node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	if *budget--; *budget < 0 {
		return errors.New("plan has too many YAML nodes to check its keys")
	}
	switch node.Kind {
	case yaml.MappingNode:
		values := make(map[string]*yaml.Node)
		if err := mappingValues(node, values, 0); err != nil {
			if path == "" {
				return err
			}
			return fmt.Errorf("%s: %w", path, err)
		}
		for key, value := range values {
			for value.Kind == yaml.AliasNode {
				value = value.Alias
			}
			if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
				continue
			}
			child := key
			if path != "" {
				child = path + "." + key
			}
			keys[child] = true
			if err := collectKeys(value, child, keys, budget); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, item := range node.Content {
			if err := collectKeys(item, fmt.Sprintf("%s[%d]", path, i), keys, budget); err != nil {
				return err
			}
		}
	}
	return nil
}

// maxMergeDepth is how many "<<" merges may be nested in a plan. A plan that
// nests them deeper is refused: the keys beyond would go unrecorded, and a
// value written as zero, or one that only a deeper merge gives, would be
// taken for a key left out and given its default.
const maxMergeDepth = 16

// mappingValues collects a mapping's keys with their value nodes, including
// the keys of "<<" merges; a key the mapping gives itself wins over a merged
// one, as it does in the decoder. Merges nested deeper than maxMergeDepth are
// an error, not silently skipped.
func mappingValues(node *yaml.Node, values map[string]*yaml.Node, depth int) error {
	if depth > maxMergeDepth {
		return fmt.Errorf("YAML merge keys (<<) are nested more than %d deep, which CertiStack cannot check for which keys the plan gives; flatten them", maxMergeDepth)
	}
	var merges []*yaml.Node
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Tag == "!!merge" {
			merges = append(merges, value)
			continue
		}
		if _, seen := values[key.Value]; !seen {
			values[key.Value] = value
		}
	}
	for _, merged := range merges {
		for merged.Kind == yaml.AliasNode {
			merged = merged.Alias
		}
		switch merged.Kind {
		case yaml.MappingNode:
			if err := mappingValues(merged, values, depth+1); err != nil {
				return err
			}
		case yaml.SequenceNode:
			for _, item := range merged.Content {
				for item.Kind == yaml.AliasNode {
					item = item.Alias
				}
				if item.Kind == yaml.MappingNode {
					if err := mappingValues(item, values, depth+1); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// given reports whether the plan's author gave the setting at path. A plan
// loaded from YAML knows exactly, so a value written as zero still counts as
// given; a plan built in code has no such record, and a non-zero value counts.
func (p *Plan) given(path string, nonzero bool) bool {
	if p.keys != nil {
		return p.keys[path]
	}
	return nonzero
}

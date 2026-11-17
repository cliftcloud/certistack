// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"fmt"
	"strings"
	"testing"
)

// chainedProbes is the handwritten plan with its one probe replaced by a
// chain of probes that each merge the one before (<<), hops deep: probes[0]
// gives timeout_sec 5, and probes[n] has it only through n merges.
func chainedProbes(hops int) string {
	text := handwritten("level: 1", "vmid: 9001", "timeout_sec: 5")
	const probe = "          - {type: tcp, target_ip: 10.100.0.10, port: 389, description: ldap, timeout_sec: 5}\n"
	if !strings.Contains(text, probe) {
		panic("the handwritten plan changed shape")
	}
	var chain strings.Builder
	chain.WriteString("          - &a0 {type: tcp, target_ip: 10.100.0.10, port: 389, description: ldap, timeout_sec: 5}\n")
	for i := 1; i <= hops; i++ {
		fmt.Fprintf(&chain, "          - &a%d {<<: *a%d}\n", i, i-1)
	}
	return strings.Replace(text, probe, chain.String(), 1)
}

// A key that only a deep chain of merges gives must be recorded as given, or
// the plan reads as if it had left it out: the probe below would have its
// timeout_sec 5 replaced by the default of 10, and a timeout_sec of 0 behind
// such a chain would skip the rule that refuses it. Merges nested past the
// limit are refused, at the probe that has them, by both loaders; a chain of
// the largest allowed depth keeps every key.
func TestMergeChainsDeeperThanTheLimitAreRefused(t *testing.T) {
	for hops, refused := range map[int]bool{1: false, 15: false, maxMergeDepth: false, maxMergeDepth + 1: true, 40: true} {
		plan, err := loadText(t, chainedProbes(hops))
		path := fmt.Sprintf("tiers[0].vms[0].probes[%d]", maxMergeDepth+1)
		switch {
		case refused && (err == nil || !strings.Contains(err.Error(), "merge keys (<<) are nested more than 16 deep")):
			t.Errorf("%d hops: err %v, want the merge depth refused", hops, err)
		case refused && hops == maxMergeDepth+1 && !strings.Contains(err.Error(), path):
			t.Errorf("%d hops: err %v does not name %s", hops, err, path)
		case !refused && err != nil:
			t.Errorf("%d hops: %v", hops, err)
		case !refused:
			last := plan.Tiers[0].VMs[0].Probes[hops]
			if last.TimeoutSec != 5 {
				t.Errorf("%d hops: the last probe's timeout_sec = %d, want the 5 its chain gives", hops, last.TimeoutSec)
			}
		}
	}
}

// The zero behind a merge chain, which no plan layout can place in a probe
// (the chain's first link would be a probe that is refused itself): the key
// record of a mapping that merges at the limit has the key, and one past it
// is an error rather than a mapping without keys.
func TestPlanKeysFollowsMergesToTheLimitAndNoFurther(t *testing.T) {
	// Each link merges the one before as a mapping ("<<: *a") or as a list of
	// mappings ("<<: [*a]").
	for _, form := range []string{"<<: *a%d", "<<: [*a%d]"} {
		document := func(hops int) []byte {
			var b strings.Builder
			b.WriteString("a0: &a0 {timeout_sec: 0}\n")
			for i := 1; i <= hops; i++ {
				fmt.Fprintf(&b, "a%d: &a%d {"+form+"}\n", i, i, i-1)
			}
			fmt.Fprintf(&b, "root: {"+form+"}\n", hops)
			return []byte(b.String())
		}
		keys, err := planKeys(document(maxMergeDepth - 1))
		if err != nil || !keys["root.timeout_sec"] {
			t.Fatalf("%s, %d merges: keys %v, err %v, want root.timeout_sec recorded", form, maxMergeDepth, keys, err)
		}
		if _, err := planKeys(document(maxMergeDepth)); err == nil || !strings.Contains(err.Error(), "nested more than 16 deep") {
			t.Fatalf("%s, %d merges: err %v, want the depth refused", form, maxMergeDepth+1, err)
		}
	}
}

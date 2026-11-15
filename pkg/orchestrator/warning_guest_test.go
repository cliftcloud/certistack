// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// The warnings about a boot that reads from PBS used to say "Windows services
// can miss their start deadline" for every guest, a Rocky Linux one included.
// They name Windows only when the plan restores a Windows VM (hardening F11,
// CR1-11).
func TestPlanWarningsNameWindowsOnlyForAWindowsGuest(t *testing.T) {
	for _, tc := range []struct {
		name, ostype string
		windows      bool
	}{
		{"no ostype in the plan", "", false},
		{"Linux 2.6 or later", "l26", false},
		{"other", "other", false},
		{"Windows 11", "win11", true},
		{"Windows Server 2019", "w2k19", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := planTestPlan()
			vm := &plan.Tiers[0].VMs[0]
			vm.OSType = tc.ostype
			vm.SourceDiskBytes = map[string]int64{"scsi0": 90 << 30, "scsi1": 10 << 30}
			o := planOrchestrator(t, plan, planPVE(t, ""))
			o.sharedDisksFn = func(context.Context, string, string) ([]string, error) { return []string{"sda"}, nil }
			p, err := o.Plan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var copyWarning, tierWarning string
			for _, warning := range p.Warnings {
				switch {
				case strings.Contains(warning, "won't all stay cached"):
					copyWarning = warning
				case strings.Contains(warning, "can keep cached"):
					tierWarning = warning
				}
			}
			if copyWarning == "" || tierWarning == "" {
				t.Fatalf("the plan lacks the copy warning (%q) or the tier warning (%q): %v", copyWarning, tierWarning, p.Warnings)
			}
			for name, warning := range map[string]string{"copy-before-boot": copyWarning, "tier cache": tierWarning} {
				if got := strings.Contains(warning, "Windows"); got != tc.windows {
					t.Errorf("the %s warning names Windows = %v, want %v:\n%s", name, got, tc.windows, warning)
				}
				// Whatever the guest, the warning still says what goes wrong.
				if !strings.Contains(warning, "start deadline") {
					t.Errorf("the %s warning no longer says what can go wrong:\n%s", name, warning)
				}
			}
		})
	}
}

// A tier is Windows if any of its VMs is: the kernel evicts the first-scanned
// disks, which may be another VM's.
func TestTierCacheWarningNamesWindowsWhenAnyVMOfTheTierIsOne(t *testing.T) {
	for _, tc := range []struct {
		ostypes []string
		windows bool
	}{
		{[]string{"l26", "l26"}, false},
		{[]string{"l26", "win10"}, true},
		{[]string{"w2k22", "l26"}, true},
	} {
		tier := config.Tier{Level: 1}
		for _, ostype := range tc.ostypes {
			tier.VMs = append(tier.VMs, config.VM{OSType: ostype})
		}
		o := &Orchestrator{cacheMemoryFn: func() (float64, error) { return 10 * 1024, nil }}
		o.beginTierCache(tier)
		msg := o.noteScannedDisks(1, 1<<40)
		if msg == "" {
			t.Fatalf("%v: no warning for a tier that outgrows the cache", tc.ostypes)
		}
		if got := strings.Contains(msg, "Windows"); got != tc.windows {
			t.Errorf("%v: the warning names Windows = %v, want %v:\n%s", tc.ostypes, got, tc.windows, msg)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// A plan may spell some settings two ways, a canonical key and an older
// alias. Normalize fills the canonical field from an alias only when the
// author left the canonical key out, and validate refuses a plan that gives
// both spellings with different values: silently choosing one would run a
// different admission policy, subnet, tier or sandbox VM than one of the
// visible keys says. A value the author wrote is never replaced,
// whatever it is: a canonical "level: -1" is invalid, not a gap the alias
// may fill.

// spelling is one way a plan may write a setting: the YAML path it lives at,
// its value as text (so ints, floats and addresses compare alike), and
// whether the author gave it.
type spelling struct {
	path  string
	text  string
	given bool
}

func floatText(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }
func intText(v int) string       { return strconv.Itoa(v) }

// cidrText is a CIDR in canonical form, so "10.100.0.0/24" and
// "10.100.0.0/24 " are the same value; anything else compares as written.
func cidrText(v string) string {
	v = strings.TrimSpace(v)
	if _, network, err := net.ParseCIDR(v); err == nil {
		return network.String()
	}
	return v
}

// firstConflict returns the first given spelling whose value differs from the
// first given one's, and that first spelling.
func firstConflict(spellings []spelling) (first, other spelling, found bool) {
	for _, s := range spellings {
		if !s.given {
			continue
		}
		if !first.given {
			first = s
			continue
		}
		if s.text != first.text {
			return first, s, true
		}
	}
	return spelling{}, spelling{}, false
}

// numField is one numeric admission setting, an int or a float.
type numField struct {
	f *float64
	i *int
}

func (n numField) text() string {
	if n.f != nil {
		return floatText(*n.f)
	}
	return intText(*n.i)
}

func (n numField) nonzero() bool {
	if n.f != nil {
		return *n.f != 0
	}
	return *n.i != 0
}

func (n numField) set(from numField) {
	switch {
	case n.f != nil && from.f != nil:
		*n.f = *from.f
	case n.i != nil && from.i != nil:
		*n.i = *from.i
	}
}

func admissionFields(a *AdmissionControl) map[string]numField {
	return map[string]numField{
		"max_host_ram_percent":     {f: &a.MaxHostRAMPercent},
		"max_host_iowait_percent":  {f: &a.MaxHostIOWaitPercent},
		"max_host_io_wait_percent": {f: &a.MaxHostIOWaitPercentAlt},
		"defer_retry_interval_sec": {i: &a.DeferRetryIntervalSec},
		"max_defer_retries":        {i: &a.MaxDeferRetries},
		"max_concurrent_boots":     {i: &a.MaxConcurrentBoots},
		"boot_settle_sec":          {i: &a.BootSettleSec},
	}
}

// admissionSetting is one admission limit and every place a plan may give it:
// the canonical key of admission_control first, then its aliases (the other
// spelling of the I/O wait limit, and the same keys under the older
// "admission" block).
type admissionSetting struct {
	canonical string
	spellings [][2]string // {block, key}
}

var admissionSettings = []admissionSetting{
	{"max_host_ram_percent", [][2]string{{"admission_control", "max_host_ram_percent"}, {"admission", "max_host_ram_percent"}}},
	{"max_host_iowait_percent", [][2]string{
		{"admission_control", "max_host_iowait_percent"}, {"admission_control", "max_host_io_wait_percent"},
		{"admission", "max_host_iowait_percent"}, {"admission", "max_host_io_wait_percent"}}},
	{"defer_retry_interval_sec", [][2]string{{"admission_control", "defer_retry_interval_sec"}, {"admission", "defer_retry_interval_sec"}}},
	{"max_defer_retries", [][2]string{{"admission_control", "max_defer_retries"}, {"admission", "max_defer_retries"}}},
	{"max_concurrent_boots", [][2]string{{"admission_control", "max_concurrent_boots"}, {"admission", "max_concurrent_boots"}}},
	{"boot_settle_sec", [][2]string{{"admission_control", "boot_settle_sec"}, {"admission", "boot_settle_sec"}}},
}

func (p *Plan) admissionSpellings(setting admissionSetting) (spellings []spelling, fields []numField) {
	blocks := map[string]*AdmissionControl{"admission_control": &p.AdmissionControl, "admission": &p.Admission}
	for _, s := range setting.spellings {
		field := admissionFields(blocks[s[0]])[s[1]]
		path := s[0] + "." + s[1]
		spellings = append(spellings, spelling{path: path, text: field.text(), given: p.given(path, field.nonzero())})
		fields = append(fields, field)
	}
	return spellings, fields
}

// normalizeAdmission fills each admission_control limit the plan leaves out
// from the same limit under one of its other spellings. It replaces nothing
// the plan gives, so a difference stays visible for validate to refuse.
func (p *Plan) normalizeAdmission() {
	for _, setting := range admissionSettings {
		spellings, fields := p.admissionSpellings(setting)
		if spellings[0].given {
			continue
		}
		for i, s := range spellings[1:] {
			if s.given {
				fields[0].set(fields[i+1])
				break
			}
		}
	}
}

// aliasConflictErrors is every setting the plan gives under two spellings
// with different values.
func aliasConflictErrors(p *Plan) []ValidationError {
	var errors []ValidationError
	report := func(spellings []spelling) {
		if first, other, found := firstConflict(spellings); found {
			errors = append(errors, ValidationError{Field: other.path, Message: fmt.Sprintf("is another spelling of %s and disagrees with it (%s, not %s); give the setting once, or give the same value", first.path, other.text, first.text)})
		}
	}
	for _, setting := range admissionSettings {
		spellings, _ := p.admissionSpellings(setting)
		report(spellings)
	}
	report([]spelling{
		{"network.ip_range", cidrText(p.Network.IPRange), p.given("network.ip_range", p.Network.IPRange != "")},
		{"network.subnet_cidr", cidrText(p.Network.SubnetCIDR), p.given("network.subnet_cidr", p.Network.SubnetCIDR != "")},
	})
	for i, tier := range p.Tiers {
		prefix := fmt.Sprintf("tiers[%d]", i)
		report([]spelling{
			{prefix + ".level", intText(tier.Level), p.given(prefix+".level", tier.Level != 0)},
			{prefix + ".tier", intText(tier.Tier), p.given(prefix+".tier", tier.Tier != 0)},
		})
		for j, vm := range tier.VMs {
			vmPrefix := fmt.Sprintf("%s.vms[%d]", prefix, j)
			report([]spelling{
				{vmPrefix + ".vmid", intText(vm.VMID), p.given(vmPrefix+".vmid", vm.VMID != 0)},
				{vmPrefix + ".target_vmid", intText(vm.TargetVMID), p.given(vmPrefix+".target_vmid", vm.TargetVMID != 0)},
			})
		}
	}
	return errors
}

// canonicalCopy is the plan with its alias spellings dropped, for writing
// it out: what a node worker reads back holds each setting once, so it
// cannot disagree with itself.
func (p *Plan) canonicalCopy() Plan {
	c := *p
	c.keys = nil
	c.Admission = AdmissionControl{}
	c.AdmissionControl.MaxHostIOWaitPercentAlt = 0
	c.Network.SubnetCIDR = ""
	c.Tiers = make([]Tier, len(p.Tiers))
	for i, tier := range p.Tiers {
		tier.Tier = 0
		tier.VMs = append([]VM(nil), tier.VMs...)
		for j := range tier.VMs {
			tier.VMs[j].TargetVMID = 0
		}
		c.Tiers[i] = tier
	}
	return c
}

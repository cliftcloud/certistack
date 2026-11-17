// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// recordedTargetAddress is the IP address a wire probe's recorded target
// names, in one spelling: the host of tcp's and ldap's "host:port", and of
// http's and dns's "scheme://host:port/path". It reports false for a target
// whose host is not an IP literal.
func recordedTargetAddress(target string) (string, bool) {
	hostPort := target
	if _, rest, found := strings.Cut(target, "://"); found {
		hostPort = rest
		if end := strings.IndexAny(hostPort, "/?#"); end >= 0 {
			hostPort = hostPort[:end]
		}
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = strings.Trim(hostPort, "[]")
	}
	address := config.WireTargetAddress(host)
	return address, address != ""
}

// SharedWireTargetProblems is what contradicts a report's attribution of its
// wire probes to its VMs: an address that passing wire probes of two or more
// VM records name. A wire probe shows that its target answered from the
// worker host, not which guest answered, and the record of the VM whose probe
// it was is credited with the answer. With one address on two records, one
// guest or one shared listener can have satisfied both, and a signed pass
// would not show that each named VM provided its own service. The
// loaders refuse a plan that names an address on two VMs (config.Validate);
// this holds a report to the same rule from its own records, so it needs no
// plan: a report of a worker given a plan that did not pass the loader is
// refused by the verifier and never signed by the controller. A probe that
// failed or was skipped credits no one.
func SharedWireTargetProblems(records []probe.VMValidationRecord) []string {
	named := make(map[string][]int)
	var order []string
	for _, record := range records {
		counted := make(map[string]bool)
		for _, result := range record.ProbeResults {
			if !config.IsWireProbe(result.Type) || !result.Passed || result.Skipped {
				continue
			}
			address, ok := recordedTargetAddress(result.Target)
			if !ok || counted[address] {
				continue
			}
			counted[address] = true
			if _, seen := named[address]; !seen {
				order = append(order, address)
			}
			if ids := named[address]; len(ids) > 0 && ids[len(ids)-1] == record.VMID {
				continue // the same VM recorded twice is not two VMs
			}
			named[address] = append(named[address], record.VMID)
		}
	}
	var problems []string
	for _, address := range order {
		ids := named[address]
		if len(ids) < 2 {
			continue
		}
		sort.Ints(ids)
		labels := make([]string, len(ids))
		for i, id := range ids {
			labels[i] = fmt.Sprintf("%d", id)
		}
		problems = append(problems, fmt.Sprintf("VMs %s each record a passing wire probe of %s: a probe shows that its target answered, not which guest answered, so one answer cannot show that each of them provided its own service; every wire-probe target must belong to exactly one VM", strings.Join(labels, ", "), address))
	}
	return problems
}

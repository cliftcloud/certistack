// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/sdn"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// The troubleshooting guide tells an operator what recovery does with an
// unconfirmed SDN allocation, with a journal that names no owner marker and with
// a zone beside a VNet it refused. Each message it quotes is the one the code
// gives, so a change to either side fails here until the other follows.
func TestSDNRecoveryDocumentationQuotesWhatRecoverySays(t *testing.T) {
	data, err := os.ReadFile(repoFile("docs", "troubleshooting.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Join(strings.Fields(string(data)), " ")

	// What the code says to a journal that names no marker: a VNet PVE lists is
	// refused, with the reason the guide quotes.
	fake := sdntest.New().Applied("csSb01", "csVn01", "csSb01-10.100.0.0-24")
	err = sdn.NewManager(fake.Serve(t)).DestroyVNet(context.Background(), "csVn01")
	var notOwned *sdn.NotOwnedError
	if !errors.As(err, &notOwned) {
		t.Fatalf("a manager with no owner marker deleted or mishandled a listed VNet: %v", err)
	}
	for _, quoted := range []string{
		"cannot show that it is the interrupted run's",
		"the run's journal names no owner marker, as the journals of earlier versions do not",
	} {
		if !strings.Contains(err.Error(), quoted) {
			t.Errorf("the code no longer says %q: %v", quoted, err)
		}
		if !strings.Contains(doc, quoted) {
			t.Errorf("docs/troubleshooting.md does not quote %q", quoted)
		}
	}
	// The refusal of a zone beside a VNet that was left in place is in recovery
	// (Linux only), so it is read from the source.
	source, err := os.ReadFile(repoFile("internal", "recovery", "recovery_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "left SDN zone %s in place") || !strings.Contains(doc, "left SDN zone … in place") {
		t.Error(`recovery's "left SDN zone … in place" and the guide's quotation of it have come apart`)
	}

	// What an operator is told about the pending allocation of a zone or VNet.
	for _, want := range []string{
		"`allocation_pending` reads `SDN zone <id>` or `SDN VNet <id>`) before it sends the request that creates it",
		"the pending allocation is cleared once PVE's lists show nothing of it is left",
		"When PVE has neither, the request had no effect",
		"On PVE 8, which has no SDN lock to hold other clients off, a zone that PVE lists as created and never applied is not shown to be the run's either",
		"recovery deletes it only while PVE still shows it is the run's",
		"and the zone stays, as it does whenever recovery left the VNet",
		"recovery then deletes no VNet and no zone that PVE lists for it",
		"`certistack plan` lists such objects as left in place",
		// The reason recovery gives for a zone nothing shows to be the run's.
		"no VNet in it carries the run's marker",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/troubleshooting.md no longer says %q", want)
		}
	}
	// A phrase of the guide that is no longer true must not come back.
	for _, stale := range []string{
		"recovery deletes such a VNet, and refuses one that has an alias",
		"retry reconciliation",
	} {
		if strings.Contains(doc, stale) {
			t.Errorf("docs/troubleshooting.md says %q, which recovery no longer does", stale)
		}
	}
}

// The guide says how recovery settles a host probe address whose addition was
// never recorded, in the words the recovery log and the plan use.
func TestHostAddressAllocationRecoveryIsDocumented(t *testing.T) {
	data, err := os.ReadFile(repoFile("docs", "troubleshooting.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Join(strings.Fields(string(data)), " ")
	for _, want := range []string{
		`The host probe address is settled from the host: the run journals "host probe address <cidr> on <vnet>" before it adds the address`,
		"Table and address both there: both are the run's and are removed.",
		"Only the address, with no table: the run never installed one, so it never added the address, which was there before; it is left alone",
		"When the host cannot be read, or a VM of the run may still run, the allocation stays.",
		"or a host probe address (`host probe address <cidr> on <vnet>`), run the recovery of step 4 first",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/troubleshooting.md no longer says %q", want)
		}
	}
	if strings.Contains(doc, "Any other pending allocation, such as the host probe address, is not settled automatically") {
		t.Error("docs/troubleshooting.md still says a host probe address is not settled automatically")
	}
}

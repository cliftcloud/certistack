// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/sdn/sdntest"
)

// A VNet's tag is sent for a vxlan network (its VNI) and for no other;
// a tag on a simple network is refused before any request, not dropped.
func TestCreateVNetSendsATagOnlyForVXLAN(t *testing.T) {
	vnetPost := func(fake *sdntest.PVE) string {
		for _, w := range fake.Writes() {
			if strings.HasPrefix(w, "POST cluster/sdn/vnets ") {
				return w
			}
		}
		return ""
	}
	t.Run("vxlan", func(t *testing.T) {
		fake := sdntest.New()
		netCfg := config.Network{Mode: "vxlan", ZoneID: "csVx01", VNetID: "csVn01", Tag: 4242, Peers: "10.0.0.1"}
		if err := NewManager(fake.Serve(t)).CreateVNet(context.Background(), netCfg); err != nil {
			t.Fatal(err)
		}
		if post := vnetPost(fake); !strings.Contains(post, `"tag":4242`) {
			t.Fatalf("VNet request %q lacks the VNI", post)
		}
		if VNetTag(netCfg) != 4242 {
			t.Fatalf("VNetTag = %d, want 4242", VNetTag(netCfg))
		}
	})
	t.Run("simple, no tag", func(t *testing.T) {
		fake := sdntest.New()
		netCfg := config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01"}
		if err := NewManager(fake.Serve(t)).CreateVNet(context.Background(), netCfg); err != nil {
			t.Fatal(err)
		}
		if post := vnetPost(fake); post == "" || strings.Contains(post, `"tag"`) {
			t.Fatalf("VNet request %q; want one without a tag", post)
		}
		if VNetTag(netCfg) != 0 {
			t.Fatalf("VNetTag = %d, want none", VNetTag(netCfg))
		}
	})
	// The reported case (a simple network with tag 4242) cannot load any
	// more; a caller that builds it anyway gets a refusal, never a silent drop.
	t.Run("simple, a tag", func(t *testing.T) {
		fake := sdntest.New()
		netCfg := config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", Tag: 4242}
		err := NewManager(fake.Serve(t)).CreateVNet(context.Background(), netCfg)
		if err == nil || !strings.Contains(err.Error(), "carries no tag") || !strings.Contains(err.Error(), "4242") {
			t.Fatalf("CreateVNet = %v, want the tag refused", err)
		}
		if len(fake.Requests) != 0 {
			t.Fatalf("requests %v; want none", fake.Requests)
		}
		if VNetTag(netCfg) != 0 {
			t.Fatalf("VNetTag = %d; the preview must not name a tag the request does not carry", VNetTag(netCfg))
		}
	})
}

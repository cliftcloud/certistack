// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// plan with storage.overlay_storage naming a storage the node does not have:
// PVE answers "No such storage.", and the failed step ends with the command
// that creates it, so a newcomer who skipped the quickstart's storage step can
// act on it.
func TestPlanRefusesAMissingOverlayStorageWithTheCommandThatCreatesIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/nodes/pve1/storage/certistack-scratch/status" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"data":null,"message":"Parameter verification failed.\n","errors":{"storage":"No such storage."}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	t.Cleanup(server.Close)
	o := planOrchestrator(t, planTestPlan(), pve.NewClient(pve.Config{BaseURL: server.URL}))
	o.opts.OverlayStorage = "certistack-scratch"

	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const want = "Create one on the node, as root: pvesm add dir certistack-scratch --path /var/lib/vz/certistack-scratch --content images --shared 0. On a cluster this defines the storage for every node; add --nodes NODE to limit it to this one. certistack setup adds it for you (quickstart, step 2)"
	var found bool
	for _, refusal := range p.Refusals {
		if strings.Contains(refusal, "No such storage") {
			found = true
			if !strings.HasSuffix(refusal, want) {
				t.Errorf("the refusal must end with the fix:\n%s", refusal)
			}
		}
	}
	if !found {
		t.Fatalf("no refusal for the missing storage in %q", p.Refusals)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// lockServer answers the SDN lock with the messages in refusals, in turn,
// then grants it; pending zones are listed as changed.
func lockServer(t *testing.T, refusals []string, tries *int) *Manager {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/cluster/sdn/lock":
			*tries++
			if *tries <= len(refusals) {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "message": refusals[*tries-1]})
				return
			}
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"tok"`)})
		case r.URL.Path == "/api2/json/cluster/sdn/zones":
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[{"zone":"prodZ","state":"changed"},{"zone":"csLab70"}]`)})
		case r.URL.Path == "/api2/json/cluster/sdn/vnets":
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[{"vnet":"newNet","state":"new"}]`)})
		default:
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[]`)})
		}
	}))
	t.Cleanup(server.Close)
	return NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
}

func shortLockWaits(t *testing.T) {
	t.Helper()
	initial, max, wait := lockRetryInitial, lockRetryMax, lockWait
	lockRetryInitial, lockRetryMax, lockWait = time.Millisecond, 5*time.Millisecond, time.Second
	t.Cleanup(func() { lockRetryInitial, lockRetryMax, lockWait = initial, max, wait })
}

func TestLockWaitsForAnotherHolder(t *testing.T) {
	shortLockWaits(t)
	tries := 0
	m := lockServer(t, []string{"sdn configuration is locked by another user", "sdn configuration is locked by another user"}, &tries)
	if err := m.Lock(context.Background()); err != nil || m.LockToken() != "tok" || tries != 3 {
		t.Fatalf("Lock = %v, token %q after %d tries; want it taken on the third", err, m.LockToken(), tries)
	}
}

func TestLockRefusesOverPendingChangesAndNamesThem(t *testing.T) {
	tries := 0
	m := lockServer(t, []string{"there are pending changes"}, &tries)
	err := m.Lock(context.Background())
	if !errors.Is(err, ErrPendingSDNChanges) || tries != 1 || m.LockToken() != "" {
		t.Fatalf("Lock = %v after %d tries; want one refusal over pending changes", err, tries)
	}
	if !strings.Contains(err.Error(), "(VNet newNet (new), zone prodZ (changed))") || !strings.Contains(err.Error(), "Ask whoever changed SDN to apply or discard the change") || !strings.Contains(err.Error(), "Do not apply someone else's change yourself") {
		t.Fatalf("refusal does not name the changes or the remedy: %v", err)
	}
}

// The error text of a failed POST to cluster/sdn/lock names the path, which
// contains "lock": only PVE's own message may count as "held elsewhere".
func TestLockFailsFastOnAnotherError(t *testing.T) {
	shortLockWaits(t)
	tries := 0
	m := lockServer(t, []string{"permission check failed (/sdn, SDN.Allocate)", "x", "x"}, &tries)
	if err := m.Lock(context.Background()); err == nil || tries != 1 {
		t.Fatalf("Lock = %v after %d tries; want one failure", err, tries)
	}
}

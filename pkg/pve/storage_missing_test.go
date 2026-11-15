// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The sentence every message that leaves a newcomer without overlay storage
// ends with. It is written out here on purpose: the test pins what the reader
// sees, and a docs test pins that the command is the one the quickstart gives.
const wantCreateOverlayStorageHint = "Create one on the node, as root: pvesm add dir certistack-scratch --path /var/lib/vz/certistack-scratch --content images --shared 0. On a cluster this defines the storage for every node; add --nodes NODE to limit it to this one. certistack setup adds it for you (quickstart, step 2)"

// A storage that does not exist is the commonest first-run mistake (the
// reader skipped the "pvesm add dir" step), and PVE answers it with a bare
// "No such storage." that names no fix. The refusal ends with the command.
func TestValidateOverlayStorageNamesTheFixWhenTheStorageDoesNotExist(t *testing.T) {
	for name, tc := range map[string]struct {
		status   int
		response APIResponse
		wantHint bool
	}{
		"PVE 8 parameter verification": {
			status:   http.StatusBadRequest,
			response: APIResponse{Message: "Parameter verification failed.", Errors: map[string]string{"storage": "No such storage."}},
			wantHint: true,
		},
		"a storage that does not exist": {
			status:   http.StatusInternalServerError,
			response: APIResponse{Message: "storage 'certistack-scratch' does not exist"},
			wantHint: true,
		},
		"a token without privileges": {
			status:   http.StatusForbidden,
			response: APIResponse{Message: "Permission check failed (/storage/certistack-scratch, Datastore.Audit)"},
		},
		"another parameter's complaint": {
			status:   http.StatusBadRequest,
			response: APIResponse{Message: "Parameter verification failed.", Errors: map[string]string{"node": "unable to parse"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(tc.response)
			}))
			defer server.Close()
			client := NewClient(Config{BaseURL: server.URL})
			_, err := client.ValidateOverlayStorage(context.Background(), "pve1", "certistack-scratch", 5<<30)
			if err == nil {
				t.Fatal("a storage PVE does not know was accepted")
			}
			if got := strings.Contains(err.Error(), wantCreateOverlayStorageHint); got != tc.wantHint {
				t.Errorf("error names the fix = %v, want %v:\n%v", got, tc.wantHint, err)
			}
			if tc.wantHint && !strings.HasSuffix(err.Error(), wantCreateOverlayStorageHint) {
				t.Errorf("the fix must end the message:\n%v", err)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status {
				t.Errorf("the PVE answer must stay in the error chain: %v", err)
			}
		})
	}
}

// The fix is one sentence from one place, so the messages of init and plan
// cannot drift apart (a docs test compares its command with the guide).
func TestCreateOverlayStorageHintIsTheCommandAndWhereItIsDocumented(t *testing.T) {
	if CreateOverlayStorageHint != wantCreateOverlayStorageHint {
		t.Errorf("CreateOverlayStorageHint = %q, want %q", CreateOverlayStorageHint, wantCreateOverlayStorageHint)
	}
	if !strings.Contains(CreateOverlayStorageHint, CreateOverlayStorageCommand) {
		t.Errorf("the hint %q does not hold the command %q", CreateOverlayStorageHint, CreateOverlayStorageCommand)
	}
}

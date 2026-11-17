// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// PVE answers access/permissions with each privilege the token holds on the
// path and, as its value, whether it propagates to the paths below. VM.Audit
// on /vms is what lets a run with a pre-provisioned sandbox see every guest on
// its VNet (/vms/<id>); held on /vms alone, without propagation, it shows no
// guest at all, and the check of the VNet would find it empty.
func TestVMAuditOnVMsMustPropagateForAPreprovisionedSandbox(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		missing     bool
	}{
		{name: "propagated", value: `1`},
		{name: "propagated, as true", value: `true`},
		{name: "on /vms alone", value: `0`, missing: true},
		{name: "on /vms alone, as false", value: `false`, missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := r.URL.Query().Get("path")
				privileges := `"SDN.Audit":1,"SDN.Use":1,"Sys.Audit":1`
				if path == "/vms" {
					privileges = `"VM.Audit":` + tc.value
				}
				_, _ = w.Write([]byte(`{"data":{"` + path + `":{` + privileges + `}}}`))
			}))
			defer server.Close()
			reqs := RunPrivileges("pve1", nil, "csSbExt", "csVnExt", false, "")
			missing, err := NewClient(Config{BaseURL: server.URL}).MissingPrivileges(context.Background(), reqs)
			if err != nil {
				t.Fatal(err)
			}
			required, _ := DescribeMissingPrivileges(missing)
			if got := strings.Contains(required, "/vms"); got != tc.missing {
				t.Fatalf("required = %q; want /vms missing: %v", required, tc.missing)
			}
			if tc.missing && !strings.Contains(required, "VM.Audit propagated to the paths below it on /vms") {
				t.Fatalf("required = %q; want it to say VM.Audit must propagate", required)
			}
		})
	}
}

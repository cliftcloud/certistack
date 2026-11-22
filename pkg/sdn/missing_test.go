// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// answerEvery answers every request with the status line and body, written by
// hand: PVE writes its message in the reason phrase, which net/http's
// ResponseWriter cannot set.
func answerEvery(t *testing.T, statusLine, body string) *pve.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprintf(buf, "HTTP/1.1 %s\r\nContent-Type: application/json;charset=UTF-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", statusLine, len(body), body)
		_ = buf.Flush()
	}))
	t.Cleanup(server.Close)
	return pve.NewClient(pve.Config{BaseURL: server.URL})
}

// A PVE 8.0 node without libpve-network-perl has no SDN API: it answers the
// read of the zones with HTTP 501 and {"data":null}. The error names the call
// and the missing package, says how to fix it, and still wraps PVE's answer.
func TestAMissingSDNAPIIsNamedWithItsFix(t *testing.T) {
	client := answerEvery(t, "501 Method 'GET /cluster/sdn/zones' not implemented", `{"data":null}`)
	_, err := NewManager(client).UsedIDs(context.Background())
	var missing *MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("UsedIDs = %v, want a MissingError", err)
	}
	if missing.Call != "GET /cluster/sdn/zones" {
		t.Errorf("Call = %q", missing.Call)
	}
	for _, want := range []string{"no SDN API", "GET /cluster/sdn/zones", "HTTP 501", "libpve-network-perl", MissingFix} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
	if strings.Contains(missing.Problem(), MissingFix) {
		t.Errorf("Problem carries the fix: %q", missing.Problem())
	}
	var apiErr *pve.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotImplemented {
		t.Errorf("PVE's answer is not wrapped: %v", err)
	}
}

// Only a 501 is a missing API: any other refusal of the read is PVE's error as
// it came.
func TestOtherSDNReadFailuresAreNotAMissingAPI(t *testing.T) {
	for _, line := range []string{"403 Permission check failed", "400 Parameter verification failed."} {
		client := answerEvery(t, line, `{"data":null}`)
		_, err := NewManager(client).UsedIDs(context.Background())
		var missing *MissingError
		if err == nil || errors.As(err, &missing) {
			t.Errorf("%s: UsedIDs = %v, want PVE's error and no MissingError", line, err)
		}
	}
}

// pvesh's answer on a node without the SDN API, read as root over SSH before
// there is a token, is the same MissingError with the same fix; any other
// failure of the read is none.
func TestPveshsMissingHandlerIsAMissingSDNAPI(t *testing.T) {
	missing := MissingFromPvesh("No 'get' handler defined for '/cluster/sdn/zones'")
	if missing == nil {
		t.Fatal("pvesh's missing handler is not a MissingError")
	}
	if got, want := missing.Problem(), "this node has no SDN API (pvesh get /cluster/sdn/zones on the node: No 'get' handler defined): the package libpve-network-perl is not installed"; got != want {
		t.Errorf("Problem = %q\nwant      %q", got, want)
	}
	if !strings.HasSuffix(missing.Error(), MissingFix) || missing.Unwrap() != nil {
		t.Errorf("Error = %q, Unwrap = %v", missing.Error(), missing.Unwrap())
	}
	for _, other := range []string{"", "ipcc_send_rec[1] failed: Connection refused", "unable to load PVE::API2"} {
		if got := MissingFromPvesh(other); got != nil {
			t.Errorf("%q = %v, want no MissingError", other, got)
		}
	}
}

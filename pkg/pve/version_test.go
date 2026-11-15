// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// PVE answers GET /api2/json/version with the version, the release and the
// repository ID; Version reads the first and sends the token like any call.
func TestVersionReadsWhatPVEReports(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"PVE 9", `{"data":{"version":"9.1.1","release":"9.1","repoid":"42a4c9c7"}}`, "9.1.1"},
		{"PVE 8", `{"data":{"version":"8.4.0","release":"8.4","repoid":"ec5affc9e41f1d79"}}`, "8.4.0"},
		{"padded", `{"data":{"version":" 8.4.1\n"}}`, "8.4.1"},
		{"no version", `{"data":{"release":"9.1"}}`, ""},
		{"no data", `{"data":null}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api2/json/version" || r.Method != http.MethodGet {
					t.Errorf("request = %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "PVEAPIToken=certistack@pve!doctor=secret" {
					t.Errorf("authorization = %q", got)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client := NewClient(Config{BaseURL: server.URL, TokenID: "certistack@pve!doctor", TokenSecret: "secret"})
			got, err := client.Version(context.Background())
			if err != nil || got != tc.want {
				t.Fatalf("Version = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestVersionReportsAnUnreachableOrRefusingNode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no ticket", http.StatusUnauthorized)
	}))
	client := NewClient(Config{BaseURL: server.URL, TokenID: "certistack@pve!doctor", TokenSecret: "wrong"})
	client.retryDelays = []time.Duration{} // a refused connection is retried; this test does not wait for it
	if _, err := client.Version(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("Version against a refusing node = %v, want its 401", err)
	}
	server.Close()
	if got, err := client.Version(context.Background()); err == nil || got != "" {
		t.Fatalf("Version against a closed node = %q, %v", got, err)
	}
}

// A diagnostic asks for no retries: a transient failure is its answer at once,
// where a run would wait about 17 seconds for the node to recover.
func TestNoRetryFailsOnTheFirstTransientFailure(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.Error(w, "busy", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := NewClient(Config{BaseURL: server.URL, TokenID: "certistack@pve!doctor", TokenSecret: "secret", NoRetry: true})
	if _, err := client.Version(context.Background()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("Version = %v, want the node's 503", err)
	}
	if hits != 1 {
		t.Fatalf("the node was asked %d times, want 1", hits)
	}
}

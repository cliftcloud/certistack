// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cliftcloud/certistack/pkg/probe/synthetic"
)

// loadProbe runs validPlan with probe as its only probe through the full
// YAML loader and returns the loaded probe.
func loadProbe(t *testing.T, probe Probe) (Probe, error) {
	t.Helper()
	plan := validPlan()
	plan.Tiers[0].VMs[0].Probes = []Probe{probe}
	data, err := yaml.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFromReader(bytes.NewReader(data))
	if err != nil {
		return Probe{}, err
	}
	return loaded.Tiers[0].VMs[0].Probes[0], nil
}

// The url shorthand keeps the whole request target, not only the decoded
// path, which would request another resource: the query dropped and %2F, %3F,
// %23 and %25 decoded. Five such URLs, plus plain controls. The loaded path
// must be the URL's request target as written, identical to the explicit path
// form, and the prober must send exactly it: the fixture server fails every
// target but the intended one.
func TestHTTPURLKeepsTheRequestTargetAsWritten(t *testing.T) {
	for _, tc := range []struct{ suffix, target string }{
		{"/health?check=database&mode=deep", "/health?check=database&mode=deep"},
		{"/tenant/a%2Fb/health", "/tenant/a%2Fb/health"},
		{"/health%3Fcheck=database", "/health%3Fcheck=database"},
		{"/health%23database", "/health%23database"},
		{"/health%252Fdatabase", "/health%252Fdatabase"},
		{"/health", "/health"},
		{"?probe=1", "/?probe=1"},
		{"", "/"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			viaURL, err := loadProbe(t, Probe{Type: "http", URL: "http://10.100.0.10:8080" + tc.suffix, ExpectedStatus: 200, TimeoutSec: 1})
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if viaURL.TargetIP != "10.100.0.10" || viaURL.Port != 8080 || viaURL.TLS || viaURL.Path != tc.target {
				t.Fatalf("url expanded to %s:%d tls=%v path %q, want 10.100.0.10:8080 path %q", viaURL.TargetIP, viaURL.Port, viaURL.TLS, viaURL.Path, tc.target)
			}
			explicit, err := loadProbe(t, Probe{Type: "http", TargetIP: "10.100.0.10", Port: 8080, Path: tc.target, ExpectedStatus: 200, TimeoutSec: 1})
			if err != nil || explicit.Path != viaURL.Path {
				t.Fatalf("explicit path %q loaded as %q (%v); the url gave %q", tc.target, explicit.Path, err, viaURL.Path)
			}

			var mu sync.Mutex
			var seen []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen = append(seen, r.RequestURI)
				mu.Unlock()
				if r.RequestURI == tc.target {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			port := server.Listener.Addr().(*net.TCPAddr).Port
			res := synthetic.NewHTTPProber("127.0.0.1", port, viaURL.Path, viaURL.TLS, false, viaURL.ExpectedStatus, time.Second, viaURL.Description, "").Probe(ctx)
			if res.Passed {
				t.Fatalf("probe passed on a request for another resource: %+v", res)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(seen) == 0 {
				t.Fatal("no request reached the server")
			}
			for _, uri := range seen {
				if uri != tc.target {
					t.Fatalf("server saw %q, want %q", uri, tc.target)
				}
			}
		})
	}
}

// A url that cannot stand for exactly one request, or that disagrees
// with a field the probe also sets, is rejected with the reason instead of
// being expanded partly or silently overriding the field.
func TestHTTPURLRejectsWhatItCannotRequestExactly(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		probe      Probe
	}{
		// Four schemes that must not be sent as plaintext HTTP.
		{"another scheme", "absolute http:// or https:// URL", Probe{URL: "ftp://10.100.0.10/health"}},
		{"gopher", "absolute http:// or https:// URL", Probe{URL: "gopher://10.100.0.10:70/health"}},
		{"ws", "absolute http:// or https:// URL", Probe{URL: "ws://10.100.0.10/health"}},
		{"wss, which is not a promise of TLS", "absolute http:// or https:// URL", Probe{URL: "wss://10.100.0.10/health"}},
		{"an upper-case scheme that is not http", "absolute http:// or https:// URL", Probe{URL: "FTP://10.100.0.10/health"}},
		{"no scheme", "absolute http:// or https:// URL", Probe{URL: "10.100.0.10/health"}},
		{"no host", "absolute http:// or https:// URL", Probe{URL: "http:///health"}},
		{"user information", "must not carry user information", Probe{URL: "http://monitor:s3cret@10.100.0.10/health"}},
		{"fragment", "#fragment", Probe{URL: "http://10.100.0.10/health#database"}},
		{"empty fragment", "#fragment", Probe{URL: "http://10.100.0.10/health#"}},
		{"space in the query", "space in its query", Probe{URL: "http://10.100.0.10/health?check=a b"}},
		{"an escape and a character that needs encoding", "would be sent as \"/a/b%20c\"", Probe{URL: "http://10.100.0.10/a%2Fb c"}},
		{"bad escape", "is not a valid URL", Probe{URL: "http://10.100.0.10/health%zz"}},
		{"port zero", "invalid port", Probe{URL: "http://10.100.0.10:0/health"}},
		{"port too large", "invalid port", Probe{URL: "http://10.100.0.10:70000/health"}},
		{"another port", "names port 8080, but port is 9090", Probe{URL: "http://10.100.0.10:8080/health", Port: 9090}},
		{"default port and another port", "names port 80, but port is 8080", Probe{URL: "http://10.100.0.10/health", Port: 8080}},
		{"another path", "names path \"/health\", but path is \"/other\"", Probe{URL: "http://10.100.0.10/health", Path: "/other"}},
		{"http with tls", "tls is true", Probe{URL: "http://10.100.0.10/health", TLS: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.probe.Type, tc.probe.ExpectedStatus, tc.probe.TimeoutSec = "http", 200, 1
			_, err := loadProbe(t, tc.probe)
			var errs ValidationErrors
			if !errors.As(err, &errs) {
				t.Fatalf("load error = %v, want validation errors", err)
			}
			if !hasFieldError(errs, "tiers[0].vms[0].probes[0].url") || !strings.Contains(validationFields(errs), tc.want) {
				t.Fatalf("errors:\n%s\nwant one on probes[0].url mentioning %q", validationFields(errs), tc.want)
			}
			if strings.Contains(validationFields(errs), "s3cret") {
				t.Fatalf("validation error repeats the URL's password:\n%s", validationFields(errs))
			}
		})
	}
}

// Fields that agree with the url are accepted, and https implies port 443.
func TestHTTPURLAcceptsAgreeingFields(t *testing.T) {
	for _, probe := range []Probe{
		{URL: "https://10.100.0.10/health?deep=1", Port: 443, TLS: true, Path: "/health?deep=1"},
		{URL: "https://10.100.0.10/health", ServerName: "app.certistack.test"},
		{URL: "HTTP://10.100.0.10:8080/health", Port: 8080},
		{URL: "http://10.100.0.10/health check", Path: "/health check"},
		{URL: "http://10.100.0.10/café?q=café"},
	} {
		probe.Type, probe.ExpectedStatus, probe.TimeoutSec = "http", 200, 1
		loaded, err := loadProbe(t, probe)
		if err != nil {
			t.Errorf("%s: %v", probe.URL, err)
			continue
		}
		if want := strings.HasPrefix(probe.URL, "https"); loaded.TLS != want || (want && loaded.Port != 443) {
			t.Errorf("%s loaded as port %d tls=%v", probe.URL, loaded.Port, loaded.TLS)
		}
	}
}

// The explicit path is the request target too, so it must reach the server as
// written: the prober refuses the same paths at run time. A path with no
// percent-escapes still loads when it has a space or an accented letter, which
// are sent in the standard percent-encoding.
func TestHTTPProbePathMustBeSendableAsWritten(t *testing.T) {
	for path, ok := range map[string]bool{
		"":                             true,
		"healthz":                      true,
		"/health?check=db&x=%2F":       true,
		"/tenant/a%2Fb/health":         true,
		"/health check":                true,
		"/café":                        true,
		"/a\"b":                        true,
		"/health?q=café":               true,
		"/health#database":             false,
		"/a%2Fb c":                     false,
		"/café%2F":                     false,
		"/health?check=a b":            false,
		"/health%zz":                   false,
		"/health?check=database\tdeep": false,
	} {
		_, err := loadProbe(t, Probe{Type: "http", TargetIP: "10.100.0.10", Port: 80, Path: path, ExpectedStatus: 200, TimeoutSec: 1})
		var errs ValidationErrors
		rejected := errors.As(err, &errs) && hasFieldError(errs, "tiers[0].vms[0].probes[0].path")
		if rejected == ok {
			t.Errorf("path %q: load error %v, want accepted=%v", path, err, ok)
		}
	}
}

// The worker reloads the controller's normalized plan: the expanded request
// target must survive that round trip unchanged.
func TestHTTPURLSurvivesTheWorkerPlan(t *testing.T) {
	plan := validPlan()
	plan.Tiers[0].VMs[0].Probes = []Probe{{Type: "http", URL: "http://10.100.0.10:8080/tenant/a%2Fb/health?deep=1", ExpectedStatus: 200, TimeoutSec: 1}}
	data, err := yaml.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	staged, err := MarshalWorkerPlan(loaded)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := LoadFromReaderForWorker(bytes.NewReader(staged))
	if err != nil {
		t.Fatalf("worker load: %v", err)
	}
	if got := worker.Tiers[0].VMs[0].Probes[0]; got.Path != "/tenant/a%2Fb/health?deep=1" || got.Port != 8080 || got.TargetIP != "10.100.0.10" {
		t.Fatalf("worker probe = %+v", got)
	}
}

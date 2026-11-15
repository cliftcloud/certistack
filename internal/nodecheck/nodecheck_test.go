// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodecheck

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pbs"
)

// probes returns probes that find every tool, reach PVE (version "9.0.3") and
// list two VMs, and count how often each is asked.
func probes() (Probes, *struct{ tools, pve, pbs int }) {
	var calls struct{ tools, pve, pbs int }
	return Probes{
		LookPath: func(name string) (string, error) { calls.tools++; return "/usr/bin/" + name, nil },
		PVEVersion: func(context.Context, Settings) (string, error) {
			calls.pve++
			return "9.0.3", nil
		},
		PBSBackups: func(context.Context, Settings) ([]pbs.VMBackups, error) {
			calls.pbs++
			return []pbs.VMBackups{{VMID: 100}, {VMID: 101}}, nil
		},
	}, &calls
}

func TestRunPassesEveryLayer(t *testing.T) {
	p, calls := probes()
	report := Run(context.Background(), Settings{PBSNamespace: "prod"}, p)
	if report.Failed() != nil || len(report.Layers) != 3 {
		t.Fatalf("report = %+v", report)
	}
	names := []string{report.Layers[0].Name, report.Layers[1].Name, report.Layers[2].Name}
	if strings.Join(names, " ") != "node_tools pve_api pbs" {
		t.Errorf("layers = %v", names)
	}
	if want := "the node reaches the PVE API and PVE accepts the token (Proxmox VE 9.0.3)"; report.Layers[1].Detail != want {
		t.Errorf("PVE detail = %q", report.Layers[1].Detail)
	}
	if want := `the PBS credential lists namespace "prod": 2 VMs have a complete backup`; report.Layers[2].Detail != want {
		t.Errorf("PBS detail = %q", report.Layers[2].Detail)
	}
	if calls.tools != len(Tools) || calls.pve != 1 || calls.pbs != 1 {
		t.Errorf("calls = %+v", *calls)
	}
}

// A layer that fails ends the report: the layers after it are not tried, so
// their credentials are not used against a node that cannot hold them.
func TestRunStopsAtTheFirstFailingLayer(t *testing.T) {
	// A missing tool: PVE and PBS are not asked.
	p, calls := probes()
	p.LookPath = func(name string) (string, error) {
		if name == "guestfish" {
			return "", errors.New("not found")
		}
		return "/usr/bin/" + name, nil
	}
	report := Run(context.Background(), Settings{}, p)
	failed := report.Failed()
	if failed == nil || failed.Name != LayerTools || failed.Code != CodeToolsMissing || len(report.Layers) != 1 {
		t.Fatalf("report = %+v", report)
	}
	if len(failed.Missing) != 1 || failed.Missing[0] != (Tool{Name: "guestfish", Package: "libguestfs-tools"}) {
		t.Errorf("missing = %+v", failed.Missing)
	}
	if calls.pve != 0 || calls.pbs != 0 {
		t.Errorf("a later layer was tried: %+v", *calls)
	}

	// A PVE failure: PBS is not asked.
	p, calls = probes()
	p.PVEVersion = func(context.Context, Settings) (string, error) { return "", errors.New("boom") }
	report = Run(context.Background(), Settings{}, p)
	if failed := report.Failed(); failed == nil || failed.Name != LayerPVE || len(report.Layers) != 2 || calls.pbs != 0 {
		t.Fatalf("report = %+v, calls %+v", report, *calls)
	}

	// A PBS failure is the last layer, with the client's own (withheld) words.
	p, _ = probes()
	p.PBSBackups = func(context.Context, Settings) ([]pbs.VMBackups, error) {
		return nil, errors.New("list PBS snapshots: exit status 255 (client output withheld; 38 bytes)")
	}
	report = Run(context.Background(), Settings{}, p)
	if failed := report.Failed(); failed == nil || failed.Name != LayerPBS || failed.Code != CodePBSFailed || !strings.Contains(failed.Detail, "exit status 255 (client output withheld; 38 bytes)") {
		t.Fatalf("report = %+v", report)
	}
}

func TestBackupCountWording(t *testing.T) {
	for n, want := range map[int]string{0: "no VM has a complete backup there yet", 1: "1 VM has a complete backup", 7: "7 VMs have a complete backup"} {
		if got := backupCount(n); got != want {
			t.Errorf("backupCount(%d) = %q, want %q", n, got, want)
		}
	}
}

// pveSettings points the real PVE client at a TLS test server, with that
// server's certificate as the CA the node trusts when trust is true.
func pveSettings(t *testing.T, server *httptest.Server, trust bool) Settings {
	t.Helper()
	s := Settings{PVEURL: server.URL, PVETokenID: "certistack-svc@pve!automation", PVETokenSecret: "the-secret"}
	if trust {
		path := filepath.Join(t.TempDir(), "pve-ca.pem")
		certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		if err := os.WriteFile(path, certificate, 0o600); err != nil {
			t.Fatal(err)
		}
		s.PVECAFile = path
	}
	return s
}

// The PVE layer classifies what the real client reports, from the errors' types
// and through its wrappers: a certificate signed by a CA the node does not
// trust is the one a stock Proxmox VE node gives until its CA is fetched.
func TestPVELayerClassifiesWhatTheRealClientReports(t *testing.T) {
	var (
		mu      sync.Mutex
		status  = http.StatusOK
		version = `{"data":{"version":"9.0.3"}}`
		hits    int
	)
	answer := func(code int, body string) {
		mu.Lock()
		defer mu.Unlock()
		status, version, hits = code, body, 0
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken=certistack-svc@pve!automation=the-secret" {
			t.Errorf("the token was not sent as PVE expects: %q", r.Header.Get("Authorization"))
		}
		mu.Lock()
		hits++
		code, body := status, version
		mu.Unlock()
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	p := DefaultProbes()

	// The CA is trusted: PVE answers.
	got, err := p.PVEVersion(context.Background(), pveSettings(t, server, true))
	if err != nil || got != "9.0.3" {
		t.Fatalf("trusted CA: %q, %v", got, err)
	}

	// No CA: the certificate is signed by an authority the node does not trust.
	_, err = p.PVEVersion(context.Background(), pveSettings(t, server, false))
	if err == nil {
		t.Fatal("an untrusted certificate was accepted")
	}
	if code, detail := ClassifyPVE(err); code != CodePVECAUntrusted || !strings.Contains(detail, "certificate signed by unknown authority") {
		t.Errorf("untrusted CA classified as %q: %s (%v)", code, detail, err)
	}

	// The CA is trusted but the URL names another host than the certificate does.
	s := pveSettings(t, server, true)
	s.PVEURL = strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	_, err = p.PVEVersion(context.Background(), s)
	if code, detail := ClassifyPVE(err); code != CodePVECertName || !strings.Contains(detail, "localhost") {
		t.Errorf("wrong host classified as %q: %s (%v)", code, detail, err)
	}

	// PVE rejects the token.
	answer(http.StatusUnauthorized, `{"data":null,"message":"invalid token"}`)
	_, err = p.PVEVersion(context.Background(), pveSettings(t, server, true))
	if code, _ := ClassifyPVE(err); code != CodePVEAuth {
		t.Errorf("a rejected token classified as %q (%v)", code, err)
	}
	answer(http.StatusForbidden, `{"data":null}`)
	_, err = p.PVEVersion(context.Background(), pveSettings(t, server, true))
	if code, _ := ClassifyPVE(err); code != CodePVEForbidden {
		t.Errorf("a forbidden token classified as %q (%v)", code, err)
	}

	// A server error is reported with PVE's words, and retried not at all.
	answer(http.StatusServiceUnavailable, `{"message":"busy"}`)
	_, err = p.PVEVersion(context.Background(), pveSettings(t, server, true))
	mu.Lock()
	defer mu.Unlock()
	if err == nil || hits != 1 {
		t.Errorf("a transient failure: %v after %d request(s), want one", err, hits)
	}
}

func TestPVELayerReportsAnUnreachableOrMisconfiguredAPI(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	settings := pveSettings(t, server, true)
	server.Close() // nothing listens any more
	_, err := DefaultProbes().PVEVersion(context.Background(), settings)
	if code, detail := ClassifyPVE(err); code != CodePVEUnreachable || !strings.Contains(detail, "cannot reach the PVE API") {
		t.Errorf("a closed server classified as %q: %s (%v)", code, detail, err)
	}

	for name, s := range map[string]Settings{
		"a URL with a path": {PVEURL: "https://pve.example:8006/api", PVETokenID: "a@pve!b", PVETokenSecret: "x"},
		"no URL":            {PVETokenID: "a@pve!b", PVETokenSecret: "x"},
		"a CA file that is not there": {PVEURL: "https://pve.example:8006", PVETokenID: "a@pve!b", PVETokenSecret: "x",
			PVECAFile: filepath.Join(t.TempDir(), "missing.pem")},
		"plain HTTP": {PVEURL: "http://pve.example:8006", PVETokenID: "a@pve!b", PVETokenSecret: "x"},
	} {
		_, err := DefaultProbes().PVEVersion(context.Background(), s)
		if code, _ := ClassifyPVE(err); err == nil || code != CodePVEConfig {
			t.Errorf("%s: classified as %q (%v)", name, code, err)
		}
	}
}

func TestClassifyPVEUsesTypesNotText(t *testing.T) {
	// A message that merely mentions the words is not a certificate failure.
	if code, _ := ClassifyPVE(errors.New("something about certificate signed by unknown authority")); code != CodePVEOther {
		t.Errorf("a look-alike message classified as %q", code)
	}
	urlErr := &url.Error{Op: "Get", URL: "https://pve:8006/api2/json/version", Err: errors.New("dial tcp 192.0.2.10:8006: connect: connection refused")}
	code, detail := ClassifyPVE(urlErr)
	if code != CodePVEUnreachable || !strings.Contains(detail, "connection refused") || strings.Contains(detail, "/api2/json") {
		t.Errorf("classified as %q: %s", code, detail)
	}
	if code, _ := ClassifyPVE(context.DeadlineExceeded); code != CodePVEUnreachable {
		t.Errorf("a timeout classified as %q", code)
	}
}

func TestNoCredentialReachesAReport(t *testing.T) {
	p, _ := probes()
	p.PBSBackups = func(context.Context, Settings) ([]pbs.VMBackups, error) {
		return nil, errors.New("list PBS snapshots: exit status 255 (client output withheld; 12 bytes)")
	}
	s := Settings{PVETokenSecret: "PVE-SECRET-VALUE", PBSPassword: "PBS-SECRET-VALUE", PBSRepository: "user@pbs!tok@host:8007:ds"}
	for _, layer := range Run(context.Background(), s, p).Layers {
		if strings.Contains(layer.Detail, "SECRET-VALUE") {
			t.Errorf("layer %s holds a secret: %q", layer.Name, layer.Detail)
		}
	}
}

// A caller with no token to offer asks to stop after a layer: the layers beyond
// it are not tried, and a failure before it still ends the report there.
func TestRunThroughStopsAfterTheNamedLayer(t *testing.T) {
	p, calls := probes()
	report := RunThrough(context.Background(), Settings{}, p, LayerTools)
	if report.Failed() != nil || len(report.Layers) != 1 || report.Layers[0].Name != LayerTools {
		t.Fatalf("report = %+v", report)
	}
	if calls.pve != 0 || calls.pbs != 0 {
		t.Errorf("a layer beyond the named one was tried: %+v", *calls)
	}

	p, calls = probes()
	if report := RunThrough(context.Background(), Settings{}, p, LayerPVE); len(report.Layers) != 2 || calls.pbs != 0 {
		t.Errorf("through pve_api: %+v, calls %+v", report, *calls)
	}

	// A failure before the named layer is the report's end.
	p, calls = probes()
	p.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	if report := RunThrough(context.Background(), Settings{}, p, LayerPBS); report.Failed() == nil || len(report.Layers) != 1 || calls.pve != 0 {
		t.Errorf("a failing tools layer: %+v", report)
	}

	// An unknown name, like none, tries every layer.
	p, _ = probes()
	if report := RunThrough(context.Background(), Settings{}, p, ""); len(report.Layers) != 3 {
		t.Errorf("no layer named: %+v", report)
	}
}

// With no namespace set, an empty list is the commonest sign that the backups
// are in a namespace: the layer still passes (the credential lists the
// repository), and its line says what to try (CR2-09). init gives the same hint.
func TestPBSLayerHintsAtTheNamespaceWhenNoVMIsListedAndNoneIsSet(t *testing.T) {
	const hint = " (if your backups are in a namespace, set PBS_NAMESPACE)"
	for name, tc := range map[string]struct {
		namespace string
		vms       int
		want      string
	}{
		"nothing listed, no namespace":   {"", 0, "the PBS credential lists the repository: no VM has a complete backup there yet" + hint},
		"nothing listed, a namespace":    {"prod", 0, `the PBS credential lists namespace "prod": no VM has a complete backup there yet`},
		"VMs listed, no namespace":       {"", 2, "the PBS credential lists the repository: 2 VMs have a complete backup"},
		"one VM listed, a namespace set": {"prod", 1, `the PBS credential lists namespace "prod": 1 VM has a complete backup`},
	} {
		p, _ := probes()
		p.PBSBackups = func(context.Context, Settings) ([]pbs.VMBackups, error) {
			backups := make([]pbs.VMBackups, tc.vms)
			for i := range backups {
				backups[i] = pbs.VMBackups{VMID: 100 + i}
			}
			return backups, nil
		}
		layer := checkPBS(context.Background(), Settings{PBSNamespace: tc.namespace}, p)
		if layer.Status != StatusPassed || layer.Detail != tc.want {
			t.Errorf("%s: layer = %s %q, want passed %q", name, layer.Status, layer.Detail, tc.want)
		}
	}
}

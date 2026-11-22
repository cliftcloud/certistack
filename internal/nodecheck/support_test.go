// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodecheck

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/sdn"
)

// A proxmox-backup-client older than the release supports (PVE 8.0 ships
// 2.99) fails the tools layer, as plan and run would refuse it; PVE and PBS are
// not asked. A supported client, and one whose version cannot be read, pass.
func TestToolsLayerHoldsTheClientToTheSupportedVersions(t *testing.T) {
	for name, tc := range map[string]struct {
		version string
		err     error
		fails   bool
	}{
		"2.99 from PVE 8.0": {version: "2.99.0", fails: true},
		"3.x":               {version: "3.2.9"},
		"4.x":               {version: "4.2.0"},
		"not readable":      {err: errors.New("exit status 1")},
		"not a version":     {version: "garbage"},
	} {
		t.Run(name, func(t *testing.T) {
			p, calls := probes()
			p.ClientVersion = func(context.Context) (string, error) { return tc.version, tc.err }
			report := Run(context.Background(), Settings{}, p)
			failed := report.Failed()
			if !tc.fails {
				if failed != nil || len(report.Layers) != 3 {
					t.Fatalf("report = %+v", report)
				}
				return
			}
			if failed == nil || failed.Name != LayerTools || failed.Code != CodeClientUnsupported || len(report.Layers) != 1 {
				t.Fatalf("report = %+v", report)
			}
			if want := "proxmox-backup-client 2.99.0 is older than proxmox-backup-client 3, the oldest this release supports"; !strings.Contains(failed.Detail, want) {
				t.Errorf("detail = %q, want it to say %q", failed.Detail, want)
			}
			if calls.pve != 0 || calls.pbs != 0 {
				t.Errorf("a later layer was tried: %+v", *calls)
			}
		})
	}

	// A caller with no token stops after the tools, and the client is still
	// held to the supported versions.
	p, _ := probes()
	p.ClientVersion = func(context.Context) (string, error) { return "2.99.0", nil }
	if failed := RunThrough(context.Background(), Settings{}, p, LayerTools).Failed(); failed == nil || failed.Code != CodeClientUnsupported {
		t.Errorf("through node_tools: %+v", failed)
	}
}

// A Proxmox VE release older than the release supports fails the PVE layer.
func TestPVELayerRefusesAnUnsupportedRelease(t *testing.T) {
	p, calls := probes()
	p.PVEVersion = func(context.Context, Settings) (string, error) { return "7.4-3", nil }
	report := Run(context.Background(), Settings{}, p)
	failed := report.Failed()
	if failed == nil || failed.Name != LayerPVE || failed.Code != CodePVEUnsupported || calls.pbs != 0 {
		t.Fatalf("report = %+v", report)
	}
	if !strings.Contains(failed.Detail, "PVE 7.4-3 is older than PVE 8") {
		t.Errorf("detail = %q", failed.Detail)
	}
}

// pveWithoutSDN is a PVE 8.0 node without libpve-network-perl, over TLS: it
// answers the version, and the SDN list with HTTP 501, {"data":null} and its
// message in the status line (written by hand: net/http cannot set a reason
// phrase).
func pveWithoutSDN(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/version" {
			_, _ = w.Write([]byte(`{"data":{"version":"8.1.3"}}`))
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		writeStatusLine(buf, "501 Method 'GET "+strings.TrimPrefix(r.URL.Path, "/api2/json")+"' not implemented", `{"data":null}`)
	}))
	t.Cleanup(server.Close)
	return server
}

func writeStatusLine(buf *bufio.ReadWriter, statusLine, body string) {
	fmt.Fprintf(buf, "HTTP/1.1 %s\r\nContent-Type: application/json;charset=UTF-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", statusLine, len(body), body)
	_ = buf.Flush()
}

// On a node whose PVE has no SDN API, init and every run fail at their first
// SDN read: the PVE layer reads the SDN lists too, and fails with what is
// missing. PBS is not asked.
func TestPVELayerFailsANodeWithoutTheSDNAPI(t *testing.T) {
	server := pveWithoutSDN(t)
	p := DefaultProbes()
	p.LookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	p.ClientVersion = nil
	asked := false
	p.PBSBackups = func(context.Context, Settings) ([]pbs.VMBackups, error) { asked = true; return nil, nil }

	report := Run(context.Background(), pveSettings(t, server, true), p)
	failed := report.Failed()
	if failed == nil || failed.Name != LayerPVE || failed.Code != CodePVESDNMissing || asked {
		t.Fatalf("report = %+v, PBS asked: %v", report, asked)
	}
	for _, want := range []string{"PVE accepts the token (Proxmox VE 8.1.3)", "no SDN API", "GET /cluster/sdn/zones", "HTTP 501", "libpve-network-perl"} {
		if !strings.Contains(failed.Detail, want) {
			t.Errorf("detail does not say %q: %q", want, failed.Detail)
		}
	}
}

// Any other failure of the SDN read fails the layer too, with PVE's words: init
// and a run would stop on it.
func TestPVELayerReportsAnSDNReadThatFails(t *testing.T) {
	p, calls := probes()
	p.PVESDN = func(context.Context, Settings) error {
		return errors.New("PVE's answer to a read of cluster/sdn/zones is not a list")
	}
	report := Run(context.Background(), Settings{}, p)
	failed := report.Failed()
	if failed == nil || failed.Name != LayerPVE || failed.Code != CodePVEOther || calls.pbs != 0 {
		t.Fatalf("report = %+v", report)
	}
	if !strings.Contains(failed.Detail, "its SDN zones and VNets could not be read: PVE's answer to a read of cluster/sdn/zones is not a list") {
		t.Errorf("detail = %q", failed.Detail)
	}

	// A node with SDN passes.
	p, _ = probes()
	p.PVESDN = func(context.Context, Settings) error { return nil }
	if report := Run(context.Background(), Settings{}, p); report.Failed() != nil {
		t.Errorf("report = %+v", report)
	}
}

// What setup reads over SSH before its first change is judged as check's
// layers judge it, in check's order: the client (tools layer), then the PVE
// release or else its SDN API (PVE layer), each with check's code and reason.
// A version that cannot be read and an SDN read that showed nothing refuse
// nothing.
func TestRefusalsJudgeWhatSetupReadsAsCheckDoes(t *testing.T) {
	noSDN := sdn.MissingFromPvesh("No 'get' handler defined for '/cluster/sdn/zones'")
	for name, tc := range map[string]struct {
		client, pve string
		sdn         *sdn.MissingError
		want        []string // name:code
	}{
		"supported":       {client: "3.1.2", pve: "8.1.3"},
		"nothing read":    {},
		"client 2.99":     {client: "2.99.0", pve: "8.1.3", want: []string{LayerTools + ":" + CodeClientUnsupported}},
		"PVE 8.0":         {client: "3.0.1", pve: "8.0.3", want: []string{LayerPVE + ":" + CodePVEUnsupported}},
		"no SDN":          {client: "3.1.2", pve: "8.1.3", sdn: noSDN, want: []string{LayerPVE + ":" + CodePVESDNMissing}},
		"PVE 8.0 as is":   {client: "2.99.0", pve: "8.0.3", sdn: noSDN, want: []string{LayerTools + ":" + CodeClientUnsupported, LayerPVE + ":" + CodePVEUnsupported}},
		"unreadable, SDN": {client: "garbage", pve: "", sdn: noSDN, want: []string{LayerPVE + ":" + CodePVESDNMissing}},
	} {
		t.Run(name, func(t *testing.T) {
			var got []string
			for _, layer := range Refusals(tc.client, tc.pve, tc.sdn) {
				got = append(got, layer.Name+":"+layer.Code)
				if layer.Status != StatusFailed || layer.Detail == "" {
					t.Errorf("layer %+v", layer)
				}
				switch layer.Code {
				case CodeClientUnsupported:
					if layer.Detail != ClientRefusal(tc.client) {
						t.Errorf("client reason %q", layer.Detail)
					}
				case CodePVEUnsupported:
					if layer.Detail != PVERefusal(tc.pve) {
						t.Errorf("PVE reason %q", layer.Detail)
					}
				case CodePVESDNMissing:
					if layer.Detail != tc.sdn.Problem() {
						t.Errorf("SDN reason %q", layer.Detail)
					}
				}
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("Refusals = %v, want %v", got, tc.want)
			}
		})
	}
}

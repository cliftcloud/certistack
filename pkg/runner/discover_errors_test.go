// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/sdn"
)

// pveAnswering is a PVE over TLS that answers every request with the status
// line and body, written by hand (PVE puts its message in the reason phrase,
// which net/http cannot set), and the environment Discover reads to reach it.
func pveAnswering(t *testing.T, statusLine, body string) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ca := filepath.Join(t.TempDir(), "pve-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PVE_URL", server.URL)
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", ca)
	t.Setenv("PVE_TLS_INSECURE", "")
	t.Setenv("PVE_TOKEN_ID", "certistack-svc@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "the-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!token@pbs.example:store")
	t.Setenv("PBS_PASSWORD", "unused")
}

// discoverReading runs Discover with a discovery that makes one read of PVE.
func discoverReading(t *testing.T, read func(context.Context, initplan.Cluster) error) error {
	t.Helper()
	previous := initplanDiscover
	t.Cleanup(func() { initplanDiscover = previous })
	initplanDiscover = func(ctx context.Context, _ initplan.Backups, cluster initplan.Cluster, req initplan.Request, _ string) (*initplan.Discovery, error) {
		return &initplan.Discovery{Node: req.Node}, read(ctx, cluster)
	}
	_, err := Discover(context.Background(), initplan.Request{Node: "pve80", VMIDs: []int{100}}, "")
	return err
}

// init's error names the PVE request that failed, so that a reader (and
// --debug) can tell which call PVE refused.
func TestDiscoverNamesThePVECallThatFailed(t *testing.T) {
	pveAnswering(t, "403 Permission check failed (/storage, Datastore.Audit)", `{"data":null}`)
	err := discoverReading(t, func(ctx context.Context, cluster initplan.Cluster) error {
		_, err := cluster.ListNodeStorages(ctx, "pve80")
		return err
	})
	if err == nil || !strings.HasPrefix(err.Error(), "GET /nodes/pve80/storage") || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("Discover = %v, want PVE's error after the call it refused", err)
	}
	var apiErr *pve.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("PVE's error is not wrapped: %v", err)
	}
}

// A PVE without the SDN API answers init's read of the zones with HTTP 501: the
// error says what is missing and how to fix it, and names the call once.
func TestDiscoverSaysWhatANodeWithoutSDNLacks(t *testing.T) {
	pveAnswering(t, "501 Method 'GET /cluster/sdn/zones' not implemented", `{"data":null}`)
	err := discoverReading(t, func(ctx context.Context, cluster initplan.Cluster) error {
		_, err := cluster.UsedSDNIDs(ctx)
		return err
	})
	var missing *sdn.MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("Discover = %v, want a missing SDN API", err)
	}
	text := err.Error()
	for _, want := range []string{"no SDN API", "libpve-network-perl", sdn.MissingFix} {
		if !strings.Contains(text, want) {
			t.Errorf("the error does not say %q: %s", want, text)
		}
	}
	if n := strings.Count(text, "GET /cluster/sdn/zones"); n != 1 {
		t.Errorf("the call is named %d times: %s", n, text)
	}
	if strings.HasPrefix(text, "PVE API error") {
		t.Errorf("the error is the bare HTTP status: %s", text)
	}
}

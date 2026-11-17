// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The endpoint's host name is redacted from an error's display text. A node
// named like that host (PVE_URL=https://pve:8006 and a node "pve", or a
// cluster alias "pve" over nodes "pve-01"...) must still be recognized when
// PVE says its VM does not exist: the match reads the message as PVE wrote it,
// and the display text stays redacted.
func TestVMNotFoundIsRecognizedWhenTheEndpointHostIsTheNodeName(t *testing.T) {
	for _, node := range []string{"pve", "pve-01"} {
		t.Run(node, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"data":null,"message":"Configuration file 'nodes/` + node + `/qemu-server/9100.conf' does not exist\n"}`))
			}))
			defer server.Close()

			c := NewClient(Config{BaseURL: "https://pve:8006"})
			if c.initErr != nil {
				t.Fatal(c.initErr)
			}
			// Route "pve:8006" to the fake, as DNS would route it to the node.
			c.httpClient.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, server.Listener.Addr().String())
				},
			}
			c.retryDelays = []time.Duration{}

			_, err := c.GetVMStatus(context.Background(), node, 9100)
			if err == nil {
				t.Fatal("no error from PVE's answer")
			}
			if !IsVMNotFound(err, node, 9100) {
				t.Fatalf("PVE's own answer that VM 9100 on node %s does not exist is not recognized as absence: %v", node, err)
			}
			// Another VM, or another node, is still not this VM's absence.
			if IsVMNotFound(err, node, 9101) || IsVMNotFound(err, node+"x", 9100) {
				t.Fatalf("the answer about VM 9100 on %s was taken for another VM's or node's: %v", node, err)
			}
			// The text an operator sees keeps the host name redacted.
			if strings.Contains(err.Error(), "pve:8006") {
				t.Fatalf("the error text shows the endpoint: %v", err)
			}
		})
	}
}

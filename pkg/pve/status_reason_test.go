// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// replyWithStatusLine answers every request with the given status line and
// JSON body, written by hand: net/http's ResponseWriter cannot set a reason
// phrase, and PVE writes its error message there.
func replyWithStatusLine(t *testing.T, statusLine, body string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("the test server cannot hijack the connection")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		writeRaw(buf, statusLine, body)
	}))
}

func writeRaw(buf *bufio.ReadWriter, statusLine, body string) {
	fmt.Fprintf(buf, "HTTP/1.1 %s\r\nContent-Type: application/json;charset=UTF-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", statusLine, len(body), body)
	_ = buf.Flush()
}

func clientFor(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	c := NewClient(Config{BaseURL: "https://pve:8006"})
	if c.initErr != nil {
		t.Fatal(c.initErr)
	}
	c.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	c.retryDelays = []time.Duration{}
	return c
}

// PVE 8.0 to 8.3 answer a request about a VM that does not exist with HTTP 500,
// the body {"data":null}, and the message only in the status line. That is
// still PVE saying the VM does not exist, for that VM on that node only.
func TestVMNotFoundIsRecognizedFromTheStatusLine(t *testing.T) {
	server := replyWithStatusLine(t, "500 Configuration file 'nodes/pve83/qemu-server/9100.conf' does not exist", `{"data":null}`)
	defer server.Close()

	_, err := clientFor(t, server).GetVMStatus(context.Background(), "pve83", 9100)
	if err == nil {
		t.Fatal("no error from PVE's answer")
	}
	if !IsVMNotFound(err, "pve83", 9100) {
		t.Fatalf("PVE's status-line answer that VM 9100 does not exist is not recognized as absence: %v", err)
	}
	if IsVMNotFound(err, "pve83", 9101) || IsVMNotFound(err, "pve84", 9100) {
		t.Fatalf("the answer about VM 9100 on pve83 was taken for another VM's or node's: %v", err)
	}
}

// A 500 whose status line carries only the standard text, or another message,
// is not a VM's absence: the run must still refuse to go on.
func TestAPlainServerErrorIsNotAVMsAbsence(t *testing.T) {
	for name, line := range map[string]string{
		"standard text": "500 Internal Server Error",
		"other message": "500 unable to read file '/etc/pve/nodes/pve83/qemu-server/9100.conf'",
	} {
		t.Run(name, func(t *testing.T) {
			server := replyWithStatusLine(t, line, `{"data":null}`)
			defer server.Close()
			_, err := clientFor(t, server).GetVMStatus(context.Background(), "pve83", 9100)
			if err == nil {
				t.Fatal("no error from a server error")
			}
			if IsVMNotFound(err, "pve83", 9100) {
				t.Fatalf("%q was taken for the VM's absence", line)
			}
		})
	}
}

// An API error records the request PVE answered, for a caller to name the call;
// a lock token in the path is never kept, and Error does not repeat the call.
func TestAPIErrorNamesTheCall(t *testing.T) {
	server := replyWithStatusLine(t, "403 Permission check failed", `{"data":null}`)
	defer server.Close()
	client := clientFor(t, server)

	err := client.Do(context.Background(), "GET", "nodes/pve1/storage", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Call() != "GET /nodes/pve1/storage" {
		t.Fatalf("Do = %v, want an API error for GET /nodes/pve1/storage", err)
	}
	if strings.Contains(apiErr.Error(), "/nodes/pve1/storage") {
		t.Errorf("Error repeats the call: %q", apiErr.Error())
	}

	err = client.Do(context.Background(), "DELETE", "cluster/sdn/zones/z1?lock-token=SECRET-TOKEN", nil, nil)
	if !errors.As(err, &apiErr) || strings.Contains(apiErr.Call(), "SECRET-TOKEN") || !strings.HasPrefix(apiErr.Call(), "DELETE /cluster/sdn/zones/z1?lock-token=") {
		t.Errorf("Call = %q", apiErr.Call())
	}
	if (&APIError{StatusCode: 500}).Call() != "" {
		t.Error("an error the client did not make names a call")
	}
}

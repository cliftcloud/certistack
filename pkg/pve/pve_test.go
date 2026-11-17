// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClient_Do_TrustsConfiguredPrivateCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`{"version":"8.4"}`)})
	}))
	defer server.Close()

	caPath := t.TempDir() + "/pve-ca.pem"
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, pemData, 0600); err != nil {
		t.Fatal(err)
	}

	client := NewClient(Config{BaseURL: server.URL, TLSCAFile: caPath})
	var result struct {
		Version string `json:"version"`
	}
	if err := client.Do(context.Background(), "GET", "version", nil, &result); err != nil {
		t.Fatalf("trusted private CA request failed: %v", err)
	}
	if result.Version != "8.4" {
		t.Fatalf("version = %q", result.Version)
	}
}

func TestClient_Do_RejectsInvalidTLSConfigurationBeforeRequest(t *testing.T) {
	client := NewClient(Config{
		BaseURL:     "https://pve.example.test:8006",
		TLSInsecure: true,
		TLSCAFile:   "/etc/certistack/pve-ca.pem",
	})
	if err := client.Do(context.Background(), "GET", "version", nil, nil); err == nil || !strings.Contains(err.Error(), "both TLSInsecure and TLSCAFile") {
		t.Fatalf("expected conflicting TLS settings to fail, got %v", err)
	}
}

// Every caller that honours PVE_TLS_INSECURE (preflight, doctor, recovery, the
// runner) builds its client here, so the lab opt-in must stop the token from
// leaving the process before any connection is made.
func TestClient_Do_InsecureTLSRequiresLabOptInBeforeRequest(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`{"version":"8.4"}`)})
	}))
	defer server.Close()

	for _, optIn := range []string{"", "false", "yes"} {
		t.Setenv(InsecureTLSLabOptInEnv, optIn)
		client := NewClient(Config{BaseURL: server.URL, TokenID: "certistack@pve!t", TokenSecret: "secret", TLSInsecure: true})
		if err := client.Do(context.Background(), "GET", "version", nil, nil); !errors.Is(err, ErrInsecureTLSForbidden) {
			t.Fatalf("opt-in %q: error = %v, want ErrInsecureTLSForbidden", optIn, err)
		}
	}
	if requests != 0 {
		t.Fatalf("insecure client without the lab opt-in sent %d request(s)", requests)
	}

	t.Setenv(InsecureTLSLabOptInEnv, "true")
	client := NewClient(Config{BaseURL: server.URL, TokenID: "certistack@pve!t", TokenSecret: "secret", TLSInsecure: true})
	if err := client.Do(context.Background(), "GET", "version", nil, nil); err != nil {
		t.Fatalf("insecure client with the lab opt-in failed: %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
}

func TestClientRejectsUnsafePVEBaseURL(t *testing.T) {
	for _, rawURL := range []string{
		"",
		"pve.example.test:8006",
		"http://pve.example.test:8006",
		"ftp://pve.example.test:8006",
		"https://pve.example.test:8006/api2/json",
		"https://user@pve.example.test:8006",
		"https://pve.example.test:8006?debug=true",
	} {
		t.Run(rawURL, func(t *testing.T) {
			if err := NewClient(Config{BaseURL: rawURL}).initErr; err == nil {
				t.Fatalf("NewClient accepted unsafe PVE base URL %q", rawURL)
			}
		})
	}
	for _, rawURL := range []string{"https://pve.example.test:8006", "http://127.0.0.1:8006", "http://[::1]:8006", "http://localhost:8006"} {
		t.Run(rawURL, func(t *testing.T) {
			if err := NewClient(Config{BaseURL: rawURL}).initErr; err != nil {
				t.Fatalf("NewClient rejected allowed PVE base URL %q: %v", rawURL, err)
			}
		})
	}
}

func TestClient_IsCertiStackRunOwnedRequiresExactMarkers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`{"tags":"certistack,run-123","description":"CertiStack Ephemeral DR VM; owner=certistack; run_id=run-123"}`)})
	}))
	defer server.Close()

	client := NewClient(Config{BaseURL: server.URL})
	owned, err := client.IsCertiStackRunOwned(context.Background(), "pve1", 9001, "run-123")
	if err != nil || !owned {
		t.Fatalf("exact ownership check = %t, %v", owned, err)
	}
	owned, err = client.IsCertiStackRunOwned(context.Background(), "pve1", 9001, "run-124")
	if err != nil || owned {
		t.Fatalf("wrong run ID ownership check = %t, %v", owned, err)
	}
}

// The PVE 9 missing-configuration answer is absence of the VM it names,
// and of no other. A different VM's or node's message, a missing storage, and
// anything a proxy could wrap around the text are not this VM being gone.
func TestIsVMNotFoundIsExactToNodeAndVM(t *testing.T) {
	answer := func(status int, message string) error {
		return fmt.Errorf("status lookup: %w", &APIError{StatusCode: status, Message: message})
	}
	const missing = "Configuration file 'nodes/pve/qemu-server/9904.conf' does not exist"
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"this VM's missing configuration":                     {answer(500, missing), true},
		"with the /etc/pve prefix":                            {answer(500, "Configuration file '/etc/pve/nodes/pve/qemu-server/9904.conf' does not exist"), true},
		"HTTP 404 (not PVE's wording: see Client.VMNotFound)": {answer(404, "not found"), false},
		"another VM's configuration":                          {answer(500, "Configuration file 'nodes/pve/qemu-server/9999.conf' does not exist"), false},
		"a VMID that only starts the same":                    {answer(500, "Configuration file 'nodes/pve/qemu-server/99040.conf' does not exist"), false},
		"another node's configuration":                        {answer(500, "Configuration file 'nodes/pve2/qemu-server/9904.conf' does not exist"), false},
		"a node that only ends the same":                      {answer(500, "Configuration file 'nodes/xpve/qemu-server/9904.conf' does not exist"), false},
		"a container's configuration":                         {answer(500, "Configuration file 'nodes/pve/lxc/9904.conf' does not exist"), false},
		"a missing storage":                                   {answer(500, "storage 'local' does not exist"), false},
		"two files, one of them this VM's":                    {answer(500, missing+"; Configuration file 'nodes/pve/qemu-server/9999.conf' does not exist"), false},
		"text before the message":                             {answer(500, "proxy says: "+missing), false},
		"text after the message":                              {answer(500, missing+" (and more)"), false},
		"another case":                                        {answer(500, "configuration file 'nodes/pve/qemu-server/9904.conf' does not exist"), false},
		"the message inside a JSON body":                      {answer(500, `{"data":null,"message":"`+missing+`"}`), false},
		"a path that leaves the node directory":               {answer(500, "Configuration file 'nodes/pve/../pve2/qemu-server/9904.conf' does not exist"), false},
		"a generic HTTP 500":                                  {answer(500, "temporary backend error"), false},
		"the message with another status":                     {answer(403, missing), false},
		"not an API error":                                    {errors.New(missing), false},
		"no error":                                            {nil, false},
	} {
		if got := IsVMNotFound(tc.err, "pve", 9904); got != tc.want {
			t.Errorf("%s: IsVMNotFound = %v, want %v", name, got, tc.want)
		}
	}
	// IsNotFound alone is the HTTP 404, and says nothing of any 500.
	if !IsNotFound(answer(404, "x")) || IsNotFound(answer(500, missing)) {
		t.Error("IsNotFound must be the HTTP 404 alone")
	}
}

func TestClient_Do_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "PVEAPIToken=testuser!tokenid=secret123" {
			t.Errorf("unexpected auth header: %s", authHeader)
		}

		resp := APIResponse{
			Data: json.RawMessage(`{"status": "running", "vmid": 9001}`),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL:     server.URL,
		TokenID:     "testuser!tokenid",
		TokenSecret: "secret123",
	})

	var result struct {
		Status string `json:"status"`
		VMID   int    `json:"vmid"`
	}

	ctx := context.Background()
	err := client.Do(ctx, "GET", "nodes/pve1/qemu/9001/status/current", nil, &result)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if result.Status != "running" || result.VMID != 9001 {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestClient_IsVMIDInUseChecksClusterResources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/cluster/resources" || r.URL.Query().Get("type") != "vm" {
			t.Fatalf("unexpected cluster resource request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`[{"type":"qemu","vmid":9901,"node":"node2"}]`)})
	}))
	defer server.Close()

	client := NewClient(Config{BaseURL: server.URL})
	used, err := client.IsVMIDInUse(context.Background(), 9901)
	if err != nil || !used {
		t.Fatalf("cluster VMID lookup = used=%v, err=%v; want in use", used, err)
	}
	used, err = client.IsVMIDInUse(context.Background(), 9902)
	if err != nil || used {
		t.Fatalf("free cluster VMID lookup = used=%v, err=%v; want free", used, err)
	}
}

func TestClient_Do_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		resp := APIResponse{
			Errors: map[string]string{"vmid": "VM 9001 already exists"},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL: server.URL,
	})

	ctx := context.Background()
	err := client.Do(ctx, "POST", "nodes/pve1/qemu", map[string]interface{}{"vmid": 9001}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 400 {
		t.Errorf("expected status code 400, got %d", apiErr.StatusCode)
	}
	if apiErr.Errors["vmid"] != "VM 9001 already exists" {
		t.Errorf("expected error detail for vmid, got %v", apiErr.Errors)
	}
}

func TestClient_Do_APIErrorDoesNotExposeEndpointOrRawBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		endpoint := "http://" + r.Host + "/private?token=not-for-reports"
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": endpoint,
			"errors":  map[string]string{"detail": endpoint},
		})
	}))
	defer server.Close()

	client := NewClient(Config{BaseURL: server.URL + "/"})
	err := client.Do(context.Background(), "GET", "version", nil, nil)
	if err == nil {
		t.Fatal("expected endpoint-bearing API error")
	}
	if strings.Contains(err.Error(), server.URL) || strings.Contains(err.Error(), "token=not-for-reports") {
		t.Fatalf("PVE API error exposed endpoint or raw body: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED_ENDPOINT]") {
		t.Fatalf("PVE API error did not retain a redacted diagnostic: %v", err)
	}
}

// The keys of PVE's errors object are parameter names, and the response is the
// endpoint's to write: a key is as untrusted as a value. It must not reach the
// operator's terminal and the logs verbatim (control characters, an endpoint
// URL, any length), and thousands of them are not all kept and printed.
func TestClient_Do_APIErrorKeysAreSanitizedAndBounded(t *testing.T) {
	respond := func(t *testing.T, errorsObject map[string]string) (*APIError, string, *httptest.Server) {
		t.Helper()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "parameter verification failed", "errors": errorsObject})
		}))
		t.Cleanup(server.Close)
		err := NewClient(Config{BaseURL: server.URL}).Do(context.Background(), "POST", "nodes/pve1/qemu", map[string]any{"vmid": 9001}, nil)
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("err = %v, want an APIError", err)
		}
		return apiErr, err.Error(), server
	}
	hasControl := func(text string) bool {
		return strings.IndexFunc(text, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
	}

	t.Run("a key with control characters and an endpoint", func(t *testing.T) {
		endpointKey := "http://pve.example.internal:8006/api2/json/secret?token=not-for-reports"
		apiErr, text, server := respond(t, map[string]string{
			"vm\nSTOLEN LINE":         "first value",
			"\x1b[31mnet0\x1b[0m":     "second value",
			"bell\a\x00":              "third value",
			endpointKey:               "fourth value",
			"vmid":                    "VM 9001 already exists",
			strings.Repeat("k", 4096): "a very long key",
		})
		if hasControl(text) {
			t.Fatalf("the error carries a control character: %q", text)
		}
		if strings.Contains(text, "STOLEN LINE") || strings.Contains(text, "token=not-for-reports") || strings.Contains(text, "pve.example.internal") || strings.Contains(text, server.URL) {
			t.Fatalf("the error carries what a key's sanitising should drop: %q", text)
		}
		for key, value := range apiErr.Errors {
			if hasControl(key) || len(key) > maxAPIErrorMessage || len(value) > maxAPIErrorMessage {
				t.Errorf("details key %q (%d bytes) or its value (%d bytes) is not sanitised and bounded", key, len(key), len(value))
			}
		}
		if apiErr.Errors["vm"] != "first value" || apiErr.Errors["vmid"] != "VM 9001 already exists" || apiErr.Errors["[REDACTED_ENDPOINT]"] != "fourth value" {
			t.Fatalf("details = %v, want the sanitised keys with their values", apiErr.Errors)
		}
	})

	t.Run("thousands of keys are capped", func(t *testing.T) {
		many := make(map[string]string, 5000)
		for i := 0; i < 5000; i++ {
			many[fmt.Sprintf("param%04d", i)] = "bad value"
		}
		apiErr, text, _ := respond(t, many)
		if len(apiErr.Errors) != maxAPIErrorDetails {
			t.Fatalf("%d details kept, want %d", len(apiErr.Errors), maxAPIErrorDetails)
		}
		if len(text) > 16<<10 {
			t.Fatalf("the error is %d bytes long", len(text))
		}
		if !strings.Contains(text, "4980 more") {
			t.Fatalf("the error does not say how many details were left out: %q", text)
		}
		// The kept entries are the same ones whatever order the map is read in.
		again, _, _ := respond(t, many)
		for key := range apiErr.Errors {
			if _, same := again.Errors[key]; !same {
				t.Fatalf("the kept details differ between two identical responses: %q is missing", key)
			}
		}
	})

	t.Run("keys that collide after sanitising are merged", func(t *testing.T) {
		apiErr, _, _ := respond(t, map[string]string{
			"net0\nfirst":  "value one",
			"net0\nsecond": "value two",
			"net0\x00":     "value three",
			"net0":         "value one",
		})
		if len(apiErr.Errors) != 1 {
			t.Fatalf("details = %v, want the colliding keys merged into one", apiErr.Errors)
		}
		merged := apiErr.Errors["net0"]
		for _, want := range []string{"value one", "value two", "value three"} {
			if strings.Count(merged, want) != 1 {
				t.Fatalf("merged value %q does not carry %q exactly once", merged, want)
			}
		}
		many := make(map[string]string, 1000)
		for i := 0; i < 1000; i++ {
			many[fmt.Sprintf("net0\n%04d", i)] = strings.Repeat("x", 100) + fmt.Sprint(i)
		}
		apiErr, _, _ = respond(t, many)
		if len(apiErr.Errors) != 1 || len(apiErr.Errors["net0"]) > maxAPIErrorMessage {
			t.Fatalf("%d details; merged value is %d bytes, want one value of at most %d", len(apiErr.Errors), len(apiErr.Errors["net0"]), maxAPIErrorMessage)
		}
	})
}

func TestClient_DoDoesNotFollowRedirects(t *testing.T) {
	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	client := NewClient(Config{BaseURL: redirector.URL})
	var result map[string]interface{}
	if err := client.Do(context.Background(), "GET", "version", nil, &result); err == nil {
		t.Fatal("redirect response was accepted as a successful PVE response")
	}
	if targetHit {
		t.Fatal("PVE client followed a redirect")
	}
}

// A mutation that expects no data does not read any status below 400 as
// success: a redirect (which is not followed) would acknowledge a change that
// was never made, and the SDN unlock would clear its journaled token on it.
func TestClient_DoNeverTakesANonSuccessStatusForSuccess(t *testing.T) {
	for _, status := range []int{
		http.StatusMultipleChoices, http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusNotModified, http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
	} {
		for _, withResult := range []bool{false, true} {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(status)
				_, _ = w.Write([]byte("<html>moved</html>"))
			}))
			client := NewClient(Config{BaseURL: server.URL})
			var result map[string]interface{}
			var target interface{}
			if withResult {
				target = &result
			}
			err := client.Do(context.Background(), "DELETE", "cluster/sdn/lock", nil, target)
			server.Close()
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
				t.Errorf("HTTP %d (result wanted: %v): err = %v, want an APIError carrying the status", status, withResult, err)
			}
		}
	}
}

// What PVE answers for a change that expects no data stays a success: an
// empty body, a null data field and a 2xx status other than 200.
func TestClient_DoAcceptsSuccessfulEmptyMutations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"null data", http.StatusOK, `{"data":null}`},
		{"empty object", http.StatusOK, `{}`},
		{"task id", http.StatusOK, `{"data":"UPID:node:0001:0002:0003:qmstop:100:root@pam:"}`},
		{"no content", http.StatusNoContent, ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client := NewClient(Config{BaseURL: server.URL})
			if err := client.Do(context.Background(), "DELETE", "cluster/sdn/lock", nil, nil); err != nil {
				t.Fatalf("Do = %v; a successful mutation without data must stay a success", err)
			}
		})
	}
}

func TestClient_DoLimitsResponseBody(t *testing.T) {
	reader := &countingReader{reader: strings.NewReader(strings.Repeat("x", maxAPIResponseBody+1024))}
	client := NewClient(Config{BaseURL: "http://127.0.0.1:8006"})
	client.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(reader),
			Header:     make(http.Header),
		}, nil
	})

	var result map[string]interface{}
	err := client.Do(context.Background(), "GET", "version", nil, &result)
	if err == nil {
		t.Fatal("oversized PVE response was accepted")
	}
	// The error says why: the reply was cut at the cap, so what failed to
	// parse is not PVE's answer.
	if !strings.Contains(err.Error(), "larger than 8 MiB") {
		t.Fatalf("err = %v; want it to say the reply is over the 8 MiB read", err)
	}
	if reader.readBytes != maxAPIResponseBody+1 {
		t.Fatalf("response reader consumed %d bytes, want cap %d and one more", reader.readBytes, maxAPIResponseBody)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type countingReader struct {
	reader    io.Reader
	readBytes int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.readBytes += n
	return n, err
}

func TestWaitForTask_Success(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var status TaskStatus
		if callCount < 2 {
			status = TaskStatus{Status: "running", ID: "9001"}
		} else {
			status = TaskStatus{Status: "stopped", ExitStatus: "OK", ID: "9001"}
		}
		data, _ := json.Marshal(status)
		resp := APIResponse{Data: data}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL: server.URL,
	})

	ctx := context.Background()
	err := client.WaitForTask(ctx, "pve1", "UPID:pve1:1234:test", 10*time.Millisecond, 2*time.Second)
	if err != nil {
		t.Fatalf("expected task completion, got %v", err)
	}
}

func TestWaitForTask_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := TaskStatus{Status: "stopped", ExitStatus: "command failed with exit code 1", ID: "9001"}
		data, _ := json.Marshal(status)
		resp := APIResponse{Data: data}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL: server.URL,
	})

	ctx := context.Background()
	err := client.WaitForTask(ctx, "pve1", "UPID:pve1:1234:test", 10*time.Millisecond, 1*time.Second)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// The UPID is the endpoint's own answer, and TaskNode accepts any text in its
// process and start fields: it goes into the status path as one segment and
// cannot start a query, a fragment or another path. A real UPID (colons, an
// "@" in its user, a token's "!") is the same path PVE decodes either way.
func TestWaitForTaskPutsTheUPIDInThePathAsOneSegment(t *testing.T) {
	for _, tc := range []struct {
		name string
		upid string
		// wire is the escaped path a UPID that needs no escaping sends: the
		// same bytes the unescaped form sent.
		wire string
	}{
		{"a real UPID", "UPID:pve1:00001234:0001A2B3:6512ABCD:qmstart:9001:root@pam:", "/api2/json/nodes/pve1/tasks/UPID:pve1:00001234:0001A2B3:6512ABCD:qmstart:9001:root@pam:/status"},
		{"a real UPID of an API token", "UPID:pve1:00001234:0001A2B3:6512ABCD:qmstart:9001:root@pam!certistack:", ""},
		{"a slash", "UPID:pve1:a/b:0001A2B3:6512ABCD:qmstart:9001:root@pam:", ""},
		{"a question mark", "UPID:pve1:00001234:x?y=1:6512ABCD:qmstart:9001:root@pam:", ""},
		{"a fragment", "UPID:pve1:00001234:0001A2B3:x#y:qmstart:9001:root@pam:", ""},
		{"dot segments", "UPID:pve1:..:..:..:qmstart:9001:root@pam:", ""},
		{"all of them", "UPID:pve1:../x?y#z:a/../b:c:qmstart:9001:root@pam:", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type request struct{ decoded, escaped, query string }
			seen := make(chan request, 8)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case seen <- request{r.URL.Path, r.URL.EscapedPath(), r.URL.RawQuery}:
				default:
				}
				data, _ := json.Marshal(TaskStatus{Status: "stopped", ExitStatus: "OK"})
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(APIResponse{Data: data})
			}))
			defer server.Close()
			if err := NewClient(Config{BaseURL: server.URL}).WaitForTask(context.Background(), "pve1", tc.upid, 5*time.Millisecond, 5*time.Second); err != nil {
				t.Fatalf("WaitForTask(%q) = %v", tc.upid, err)
			}
			got := <-seen
			if want := "/api2/json/nodes/pve1/tasks/" + tc.upid + "/status"; got.decoded != want {
				t.Errorf("PVE reads the path %q, want %q", got.decoded, want)
			}
			if got.query != "" {
				t.Errorf("the request carries the query %q", got.query)
			}
			if segments := strings.Split(got.escaped, "/"); len(segments) != 8 || segments[5] != "tasks" || segments[7] != "status" {
				t.Errorf("the request path %q is not nodes/pve1/tasks/<one segment>/status", got.escaped)
			}
			if tc.wire != "" && got.escaped != tc.wire {
				t.Errorf("a real UPID went out as %q, want the unchanged %q", got.escaped, tc.wire)
			}
		})
	}
}

func TestWaitForTaskRejectsMalformedOrWrongNodeTaskID(t *testing.T) {
	client := NewClient(Config{BaseURL: "http://127.0.0.1:1"})
	if err := client.WaitForTask(context.Background(), "pve1", "", time.Second, time.Second); err == nil {
		t.Fatal("WaitForTask accepted an empty task ID")
	}
	for _, taskID := range []string{"OK", "UPID::pid:task", "UPID:pve1:pid:"} {
		t.Run(taskID, func(t *testing.T) {
			err := client.WaitForTask(context.Background(), "pve1", taskID, time.Second, time.Second)
			if err == nil || !strings.Contains(err.Error(), "invalid PVE task identifier") {
				t.Fatalf("WaitForTask(%q) error = %v", taskID, err)
			}
		})
	}
	if err := client.WaitForTask(context.Background(), "pve1", "UPID:pve2:pid:task", time.Second, time.Second); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("WaitForTask accepted a task from another node: %v", err)
	}
}

func TestClient_VMLifecycle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := APIResponse{
			Data: json.RawMessage(`"UPID:pve1:test:task"`),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL: server.URL,
	})

	ctx := context.Background()

	// CreateVM
	cfg := VMConfig{
		VMID:      9001,
		Name:      "test-vm",
		Cores:     2,
		MemoryMB:  2048,
		DeltaPath: "/tmp/delta.qcow2",
		Bridge:    "cs_vn_01",
	}
	upid, err := client.CreateVM(ctx, "pve1", cfg)
	if err != nil || upid != "UPID:pve1:test:task" {
		t.Fatalf("CreateVM failed: upid=%s, err=%v", upid, err)
	}

	// StartVM
	upid, err = client.StartVM(ctx, "pve1", 9001)
	if err != nil || upid != "UPID:pve1:test:task" {
		t.Fatalf("StartVM failed: upid=%s, err=%v", upid, err)
	}

	// StopVM
	upid, err = client.StopVM(ctx, "pve1", 9001)
	if err != nil || upid != "UPID:pve1:test:task" {
		t.Fatalf("StopVM failed: upid=%s, err=%v", upid, err)
	}

	// DestroyVM
	upid, err = client.DestroyVM(ctx, "pve1", 9001)
	if err != nil || upid != "UPID:pve1:test:task" {
		t.Fatalf("DestroyVM failed: upid=%s, err=%v", upid, err)
	}
}

func TestClient_CreateVM_MultipleDiskOverlays(t *testing.T) {
	var createBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/api2/json/nodes/pve1/qemu" {
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Errorf("decode create request: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:test:task"`)})
	}))
	defer server.Close()

	client := NewClient(Config{BaseURL: server.URL})
	_, err := client.CreateVM(context.Background(), "pve1", VMConfig{
		VMID:      9001,
		Name:      "postgres-restore",
		Bridge:    "cs_vn_01",
		Cores:     4,
		Sockets:   2,
		MemoryMB:  8192,
		CPUWeight: 200,
		Machine:   "pc-q35-8.1",
		OSType:    "l26",
		BIOS:      "seabios",
		SCSIHW:    "virtio-scsi-pci",
		NICModel:  "e1000",
		DiskOverlays: []DiskOverlay{
			{Slot: "scsi0", Path: "/var/lib/certistack/scsi0.qcow2"},
			{Slot: "scsi1", Path: "/var/lib/certistack/scsi1.qcow2"},
		},
	})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if got, _ := createBody["scsi0"].(string); got == "" || !strings.Contains(got, "scsi0.qcow2") {
		t.Errorf("scsi0 = %q, want first overlay", got)
	}
	if got, _ := createBody["scsi1"].(string); got == "" || !strings.Contains(got, "scsi1.qcow2") {
		t.Errorf("scsi1 = %q, want second overlay", got)
	}
	if got, _ := createBody["cpuunits"].(float64); got != 200 {
		t.Errorf("cpuunits = %v, want 200", got)
	}
	if got, _ := createBody["boot"].(string); got != "order=scsi0" {
		t.Errorf("boot = %q, want order=scsi0", got)
	}
	if got := int(createBody["sockets"].(float64)); got != 2 {
		t.Errorf("sockets = %d, want 2", got)
	}
	if got, _ := createBody["machine"].(string); got != "pc-q35-8.1" {
		t.Errorf("machine = %q", got)
	}
	if got, _ := createBody["scsihw"].(string); got != "virtio-scsi-pci" {
		t.Errorf("scsihw = %q", got)
	}
	if got, _ := createBody["net0"].(string); got != "e1000,bridge=cs_vn_01,firewall=1" {
		t.Errorf("net0 = %q", got)
	}
}

func TestClient_CreateVMRejectsUnsupportedNICModel(t *testing.T) {
	client := NewClient(Config{BaseURL: "http://localhost:1"})
	_, err := client.CreateVM(context.Background(), "pve1", VMConfig{
		VMID:     9001,
		Bridge:   "cs_vn_01",
		NICModel: "not-a-nic",
		DiskOverlays: []DiskOverlay{
			{Slot: "scsi0", Path: "/var/lib/certistack/scsi0.qcow2"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported net0 model") {
		t.Fatalf("CreateVM error = %v", err)
	}
}

func TestClient_CreateVM_UsesLocalQMForPVEPathGuard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api2/json/nodes/pve1/qemu" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"data":null,"message":"Only root can pass arbitrary filesystem paths."}`))
	}))
	defer server.Close()

	client := NewClient(Config{BaseURL: server.URL})
	client.isRootFn = func() bool { return true }
	client.isLocalNodeFn = func(node string) bool { return node == "pve1" }
	var gotArgs []string
	client.runQMFn = func(_ context.Context, args []string) error {
		gotArgs = append([]string(nil), args...)
		return nil
	}

	upid, err := client.CreateVM(context.Background(), "pve1", VMConfig{
		VMID:   9001,
		Name:   "local-qm-fallback",
		Bridge: "csVn70",
		DiskOverlays: []DiskOverlay{
			{Slot: "scsi0", Path: "/var/lib/certistack/scsi0.qcow2"},
			{Slot: "scsi1", Path: "/var/lib/certistack/scsi1.qcow2"},
		},
	})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if !strings.HasPrefix(upid, localQMTaskPrefix) {
		t.Fatalf("UPID = %q, want local qm marker", upid)
	}
	if err := client.WaitForTask(context.Background(), "pve1", upid, time.Second, time.Second); err != nil {
		t.Fatalf("WaitForTask for local qm marker: %v", err)
	}
	got := strings.Join(gotArgs, " ")
	for _, want := range []string{
		"create 9001",
		"--scsi0 /var/lib/certistack/scsi0.qcow2,format=qcow2,discard=on,iothread=1,backup=0,cache=unsafe",
		"--scsi1 /var/lib/certistack/scsi1.qcow2,format=qcow2,discard=on,iothread=1,backup=0,cache=unsafe",
		"--net0 virtio,bridge=csVn70,firewall=1",
		"--boot order=scsi0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("qm args %q do not contain %q", got, want)
		}
	}
}

func TestClient_CreateVM_DoesNotUseLocalQMOffTargetNode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"data":null,"message":"Only root can pass arbitrary filesystem paths."}`))
	}))
	defer server.Close()

	client := NewClient(Config{BaseURL: server.URL})
	client.isRootFn = func() bool { return true }
	client.isLocalNodeFn = func(string) bool { return false }
	called := false
	client.runQMFn = func(_ context.Context, _ []string) error {
		called = true
		return nil
	}

	_, err := client.CreateVM(context.Background(), "remote-pve", VMConfig{
		VMID:         9001,
		Bridge:       "csVn70",
		DiskOverlays: []DiskOverlay{{Slot: "scsi0", Path: "/var/lib/certistack/scsi0.qcow2"}},
	})
	if err == nil {
		t.Fatal("expected PVE path permission error")
	}
	if called {
		t.Fatal("local qm fallback must not run for a non-local node")
	}
}

func TestClient_StopVM_RespectsTokenLocking(t *testing.T) {
	var requestBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api2/json/nodes/pve1/qemu/9001/status/stop" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Errorf("decode stop request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:test:stop"`)})
	}))
	defer server.Close()

	client := NewClient(Config{BaseURL: server.URL})
	upid, err := client.StopVM(context.Background(), "pve1", 9001)
	if err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	if upid != "UPID:pve1:test:stop" {
		t.Fatalf("UPID = %q", upid)
	}
	if _, hasSkipLock := requestBody["skiplock"]; hasSkipLock {
		t.Fatal("scoped API token stop request must not bypass PVE locks")
	}
	if got := int(requestBody["timeout"].(float64)); got != 5 {
		t.Errorf("timeout = %d, want 5", got)
	}
}

func TestClient_CreateVM_RejectsUnsafeDiskLayout(t *testing.T) {
	client := NewClient(Config{BaseURL: "http://localhost:1"})
	_, err := client.CreateVM(context.Background(), "pve1", VMConfig{
		VMID: 9001,
		DiskOverlays: []DiskOverlay{
			{Slot: "scsi0", Path: "/tmp/delta.qcow2,backup=1"},
		},
	})
	if err == nil {
		t.Fatal("expected unsafe overlay path to be rejected")
	}
}

func TestClient_CreateVMRejectsUnsafeNICIdentityAndBridge(t *testing.T) {
	client := NewClient(Config{BaseURL: "http://localhost:1"})
	for name, cfg := range map[string]VMConfig{
		"option-injected bridge": {
			VMID: 9001, Bridge: "csVn70,link_down=0",
			DiskOverlays: []DiskOverlay{{Slot: "scsi0", Path: "/tmp/delta.qcow2"}},
		},
		"malformed MAC": {
			VMID: 9001, Bridge: "csVn70", MAC: "not-a-mac",
			DiskOverlays: []DiskOverlay{{Slot: "scsi0", Path: "/tmp/delta.qcow2"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.CreateVM(context.Background(), "pve1", cfg); err == nil {
				t.Fatal("expected unsafe NIC configuration to be rejected")
			}
		})
	}
}

func TestClientRejectsUnsafeNodeBeforeLifecycleRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`{}`)})
	}))
	defer server.Close()

	client := NewClient(Config{BaseURL: server.URL})
	operations := map[string]func(string) error{
		"create": func(node string) error {
			_, err := client.CreateVM(context.Background(), node, VMConfig{VMID: 9001, Bridge: "csVn70", DeltaPath: "/tmp/delta.qcow2"})
			return err
		},
		"start":   func(node string) error { _, err := client.StartVM(context.Background(), node, 9001); return err },
		"stop":    func(node string) error { _, err := client.StopVM(context.Background(), node, 9001); return err },
		"destroy": func(node string) error { _, err := client.DestroyVM(context.Background(), node, 9001); return err },
		"status":  func(node string) error { _, err := client.GetVMStatus(context.Background(), node, 9001); return err },
		"config":  func(node string) error { _, err := client.GetVMConfig(context.Background(), node, 9001); return err },
	}
	for _, node := range []string{".", "..", "../cluster", "pve1/tasks", "pve1?x=1", "pve1%2fother", " pve1"} {
		for operation, call := range operations {
			t.Run(operation+"_"+node, func(t *testing.T) {
				if err := call(node); err == nil || !strings.Contains(err.Error(), "invalid PVE node") {
					t.Fatalf("%s(%q) error = %v", operation, node, err)
				}
			})
		}
	}
	if requests != 0 {
		t.Fatalf("unsafe node names reached PVE API %d time(s)", requests)
	}
}

func TestClientRejectsInvalidVMIDBeforeLifecycleRequest(t *testing.T) {
	client := NewClient(Config{BaseURL: "http://127.0.0.1:1"})
	for operation, call := range map[string]func() error{
		"create":  func() error { _, err := client.CreateVM(context.Background(), "pve1", VMConfig{VMID: 0}); return err },
		"start":   func() error { _, err := client.StartVM(context.Background(), "pve1", 0); return err },
		"stop":    func() error { _, err := client.StopVM(context.Background(), "pve1", 0); return err },
		"destroy": func() error { _, err := client.DestroyVM(context.Background(), "pve1", 0); return err },
		"status":  func() error { _, err := client.GetVMStatus(context.Background(), "pve1", 0); return err },
		"config":  func() error { _, err := client.GetVMConfig(context.Background(), "pve1", 0); return err },
	} {
		t.Run(operation, func(t *testing.T) {
			if err := call(); err == nil || !strings.Contains(err.Error(), "invalid VMID") {
				t.Fatalf("%s with VMID 0 error = %v", operation, err)
			}
		})
	}
}

func TestOwnedMetadataRequiresExactRecoveryMarkers(t *testing.T) {
	if _, _, err := ownedMetadata("customer-tag", "owner=customer", "run-1"); err == nil {
		t.Fatal("expected custom metadata without CertiStack markers to be rejected")
	}
	if _, _, err := ownedMetadata("certistack,run-2", "owner=certistack; run_id=run-2", "run-1"); err == nil {
		t.Fatal("expected mismatched run ownership metadata to be rejected")
	}
	tags, description, err := ownedMetadata("", "", "run-1")
	if err != nil || !hasExactTag(tags, "run-1") || !hasExactDescriptionField(description, "run_id", "run-1") {
		t.Fatalf("default owned metadata = %q, %q, %v", tags, description, err)
	}
}

func TestEffectiveHardwareAppliesCreateDefaultsAndKeepsInheritedValues(t *testing.T) {
	defaults := VMConfig{}.EffectiveHardware()
	if defaults.Cores != 2 || defaults.Sockets != 1 || defaults.MemoryMB != 2048 || defaults.SCSIHW != "virtio-scsi-single" ||
		defaults.OSType != "l26" || defaults.NICModel != "virtio" || defaults.CPU != "host" || defaults.Machine != "" || defaults.BIOS != "" {
		t.Fatalf("default hardware = %+v", defaults)
	}
	inherited := VMConfig{Cores: 4, Sockets: 2, MemoryMB: 8192, BalloonMB: 0, Machine: "q35", BIOS: "seabios",
		SCSIHW: "virtio-scsi-pci", OSType: "win11", NICModel: "e1000e", MAC: "BC:24:11:D8:F8:DD"}.EffectiveHardware()
	if inherited.Cores != 4 || inherited.Sockets != 2 || inherited.MemoryMB != 8192 || inherited.Machine != "q35" ||
		inherited.BIOS != "seabios" || inherited.SCSIHW != "virtio-scsi-pci" || inherited.OSType != "win11" ||
		inherited.NICModel != "e1000e" || inherited.MAC != "BC:24:11:D8:F8:DD" {
		t.Fatalf("inherited hardware was not preserved: %+v", inherited)
	}
}

const testOverlayVolume = "certistack-scratch:17011/certistack-delta-vm17011-scsi0-1790184983835370240-0.qcow2"

func TestClient_CreateVM_AttachesOverlayVolumesThroughTheAPI(t *testing.T) {
	var createBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api2/json/nodes/pve1/qemu" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&createBody)
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:1:2:3:qmcreate:17011:tok:"`)})
	}))
	defer server.Close()

	client := NewClient(Config{BaseURL: server.URL})
	client.runQMFn = func(context.Context, []string) error {
		t.Fatal("volume overlays must not need the local root qm fallback")
		return nil
	}
	if _, err := client.CreateVM(context.Background(), "pve1", VMConfig{
		VMID: 17011, Name: "volume-overlay", Bridge: "csVn70",
		DiskOverlays: []DiskOverlay{{Slot: "scsi0", Path: "/var/lib/vz/certistack-scratch/images/17011/x.qcow2", Volume: testOverlayVolume}},
	}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if got, _ := createBody["scsi0"].(string); got != testOverlayVolume+",discard=on,iothread=1,backup=0,cache=unsafe" {
		t.Fatalf("scsi0 = %q, want the volume ID without a raw path or format override", got)
	}
}

const (
	testEFIVolume = "certistack-scratch:17301/certistack-delta-vm17301-efidisk0-1-0.raw"
	testTPMVolume = "certistack-scratch:17301/certistack-delta-vm17301-tpmstate0-1-1.raw"
)

func uefiVMConfig() VMConfig {
	return VMConfig{
		VMID: 17301, Name: "uefi", Bridge: "csVn70", BIOS: "ovmf",
		DiskOverlays: []DiskOverlay{{Slot: "scsi0", Volume: "certistack-scratch:17301/certistack-delta-vm17301-scsi0-1-0.qcow2"}},
		FirmwareVolumes: []FirmwareVolume{
			{Slot: "efidisk0", Volume: testEFIVolume, Options: "efitype=4m,pre-enrolled-keys=1"},
			{Slot: "tpmstate0", Volume: testTPMVolume, Options: "version=v2.0"},
		},
	}
}

func TestClient_CreateVM_AttachesFirmwareState(t *testing.T) {
	var createBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&createBody)
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:1:2:3:qmcreate:17301:tok:"`)})
	}))
	defer server.Close()

	client := NewClient(Config{BaseURL: server.URL})
	if _, err := client.CreateVM(context.Background(), "pve1", uefiVMConfig()); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	for key, want := range map[string]string{
		"bios":      "ovmf",
		"efidisk0":  testEFIVolume + ",efitype=4m,pre-enrolled-keys=1",
		"tpmstate0": testTPMVolume + ",version=v2.0",
		"boot":      "order=scsi0",
	} {
		if got, _ := createBody[key].(string); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

// A Proxmox VE release that predates efidisk0's ms-cert option answers HTTP
// 400 for that drive; the VM is created again without the option, once, and
// nothing else about the drive changes. A node that knows the option, or any
// other efidisk0 refusal, is left alone.
func TestClient_CreateVM_RetriesWithoutMSCertWhereUnknown(t *testing.T) {
	withCert := uefiVMConfig()
	withCert.FirmwareVolumes[0].Options = "efitype=4m,ms-cert=2023w,pre-enrolled-keys=1"
	for _, tc := range []struct {
		name         string
		rejectMSCert bool
		rejectAlways string // a key PVE refuses on every request
		wantRequests int
		wantEFI      string
		wantErr      bool
	}{
		{"older release", true, "", 2, testEFIVolume + ",efitype=4m,pre-enrolled-keys=1", false},
		{"release that knows the option", false, "", 1, testEFIVolume + ",efitype=4m,ms-cert=2023w,pre-enrolled-keys=1", false},
		{"unrelated refusal", false, "scsi0", 1, testEFIVolume + ",efitype=4m,ms-cert=2023w,pre-enrolled-keys=1", true},
		{"drive refused with or without the option", false, "efidisk0", 2, testEFIVolume + ",efitype=4m,pre-enrolled-keys=1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bodies []map[string]interface{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&body)
				bodies = append(bodies, body)
				efi, _ := body["efidisk0"].(string)
				key := tc.rejectAlways
				if key == "" && tc.rejectMSCert && strings.Contains(efi, "ms-cert=") {
					key = "efidisk0"
				}
				if key != "" {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(APIResponse{Message: "Parameter verification failed.", Errors: map[string]string{key: "invalid format - format error"}})
					return
				}
				_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:1:2:3:qmcreate:17301:tok:"`)})
			}))
			defer server.Close()

			_, err := NewClient(Config{BaseURL: server.URL}).CreateVM(context.Background(), "pve1", withCert)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CreateVM error = %v, want error %v", err, tc.wantErr)
			}
			if len(bodies) != tc.wantRequests {
				t.Fatalf("%d create requests, want %d", len(bodies), tc.wantRequests)
			}
			if got, _ := bodies[0]["efidisk0"].(string); got != testEFIVolume+",efitype=4m,ms-cert=2023w,pre-enrolled-keys=1" {
				t.Fatalf("first efidisk0 = %q: the option must be sent first", got)
			}
			if got, _ := bodies[len(bodies)-1]["efidisk0"].(string); got != tc.wantEFI {
				t.Fatalf("last efidisk0 = %q, want %q", got, tc.wantEFI)
			}
			if got, _ := bodies[len(bodies)-1]["tpmstate0"].(string); got != testTPMVolume+",version=v2.0" {
				t.Fatalf("tpmstate0 = %q, want it untouched", got)
			}
		})
	}
	if withCert.FirmwareVolumes[0].Options != "efitype=4m,ms-cert=2023w,pre-enrolled-keys=1" {
		t.Fatalf("the caller's firmware options were changed: %q", withCert.FirmwareVolumes[0].Options)
	}
}

func TestClient_CreateVM_FirmwareFallsBackToLocalQM(t *testing.T) {
	args := localQMCreateArgs(uefiVMConfig(), "l26", 1, 1, 2048, "virtio-scsi-single", "certistack", "owner=certistack", "virtio,bridge=csVn70,firewall=1", uefiVMConfig().DiskOverlays)
	got := strings.Join(args, " ")
	for _, want := range []string{"--efidisk0 " + testEFIVolume + ",efitype=4m,pre-enrolled-keys=1", "--tpmstate0 " + testTPMVolume + ",version=v2.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("qm args %q lack %q", got, want)
		}
	}
}

func TestClient_CreateVM_AttachesDisksOnEveryBus(t *testing.T) {
	var createBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&createBody)
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:1:2:3:qmcreate:14100:tok:"`)})
	}))
	defer server.Close()

	volume := func(slot string) string {
		return "certistack-scratch:14100/certistack-delta-vm14100-" + slot + "-1-0.qcow2"
	}
	cfg := VMConfig{
		VMID: 14100, Name: "legacy-virtio", Bridge: "csVn70", BootDisk: "virtio0",
		DiskOverlays: []DiskOverlay{
			{Slot: "virtio0", Volume: volume("virtio0")},
			{Slot: "sata1", Volume: volume("sata1")},
			{Slot: "ide0", Volume: volume("ide0")},
		},
	}
	client := NewClient(Config{BaseURL: server.URL})
	if _, err := client.CreateVM(context.Background(), "pve1", cfg); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	for key, want := range map[string]string{
		"virtio0": volume("virtio0") + ",discard=on,iothread=1,backup=0,cache=unsafe",
		"sata1":   volume("sata1") + ",discard=on,backup=0,cache=unsafe", // no iothread on SATA
		"ide0":    volume("ide0") + ",discard=on,backup=0,cache=unsafe",
		"boot":    "order=virtio0",
	} {
		if got, _ := createBody[key].(string); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}

	cfg.BootDisk = "scsi0"
	if _, err := client.CreateVM(context.Background(), "pve1", cfg); err == nil || !strings.Contains(err.Error(), "not one of the VM's disks") {
		t.Fatalf("boot disk outside the VM: err %v", err)
	}
	cfg.BootDisk = ""
	cfg.DiskOverlays = []DiskOverlay{{Slot: "scsi1", Volume: volume("scsi0")}}
	if _, err := client.CreateVM(context.Background(), "pve1", cfg); err == nil || !strings.Contains(err.Error(), "invalid overlay volume") {
		t.Fatalf("scsi0 overlay attached as scsi1: err %v", err)
	}
}

func TestOverlayDriveOptionsFollowTheController(t *testing.T) {
	for _, tc := range []struct {
		slot, scsiHW, want string
	}{
		{"scsi0", "virtio-scsi-single", "discard=on,iothread=1,backup=0,cache=unsafe"},
		{"scsi0", "virtio-scsi-pci", "discard=on,backup=0,cache=unsafe"}, // PVE warns and ignores iothread here
		{"scsi0", "lsi", "discard=on,backup=0,cache=unsafe"},
		{"virtio0", "lsi", "discard=on,iothread=1,backup=0,cache=unsafe"}, // VirtIO block has its own controller
		{"sata0", "virtio-scsi-single", "discard=on,backup=0,cache=unsafe"},
		{"ide0", "virtio-scsi-single", "discard=on,backup=0,cache=unsafe"},
	} {
		if got := overlayDriveOptions(tc.slot, tc.scsiHW); got != tc.want {
			t.Errorf("%s behind %s: %q, want %q", tc.slot, tc.scsiHW, got, tc.want)
		}
	}
}

func TestWaitForTaskAcceptsWarnings(t *testing.T) {
	for exit, succeeds := range map[string]bool{"OK": true, "WARNINGS: 1": true, "command failed": false, "unexpected status": false} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"status": "stopped", "exitstatus": exit}})
		}))
		err := NewClient(Config{BaseURL: server.URL}).WaitForTask(context.Background(), "pve1", "UPID:pve1:1:2:3:qmstart:17011:tok:", 10*time.Millisecond, 2*time.Second)
		server.Close()
		if (err == nil) != succeeds {
			t.Errorf("exit status %q: err %v", exit, err)
		}
	}
}

func TestClient_CreateVM_AttachesAdditionalNICsToTheIsolatedBridgeOnly(t *testing.T) {
	var createBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&createBody)
		_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(`"UPID:pve1:1:2:3:qmcreate:17011:tok:"`)})
	}))
	defer server.Close()
	cfg := VMConfig{
		VMID: 17011, Name: "multi-homed", Bridge: "csVn70", MAC: "BC:24:11:00:00:01",
		DiskOverlays:   []DiskOverlay{{Slot: "scsi0", Volume: testOverlayVolume}},
		AdditionalNICs: []NIC{{Slot: "net1", Model: "e1000-82545em", MAC: "bc:24:11:00:00:02"}},
	}
	client := NewClient(Config{BaseURL: server.URL})
	if _, err := client.CreateVM(context.Background(), "pve1", cfg); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if got, _ := createBody["net1"].(string); got != "e1000-82545em=BC:24:11:00:00:02,bridge=csVn70,firewall=1" {
		t.Fatalf("net1 = %q", got)
	}
	args := strings.Join(localQMCreateArgs(cfg, "l26", 1, 1, 2048, "virtio-scsi-single", "t", "d", "virtio,bridge=csVn70,firewall=1", cfg.DiskOverlays), " ")
	if !strings.Contains(args, "--net1 e1000-82545em=BC:24:11:00:00:02,bridge=csVn70,firewall=1") {
		t.Fatalf("qm args %q lack net1", args)
	}
	for name, nic := range map[string]NIC{
		"net0 again":    {Slot: "net0", Model: "virtio", MAC: "BC:24:11:00:00:09"},
		"out of range":  {Slot: "net32", Model: "virtio", MAC: "BC:24:11:00:00:09"},
		"unknown model": {Slot: "net1", Model: "tulip", MAC: "BC:24:11:00:00:09"},
		"bad MAC":       {Slot: "net1", Model: "virtio", MAC: "BC:24:11:00:00"},
		"option inject": {Slot: "net1", Model: "virtio", MAC: "BC:24:11:00:00:09,bridge=vmbr0"},
	} {
		bad := cfg
		bad.AdditionalNICs = []NIC{nic}
		if _, err := client.CreateVM(context.Background(), "pve1", bad); err == nil {
			t.Errorf("%s: CreateVM accepted %+v", name, nic)
		}
	}
	dup := cfg
	dup.AdditionalNICs = []NIC{cfg.AdditionalNICs[0], cfg.AdditionalNICs[0]}
	if _, err := client.CreateVM(context.Background(), "pve1", dup); err == nil {
		t.Error("CreateVM accepted a duplicate net1")
	}
}

func TestClient_CreateVM_RejectsUnsafeFirmwareVolumes(t *testing.T) {
	client := NewClient(Config{BaseURL: "http://localhost:1"})
	for name, firmware := range map[string]FirmwareVolume{
		"another VM's volume":       {Slot: "efidisk0", Volume: "certistack-scratch:17302/certistack-delta-vm17302-efidisk0-1-0.raw"},
		"slot and volume disagree":  {Slot: "efidisk0", Volume: testTPMVolume},
		"not a CertiStack copy":     {Slot: "tpmstate0", Volume: "local-lvm:vm-17301-disk-2"},
		"qcow2 TPM state":           {Slot: "tpmstate0", Volume: "certistack-scratch:17301/certistack-delta-vm17301-tpmstate0-1-1.qcow2"},
		"injected drive option":     {Slot: "efidisk0", Volume: testEFIVolume, Options: "efitype=4m,file=/etc/shadow"},
		"option with a bad value":   {Slot: "tpmstate0", Volume: testTPMVolume, Options: "version=v9"},
		"slot reused for data disk": {Slot: "scsi0", Volume: testEFIVolume},
	} {
		cfg := uefiVMConfig()
		cfg.FirmwareVolumes = []FirmwareVolume{firmware}
		if _, err := client.CreateVM(context.Background(), "pve1", cfg); err == nil {
			t.Errorf("%s: CreateVM accepted %+v", name, firmware)
		}
	}
}

func TestClient_CreateVM_RejectsForeignOverlayVolumes(t *testing.T) {
	client := NewClient(Config{BaseURL: "http://localhost:1"})
	for _, volume := range []string{
		"certistack-scratch:17012/certistack-delta-vm17011-scsi0-1-0.qcow2", // owned by another VM
		"local-lvm:vm-17011-disk-0",                                         // not a CertiStack overlay
		"certistack-scratch:17011/../../etc/passwd",
	} {
		_, err := client.CreateVM(context.Background(), "pve1", VMConfig{
			VMID: 17011, Bridge: "csVn70",
			DiskOverlays: []DiskOverlay{{Slot: "scsi0", Volume: volume}},
		})
		if err == nil || !strings.Contains(err.Error(), "invalid overlay volume") {
			t.Errorf("volume %q: error = %v, want rejection", volume, err)
		}
	}
}

func TestClient_CreateVM_ExplainsStockPVEPathAssociationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"data":null,"message":"Only root can pass arbitrary filesystem paths."}`))
	}))
	defer server.Close()
	client := NewClient(Config{BaseURL: server.URL})
	client.isRootFn = func() bool { return true }
	client.isLocalNodeFn = func(string) bool { return true }
	client.runQMFn = func(context.Context, []string) error {
		return errors.New("qm create failed: 400 Parameter verification failed. scsi0: unable to associate path '/x.qcow2' to any storage")
	}
	_, err := client.CreateVM(context.Background(), "pve1", VMConfig{
		VMID: 9001, Bridge: "csVn70", DiskOverlays: []DiskOverlay{{Slot: "scsi0", Path: "/x.qcow2"}},
	})
	if err == nil || !strings.Contains(err.Error(), "overlay_storage") {
		t.Fatalf("error = %v, want guidance to configure storage.overlay_storage", err)
	}
	if !strings.Contains(err.Error(), CreateOverlayStorageCommand) {
		t.Fatalf("error = %v, want the command that creates the overlay storage (%s)", err, CreateOverlayStorageCommand)
	}
}

func TestValidateOverlayStorage(t *testing.T) {
	statusJSON := map[string]string{
		"good":     `{"type":"dir","content":"images","active":1,"enabled":1,"avail":10737418240}`,
		"lvm":      `{"type":"lvmthin","content":"images,rootdir","active":1,"enabled":1,"avail":10737418240}`,
		"noimages": `{"type":"dir","content":"iso,backup","active":1,"enabled":1,"avail":10737418240}`,
		"inactive": `{"type":"dir","content":"images","active":0,"enabled":1,"avail":10737418240}`,
		"full":     `{"type":"dir","content":"images","active":1,"enabled":1,"avail":1048576}`,
	}
	for name, want := range map[string]string{"good": "", "lvm": "file-based", "noimages": "images", "inactive": "not active", "full": "MiB free"} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api2/json/nodes/pve1/storage/certistack-scratch/status" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(APIResponse{Data: json.RawMessage(statusJSON[name])})
			}))
			defer server.Close()
			_, err := NewClient(Config{BaseURL: server.URL}).ValidateOverlayStorage(context.Background(), "pve1", "certistack-scratch", 5<<30)
			if want == "" && err != nil {
				t.Fatalf("valid storage rejected: %v", err)
			}
			if want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
				t.Fatalf("error = %v, want %q", err, want)
			}
		})
	}
}

// An HTTP 404 is what a proxy, a gateway or a misrouted request gives for
// anything, and PVE words a missing VM otherwise: Client.VMNotFound takes it for
// the VM's absence only when the cluster's resource list, read now, has no guest
// with that ID. Anything that leaves the VM unproven leaves it "not known to be
// gone".
func TestClientVMNotFoundNeedsTheClusterToBackAnHTTP404(t *testing.T) {
	const wording = "Configuration file 'nodes/pve/qemu-server/9904.conf' does not exist"
	answer := func(status int, message string) error {
		return fmt.Errorf("status lookup: %w", &APIError{StatusCode: status, Message: message})
	}
	for name, tc := range map[string]struct {
		err        error
		listStatus int    // the resource list's HTTP status
		listBody   string // its body ("" is {"data":[]})
		want       bool
		wantList   bool // the list was asked
	}{
		"PVE's own wording needs no list":           {err: answer(500, wording), listStatus: 500, want: true},
		"a 404 and a list without the VM":           {err: answer(404, "x"), listStatus: 200, listBody: `{"data":[{"vmid":100},{"vmid":9001}]}`, want: true, wantList: true},
		"a 404 and an empty list":                   {err: answer(404, "x"), listStatus: 200, want: true, wantList: true},
		"a 404 and a list naming the VM":            {err: answer(404, "x"), listStatus: 200, listBody: `{"data":[{"vmid":9904}]}`, wantList: true},
		"a 404 and a list that answers 404 too":     {err: answer(404, "x"), listStatus: 404, wantList: true},
		"a 404 and a list that cannot be read":      {err: answer(404, "x"), listStatus: 500, wantList: true},
		"a 404 and a list that is not the list":     {err: answer(404, "x"), listStatus: 200, listBody: `{"data":"<html>Not Found</html>"}`, wantList: true},
		"a 404 and a list the token may not read":   {err: answer(404, "x"), listStatus: 403, wantList: true},
		"a 404 and a reply with no data field":      {err: answer(404, "x"), listStatus: 200, listBody: `{}`, wantList: true},
		"a 404 and a reply whose data is null":      {err: answer(404, "x"), listStatus: 200, listBody: `{"data":null}`, wantList: true},
		"a 404 and an entry that names no vmid":     {err: answer(404, "x"), listStatus: 200, listBody: `{"data":[{"vmid":100},{"node":"pve"}]}`, wantList: true},
		"a 404 and an entry whose vmid is null":     {err: answer(404, "x"), listStatus: 200, listBody: `{"data":[{"vmid":null}]}`, wantList: true},
		"a 404 and an entry whose vmid is zero":     {err: answer(404, "x"), listStatus: 200, listBody: `{"data":[{"vmid":0}]}`, wantList: true},
		"another VM's wording is not an answer":     {err: answer(500, "Configuration file 'nodes/pve/qemu-server/9999.conf' does not exist"), listStatus: 200},
		"a generic 500":                             {err: answer(500, "temporary backend error"), listStatus: 200},
		"a lost reply (HTTP 596)":                   {err: answer(596, "x"), listStatus: 200},
		"a refused request":                         {err: answer(403, "x"), listStatus: 200},
		"an error that is not PVE's":                {err: errors.New("connection refused"), listStatus: 200},
		"no error":                                  {err: nil, listStatus: 200},
		"a 404 wrapped like the status read wraps":  {err: fmt.Errorf("failed to get status for VM 9904: %w", &APIError{StatusCode: 404}), listStatus: 200, want: true, wantList: true},
		"a 404 with a list entry for another guest": {err: answer(404, "x"), listStatus: 200, listBody: `{"data":[{"vmid":99040},{"vmid":990}]}`, want: true, wantList: true},
	} {
		t.Run(name, func(t *testing.T) {
			listed := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api2/json/cluster/resources" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				listed = true
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.listStatus)
				body := tc.listBody
				if body == "" {
					body = `{"data":[]}`
				}
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			client := NewClient(Config{BaseURL: server.URL})
			client.retryDelays = []time.Duration{}
			if got := client.VMNotFound(context.Background(), tc.err, "pve", 9904); got != tc.want {
				t.Errorf("VMNotFound = %v, want %v", got, tc.want)
			}
			if listed != tc.wantList {
				t.Errorf("the cluster list was asked = %v, want %v", listed, tc.wantList)
			}
		})
	}
	var nilClient *Client
	if nilClient.VMNotFound(context.Background(), answer(404, "x"), "pve", 9904) {
		t.Error("a missing client took a 404 for an absence")
	}
}

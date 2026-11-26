// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package pve provides a REST API client for Proxmox VE. Which PVE versions a
// release is tested with, and which it refuses, is decided in internal/support
// from the version Client.Version reads.
package pve

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// Config holds connection credentials and settings for the PVE REST API.
type Config struct {
	BaseURL     string        // e.g. "https://pve.local:8006"
	TokenID     string        // e.g. "root@pam!certistack"
	TokenSecret string        // e.g. "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	TLSInsecure bool          // Skip TLS certificate validation. Never combine with TLSCAFile.
	TLSCAFile   string        // Absolute PEM file containing a private PVE CA certificate.
	Timeout     time.Duration // Default HTTP timeout
	// NoRetry makes a request fail on its first transient failure instead of
	// retrying it for about 17 seconds. A diagnostic that must say at once why
	// the API cannot be used (certificate not trusted, connection refused) sets
	// it; a run does not.
	NoRetry bool
}

// IsNotFound reports whether err is an HTTP 404 response. It says nothing about
// WHICH object was not found, nor whether PVE sent it, and PVE 9 answers a
// missing VM with HTTP 500, so a decision about a VM must use IsVMNotFound or
// Client.VMNotFound.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// IsVMNotFound reports whether err is PVE's own definite answer that VM vmid
// does not exist on node: the HTTP 500 PVE gives a request for a VM whose
// configuration file is missing, when that message names exactly this node and
// VM ID ("Configuration file 'nodes/<node>/qemu-server/<vmid>.conf' does not
// exist"). The same message for another VM, node or file (a missing storage, a
// different VM's configuration, text a proxy injected) is not this VM's
// absence: nothing is decided about a VM from an answer that is not about it.
//
// An HTTP 404 is not this answer: PVE words a missing VM as above, and a 404
// is what a proxy, a gateway or a misrouted request gives for anything. A
// decision about a VM that a 404 could change uses Client.VMNotFound, which
// asks the cluster whether the VM is really gone.
func IsVMNotFound(err error, node string, vmid int) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError {
		return false
	}
	// The message as PVE wrote it: the display text has the endpoint's
	// host name redacted, which rewrites a node named like the host.
	text := apiErr.matchMessage
	if text == "" {
		text = apiErr.Message
	}
	return missingVMConfigMessage(node, vmid).MatchString(text)
}

// VMNotFound reports whether err, the answer to a request about VM vmid on
// node, says the VM does not exist: PVE's own wording (IsVMNotFound), or an
// HTTP 404 that the cluster's resource list, read now, backs by naming no guest
// with that ID. A 404 alone can come from anything between the client and PVE
// (a proxy that answers 404 to the whole API reads as "every VM is gone"), and
// a teardown or a recovery that believed it would release the disks, the PBS
// maps and the network a running VM still uses. A list that cannot be read, or
// that names the ID, leaves the VM not known to be gone.
func (c *Client) VMNotFound(ctx context.Context, err error, node string, vmid int) bool {
	if IsVMNotFound(err, node, vmid) {
		return true
	}
	if c == nil || !IsNotFound(err) {
		return false
	}
	used, listErr := c.UsedVMIDs(ctx)
	return listErr == nil && !used[vmid]
}

// missingVMConfigMessage matches a missing-configuration message for exactly
// this node and VM ID, and nothing else in the message.
func missingVMConfigMessage(node string, vmid int) *regexp.Regexp {
	return regexp.MustCompile(`^Configuration file '(?:/etc/pve/)?nodes/` + regexp.QuoteMeta(node) + `/qemu-server/` + strconv.Itoa(vmid) + `\.conf' does not exist$`)
}

// Client interacts with the Proxmox VE REST API v2.
type Client struct {
	cfg           Config
	httpClient    *http.Client
	initErr       error
	isLocalNodeFn func(string) bool
	isRootFn      func() bool
	runQMFn       func(context.Context, []string) error
	// retryDelays are the waits before each retry of a transient failure;
	// nil means defaultRetryDelays.
	retryDelays []time.Duration
}

// defaultRetryDelays give a request four attempts over about 17 seconds,
// enough for a cluster node busy with clones or backups to answer again.
var defaultRetryDelays = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}

// NewClient creates a new PVE REST API client configured with API token auth.
func NewClient(cfg Config) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.TLSInsecure,
	}
	initErr := validateBaseURL(cfg.BaseURL)
	if initErr == nil && cfg.TLSInsecure && cfg.TLSCAFile != "" {
		initErr = errors.New("PVE TLS configuration cannot set both TLSInsecure and TLSCAFile")
	} else if initErr == nil && cfg.TLSInsecure {
		initErr = CheckInsecureTLSOptIn()
	} else if initErr == nil && cfg.TLSCAFile != "" {
		initErr = loadCustomCA(tlsConfig, cfg.TLSCAFile)
	}

	transport := &http.Transport{
		TLSClientConfig:    tlsConfig,
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
	}

	if cfg.TLSInsecure && initErr == nil {
		slog.Warn("TLS certificate verification is DISABLED for PVE API client (insecure_skip_verify=true)")
	}

	var retryDelays []time.Duration
	if cfg.NoRetry {
		retryDelays = []time.Duration{}
	}
	return &Client{
		cfg:           cfg,
		initErr:       initErr,
		retryDelays:   retryDelays,
		isLocalNodeFn: isLocalPveNode,
		isRootFn:      processRunsAsRoot,
		runQMFn:       runLocalQM,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// InsecureTLSLabOptInEnv names the explicit acknowledgement a disposable lab
// must set before any PVE client may skip certificate verification.
const InsecureTLSLabOptInEnv = "CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB"

// ErrInsecureTLSForbidden is returned for TLSInsecure without the lab opt-in.
var ErrInsecureTLSForbidden = errors.New("PVE_TLS_INSECURE is forbidden; configure a trusted PVE CA (CERTISTACK_PVE_CA_SOURCE). Disposable labs must explicitly set " + InsecureTLSLabOptInEnv + "=true")

// CheckInsecureTLSOptIn enforces the lab opt-in for disabling PVE certificate
// verification. NewClient applies it, so a client that would skip
// verification refuses to send the API token at all, whichever caller
// (preflight, doctor, recovery, or the runner) constructed it.
func CheckInsecureTLSOptIn() error {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(InsecureTLSLabOptInEnv)))
	if value == "1" || value == "true" {
		return nil
	}
	return ErrInsecureTLSForbidden
}

// validateBaseURL prevents credentials and recovery traffic from being sent to
// a clear-text remote endpoint or a URL whose path/query could change the PVE
// API target. HTTP is retained only for loopback test and disposable-lab
// endpoints; production PVE endpoints must use HTTPS.
func validateBaseURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("PVE base URL must be an absolute HTTP(S) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("PVE base URL must not contain credentials, path, query, or fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		if host == "localhost" {
			return nil
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("PVE base URL must use HTTPS unless its host is loopback")
	default:
		return fmt.Errorf("PVE base URL must use HTTPS (or loopback HTTP), got scheme %q", u.Scheme)
	}
}

// MaxCAFileBytes is the most that is read from a PVE TLS CA file: a private CA
// chain of a few certificates is a few KiB of PEM, so 1 MiB holds any real one
// with room for comments. The controller stages the same file on the node
// under the same limit.
const MaxCAFileBytes = 1 << 20

func loadCustomCA(tlsConfig *tls.Config, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("PVE TLS CA file must be an absolute path")
	}
	// A bounded read of a regular file: a named pipe, a device or a file over
	// the limit is refused without being waited on or read whole. A
	// link to a regular file is followed; a CA certificate is public.
	pemData, err := attest.ReadRegularFile(path, "PVE TLS CA file", MaxCAFileBytes)
	if err != nil {
		return fmt.Errorf("read PVE TLS CA file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return fmt.Errorf("PVE TLS CA file %q contains no valid PEM certificates", path)
	}
	tlsConfig.RootCAs = pool
	return nil
}

// APIResponse is the standard wrapper returned by the Proxmox VE REST API.
type APIResponse struct {
	Data    json.RawMessage   `json:"data"`
	Errors  map[string]string `json:"errors,omitempty"`
	Message string            `json:"message,omitempty"`
}

const maxAPIResponseBody = 8 << 20
const maxAPIErrorMessage = 512
const maxAPIErrorDetails = 20

var endpointURLPattern = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)

// APIError represents an error response from the PVE API.
type APIError struct {
	StatusCode int
	Message    string
	// Errors holds the details of PVE's errors object, one per parameter name:
	// the names and the texts are sanitized and bounded, at most
	// maxAPIErrorDetails are kept, and omitted counts those that were not.
	Errors  map[string]string
	omitted int
	// matchMessage is the message as PVE wrote it, cleaned of control
	// characters and bounded but NOT redacted, for classification only: the
	// redaction of the endpoint's host name would rewrite a node name that is
	// (or contains) that host name, and an exact match on "nodes/<node>/..."
	// would never succeed. It is never printed (Error uses Message).
	matchMessage string
	// Method and Path are the request PVE answered ("GET",
	// "nodes/pve1/storage"), the path with any lock token redacted; empty in an
	// error the client did not make.
	Method, Path string
}

// Call is the request PVE answered with this error, as "GET
// /nodes/pve1/storage", or "" when it is not known. Error does not include it,
// so a caller that names the call says it once.
func (e *APIError) Call() string {
	if e.Method == "" || e.Path == "" {
		return ""
	}
	return e.Method + " /" + strings.TrimLeft(e.Path, "/")
}

func (e *APIError) Error() string {
	if len(e.Errors) > 0 {
		var errList []string
		for k, v := range e.Errors {
			errList = append(errList, fmt.Sprintf("%s: %s", k, v))
		}
		more := ""
		if e.omitted > 0 {
			more = fmt.Sprintf(", and %d more", e.omitted)
		}
		return fmt.Sprintf("PVE API error (HTTP %d): %s - details: %s%s", e.StatusCode, e.Message, strings.Join(errList, ", "), more)
	}
	return fmt.Sprintf("PVE API error (HTTP %d): %s", e.StatusCode, e.Message)
}

// Do executes an authenticated HTTP request against the PVE REST API.
// It serializes the body to JSON, adds authentication headers, and
// unmarshals the response data into the target result structure.
//
// A transient failure is retried, logging each retry: for a GET (read-only
// in PVE) a dropped connection, a gateway error, or pveproxy failing to
// reach or hear back from the target node (HTTP 595-597); for any other
// method only a failure that proves the request never arrived (a refused
// connection, or 595 from pveproxy), since a lost reply to a mutation is
// ambiguous and its caller must decide from the actual state.
func (c *Client) Do(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	if c.initErr != nil {
		return fmt.Errorf("configure PVE API client: %w: %w", ErrRequestNotSent, c.initErr)
	}
	var payload []byte
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		payload = jsonBytes
	} else if method == "POST" || method == "PUT" {
		payload = []byte("{}")
	}
	delays := c.retryDelays
	if delays == nil {
		delays = defaultRetryDelays
	}
	for attempt := 0; ; attempt++ {
		transient, err := c.do(ctx, method, path, payload, result)
		if err == nil || !transient || attempt >= len(delays) {
			return err
		}
		if ctx.Err() != nil {
			return retryInterrupted(ctx, err)
		}
		slog.Warn("PVE API request failed transiently; retrying",
			"method", method, "path", redactPath(path), "attempt", attempt+1, "retry_in", delays[attempt].String(),
			"error", sanitizeAPIErrorText(retryLogText(err), c.cfg.BaseURL))
		timer := time.NewTimer(delays[attempt])
		select {
		case <-ctx.Done():
			timer.Stop()
			return retryInterrupted(ctx, err)
		case <-timer.C:
		}
	}
}

// retryInterrupted is the error of a request whose retry the context ended: the
// failure that made it retry, which stays reachable (errors.As finds the
// APIError), and the context's error, so that a caller that classifies an
// interruption by errors.Is(err, context.Canceled) or DeadlineExceeded still
// sees one, and a signal's cancellation is not reported as the proxy failure
// that preceded it. The message ends with the context's text, as an error
// that wraps a cancellation
// does; the failure is the client's own bounded and sanitized error.
func retryInterrupted(ctx context.Context, last error) error {
	cause := ctx.Err()
	if cause == nil || errors.Is(last, cause) {
		return last
	}
	return fmt.Errorf("%w; stopped retrying because the request was canceled: %w", last, cause)
}

// do sends one request. transient reports a failure that Do may retry.
func (c *Client) do(ctx context.Context, method, path string, payload []byte, result interface{}) (transient bool, err error) {
	requestURL := fmt.Sprintf("%s/api2/json/%s", strings.TrimRight(c.cfg.BaseURL, "/"), strings.TrimLeft(path, "/"))
	readOnly := method == http.MethodGet

	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, requestURL, bodyReader)
	if err != nil {
		return false, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Proxmox API token authorization header format:
	// Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET
	if c.cfg.TokenID != "" && c.cfg.TokenSecret != "" {
		tokenHeader := fmt.Sprintf("PVEAPIToken=%s=%s", c.cfg.TokenID, c.cfg.TokenSecret)
		req.Header.Set("Authorization", tokenHeader)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if ctxErr := ctx.Err(); ctxErr != nil {
		// Canceled before anything was sent.
		return false, &transportError{method: method, path: path, cause: ctxErr, neverArrived: true}
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		var dialErr *net.OpError
		failure := &transportError{method: method, path: path, cause: err, neverArrived: errors.As(err, &dialErr) && dialErr.Op == "dial"}
		// A certificate the TLS stack refused is refused on every attempt.
		if _, refused := certificateProblem(err); refused {
			return false, failure
		}
		// A timeout has already spent the request's whole budget; retrying
		// it would turn one unresponsive node into minutes of waiting.
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return false, failure
		}
		var opErr *net.OpError
		neverArrived := errors.As(err, &opErr) && opErr.Op == "dial"
		return readOnly || neverArrived, failure
	}
	defer resp.Body.Close()

	// One byte past the cap tells a reply that is over it from one that ends
	// there: a reply cut at the cap is not PVE's answer, and its parse error
	// would only say that it ends early.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBody+1))
	if err != nil {
		return readOnly, fmt.Errorf("failed to read PVE response body: %w", err)
	}
	oversized := len(respBody) > maxAPIResponseBody
	if oversized {
		respBody = respBody[:maxAPIResponseBody]
	}

	// Only a 2xx status is PVE's acknowledgement. A redirect is never followed
	// (CheckRedirect), so it carries no answer about the request: for a change
	// that expects no data it would otherwise read as success, and the SDN
	// unlock would clear its journaled lock token on it.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr APIResponse
		decodeErr := json.Unmarshal(respBody, &apiErr)
		message := sanitizeAPIErrorText(apiErr.Message, c.cfg.BaseURL)
		if message == "" && decodeErr != nil {
			message = sanitizeAPIErrorText(string(respBody), c.cfg.BaseURL)
		}
		// PVE also writes its error text into the HTTP status line, and some
		// releases (PVE 8.0 to 8.3 among them) leave it out of the JSON body
		// ({"data":null}): the status line is then the only place that says,
		// for example, that a VM's configuration file does not exist.
		reason := statusReason(resp)
		if message == "" && reason != "" {
			message = sanitizeAPIErrorText(reason, c.cfg.BaseURL)
		}
		if resp.StatusCode < 400 {
			// A redirect's or informational reply's body is not PVE's message.
			message = fmt.Sprintf("unexpected HTTP status %d %s: the request was not followed and PVE has not acknowledged it", resp.StatusCode, statusText(resp.StatusCode))
		}
		if message == "" {
			message = statusText(resp.StatusCode)
		}
		details, omitted := sanitizeAPIErrorDetails(apiErr.Errors, c.cfg.BaseURL)
		matchMessage := apiErrorMatchText(apiErr.Message)
		if matchMessage == "" && decodeErr != nil {
			matchMessage = apiErrorMatchText(string(respBody))
		}
		if matchMessage == "" && reason != "" {
			matchMessage = apiErrorMatchText(reason)
		}
		return transientStatus(resp.StatusCode, readOnly), &APIError{
			StatusCode:   resp.StatusCode,
			Message:      message,
			Errors:       details,
			omitted:      omitted,
			matchMessage: matchMessage,
			Method:       method,
			Path:         redactPath(path),
		}
	}

	if result != nil {
		if oversized {
			return false, fmt.Errorf("PVE's reply to %s %s is larger than %d MiB, the most CertiStack reads of one reply, so it was not read", method, redactPath(path), maxAPIResponseBody>>20)
		}
		var apiResp APIResponse
		if err := json.Unmarshal(respBody, &apiResp); err != nil {
			return false, fmt.Errorf("failed to unmarshal PVE API response wrapper: %w", err)
		}

		if len(apiResp.Data) > 0 {
			if err := json.Unmarshal(apiResp.Data, result); err != nil {
				return false, fmt.Errorf("failed to unmarshal PVE API data field into target: %w", err)
			}
		}
	}

	return false, nil
}

// transientStatus reports an HTTP status worth retrying. pveproxy answers
// 595 when it cannot connect to the target node (the request never
// arrived), 596 when sending the request or reading the reply's headers
// failed, and 597 when reading the reply's body failed; a gateway in front
// of PVE answers 502-504. HTTP 500 is a definite PVE answer (IsVMNotFound
// relies on one) and is never retried.
func transientStatus(status int, readOnly bool) bool {
	switch status {
	case 595:
		return true
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, 596, 597:
		return readOnly
	}
	return false
}

// IsTransient reports an error of a read that PVE never answered: no
// response at all, or a pveproxy or gateway status for a request lost in
// transit (595-597, 502-504). The retries in Do have run out by then, and
// only a caller with another way to find the answer can use it. A certificate
// the client refused is neither: PVE was reached, and refused again every time.
func IsTransient(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return transientStatus(apiErr.StatusCode, true)
	}
	var transport *transportError
	if !errors.As(err, &transport) {
		return false
	}
	// A refused certificate is not a read PVE failed to answer: it will be
	// refused again, and no other way to the answer makes the API usable.
	_, refused := certificateProblem(transport.cause)
	return !refused
}

// statusReason is the reason phrase of the reply's status line when it says
// more than the standard text for its code (PVE puts its error message there),
// or "". pveproxy's own codes 595 to 597 keep statusText's explanation, and a
// phrase net/http made up for a code it does not know ("status code 599") is
// not one.
func statusReason(resp *http.Response) string {
	if resp.StatusCode >= 595 && resp.StatusCode <= 597 {
		return ""
	}
	reason := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
	if reason == "" || strings.EqualFold(reason, http.StatusText(resp.StatusCode)) || reason == "status code "+strconv.Itoa(resp.StatusCode) {
		return ""
	}
	return reason
}

// statusText names an HTTP status, including the ones pveproxy uses when a
// request for another cluster node fails in transit, which it often sends
// without a message.
func statusText(status int) string {
	switch status {
	case 595:
		return "pveproxy could not connect to the target node"
	case 596:
		return "pveproxy lost the request or the reply headers in transit to the target node (busy or unreachable)"
	case 597:
		return "pveproxy lost the reply body from the target node"
	}
	return http.StatusText(status)
}

// transportError is a request that got no HTTP response. Its message names
// only the method and path, since the cause can carry the endpoint; the cause
// remains available to errors.Is and, sanitized, to the retry log.
type transportError struct {
	method, path string
	cause        error
	// neverArrived is true when the request provably was not sent: the
	// context was already done, or the connection was never made.
	neverArrived bool
}

func (e *transportError) Error() string {
	message := fmt.Sprintf("PVE HTTP request failed for %s %s", e.method, redactPath(e.path))
	// A refused certificate is the one cause worth naming here: the sentence is
	// fixed text with the remedy, and says nothing of the endpoint.
	if problem, refused := certificateProblem(e.cause); refused {
		return message + ": " + problem
	}
	return message
}

// ErrRequestNotSent marks an error of a request that provably never reached
// PVE: the client is not configured, the request was canceled before it was
// sent, or no connection was ever made. It is not marked when a reply was
// lost, and a mutation whose reply was lost may have been made.
var ErrRequestNotSent = errors.New("the request was not sent")

// NotSent reports whether err is an error of a request that provably never
// reached PVE (see ErrRequestNotSent), so that a caller may treat it as not
// having changed anything.
func NotSent(err error) bool {
	if errors.Is(err, ErrRequestNotSent) {
		return true
	}
	var transport *transportError
	return errors.As(err, &transport) && transport.neverArrived
}

var lockTokenQuery = regexp.MustCompile(`(lock-token=)[^&#]*`)

// redactPath hides a lock token in a request path's query: the token is what
// releases or uses PVE's SDN lock, and error text reaches logs and reports.
func redactPath(path string) string {
	return lockTokenQuery.ReplaceAllString(path, "${1}<redacted>")
}

func (e *transportError) Unwrap() error { return e.cause }

// retryLogText describes a failure for the retry log, with the transport
// cause (still sanitized by the caller) that the error message leaves out.
func retryLogText(err error) string {
	var transport *transportError
	if errors.As(err, &transport) && transport.cause != nil {
		return err.Error() + ": " + transport.cause.Error()
	}
	return err.Error()
}

// apiErrorMatchText cleans an error message the way sanitizeAPIErrorText
// does (first line, no control characters, bounded) without redacting
// anything, for the exact matches of IsVMNotFound.
func apiErrorMatchText(value string) string {
	message := strings.TrimSpace(value)
	if newline := strings.IndexByte(message, '\n'); newline >= 0 {
		message = message[:newline]
	}
	message = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, message)
	if len(message) > maxAPIErrorMessage {
		message = message[:maxAPIErrorMessage]
	}
	return strings.TrimSpace(message)
}

func sanitizeAPIErrorText(value, rawBaseURL string) string {
	message := strings.TrimSpace(value)
	if newline := strings.IndexByte(message, '\n'); newline >= 0 {
		message = message[:newline]
	}
	message = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, message)
	message = redactEndpoint(message, rawBaseURL)
	if len(message) > maxAPIErrorMessage {
		message = message[:maxAPIErrorMessage]
	}
	return strings.TrimSpace(message)
}

// sanitizeAPIErrorDetails makes the errors object of an error response safe to
// print: the response is the endpoint's to write, so a parameter name is as
// untrusted as its text. Each name goes through sanitizeAPIErrorText like each
// value (first line, no control characters, endpoint redacted, bounded); names
// that become the same after sanitizing are merged, their distinct texts
// joined; and at most maxAPIErrorDetails names are kept. The raw names are
// taken in sorted order, so the same response keeps the same details. omitted
// counts the entries that were left out for the cap.
func sanitizeAPIErrorDetails(raw map[string]string, rawBaseURL string) (details map[string]string, omitted int) {
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make(map[string][]string, maxAPIErrorDetails)
	var order []string
	for _, rawKey := range keys {
		key := sanitizeAPIErrorText(rawKey, rawBaseURL)
		value := sanitizeAPIErrorText(raw[rawKey], rawBaseURL)
		known, kept := parts[key]
		if !kept {
			if len(parts) >= maxAPIErrorDetails {
				omitted++
				continue
			}
			order = append(order, key)
		}
		switch {
		case value == "":
			parts[key] = known
		case !slices.Contains(known, value):
			parts[key] = append(known, value)
		}
	}
	details = make(map[string]string, len(order))
	for _, key := range order {
		details[key] = boundAPIErrorText(strings.Join(parts[key], "; "))
	}
	return details, omitted
}

// boundAPIErrorText cuts text to maxAPIErrorMessage bytes without splitting a
// character.
func boundAPIErrorText(text string) string {
	if len(text) <= maxAPIErrorMessage {
		return text
	}
	cut := maxAPIErrorMessage
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return strings.TrimSpace(text[:cut])
}

func redactEndpoint(value, rawBaseURL string) string {
	value = endpointURLPattern.ReplaceAllString(value, "[REDACTED_ENDPOINT]")
	value = strings.ReplaceAll(value, rawBaseURL, "[REDACTED_ENDPOINT]")
	parsed, err := url.Parse(rawBaseURL)
	if err != nil {
		return value
	}
	for _, identity := range []string{parsed.Host, parsed.Hostname()} {
		if identity != "" {
			value = strings.ReplaceAll(value, identity, "[REDACTED_HOST]")
		}
	}
	return value
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultURL is the one endpoint the report goes to.
	DefaultURL = "https://certistack.dev/api/telemetry"
	// ContentType is the constant request content type.
	ContentType = "application/json"
	// UserAgentPrefix is followed by the sanitized version; it is the only
	// user agent the report ever sends.
	UserAgentPrefix = "certistack-telemetry/"
	// SendTimeout bounds one request end to end: dial, TLS, request, response.
	SendTimeout = 3 * time.Second
	// ExitBudget is the longest the command waits for the report at exit; the
	// caller gives AfterRun a context with this deadline.
	ExitBudget = 2 * time.Second
	// Interval is the shortest time between two reports from one installation.
	Interval = 24 * time.Hour

	maxResponseBytes = 4 << 10
)

// ParseEndpoint accepts https, or http for a loopback host (so a test can use
// a local server), with no credentials and no fragment.
func ParseEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("the telemetry URL is not a URL: %w", err)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("the telemetry URL has no host")
	}
	if u.User != nil || u.Fragment != "" {
		return nil, errors.New("the telemetry URL must not carry credentials or a fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return nil, errors.New("the telemetry URL may use http only for a loopback host")
		}
	default:
		return nil, errors.New("the telemetry URL must be https")
	}
	return u, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ResolveEndpoint is CERTISTACK_TELEMETRY_URL when set, else DefaultURL. A
// value that is not acceptable is an error, never a fallback to the default.
func ResolveEndpoint(getenv func(string) string) (string, error) {
	raw := strings.TrimSpace(getenv(VarURL))
	if raw == "" {
		raw = DefaultURL
	}
	u, err := ParseEndpoint(raw)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// newTransport honors the standard proxy environment (HTTPS_PROXY, NO_PROXY),
// asks for no compression, and keeps no connection open after the one report.
func newTransport(timeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:   true,
		DisableCompression:  true,
	}
}

// Client posts one report. It does not retry, does not follow a redirect,
// honors the standard proxy environment, and reads at most maxResponseBytes
// of the answer, which it ignores.
type Client struct {
	URL       string
	UserAgent string
	Timeout   time.Duration
}

// Send posts body once. Any failure is an error for the caller to ignore or
// log; it is never retried.
func (c Client) Send(ctx context.Context, body []byte) error {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = SendTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("User-Agent", c.UserAgent)

	transport := newTransport(timeout)
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// A redirect is an answer, not an instruction: the report goes to the
		// one URL and nowhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the telemetry endpoint answered %d", resp.StatusCode)
	}
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/httptarget"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// HTTPProber transmits an HTTP/HTTPS GET request to validate service health and status codes.
type HTTPProber struct {
	TargetIP   string
	Port       int
	Path       string
	TLS        bool
	ServerName string
	// TLSRootCAs is intended for trusted, controller-supplied roots in
	// programmatic callers and tests. Plans do not expose a TLS bypass: when
	// nil, Go's system trust store is used.
	TLSRootCAs     *x509.CertPool
	ExpectedStatus int
	Timeout        time.Duration
	Description    string
	Source         Source
}

// NewHTTPProber creates a new HTTP/HTTPS health prober. The insecureSkipVerify
// argument is ignored: CertiStack never disables TLS verification.
func NewHTTPProber(targetIP string, port int, path string, useTLS bool, _ bool, expectedStatus int, timeout time.Duration, desc, serverName string) *HTTPProber {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if expectedStatus <= 0 {
		expectedStatus = http.StatusOK
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return &HTTPProber{
		TargetIP:       targetIP,
		Port:           port,
		Path:           path,
		TLS:            useTLS,
		ServerName:     serverName,
		ExpectedStatus: expectedStatus,
		Timeout:        timeout,
		Description:    desc,
	}
}

// Probe executes an HTTP request and checks the response code and TLS handshake, retrying until timeout or success.
func (p *HTTPProber) Probe(ctx context.Context) probe.Result {
	start := time.Now()

	scheme := "http"
	if p.TLS {
		scheme = "https"
	}

	// Path is the request target the plan wrote, query and percent-encoding
	// included, and Target names it as the server receives it. A path that
	// would reach the server as something else, or not at all (a #fragment is
	// never sent), would test some other resource, so it fails before any
	// request is made.
	hostPort := net.JoinHostPort(p.TargetIP, strconv.Itoa(p.Port))
	res := probe.Result{
		Type:        "http",
		Target:      fmt.Sprintf("%s://%s%s", scheme, hostPort, httptarget.Sent(p.Path)),
		Description: p.Description,
		// The connection is pinned to TargetIP, so the target above names only
		// the address. The virtual host the probe asserted (Host header and
		// TLS server name) is a separate identity the report must carry.
		ServerName: p.ServerName,
	}
	p.Source.annotate(&res)
	if problem := httptarget.Problem(p.Path); problem != "" {
		res.Duration = time.Since(start)
		res.Error = fmt.Sprintf("HTTP probe failed: request path %q %s", p.Path, problem)
		return res
	}
	targetURL := res.Target

	deadline := start.Add(p.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	// lastErr is what the target last told us. A later attempt that only ran
	// out of time must not replace it: "expected 200, got 503" is evidence,
	// "context deadline exceeded" is not.
	var lastErr error
	interrupted := false
	for {
		attemptTimeout := 3 * time.Second
		remain := time.Until(deadline)
		if remain <= 0 {
			break
		}
		if remain < attemptTimeout {
			attemptTimeout = remain
		}

		dialer, err := p.Source.dialer("tcp", attemptTimeout)
		if err != nil {
			res.Duration = time.Since(start)
			res.Error = fmt.Sprintf("HTTP probe failed: %v", err)
			return res
		}
		transport := &http.Transport{
			DialContext: dialer.DialContext,
			TLSClientConfig: &tls.Config{
				ServerName: p.ServerName,
				RootCAs:    p.TLSRootCAs,
				MinVersion: tls.VersionTLS12,
			},
			DisableKeepAlives: true,
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   attemptTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			res.Duration = time.Since(start)
			res.Passed = false
			res.Error = fmt.Sprintf("failed to create request: %v", err)
			return res
		}
		if p.ServerName != "" {
			// The connection remains pinned to TargetIP, while Host and SNI use
			// the intended virtual hostname. This permits deterministic tests of
			// TLS vhosts in an isolated sandbox without relying on DNS.
			req.Host = p.ServerName
		}

		resp, err := client.Do(req)
		if err == nil {
			// The response body is never read into the result: the result goes
			// into the report, and a failing health endpoint can answer with a
			// stack trace or application data.
			resp.Body.Close()

			switch {
			case resp.StatusCode < 100 || resp.StatusCode > 599:
				// net/http accepts any three digits as a status line's code, but
				// HTTP defines 100 to 599 (RFC 9110 section 15): another number is
				// no answer, however it compares to the expectation.
				lastErr = fmt.Errorf("the server answered with status %d, which is not an HTTP status code (100 to 599)", resp.StatusCode)
			case resp.StatusCode == p.ExpectedStatus:
				// A plan may deliberately expect a redirect status (301, 302,
				// 307, ...); CheckRedirect above already guarantees the client
				// never follows it, so accepting an exact match here does not
				// reopen that guarantee.
				res.Duration = time.Since(start)
				res.Passed = true
				res.Detail = fmt.Sprintf("HTTP %d OK (%d %s) in %v", resp.StatusCode, resp.StatusCode, http.StatusText(resp.StatusCode), res.Duration)
				return res
			case resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest:
				lastErr = fmt.Errorf("redirect response %d rejected (expected %d)", resp.StatusCode, p.ExpectedStatus)
			default:
				lastErr = fmt.Errorf("expected HTTP status %d, got %d %s", p.ExpectedStatus, resp.StatusCode, http.StatusText(resp.StatusCode))
			}
		} else if lastErr != nil && isTimeout(err) && !isTimeout(lastErr) {
			interrupted = true
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			if lastErr == nil || isTimeout(lastErr) {
				lastErr = ctx.Err()
			} else {
				interrupted = true
			}
			goto done
		case <-time.After(1 * time.Second):
		}
	}

done:
	res.Duration = time.Since(start)
	res.Passed = false
	res.Error = fmt.Sprintf("HTTP probe failed: %v", lastErr)
	if interrupted {
		res.Error += " (last answered attempt; later attempts ran out of time)"
	}
	return res
}

// isTimeout reports an attempt that ended only because time ran out, as
// opposed to an answer from the target (a status, a refusal, a TLS error).
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package synthetic implements in-band wire-level network probers for Stage 2 verification.
package synthetic

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// TCPProber executes an active TCP 3-way handshake against a target IP and port.
type TCPProber struct {
	TargetIP    string
	Port        int
	Timeout     time.Duration
	Description string
	Source      Source
}

// NewTCPProber creates a TCP socket prober.
func NewTCPProber(targetIP string, port int, timeout time.Duration, desc string) *TCPProber {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &TCPProber{
		TargetIP:    targetIP,
		Port:        port,
		Timeout:     timeout,
		Description: desc,
	}
}

// Probe evaluates socket connectivity by performing a TCP handshake, retrying until timeout or success.
func (p *TCPProber) Probe(ctx context.Context) probe.Result {
	start := time.Now()
	addr := net.JoinHostPort(p.TargetIP, strconv.Itoa(p.Port))

	res := probe.Result{
		Type:        "tcp",
		Target:      addr,
		Description: p.Description,
	}
	p.Source.annotate(&res)

	deadline := start.Add(p.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	// As in the HTTP prober: an attempt that only ran out of time must not
	// replace what the target last answered ("connection refused" is the
	// evidence of a stopped service, "context deadline exceeded" is not).
	var lastErr error
	interrupted := false
	for {
		attemptTimeout := 2 * time.Second
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
			res.Error = fmt.Sprintf("TCP handshake failed: %v", err)
			return res
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			res.Duration = time.Since(start)
			res.Passed = true
			res.Detail = fmt.Sprintf("Service readiness time: %v (TCP 3-way handshake established with %s)", res.Duration, addr)
			return res
		}

		if lastErr != nil && isTimeout(err) && !isTimeout(lastErr) {
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
	res.Error = fmt.Sprintf("TCP handshake failed: %v", lastErr)
	if interrupted {
		res.Error += " (last answered attempt; later attempts ran out of time)"
	}
	return res
}

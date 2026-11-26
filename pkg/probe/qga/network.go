// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package qga

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// NetworkProber executes a network check inside the recovered guest through
// QGA. It intentionally replaces host-namespace TCP and HTTP checks.
type NetworkProber struct {
	SocketPath, Command, Type, Target, Description string
	Timeout                                        time.Duration
}

func newNetworkProber(socketPath, command, probeType, target, desc string, timeout time.Duration) *NetworkProber {
	return &NetworkProber{SocketPath: socketPath, Command: command, Type: probeType, Target: target, Description: desc, Timeout: timeout}
}

// NewTCPNetworkProber requires netcat in the recovered guest. Missing tools
// fail the probe instead of falling back to a host-side network connection.
func NewTCPNetworkProber(socketPath, targetIP string, port int, timeout time.Duration, desc string) *NetworkProber {
	seconds := timeoutSeconds(timeout)
	command := fmt.Sprintf("command -v nc >/dev/null 2>&1 && timeout %d nc -z -w %d %s %d", seconds, seconds, shellQuote(targetIP), port)
	return newNetworkProber(socketPath, command, "tcp", net.JoinHostPort(targetIP, strconv.Itoa(port)), desc, timeout)
}

// NewHTTPNetworkProber requires curl in the recovered guest and validates the
// expected HTTP status without using the host network namespace. When
// serverName is set, curl uses it for both TLS SNI and the HTTP Host header;
// --resolve still pins the actual connection to the sandbox IP. curl never
// receives a TLS-verification bypass.
func NewHTTPNetworkProber(socketPath, targetIP string, port int, path string, useTLS bool, serverName string, expectedStatus int, timeout time.Duration, desc string) *NetworkProber {
	seconds := timeoutSeconds(timeout)
	if port <= 0 {
		port = 80
		if useTLS {
			port = 443
		}
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	host := targetIP
	resolve := ""
	if serverName != "" {
		host = serverName
		// curl takes an IPv6 address here in brackets (curl 7.57 and later).
		address := targetIP
		if strings.Contains(address, ":") {
			address = "[" + address + "]"
		}
		resolve = " --resolve " + shellQuote(fmt.Sprintf("%s:%d:%s", serverName, port, address))
	}
	targetURL := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(host, strconv.Itoa(port)), path)
	command := fmt.Sprintf("command -v curl >/dev/null 2>&1 && test \"$(curl -sS --noproxy '*'%s --connect-timeout %d --max-time %d -o /dev/null -w '%%{http_code}' %s)\" = %s", resolve, seconds, seconds, shellQuote(targetURL), shellQuote(strconv.Itoa(expectedStatus)))
	target := targetURL
	if serverName != "" {
		target = fmt.Sprintf("%s (resolved to %s)", targetURL, targetIP)
	}
	return newNetworkProber(socketPath, command, "http", target, desc, timeout)
}

func (p *NetworkProber) Probe(ctx context.Context) probe.Result {
	start := time.Now()
	result := probe.Result{Type: p.Type, Target: p.Target, Description: p.Description}
	client, err := DialContext(ctx, p.SocketPath, p.Timeout)
	if err == nil {
		defer client.Close()
		execution, execErr := client.Exec(ctx, p.Command, 250*time.Millisecond, p.Timeout)
		if execErr != nil {
			err = execErr
		} else if !execution.Succeeded() {
			err = fmt.Errorf("guest network command %s: %s", execution.Outcome(), truncateForReport(strings.TrimSpace(execution.Stderr)))
		}
	}
	result.Duration = time.Since(start)
	if err != nil {
		result.Error = fmt.Sprintf("in-guest %s probe failed: %v", p.Type, err)
		return result
	}
	result.Passed = true
	result.Detail = fmt.Sprintf("in-guest %s probe succeeded through QGA", p.Type)
	return result
}

func timeoutSeconds(timeout time.Duration) int {
	seconds := int(timeout.Seconds())
	if seconds < 1 {
		return 1
	}
	return seconds
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

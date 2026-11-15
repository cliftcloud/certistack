// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/internal/httptarget"
)

// httpProbePath is the request target an http probe sends for path: the
// prober's "/" default and leading-slash rule, nothing else.
func httpProbePath(path string) string {
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

// expandHTTPProbeURL applies an http probe's url shorthand for target_ip,
// port, path and tls. The request target is the URL's own text after the
// host, so its query and percent-encoding reach the server exactly as
// written: the decoded url.URL.Path would turn "a%2Fb" into "a/b" and drop
// the query. A target_ip, port, path or tls the probe also sets must agree
// with the URL: the prober connects to target_ip, so a URL naming another host
// would be ignored and the plan would claim a request that is never made.
func expandHTTPProbeURL(p Probe) (Probe, error) {
	u, err := url.Parse(p.URL)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return p, fmt.Errorf("is not a valid URL: %v", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.Hostname() == "" {
		return p, errors.New("must be an absolute http:// or https:// URL such as http://192.0.2.10:8080/healthz")
	}
	if u.User != nil {
		return p, errors.New("must not carry user information: the probe sends no credentials")
	}
	if strings.Contains(p.URL, "#") {
		return p, errors.New("must not contain a #fragment: a fragment is never sent to the server")
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		n, err := strconv.Atoi(u.Port())
		if err != nil || n < 1 || n > 65535 {
			return p, fmt.Errorf("has an invalid port %q", u.Port())
		}
		port = n
	}
	// With no user information or fragment, the authority ends at the first
	// "/" or "?" after the scheme.
	rest := p.URL[strings.Index(p.URL, "://")+3:]
	target := "/"
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		target = httpProbePath(rest[i:])
	}
	if problem := httptarget.Problem(target); problem != "" {
		return p, fmt.Errorf("path %q %s", target, problem)
	}
	useTLS := u.Scheme == "https"
	switch {
	case strings.TrimSpace(p.TargetIP) != "" && !sameProbeHost(p.TargetIP, u.Hostname()):
		return p, fmt.Errorf("names host %s, but target_ip is %s; set only one of them", u.Hostname(), strings.TrimSpace(p.TargetIP))
	case p.Port != 0 && p.Port != port:
		return p, fmt.Errorf("names port %d, but port is %d; set only one of them", port, p.Port)
	case p.Path != "" && httpProbePath(p.Path) != target:
		return p, fmt.Errorf("names path %q, but path is %q; set only one of them", target, p.Path)
	case p.TLS && !useTLS:
		return p, errors.New("is an http:// URL, but tls is true; use an https:// URL")
	}
	p.TargetIP, p.Port, p.Path, p.TLS = u.Hostname(), port, target, useTLS
	return p, nil
}

// sameProbeHost reports whether a probe's target_ip and a URL's host name the
// same host: the same address however it is spelled, else the same name.
func sameProbeHost(targetIP, host string) bool {
	targetIP = strings.TrimSpace(targetIP)
	if a, b := net.ParseIP(targetIP), net.ParseIP(host); a != nil && b != nil {
		return a.Equal(b)
	}
	return strings.EqualFold(targetIP, host)
}

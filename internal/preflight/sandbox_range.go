// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// SandboxRangeCheckName names the check that the sandbox network does not
// contain a server the run needs.
const SandboxRangeCheckName = "sandbox_range"

// endpointHost is the host part of a PBS repository string
// ([[user@]server[:port]:]datastore), or "" for a local datastore.
func repositoryHost(repository string) string {
	repository = strings.TrimSpace(repository)
	if i := strings.LastIndex(repository, "@"); i >= 0 {
		repository = repository[i+1:]
	}
	if strings.HasPrefix(repository, "[") { // [IPv6]:port:datastore
		if end := strings.Index(repository, "]"); end > 0 {
			return repository[1:end]
		}
		return ""
	}
	if i := strings.Index(repository, ":"); i > 0 {
		return repository[:i]
	}
	return "" // a bare datastore name: local
}

// CheckSandboxRange reports a plan whose sandbox network contains the PVE API
// or the PBS server. Once the probe address is on the sandbox bridge the node
// routes that whole range to it, so the run would lose its own PVE or PBS
// connection (a PBS map, which stays connected for the whole run, fails with
// "client error (Connect)"). lookup resolves a host name; nil uses the system
// resolver with a short limit.
func CheckSandboxRange(ctx context.Context, plan *config.Plan, pveURL, pbsRepository string, lookup func(context.Context, string) ([]string, error)) error {
	if plan == nil {
		return nil
	}
	cidr := plan.Network.IPRange
	if cidr == "" {
		cidr = plan.Network.SubnetCIDR
	}
	if cidr == "" {
		return nil // no range to judge: plan validation refuses the plan
	}
	prefix, err := config.ParseSandboxRange(cidr)
	if err != nil {
		// Never "nothing to judge": a range that cannot be read has not been
		// compared with the PVE API and the PBS server.
		return fmt.Errorf("network.ip_range %w (the range was not compared with the PVE API and the PBS server)", err)
	}
	sandbox := &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), 32)}
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]string, error) {
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			return net.DefaultResolver.LookupHost(ctx, host)
		}
	}
	for _, endpoint := range []struct{ name, host string }{
		{"the PVE API", hostOfURL(pveURL)},
		{"the PBS server", repositoryHost(pbsRepository)},
	} {
		if endpoint.host == "" {
			continue
		}
		addresses := []string{endpoint.host}
		if net.ParseIP(endpoint.host) == nil {
			resolved, err := lookup(ctx, endpoint.host)
			if err != nil {
				continue // an unresolvable name is not this check's finding
			}
			addresses = resolved
		}
		for _, text := range addresses {
			if ip := net.ParseIP(text); ip != nil && sandbox.Contains(ip) {
				// A server named by its address shows that address once; one named by
				// a host name shows the name and the address it resolved to.
				named := ip.String()
				if endpoint.host != text {
					named = endpoint.host + ", " + ip.String()
				}
				return fmt.Errorf("network.ip_range %s contains %s (%s). Once the probe address is assigned the node routes the whole range to the sandbox bridge, so the run would lose its connection to %s. Choose a network.ip_range that does not contain the PVE API or the PBS server", sandbox, endpoint.name, named, endpoint.name)
			}
		}
	}
	return nil
}

// CheckSandboxRangeByAddress is CheckSandboxRange for a caller that must not
// resolve names: it refuses a range that holds the PVE API or the PBS server
// only where the URL or the repository gives that server's address, and leaves
// a host name alone. A controller uses it before it stages a worker: the node
// resolves names as its own resolver does, and its check is the one that
// counts, so a controller's different answer must not refuse a range the node
// would accept.
func CheckSandboxRangeByAddress(ctx context.Context, plan *config.Plan, pveURL, pbsRepository string) error {
	return CheckSandboxRange(ctx, plan, pveURL, pbsRepository, func(context.Context, string) ([]string, error) {
		return nil, errors.New("names are resolved on the node")
	})
}

func hostOfURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return u.Hostname()
}

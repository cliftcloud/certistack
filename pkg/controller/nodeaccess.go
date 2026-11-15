// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"regexp"
	"strings"

	"github.com/cliftcloud/certistack/internal/nodeidentity"
	"github.com/cliftcloud/certistack/pkg/config"
)

// The functions here are what `certistack setup` and `certistack check` do
// over the controller's own SSH access: the same identity, known_hosts file,
// account and sudo setting a run uses, with host-key checking always on. They
// stage nothing on the node, except Check, which stages a worker exactly as
// Plan does and removes it again.

// ValidateSSH checks an SSH configuration the way every controller operation
// does before it connects: a valid host, user and port, and an absolute
// known_hosts file and identity that exist.
func ValidateSSH(cfg SSHConfig) error {
	return validateSSHConfig(cfg)
}

// NodeMachine is the node's `uname -m`, asked over SSH. The connection is
// tried once and not retried: it is a diagnostic, which must say at once why
// the node cannot be reached.
func (e *Executor) NodeMachine(ctx context.Context, cfg SSHConfig) (string, error) {
	if e == nil || e.runner == nil {
		return "", errors.New("controller executor is not initialized")
	}
	output, err := e.remoteCommand(ctx, cfg, []string{"/usr/bin/uname", "-m"})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// NodeName is the PVE name of the node the SSH access reaches, asked over the
// same strict connection: the target of /etc/pve/local, PVE's own link to the
// node's directory in its cluster file system (nodes/<name>), and where there is
// no such link (not a PVE host) the short host name. It is what the node-side
// check compares CERTISTACK_NODE with, learned here so that `check` can say so
// at the SSH layer. A node that gives no name is an error: not a name that
// matched.
func (e *Executor) NodeName(ctx context.Context, cfg SSHConfig) (string, error) {
	if e == nil || e.runner == nil {
		return "", errors.New("controller executor is not initialized")
	}
	output, linkErr := e.remoteCommand(ctx, cfg, []string{"/usr/bin/readlink", "/etc/pve/local"})
	if linkErr == nil {
		name, err := nodeidentity.NameFromLinkTarget(strings.TrimSpace(string(output)))
		if err != nil {
			return "", fmt.Errorf("read /etc/pve/local on %s: %w", cfg.Host, err)
		}
		return name, nil
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	// No link: not a PVE host, or its cluster file system is not mounted.
	output, err := e.remoteCommand(ctx, cfg, []string{"/usr/bin/hostname"})
	if err != nil {
		return "", fmt.Errorf("read the node's name: /etc/pve/local: %w; host name: %v", linkErr, err)
	}
	name := nodeidentity.ShortHostName(strings.TrimSpace(string(output)))
	if name == "" {
		return "", fmt.Errorf("the node on %s gave an empty host name", cfg.Host)
	}
	return name, nil
}

// ReadNodeFile returns the content of a regular file on the node, read with
// /usr/bin/cat (and passwordless sudo when cfg asks for it, as a run's staging
// does). The connection is tried once. A file larger than limit bytes is
// refused.
func (e *Executor) ReadNodeFile(ctx context.Context, cfg SSHConfig, remotePath string, limit int) ([]byte, error) {
	if e == nil || e.runner == nil {
		return nil, errors.New("controller executor is not initialized")
	}
	if !safeRemoteAbsolutePath(remotePath) {
		return nil, fmt.Errorf("%q is not a clean absolute path on the node", remotePath)
	}
	command := append(e.privilegePrefix(cfg), "/usr/bin/cat", remotePath)
	output, err := e.remoteCommand(ctx, cfg, command)
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(output) > limit {
		return nil, fmt.Errorf("%s on %s is larger than %d bytes", remotePath, cfg.Host, limit)
	}
	return output, nil
}

// Check has a temporary worker, staged on the node as Plan stages it, run the
// layers of `certistack check` that only the node can answer (node-check): the
// tools a run needs, the PVE API with the token, and the PBS credential. It
// returns the worker's report as JSON and removes the workspace. The
// worker uses the same environment and CA file a run would. through, when set
// to a layer's name (node_tools, pve_api), has the worker stop after that
// layer: the credentials of the layers beyond it are staged but not used.
func (e *Executor) Check(ctx context.Context, opts RunOptions, through string) ([]byte, error) {
	if e == nil || e.runner == nil {
		return nil, errors.New("controller executor is not initialized")
	}
	if through != "" && !checkLayerName.MatchString(through) {
		return nil, fmt.Errorf("invalid check layer %q", through)
	}
	if err := validateNode(&opts); err != nil {
		return nil, err
	}
	if err := resolveScratchDir(&opts, nil); err != nil {
		return nil, err
	}
	sandbox, err := sandboxCheckArguments(opts.Sandbox)
	if err != nil {
		return nil, err
	}
	if opts.NoWireProbes {
		// The plan has no wire probe: the worker does not require nft.
		sandbox = append(sandbox, "--no-wire-probes")
	}
	if opts.Sandbox != nil {
		// The range must not hold the address this session reaches the node from.
		if client := e.nodeSSHClient(ctx, opts.SSH); client != "" {
			sandbox = append(sandbox, "--ssh-client", client)
		}
	}
	return e.readOnNode(ctx, opts, nil, "check", func(workspace string) []string {
		return buildNodeCheckCommand(workspace, opts.NodeName, through, sandbox)
	})
}

// checkLayerName is what a layer's name looks like.
var checkLayerName = regexp.MustCompile(`^[a-z_]+$`)

// What each field of a plan's network looks like on a worker's command line:
// anything else never reaches the node.
var (
	sandboxRangePattern     = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$`)
	sandboxAddressPattern   = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`)
	sandboxIdentifier       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,31}$`)
	sandboxLifecyclePattern = regexp.MustCompile(`^[a-z]{0,32}$`)
)

// sandboxCheckArguments are node-check's flags for the plan's network, or none
// for no network. A network that is not an IPv4 range with its probe address
// is refused here.
func sandboxCheckArguments(network *config.Network) ([]string, error) {
	if network == nil {
		return nil, nil
	}
	// The range is not trimmed: the one reader of it (config.ParseSandboxRange,
	// which plan validation, the node's overlap check and the engine share)
	// refuses a spelling with spaces, and so must the check that stages it.
	rangeText := network.IPRange
	if rangeText == "" {
		rangeText = network.SubnetCIDR
	}
	probe, vnet, lifecycle := strings.TrimSpace(network.ProbeIP), strings.TrimSpace(network.VNetID), strings.TrimSpace(network.Lifecycle)
	switch {
	case !sandboxRangePattern.MatchString(rangeText):
		return nil, fmt.Errorf("the plan's network.ip_range %q is not an IPv4 range such as 192.0.2.0/24", rangeText)
	case !sandboxAddressPattern.MatchString(probe):
		return nil, fmt.Errorf("the plan's network.probe_ip %q is not an IPv4 address", probe)
	case vnet != "" && !sandboxIdentifier.MatchString(vnet):
		return nil, fmt.Errorf("the plan's network.vnet_id %q is not a PVE SDN identifier", vnet)
	case !sandboxLifecyclePattern.MatchString(lifecycle):
		return nil, fmt.Errorf("the plan's network.lifecycle %q is not a lifecycle", lifecycle)
	}
	if _, err := config.ParseSandboxRange(rangeText); err != nil {
		return nil, fmt.Errorf("the plan's network.ip_range %w", err)
	}
	if address, err := netip.ParseAddr(probe); err != nil || !address.Is4() {
		return nil, fmt.Errorf("the plan's network.probe_ip %q is not an IPv4 address (no leading zeros): write it as in 192.0.2.1", probe)
	}
	arguments := []string{"--sandbox-range", rangeText, "--sandbox-probe", probe}
	if strings.EqualFold(strings.TrimSpace(network.Mode), "vxlan") && strings.TrimSpace(network.Peers) != "" {
		// The peers of a vxlan zone are addresses the node reaches that the range
		// must not hold. They go in their canonical form, each an IP address.
		peers, err := network.VXLANPeerAddresses()
		if err != nil {
			return nil, fmt.Errorf("the plan's network.peers: %w", err)
		}
		arguments = append(arguments, "--sandbox-mode", "vxlan", "--sandbox-peers", strings.Join(peers, ","))
	}
	if vnet != "" {
		arguments = append(arguments, "--sandbox-vnet", vnet)
	}
	if lifecycle != "" {
		arguments = append(arguments, "--sandbox-lifecycle", lifecycle)
	}
	return arguments, nil
}

// nodeSSHClient is the address this SSH access reaches the node from, as the
// node sees it: the first field of SSH_CONNECTION, asked in a session of the
// same access and without sudo, which would drop the variable (a worker started
// under sudo or as a transient service has none of its own). It is "" when the
// node does not say, or says anything but an IPv4 address: the check then
// goes without it, as it did before it existed.
func (e *Executor) nodeSSHClient(ctx context.Context, cfg SSHConfig) string {
	output, err := e.remoteCommand(ctx, cfg, []string{"/bin/sh", "-c", `printf '%s' "$SSH_CONNECTION"`})
	if err != nil {
		return ""
	}
	if len(output) > 256 {
		return ""
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return ""
	}
	addr, err := netip.ParseAddr(fields[0])
	if err != nil {
		return ""
	}
	if addr = addr.Unmap(); !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() {
		return ""
	}
	return addr.String()
}

// buildNodeCheckCommand is node-check's command line in workspace. It names the
// node the controller addresses, which the worker refuses unless it is the host's
// own, and carries the flags for the plan's network (sandboxCheckArguments), if
// there is one.
func buildNodeCheckCommand(workspace, nodeName, through string, sandbox []string) []string {
	command := []string{
		path.Join(workspace, "certistack-node"), "node-check",
		"--node", nodeName,
		"--env-file", path.Join(workspace, "runtime.env"),
	}
	if through != "" {
		command = append(command, "--through", through)
	}
	return append(command, sandbox...)
}

// RunNodeScript runs a shell script on the node over the controller's strict
// SSH access, as root (with passwordless sudo when cfg asks for it), the
// script being one argument to /bin/sh -c. It returns the script's standard
// output; its standard error goes to stderr as it comes, so the operator sees
// what the script says while it runs. It is what `certistack setup` uses for
// the steps it takes on the node after the operator has agreed to each. The
// connection is tried once. A script that fails still returns what it wrote to
// standard output, with the error: a token's secret, printed once before a
// later step failed, is not lost.
func (e *Executor) RunNodeScript(ctx context.Context, cfg SSHConfig, script string, stderr io.Writer) ([]byte, error) {
	if e == nil || e.runner == nil {
		return nil, errors.New("controller executor is not initialized")
	}
	if strings.TrimSpace(script) == "" {
		return nil, errors.New("the script is empty")
	}
	command := append(e.privilegePrefix(cfg), "/bin/sh", "-c", script)
	runner, ok := e.runner.(scriptCommandRunner)
	if !ok || stderr == nil {
		return e.remoteCommandWithProgress(ctx, cfg, command, stderr)
	}
	args := append(e.sshBaseArgs(cfg), e.target(cfg))
	for _, arg := range command {
		args = append(args, shellQuote(arg))
	}
	output, err := runner.RunKeepingStdout(ctx, "ssh", args, stderr)
	if err != nil {
		return output, fmt.Errorf("SSH command on %s: %w", cfg.Host, err)
	}
	return output, nil
}

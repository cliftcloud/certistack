// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package nodecheck answers, on the node, the layers of `certistack check` that
// only the node can answer: whether the tools a run needs are installed, whether
// the PVE API accepts the token over the TLS trust the run would use, and
// whether the PBS credential can list the repository's namespace. The temporary
// worker runs it (node-check) and the controller reads its report. It stops at
// the first layer that fails, so a missing tool is never reported as a PVE
// problem, and it changes nothing.
package nodecheck

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// The layers, in the order they are tried.
const (
	LayerTools = "node_tools"
	LayerPVE   = "pve_api"
	LayerPBS   = "pbs"
	// LayerSandbox is the plan's sandbox network against this node. It is
	// tried only when the controller names a plan's network (Settings.Sandbox).
	LayerSandbox = "sandbox_network"
)

// Statuses of a layer.
const (
	StatusPassed = "passed"
	StatusFailed = "failed"
	// StatusUnchecked is a layer that could not be made: neither a pass nor a
	// failure. Its Detail says why and what to do by hand.
	StatusUnchecked = "unchecked"
)

// Codes of a failed layer, for the controller to attach the fix to.
const (
	CodeToolsMissing   = "tools_missing"
	CodePVEConfig      = "pve_config"
	CodePVECAUntrusted = "pve_ca_untrusted"
	CodePVECertName    = "pve_cert_name"
	CodePVECertInvalid = "pve_cert_invalid"
	CodePVEAuth        = "pve_auth"
	CodePVEForbidden   = "pve_forbidden"
	CodePVEUnreachable = "pve_unreachable"
	CodePVEOther       = "pve_other"
	CodePBSFailed      = "pbs_failed"
	// CodeSandboxRange is a sandbox range that holds the PVE API or the PBS
	// server, CodeSandboxNetwork one that overlaps a network the node uses.
	CodeSandboxRange   = "sandbox_range"
	CodeSandboxNetwork = "sandbox_network"
)

// Tools are what a run needs on the node, with the package that provides each.
// They are the programs the node preflight (certistack doctor) looks for, and
// a test keeps the two lists equal: ip puts the probe address on the sandbox
// bridge and nft contains it (nftables), qemu-img makes the overlays, guestfish
// writes the guest's network recovery, and proxmox-backup-client maps the
// backups. The PVE commands (qm, pvesm) are on every Proxmox VE node and are
// not looked for: the node-name check already refuses a host that is not one.
var Tools = []Tool{
	{Name: "qemu-img", Package: "qemu-utils"},
	{Name: "proxmox-backup-client", Package: "proxmox-backup-client"},
	{Name: "guestfish", Package: "libguestfs-tools"},
	{Name: "ip", Package: "iproute2"},
	{Name: "nft", Package: "nftables", WireProbesOnly: true},
}

// Tool is a program a run needs on the node and the Debian package it is in.
type Tool struct {
	Name    string `json:"name"`
	Package string `json:"package"`
	// WireProbesOnly marks a tool that only a plan with a wire probe needs
	// (Settings.NoWireProbes).
	WireProbesOnly bool `json:"wire_probes_only,omitempty"`
}

// Layer is the result of one layer.
type Layer struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	// Code names the kind of failure, when there is one.
	Code string `json:"code,omitempty"`
	// Detail is what passed, or what failed and why. It never holds a credential.
	Detail string `json:"detail,omitempty"`
	// Missing are the tools that were not found.
	Missing []Tool `json:"missing,omitempty"`
}

// Report is what node-check prints: the layers that were tried, in order, the
// last of them the one that failed if any did.
type Report struct {
	Layers []Layer `json:"layers"`
}

// Failed is the layer that failed, or nil when none did. A layer that could not
// be made (StatusUnchecked) did not fail.
func (r Report) Failed() *Layer {
	for i := range r.Layers {
		if r.Layers[i].Status == StatusFailed {
			return &r.Layers[i]
		}
	}
	return nil
}

// Settings are the connections to try, from the worker's environment.
type Settings struct {
	PVEURL         string
	PVETLSInsecure bool
	PVECAFile      string
	PVETokenID     string
	PVETokenSecret string

	PBSRepository  string
	PBSPassword    string
	PBSFingerprint string
	PBSNamespace   string

	// Sandbox, when set, is the plan's sandbox network that LayerSandbox
	// judges against this node.
	Sandbox *Sandbox

	// NoWireProbes is set when the controller named a plan that has no wire
	// probe (tcp, http, dns, ldap, mssql, smb): such a plan puts no address on
	// the sandbox bridge, so nft, which contains that address, is not required
	// of the node. With no plan named, nft is required, as doctor does.
	NoWireProbes bool
}

// Sandbox is the part of a plan's network the node judges.
type Sandbox struct {
	IPRange   string
	ProbeIP   string
	VNetID    string
	Lifecycle string
	// Mode and Peers are the plan's network.mode and network.peers: the peers of
	// a vxlan zone are addresses the node reaches that the range must not hold.
	Mode  string
	Peers string
}

// SettingsFromEnvironment reads the settings from the variables the worker is
// given: the ones a run's worker reads.
func SettingsFromEnvironment(insecure bool) Settings {
	return Settings{
		PVEURL:         os.Getenv("PVE_URL"),
		PVETLSInsecure: insecure,
		PVECAFile:      os.Getenv("CERTISTACK_PVE_CA_SOURCE"),
		PVETokenID:     os.Getenv("PVE_TOKEN_ID"),
		PVETokenSecret: os.Getenv("PVE_TOKEN_SECRET"),
		PBSRepository:  os.Getenv("PBS_REPOSITORY"),
		PBSPassword:    os.Getenv("PBS_PASSWORD"),
		PBSFingerprint: os.Getenv("PBS_FINGERPRINT"),
		PBSNamespace:   os.Getenv("PBS_NAMESPACE"),
	}
}

// Probes are what the layers ask of the node. A test replaces them.
type Probes struct {
	LookPath   func(name string) (string, error)
	PVEVersion func(ctx context.Context, s Settings) (string, error)
	PBSBackups func(ctx context.Context, s Settings) ([]pbs.VMBackups, error)
	// NodeNetworks reads the node's routes and addresses.
	NodeNetworks func() (preflight.NodeNetworks, error)
}

// DefaultProbes are the real ones: the node's PATH, the PVE client a run uses
// (with its TLS trust, and no retries so a failure is reported at once), and
// the PBS client a run uses.
func DefaultProbes() Probes {
	return Probes{
		LookPath: exec.LookPath,
		PVEVersion: func(ctx context.Context, s Settings) (string, error) {
			return pve.NewClient(pve.Config{
				BaseURL:     s.PVEURL,
				TLSInsecure: s.PVETLSInsecure,
				TLSCAFile:   s.PVECAFile,
				TokenID:     s.PVETokenID,
				TokenSecret: s.PVETokenSecret,
				Timeout:     10 * time.Second,
				NoRetry:     true,
			}).Version(ctx)
		},
		PBSBackups: func(ctx context.Context, s Settings) ([]pbs.VMBackups, error) {
			return pbs.New(pbs.Config{
				Repository:  s.PBSRepository,
				Password:    s.PBSPassword,
				Fingerprint: s.PBSFingerprint,
				Namespace:   s.PBSNamespace,
			}).ListVMBackups(ctx)
		},
		NodeNetworks: preflight.ReadNodeNetworks,
	}
}

// Layers are the layer names, in the order they are tried.
var Layers = []string{LayerTools, LayerPVE, LayerPBS, LayerSandbox}

// Run tries the layers in order and stops at the first that fails.
func Run(ctx context.Context, s Settings, p Probes) Report {
	return RunThrough(ctx, s, p, LayerPBS)
}

// RunThrough is Run that stops after the layer named through, when that layer
// passes. A caller that has no token to offer PVE yet asks for LayerTools and
// learns about the node's tools without a credential being tried. An unknown
// name runs every layer, the sandbox layer only where there is a plan's
// network to judge (Settings.Sandbox).
func RunThrough(ctx context.Context, s Settings, p Probes, through string) Report {
	var report Report
	for _, name := range Layers {
		var layer Layer
		switch name {
		case LayerTools:
			layer = checkTools(s, p)
		case LayerPVE:
			layer = checkPVE(ctx, s, p)
		case LayerPBS:
			layer = checkPBS(ctx, s, p)
		default:
			if s.Sandbox == nil {
				continue
			}
			layer = checkSandbox(ctx, s, p)
		}
		report.Layers = append(report.Layers, layer)
		if layer.Status == StatusFailed || name == through {
			break
		}
	}
	return report
}

func checkTools(s Settings, p Probes) Layer {
	var missing []Tool
	var found, notNeeded []string
	for _, tool := range Tools {
		_, err := p.LookPath(tool.Name)
		switch {
		case err == nil:
			found = append(found, tool.Name)
		case tool.WireProbesOnly && s.NoWireProbes:
			notNeeded = append(notNeeded, tool.Name)
		default:
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		names := make([]string, len(missing))
		for i, tool := range missing {
			names[i] = tool.Name
		}
		return Layer{Name: LayerTools, Status: StatusFailed, Code: CodeToolsMissing, Missing: missing,
			Detail: "not installed on the node (or not on its PATH): " + strings.Join(names, ", ")}
	}
	detail := "found on the node: " + strings.Join(found, ", ")
	if len(notNeeded) > 0 {
		detail += "; " + strings.Join(notNeeded, ", ") + " not found, and not needed: the plan has no wire probe"
	}
	return Layer{Name: LayerTools, Status: StatusPassed, Detail: detail}
}

func checkPVE(ctx context.Context, s Settings, p Probes) Layer {
	version, err := p.PVEVersion(ctx, s)
	if err != nil {
		code, detail := ClassifyPVE(err)
		return Layer{Name: LayerPVE, Status: StatusFailed, Code: code, Detail: detail}
	}
	detail := "the node reaches the PVE API and PVE accepts the token"
	if version != "" {
		detail += " (Proxmox VE " + version + ")"
	}
	return Layer{Name: LayerPVE, Status: StatusPassed, Detail: detail}
}

func checkPBS(ctx context.Context, s Settings, p Probes) Layer {
	where := "the repository"
	if s.PBSNamespace != "" {
		where = fmt.Sprintf("namespace %q", s.PBSNamespace)
	}
	backups, err := p.PBSBackups(ctx, s)
	if err != nil {
		return Layer{Name: LayerPBS, Status: StatusFailed, Code: CodePBSFailed, Detail: err.Error()}
	}
	detail := fmt.Sprintf("the PBS credential lists %s: %s", where, backupCount(len(backups)))
	if len(backups) == 0 && s.PBSNamespace == "" {
		// The commonest cause of an empty list on a working credential is
		// backups kept in a namespace, which the root of the repository does
		// not list. The layer passes: the credential works.
		detail += " (if your backups are in a namespace, set PBS_NAMESPACE)"
	}
	return Layer{Name: LayerPBS, Status: StatusPassed, Detail: detail}
}

// checkSandbox judges the plan's sandbox network on the node: that the range
// holds neither the PVE API nor the PBS server this node would use, and that it
// overlaps none of the node's own networks. Routes the node would not give are
// a layer that could not be made, never a pass.
func checkSandbox(ctx context.Context, s Settings, p Probes) Layer {
	network := config.Network{IPRange: s.Sandbox.IPRange, ProbeIP: s.Sandbox.ProbeIP, VNetID: s.Sandbox.VNetID, Lifecycle: s.Sandbox.Lifecycle, Mode: s.Sandbox.Mode, Peers: s.Sandbox.Peers}
	plan := &config.Plan{Network: network}
	if err := preflight.CheckSandboxRange(ctx, plan, s.PVEURL, s.PBSRepository, nil); err != nil {
		return Layer{Name: LayerSandbox, Status: StatusFailed, Code: CodeSandboxRange, Detail: err.Error()}
	}
	read := p.NodeNetworks
	if read == nil {
		read = preflight.ReadNodeNetworks
	}
	warning, err := preflight.VerifySandboxNetwork(network, preflight.OwnVNetInterface(network), read)
	switch {
	case err != nil:
		return Layer{Name: LayerSandbox, Status: StatusFailed, Code: CodeSandboxNetwork, Detail: err.Error()}
	case warning != "":
		return Layer{Name: LayerSandbox, Status: StatusUnchecked, Detail: warning}
	}
	return Layer{Name: LayerSandbox, Status: StatusPassed, Detail: fmt.Sprintf("network.ip_range %s holds neither the PVE API nor the PBS server, and overlaps none of the node's routes or addresses", s.Sandbox.IPRange)}
}

func backupCount(vms int) string {
	switch vms {
	case 0:
		return "no VM has a complete backup there yet"
	case 1:
		return "1 VM has a complete backup"
	}
	return fmt.Sprintf("%d VMs have a complete backup", vms)
}

// ClassifyPVE says what kind of failure err is, in words that name the cause
// and hold no credential, from the error's type and not its text.
func ClassifyPVE(err error) (code, detail string) {
	var (
		unknownAuthority x509.UnknownAuthorityError
		hostname         x509.HostnameError
		invalid          x509.CertificateInvalidError
		apiError         *pve.APIError
		urlError         *url.Error
	)
	switch {
	case errors.As(err, &unknownAuthority):
		return CodePVECAUntrusted, "the node does not trust the certificate authority that signed the PVE API certificate (x509: certificate signed by unknown authority)"
	case errors.As(err, &hostname):
		return CodePVECertName, "the PVE API certificate does not name the host in PVE_URL (" + hostname.Host + ")"
	case errors.As(err, &invalid):
		return CodePVECertInvalid, "the PVE API certificate is not valid: " + invalid.Error()
	case errors.As(err, &apiError):
		switch apiError.StatusCode {
		case http.StatusUnauthorized:
			return CodePVEAuth, "PVE answered but rejected the token (HTTP 401)"
		case http.StatusForbidden:
			return CodePVEForbidden, "PVE answered but the token may not read the version (HTTP 403)"
		}
		return CodePVEOther, apiError.Error()
	case strings.HasPrefix(err.Error(), "configure PVE API client"):
		return CodePVEConfig, err.Error()
	case errors.As(err, &urlError):
		return CodePVEUnreachable, "the node cannot reach the PVE API: " + urlError.Err.Error()
	case errors.Is(err, context.DeadlineExceeded), pve.IsTransient(err):
		return CodePVEUnreachable, "the node cannot reach the PVE API: " + err.Error()
	}
	return CodePVEOther, err.Error()
}

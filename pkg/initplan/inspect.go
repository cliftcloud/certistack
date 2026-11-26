// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package initplan

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/cliftcloud/certistack/internal/vmlimits"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// init --inspect looks inside the newest backup of each Linux VM that the plan
// gives a sandbox address, read-only, for the services the guest runs, and
// Compose writes a probe for what it finds. The types below are what the
// controller asks a node for and what the node answers: the node is the
// less-trusted side, so the controller checks the answer against its request
// (CheckInspection) and treats every text in it as the guest's.

// The services an inspection recognizes, by kind.
const (
	ServiceNginx      = "nginx"
	ServiceApache     = "apache"
	ServicePostgreSQL = "postgresql"
	ServiceMariaDB    = "mariadb"
	ServiceRedis      = "redis"
	ServiceSSH        = "sshd"
)

// InspectRequest is what init asks a node to inspect.
type InspectRequest struct {
	Node      string          `json:"node"`
	Namespace string          `json:"namespace,omitempty"`
	Targets   []InspectTarget `json:"targets"`
}

// InspectTarget is one VM's newest backup, as discovery found it.
type InspectTarget struct {
	SourceVMID int    `json:"source_vmid"`
	Snapshot   string `json:"snapshot"`
}

// maxInspectTargets is the most VMs one inspection reads: as many as a plan
// gives sandbox addresses.
const maxInspectTargets = lastGuestHost - firstGuestHost + 1

// ValidateInspectRequest checks every value of req, which reaches a node's
// command line.
func ValidateInspectRequest(req InspectRequest) error {
	if err := ValidateRequest(Request{Node: req.Node, Namespace: req.Namespace}); err != nil {
		return err
	}
	if len(req.Targets) == 0 || len(req.Targets) > maxInspectTargets {
		return fmt.Errorf("an inspection reads 1 to %d VMs, not %d", maxInspectTargets, len(req.Targets))
	}
	seen := map[int]bool{}
	for _, target := range req.Targets {
		if target.SourceVMID < 1 || target.SourceVMID > vmlimits.MaxVMID {
			return fmt.Errorf("invalid VM ID %d", target.SourceVMID)
		}
		if vmid, ok := pbs.SnapshotVMID(target.Snapshot); !ok || vmid != target.SourceVMID {
			return fmt.Errorf("%q is not a backup snapshot of VM %d", target.Snapshot, target.SourceVMID)
		}
		if seen[target.SourceVMID] {
			return fmt.Errorf("VM %d is named twice", target.SourceVMID)
		}
		seen[target.SourceVMID] = true
	}
	return nil
}

// InspectionTargets are the VMs of d whose newest backup init --inspect
// reads: the Linux guests with a NIC that the plan Compose writes keeps and
// gives a sandbox address, the only ones whose services a wire probe can
// reach. overlayStorage is the operator's choice, as for Compose.
func InspectionTargets(d *Discovery, overlayStorage string) []InspectTarget {
	if d == nil {
		return nil
	}
	storage, _, err := chooseOverlayStorage(d, overlayStorage)
	if err != nil {
		return nil // Compose refuses the same choice, and says why
	}
	var targets []InspectTarget
	for i, reason := range leftOutVMs(d.VMs, storage) {
		vm := d.VMs[i]
		if reason == "" && guestKind(vm.OSType) == "linux" && vm.HasNIC && len(targets) < maxInspectTargets {
			targets = append(targets, InspectTarget{SourceVMID: vm.SourceVMID, Snapshot: vm.Snapshot})
		}
	}
	return targets
}

// Inspection is a node's answer to an InspectRequest.
type Inspection struct {
	// Refused says why nothing was inspected: the node's host lock is held,
	// its journal records an unfinished run, guestfish is missing.
	Refused string `json:"refused,omitempty"`
	// VMs are the requested VMs, in the request's order.
	VMs []InspectedVM `json:"vms,omitempty"`
	// Journaled is true once the node's journal names the inspection,
	// before anything is mapped: the controller then verifies the journal as
	// it verifies a run's. False when nothing was mapped.
	Journaled bool `json:"journaled,omitempty"`
	// CleanupVerified is true when every map was shown released and the
	// journal marked cleaned; CleanupErrors say what was not.
	CleanupVerified bool     `json:"cleanup_verified,omitempty"`
	CleanupErrors   []string `json:"cleanup_errors,omitempty"`
	// Interrupted names the signal that stopped the inspection.
	Interrupted string `json:"interrupted,omitempty"`
}

// InspectedVM is what an inspection made of one VM's backup.
type InspectedVM struct {
	SourceVMID int    `json:"source_vmid"`
	Snapshot   string `json:"snapshot"`
	// Skipped says why the backup was not read at all.
	Skipped string `json:"skipped,omitempty"`
	// Failed says why reading it failed.
	Failed string `json:"failed,omitempty"`
	GuestFindings
}

// GuestFindings is what a guest's files say it runs.
type GuestFindings struct {
	// OS is the guest's name for itself (os-release PRETTY_NAME).
	OS       string    `json:"os,omitempty"`
	Services []Service `json:"services,omitempty"`
	// Notes say what was not read or followed.
	Notes []string `json:"notes,omitempty"`
}

// Service is one service the guest enables, and how it listens.
type Service struct {
	Kind string `json:"kind"`
	// Unit is the systemd unit the guest enables.
	Unit string `json:"unit"`
	// Config is the main configuration file read, "" when none was.
	Config    string     `json:"config,omitempty"`
	Listeners []Listener `json:"listeners,omitempty"`
	// Defaulted is true when no listen setting was found and the server's
	// own default is what the listeners show.
	Defaulted bool `json:"defaulted,omitempty"`
	// NoTCP says why the service accepts no TCP connection at all.
	NoTCP string   `json:"no_tcp,omitempty"`
	Notes []string `json:"notes,omitempty"`
}

// Listener is one address and port a service listens on.
type Listener struct {
	// Address is as configured; "" is every address.
	Address string `json:"address,omitempty"`
	Port    int    `json:"port"`
	TLS     bool   `json:"tls,omitempty"`
	// HTTP is true for a web server's listener.
	HTTP bool `json:"http,omitempty"`
	// Status is the HTTP status the configuration answers "/" with on this
	// port (a redirect, a return), 0 when it shows none.
	Status int `json:"status,omitempty"`
	// File is where the setting was read; Text the setting as written.
	File string `json:"file,omitempty"`
	Text string `json:"text,omitempty"`
}

// Scopes of a listener's address.
const (
	ScopeAll      = "all"      // every address: the sandbox address too
	ScopeLoopback = "loopback" // the guest itself only
	ScopeAddress  = "address"  // one address of the guest's own network
)

// Scope says which addresses of the guest the listener answers on.
func (l Listener) Scope() string {
	address := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(l.Address), "["), "]")
	switch strings.ToLower(address) {
	case "", "*", "0.0.0.0", "::", "_default_":
		return ScopeAll
	case "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback":
		return ScopeLoopback
	}
	if ip := net.ParseIP(address); ip != nil {
		if ip.IsLoopback() {
			return ScopeLoopback
		}
		if ip.IsUnspecified() {
			return ScopeAll
		}
	}
	return ScopeAddress
}

// Bounds of what the controller takes from a node's inspection. They are far
// above what a guest has: what goes past them is dropped.
const (
	maxInspectedServices = 32
	maxInspectedListener = 16
	maxInspectedNotes    = 8
	maxInspectedText     = 300
)

var knownServiceKinds = map[string]bool{ServiceNginx: true, ServiceApache: true, ServicePostgreSQL: true, ServiceMariaDB: true, ServiceRedis: true, ServiceSSH: true}

// CheckInspection checks a node's answer against the request it answers:
// at most one entry per requested VM, for that VM's backup, and nothing past
// the bounds. What a node may not answer is an error; what is merely more
// than init uses is dropped.
func CheckInspection(req InspectRequest, in *Inspection) error {
	if in == nil {
		return errors.New("no inspection")
	}
	wanted := map[int]string{}
	for _, target := range req.Targets {
		wanted[target.SourceVMID] = target.Snapshot
	}
	seen := map[int]bool{}
	for i := range in.VMs {
		vm := &in.VMs[i]
		snapshot, ok := wanted[vm.SourceVMID]
		switch {
		case !ok:
			return fmt.Errorf("the node answered for VM %d, which was not asked for", vm.SourceVMID)
		case seen[vm.SourceVMID]:
			return fmt.Errorf("the node answered twice for VM %d", vm.SourceVMID)
		case vm.Snapshot != snapshot:
			return fmt.Errorf("the node answered for VM %d's backup %q, not the %q asked for", vm.SourceVMID, vm.Snapshot, snapshot)
		}
		seen[vm.SourceVMID] = true
		var services []Service
		for _, service := range vm.Services {
			if !knownServiceKinds[service.Kind] || len(services) == maxInspectedServices {
				continue
			}
			var listeners []Listener
			for _, l := range service.Listeners {
				if l.Port < 1 || l.Port > 65535 || len(listeners) == maxInspectedListener {
					continue
				}
				if l.Status != 0 && (l.Status < 200 || l.Status > 599) {
					l.Status = 0
				}
				listeners = append(listeners, l)
			}
			service.Listeners = listeners
			if len(service.Notes) > maxInspectedNotes {
				service.Notes = service.Notes[:maxInspectedNotes]
			}
			services = append(services, service)
		}
		vm.Services = services
		if len(vm.Notes) > maxInspectedNotes {
			vm.Notes = vm.Notes[:maxInspectedNotes]
		}
	}
	return nil
}

// guestText is a text of the guest's (a file name, a unit, its OS name) or
// of the node's, made safe for a comment of the plan: printable ASCII on one
// line, bounded. Anything else becomes "?", so it cannot end the comment,
// start a line of YAML, or reorder what the operator reads.
func guestText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxInspectedText {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r > 0x7e {
			r = '?'
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

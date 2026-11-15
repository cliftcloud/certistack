// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package initplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/macaddr"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// Options are the operator's choices for Compose.
type Options struct {
	PlanID string
	Name   string
	// OverlayStorage is the storage to put overlays on; empty chooses one of
	// the discovered storages.
	OverlayStorage string
	// Written is when the plan is written, for its header.
	Written time.Time
	// Inspect is set when init --inspect was asked for. Inspection is the
	// node's answer, checked with CheckInspection; nil, or one with Refused
	// set, when the node could not be asked or refused: each Linux VM then
	// keeps the SSH probe, with the reason.
	Inspect    bool
	Inspection *Inspection
}

// Result is a composed plan.
type Result struct {
	YAML []byte
	// Notes are what the operator should know before the first run: VMs
	// left out and why, and probes to change.
	Notes []string
	// VMs is how many VMs the plan restores.
	VMs int
	// InspectHint is set when the plan checks Linux VMs on SSH and
	// --inspect was not asked for: it could have found their services.
	InspectHint bool
}

// inspectedVM is the node's answer for one VM, or nil.
func inspectedVM(in *Inspection, vmid int) *InspectedVM {
	if in == nil {
		return nil
	}
	for i := range in.VMs {
		if in.VMs[i].SourceVMID == vmid {
			return &in.VMs[i]
		}
	}
	return nil
}

// notInspectedReason is why the node has no answer for a VM.
func notInspectedReason(in *Inspection) string {
	switch {
	case in == nil:
		return "the node was not asked"
	case in.Refused != "":
		return in.Refused
	case in.Interrupted != "":
		return "the inspection was stopped (" + in.Interrupted + ")"
	}
	return "the node gave no answer for it"
}

// notInspectedKind says, for a VM init --inspect does not read, what it is.
func notInspectedKind(kind, osType string, hasNIC bool) string {
	switch {
	case kind == "windows":
		return "a Windows guest"
	case kind != "linux":
		return "guest OS type " + guestText(osType)
	case !hasNIC:
		return "a Linux guest without a NIC"
	}
	return ""
}

// notInspectedComment is the plan's comment for a VM init --inspect does not
// read.
func notInspectedComment(kind, osType string, hasNIC bool) string {
	if kind == "linux" && !hasNIC {
		return "Not inspected: its backup has no NIC, so the sandbox gives it no address on which a service found in it could be probed."
	}
	return "Not inspected: init --inspect reads Linux guests, and this is " + notInspectedKind(kind, osType, hasNIC) + "."
}

// checksSSH reports whether the choice checks the VM on SSH: the fallback, or
// sshd as the one service found to probe.
func (c probeChoice) checksSSH() bool {
	return c.fallback != "" || len(c.probes) == 1 && c.probes[0].service.Kind == ServiceSSH
}

// sandbox addresses: the RFC 5737 documentation range, on an isolated
// VNet, so it never clashes with a real network the sandbox could reach.
const (
	sandboxRange   = "192.0.2.0/24"
	sandboxProbeIP = "192.0.2.1"
	firstGuestHost = 10
	lastGuestHost  = 250
)

// uefiNeedsStorage is why a UEFI VM is left out when there is no overlay
// storage: Proxmox VE attaches firmware state only from a storage volume.
const uefiNeedsStorage = "it boots with UEFI, which needs overlay storage for its firmware state"

// leftOut says why the plan Compose writes leaves vm out, or "" when it keeps
// it. storage is the one chosen for overlays, "" for none. It is the one rule
// for both what Compose writes and how many sandbox IDs discovery reserves: a
// VM that is left out must not spend an ID, and a reason added to one of the
// two and not the other brought an earlier failure back for the VMs only
// that one knew of (the guests it leaves out).
func leftOut(vm VM, storage string) string {
	switch {
	case vm.Error != "":
		return vm.Error
	case vm.BIOS == "ovmf" && storage == "":
		return uefiNeedsStorage
	case !vm.Agent && !(guestKind(vm.OSType) == "linux" && vm.HasNIC):
		// Without the agent or an address the sandbox can give it, the only
		// probe left would be QMP, which shows that QEMU runs the VM and
		// nothing about the guest: a boot loop or a kernel panic passes it. A
		// plan is never written that certifies a guest on that.
		return "its backup has no guest agent enabled, and only a Linux guest with a NIC gets a sandbox address to probe, so a run could show that QEMU runs it but nothing about the guest. Enable the guest agent in the VM and back it up again, or add it to the plan by hand with a tcp or http probe on its own address (its network_recovery mode is preserve, and network.ip_range must be the guest's subnet)"
	}
	return ""
}

// leftOutVMs says, for each of vms, why the plan Compose writes leaves it out,
// or "" when it keeps it: leftOut, and then the one reason that is a property
// of a pair. The plan inherits each backup's net0 MAC, and the sandbox VMs
// share one isolated VNet, so a backup whose MAC an earlier kept VM's backup
// also carries (VMs cloned from one another) cannot be in the same plan: two
// NICs with one address make the VNet's bridge send frames for both guests to
// whichever port spoke last, and a run refuses the plan. The later
// VM is left out, with the reason.
func leftOutVMs(vms []VM, storage string) []string {
	reasons := make([]string, len(vms))
	var registry macaddr.Registry
	for i, vm := range vms {
		if reasons[i] = leftOut(vm, storage); reasons[i] != "" || vm.MAC == "" {
			continue
		}
		if prior, ok := registry.Claim(vm.MAC, vmLabel(vm)); !ok {
			reasons[i] = fmt.Sprintf("its backup's net0 MAC %s is also the MAC of VM %s, and two NICs with one address on the sandbox network make the bridge send frames for both guests to whichever spoke last. Restore the two in separate plans, or add this one to a plan by hand with a distinct mac and network_recovery.mode auto", vm.MAC, prior)
		}
	}
	return reasons
}

// sandboxIDsNeeded is how many sandbox VM IDs the plan of d needs: one for
// each VM Compose keeps (leftOutVMs). storage is the one chosen for overlays,
// or "" to ask about the discovered storages (Compose only ever picks one of
// them, or refuses).
func (d *Discovery) sandboxIDsNeeded(storage string) int {
	if storage == "" && len(d.Storages) > 0 {
		storage = d.Storages[0].Storage
	}
	needed := 0
	for _, reason := range leftOutVMs(d.VMs, storage) {
		if reason == "" {
			needed++
		}
	}
	return needed
}

// Compose writes a plan for the discovered VMs: one tier, each VM restored
// from its newest backup with its backed-up configuration, and a first
// probe chosen from what the backup says about the guest. The plan is
// validated as `certistack validate` would; one that is not valid is an
// error, never written.
func Compose(d *Discovery, opts Options) (*Result, error) {
	if d == nil || len(d.VMs) == 0 {
		return nil, errors.New("no VMs to put in the plan")
	}
	res := &Result{}
	note := func(format string, args ...any) { res.Notes = append(res.Notes, fmt.Sprintf(format, args...)) }

	storage, storageComment, err := chooseOverlayStorage(d, opts.OverlayStorage)
	if err != nil {
		return nil, err
	}
	// Only the VMs the plan can hold need a sandbox ID.
	if len(d.SandboxVMIDs) < d.sandboxIDsNeeded(storage) || d.ZoneID == "" || d.VNetID == "" {
		return nil, errors.New("the discovery has no free sandbox VM IDs or SDN IDs")
	}
	if storage == "" {
		note("Node %s has no storage the token can use for overlays (file-based, with disk image content), so overlays go to the node's scratch directory. UEFI VMs need one; see storage.overlay_storage in the plan reference. %s", progress.SingleLine(d.Node), pve.CreateOverlayStorageHint)
	}

	type entry struct {
		vm      VM
		vmid    int
		address string // the sandbox address of a Linux guest checked on the wire
		kind    string
		// choice is what init --inspect chose for a Linux guest checked on
		// the wire; nil without --inspect.
		choice *probeChoice
	}
	var entries []entry
	var excluded []string
	nextHost, nextID := firstGuestHost, 0
	var linuxSSH, windowsQGA, multiNIC, inspected, notInspected []string
	reasons := leftOutVMs(d.VMs, storage)
	for i, vm := range d.VMs {
		label := vmLabel(vm)
		if reason := reasons[i]; reason != "" {
			excluded = append(excluded, progress.SingleLine(fmt.Sprintf("VM %s: %s", label, reason)))
			continue
		}
		e := entry{vm: vm, vmid: d.SandboxVMIDs[nextID], kind: guestKind(vm.OSType)}
		nextID++
		if e.kind == "linux" && vm.HasNIC {
			if nextHost > lastGuestHost {
				return nil, fmt.Errorf("more than %d Linux VMs; split them into several plans", lastGuestHost-firstGuestHost+1)
			}
			e.address = hostAddress(nextHost)
			nextHost++
			switch {
			case !opts.Inspect:
				linuxSSH = append(linuxSSH, label)
			default:
				choice := chooseProbes(inspectedVM(opts.Inspection, vm.SourceVMID), notInspectedReason(opts.Inspection))
				e.choice = &choice
				if choice.checksSSH() {
					linuxSSH = append(linuxSSH, label+": "+progress.SingleLine(choice.summary))
				} else {
					inspected = append(inspected, label+": "+progress.SingleLine(choice.summary))
				}
			}
		} else if e.kind == "windows" && vm.Agent {
			windowsQGA = append(windowsQGA, label)
		}
		if opts.Inspect && e.address == "" {
			notInspected = append(notInspected, label+": "+notInspectedKind(e.kind, vm.OSType, vm.HasNIC))
		}
		if len(vm.OtherNICs) > 0 {
			multiNIC = append(multiNIC, label)
		}
		entries = append(entries, e)
	}
	for _, reason := range excluded {
		note("Not in the plan: %s.", reason)
	}
	if len(entries) == 0 {
		refusal := fmt.Sprintf("none of the VMs can be restored as their backups stand:\n  %s", strings.Join(excluded, "\n  "))
		for _, reason := range reasons {
			if reason == uefiNeedsStorage {
				// Name the way out once, whatever the number of UEFI VMs.
				refusal += "\nUEFI VMs need overlay storage. " + pve.CreateOverlayStorageHint
				break
			}
		}
		return nil, errors.New(refusal)
	}
	res.VMs = len(entries)
	switch {
	case len(linuxSSH) > 0 && !opts.Inspect:
		note("Linux VMs checked on SSH (port 22) until you change it to the service each one provides: %s.", strings.Join(linuxSSH, ", "))
		res.InspectHint = true
	case len(linuxSSH) > 0:
		note("Linux VMs checked on SSH until you change it to the service each one provides: %s.", strings.Join(linuxSSH, "; "))
	}
	if len(inspected) > 0 {
		note("Linux VMs checked on the services found in their newest backup (confirm each is what the VM is for): %s.", strings.Join(inspected, "; "))
	}
	if len(notInspected) > 0 {
		note("Not inspected (init --inspect reads the Linux guests the sandbox gives an address): %s.", strings.Join(notInspected, "; "))
	}
	if len(windowsQGA) > 0 {
		note("Windows VMs checked through their guest agent (the Event Log service): %s. Add the service each one provides.", strings.Join(windowsQGA, ", "))
	}
	if len(multiNIC) > 0 {
		note("VMs with more NICs than net0, which the sandbox leaves out: %s. A service bound to another NIC's address can fail to start; then set network_recovery.attach_all_nics: true (see the plan's comments).", strings.Join(multiNIC, ", "))
	}

	planID := opts.PlanID
	if planID == "" {
		planID = "recovery-" + d.Node
	}
	name := opts.Name
	if name == "" {
		name = fmt.Sprintf("Recovery check of %d VM(s) on %s", len(entries), progress.SingleLine(d.Node))
	}
	written := opts.Written
	if written.IsZero() {
		written = time.Now()
	}

	var b bytes.Buffer
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# Written by `certistack init` on %s from node %s and its PBS backups.", written.UTC().Format("2006-01-02 15:04 UTC"), progress.SingleLine(d.Node))
	w("# A run restores the newest backup of each VM below into an isolated")
	w("# sandbox, checks each guest with the probes listed under it (from the")
	w("# worker over the sandbox network, or through the guest agent), writes a JSON")
	w("# report (unsigned in the Community Edition), and removes the sandbox. Backups")
	w("# and source VMs are only read.")
	w("# A VM counts as verified only when a probe that asserts something in the")
	w("# guest passed. The plan is valid as it stands. Change each probe marked")
	w("# CHANGE to the service its VM exists for, then:")
	w("#   certistack plan <this file>   shows what a run would do, and changes nothing")
	w("#   certistack run <this file>")
	w(`version: "v1"`)
	w("plan_id: %s", q(planID))
	w("name: %s", q(name))
	w("# Each sandbox VM takes its disks, firmware and hardware from its backup.")
	w("use_backup_config: true")
	w("")
	w("compliance:")
	w("  # The standards the report is labelled with: DORA, SOC2, HIPAA, ISO27001,")
	w("  # CIS_V8 (a label, not a certification). %s names none and stands alone;", config.FrameworkNone)
	w("  # replace it to name one or more. It is valid as it stands.")
	w("  frameworks: [%s]", config.FrameworkNone)
	w("  # Your choice: the days you keep each report (1 to 36500; 2555 is seven years).")
	w("  # 90 is valid as it stands.")
	w("  retention_days: 90")
	w("")
	w("admission_control:")
	w("  # A run waits, and retries, while the node is busier than this.")
	w("  max_host_ram_percent: 85.0")
	w("  max_host_iowait_percent: 12.0")
	w("  defer_retry_interval_sec: 30")
	w("  max_defer_retries: 10")
	w("")
	w("network:")
	w("  # An SDN zone and VNet the run creates and removes: no gateway, no")
	w("  # uplink, so the sandbox cannot reach any other network. Both IDs were")
	w("  # free when this was written.")
	w(`  mode: "simple"`)
	w("  zone_id: %s", q(d.ZoneID))
	w("  vnet_id: %s", q(d.VNetID))
	w("  ip_range: %s", q(sandboxRange))
	w("  probe_ip: %s", q(sandboxProbeIP))
	if storage != "" || d.Namespace != "" {
		w("")
		w("storage:")
		if storage != "" {
			w("  # The sandbox's disk writes go to overlays on this storage (%s).", progress.SingleLine(storageComment))
			w("  overlay_storage: %s", q(storage))
		}
		if d.Namespace != "" {
			w("  pbs_namespace: %s", q(d.Namespace))
		}
	}
	w("")
	w("tiers:")
	w("  - level: 1")
	w(`    name: "Recovery check"`)
	w("    # Tiers start in order. Put what the others need (DNS, directory,")
	w("    # databases) in an earlier tier, and each tier's dependants after it.")
	w("    vms:")
	for _, e := range entries {
		vm := e.vm
		w("      # VM %s: %s, backed up %s%s.", vmLabel(vm), guestDescription(e.kind, vm.OSType), vm.BackupTime.UTC().Format("2006-01-02 15:04 UTC"), diskDescription(vm.DiskBytes))
		w("      - vmid: %d", e.vmid)
		w("        source_vmid: %d", vm.SourceVMID)
		w("        name: %s", q(sandboxName(vm)))
		w("        source_pbs:")
		w(`          storage_id: "pbs"`)
		w(`          snapshot: "latest"`)
		if d.Namespace != "" {
			w("          namespace: %s", q(d.Namespace))
		}
		if len(vm.OtherNICs) > 0 {
			w("        # The backup also has %s; the sandbox attaches only net0. If a", progress.SingleLine(strings.Join(vm.OtherNICs, ", ")))
			w("        # service listens on one of their addresses, it can fail to start:")
			w("        # then set network_recovery.attach_all_nics: true.")
		}
		if e.address == "" {
			w("        # The guest keeps its own network settings in the sandbox.")
			w("        network_recovery:")
			w(`          mode: "preserve"`)
		}
		w("        probes:")
		if opts.Inspect && e.address == "" {
			writeComment(w, "          ", notInspectedComment(e.kind, vm.OSType, vm.HasNIC))
		}
		switch {
		case e.address != "" && e.choice != nil && !e.choice.checksSSH():
			w("          # The run gives the guest this address on the sandbox VNet.")
			for _, line := range e.choice.header {
				writeComment(w, "          ", line)
			}
			for _, p := range e.choice.probes {
				writeProbe(w, p, e.address)
			}
		case e.address != "" && e.choice != nil:
			// SSH, as without --inspect, with what the inspection found or
			// why it found nothing, and today's CHANGE.
			w("          # The run gives the guest this address on the sandbox VNet.")
			for _, line := range e.choice.header {
				writeComment(w, "          ", line)
			}
			w("          # CHANGE: check the service this VM is for: http, dns, ldap,")
			w(`          # mssql, smb, or qga "systemctl is-active <unit>".`)
			if len(e.choice.probes) == 1 {
				writeProbe(w, e.choice.probes[0], e.address)
				break
			}
			w(`          - type: "tcp"`)
			w("            target_ip: %s", q(e.address))
			w("            port: 22")
			w("            timeout_sec: 300")
			w(`            description: "SSH answers on the sandbox address"`)
		case e.address != "":
			w("          # The run gives the guest this address on the sandbox VNet.")
			w("          # CHANGE: check the service this VM is for: http, dns, ldap,")
			w(`          # mssql, smb, or qga "systemctl is-active <unit>".`)
			w(`          - type: "tcp"`)
			w("            target_ip: %s", q(e.address))
			w("            port: 22")
			w("            timeout_sec: 300")
			w(`            description: "SSH answers on the sandbox address"`)
		case e.kind == "windows" && vm.Agent:
			w("          # The guest agent runs sc.exe: Windows started its services.")
			w(`          # CHANGE: add the service this VM is for, e.g. "sc query W3SVC".`)
			w(`          - type: "qga"`)
			w(`            command: "sc query EventLog"`)
			w("            require_qga: true")
			w("            timeout_sec: 600")
			w(`            description: "Windows Event Log service is running"`)
		case vm.Agent:
			w("          # CHANGE: add the service this VM is for.")
			w(`          - type: "qga"`)
			w(`            command: "ping"`)
			w("            require_qga: true")
			w("            timeout_sec: 300")
			w(`            description: "the guest agent answers"`)
		default:
			// Left out above: no probe here would assert anything in the guest.
			return nil, fmt.Errorf("no guest-level probe for VM %s (this is a bug in init)", vmLabel(vm))
		}
	}
	if len(excluded) > 0 {
		w("")
		w("# Not in this plan:")
		for _, reason := range excluded {
			w("#   %s", reason)
		}
	}

	// The plan as written must be valid: a first plan that needs an edit before
	// it validates is a plan the reader has to correct before trying it.
	if _, err := config.LoadFromReader(bytes.NewReader(b.Bytes())); err != nil {
		return nil, fmt.Errorf("the composed plan does not validate (this is a bug in init): %w", err)
	}
	res.YAML = b.Bytes()
	return res, nil
}

// chooseOverlayStorage is the requested storage, which must be one the node
// can use, or the discovered one with the most room, preferring storage
// local to the node. The comment says why, and what else there was.
func chooseOverlayStorage(d *Discovery, requested string) (string, string, error) {
	var names []string
	for _, s := range d.Storages {
		names = append(names, s.Storage)
	}
	if requested != "" {
		for _, s := range d.Storages {
			if s.Storage == requested {
				return requested, fmt.Sprintf("%s free", gib(s.Avail)), nil
			}
		}
		if len(names) == 0 {
			return "", "", fmt.Errorf("overlay storage %q cannot hold overlays on node %s: the node has no active file-based storage with disk image content that the token can use. %s", requested, d.Node, pve.CreateOverlayStorageHint)
		}
		return "", "", fmt.Errorf("overlay storage %q cannot hold overlays on node %s; these can: %s", requested, d.Node, strings.Join(names, ", "))
	}
	if len(d.Storages) == 0 {
		return "", "", nil
	}
	candidates := append([]pve.NodeStorage(nil), d.Storages...)
	sort.SliceStable(candidates, func(i, j int) bool {
		if (candidates[i].Shared == 0) != (candidates[j].Shared == 0) {
			return candidates[i].Shared == 0
		}
		return candidates[i].Avail > candidates[j].Avail
	})
	chosen := candidates[0]
	comment := fmt.Sprintf("%s free", gib(chosen.Avail))
	if len(candidates) > 1 {
		var others []string
		for _, s := range candidates[1:] {
			others = append(others, s.Storage)
		}
		comment = fmt.Sprintf("%s free; also possible: %s", gib(chosen.Avail), strings.Join(others, ", "))
	}
	return chosen.Storage, comment, nil
}

func guestKind(osType string) string {
	switch {
	case osType == "l26" || osType == "l24":
		return "linux"
	case strings.HasPrefix(osType, "w"):
		return "windows"
	default:
		return "other"
	}
}

// windowsVersions are PVE's own labels for its Windows OS types.
var windowsVersions = map[string]string{
	"win11":  "Windows 11/2022/2025",
	"win10":  "Windows 10/2016/2019",
	"win8":   "Windows 8.x/2012/2012 R2",
	"win7":   "Windows 7/2008 R2",
	"w2k8":   "Windows Vista/2008",
	"wvista": "Windows Vista/2008",
	"w2k3":   "Windows 2003",
	"wxp":    "Windows XP/2003",
	"w2k":    "Windows 2000",
}

func guestDescription(kind, osType string) string {
	osType = progress.SingleLine(osType)
	switch kind {
	case "linux":
		return "Linux"
	case "windows":
		if version, ok := windowsVersions[osType]; ok {
			return version + " (ostype " + osType + ")"
		}
		return "Windows (ostype " + osType + ")"
	default:
		return "guest OS type " + osType
	}
}

func diskDescription(bytes int64) string {
	if bytes <= 0 {
		return ""
	}
	return ", " + gib(bytes) + " of disks"
}

func gib(bytes int64) string {
	return fmt.Sprintf("%.0f GiB", float64(bytes)/(1<<30))
}

func vmLabel(vm VM) string {
	if name := progress.SingleLine(vm.Name); name != "" {
		return fmt.Sprintf("%d (%s)", vm.SourceVMID, name)
	}
	return fmt.Sprint(vm.SourceVMID)
}

// dnsName is what a PVE VM name is made of, the form the node reads a
// backup's name in (sandboxName cuts it to PVE's length).
var dnsName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// sandboxName is the sandbox VM's name: "cs-" and the source's name, or its
// VM ID, within PVE's 63 characters. A source already named "cs-…" gets
// "cs-sandbox-…": never the source's own name, and no "cs-cs-".
func sandboxName(vm VM) string {
	base := vm.Name
	if !dnsName.MatchString(base) {
		// No name, or one no PVE VM has (only a worker that lies sends it).
		base = fmt.Sprintf("vm%d", vm.SourceVMID)
	}
	name := "cs-" + base
	if rest, ok := strings.CutPrefix(base, "cs-"); ok {
		name = "cs-sandbox-" + rest
	}
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-.")
	}
	return name
}

func hostAddress(host int) string {
	ip := net.ParseIP(sandboxProbeIP).To4()
	return net.IPv4(ip[0], ip[1], ip[2], byte(host)).String()
}

// q quotes s as a YAML double-quoted scalar; a JSON string is one.
func q(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

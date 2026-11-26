// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package initplan writes a first plan from what a node and its PBS
// repository really hold: the VMs with backups, what each backup's
// configuration says about its guest, the storages a run could put overlays
// on, and sandbox IDs that are free. Discover runs on the node, with a
// run's credentials, and only reads; Compose turns what it found into a
// commented plan that validates.
package initplan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cliftcloud/certistack/internal/vmlimits"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// Request is what to discover. Without VMIDs or All, Discover only lists
// the VMs that have backups.
type Request struct {
	Node      string `json:"node"`
	Namespace string `json:"namespace,omitempty"`
	VMIDs     []int  `json:"vmids,omitempty"`
	All       bool   `json:"all,omitempty"`
	// FirstVMID is where the search for free sandbox VM IDs starts.
	FirstVMID int `json:"first_vmid,omitempty"`
	// AvoidVMIDs and AvoidSDNIDs are taken by other plans, which PVE does
	// not know about between their runs.
	AvoidVMIDs  []int    `json:"avoid_vmids,omitempty"`
	AvoidSDNIDs []string `json:"avoid_sdn_ids,omitempty"`
}

// DefaultFirstVMID is where sandbox VM IDs start by default.
const DefaultFirstVMID = 9100

var (
	nodeName      = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	namespacePart = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$`)
	sdnID         = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,7}$`)
)

// ValidateRequest checks every value of req, which reaches a node's
// command line.
func ValidateRequest(req Request) error {
	if !nodeName.MatchString(req.Node) {
		return fmt.Errorf("invalid PVE node name %+q", req.Node)
	}
	if ns := req.Namespace; ns != "" {
		parts := strings.Split(ns, "/")
		if len(parts) > 7 {
			return fmt.Errorf("invalid PBS namespace %q: at most 7 levels", ns)
		}
		for _, part := range parts {
			if !namespacePart.MatchString(part) {
				return fmt.Errorf("invalid PBS namespace %q", ns)
			}
		}
	}
	if req.All && len(req.VMIDs) > 0 {
		return errors.New("name VMs or ask for all of them, not both")
	}
	for _, id := range append(append([]int(nil), req.VMIDs...), req.AvoidVMIDs...) {
		if id < 1 || id > vmlimits.MaxVMID {
			return fmt.Errorf("invalid VM ID %d", id)
		}
	}
	if req.FirstVMID != 0 && !vmlimits.ValidVMID(req.FirstVMID) {
		return fmt.Errorf("the first sandbox VM ID must be between %d and %d, not %d", vmlimits.MinVMID, vmlimits.MaxVMID, req.FirstVMID)
	}
	for _, id := range req.AvoidSDNIDs {
		if !sdnID.MatchString(id) {
			return fmt.Errorf("invalid SDN ID %q", id)
		}
	}
	return nil
}

// Discovery is what Discover found.
type Discovery struct {
	Node      string `json:"node"`
	Namespace string `json:"namespace,omitempty"`
	// Backups are every VM with a complete backup.
	Backups []pbs.VMBackups `json:"backups"`
	// VMs are the requested VMs, as their newest backups describe them.
	VMs []VM `json:"vms,omitempty"`
	// Storages are the node's storages that can hold overlays.
	Storages []pve.NodeStorage `json:"storages,omitempty"`
	// SandboxVMIDs are free VM IDs, one per VM.
	SandboxVMIDs []int  `json:"sandbox_vmids,omitempty"`
	ZoneID       string `json:"zone_id,omitempty"`
	VNetID       string `json:"vnet_id,omitempty"`
}

// VM is one VM's newest backup, as a run reads it.
type VM struct {
	SourceVMID int       `json:"source_vmid"`
	Snapshot   string    `json:"snapshot"`
	BackupTime time.Time `json:"backup_time"`
	Name       string    `json:"name,omitempty"`
	OSType     string    `json:"ostype,omitempty"`
	BIOS       string    `json:"bios,omitempty"`
	// MemoryMB is the memory the backup's configuration gives the VM; 0 when it
	// gives none.
	MemoryMB int  `json:"memory_mb,omitempty"`
	Agent    bool `json:"agent,omitempty"`
	// HasNIC is true when the backup has a usable net0, and MAC its address.
	HasNIC bool   `json:"has_nic,omitempty"`
	MAC    string `json:"mac,omitempty"`
	// OtherNICs are the backup's NICs after net0 (net1…), which a run
	// leaves out unless attach_all_nics is set.
	OtherNICs []string `json:"other_nics,omitempty"`
	DiskBytes int64    `json:"disk_bytes,omitempty"`
	CryptMode string   `json:"crypt_mode,omitempty"`
	// Error is why a run could not read the backup, which leaves the VM out
	// of the plan.
	Error string `json:"error,omitempty"`
}

// Backups reads the repository, as a run's PBS client does.
type Backups interface {
	ListVMBackups(ctx context.Context) ([]pbs.VMBackups, error)
	LoadVMProfile(ctx context.Context, snapshot, scratchDir string) (pbs.VMProfile, error)
}

// Cluster reads PVE, as a run's PVE client does.
type Cluster interface {
	UsedVMIDs(ctx context.Context) (map[int]bool, error)
	ListNodeStorages(ctx context.Context, node string) ([]pve.NodeStorage, error)
	// UsedSDNIDs is every SDN zone and VNet ID, lower-cased.
	UsedSDNIDs(ctx context.Context) (map[string]bool, error)
}

// profileReaders is how many backups' configurations are read at once.
const profileReaders = 4

// Discover finds what a plan for req needs. It changes nothing: it lists
// snapshots, reads the requested VMs' backed-up configurations into
// scratchDir, and reads PVE's VM IDs, storages and SDN IDs.
func Discover(ctx context.Context, backups Backups, cluster Cluster, req Request, scratchDir string) (*Discovery, error) {
	if err := ValidateRequest(req); err != nil {
		return nil, err
	}
	list, err := backups.ListVMBackups(ctx)
	if err != nil {
		return nil, err
	}
	d := &Discovery{Node: req.Node, Namespace: req.Namespace, Backups: list}
	chosen, err := choose(list, req)
	if err != nil || len(chosen) == 0 {
		return d, err
	}
	d.VMs = readVMs(ctx, backups, chosen, scratchDir)

	storages, err := cluster.ListNodeStorages(ctx, req.Node)
	if err != nil {
		return nil, err
	}
	for _, s := range storages {
		if s.CanHoldOverlays() {
			d.Storages = append(d.Storages, s)
		}
	}
	sort.Slice(d.Storages, func(i, j int) bool { return d.Storages[i].Storage < d.Storages[j].Storage })

	used, err := cluster.UsedVMIDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range req.AvoidVMIDs {
		used[id] = true
	}
	for _, b := range list {
		used[b.VMID] = true // a deleted VM's ID still names its backups
	}
	first := req.FirstVMID
	if first <= 0 {
		first = DefaultFirstVMID
	}
	// One sandbox ID for each VM the plan can hold. A VM that will be left
	// out, whose backup could not be read or that needs storage the node
	// lacks, must not use up an ID: with few IDs left it would fail a
	// discovery whose plan needs only the rest.
	needed := d.sandboxIDsNeeded("")
	for id := first; len(d.SandboxVMIDs) < needed; id++ {
		if id > vmlimits.MaxVMID {
			return nil, errors.New("no free VM IDs above the first sandbox VM ID")
		}
		if !used[id] {
			d.SandboxVMIDs = append(d.SandboxVMIDs, id)
		}
	}

	taken, err := cluster.UsedSDNIDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range req.AvoidSDNIDs {
		taken[strings.ToLower(id)] = true
	}
	for n := 1; n <= 99 && d.ZoneID == ""; n++ {
		zone, vnet := fmt.Sprintf("csZone%d", n), fmt.Sprintf("csVnet%d", n)
		if !taken[strings.ToLower(zone)] && !taken[strings.ToLower(vnet)] {
			d.ZoneID, d.VNetID = zone, vnet
		}
	}
	if d.ZoneID == "" {
		return nil, errors.New("SDN zones csZone1 to csZone99 are all taken; name a zone in the plan yourself")
	}
	return d, nil
}

// choose is the backups req asks for, in VM ID order. A requested VM
// without a backup is an error that names what is there.
func choose(list []pbs.VMBackups, req Request) ([]pbs.VMBackups, error) {
	if req.All {
		return list, nil
	}
	byID := map[int]pbs.VMBackups{}
	for _, b := range list {
		byID[b.VMID] = b
	}
	var chosen []pbs.VMBackups
	var missing []string
	seen := map[int]bool{}
	for _, id := range req.VMIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		if b, ok := byID[id]; ok {
			chosen = append(chosen, b)
		} else {
			missing = append(missing, fmt.Sprint(id))
		}
	}
	if len(missing) > 0 {
		where := "the repository"
		if req.Namespace != "" {
			where = fmt.Sprintf("namespace %q", req.Namespace)
		}
		return nil, fmt.Errorf("no complete backup of VM %s in %s; run init without --vm to list the VMs that have one", strings.Join(missing, ", "), where)
	}
	sort.Slice(chosen, func(i, j int) bool { return chosen[i].VMID < chosen[j].VMID })
	return chosen, nil
}

// readVMs reads each chosen VM's newest backup configuration, a few at a
// time: a fixed pool of profileReaders readers takes the backups one by one,
// so a long list costs no more goroutines than that. A backup a run could not
// read is kept with its error, and a backup the pool reaches after the run was
// canceled is not opened at all.
func readVMs(ctx context.Context, backups Backups, chosen []pbs.VMBackups, scratchDir string) []VM {
	vms := make([]VM, len(chosen))
	for i, b := range chosen {
		vms[i] = VM{SourceVMID: b.VMID, Snapshot: b.Latest, BackupTime: b.Time}
	}
	pending := make(chan *VM)
	var wg sync.WaitGroup
	for range min(profileReaders, len(vms)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for vm := range pending {
				readVM(ctx, backups, vm, scratchDir)
			}
		}()
	}
	for i := range vms {
		pending <- &vms[i]
	}
	close(pending)
	wg.Wait()
	return vms
}

// readVM reads one backup's configuration into a private scratch directory
// that it removes again. It makes nothing once ctx is done: a canceled run
// does not create a directory, or ask the repository, for the backups still
// waiting.
func readVM(ctx context.Context, backups Backups, vm *VM, scratchDir string) {
	if err := ctx.Err(); err != nil {
		vm.Error = fmt.Sprintf("not read: %v", err)
		return
	}
	dir, err := os.MkdirTemp(scratchDir, "certistack-init-")
	if err != nil {
		vm.Error = fmt.Sprintf("create a private scratch directory: %v", err)
		return
	}
	defer os.RemoveAll(dir)
	profile, err := backups.LoadVMProfile(ctx, vm.Snapshot, dir)
	if err != nil {
		vm.Error = err.Error()
		return
	}
	vm.Name = profile.Name
	vm.MemoryMB = profile.MemoryMB
	vm.OSType = profile.OSType
	vm.BIOS = profile.BIOS
	vm.Agent = profile.Agent
	vm.HasNIC = profile.MAC != ""
	vm.MAC = profile.MAC
	for _, nic := range profile.NICs {
		vm.OtherNICs = append(vm.OtherNICs, nic.Slot)
	}
	vm.CryptMode = profile.CryptMode
	for _, size := range profile.DiskBytes {
		vm.DiskBytes += size
	}
}

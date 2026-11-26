// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package journal persists resource ownership before advancing a run. A pending
// allocation after a crash is deliberately not guessed or silently discarded.
package journal

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const maxJournalBytes = 1 << 20

// LockHeldMessage starts the error Lock returns while another CertiStack
// operation holds the host lock; a controller recognizes a busy node by it.
const LockHeldMessage = "another CertiStack operation holds the host lock"

// Process records process identification including kernel start ticks to prevent PID reuse collisions.
//
// A PID and its start ticks (time since boot) name a process only within one
// boot of the host. BootID is the boot (/proc/sys/kernel/random/boot_id) the
// process was recorded in: a process recorded in another boot is gone, and one
// whose boot cannot be compared with this one is not signaled. A record
// without a BootID is re-checked by PID and start ticks only, and is not given
// a boot it never had.
type Process struct {
	PID        int    `json:"pid"`
	StartTicks string `json:"start_ticks"`
	BootID     string `json:"boot_id,omitempty"`
}

// TrackedLoop records an allocated loop device and its kernel-verified backing
// file identity. PBS snapshot labels are provenance, not safe loop identities.
//
// The backing path alone does not say whether a loop that is still there is
// the run's: once a PBS map's FUSE file is gone, a loop that something still
// holds reads "/" like any other stale loop. DiskSeq is the kernel's disk
// sequence number of the attachment (/sys/block/loopN/diskseq), read when the
// run mapped it, in the boot BootID names. The kernel gives a loop device a new
// number when it is attached and when it is finally released, never while a
// detach is deferred, and never the same number twice in one boot: the same
// number on the same device in the same boot is the run's attachment, whatever
// its backing reads now. Zero and "" are "not recorded" (a journal written
// without them, or a kernel without the attribute): the loop is then judged
// by its backing path alone, and a stale one is never called released.
type TrackedLoop struct {
	Device  string `json:"device"`
	Backing string `json:"backing"`
	DiskSeq uint64 `json:"diskseq,omitempty"`
	BootID  string `json:"boot_id,omitempty"`
}

// MapIntent records a PBS map before proxmox-backup-client makes it. A
// worker killed during the map, or a map that times out after its loop
// device exists, leaves a device this journal never learned. Recovery
// stops the map's own processes, and releases a loop device or map file
// only when its pid file leads to one of them. It knows the map's own
// processes by Token and Owner: a journal from before them has
// neither, and recovery then stops no process for it.
type MapIntent struct {
	Snapshot   string    `json:"snapshot"`
	Archive    string    `json:"archive"`
	NameSuffix string    `json:"name_suffix"`
	At         time.Time `json:"at"`
	// Device is set once the map's loop device is recorded in Loops.
	Device string `json:"device,omitempty"`
	// Owner is pbs.MapOwner of the repository and namespace the map reads
	// from, never the repository itself.
	Owner string `json:"owner,omitempty"`
	// Token is the pbs.MapTokenEnv the run gave the map's client. The map's
	// daemon keeps it in its environment across its fork, so a process that
	// carries it was started from this map.
	Token string `json:"token,omitempty"`
	// Processes are the proxmox-backup-client processes recovery proved to
	// be the map's own, journaled before it signaled them. A later attempt
	// stops them again while they run, and knows the map's leftovers by the
	// PID in their pid file once they are gone.
	Processes []Process `json:"processes,omitempty"`
	// BootID is the boot (/proc/sys/kernel/random/boot_id) Processes ran in:
	// a PID and start time name a process only within one boot.
	BootID string `json:"boot_id,omitempty"`
	// StaleLoopsChecked and StaleLoopsBefore record, before the map began, the
	// loop devices that were already stale on the host (read-only, attached to a
	// FUSE file no longer mounted). A stale loop that appears afterwards, with
	// the host lock held by this run alone, is what an interrupted map of this run
	// left; one that was there before is not touched.
	StaleLoopsChecked bool     `json:"stale_loops_checked,omitempty"`
	StaleLoopsBefore  []string `json:"stale_loops_before,omitempty"`
}

// AddProcess records p as one of the map's own processes.
func (m *MapIntent) AddProcess(p Process) {
	for _, known := range m.Processes {
		if known == p {
			return
		}
	}
	m.Processes = append(m.Processes, p)
}

// TrackedVM records a sandbox VM created during a run.
type TrackedVM struct {
	VMID    int     `json:"vmid"`
	Node    string  `json:"node"`
	Process Process `json:"process,omitempty"`
}

// TrackedHostAddress records the exact temporary address that makes the PVE
// host a probe endpoint on a transient isolated VNet.
type TrackedHostAddress struct {
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
	// ContainmentOnly records that only this run's nftables containment
	// table for the address is owned: the address itself was never assigned
	// (it may belong to someone else), so recovery removes only the table.
	ContainmentOnly bool `json:"containment_only,omitempty"`
	// IfIndex is the kernel index of the interface the address was added to,
	// and TableHandle the nftables handle of the containment table the run
	// installed. Recovery removes the address only while the
	// interface still has that index, and deletes the table by its handle, so
	// an interface, address or table of the same name that someone else made
	// since is left alone. Zero is "not recorded" (a journal from an earlier
	// version, or a kernel answer that could not be read): recovery then removes
	// nothing of it, and says what to check and remove by hand.
	IfIndex     int    `json:"ifindex,omitempty"`
	TableHandle uint64 `json:"nft_handle,omitempty"`
	// BootID is the boot (/proc/sys/kernel/random/boot_id) in which the run
	// captured IfIndex and TableHandle. Both numbers are kernel-lifetime
	// identities: an interface index and a table handle are allocated again after
	// a reboot, so a replacement of the same name can carry the same numbers.
	// They name the run's own interface or table only within this boot. A record
	// of another boot is of kernel objects that went with that boot; one whose
	// boot cannot be compared with the current one is left unresolved. A record
	// without a BootID is not given a boot it never had, and is reconciled by
	// the numbers alone.
	BootID string `json:"boot_id,omitempty"`
}

// Record holds the durable on-disk state of an active run.
type Record struct {
	RunID             string               `json:"run_id"`
	Phase             string               `json:"phase"`
	UpdatedAt         time.Time            `json:"updated_at"`
	Scratch           string               `json:"scratch"`
	AllocationPending string               `json:"allocation_pending,omitempty"`
	LoopDevice        string               `json:"loop_device,omitempty"`    // Legacy single loop
	LoopBacking       string               `json:"loop_backing,omitempty"`   // Legacy single loop
	Mapper            Process              `json:"mapper,omitempty"`         // Legacy mapper process
	QEMU              Process              `json:"qemu,omitempty"`           // Legacy QEMU process
	Loops             []TrackedLoop        `json:"loops,omitempty"`          // Multi-loop tracking
	MapIntents        []MapIntent          `json:"map_intents,omitempty"`    // PBS maps being made
	VMs               []TrackedVM          `json:"vms,omitempty"`            // Multi-VM tracking
	SDNZones          []string             `json:"sdn_zones,omitempty"`      // Ephemeral SDN zones
	SDNVNets          []string             `json:"sdn_vnets,omitempty"`      // Ephemeral SDN VNets
	SDNLockToken      string               `json:"sdn_lock_token,omitempty"` // PVE's SDN lock, while held
	HostAddresses     []TrackedHostAddress `json:"host_addresses,omitempty"` // Temporary VNet probe endpoints
	DeltaFiles        []string             `json:"delta_files,omitempty"`    // Ephemeral COW delta files
	// ScreenshotFiles are the diagnostic console-image files (a raw frame QEMU
	// writes and the PNG made from it) a screendump may have left in the scratch
	// directory. Each is journaled, by its exact unique name, before QEMU is
	// asked to write it, and dropped once removed; recovery removes what is still
	// recorded.
	ScreenshotFiles []string `json:"screenshot_files,omitempty"`
	CleanupErrors   []string `json:"cleanup_errors,omitempty"`
	// DeltaIdentities names, for the files in DeltaFiles this run created and
	// published, the file it created. Cleanup removes such a path only while
	// it still holds that file: one that appeared at the path since is left
	// alone. A path without an identity (one journaled without it, or a
	// staging file whose unguessable name is the proof) is removed by path.
	DeltaIdentities map[string]FileIdentity `json:"delta_identities,omitempty"`
	// SDNLockRequested is when a request for PVE's SDN lock was sent whose
	// answer is not known yet: PVE may hold the lock for it.
	SDNLockRequested string `json:"sdn_lock_requested,omitempty"`
	// SDNApplyTask is the UPID of the run's last SDN apply, which a later
	// apply waits for.
	SDNApplyTask string `json:"sdn_apply_task,omitempty"`
	// SDNApplyUnknown is when an SDN apply's reply was lost or named no task:
	// PVE may be reloading the nodes for it, and no apply starts over it until
	// no reloadnetworkall task is running.
	SDNApplyUnknown string `json:"sdn_apply_unknown,omitempty"`
	// SDNOwner is the marker the run gave the VNet it created (its alias in
	// PVE): recovery deletes a recorded VNet only while it still carries the
	// marker, since a VNet an administrator or another run created later under
	// the same name is not the run's. A journal without it cannot prove ownership.
	SDNOwner string `json:"sdn_owner,omitempty"`
}

// Allocation-pending texts of an SDN zone or VNet whose creation was sent and
// not confirmed: "SDN zone <id>", "SDN VNet <id>". Journals of every version
// carry them.
const (
	pendingZonePrefix = "SDN zone "
	pendingVNetPrefix = "SDN VNet "
)

// PendingSDNZoneAllocation is the zone whose creation was sent and never
// confirmed, or "". The zone is in SDNZones too from the version that journals
// it before the request; in a journal of an earlier one it is only here.
func (r *Record) PendingSDNZoneAllocation() string {
	if id, ok := strings.CutPrefix(r.AllocationPending, pendingZonePrefix); ok {
		return id
	}
	return ""
}

// PendingSDNVNetAllocation is PendingSDNZoneAllocation's VNet.
func (r *Record) PendingSDNVNetAllocation() string {
	if id, ok := strings.CutPrefix(r.AllocationPending, pendingVNetPrefix); ok {
		return id
	}
	return ""
}

// SDNZonePending and SDNVNetPending are the AllocationPending text of a
// creation about to be sent, for the run to journal before it sends it.
func SDNZonePending(id string) string { return pendingZonePrefix + id }

// SDNVNetPending is SDNZonePending's VNet.
func SDNVNetPending(id string) string { return pendingVNetPrefix + id }

// pendingHostAddressPrefix starts the allocation-pending text of a host probe
// address whose addition was started and never recorded: "host probe address
// <cidr> on <interface>". Journals of every version carry it.
const pendingHostAddressPrefix = "host probe address "

// HostAddressPending is the AllocationPending text of a host probe address
// about to be added, for the run to journal before it touches the host.
func HostAddressPending(cidr, iface string) string {
	return pendingHostAddressPrefix + cidr + " on " + iface
}

// PendingHostAddressAllocation is the interface and CIDR of a host probe
// address whose addition was started and never recorded, or ok false. The text
// must be exactly HostAddressPending's: a free-form allocation is not read
// into one (recovery settles a host address by inspecting the host, and only
// for text it can name precisely).
func (r *Record) PendingHostAddressAllocation() (iface, cidr string, ok bool) {
	rest, found := strings.CutPrefix(r.AllocationPending, pendingHostAddressPrefix)
	if !found {
		return "", "", false
	}
	parts := strings.Split(rest, " ")
	if len(parts) != 3 || parts[1] != "on" || parts[0] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[2], parts[0], true
}

// SDNAllocationPending reports whether AllocationPending is the creation of an
// SDN zone or VNet, which recovery can settle from PVE's own lists, rather than
// another kind of allocation, which only an operator can.
func (r *Record) SDNAllocationPending() bool {
	return r.PendingSDNZoneAllocation() != "" || r.PendingSDNVNetAllocation() != ""
}

// AddLoop registers a mapped loop device and its kernel-verified backing path
// into the journal record, with no attachment identity (see AddTrackedLoop).
func (r *Record) AddLoop(device, backing string) {
	r.AddTrackedLoop(TrackedLoop{Device: device, Backing: backing})
}

// AddTrackedLoop registers a mapped loop device with what the kernel reported
// for it: its backing path and, when it could be read, the attachment's disk
// sequence number and boot.
func (r *Record) AddTrackedLoop(loop TrackedLoop) {
	for _, l := range r.Loops {
		if l.Device == loop.Device {
			return
		}
	}
	r.Loops = append(r.Loops, loop)
	if r.LoopDevice == "" {
		r.LoopDevice = loop.Device
		r.LoopBacking = loop.Backing
	}
}

// AddMapIntent records a map about to be made and returns its index for
// ResolveMapIntent.
func (r *Record) AddMapIntent(snapshot, archive, nameSuffix string, at time.Time) int {
	r.MapIntents = append(r.MapIntents, MapIntent{Snapshot: snapshot, Archive: archive, NameSuffix: nameSuffix, At: at.UTC()})
	return len(r.MapIntents) - 1
}

// SetMapIntentIdentity records what the map at index reads from (a
// pbs.MapOwner) and the token its processes will carry.
func (r *Record) SetMapIntentIdentity(index int, owner, token string) {
	if index >= 0 && index < len(r.MapIntents) {
		r.MapIntents[index].Owner = owner
		r.MapIntents[index].Token = token
	}
}

// SetMapIntentStaleLoops records the stale FUSE loop devices the host had when
// the map was about to begin. An empty list is a statement too: none.
func (r *Record) SetMapIntentStaleLoops(index int, devices []string) {
	if index >= 0 && index < len(r.MapIntents) {
		r.MapIntents[index].StaleLoopsChecked = true
		r.MapIntents[index].StaleLoopsBefore = append([]string(nil), devices...)
	}
}

// ResolveMapIntent records the loop device a map produced.
func (r *Record) ResolveMapIntent(index int, device string) {
	if index >= 0 && index < len(r.MapIntents) {
		r.MapIntents[index].Device = device
	}
}

// UnresolvedMapIntents are the maps begun but never recorded as a loop.
func (r *Record) UnresolvedMapIntents() []MapIntent {
	var open []MapIntent
	for _, intent := range r.MapIntents {
		if intent.Device == "" {
			open = append(open, intent)
		}
	}
	return open
}

// OpenMapIntents are the UnresolvedMapIntents themselves, for recovery to
// journal what it finds out about them.
func (r *Record) OpenMapIntents() []*MapIntent {
	var open []*MapIntent
	for i := range r.MapIntents {
		if r.MapIntents[i].Device == "" {
			open = append(open, &r.MapIntents[i])
		}
	}
	return open
}

// MapIntentOfLoop is the map intent whose loop device is device, or the zero
// intent when the journal has none: an older journal, or a loop no intent
// resolved to.
func (r *Record) MapIntentOfLoop(device string) MapIntent {
	for _, intent := range r.MapIntents {
		if intent.Device != "" && intent.Device == device {
			return intent
		}
	}
	return MapIntent{}
}

// ForgetReleasedMaps drops the map intents from index first on, and the loop
// devices they resolved to, once the caller has shown every one of those maps
// released: its loop gone, or another file's now with nothing of the map
// left, and a failed map's leftovers released through its intent. It is for an
// operation that maps one VM's backup after another (init --inspect): the
// kernel hands the next map the loop numbers the last one freed, and AddLoop
// keeps the first backing recorded for a device, so a record kept past its
// release would describe the new map with the old map's identity, and
// recovery would leave the new map alone as another file's. A map not shown
// released must stay recorded, for recovery.
func (r *Record) ForgetReleasedMaps(first int) {
	if first < 0 {
		first = 0
	}
	if first >= len(r.MapIntents) {
		return
	}
	released := map[string]bool{}
	for _, intent := range r.MapIntents[first:] {
		if intent.Device != "" {
			released[intent.Device] = true
		}
	}
	// A new array: what an earlier caller holds of the old one (a pointer to
	// an intent) is never written over by the next map's intent.
	r.MapIntents = append([]MapIntent(nil), r.MapIntents[:first]...)
	if len(r.MapIntents) == 0 {
		r.MapIntents = nil
	}
	var loops []TrackedLoop
	for _, loop := range r.Loops {
		if !released[loop.Device] {
			loops = append(loops, loop)
		}
	}
	r.Loops = loops
	if released[r.LoopDevice] {
		r.LoopDevice, r.LoopBacking = "", ""
	}
}

// AddVM registers a sandbox VM into the journal record.
func (r *Record) AddVM(vmid int, node string, pid int, startTicks string) {
	r.AddVMProcess(vmid, node, Process{PID: pid, StartTicks: startTicks})
}

// AddVMProcess registers a sandbox VM with its QEMU process, including the
// boot it was recorded in (Process.BootID), without which a recorded PID and
// start time cannot be told from a later boot's process.
func (r *Record) AddVMProcess(vmid int, node string, p Process) {
	for i, vm := range r.VMs {
		if vm.VMID == vmid {
			if p.PID > 0 {
				r.VMs[i].Process = p
			}
			return
		}
	}
	r.VMs = append(r.VMs, TrackedVM{
		VMID:    vmid,
		Node:    node,
		Process: p,
	})
	if r.QEMU.PID == 0 && p.PID > 0 {
		r.QEMU = p
	}
}

// AddSDNZone registers an ephemeral SDN zone into the journal record.
func (r *Record) AddSDNZone(zone string) {
	for _, z := range r.SDNZones {
		if z == zone {
			return
		}
	}
	r.SDNZones = append(r.SDNZones, zone)
}

// AddSDNVNet registers an ephemeral SDN VNet into the journal record.
func (r *Record) AddSDNVNet(vnet string) {
	for _, v := range r.SDNVNets {
		if v == vnet {
			return
		}
	}
	r.SDNVNets = append(r.SDNVNets, vnet)
}

// NoteSDNLock records the state of PVE's SDN lock: the token held ("" for
// none), whether a lock request's answer is still unknown (kept with the
// time of the first such request), the last apply's task, and whether an
// apply's outcome is unknown (likewise kept with its time).
func (r *Record) NoteSDNLock(token string, requested bool, applyTask string, applyUnknown bool, at time.Time) {
	r.SDNLockToken = token
	stamp := at.UTC().Format(time.RFC3339)
	switch {
	case !requested:
		r.SDNLockRequested = ""
	case r.SDNLockRequested == "":
		r.SDNLockRequested = stamp
	}
	r.SDNApplyTask = applyTask
	switch {
	case !applyUnknown:
		r.SDNApplyUnknown = ""
	case r.SDNApplyUnknown == "":
		r.SDNApplyUnknown = stamp
	}
}

// AddHostAddress registers one exact host-side VNet address for crash-safe
// reconciliation. It never infers interface names or CIDRs during recovery.
func (r *Record) AddHostAddress(iface, cidr string) {
	for _, address := range r.HostAddresses {
		if address.Interface == iface && address.CIDR == cidr {
			return
		}
	}
	r.HostAddresses = append(r.HostAddresses, TrackedHostAddress{Interface: iface, CIDR: cidr})
}

// SetHostAddressIdentity records the kernel identities of the interface and the
// containment table of a registered host address (see TrackedHostAddress). A
// zero leaves what is recorded.
func (r *Record) SetHostAddressIdentity(iface, cidr string, ifindex int, tableHandle uint64) {
	for i := range r.HostAddresses {
		if r.HostAddresses[i].Interface == iface && r.HostAddresses[i].CIDR == cidr {
			if ifindex != 0 {
				r.HostAddresses[i].IfIndex = ifindex
			}
			if tableHandle != 0 {
				r.HostAddresses[i].TableHandle = tableHandle
			}
		}
	}
}

// SetHostAddressBoot records the boot in which the identities of a registered
// host address were captured (see TrackedHostAddress.BootID). An empty bootID
// leaves what is recorded.
func (r *Record) SetHostAddressBoot(iface, cidr, bootID string) {
	if bootID == "" {
		return
	}
	for i := range r.HostAddresses {
		if r.HostAddresses[i].Interface == iface && r.HostAddresses[i].CIDR == cidr {
			r.HostAddresses[i].BootID = bootID
		}
	}
}

// DropHostAddress forgets a host address record once its removal is confirmed,
// so that a journal kept for another resource's failure cannot later remove a
// replacement that reuses the interface and CIDR.
func (r *Record) DropHostAddress(iface, cidr string) {
	kept := r.HostAddresses[:0:0]
	for _, address := range r.HostAddresses {
		if address.Interface != iface || address.CIDR != cidr {
			kept = append(kept, address)
		}
	}
	r.HostAddresses = kept
}

// SetHostContainmentOnly records that a registered host address was removed
// and only its containment table remains, so the next attempt removes the table
// (by its recorded handle) and does not delete the address again: an address
// with the same CIDR on the same interface by then is someone else's, and
// carries the same interface index when the interface is a pre-provisioned VNet
// that outlives the run. A record without a match is left as it is.
func (r *Record) SetHostContainmentOnly(iface, cidr string) {
	for i := range r.HostAddresses {
		if r.HostAddresses[i].Interface == iface && r.HostAddresses[i].CIDR == cidr {
			r.HostAddresses[i].ContainmentOnly = true
		}
	}
}

// AddHostContainment registers a containment table left by a failed address
// assignment. The address itself is not recorded as owned.
func (r *Record) AddHostContainment(iface, cidr string) {
	for _, address := range r.HostAddresses {
		if address.Interface == iface && address.CIDR == cidr {
			return
		}
	}
	r.HostAddresses = append(r.HostAddresses, TrackedHostAddress{Interface: iface, CIDR: cidr, ContainmentOnly: true})
}

// AddDeltaFile registers an ephemeral .qcow2 delta overlay path into the journal record.
func (r *Record) AddDeltaFile(path string) {
	for _, f := range r.DeltaFiles {
		if f == path {
			return
		}
	}
	r.DeltaFiles = append(r.DeltaFiles, path)
}

// FileIdentity is the kernel's identity of a regular file this run created: the
// device and inode, and the creation time where the filesystem has one (it
// tells a file from a later one that reuses the inode number).
type FileIdentity struct {
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	BtimeNS int64  `json:"btime_ns,omitempty"`
}

// SetDeltaFile registers a delta file path together with the identity of the
// file this run created there.
func (r *Record) SetDeltaFile(path string, id FileIdentity) {
	r.AddDeltaFile(path)
	if r.DeltaIdentities == nil {
		r.DeltaIdentities = make(map[string]FileIdentity)
	}
	r.DeltaIdentities[path] = id
}

// DeltaIdentity is the identity recorded for a delta file path, if any.
func (r *Record) DeltaIdentity(path string) (FileIdentity, bool) {
	id, ok := r.DeltaIdentities[path]
	return id, ok
}

// DropDeltaFile forgets a delta file path (and its identity): the file is gone,
// or was never this run's.
func (r *Record) DropDeltaFile(path string) {
	kept := r.DeltaFiles[:0:0]
	for _, f := range r.DeltaFiles {
		if f != path {
			kept = append(kept, f)
		}
	}
	r.DeltaFiles = kept
	delete(r.DeltaIdentities, path)
	if len(r.DeltaIdentities) == 0 {
		r.DeltaIdentities = nil
	}
}

// AddScreenshotFiles records diagnostic screenshot files the run is about to
// make.
func (r *Record) AddScreenshotFiles(paths ...string) {
	for _, path := range paths {
		known := false
		for _, f := range r.ScreenshotFiles {
			if f == path {
				known = true
				break
			}
		}
		if !known {
			r.ScreenshotFiles = append(r.ScreenshotFiles, path)
		}
	}
}

// DropScreenshotFiles forgets screenshot files that have been removed.
func (r *Record) DropScreenshotFiles(paths ...string) {
	gone := map[string]bool{}
	for _, path := range paths {
		gone[path] = true
	}
	var kept []string
	for _, f := range r.ScreenshotFiles {
		if !gone[f] {
			kept = append(kept, f)
		}
	}
	r.ScreenshotFiles = kept
}

// Write serializes value as indented JSON and writes it atomically to path.
func Write(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("journal: failed to marshal record: %w", err)
	}
	return AtomicWrite(path, append(data, '\n'))
}

// AtomicWrite safely writes data to path using a tempfile, file fsync, atomic rename, and directory fsync.
func AtomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("journal: failed to create directory %s: %w", dir, err)
	}

	f, err := os.CreateTemp(dir, ".certistack-write-")
	if err != nil {
		return fmt.Errorf("journal: failed to create temp file: %w", err)
	}
	name := f.Name()
	defer os.Remove(name)

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("journal: failed to write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("journal: failed to sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("journal: failed to rename %s to %s: %w", name, path, err)
	}

	// Renaming the tempfile is not durable across a sudden power loss until the
	// containing directory is synced on POSIX filesystems. On Windows, FlushFileBuffers
	// on a directory handle returns ERROR_ACCESS_DENIED.
	if runtime.GOOS != "windows" {
		d, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("journal: failed to open parent directory for sync: %w", err)
		}
		if err := d.Sync(); err != nil {
			_ = d.Close()
			return fmt.Errorf("journal: failed to sync parent directory: %w", err)
		}
		if err := d.Close(); err != nil {
			return fmt.Errorf("journal: failed to close parent directory: %w", err)
		}
	}
	return nil
}

// UnreadableJournalAdvice is the next step for a journal that cannot be read:
// nothing then says what its run left on the node.
const UnreadableJournalAdvice = "if it was edited by hand, correct the edit; otherwise nothing tells CertiStack what its run left: remove that run's sandbox VM, overlays and PBS maps by hand, then move the file out of the state directory"

// Load reads and parses an active journal record from disk. A missing file is
// an error that wraps os.ErrNotExist. Anything but a regular file (a named
// pipe, which a plain open would wait on forever, a device, a directory), a
// file larger than any journal CertiStack writes, or one that is not JSON is
// refused with its path, and nothing of it is used.
func Load(path string) (Record, error) {
	var r Record
	data, err := readStateFile(path, "journal", maxJournalBytes, ": "+UnreadableJournalAdvice)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return Record{}, fmt.Errorf("journal %s is not valid JSON (%v): %s", path, err, UnreadableJournalAdvice)
	}
	return r, nil
}

// readStateFile reads a file of the state directory, of at most limit bytes.
// It is opened without waiting on a named pipe, and must be a regular file:
// CertiStack writes only those there. Errors name the file as what, and a
// refusal ends with advice.
func readStateFile(path, what string, limit int64, advice string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|openNonBlocking, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", what, path, err)
	}
	if !info.Mode().IsRegular() {
		kind := "not a regular file"
		switch mode := info.Mode(); {
		case mode.IsDir():
			kind = "a directory"
		case mode&os.ModeNamedPipe != 0:
			kind = "a named pipe"
		case mode&os.ModeSocket != 0:
			kind = "a socket"
		case mode&os.ModeDevice != 0:
			kind = "a device"
		}
		return nil, fmt.Errorf("%s %s is %s, not the regular file CertiStack writes, so it was not read%s", what, path, kind, advice)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", what, path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s %s is larger than %d bytes, more than CertiStack writes, so it was not read%s", what, path, limit, advice)
	}
	return data, nil
}

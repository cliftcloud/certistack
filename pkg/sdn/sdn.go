// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package sdn manages dynamic software-defined network sandboxes on Proxmox VE.
package sdn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// Manager coordinates SDN zone, VNet, and subnet provisioning with zero external leakage.
type Manager struct {
	client *pve.Client
	// lockToken is the token of PVE's SDN configuration lock while this
	// manager holds it (see Lock).
	lockToken string
	// lockHeld is true while the lock is certainly this token's: the
	// manager took it itself, and nothing since could have released it. An
	// adopted token, or one an unanswered apply or release may have spent,
	// is not (see EnsureLock).
	lockHeld bool
	// lockUnknown records a lock request whose answer never came.
	lockUnknown bool
	// noLockAPI records that PVE answered the SDN lock request itself as a
	// missing endpoint (PVE 8, see lockEndpoint): the manager then holds, asks
	// for and journals no lock, and sends no lock parameter. It is set by that
	// answer alone.
	noLockAPI bool
	// lockWait replaces the package's lockWait when set (SetLockWait).
	lockWait time.Duration
	// reloadTask is the UPID of this manager's last SDN apply.
	reloadTask string
	// applyUnknown records an apply whose task PVE did not identify.
	applyUnknown bool
	// persist journals the lock state (SetPersist).
	persist func(LockState) error
	// applyWait replaces reloadTaskWait when set (SetApplyWait).
	applyWait time.Duration
	// mutations counts the deletes of this manager's that PVE accepted, so
	// that there is a change to apply or to keep locked (see Mutations).
	mutations int
	// lockStood records that a lock was known to stand when the manager
	// adopted its token (EnsureLock): a write PVE then accepts with that
	// token proves the standing lock is the token's (acceptedUnderLock).
	lockStood bool
	// unlockedForeign records that the last Unlock found another client's lock.
	unlockedForeign bool
	// ownZones and ownVNets are the objects this manager's run owns
	// (SetOwnObjects): the only pending changes it may apply under a token
	// PVE may no longer honor.
	ownZones, ownVNets []string
	// ownerMarker is the alias the run's VNet carries (SetOwnerMarker): a VNet
	// is deleted only while it still has it.
	ownerMarker string
	// createdZones are the zones this manager created and PVE confirmed, and
	// provenZones those ProveZones showed to be the run's while a VNet that
	// carries the marker was still in them: a zone has no marker of its own,
	// so these are what lets DestroyZone delete one (see checkZoneOwner).
	createdZones, provenZones map[string]bool
}

// NotOwnedError means a recorded SDN object exists but CertiStack cannot show
// it is the interrupted run's: another run, an administrator or another tool
// created it under the same name. It is left unchanged, and reported.
type NotOwnedError struct {
	Resource, ID, Reason string
}

func (e *NotOwnedError) Error() string {
	return fmt.Sprintf("sandbox %s %q exists, but CertiStack cannot show that it is the interrupted run's (%s), so it left it unchanged. Review it in PVE (Datacenter > SDN); if it is the sandbox's, delete it there (a VNet with its subnets first, then its zone), then "+recoverhint.Again, e.Resource, e.ID, e.Reason)
}

// noMarkerReason is why a manager with no owner marker proves nothing: its
// journal records no marker (a journal without the marker field), so the run's
// objects have no identity that PVE could show later.
const noMarkerReason = "the run's journal names no owner marker, so nothing shows that an object of this name is the one the run created"

// OwnerMarker is the alias CertiStack gives the VNet a run creates: PVE's only
// free-text field on an SDN object that a run can set and read back (a zone
// has none), and one that an object created later under the same name does
// not carry. runID is the run's journal ID. The text fits PVE's alias
// pattern (letters, digits, spaces, hyphens, underscores, dots).
func OwnerMarker(runID string) string { return "certistack " + runID }

// SetOwnerMarker names the marker the run's VNet carries: CreateVNet sets it,
// and DestroyVNet deletes only a VNet that has it. A manager without one
// deletes no VNet and no zone that PVE lists: a journal without a marker
// cannot show that a present object of the recorded name is the run's, so
// nothing is deleted on it.
func (m *Manager) SetOwnerMarker(marker string) { m.ownerMarker = marker }

// checkVNetOwner refuses a VNet that is present but not provably the run's.
// An absent VNet passes (there is nothing to delete).
func (m *Manager) checkVNetOwner(ctx context.Context, vnetID string) error {
	var entry struct {
		VNet  string `json:"vnet"`
		Alias string `json:"alias"`
	}
	found, err := m.listed(ctx, "cluster/sdn/vnets", "vnet", vnetID, &entry)
	if err != nil {
		return fmt.Errorf("read SDN VNet %s before deleting it: %w", vnetID, err)
	}
	if !found {
		return nil
	}
	switch {
	case m.ownerMarker == "":
		return &NotOwnedError{Resource: "VNet", ID: vnetID, Reason: noMarkerReason}
	case entry.Alias != m.ownerMarker:
		return &NotOwnedError{Resource: "VNet", ID: vnetID, Reason: "it does not carry the run's marker"}
	}
	return nil
}

// checkZoneOwner refuses a zone that is present but not shown to be the run's.
// A zone has no free-text field to carry a marker, so it is the run's when:
//   - this manager created it, and PVE confirmed the creation (a zone of that
//     ID could not exist then);
//   - a VNet in it carries the run's marker, in PVE's pending view, where a
//     VNet whose deletion is not yet applied keeps its zone and alias; read
//     now, or earlier by ProveZones, before the run's VNets were deleted;
//   - it was never applied, and the run's SDN lock stands: PVE grants the
//     lock only while nothing is pending and takes a write only with the
//     standing lock's token, which DestroyZone sends, so a never-applied zone
//     was made under the run's lock. On a PVE without the lock (PVE 8) a
//     never-applied zone is taken too: DestroyZone is reached only for a zone
//     whose creation the run confirmed (DestroyUnconfirmedZone, which refuses
//     on PVE 8, handles the rest), and a zone made later under the same name
//     would need the run's never-applied zone deleted and made again with no
//     apply in between.
//
// Anything else, such as an empty zone of the same name someone made after
// the run's VNet was gone, is left in place and reported. Without a marker
// (a journal that records none) nothing shows a present zone is the run's.
func (m *Manager) checkZoneOwner(ctx context.Context, zoneID string) error {
	if m.ownerMarker != "" {
		if m.createdZones[zoneID] || m.provenZones[zoneID] {
			return nil
		}
		zoneStates, _, err := m.ObjectStates(ctx, []string{zoneID}, nil)
		if err != nil {
			return fmt.Errorf("read SDN zone %s before deleting it: %w", zoneID, err)
		}
		switch zoneStates[zoneID] {
		case Absent:
			return nil
		case New:
			if m.lockSession() || m.noLockAPI {
				return nil
			}
		}
		owners, err := m.zonesWithMarkedVNet(ctx)
		if err != nil {
			return fmt.Errorf("read SDN zone %s before deleting it: %w", zoneID, err)
		}
		if owners[zoneID] {
			return nil
		}
		return &NotOwnedError{Resource: "zone", ID: zoneID, Reason: zoneUnprovenReason}
	}
	var entry struct {
		Zone string `json:"zone"`
	}
	found, err := m.listed(ctx, "cluster/sdn/zones", "zone", zoneID, &entry)
	if err != nil {
		return fmt.Errorf("read SDN zone %s before deleting it: %w", zoneID, err)
	}
	if found {
		return &NotOwnedError{Resource: "zone", ID: zoneID, Reason: noMarkerReason}
	}
	return nil
}

// zoneUnprovenReason is why a zone with no VNet that carries the run's marker
// is left: a zone of the same name made later cannot be told from the run's.
const zoneUnprovenReason = "no VNet in it carries the run's marker, and a zone has no marker of its own, so it cannot be told from a zone made later under the same name"

// lockSession reports whether the manager writes under an SDN lock token:
// PVE then takes a write only while that token's lock stands.
func (m *Manager) lockSession() bool { return !m.noLockAPI && m.lockToken != "" }

// ProveZones records which of zones are shown to be the run's by a VNet in
// them that carries the run's marker, or by being never applied under the
// run's lock (see checkZoneOwner). Recovery calls it before it deletes the
// run's VNets: once they are gone, nothing in PVE would show it.
func (m *Manager) ProveZones(ctx context.Context, zones []string) error {
	if m.ownerMarker == "" || len(zones) == 0 {
		return nil
	}
	zoneStates, _, err := m.ObjectStates(ctx, zones, nil)
	if err != nil {
		return err
	}
	owners, err := m.zonesWithMarkedVNet(ctx)
	if err != nil {
		return err
	}
	for _, id := range zones {
		if owners[id] || (zoneStates[id] == New && m.lockSession()) {
			if m.provenZones == nil {
				m.provenZones = map[string]bool{}
			}
			m.provenZones[id] = true
		}
	}
	return nil
}

// NoteOwnUnapplied records zones that OwnUnappliedOnly read to be never
// applied, with nothing else pending in the cluster: the read the caller acted
// on shows them to be the run's own unapplied creations, which DestroyZone may
// then delete.
func (m *Manager) NoteOwnUnapplied(zones []string) {
	for _, id := range zones {
		if m.provenZones == nil {
			m.provenZones = map[string]bool{}
		}
		m.provenZones[id] = true
	}
}

// zonesWithMarkedVNet reads PVE's pending view of the VNets and returns the
// zones that hold one carrying the run's marker. A running VNet, and one whose
// deletion is not yet applied, shows its zone and alias at the top level; a
// never-applied one shows them under "pending".
func (m *Manager) zonesWithMarkedVNet(ctx context.Context) (map[string]bool, error) {
	var raw json.RawMessage
	if err := m.client.Do(ctx, "GET", "cluster/sdn/vnets?pending=1", nil, &raw); err != nil {
		return nil, fmt.Errorf("read the cluster's SDN VNets: %w", err)
	}
	var entries []map[string]json.RawMessage
	if trimmed := strings.TrimSpace(string(raw)); !strings.HasPrefix(trimmed, "[") || json.Unmarshal(raw, &entries) != nil {
		return nil, errors.New("read the cluster's SDN VNets: PVE's answer is not a list")
	}
	owners := map[string]bool{}
	for _, entry := range entries {
		var pending map[string]json.RawMessage
		_ = json.Unmarshal(entry["pending"], &pending)
		field := func(key string) string {
			var value string
			if json.Unmarshal(entry[key], &value) == nil && value != "" {
				return value
			}
			_ = json.Unmarshal(pending[key], &value)
			return value
		}
		if zone := field("zone"); zone != "" && field("alias") == m.ownerMarker {
			owners[zone] = true
		}
	}
	return owners, nil
}

// reloadTaskWait bounds how long an apply waits for the previous one's
// task: PVE reloads the nodes one after another, about 6.5 s each.
var reloadTaskWait = 10 * time.Minute

// OwnershipCollisionError means a requested sandbox identifier is already
// present in PVE. CertiStack only tears down resources it recorded before
// creation; it must never adopt, reuse, or delete a pre-existing zone or VNet.
type OwnershipCollisionError struct {
	Resource string
	ID       string
}

func (e *OwnershipCollisionError) Error() string {
	return fmt.Sprintf("sandbox %s %q already exists; CertiStack does not own or reuse pre-existing resources. Review that exact resource or reconcile its interrupted run before retrying", e.Resource, e.ID)
}

// NewManager creates a new SDN sandbox manager.
func NewManager(client *pve.Client) *Manager {
	return &Manager{client: client}
}

// EnsureSandboxAvailable verifies both requested identifiers are absent before
// making any SDN mutation. A plan may be run repeatedly with stable IDs because
// normal teardown removes its owned resources. If an ID remains, however, its
// ownership is ambiguous and the safe response is to stop for reconciliation.
func (m *Manager) EnsureSandboxAvailable(ctx context.Context, netCfg config.Network) error {
	return m.EnsureSandboxAvailableAfter(ctx, netCfg, nil)
}

// EnsureSandboxAvailableAfter is EnsureSandboxAvailable once the IDs gone
// names are deleted: plan's view of a run whose recovery of an unfinished
// run deletes that run's zone and VNet first.
func (m *Manager) EnsureSandboxAvailableAfter(ctx context.Context, netCfg config.Network, gone func(id string) bool) error {
	for _, check := range []struct{ resource, id string }{{"zone", netCfg.ZoneID}, {"VNet", netCfg.VNetID}} {
		err := m.ensureAbsent(ctx, check.resource, check.id)
		var collision *OwnershipCollisionError
		if errors.As(err, &collision) && gone != nil && gone(check.id) {
			continue
		}
		if err != nil {
			return err
		}
	}
	if netCfg.Mode == "vxlan" {
		if err := validateVXLANNetwork(netCfg); err != nil {
			return err
		}
		if err := m.ensureVXLANVNIAvailable(ctx, netCfg.Tag); err != nil {
			return err
		}
	}
	return nil
}

func validateVXLANNetwork(netCfg config.Network) error {
	if netCfg.Tag <= 0 || netCfg.Tag > config.MaxVXLANVNI {
		return fmt.Errorf("VXLAN VNI must be between 1 and %d, got %d", config.MaxVXLANVNI, netCfg.Tag)
	}
	if _, err := netCfg.VXLANPeerAddresses(); err != nil {
		return fmt.Errorf("invalid VXLAN peers: %w", err)
	}
	return nil
}

func (m *Manager) ensureVXLANVNIAvailable(ctx context.Context, vni int) error {
	var vnets []struct {
		VNet string `json:"vnet"`
		Tag  int    `json:"tag"`
	}
	if err := m.client.Do(ctx, "GET", "cluster/sdn/vnets", nil, &vnets); err != nil {
		return fmt.Errorf("check whether VXLAN VNI %d is available: %w", vni, err)
	}
	for _, vnet := range vnets {
		if vnet.Tag == vni {
			return fmt.Errorf("VXLAN VNI %d is already used by VNet %q", vni, vnet.VNet)
		}
	}
	return nil
}

// ValidatePreprovisionedSandbox verifies that a platform-owned sandbox has
// the exact isolated topology a plan declares. It performs only read-only PVE
// API calls and deliberately refuses an incomplete or routed sandbox rather
// than attempting to repair or adopt it.
func (m *Manager) ValidatePreprovisionedSandbox(ctx context.Context, netCfg config.Network) error {
	if netCfg.Gateway != "" {
		return fmt.Errorf("preprovisioned sandbox must not declare a gateway")
	}
	if err := validateSDNIdentifier("zone", netCfg.ZoneID); err != nil {
		return err
	}
	if err := validateSDNIdentifier("VNet", netCfg.VNetID); err != nil {
		return err
	}

	// The zone and VNet are read from PVE's lists, which need only
	// SDN.Audit; reading one zone by its path needs SDN.Allocate, which a
	// pre-provisioned sandbox's token does not have.
	var zone struct {
		Zone  string `json:"zone"`
		Type  string `json:"type"`
		IPAM  string `json:"ipam"`
		Peers string `json:"peers"`
	}
	if found, err := m.listed(ctx, "cluster/sdn/zones", "zone", netCfg.ZoneID, &zone); err != nil {
		return fmt.Errorf("read preprovisioned sandbox zone %q: %w", netCfg.ZoneID, err)
	} else if !found {
		return fmt.Errorf("preprovisioned sandbox zone %q does not exist, or the token lacks SDN.Audit on /sdn/zones/%s", netCfg.ZoneID, netCfg.ZoneID)
	}
	if zone.Type != netCfg.Mode {
		return fmt.Errorf("preprovisioned sandbox zone %q has type %q, but plan requires %q", netCfg.ZoneID, zone.Type, netCfg.Mode)
	}
	// PVE's own IPAM is the default: PVE 8 lists a zone created without the option with no
	// "ipam" member at all, PVE 9 lists "pve". Only a named external plugin is refused.
	if zone.IPAM != "pve" && zone.IPAM != "" {
		return fmt.Errorf("preprovisioned sandbox zone %q uses IPAM %q; CertiStack requires pve IPAM", netCfg.ZoneID, zone.IPAM)
	}
	if netCfg.Mode == "vxlan" {
		if err := validateVXLANNetwork(netCfg); err != nil {
			return err
		}
		requestedPeers, err := netCfg.VXLANPeerAddresses()
		if err != nil {
			return fmt.Errorf("invalid VXLAN peers: %w", err)
		}
		configuredPeers, err := (config.Network{Peers: zone.Peers}).VXLANPeerAddresses()
		if err != nil || strings.Join(configuredPeers, ",") != strings.Join(requestedPeers, ",") {
			return fmt.Errorf("preprovisioned sandbox zone %q has VXLAN peers %q, but plan requires %q", netCfg.ZoneID, zone.Peers, strings.Join(requestedPeers, ","))
		}
	}

	var vnet struct {
		VNet string `json:"vnet"`
		Zone string `json:"zone"`
		Tag  int    `json:"tag"`
	}
	if found, err := m.listed(ctx, "cluster/sdn/vnets", "vnet", netCfg.VNetID, &vnet); err != nil {
		return fmt.Errorf("read preprovisioned sandbox VNet %q: %w", netCfg.VNetID, err)
	} else if !found {
		return fmt.Errorf("preprovisioned sandbox VNet %q does not exist, or the token lacks SDN.Audit on /sdn/zones/%s/%s", netCfg.VNetID, netCfg.ZoneID, netCfg.VNetID)
	}
	if vnet.Zone != netCfg.ZoneID {
		return fmt.Errorf("preprovisioned sandbox VNet %q belongs to zone %q, not required zone %q", netCfg.VNetID, vnet.Zone, netCfg.ZoneID)
	}
	if netCfg.Mode == "vxlan" && vnet.Tag != netCfg.Tag {
		return fmt.Errorf("preprovisioned sandbox VNet %q has VXLAN VNI %d, but plan requires %d", netCfg.VNetID, vnet.Tag, netCfg.Tag)
	}

	var subnets []map[string]json.RawMessage
	if err := m.client.Do(ctx, "GET", fmt.Sprintf("cluster/sdn/vnets/%s/subnets", netCfg.VNetID), nil, &subnets); err != nil {
		return fmt.Errorf("read preprovisioned sandbox VNet %q subnets: %w", netCfg.VNetID, err)
	}

	// The plan's range is read by the one parser every user of it shares; the
	// subnets PVE holds are PVE's data and are read tolerantly below.
	requestedSubnet, err := config.ParseSandboxRange(netCfg.IPRange)
	if err != nil {
		return fmt.Errorf("validate requested sandbox subnet: network.ip_range %w", err)
	}
	expectedSubnet := requestedSubnet.String()
	foundExpectedSubnet := false
	for _, subnet := range subnets {
		if jsonValueEnabled(subnet["gateway"]) {
			return fmt.Errorf("preprovisioned sandbox VNet %q has a gateway; isolated sandbox networks cannot define a gateway", netCfg.VNetID)
		}
		if jsonValueEnabled(subnet["snat"]) {
			return fmt.Errorf("preprovisioned sandbox VNet %q enables SNAT; isolated sandbox networks cannot enable SNAT", netCfg.VNetID)
		}
		if rawVNet, ok := subnet["vnet"]; ok {
			var subnetVNet string
			if err := json.Unmarshal(rawVNet, &subnetVNet); err != nil || subnetVNet != netCfg.VNetID {
				return fmt.Errorf("preprovisioned sandbox subnet does not belong to VNet %q", netCfg.VNetID)
			}
		}
		if rawCIDR, ok := subnet["cidr"]; ok {
			var cidr string
			if err := json.Unmarshal(rawCIDR, &cidr); err == nil {
				if normalized, cidrErr := normalizedCIDR(cidr); cidrErr == nil && normalized == expectedSubnet {
					foundExpectedSubnet = true
				}
			}
		}
	}
	if !foundExpectedSubnet {
		return fmt.Errorf("preprovisioned sandbox VNet %q does not define required isolated subnet %s", netCfg.VNetID, expectedSubnet)
	}
	return nil
}

func normalizedCIDR(cidr string) (string, error) {
	_, subnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return "", fmt.Errorf("invalid CIDR %q", cidr)
	}
	return subnet.String(), nil
}

func jsonValueEnabled(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return true
	}
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case float64:
		return typed != 0
	case string:
		trimmed := strings.TrimSpace(strings.ToLower(typed))
		return trimmed != "" && trimmed != "0" && trimmed != "false" && trimmed != "off" && trimmed != "no"
	default:
		return true
	}
}

// listed finds the entry of PVE's list at path whose key field is id, and
// decodes it into out. PVE lists only the entries the token may audit.
func (m *Manager) listed(ctx context.Context, path, key, id string, out interface{}) (bool, error) {
	// An answer that is not a list (null, a string, an object) is not "not
	// listed", and neither is a list with an entry whose ID cannot be read,
	// which could be id: a read that cannot be told from an empty list would
	// let a caller act on the absence of what it never saw (a deletion that
	// needs no ownership proof for an absent object, for one).
	entries, err := m.readList(ctx, path)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		entryID, err := entryString(entry, key)
		if err != nil || entryID == "" {
			return false, fmt.Errorf("PVE's list %s has an entry without a usable %q, so it cannot show whether %s is there", path, key, id)
		}
		if entryID != id {
			continue
		}
		raw, err := json.Marshal(entry)
		if err != nil {
			return false, err
		}
		return true, json.Unmarshal(raw, out)
	}
	return false, nil
}

// UsedIDs is every SDN zone and VNet ID the token can see, lower-cased.
func (m *Manager) UsedIDs(ctx context.Context) (map[string]bool, error) {
	used := map[string]bool{}
	for _, list := range []struct{ path, key string }{{"cluster/sdn/zones", "zone"}, {"cluster/sdn/vnets", "vnet"}} {
		ids, err := m.listIDs(ctx, list.path, list.key)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			used[strings.ToLower(id)] = true
		}
	}
	return used, nil
}

// ensureAbsent fails unless no zone or VNet (resource) named id exists. It
// reads PVE's list, not the object: PVE answers a read of a missing zone
// with HTTP 500 "sdn zone '<id>' does not exist", not 404, so a read made
// every free ID look like an error. An ID equal but for case counts as
// taken.
func (m *Manager) ensureAbsent(ctx context.Context, resource, id string) error {
	if err := validateSDNIdentifier(resource, id); err != nil {
		return err
	}

	var path, key string
	switch resource {
	case "zone":
		path, key = "cluster/sdn/zones", "zone"
	case "VNet":
		path, key = "cluster/sdn/vnets", "vnet"
	default:
		return fmt.Errorf("unsupported SDN resource type %q", resource)
	}
	ids, err := m.listIDs(ctx, path, key)
	if err != nil {
		return fmt.Errorf("check whether sandbox %s %q is available: %w", resource, id, err)
	}
	for _, existing := range ids {
		if strings.EqualFold(existing, id) {
			return &OwnershipCollisionError{Resource: resource, ID: id}
		}
	}
	return nil
}

// listIDs is the key field of every entry in PVE's list at path.
func (m *Manager) listIDs(ctx context.Context, path, key string) ([]string, error) {
	entries, err := m.readList(ctx, path)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		id, err := entryString(entry, key)
		if err != nil || id == "" {
			return nil, fmt.Errorf("PVE's list %s has an entry without a usable %q: a list that cannot be read in full does not show which IDs are free", path, key)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// readList reads a PVE list: its data present, a JSON array, every entry an
// object. PVE answers an empty list as []; data that is missing, null or not a
// list is an answer that carries no list, which is not an empty one, and a
// caller that took it for "nothing there" would act on what it never saw.
func (m *Manager) readList(ctx context.Context, path string) ([]map[string]json.RawMessage, error) {
	var raw json.RawMessage
	if err := m.client.Do(ctx, "GET", path, nil, &raw); err != nil {
		return nil, err
	}
	var entries []map[string]json.RawMessage
	if trimmed := strings.TrimSpace(string(raw)); !strings.HasPrefix(trimmed, "[") || json.Unmarshal(raw, &entries) != nil {
		return nil, fmt.Errorf("PVE's answer to a read of %s is not a list", path)
	}
	return entries, nil
}

// entryString is the string value of an entry's field. An absent or null field
// is "" with no error; a field of any other JSON type is malformed.
func entryString(entry map[string]json.RawMessage, key string) (string, error) {
	raw, ok := entry[key]
	if !ok || strings.TrimSpace(string(raw)) == "null" {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("field %q is not a string", key)
	}
	return value, nil
}

// sdnObjectAbsent reports whether err says the SDN object id does not
// exist: a 404, or the HTTP 500 "sdn zone '<id>' does not exist" PVE gives
// instead. Any other error is not an absence.
func sdnObjectAbsent(err error, id string) bool {
	if pve.IsNotFound(err) {
		return true
	}
	var apiErr *pve.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError {
		return false
	}
	message := strings.ToLower(apiErr.Message)
	return strings.Contains(message, "does not exist") && strings.Contains(message, "'"+strings.ToLower(id)+"'")
}

// CreateZone provisions a transient SDN zone satisfying the No-Gateway and
// isolation invariants. A simple zone is created on node alone, where the
// sandbox runs, so no other node builds its bridge.
func (m *Manager) CreateZone(ctx context.Context, netCfg config.Network, node string) error {
	if err := validateSDNIdentifier("zone", netCfg.ZoneID); err != nil {
		return err
	}

	body := map[string]interface{}{
		"zone": netCfg.ZoneID,
		"type": netCfg.Mode,
		"ipam": "pve",
	}

	if netCfg.Mode == "vxlan" {
		if err := validateVXLANNetwork(netCfg); err != nil {
			return err
		}
		peers, _ := netCfg.VXLANPeerAddresses()
		body["peers"] = strings.Join(peers, ",")
	} else if node != "" {
		// The zone's node list is sent as given: a name that is a list
		// ("pve1,pve2") or anything PVE's node names are not would build the
		// zone on nodes the run never chose.
		if err := pve.ValidateNodeName(node); err != nil {
			return fmt.Errorf("create SDN zone %s: %w", netCfg.ZoneID, err)
		}
		body["nodes"] = node
	}

	slog.Info("creating isolated SDN zone", "zone", netCfg.ZoneID, "mode", netCfg.Mode)
	if err := m.client.Do(ctx, "POST", "cluster/sdn/zones", m.locked(body), nil); err != nil {
		return fmt.Errorf("failed to create SDN zone %s: %w", netCfg.ZoneID, err)
	}
	// PVE refuses to create a zone whose ID exists, so this one is the run's.
	if m.createdZones == nil {
		m.createdZones = map[string]bool{}
	}
	m.createdZones[netCfg.ZoneID] = true

	return nil
}

// VNetTag is the tag CreateVNet sends for netCfg's VNet: the VXLAN VNI of a
// vxlan network, and none (0) for any other. The plan's preview prints the same
// value, so it never names a tag the request does not carry.
func VNetTag(netCfg config.Network) int {
	if netCfg.Mode == "vxlan" {
		return netCfg.Tag
	}
	return 0
}

// CreateVNet provisions an ephemeral VNet bridge attached to the isolated zone.
// The caller must journal this successful allocation before calling
// CreateSubnet: PVE can create the VNet even if a later subnet request fails.
// Strictly omits any default gateway, SNAT, or physical uplink bindings.
func (m *Manager) CreateVNet(ctx context.Context, netCfg config.Network) error {
	if err := validateSDNIdentifier("VNet", netCfg.VNetID); err != nil {
		return err
	}
	if err := validateSDNIdentifier("zone", netCfg.ZoneID); err != nil {
		return err
	}
	if netCfg.Gateway != "" {
		return fmt.Errorf("SDN gateway must be empty for an isolated CertiStack network")
	}

	body := map[string]interface{}{
		"vnet": netCfg.VNetID,
		"zone": netCfg.ZoneID,
	}
	if m.ownerMarker != "" {
		body["alias"] = m.ownerMarker
	}

	if netCfg.Mode == "vxlan" {
		if err := validateVXLANNetwork(netCfg); err != nil {
			return err
		}
	} else if netCfg.Tag != 0 {
		// Nothing is sent for it, so a tag the plan set would never reach PVE: the
		// plan loader refuses it, and so does this.
		return fmt.Errorf("a %s network's VNet carries no tag, so the plan's tag %d would not reach PVE; only vxlan networks have one", netCfg.Mode, netCfg.Tag)
	}
	if tag := VNetTag(netCfg); tag != 0 {
		body["tag"] = tag
	}

	slog.Info("creating isolated SDN VNet", "vnet", netCfg.VNetID, "zone", netCfg.ZoneID)
	if err := m.client.Do(ctx, "POST", "cluster/sdn/vnets", m.locked(body), nil); err != nil {
		return fmt.Errorf("failed to create SDN VNet %s: %w", netCfg.VNetID, err)
	}

	return nil
}

// CreateSubnet attaches the isolated subnet after its parent VNet has been
// durably journaled. DestroyVNet removes child subnets, so a failure or crash
// after this call still has an exact tracked parent resource for recovery.
func (m *Manager) CreateSubnet(ctx context.Context, netCfg config.Network) error {
	if netCfg.IPRange == "" {
		return nil
	}
	if err := validateSDNIdentifier("VNet", netCfg.VNetID); err != nil {
		return err
	}
	// One parser for the range (config.ParseSandboxRange): a spelling plan
	// validation refuses is not sent to PVE as the subnet to create.
	subnet, err := config.ParseSandboxRange(netCfg.IPRange)
	if err != nil {
		return fmt.Errorf("create the sandbox subnet: network.ip_range %w", err)
	}
	subnetPath := fmt.Sprintf("cluster/sdn/vnets/%s/subnets", netCfg.VNetID)
	subnetBody := map[string]interface{}{
		"subnet": subnet.String(),
		"type":   "subnet",
	}
	slog.Info("creating isolated subnet", "vnet", netCfg.VNetID, "cidr", subnet.String())
	if err := m.client.Do(ctx, "POST", subnetPath, m.locked(subnetBody), nil); err != nil {
		return fmt.Errorf("register subnet %s for VNet %s: %w", subnet, netCfg.VNetID, err)
	}
	return nil
}

// Reload applies the SDN configuration under the SDN lock, releasing it.
// An apply commits every pending change, on every node, so it is made only
// under a lock the manager holds: without one, nothing is
// applied. It returns once PVE has taken the apply, not when the nodes
// have reloaded their networks. PVE forks each node's reload one after
// another, about 6.5 s a node, and its task ends when the last is forked; the
// caller waits for its own node itself, and ReloadFailed tells whether the task
// failed. This manager's own earlier apply must have ended first, so that its
// two reloads never contend for a node's network; an apply another client makes
// at the same time is not held off, since PVE's lock covers the configuration,
// not the reload.
func (m *Manager) Reload(ctx context.Context) error {
	if m.lockToken == "" && !m.noLockAPI {
		return errors.New("CertiStack applies SDN only under PVE's SDN configuration lock, and holds none: nothing was applied")
	}
	if err := m.WaitForApply(ctx); err != nil {
		return err
	}
	if m.noLockAPI {
		// A PVE without an SDN lock (PVE 8) commits whatever is pending, and
		// refuses nothing: the apply is made only when every pending change it
		// can read is this run's own (see lockEndpoint).
		if err := m.noLockGuard(ctx); err != nil {
			return fmt.Errorf("apply SDN: %w", err)
		}
	} else if !m.lockHeld {
		// A token adopted, or one an unanswered apply or release may have
		// spent: the apply goes ahead only while a lock stands (EnsureLock).
		held := m.lockToken
		if err := m.EnsureLock(ctx); err != nil {
			return fmt.Errorf("apply SDN: %w", err)
		}
		if m.lockToken != held {
			// No lock stood, and nothing was pending: there is nothing of
			// this manager's to apply.
			return errors.Join(fmt.Errorf("%w, and nothing was pending: its change was applied already, or never made; CertiStack applied nothing", ErrSDNLockLost), m.Unlock(ctx))
		}
		// PVE offers no apply that checks the lock and commits in one step, so
		// a lock another client releases between the check above and the PUT
		// would leave PVE taking this token for anything: apply only when
		// every pending change is this run's own.
		foreign, err := m.ForeignPending(ctx)
		if err != nil {
			return fmt.Errorf("apply SDN: read the pending changes before applying under a lock token PVE may no longer honor: %w", err)
		}
		if len(foreign) > 0 {
			return fmt.Errorf("%w (%s). Applying now would apply them too, on every node, so CertiStack does not. Ask whoever changed SDN to apply or discard the change (Datacenter > SDN); do not apply someone else's change yourself. Then "+recoverhint.Recover, ErrPendingSDNChanges, strings.Join(foreign, ", "))
		}
	}
	slog.Info("applying and reloading SDN configuration cluster-wide")
	// Without an SDN lock (PVE 8) the apply carries no parameter: that PVE's
	// schema refuses lock-token and release-lock.
	body := map[string]interface{}{}
	if !m.noLockAPI {
		body["lock-token"], body["release-lock"] = m.lockToken, 1
	}
	var upid string
	if err := m.client.Do(ctx, "PUT", "cluster/sdn", body, &upid); err != nil {
		if definite(err) && strings.Contains(apiMessage(err), "invalid lock token") {
			// Another lock stands: this token's is gone.
			m.lockToken = ""
		}
		// PVE commits and releases in one step, so a refusal normally
		// leaves the lock held; an answer that is not PVE's own may not,
		// and may hide an apply whose task nobody can name (journaled, so
		// that no later apply starts while its reload may still run).
		m.lockHeld = false
		if !definite(err) && !pve.NotSent(err) {
			m.applyUnknown = true
		}
		return errors.Join(fmt.Errorf("failed to reload SDN configuration: %w", err), m.note(false))
	}
	// Applied: PVE released the lock.
	m.acceptedUnderLock()
	m.lockToken, m.lockHeld = "", false
	if _, err := pve.TaskNode(upid); err != nil {
		m.reloadTask, m.applyUnknown = "", true
		return errors.Join(fmt.Errorf("SDN reload returned an invalid task identifier %q", upid), m.note(false))
	}
	m.reloadTask = upid
	return m.note(false)
}

// applyPoll is how often WaitForApply asks PVE whether an apply still runs.
var applyPoll = 2 * time.Second

// SetApplyWait bounds how long WaitForApply waits for an apply to end; zero
// is the default, 10 minutes.
func (m *Manager) SetApplyWait(wait time.Duration) { m.applyWait = wait }

func (m *Manager) applyWaitBound() time.Duration {
	if m.applyWait > 0 {
		return m.applyWait
	}
	return reloadTaskWait
}

// WaitForApply waits for the last apply to end. A task that has not ended,
// or whose state cannot be read, stops the next apply: the two
// would contend for every node's network, and the first may still be
// reloading it. A task that ended in failure has ended. An apply whose task
// is unknown (its reply was lost, or named none) is looked for among PVE's
// running reloadnetworkall tasks; if they cannot be listed, nothing is
// applied over it. The unknown marker is journaled, so that it holds across
// a crash and a recovery.
func (m *Manager) WaitForApply(ctx context.Context) error {
	if m.applyUnknown {
		if err := m.waitNoRunningApply(ctx); err != nil {
			return err
		}
		m.applyUnknown = false
		if err := m.note(false); err != nil {
			return err
		}
	}
	if m.reloadTask == "" {
		return nil
	}
	node, err := pve.TaskNode(m.reloadTask)
	if err != nil {
		return err
	}
	waitErr := m.client.WaitForTask(ctx, node, m.reloadTask, 2*time.Second, m.applyWaitBound())
	if waitErr == nil {
		return nil
	}
	var status pve.TaskStatus
	if err := m.client.Do(ctx, "GET", fmt.Sprintf("nodes/%s/tasks/%s/status", node, url.PathEscape(m.reloadTask)), nil, &status); err == nil && status.Status == "stopped" {
		slog.Warn("the previous SDN apply did not end cleanly", "task", m.reloadTask, "exit_status", status.ExitStatus)
		return nil
	}
	return fmt.Errorf("the previous SDN apply (task %s) has not ended, or its state cannot be read, so CertiStack applies nothing over it: %w", m.reloadTask, waitErr)
}

// waitNoRunningApply waits until PVE lists no running reloadnetworkall task,
// the task of an SDN apply.
func (m *Manager) waitNoRunningApply(ctx context.Context) error {
	deadline := time.Now().Add(m.applyWaitBound())
	for {
		running, err := m.runningApplies(ctx)
		if err != nil {
			return fmt.Errorf("the previous SDN apply's task is unknown (PVE's answer to it was lost, or named no task) and PVE's task list cannot be read, so CertiStack cannot tell it has ended and applies nothing over it; "+recoverhint.Recovery+" applies later: %w", err)
		}
		if running == 0 {
			return nil
		}
		if time.Now().Add(applyPoll).After(deadline) {
			return fmt.Errorf("an SDN apply (%d running reloadnetworkall task(s)) has not ended, and the previous apply's task is unknown, so CertiStack applies nothing over it; "+recoverhint.Recovery+" applies later", running)
		}
		if err := sleepCtx(ctx, applyPoll); err != nil {
			return fmt.Errorf("wait for the running SDN apply: %w", err)
		}
	}
}

// runningApplies counts PVE's running reloadnetworkall tasks. The list is
// the token's own tasks at least; an answer that is not a list is an error.
func (m *Manager) runningApplies(ctx context.Context) (int, error) {
	var raw json.RawMessage
	if err := m.client.Do(ctx, "GET", "cluster/tasks", nil, &raw); err != nil {
		return 0, err
	}
	var tasks []struct {
		Type    string `json:"type"`
		EndTime int64  `json:"endtime"`
	}
	if trimmed := strings.TrimSpace(string(raw)); !strings.HasPrefix(trimmed, "[") || json.Unmarshal(raw, &tasks) != nil {
		return 0, errors.New("PVE's task list is not a list")
	}
	running := 0
	for _, task := range tasks {
		if task.Type == "reloadnetworkall" && task.EndTime == 0 {
			running++
		}
	}
	return running, nil
}

// AdoptApplyTask makes the manager's last apply the one a run's journal
// records, so that the next apply waits for it.
func (m *Manager) AdoptApplyTask(upid string) error {
	if _, err := pve.TaskNode(upid); err != nil {
		return err
	}
	m.reloadTask = upid
	return nil
}

// AdoptApplyUnknown records, from a run's journal, an apply whose outcome
// was lost (see WaitForApply).
func (m *Manager) AdoptApplyUnknown() { m.applyUnknown = true }

// ApplyUnknown reports an apply whose outcome is unknown and not yet waited for.
func (m *Manager) ApplyUnknown() bool { return m.applyUnknown }

// SetOwnObjects names the zones and VNets this manager's run owns: the only
// pending changes it applies under a lock token PVE may no longer honor.
func (m *Manager) SetOwnObjects(zones, vnets []string) { m.ownZones, m.ownVNets = zones, vnets }

// Mutations counts the deletes of this manager's that PVE accepted: an
// object, or a subnet of one, is gone from the configuration, so there is a
// change to apply, or to keep the lock over, even if a later delete failed (a
// lock released over a pending deletion would block every SDN lock in the
// cluster).
func (m *Manager) Mutations() int { return m.mutations }

// Mutated reports that at least one delete of this manager's was accepted.
func (m *Manager) Mutated() bool { return m.mutations > 0 }

// ClearApplyUnknown drops the unknown-apply marker, and journals that, for a
// caller that will apply nothing (see WaitForApply).
func (m *Manager) ClearApplyUnknown() error {
	if !m.applyUnknown {
		return nil
	}
	m.applyUnknown = false
	return m.note(false)
}

// acceptedUnderLock notes that PVE accepted a write made with the manager's
// token. When a lock was known to stand as the token was adopted, the write
// proves that lock is the token's: none requested earlier and lost can stand
// beside it.
func (m *Manager) acceptedUnderLock() {
	if m.lockStood && m.lockUnknown {
		m.lockUnknown = false
	}
}

// ObjectState is where a zone or VNet stands between PVE's SDN
// configuration and the running configuration the last apply made.
type ObjectState int

const (
	// Absent is in neither: there is nothing to delete or apply.
	Absent ObjectState = iota
	// Applied is running, and still configured.
	Applied
	// New is configured and has never been applied.
	New
	// Deleted is running but deleted from the configuration: the deletion
	// has not been applied.
	Deleted
)

// ObjectStates reads where each zone and VNet stands, from PVE's pending
// view of its lists: every object configured or running, with its state
// ("new", "deleted", "changed", or none). An answer that is not a list is
// an error, never an empty cluster.
func (m *Manager) ObjectStates(ctx context.Context, zones, vnets []string) (zoneStates, vnetStates map[string]ObjectState, err error) {
	zoneStates, err = m.objectStates(ctx, "cluster/sdn/zones?pending=1", "zone", zones)
	if err != nil {
		return nil, nil, err
	}
	vnetStates, err = m.objectStates(ctx, "cluster/sdn/vnets?pending=1", "vnet", vnets)
	if err != nil {
		return nil, nil, err
	}
	return zoneStates, vnetStates, nil
}

func (m *Manager) objectStates(ctx context.Context, path, key string, ids []string) (map[string]ObjectState, error) {
	states := map[string]ObjectState{}
	if len(ids) == 0 {
		return states, nil
	}
	var raw json.RawMessage
	if err := m.client.Do(ctx, "GET", path, nil, &raw); err != nil {
		return nil, fmt.Errorf("read the cluster's SDN %ss: %w", key, err)
	}
	var entries []map[string]json.RawMessage
	if trimmed := strings.TrimSpace(string(raw)); !strings.HasPrefix(trimmed, "[") || json.Unmarshal(raw, &entries) != nil {
		return nil, fmt.Errorf("read the cluster's SDN %ss: PVE's answer is not a list", key)
	}
	found := map[string]ObjectState{}
	for _, entry := range entries {
		// An entry whose ID cannot be read could be any of ids: skipping it
		// would call that object absent, and an absent zone needs no proof that
		// it is the run's before its deletion is sent.
		id, err := entryString(entry, key)
		if err != nil || id == "" {
			return nil, fmt.Errorf("read the cluster's SDN %ss: an entry of PVE's list has no usable %q, so the list cannot show which %ss are there", key, key, key)
		}
		var state string
		_ = json.Unmarshal(entry["state"], &state)
		switch state {
		case "new":
			found[id] = New
		case "deleted":
			found[id] = Deleted
		default:
			found[id] = Applied
		}
	}
	for _, id := range ids {
		states[id] = found[id]
	}
	return states, nil
}

// ReloadFailed reports the last apply's task as failed if it has ended
// with an error. A task still reloading other nodes is not a failure.
func (m *Manager) ReloadFailed(ctx context.Context) error {
	if m.reloadTask == "" {
		return nil
	}
	node, err := pve.TaskNode(m.reloadTask)
	if err != nil {
		return err
	}
	var status pve.TaskStatus
	if err := m.client.Do(ctx, "GET", fmt.Sprintf("nodes/%s/tasks/%s/status", node, url.PathEscape(m.reloadTask)), nil, &status); err != nil {
		return fmt.Errorf("read SDN apply task %s: %w", m.reloadTask, err)
	}
	if status.Status != "stopped" || status.ExitStatus == "OK" || strings.HasPrefix(status.ExitStatus, "WARNINGS:") {
		return nil
	}
	return fmt.Errorf("SDN apply task %s failed: %s", m.reloadTask, status.ExitStatus)
}

// DestroyVNet removes an ephemeral VNet and its subnets, the subnets
// first. PVE refuses to delete a VNet that has subnets, and says only
// "delete sdn vnet object failed: 400 Parameter verification failed." (its
// reason is lost when the error is rewrapped), so no error text can tell
// the caller to delete them. An already-absent VNet is success.
func (m *Manager) DestroyVNet(ctx context.Context, vnetID string) error {
	if vnetID == "" {
		return nil
	}
	if err := validateSDNIdentifier("VNet", vnetID); err != nil {
		return err
	}

	if err := m.checkVNetOwner(ctx, vnetID); err != nil {
		return err
	}
	slog.Info("destroying ephemeral SDN VNet", "vnet", vnetID)
	path := fmt.Sprintf("cluster/sdn/vnets/%s", vnetID)
	subnetsPath := path + "/subnets"
	var subnets []struct {
		ID     string `json:"id"`
		Subnet string `json:"subnet"`
	}
	var errs []error
	if err := m.client.Do(ctx, "GET", subnetsPath, nil, &subnets); err != nil {
		if sdnObjectAbsent(err, vnetID) {
			return nil
		}
		// Try the VNet all the same: it may have no subnet.
		errs = append(errs, fmt.Errorf("list SDN VNet %s subnets before deletion: %w", vnetID, err))
		subnets = nil
	}
	for _, s := range subnets {
		subID := s.ID
		if subID == "" {
			subID = s.Subnet
		}
		if subID == "" {
			continue
		}
		slog.Info("destroying ephemeral SDN subnet", "vnet", vnetID, "subnet", subID)
		delSubnetPath := subnetsPath + "/" + url.PathEscape(subID)
		if err := m.client.Do(ctx, "DELETE", m.lockedPath(delSubnetPath), nil, nil); err != nil && !pve.IsNotFound(err) && !sdnObjectAbsent(err, subID) {
			errs = append(errs, fmt.Errorf("delete SDN subnet %s from VNet %s: %w", subID, vnetID, err))
		} else if err == nil {
			m.deleted()
		}
	}
	err := m.client.Do(ctx, "DELETE", m.lockedPath(path), nil, nil)
	if err == nil {
		m.deleted()
	}
	if err == nil || sdnObjectAbsent(err, vnetID) {
		return nil
	}
	return errors.Join(append(errs, fmt.Errorf("failed to delete SDN VNet %s: %w", vnetID, err))...)
}

// DestroyZone removes an ephemeral SDN zone.
func (m *Manager) DestroyZone(ctx context.Context, zoneID string) error {
	if zoneID == "" {
		return nil
	}
	if err := validateSDNIdentifier("zone", zoneID); err != nil {
		return err
	}
	if err := m.checkZoneOwner(ctx, zoneID); err != nil {
		return err
	}

	slog.Info("destroying ephemeral SDN zone", "zone", zoneID)
	path := fmt.Sprintf("cluster/sdn/zones/%s", zoneID)
	if err := m.client.Do(ctx, "DELETE", m.lockedPath(path), nil, nil); err != nil {
		if sdnObjectAbsent(err, zoneID) {
			return nil
		}
		return fmt.Errorf("failed to delete SDN zone %s: %w", zoneID, err)
	}
	m.deleted()

	return nil
}

// DestroyUnconfirmedZone removes a zone whose creation was sent and never
// confirmed: the reply was lost, or PVE refused the request. A zone
// has no marker, so what makes one the run's is its state in PVE's pending view:
// it is deleted only while it is configured and was never applied ("new"), which
// a zone of the same name that someone else made and applied is not, and the run
// holds the SDN lock while it makes its creations, so no one else's unapplied
// zone can have appeared in between. Created reports whether PVE had the zone
// at all: a creation that had no effect has nothing to delete, and no write is
// made for it.
//
// That reasoning needs the lock. A PVE without one (PVE 8, noLockAPI) holds no
// other client off, so a zone that is only "new" may be one another client
// created under the same name after the availability read, and nothing on it
// (a zone has no marker, and the run's VNet, which carries it, does not exist
// while the zone's creation is unconfirmed) shows whose it is. There it is left
// in place and reported as not confirmed as the run's, which keeps the
// allocation unresolved and visible for the operator; a zone PVE does not list
// at all still has nothing to delete.
func (m *Manager) DestroyUnconfirmedZone(ctx context.Context, zoneID string) (created bool, err error) {
	if err := validateSDNIdentifier("zone", zoneID); err != nil {
		return false, err
	}
	states, _, err := m.ObjectStates(ctx, []string{zoneID}, nil)
	if err != nil {
		return false, fmt.Errorf("read SDN zone %s before deleting it: %w", zoneID, err)
	}
	switch states[zoneID] {
	case Absent:
		return false, nil
	case New:
		if m.noLockAPI {
			return true, &NotOwnedError{Resource: "zone", ID: zoneID, Reason: "the run's creation of it was never confirmed, and this PVE has no SDN lock (PVE 8), so it held no other client's creation of a zone of that name off: a zone that PVE has configured and never applied may be another client's, and nothing shows it is the run's"}
		}
		return true, m.DestroyZone(ctx, zoneID)
	}
	return true, &NotOwnedError{Resource: "zone", ID: zoneID, Reason: "the run's creation of it was never confirmed, and PVE runs a zone of that name which the run never applied, so it is not the run's"}
}

// DestroyUnconfirmedVNet is DestroyUnconfirmedZone's counterpart for a VNet
// whose creation was never confirmed. The VNet carries the run's marker, which
// DestroyVNet demands, so what is left to establish is whether PVE has it.
func (m *Manager) DestroyUnconfirmedVNet(ctx context.Context, vnetID string) (created bool, err error) {
	if err := validateSDNIdentifier("VNet", vnetID); err != nil {
		return false, err
	}
	_, states, err := m.ObjectStates(ctx, nil, []string{vnetID})
	if err != nil {
		return false, fmt.Errorf("read SDN VNet %s before deleting it: %w", vnetID, err)
	}
	if states[vnetID] == Absent {
		return false, nil
	}
	return true, m.DestroyVNet(ctx, vnetID)
}

// RecoveryRefusals lists the recorded objects that recovery would leave in
// place, for `plan`'s preview: each is listed by PVE and not provably the
// run's (DestroyVNet's and DestroyZone's own checks), and a zone is left
// whenever one of the run's VNets is, since a zone has no marker of its own.
func (m *Manager) RecoveryRefusals(ctx context.Context, zones, vnets []string) ([]*NotOwnedError, error) {
	var refused []*NotOwnedError
	for _, id := range vnets {
		if err := validateSDNIdentifier("VNet", id); err != nil {
			return nil, err
		}
		if err := m.checkVNetOwner(ctx, id); err != nil {
			var notOwned *NotOwnedError
			if !errors.As(err, &notOwned) {
				return nil, err
			}
			refused = append(refused, notOwned)
		}
	}
	for _, id := range zones {
		if err := validateSDNIdentifier("zone", id); err != nil {
			return nil, err
		}
		if len(refused) > 0 {
			zoneStates, _, err := m.ObjectStates(ctx, []string{id}, nil)
			if err != nil {
				return nil, err
			}
			if zoneStates[id] != Absent {
				refused = append(refused, &NotOwnedError{Resource: "zone", ID: id, Reason: "a VNet of the run is refused as not provably the run's, and a zone has no marker of its own"})
			}
			continue
		}
		if err := m.checkZoneOwner(ctx, id); err != nil {
			var notOwned *NotOwnedError
			if !errors.As(err, &notOwned) {
				return nil, err
			}
			refused = append(refused, notOwned)
		}
	}
	return refused, nil
}

// deleted notes a delete PVE accepted.
func (m *Manager) deleted() {
	m.mutations++
	m.acceptedUnderLock()
}

func validateSDNIdentifier(resource, id string) error {
	if id == "" {
		return fmt.Errorf("SDN %s identifier must not be empty", strings.ToLower(resource))
	}
	for index, r := range id {
		isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		isDigit := r >= '0' && r <= '9'
		if (!isLetter && !isDigit) || (index == 0 && !isLetter) {
			return fmt.Errorf("SDN %s identifier %q must start with a letter and contain only letters and digits", strings.ToLower(resource), id)
		}
	}
	return nil
}

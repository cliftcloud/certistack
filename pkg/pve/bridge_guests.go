// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// BridgeGuest is a guest with a network device on a bridge, in its running
// configuration or in a change pending for its next start.
type BridgeGuest struct {
	VMID   int
	Type   string // "qemu" or "lxc"
	Name   string
	Node   string
	Status string
	Device string // "net0"
	// CertiStack is a guest that carries CertiStack's exact "certistack" tag:
	// a sandbox VM of another run, or one a crashed run left.
	CertiStack bool
}

func (g BridgeGuest) String() string {
	kind := "VM"
	if g.Type == "lxc" {
		kind = "container"
	}
	name := ""
	if g.Name != "" {
		// PVE allows only a DNS name; anything else is shown quoted, so
		// that it cannot pass for part of the message.
		name = fmt.Sprintf(" (%s)", g.Name)
		if !guestName.MatchString(g.Name) {
			name = fmt.Sprintf(" (%q)", g.Name)
		}
	}
	status := g.Status
	if !guestStatus.MatchString(status) {
		status = fmt.Sprintf("%q", status)
	}
	tagged := ""
	if g.CertiStack {
		tagged = ", tagged certistack"
	}
	return fmt.Sprintf("%s %d%s on %s, %s, %s%s", kind, g.VMID, name, g.Node, status, g.Device, tagged)
}

var (
	netDeviceKey = regexp.MustCompile(`^net[0-9]+$`)
	guestName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$`)
	// guestStatus is a status as PVE writes one ("running", "stopped"):
	// anything else is shown quoted.
	guestStatus = regexp.MustCompile(`^[a-z][a-z-]{0,31}$`)
)

// bridgeGuestReads is how many guests' configurations are read at once.
const bridgeGuestReads = 8

// GuestsOnBridge lists the guests the token can see that have a network device
// on bridge, now or once a pending change is applied. With node set, only that
// node's guests are read. Templates are left out (they never run), and so is a
// guest in own that carries runID's ownership markers: one of the run's own
// sandbox VMs. A list that cannot be read in full is an error, never a shorter
// list.
func (c *Client) GuestsOnBridge(ctx context.Context, bridge, node string, own map[int]bool, runID string) ([]BridgeGuest, error) {
	if strings.TrimSpace(bridge) == "" {
		return nil, errors.New("bridge is required")
	}
	var raw json.RawMessage
	if err := c.Do(ctx, "GET", "cluster/resources?type=vm", nil, &raw); err != nil {
		return nil, fmt.Errorf("list cluster guests: %w", err)
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, errors.New("list cluster guests: PVE's reply carries no data field, so it is not an answer that no guest exists")
	}
	var resources []struct {
		VMID     *int   `json:"vmid"`
		Type     string `json:"type"`
		Node     string `json:"node"`
		Name     string `json:"name"`
		Status   string `json:"status"`
		Template int    `json:"template"`
	}
	if err := json.Unmarshal(raw, &resources); err != nil {
		return nil, fmt.Errorf("list cluster guests: %w", err)
	}
	var guests []BridgeGuest
	for _, r := range resources {
		if r.VMID == nil || *r.VMID <= 0 {
			return nil, errors.New("list cluster guests: an entry of PVE's list names no VMID, so the list is not complete")
		}
		if r.Type != "qemu" && r.Type != "lxc" {
			return nil, fmt.Errorf("list cluster guests: guest %d has type %q, which CertiStack cannot read", *r.VMID, r.Type)
		}
		if err := validateNodeName(r.Node); err != nil {
			return nil, fmt.Errorf("list cluster guests: guest %d: %w", *r.VMID, err)
		}
		if r.Template == 1 || (node != "" && r.Node != node) {
			continue
		}
		guests = append(guests, BridgeGuest{VMID: *r.VMID, Type: r.Type, Name: r.Name, Node: r.Node, Status: r.Status})
	}

	devices := make([][]string, len(guests))
	owned := make([]bool, len(guests))
	tagged := make([]bool, len(guests))
	errs := make([]error, len(guests))
	slots := make(chan struct{}, bridgeGuestReads)
	var wg sync.WaitGroup
	for i := range guests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			g := guests[i]
			devices[i], owned[i], tagged[i], errs[i] = c.guestDevicesOnBridge(ctx, g.Node, g.Type, g.VMID, bridge, runID)
		}(i)
	}
	wg.Wait()

	var found []BridgeGuest
	var present map[int]bool
	for i, g := range guests {
		if errs[i] != nil {
			// A guest removed since the list was read is on no bridge.
			if present == nil {
				used, err := c.UsedVMIDs(ctx)
				if err != nil {
					return nil, fmt.Errorf("read the network devices of guest %d on %s: %w", g.VMID, g.Node, errs[i])
				}
				present = used
			}
			if !present[g.VMID] {
				continue
			}
			return nil, fmt.Errorf("read the network devices of guest %d on %s: %w", g.VMID, g.Node, errs[i])
		}
		if own[g.VMID] && owned[i] {
			continue
		}
		g.CertiStack = tagged[i]
		for _, device := range devices[i] {
			g.Device = device
			found = append(found, g)
		}
	}
	sort.SliceStable(found, func(a, b int) bool {
		if found[a].VMID != found[b].VMID {
			return found[a].VMID < found[b].VMID
		}
		return found[a].Device < found[b].Device
	})
	return found, nil
}

// guestDevicesOnBridge reads a guest's configuration with its pending changes
// and returns its network devices on bridge, whether it carries runID's
// ownership markers (a container never does), and whether it carries
// CertiStack's tag.
func (c *Client) guestDevicesOnBridge(ctx context.Context, node, kind string, vmid int, bridge, runID string) (devices []string, owned, tagged bool, err error) {
	// PVE answers every guest's configuration as a list of its entries ([]
	// for a configuration with none). A reply with no data field, or null,
	// carries no configuration: it is not an answer that the guest has no
	// network device.
	var raw json.RawMessage
	if err := c.Do(ctx, "GET", fmt.Sprintf("nodes/%s/%s/%d/pending", node, kind, vmid), nil, &raw); err != nil {
		return nil, false, false, err
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, false, false, errors.New("PVE's reply carries no configuration, so it is not an answer that the guest has no network device")
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, false, false, fmt.Errorf("read PVE's reply: %w", err)
	}
	var tags, description string
	for _, entry := range entries {
		// An entry whose key cannot be read could be a network device.
		var key string
		if err := json.Unmarshal(entry["key"], &key); err != nil || key == "" {
			return nil, false, false, errors.New("an entry of the guest's configuration names no key, so its network devices cannot all be read")
		}
		switch {
		case key == "tags":
			_ = json.Unmarshal(entry["value"], &tags)
		case key == "description":
			_ = json.Unmarshal(entry["value"], &description)
		case netDeviceKey.MatchString(key):
			value, err := configText(entry, "value")
			if err != nil {
				return nil, false, false, fmt.Errorf("network device %s: %w", key, err)
			}
			pending, err := configText(entry, "pending")
			if err != nil {
				return nil, false, false, fmt.Errorf("network device %s: %w", key, err)
			}
			if deviceBridge(value) == bridge || deviceBridge(pending) == bridge {
				devices = append(devices, key)
			}
		}
	}
	owned = kind == "qemu" && strings.TrimSpace(runID) != "" &&
		hasExactTag(tags, "certistack") && hasExactTag(tags, runID) &&
		hasExactDescriptionField(description, "owner", "certistack") &&
		hasExactDescriptionField(description, "run_id", runID)
	return devices, owned, hasExactTag(tags, "certistack"), nil
}

// configText is a text field of a configuration entry: empty when the entry
// has no such field (a device only added, or only pending deletion), and an
// error when the field is there but is not text.
func configText(entry map[string]json.RawMessage, field string) (string, error) {
	raw, ok := entry[field]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return "", fmt.Errorf("its %s is not a device specification PVE writes", field)
	}
	return text, nil
}

// deviceBridge is the bridge a network device's specification names, such as
// "virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1" (a VM) or
// "name=eth0,bridge=vmbr0,ip=dhcp" (a container).
func deviceBridge(spec string) string {
	for _, part := range strings.Split(spec, ",") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(part), "bridge="); ok {
			return value
		}
	}
	return ""
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// PrivilegeRequirement is what a run needs on one PVE ACL path. Without a
// Required privilege a run fails there. Without an Advisory one it works
// around it or only some plans need it.
type PrivilegeRequirement struct {
	Path     string
	Required []string
	Advisory []string
	Why      string
	// Propagate requires the Required privileges to reach the paths below
	// Path: PVE's ACL propagate flag, which access/permissions returns as each
	// privilege's value.
	Propagate bool
}

// RunPrivileges are the documented CertiStackRole's privileges, placed on
// the paths a run of these VMs, sandbox and overlay storage touches. A
// pre-provisioned sandbox is only read and used, never allocated.
func RunPrivileges(node string, vmids []int, zone, vnet string, ephemeralSDN bool, overlayStorage string) []PrivilegeRequirement {
	var reqs []PrivilegeRequirement
	for _, vmid := range vmids {
		reqs = append(reqs, PrivilegeRequirement{
			Path:     fmt.Sprintf("/vms/%d", vmid),
			Required: []string{"VM.Allocate", "VM.Audit", "VM.PowerMgmt", "VM.Config.Disk", "VM.Config.CPU", "VM.Config.Memory", "VM.Config.Network", "VM.Config.Options", "VM.Config.HWType"},
			Advisory: []string{"VM.Config.CDROM", "VM.Console"},
			Why:      "create, configure, start and destroy the sandbox VM",
		})
	}
	if ephemeralSDN {
		reqs = append(reqs,
			PrivilegeRequirement{Path: "/sdn", Required: []string{"SDN.Allocate"}, Why: "apply the SDN changes (reload)"},
			PrivilegeRequirement{Path: "/sdn/zones", Required: []string{"SDN.Allocate", "SDN.Audit"}, Why: "create the sandbox zone"},
		)
	} else {
		reqs = append(reqs,
			PrivilegeRequirement{Path: "/sdn/zones/" + zone, Required: []string{"SDN.Audit"}, Why: "check that the pre-provisioned sandbox zone is isolated"},
			// PVE lists only the guests a token may audit: without this, a
			// guest on the VNet could be one the run never sees. Held on /vms
			// alone, without propagation, it shows no guest (/vms/<id>) at all.
			PrivilegeRequirement{Path: "/vms", Required: []string{"VM.Audit"}, Why: "see every guest on the pre-provisioned sandbox VNet", Propagate: true},
		)
	}
	reqs = append(reqs, PrivilegeRequirement{Path: fmt.Sprintf("/sdn/zones/%s/%s", zone, vnet), Required: []string{"SDN.Audit", "SDN.Use"}, Why: "attach the sandbox VMs to the sandbox VNet"})
	if overlayStorage != "" {
		reqs = append(reqs, PrivilegeRequirement{Path: "/storage/" + overlayStorage, Required: []string{"Datastore.AllocateSpace", "Datastore.Audit"}, Why: "hold the overlays and firmware copies"})
	}
	reqs = append(reqs, PrivilegeRequirement{Path: "/nodes/" + node, Advisory: []string{"Sys.Audit"}, Why: "read the node's status and QEMU machine versions"})
	return reqs
}

// MissingPrivilege is what the token lacks on one path.
type MissingPrivilege struct {
	Path     string
	Required []string
	Advisory []string
	Why      string
}

// Permissions returns the privileges the client's token holds on path,
// inherited ones included, as PVE computes them.
func (c *Client) Permissions(ctx context.Context, path string) (map[string]bool, error) {
	propagates, err := c.privilegePropagation(ctx, path)
	if err != nil {
		return nil, err
	}
	privileges := map[string]bool{}
	for name := range propagates {
		privileges[name] = true
	}
	return privileges, nil
}

// privilegePropagation returns each privilege the token holds on path and
// whether it propagates to the paths below: PVE answers access/permissions
// with a map of path to (privilege to propagate flag), the flag 1 or 0.
func (c *Client) privilegePropagation(ctx context.Context, path string) (map[string]bool, error) {
	var byPath map[string]map[string]any
	if err := c.Do(ctx, "GET", "access/permissions?path="+url.QueryEscape(path), nil, &byPath); err != nil {
		return nil, fmt.Errorf("read the token's privileges on %s: %w", path, err)
	}
	privileges := map[string]bool{}
	for _, privs := range byPath {
		for name, flag := range privs {
			privileges[name] = privileges[name] || propagateFlag(flag)
		}
	}
	return privileges, nil
}

// propagateFlag reads a privilege's propagate flag as PVE writes it (1 or 0),
// or as true or false. Anything else is not shown to propagate.
func propagateFlag(flag any) bool {
	switch v := flag.(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v == "1" || strings.EqualFold(v, "true")
	}
	return false
}

// MissingPrivileges checks every requirement and returns what the token
// lacks, path by path, so an operator sees every missing privilege at once.
func (c *Client) MissingPrivileges(ctx context.Context, reqs []PrivilegeRequirement) ([]MissingPrivilege, error) {
	var missing []MissingPrivilege
	for _, req := range reqs {
		propagates, err := c.privilegePropagation(ctx, req.Path)
		if err != nil {
			return nil, err
		}
		gap := MissingPrivilege{Path: req.Path, Why: req.Why}
		for _, priv := range req.Required {
			propagated, held := propagates[priv]
			switch {
			case !held:
				gap.Required = append(gap.Required, priv)
			case req.Propagate && !propagated:
				gap.Required = append(gap.Required, priv+" propagated to the paths below it")
			}
		}
		for _, priv := range req.Advisory {
			if _, held := propagates[priv]; !held {
				gap.Advisory = append(gap.Advisory, priv)
			}
		}
		if len(gap.Required) > 0 || len(gap.Advisory) > 0 {
			missing = append(missing, gap)
		}
	}
	return missing, nil
}

// DescribeMissingPrivileges says what the token lacks: the required
// privileges (which fail a run) and, separately, the advisory ones.
func DescribeMissingPrivileges(missing []MissingPrivilege) (required, advisory string) {
	var req, adv []string
	for _, gap := range missing {
		if len(gap.Required) > 0 {
			req = append(req, fmt.Sprintf("%s on %s (to %s)", strings.Join(gap.Required, ", "), gap.Path, gap.Why))
		}
		if len(gap.Advisory) > 0 {
			adv = append(adv, fmt.Sprintf("%s on %s (to %s)", strings.Join(gap.Advisory, ", "), gap.Path, gap.Why))
		}
	}
	sort.Strings(req)
	sort.Strings(adv)
	return strings.Join(req, "; "), strings.Join(adv, "; ")
}

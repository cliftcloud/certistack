// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var storageIDExpr = regexp.MustCompile(`^[a-z][a-z0-9_.-]*[a-z0-9]$`)

// CreateOverlayStorageCommand is the command that creates the overlay storage
// (certistack setup runs it, and docs/manual-setup.md, "Set up by hand",
// gives it): a directory storage local to the node with "images" content, run
// as root on the node. Every message that leaves a reader without usable
// overlay storage ends with it (CreateOverlayStorageHint), and a docs test
// compares it with the guide, so the two cannot drift.
const CreateOverlayStorageCommand = "pvesm add dir certistack-scratch --path /var/lib/vz/certistack-scratch --content images --shared 0"

// CreateOverlayStorageHint is the sentence that ends those messages. "One"
// is the overlay storage the message has just said is missing. On a cluster
// pvesm defines a storage for every node unless it is given --nodes (the
// option of pvesm add that lists the nodes the storage applies to), which the
// command leaves out because it needs the node's name; the sentence says so.
const CreateOverlayStorageHint = "Create one on the node, as root: " + CreateOverlayStorageCommand + ". On a cluster this defines the storage for every node; add --nodes NODE to limit it to this one. certistack setup adds it for you (quickstart, step 2)"

// hintedError is err followed by a sentence that says how to fix it. The
// error stays in the chain, so errors.As and errors.Is see through it.
type hintedError struct {
	err  error
	hint string
}

func (e *hintedError) Error() string {
	return strings.TrimRight(e.err.Error(), " .") + ". " + e.hint
}

func (e *hintedError) Unwrap() error { return e.err }

// overlayStorageMissing reports whether err is PVE's answer that storage is
// not configured: "No such storage." in the parameter verification of PVE 8
// and 9, or "storage 'ID' does not exist".
func overlayStorageMissing(err error, storage string) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	texts := []string{apiErr.Message}
	for _, text := range apiErr.Errors {
		texts = append(texts, text)
	}
	for _, text := range texts {
		text = strings.ToLower(text)
		if strings.Contains(text, "no such storage") || strings.Contains(text, "storage '"+strings.ToLower(storage)+"' does not exist") {
			return true
		}
	}
	return false
}

// NodeStorageStatus is the subset of GET /nodes/{node}/storage/{id}/status
// that decides whether a storage can hold CertiStack overlays. The endpoint
// needs only Datastore.Audit, unlike reading the storage configuration.
type NodeStorageStatus struct {
	Type    string `json:"type"`
	Content string `json:"content"`
	Active  int    `json:"active"`
	Enabled int    `json:"enabled"`
	Avail   int64  `json:"avail"`
	Total   int64  `json:"total"`
	Shared  int    `json:"shared"`
}

// fileOverlayStorageTypes are PVE storage types whose volumes are files that
// qemu-img can create with a backing device.
var fileOverlayStorageTypes = map[string]bool{
	"dir": true, "nfs": true, "cifs": true, "cephfs": true, "btrfs": true, "glusterfs": true,
}

// GetNodeStorageStatus reads one storage's status as seen from node.
func (c *Client) GetNodeStorageStatus(ctx context.Context, node, storage string) (*NodeStorageStatus, error) {
	if err := validateNodeName(node); err != nil {
		return nil, err
	}
	if !storageIDExpr.MatchString(storage) {
		return nil, fmt.Errorf("invalid PVE storage ID %q", storage)
	}
	var status NodeStorageStatus
	if err := c.Do(ctx, "GET", fmt.Sprintf("nodes/%s/storage/%s/status", node, storage), nil, &status); err != nil {
		return nil, fmt.Errorf("read storage %q status on node %s: %w", storage, node, err)
	}
	return &status, nil
}

// NodeStorage is one storage in GET /nodes/{node}/storage, which lists the
// storages the token may audit or allocate on.
type NodeStorage struct {
	Storage string `json:"storage"`
	NodeStorageStatus
}

// ListNodeStorages lists the enabled storages node sees.
func (c *Client) ListNodeStorages(ctx context.Context, node string) ([]NodeStorage, error) {
	if err := validateNodeName(node); err != nil {
		return nil, err
	}
	var storages []NodeStorage
	if err := c.Do(ctx, "GET", fmt.Sprintf("nodes/%s/storage?enabled=1", node), nil, &storages); err != nil {
		return nil, fmt.Errorf("list storages on node %s: %w", node, err)
	}
	return storages, nil
}

// CanHoldOverlays reports whether s is a storage ValidateOverlayStorage
// accepts, whatever its free space: active, file-based, with "images"
// content.
func (s NodeStorageStatus) CanHoldOverlays() bool {
	return fileOverlayStorageTypes[s.Type] && contentIncludes(s.Content, "images") && s.Active == 1
}

// ValidateOverlayStorage fails closed unless storage is an active, file-based
// storage with "images" content and at least minFreeBytes free. It checks the
// status's active flag only: the enabled flag is decoded and is not consulted
// (the storage listing asks for enabled storages only).
func (c *Client) ValidateOverlayStorage(ctx context.Context, node, storage string, minFreeBytes int64) (*NodeStorageStatus, error) {
	status, err := c.GetNodeStorageStatus(ctx, node, storage)
	if err != nil {
		if overlayStorageMissing(err, storage) {
			return nil, &hintedError{err: err, hint: CreateOverlayStorageHint}
		}
		return nil, err
	}
	switch {
	case !fileOverlayStorageTypes[status.Type]:
		return nil, fmt.Errorf("overlay storage %q is type %q; it must be file-based (dir, nfs, cifs, cephfs, btrfs)", storage, status.Type)
	case !contentIncludes(status.Content, "images"):
		return nil, fmt.Errorf("overlay storage %q does not allow disk images (content %q); add \"images\" content", storage, status.Content)
	case status.Active != 1:
		return nil, fmt.Errorf("overlay storage %q is not active on node %s", storage, node)
	case status.Avail < minFreeBytes:
		return nil, fmt.Errorf("overlay storage %q has %d MiB free on node %s; at least %d MiB is required", storage, status.Avail>>20, node, minFreeBytes>>20)
	}
	return status, nil
}

func contentIncludes(content, want string) bool {
	for _, c := range strings.Split(content, ",") {
		if strings.TrimSpace(c) == want {
			return true
		}
	}
	return false
}

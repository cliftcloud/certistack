// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TaskStatus represents the current state of a Proxmox VE background task.
type TaskStatus struct {
	Status     string `json:"status"`     // "running" or "stopped"
	ExitStatus string `json:"exitstatus"` // "OK" on success, or error string
	ID         string `json:"id"`
	Node       string `json:"node"`
	PID        int    `json:"pid"`
	StartTime  int64  `json:"starttime"`
	Type       string `json:"type"`
	User       string `json:"user"`
}

// TaskNode validates the minimum stable PVE UPID shape and returns the node
// encoded by PVE. A task handle must never be treated as an opaque successful
// response. PVE's full UPID format contains additional fields, but node,
// process/start field, and task type are present on every asynchronous task
// response we can safely poll. Only the node is validated as a name: the other
// fields need only be non-empty, so a handle that passes can still carry any
// text in them, and a caller that puts it in an API path must escape it
// (url.PathEscape), as WaitForTask does.
func TaskNode(upid string) (string, error) {
	parts := strings.Split(upid, ":")
	if len(parts) < 4 || parts[0] != "UPID" {
		return "", fmt.Errorf("invalid PVE task identifier %q", upid)
	}
	for i := 1; i < 4; i++ {
		if parts[i] == "" || strings.TrimSpace(parts[i]) != parts[i] {
			return "", fmt.Errorf("invalid PVE task identifier %q", upid)
		}
	}
	if err := validateNodeName(parts[1]); err != nil {
		return "", fmt.Errorf("invalid PVE task node %q: %w", parts[1], err)
	}
	return parts[1], nil
}

// TaskHandle is what a full PVE task identifier names: the node that runs the
// task, its type (for example "qmstop" or "qmdestroy"), the object it acts on
// (a VM's ID for the qemu tasks) and the user that started it.
type TaskHandle struct {
	Node string
	Type string
	ID   string
	User string
}

// ParseTask reads a full PVE task identifier,
// "UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:", which is what
// PVE returns for every task. ok is false for anything else (a shorter handle,
// non-hexadecimal process or start fields, a missing type or user): its type
// and object are then unknown, and a caller cannot bind the task to what it
// asked for. Such a handle can still be polled when TaskNode accepts it; it is
// not thereby free of unusual characters, which only an escaped path keeps
// from altering the request.
func ParseTask(upid string) (task TaskHandle, ok bool) {
	parts := strings.Split(upid, ":")
	if len(parts) != 9 || parts[0] != "UPID" || parts[8] != "" {
		return TaskHandle{}, false
	}
	if _, err := TaskNode(upid); err != nil {
		return TaskHandle{}, false
	}
	for _, field := range parts[2:5] {
		if !isHexField(field) {
			return TaskHandle{}, false
		}
	}
	if parts[5] == "" || parts[7] == "" {
		return TaskHandle{}, false
	}
	return TaskHandle{Node: parts[1], Type: parts[5], ID: parts[6], User: parts[7]}, true
}

func isHexField(s string) bool {
	if s == "" || len(s) > 16 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// expectVMTask checks that the task PVE returned for an operation on VM vmid
// is one of that operation's own: a full handle whose type is one of types and
// whose object is the VM. A handle PVE's own answer cannot bind (not in the
// full form) is left to the caller's check of the VM itself, which is the
// proof of what a task did in any case: a task of another type or object that
// succeeds says nothing about this VM.
func expectVMTask(upid string, vmid int, operation string, types ...string) error {
	task, full := ParseTask(upid)
	if !full {
		return nil
	}
	for _, t := range types {
		if task.Type == t && task.ID == strconv.Itoa(vmid) {
			return nil
		}
	}
	return fmt.Errorf("PVE answered the %s of VM %d with a %q task for %q, not a %s of that VM, so its outcome says nothing about the VM", operation, vmid, task.Type, task.ID, operation)
}

// ValidateNodeName is validateNodeName for callers outside the package: the
// node name a run is given, checked before anything is changed for it (a zone's
// node list, for one, is sent to PVE verbatim).
func ValidateNodeName(node string) error { return validateNodeName(node) }

// validateNodeName rejects characters that could alter an interpolated PVE API
// path. PVE node names are host-style identifiers; dots and underscores are
// retained for existing installations, while URL, path, whitespace, and
// Unicode ambiguity are intentionally not accepted at this boundary.
func validateNodeName(node string) error {
	if node == "" {
		return fmt.Errorf("node must not be empty")
	}
	if strings.TrimSpace(node) != node {
		return fmt.Errorf("invalid PVE node name %q", node)
	}
	if !isNodeAlphaNumeric(rune(node[0])) || !isNodeAlphaNumeric(rune(node[len(node)-1])) {
		return fmt.Errorf("invalid PVE node name %q", node)
	}
	for _, r := range node {
		if isNodeAlphaNumeric(r) || r == '.' || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("invalid PVE node name %q", node)
	}
	return nil
}

func isNodeAlphaNumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// WaitForTask polls a task UPID on the specified node until it completes.
// Returns nil if the task completed with exitstatus "OK".
// Returns an error if the task failed, timed out, or if the context was canceled.
func (c *Client) WaitForTask(ctx context.Context, node, upid string, pollInterval, timeout time.Duration) error {
	if upid == "" {
		return fmt.Errorf("task UPID must not be empty")
	}
	// Local qm operations complete synchronously. They deliberately have no PVE
	// UPID to poll, so preserve the existing caller contract with a private
	// completed-task marker.
	if strings.HasPrefix(upid, localQMTaskPrefix) {
		return nil
	}
	if err := validateNodeName(node); err != nil {
		return err
	}
	taskNode, err := TaskNode(upid)
	if err != nil {
		return err
	}
	if taskNode != node {
		return fmt.Errorf("PVE task node %q does not match requested node %q", taskNode, node)
	}
	if pollInterval <= 0 {
		pollInterval = 1 * time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	path := fmt.Sprintf("nodes/%s/tasks/%s/status", node, url.PathEscape(upid))
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctxTimeout.Done():
			return fmt.Errorf("timed out waiting for task %s on node %s: %w", upid, node, ctxTimeout.Err())
		case <-ticker.C:
			var status TaskStatus
			err := c.Do(ctxTimeout, "GET", path, nil, &status)
			if err != nil {
				slog.Warn("failed to poll task status, will retry", "upid", upid, "error", err)
				continue
			}

			if err := checkTaskStatusIdentity(upid, status); err != nil {
				return err
			}

			if status.Status == "stopped" {
				if status.ExitStatus == "OK" {
					slog.Debug("task completed successfully", "upid", upid, "node", node)
					return nil
				}
				// PVE ends a task that succeeded with warnings as
				// "WARNINGS: <count>" and treats it as successful itself.
				if strings.HasPrefix(status.ExitStatus, "WARNINGS:") {
					slog.Warn("task completed with warnings", "upid", upid, "node", node, "exit_status", status.ExitStatus)
					return nil
				}
				return fmt.Errorf("task %s failed with exit status: %s", upid, status.ExitStatus)
			}
		}
	}
}

// checkTaskStatusIdentity refuses a status answer that describes another task
// than the one polled: PVE's status names the task's node, type and object,
// and a full handle names the same. What a status does not name is not
// compared. Whether the task's success means anything for a resource is for
// the caller to establish from the resource itself.
func checkTaskStatusIdentity(upid string, status TaskStatus) error {
	task, full := ParseTask(upid)
	if !full {
		return nil
	}
	// PVE escapes some characters in the handle's object (a service name's
	// colon), and reports it unescaped: only plain objects are compared.
	plainID := !strings.Contains(status.ID+task.ID, `\`)
	if (status.Node == "" || status.Node == task.Node) &&
		(status.Type == "" || status.Type == task.Type) &&
		(status.ID == "" || !plainID || status.ID == task.ID) {
		return nil
	}
	return fmt.Errorf("PVE's status of task %q for %q on %s describes a %q task for %q on %s instead", task.Type, task.ID, task.Node, status.Type, status.ID, status.Node)
}

// NodeCount is the number of nodes in the cluster, online or not.
func (c *Client) NodeCount(ctx context.Context) (int, error) {
	var nodes []struct {
		Node string `json:"node"`
	}
	if err := c.Do(ctx, "GET", "nodes", nil, &nodes); err != nil {
		return 0, fmt.Errorf("list the cluster's nodes: %w", err)
	}
	return len(nodes), nil
}

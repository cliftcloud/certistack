// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cliftcloud/certistack/internal/process"
)

// VMBackups is one VM's backups in the repository (and namespace): its
// newest complete snapshot, as "latest" resolves it, and how many complete
// snapshots it has.
type VMBackups struct {
	VMID   int       `json:"vmid"`
	Latest string    `json:"latest"`
	Time   time.Time `json:"time"`
	Count  int       `json:"count"`
	// Comment is the first line of the newest snapshot's notes; by PVE's
	// default notes template, the guest's name.
	Comment string `json:"comment,omitempty"`
	// DiskBytes is the length of the disk images of the newest snapshot all
	// together; 0 when the listing does not say.
	DiskBytes int64 `json:"disk_bytes,omitempty"`
}

// imageBytes is the length of the disk images a snapshot lists, together.
func imageBytes(files *[]snapshotFile) int64 {
	if files == nil {
		return 0
	}
	var total int64
	for _, file := range *files {
		if strings.HasSuffix(file.Filename, ".img.fidx") && file.Size > 0 {
			total += file.Size
		}
	}
	return total
}

type snapshotListCommentEntry struct {
	snapshotListEntry
	Comment string `json:"comment"`
}

// ListVMBackups lists every VM that has a complete snapshot in the
// repository, by VMID. It reads the snapshot list once; a VM whose
// snapshots are all incomplete is left out, as "latest" could not resolve
// it.
//
// The client's output is capped (16 MiB), and a repository with a few tens of
// thousands of snapshots lists more than that. Then the list is read VM by VM
// instead (listVMBackupsByGroup), so that a large repository is listed, not
// refused; a list that cannot be read either way fails, never partly.
func (c *Client) ListVMBackups(ctx context.Context) ([]VMBackups, error) {
	args := append([]string{"snapshot", "list", "--output-format", "json"}, c.targetArgs()...)
	output, err := c.runLimited(ctx, 60*time.Second, pbsListOutputLimit, args...)
	if errors.Is(err, process.ErrOutputLimit) {
		slog.Info("the repository's snapshot list is longer than CertiStack reads at once; listing it VM by VM")
		return c.listVMBackupsByGroup(ctx)
	}
	if err != nil {
		return nil, listFailure("list PBS snapshots", err, []byte(output))
	}
	return ParseVMBackupsJSON([]byte(output))
}

// listVMBackupsByGroup is ListVMBackups for a repository whose whole snapshot
// list is too long to read at once: the backup groups are listed (a line each,
// not a line per snapshot; listBackupGroups says how, for a namespace), and
// then the snapshots of each VM's group, so no single output grows with the
// number of snapshots of the repository. Groups of containers and hosts are
// not asked about. Any listing that fails fails the whole, naming the group: a
// VM left out of the list because its listing failed would read as a VM with
// no backup.
func (c *Client) listVMBackupsByGroup(ctx context.Context) ([]VMBackups, error) {
	groups, err := c.listBackupGroups(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	var vmids []int
	for _, group := range groups {
		if group.BackupType != "vm" {
			continue
		}
		vmid, err := strconv.Atoi(group.BackupID)
		if err != nil || vmid <= 0 || seen[vmid] {
			continue
		}
		seen[vmid] = true
		vmids = append(vmids, vmid)
	}
	sort.Ints(vmids)

	var backups []VMBackups
	for _, vmid := range vmids {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("list PBS snapshots by VM: %w", err)
		}
		group := fmt.Sprintf("vm/%d", vmid)
		args := append([]string{"snapshot", "list", group, "--output-format", "json"}, c.targetArgs()...)
		output, err := c.runLimited(ctx, 60*time.Second, pbsListOutputLimit, args...)
		if err != nil {
			return nil, listFailure("list PBS snapshots for "+group, err, []byte(output))
		}
		listed, err := ParseVMBackupsJSON([]byte(output))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", group, err)
		}
		if len(listed) > 1 || (len(listed) == 1 && listed[0].VMID != vmid) {
			return nil, fmt.Errorf("list PBS snapshots for %s: the client listed snapshots of other backup groups", group)
		}
		backups = append(backups, listed...)
		groupListed(vmid)
	}
	return backups, nil
}

// backupGroup is one backup group a listing names.
type backupGroup struct {
	BackupType string `json:"backup-type"`
	BackupID   string `json:"backup-id"`
}

// listBackupGroups lists the backup groups of the repository's namespace.
// `proxmox-backup-client group list` takes no --ns in any client version, and
// the 3.x client ignores PBS_NAMESPACE, so for a namespace the groups come
// from the PBS API; the client's command reads the root namespace and is used
// only when there is no namespace.
func (c *Client) listBackupGroups(ctx context.Context) ([]backupGroup, error) {
	if c.cfg.Namespace != "" {
		groups, err := c.listBackupGroupsAPI(ctx)
		if err != nil {
			return nil, fmt.Errorf("list PBS backup groups of namespace %q through the PBS API (the client's group list cannot be limited to a namespace): %w", c.cfg.Namespace, err)
		}
		return groups, nil
	}
	args := []string{"group", "list", "--output-format", "json"}
	if c.cfg.Repository != "" {
		args = append(args, "--repository", c.cfg.Repository)
	}
	output, err := c.runLimited(ctx, 60*time.Second, pbsListOutputLimit, args...)
	if err != nil {
		return nil, commandFailure("list PBS backup groups", err, []byte(output))
	}
	var groups []backupGroup
	if err := json.Unmarshal([]byte(output), &groups); err != nil {
		return nil, fmt.Errorf("parse PBS backup group list JSON: %w", err)
	}
	return groups, nil
}

// groupListed is called after listVMBackupsByGroup has listed one VM's
// snapshots. It does nothing; it is a variable so that a test can end the
// context at the one moment the loop looks for it, between two groups.
var groupListed = func(vmid int) {}

// ParseVMBackupsJSON groups the output of `proxmox-backup-client snapshot
// list --output-format json` by VM. Snapshots of containers and hosts, and
// incomplete ones, are skipped.
func ParseVMBackupsJSON(data []byte) ([]VMBackups, error) {
	var entries []snapshotListCommentEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse PBS snapshot list JSON: %w", err)
	}
	byVM := map[int]*VMBackups{}
	for _, entry := range entries {
		if entry.BackupType != "vm" || !entry.complete() || !entry.holdsDiskImage() {
			continue
		}
		vmid, err := strconv.Atoi(entry.BackupID)
		if err != nil || vmid <= 0 {
			continue
		}
		backupTime, err := parseBackupTime(entry.BackupTime)
		if err != nil {
			return nil, fmt.Errorf("parse backup time for vm/%s: %w", entry.BackupID, err)
		}
		vm := byVM[vmid]
		if vm == nil {
			vm = &VMBackups{VMID: vmid}
			byVM[vmid] = vm
		}
		vm.Count++
		if vm.Latest == "" || backupTime.After(vm.Time) {
			vm.Time = backupTime
			vm.Latest = fmt.Sprintf("vm/%d/%s", vmid, backupTime.Format(time.RFC3339))
			vm.Comment = snapshotComment(entry.Comment)
			vm.DiskBytes = imageBytes(entry.Files)
		}
	}
	backups := make([]VMBackups, 0, len(byVM))
	for _, vm := range byVM {
		backups = append(backups, *vm)
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].VMID < backups[j].VMID })
	return backups, nil
}

// snapshotComment is the first line of a snapshot's notes, without control
// characters and at most 64 runes, for display only.
func snapshotComment(comment string) string {
	line, _, _ := strings.Cut(comment, "\n")
	line = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, line)
	line = strings.TrimSpace(line)
	if runes := []rune(line); len(runes) > 64 {
		line = string(runes[:64])
	}
	return line
}

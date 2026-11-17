// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"regexp"
	"strings"
)

// Backup consistency states. A restore test proves the backed-up disks
// boot and serve; whether the guest had flushed and frozen its file systems
// when the snapshot was taken says how much the applications had to recover
// on their own, which a database owner needs to know.
const (
	// ConsistencyQuiesced: the guest agent froze the guest's file systems
	// (VSS on Windows) for the snapshot.
	ConsistencyQuiesced = "quiesced"
	// ConsistencyCrash: a running VM was backed up without a freeze that
	// held, so the disks are as after a power loss.
	ConsistencyCrash = "crash-consistent"
	// ConsistencyPoweredOff: the VM was not running, or was shut down for
	// the backup (stop mode).
	ConsistencyPoweredOff = "powered-off"
	// ConsistencyUnknown: the backup's log could not be read or did not say.
	ConsistencyUnknown = "unknown"
)

// QuiescedRequirementUnmet explains why a backup in state fails a plan's
// require_quiesced_backup, or returns "" when it meets it. Only a quiesced
// or powered-off backup meets it: an unknown state proves nothing.
func QuiescedRequirementUnmet(state, detail string) string {
	switch state {
	case ConsistencyQuiesced, ConsistencyPoweredOff:
		return ""
	case "":
		state, detail = ConsistencyUnknown, "no backup log was read"
	}
	reason := "the plan requires a quiesced backup (require_quiesced_backup), but this one is " + state
	if detail != "" {
		reason += ": " + detail
	}
	return reason
}

// BackupConsistency is how consistent a backup's disks were, read from the
// log vzdump stores with the snapshot. That log is uploaded after the
// snapshot is complete and is not covered by its manifest or signature.
type BackupConsistency struct {
	State  string
	Detail string
}

const maxConsistencyDetail = 240

func unknownConsistency(detail string) BackupConsistency {
	return BackupConsistency{State: ConsistencyUnknown, Detail: detail}
}

// ParseBackupLog classifies a vzdump QEMU backup log (client.log.blob).
//
// The log's freeze and thaw errors quote the guest agent, which the guest
// controls, even across lines. So a line's level is read only at its fixed
// position; vzdump's own markers count only as INFO lines; the VM's status
// and backup mode count only as vzdump states them, once and before it
// touches the guest; and once a problem is found, no later line can clear
// it. Every quoted reason is stripped of control characters and bounded.
//
// Only a recognized problem is conclusive on its own. Every other state
// needs the log to reach "started backup task", and a quiesced one the
// whole sequence vzdump writes around the snapshot, in order: the freeze,
// then the thaw, then the task. "issuing ... fs-freeze" is written before
// the freeze is attempted, so it proves nothing by itself; a log that ends
// earlier, cut short or truncated, is unknown.
func ParseBackupLog(log string) BackupConsistency {
	var status, mode, problem string
	var freezeIssued, thawIssued, taskStarted bool
	for _, line := range strings.Split(log, "\n") {
		level, message := backupLogMessage(line)
		if level == "" {
			continue
		}
		switch {
		case level == "INFO" && strings.HasPrefix(message, "status = "):
			if status == "" && !freezeIssued {
				status = firstField(strings.TrimPrefix(message, "status = "))
			}
		case level == "INFO" && strings.HasPrefix(message, "backup mode: "):
			if mode == "" && !freezeIssued {
				mode = firstField(strings.TrimPrefix(message, "backup mode: "))
			}
		case level == "INFO" && message == "issuing guest-agent 'fs-freeze' command":
			if !taskStarted {
				freezeIssued = true
			}
		case level == "INFO" && message == "issuing guest-agent 'fs-thaw' command":
			if freezeIssued && !taskStarted {
				thawIssued = true
			}
		case level == "INFO" && strings.HasPrefix(message, "started backup task"):
			taskStarted = true
		case problem != "":
			// The first problem stands.
		case strings.HasPrefix(message, "unable to freeze guest fs"):
			problem = "the guest agent could not freeze the file systems: " + logReason(message)
		case strings.HasPrefix(message, "skipping guest filesystem freeze"), strings.HasPrefix(message, "skipping guest-agent 'fs-freeze'"):
			problem = "the file systems were not frozen: " + logReason(message)
		case level == "ERROR" && freezeIssued && !taskStarted && !thawIssued:
			// Older qemu-server logs a refused freeze as a plain command
			// error ("VM 7128 qmp command 'guest-fsfreeze-freeze' failed").
			problem = "the file system freeze failed: " + boundedLogText(message)
		case level == "ERROR" && thawIssued && !taskStarted:
			// A freeze that did not hold until the thaw, such as Windows
			// VSS releasing writes after its 10-second limit, gives no
			// guarantee for the snapshot taken in between.
			problem = "the file system freeze did not hold until the snapshot: " + boundedLogText(message)
		}
	}
	switch {
	case status == "" && mode == "":
		return unknownConsistency("the backup log does not describe the VM's state")
	case status == "stopped" && taskStarted:
		return BackupConsistency{State: ConsistencyPoweredOff, Detail: "the VM was not running during the backup"}
	case mode == "stop" && taskStarted:
		return BackupConsistency{State: ConsistencyPoweredOff, Detail: "the VM was shut down for the backup (stop mode)"}
	case problem != "":
		return BackupConsistency{State: ConsistencyCrash, Detail: problem}
	case !taskStarted:
		return unknownConsistency("the backup log ends before the backup task started, so it does not show how the snapshot was taken")
	case freezeIssued && !thawIssued:
		return unknownConsistency("the backup log shows the file system freeze but no thaw before the backup task started")
	case freezeIssued:
		return BackupConsistency{State: ConsistencyQuiesced, Detail: "the guest agent froze the file systems for the snapshot"}
	case mode == "suspend":
		return BackupConsistency{State: ConsistencyCrash, Detail: "the VM was suspended for the backup without a file system freeze"}
	case status != "" && status != "running":
		return BackupConsistency{State: ConsistencyCrash, Detail: "the VM was " + boundedLogText(status) + " during the backup, without a file system freeze"}
	default:
		return BackupConsistency{State: ConsistencyCrash, Detail: "the file systems were not frozen: the VM has no guest agent enabled"}
	}
}

var backupLogTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} `)

// backupLogMessage splits "2026-09-26 21:08:43 INFO: message", or the same
// line without its timestamp, into its level and message. The level is read
// only at that position, never from inside a message; lines without one
// are not log messages.
func backupLogMessage(line string) (string, string) {
	line = strings.TrimRight(line, "\r")
	if prefix := backupLogTimestamp.FindString(line); prefix != "" {
		line = line[len(prefix):]
	}
	for _, level := range []string{"INFO", "WARN", "ERROR"} {
		if message, ok := strings.CutPrefix(line, level+":"); ok {
			return level, strings.TrimSpace(message)
		}
	}
	return "", ""
}

func firstField(value string) string {
	if fields := strings.Fields(value); len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// logReason returns what follows " - " in a vzdump message ("unable to
// freeze guest fs - failed to open /var/lib/pgsql: Permission denied").
func logReason(message string) string {
	if _, reason, ok := strings.Cut(message, " - "); ok {
		return boundedLogText(reason)
	}
	return boundedLogText(message)
}

func boundedLogText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	if len(value) > maxConsistencyDetail {
		value = strings.ToValidUTF8(value[:maxConsistencyDetail], "") + "..."
	}
	return value
}

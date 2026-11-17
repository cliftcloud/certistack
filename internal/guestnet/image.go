// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/sysutil"
)

// ImageReader reads files from the disks of a mapped backup without changing
// anything: every guestfish it starts opens the disks read-only (--ro), as
// raw images, inspects them (-i, which mounts the guest's file systems
// read-only), and runs only commands that read: is-file, is-dir, find, cat
// and echo. It is for `certistack init --inspect`, which reads a few
// configuration files of a guest from its PBS map; network recovery's Adapter
// is the code that writes, and only to disposable overlays.
type ImageReader struct {
	devices []string
	run     commandRunner
	nonce   func() (string, error)
}

// imageReadTimeout bounds one guestfish launch of an ImageReader: the
// appliance's start and inspection, then a few dozen small reads.
const imageReadTimeout = 3 * time.Minute

// maxReadAttempts is how many guestfish launches one Gather makes at most: a
// command that fails ends its launch, and the commands after it are run
// again in the next.
const maxReadAttempts = 3

// NewImageReader is a reader of the mapped disks devices, in the order the
// guest sees them: guestfish -i needs every disk of a guest whose file systems
// span several. Each must be a mapped loop or NBD device.
func NewImageReader(devices []string) (*ImageReader, error) {
	if len(devices) == 0 || len(devices) > maxOverlays {
		return nil, fmt.Errorf("an image reader needs 1 to %d disks, not %d", maxOverlays, len(devices))
	}
	for _, device := range devices {
		if !sysutil.ValidMappedDevice(device) {
			return nil, fmt.Errorf("%q is not a mapped loop or NBD device", device)
		}
	}
	return &ImageReader{devices: append([]string(nil), devices...), run: runImageGuestfish, nonce: randomNonce}, nil
}

func runImageGuestfish(ctx context.Context, args ...string) (string, error) {
	result, err := sysutil.Run(ctx, imageReadTimeout, "guestfish", args...)
	if result == nil {
		return "", err
	}
	if err != nil {
		if reason := guestfishReason(result.Stderr); reason != "" {
			err = fmt.Errorf("%w: %s", err, reason)
		}
		err = withEncryptedVolume(ctx, args, err)
	}
	return string(result.Stdout), err
}

func randomNonce() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ReadRequest is what one Gather asks of the guest. Every path is a clean
// absolute guest path.
type ReadRequest struct {
	// Files are asked whether they are regular files, following symbolic
	// links inside the guest.
	Files []string
	// Dirs are asked whether they are directories.
	Dirs []string
	// Find lists every entry beneath each directory, recursively, as paths
	// relative to it. Each must exist.
	Find []string
	// Read is the files whose contents are read.
	Read []string
}

// ReadResult is what a Gather found. A path a command failed on is in Failed,
// with guestfish's reason, and in none of the others.
type ReadResult struct {
	IsFile  map[string]bool
	IsDir   map[string]bool
	Found   map[string][]string
	Content map[string]string
	Failed  map[string]string
}

// imageCommand is one guestfish command of a Gather.
type imageCommand struct {
	verb string // is-file, is-dir, find, cat
	path string
}

func (c imageCommand) words() []string {
	if c.verb == "is-file" {
		return []string{c.verb, c.path, "followsymlinks:true"}
	}
	return []string{c.verb, c.path}
}

// maxFoundEntries bounds what one find returns: a configuration directory is
// small, and a guest that holds more there is not read in full.
const maxFoundEntries = 4096

// Gather answers req in as few guestfish launches as it can: one, unless a
// command fails. guestfish stops at the first command that fails, after
// printing what the commands before it printed, so the failed command is
// recorded in Failed and the commands after it are run again in a new launch,
// up to maxReadAttempts launches in all. Each command's output is told apart
// by an echo of a marker that holds a random nonce, which no file of the guest
// can contain. A launch that fails before its first command (the disks cannot
// be opened or inspected) is the error, classified by InspectionError.
func (r *ImageReader) Gather(ctx context.Context, req ReadRequest) (ReadResult, error) {
	result := ReadResult{IsFile: map[string]bool{}, IsDir: map[string]bool{}, Found: map[string][]string{}, Content: map[string]string{}, Failed: map[string]string{}}
	var commands []imageCommand
	for _, group := range []struct {
		verb  string
		paths []string
	}{{"is-file", req.Files}, {"is-dir", req.Dirs}, {"find", req.Find}, {"cat", req.Read}} {
		for _, p := range group.paths {
			if !cleanGuestPath(p) {
				return result, fmt.Errorf("%q is not a clean absolute guest path", p)
			}
			commands = append(commands, imageCommand{verb: group.verb, path: p})
		}
	}
	for attempt := 1; len(commands) > 0; attempt++ {
		if attempt > maxReadAttempts {
			for _, c := range commands {
				result.Failed[c.path] = fmt.Sprintf("not read: guestfish failed %d times before it got to it", maxReadAttempts)
			}
			break
		}
		nonce, err := r.nonce()
		if err != nil {
			return result, fmt.Errorf("make a read marker: %w", err)
		}
		marker := "@certistack-" + nonce + ":"
		args := append(guestfishDrivesOf("--ro", "raw", r.devices), "--")
		for i, c := range commands {
			args = append(args, "echo", marker+strconv.Itoa(i), ":")
			args = append(args, c.words()...)
			args = append(args, ":")
		}
		args = append(args, "echo", marker+"end")
		output, runErr := r.run(ctx, args...)
		sections, done := splitSections(output, marker, len(commands))
		for i := 0; i < done; i++ {
			record(&result, commands[i], sections[i])
		}
		if runErr == nil && done == len(commands) {
			break
		}
		if runErr == nil {
			return result, fmt.Errorf("guestfish ended without finishing its reads")
		}
		if done == 0 && !sectionStarted(output, marker, 0) {
			// Nothing ran: the appliance could not open or inspect the disks.
			return result, InspectionError(runErr)
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if done >= len(commands) {
			// Every command printed what it read, and guestfish failed after
			// them (unmounting, say): what was read stands.
			break
		}
		failed := commands[done]
		result.Failed[failed.path] = failureReason(runErr)
		commands = commands[done+1:]
	}
	return result, nil
}

// splitSections cuts guestfish's output at the markers echoed before each of
// n commands and after the last. sections[i] is what command i printed;
// done is how many commands are known to have finished (their next marker was
// printed).
func splitSections(output, marker string, n int) (sections []string, done int) {
	pos := -1
	for i := 0; i <= n; i++ {
		tag := marker + strconv.Itoa(i) + "\n"
		if i == n {
			tag = marker + "end\n"
		}
		at := strings.Index(output[max(pos, 0):], tag)
		if at < 0 {
			break
		}
		at += max(pos, 0)
		if i > 0 {
			sections = append(sections, output[pos:at])
			done = i
		}
		pos = at + len(tag)
	}
	return sections, done
}

// sectionStarted reports whether the marker before command i was printed.
func sectionStarted(output, marker string, i int) bool {
	return strings.Contains(output, marker+strconv.Itoa(i)+"\n")
}

// record files what command c printed in result.
func record(result *ReadResult, c imageCommand, section string) {
	switch c.verb {
	case "is-file":
		result.IsFile[c.path] = strings.TrimSpace(section) == "true"
	case "is-dir":
		result.IsDir[c.path] = strings.TrimSpace(section) == "true"
	case "find":
		var entries []string
		for _, line := range strings.Split(section, "\n") {
			// libguestfs 1.54.1 on a PVE 9.2 node prints each entry with a
			// leading slash ("/nginx.service", "/sub/file"), though its manual
			// says "without any prefix": either form is read, and an entry is
			// kept relative to the directory.
			line = strings.TrimPrefix(line, "/")
			if line == "" || !safeRelativePath(line) {
				continue
			}
			if len(entries) == maxFoundEntries {
				break
			}
			entries = append(entries, line)
		}
		result.Found[c.path] = entries
	case "cat":
		// guestfish ends what it prints of a string with a newline of its own.
		result.Content[c.path] = strings.TrimSuffix(section, "\n")
	}
}

// safeRelativePath reports whether a find entry is a path whose every
// component can be named again (safeEntryName): one that could not, or that
// would be a line of the listing that never was a file, is dropped.
func safeRelativePath(entry string) bool {
	for _, component := range strings.Split(entry, "/") {
		if !safeEntryName(component) {
			return false
		}
	}
	return true
}

// cleanGuestPath reports whether p is a clean absolute guest path that
// guestfish takes as one argument of one command.
func cleanGuestPath(p string) bool {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || p == ":" {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// failureReason is guestfish's reason for a failed command, one bounded line.
func failureReason(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "No such file or directory"):
		return "not found"
	case strings.Contains(message, "output exceeded"):
		return "too large to read"
	}
	const maximum = 200
	if len(message) > maximum {
		message = message[:maximum] + "..."
	}
	return message
}

// guestfishDrivesOf adds every image as a drive of the given format, in
// order, for guestfishDrives (qcow2 overlays) and ImageReader (raw maps).
func guestfishDrivesOf(access, format string, images []string) []string {
	args := make([]string, 0, 3+3*len(images))
	args = append(args, access, keysFromStdin)
	for _, image := range images {
		args = append(args, "--format="+format, "-a", image)
	}
	return append(args, "-i")
}

// InspectionError says, in words for a plan's comment, why guestfish could
// not open or inspect a backup's disks. A guest it cannot read whatever is
// tried (an encrypted volume, no operating system it recognises, several, a
// partition layout it cannot read) is a refusal (IsRefusal), as network
// recovery's dependencyError makes one; a missing guestfish names the package.
func InspectionError(err error) error {
	message := err.Error()
	switch {
	case errors.Is(err, exec.ErrNotFound) || strings.Contains(message, "executable file not found"):
		return fmt.Errorf("guestfish is not installed on the node (install libguestfs-tools): %w", err)
	case encryptedVolume(message) != "":
		return guestRefusal{fmt.Errorf("a backed-up disk holds a %s-encrypted volume, which cannot be read without its passphrase: %w", encryptedVolume(message), err)}
	case strings.Contains(message, "no operating system was found"):
		return guestRefusal{fmt.Errorf("libguestfs found no operating system on the backed-up disks (an appliance, or a system it cannot inspect): %w", err)}
	case strings.Contains(message, "multi-boot"):
		return guestRefusal{fmt.Errorf("more than one backed-up disk holds an operating system: %w", err)}
	case strings.Contains(message, "inspect_os") && strings.Contains(message, "Invalid partition table"):
		return guestRefusal{fmt.Errorf("libguestfs cannot read the disks' partition layout, as with FreeBSD-based systems such as OPNsense: %w", err)}
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("guestfish did not finish within %s: %w", imageReadTimeout, err)
	}
	return fmt.Errorf("guestfish could not open the backed-up disks: %w", err)
}

// IsRefusal reports whether err is a guest that guestfish cannot read however
// it is asked (guestRefusal), as opposed to a failure of the node or the tool.
func IsRefusal(err error) bool {
	return isGuestRefusal(err)
}

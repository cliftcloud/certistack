// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/recoverhint"
)

// Holders of a mapped loop device.
//
// A PBS map is a read-only loop device with partition scanning. The host's
// own udev rules look at those partitions as they would at any disk: a guest
// with Linux software RAID gets its arrays assembled on the host (md126 over
// loop0p1 and loop1p1), and a guest with LVM or dm-crypt can get device-mapper
// devices activated on them. Such a device holds its member partitions open,
// and a loop device that is held cannot be released: losetup -d and
// proxmox-backup-client unmap only mark it for removal (autoclear), and the
// loop stays, with the backing file "/" because the FUSE file is gone.
//
// ReleaseLoopHolders stops those devices before the loop is unmapped. It stops
// only what it can show is the run's own: every member of the holder, however
// many layers down, must be a partition of a loop device the run's journal
// tracks and that still backs the file the run recorded for it. Anything else
// is left alone and reported.

// LoopIdentity is a loop device a run's journal tracks and the backing file
// the kernel reported for it when the run mapped it.
type LoopIdentity struct {
	Device  string // /dev/loopN
	Backing string
}

// LoopHolder is a block device that holds a loop device, or one of its
// partitions, open as a member.
type LoopHolder struct {
	Name   string // kernel name: md126, dm-0
	DMName string // the device-mapper name of a dm-N device, else ""
}

// Kind is "md" for a software RAID array, "dm" for a device-mapper device, and
// "" for anything else.
func (h LoopHolder) Kind() string {
	switch {
	case mdNameExpr.MatchString(h.Name):
		return "md"
	case dmNameExpr.MatchString(h.Name):
		return "dm"
	}
	return ""
}

// Label names the holder for an operator: md126, or dm-0 (rl-root).
func (h LoopHolder) Label() string {
	if h.DMName != "" {
		return fmt.Sprintf("%s (%s)", h.Name, h.DMName)
	}
	return h.Name
}

var (
	mdNameExpr   = regexp.MustCompile(`^md[0-9]+$`)
	dmNameExpr   = regexp.MustCompile(`^dm-[0-9]+$`)
	loopPartExpr = regexp.MustCompile(`^loop([0-9]+)(?:p[0-9]+)?$`)
	mdPartExpr   = regexp.MustCompile(`^(md[0-9]+)p[0-9]+$`)
)

// StopCommands are the commands that release holders, in the order that works
// (holders is children first, as LoopHolders returns it): consecutive arrays
// share one mdadm command, consecutive device-mapper devices one dmsetup
// command. A holder of an unknown kind has none.
func StopCommands(holders []LoopHolder) []string {
	var commands []string
	var kind string
	var names []string
	flush := func() {
		if len(names) == 0 {
			return
		}
		switch kind {
		case "md":
			commands = append(commands, "mdadm --stop "+strings.Join(names, " "))
		case "dm":
			commands = append(commands, "dmsetup remove "+strings.Join(names, " "))
		}
		names = nil
	}
	for _, h := range holders {
		k := h.Kind()
		if k == "" || (k == "dm" && h.DMName == "") {
			flush()
			kind = ""
			continue
		}
		if k != kind {
			flush()
			kind = k
		}
		if k == "md" {
			names = append(names, "/dev/"+h.Name)
		} else {
			names = append(names, h.DMName)
		}
	}
	flush()
	return commands
}

// HolderLabels joins the holders' labels.
func HolderLabels(holders []LoopHolder) string {
	labels := make([]string, len(holders))
	for i, h := range holders {
		labels[i] = h.Label()
	}
	return strings.Join(labels, ", ")
}

// holderHost is where the holder code looks and what it runs. The host's is
// hostHolders; tests build their own.
type holderHost struct {
	sysBlock  string // /sys/block
	mountInfo string // /proc/self/mountinfo
	// checkLoop is CheckLoop.
	checkLoop func(device, recorded string) (LoopState, error)
	lookPath  func(string) (string, error)
	// run runs a command to completion; its error carries what the command said.
	run func(ctx context.Context, name string, args ...string) error
	// writeAttr writes a sysfs attribute.
	writeAttr func(path, value string) error
	sleep     func(time.Duration)
	// bootID is the current boot (/proc/sys/kernel/random/boot_id), which a
	// recorded disk sequence number is compared in.
	bootID func() (string, error)
	// settleAttempts and settleInterval bound the wait for a stopped holder to
	// leave the kernel's holder lists.
	settleAttempts int
	settleInterval time.Duration
	// stopAttempts and stopInterval bound the retries of an array's stop, which
	// is refused while something (udev probing it) briefly has the array open.
	stopAttempts int
	stopInterval time.Duration
}

func hostHolders() holderHost {
	return holderHost{
		sysBlock:       SysBlockDir,
		mountInfo:      "/proc/self/mountinfo",
		checkLoop:      CheckLoop,
		lookPath:       exec.LookPath,
		run:            runHolderCommand,
		writeAttr:      writeSysfsAttr,
		sleep:          time.Sleep,
		bootID:         currentBootID,
		settleAttempts: 10,
		settleInterval: 500 * time.Millisecond,
		stopAttempts:   5,
		stopInterval:   time.Second,
	}
}

const holderCommandTimeout = 30 * time.Second

func runHolderCommand(ctx context.Context, name string, args ...string) error {
	result, err := Run(ctx, holderCommandTimeout, name, args...)
	if err == nil {
		return nil
	}
	if result != nil {
		if said := firstLine(result.Stderr); said != "" {
			return fmt.Errorf("%s: %w: %s", name, err, said)
		}
	}
	return fmt.Errorf("%s: %w", name, err)
}

func firstLine(out []byte) string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	line = strings.TrimSpace(line)
	if len(line) > 300 {
		line = line[:300]
	}
	return line
}

func writeSysfsAttr(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(value)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// LoopHolders lists the md and device-mapper devices (and whatever else holds
// them in turn) that hold the loop device or one of its partitions, children
// first: the order in which they have to be released. Nothing is changed.
func LoopHolders(device string) ([]LoopHolder, error) {
	return hostHolders().loopHolders(device)
}

func (h holderHost) loopHolders(device string) ([]LoopHolder, error) {
	if !validNumberedDevice(device, "/dev/loop") {
		return nil, fmt.Errorf("invalid loop device %q", device)
	}
	names, err := h.collect(filepath.Base(device))
	if err != nil {
		return nil, err
	}
	holders := make([]LoopHolder, len(names))
	for i, name := range names {
		holders[i] = h.holder(name)
	}
	return holders, nil
}

func (h holderHost) holder(name string) LoopHolder {
	holder := LoopHolder{Name: name}
	if dmNameExpr.MatchString(name) {
		if data, err := os.ReadFile(filepath.Join(h.sysBlock, name, "dm", "name")); err == nil {
			holder.DMName = strings.TrimSpace(string(data))
		}
	}
	return holder
}

const maxHolderDepth = 8

// collect is the names of everything that holds the block device name, its
// partitions included, and what holds those in turn, each after what holds it
// (children first), once.
func (h holderHost) collect(name string) ([]string, error) {
	var out []string
	seen := map[string]bool{name: true}
	var walk func(string, int) error
	walk = func(n string, depth int) error {
		if depth > maxHolderDepth {
			return fmt.Errorf("%s is held through more than %d layers of devices", name, maxHolderDepth)
		}
		direct, err := h.directHolders(n)
		if err != nil {
			return err
		}
		for _, holder := range direct {
			if seen[holder] {
				continue
			}
			seen[holder] = true
			if err := walk(holder, depth+1); err != nil {
				return err
			}
			out = append(out, holder)
		}
		return nil
	}
	if err := walk(name, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// directHolders are the entries of the holders directory of the block device
// name and of each of its partitions.
func (h holderHost) directHolders(name string) ([]string, error) {
	dirs, err := h.deviceDirs(name)
	if err != nil || dirs == nil {
		return nil, err
	}
	var holders []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(filepath.Join(dir, "holders"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("cannot list what holds %s: %w", filepath.Base(dir), err)
		}
		for _, entry := range entries {
			holders = append(holders, entry.Name())
		}
	}
	sort.Strings(holders)
	return holders, nil
}

// deviceDirs is the sysfs directory of the block device name and those of its
// partitions; nil when the device is not there.
func (h holderHost) deviceDirs(name string) ([]string, error) {
	base := filepath.Join(h.sysBlock, name)
	entries, err := os.ReadDir(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot list %s: %w", name, err)
	}
	dirs := []string{base}
	for _, entry := range entries {
		if entry.IsDir() && isPartitionOf(name, entry.Name()) {
			dirs = append(dirs, filepath.Join(base, entry.Name()))
		}
	}
	return dirs, nil
}

// isPartitionOf reports whether child names a partition of the block device
// parent: parent and a number, with a "p" between them when parent itself ends
// in a digit (loop0p1, md126p1, sda1).
func isPartitionOf(parent, child string) bool {
	rest, ok := strings.CutPrefix(child, parent)
	if parent == "" || !ok || rest == "" {
		return false
	}
	if last := parent[len(parent)-1]; last >= '0' && last <= '9' {
		var found bool
		if rest, found = strings.CutPrefix(rest, "p"); !found {
			return false
		}
	}
	if rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ReleaseError is what ReleaseLoopHolders returns when it left holders alone,
// or could not stop one: the loop device, what holds it, and why.
type ReleaseError struct {
	Device  string
	Holders []LoopHolder
	Reason  string
	// Stopped is what was stopped before the failure, in the order it was.
	Stopped []LoopHolder
}

func (e *ReleaseError) Error() string {
	msg := fmt.Sprintf("%s is held by %s (devices the host assembled from its partitions) and cannot be released yet: %s", e.Device, HolderLabels(e.Holders), e.Reason)
	if len(e.Stopped) > 0 {
		msg += fmt.Sprintf(" (already stopped: %s)", HolderLabels(e.Stopped))
	}
	commands := StopCommands(e.Holders)
	rest := ""
	for _, h := range e.Holders {
		if h.Kind() == "" {
			rest = ", and release the others by hand"
		}
	}
	if len(commands) > 0 {
		msg += fmt.Sprintf("; once nothing uses them, stop them (%s%s) and "+recoverhint.Recover, strings.Join(commands, ", then "), rest)
	} else {
		msg += "; release them by hand and " + recoverhint.Recover
	}
	return msg
}

// ReleaseLoopHolders stops the md arrays and removes the device-mapper devices
// that hold the loop device or its partitions, children first, so that the loop
// can be unmapped. It returns what it stopped.
//
// It acts only on a loop device that still backs the file the run recorded
// for it (CheckLoop): one that is gone, or that backs another file, has nothing
// of the run's to release, and is left to the caller's unmap. A holder is
// stopped only when
//   - it is an md array (mdadm --stop, or the array's sysfs attributes when mdadm
//     is not installed) or a device-mapper device (dmsetup remove --retry), and
//     nothing else;
//   - every one of its members, through any layers of md and device-mapper
//     devices below it, is the loop device or a partition of a loop device in
//     owned, which still backs the file recorded for it: the host's own arrays,
//     another operation's, and arrays built from a mix are never touched; and
//   - neither it nor its partitions are mounted.
//
// Every holder is judged before any is touched: when one is refused, nothing is
// stopped, and the error (a *ReleaseError) names the holder and why. A stop that
// fails ends the release there; what was stopped before it is in the error.
// With no holders it does nothing.
func ReleaseLoopHolders(ctx context.Context, device string, owned []LoopIdentity) ([]LoopHolder, error) {
	return hostHolders().release(ctx, device, owned)
}

func (h holderHost) release(ctx context.Context, device string, owned []LoopIdentity) ([]LoopHolder, error) {
	if !validNumberedDevice(device, "/dev/loop") {
		return nil, fmt.Errorf("invalid loop device %q", device)
	}
	own := map[string]LoopIdentity{}
	for _, id := range owned {
		own[id.Device] = id
	}
	target, ok := own[device]
	if !ok {
		return nil, fmt.Errorf("%s is not a loop device the run's journal records, so what holds it is left alone", device)
	}
	state, err := h.checkLoop(device, target.Backing)
	switch {
	case err != nil:
		return nil, fmt.Errorf("cannot establish that %s is still the run's PBS map, so what holds it is left alone: %w", device, err)
	case state != LoopRecorded:
		return nil, nil
	}
	names, err := h.collect(filepath.Base(device))
	if err != nil {
		return nil, fmt.Errorf("cannot list what holds %s: %w", device, err)
	}
	if len(names) == 0 {
		return nil, nil
	}
	holders := make([]LoopHolder, len(names))
	for i, name := range names {
		holders[i] = h.holder(name)
	}
	refuse := func(why string) error {
		return &ReleaseError{Device: device, Holders: holders, Reason: why}
	}

	mounts, err := h.readMounts()
	if err != nil {
		return nil, refuse("the mount table cannot be read, so it is not known whether they are in use: " + err.Error())
	}
	proof := &ownership{host: h, own: own, states: map[string]error{}}
	for _, holder := range holders {
		if why := h.judge(holder, proof, mounts); why != "" {
			return nil, refuse(why)
		}
	}

	var stopped []LoopHolder
	for _, holder := range holders {
		if err := h.stop(ctx, holder); err != nil {
			return stopped, &ReleaseError{Device: device, Holders: holders, Stopped: stopped, Reason: fmt.Sprintf("%s could not be stopped: %v", holder.Label(), err)}
		}
		stopped = append(stopped, holder)
	}
	// A stop returns before the kernel has finished letting go of the members.
	var remaining []string
	for attempt := 1; ; attempt++ {
		if remaining, err = h.collect(filepath.Base(device)); err == nil && len(remaining) == 0 {
			return stopped, nil
		}
		if attempt >= h.settleAttempts {
			break
		}
		h.sleep(h.settleInterval)
	}
	if err != nil {
		return stopped, fmt.Errorf("cannot confirm that what held %s is gone: %w", device, err)
	}
	return stopped, &ReleaseError{Device: device, Holders: holders, Stopped: stopped, Reason: fmt.Sprintf("%s still hold it after they were stopped", strings.Join(remaining, ", "))}
}

// judge is "" when holder may be stopped, else why not.
func (h holderHost) judge(holder LoopHolder, proof *ownership, mounts mountTable) string {
	switch holder.Kind() {
	case "":
		return fmt.Sprintf("%s is neither a software RAID (md) array nor a device-mapper device, and CertiStack stops nothing else", holder.Name)
	case "dm":
		if !validDMName(holder.DMName) {
			return fmt.Sprintf("%s has no usable device-mapper name", holder.Name)
		}
	}
	if err := proof.members(holder.Name, 0); err != nil {
		return err.Error()
	}
	if why := h.mountedWhere(holder, mounts); why != "" {
		return why
	}
	return ""
}

func validDMName(name string) bool {
	if name == "" || name[0] == '-' {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// ownership shows whether a holder's members are the run's loops.
type ownership struct {
	host   holderHost
	own    map[string]LoopIdentity
	states map[string]error // loop device -> nil when it is the run's, else why not
}

// members is nil when every member of the md or device-mapper device name,
// recursively, is the loop device or a partition of a loop device of the run.
func (p *ownership) members(name string, depth int) error {
	if depth > maxHolderDepth {
		return fmt.Errorf("%s is built through more than %d layers of devices", name, maxHolderDepth)
	}
	slaves, err := os.ReadDir(filepath.Join(p.host.sysBlock, name, "slaves"))
	if err != nil {
		return fmt.Errorf("the members of %s cannot be listed, so it is not shown to be the run's: %v", name, err)
	}
	if len(slaves) == 0 {
		return fmt.Errorf("%s lists no members, so it is not shown to be the run's", name)
	}
	for _, slave := range slaves {
		member := slave.Name()
		if m := loopPartExpr.FindStringSubmatch(member); m != nil {
			if err := p.loop("/dev/loop" + m[1]); err != nil {
				return fmt.Errorf("%s has the member %s: %v", name, member, err)
			}
			continue
		}
		layer := member
		if m := mdPartExpr.FindStringSubmatch(member); m != nil {
			layer = m[1]
		}
		if !mdNameExpr.MatchString(layer) && !dmNameExpr.MatchString(layer) {
			return fmt.Errorf("%s has the member %s, which is not a partition of a loop device the run mapped", name, member)
		}
		if err := p.members(layer, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// loop is nil when device is a loop device of the run that still backs the
// file recorded for it.
func (p *ownership) loop(device string) error {
	if err, done := p.states[device]; done {
		return err
	}
	var result error
	id, tracked := p.own[device]
	switch {
	case !tracked:
		result = fmt.Errorf("%s is not a loop device the run mapped", device)
	default:
		state, err := p.host.checkLoop(device, id.Backing)
		switch {
		case err != nil:
			result = fmt.Errorf("it cannot be shown that %s is still the run's PBS map: %v", device, err)
		case state != LoopRecorded:
			result = fmt.Errorf("%s no longer backs the PBS map the run recorded", device)
		}
	}
	p.states[device] = result
	return result
}

// mountTable is what the mount table says is mounted, by device number and by
// source, with the mount point.
type mountTable struct {
	byDev    map[string]string
	bySource map[string]string
}

func (h holderHost) readMounts() (mountTable, error) {
	data, err := os.ReadFile(h.mountInfo)
	if err != nil {
		return mountTable{}, err
	}
	table := mountTable{byDev: map[string]string{}, bySource: map[string]string{}}
	for _, line := range strings.Split(string(data), "\n") {
		// id parent major:minor root mount-point options [optional...] - type source options
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		point := unescapeMountPath(fields[4])
		table.byDev[fields[2]] = point
		for i := 5; i < len(fields)-2; i++ {
			if fields[i] == "-" {
				table.bySource[unescapeMountPath(fields[i+2])] = point
				break
			}
		}
	}
	return table, nil
}

// mountedWhere is "" when neither the holder nor its partitions are mounted,
// else why it is left.
func (h holderHost) mountedWhere(holder LoopHolder, mounts mountTable) string {
	dirs, _ := h.deviceDirs(holder.Name)
	for _, dir := range dirs {
		if data, err := os.ReadFile(filepath.Join(dir, "dev")); err == nil {
			if point, mounted := mounts.byDev[strings.TrimSpace(string(data))]; mounted {
				return fmt.Sprintf("%s is mounted at %s", filepath.Base(dir), point)
			}
		}
	}
	names := []string{"/dev/" + holder.Name}
	if holder.DMName != "" {
		names = append(names, "/dev/mapper/"+holder.DMName)
	}
	for source, point := range mounts.bySource {
		if !strings.HasPrefix(source, "/dev/") {
			continue
		}
		if containsString(names, source) {
			return fmt.Sprintf("%s is mounted at %s", holder.Name, point)
		}
		// A symbolic link to the device (/dev/md/root, /dev/vg/lv).
		if real, err := filepath.EvalSymlinks(source); err == nil && filepath.Base(real) == holder.Name {
			return fmt.Sprintf("%s is mounted at %s", holder.Name, point)
		}
	}
	return ""
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// stop releases one md or device-mapper device.
func (h holderHost) stop(ctx context.Context, holder LoopHolder) error {
	switch holder.Kind() {
	case "md":
		if _, err := h.lookPath("mdadm"); err == nil {
			return h.retry(func() error { return h.run(ctx, "mdadm", "--stop", "/dev/"+holder.Name) })
		}
		// Without mdadm the array is stopped through its own attributes: first
		// "inactive", which stops it and is refused while it is in use, then "clear",
		// which disassembles it (what STOP_ARRAY does) so that its members are free.
		attr := filepath.Join(h.sysBlock, holder.Name, "md", "array_state")
		return h.retry(func() error {
			for _, value := range []string{"inactive", "clear"} {
				if err := h.writeAttr(attr, value); err != nil {
					return fmt.Errorf("mdadm is not installed, and writing %q to the array's array_state failed: %w", value, err)
				}
			}
			return nil
		})
	case "dm":
		return h.run(ctx, "dmsetup", "remove", "--retry", holder.DMName)
	}
	return fmt.Errorf("%s is neither an md array nor a device-mapper device", holder.Name)
}

// retry runs stop until it succeeds, up to stopAttempts times: a stop is
// refused while udev, which probes a new array, has it open for a moment.
func (h holderHost) retry(stop func() error) error {
	var err error
	for attempt := 1; ; attempt++ {
		if err = stop(); err == nil || attempt >= h.stopAttempts {
			return err
		}
		h.sleep(h.stopInterval)
	}
}

// staleBacking reports whether a loop device's backing is what the kernel
// shows once the file it was attached to has no path any more: the root of a
// detached single-file mount, which a PBS map's FUSE file is ("/"), or nothing.
func staleBacking(backing string) bool {
	switch strings.TrimSuffix(strings.TrimSpace(backing), " (deleted)") {
	case "/", "":
		return true
	}
	return false
}

// HeldAfterUnmap is the holders of a loop device that a run's unmap has left
// attached: the device backs no file any more (its FUSE file is gone) and
// something holds it, so it cannot go. It is false for a device that is gone,
// that backs a real file, or that nothing holds, and when that cannot be read.
// This is a diagnostic, not proof of release: mounts and open file descriptors
// do not appear in the block-device holder graph. Use AwaitLoopReleased to
// establish cleanup, even when this returns false.
func HeldAfterUnmap(device string) ([]LoopHolder, bool) {
	return hostHolders().heldAfterUnmap(device)
}

func (h holderHost) heldAfterUnmap(device string) ([]LoopHolder, bool) {
	if !validNumberedDevice(device, "/dev/loop") {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(h.sysBlock, filepath.Base(device), "loop", "backing_file"))
	if err != nil || !staleBacking(string(data)) {
		return nil, false
	}
	holders, err := h.loopHolders(device)
	return holders, err == nil && len(holders) > 0
}

// HoldersNote says, for a loop device that is still attached, what holds it
// and how to let it go; "" when nothing holds it.
func HoldersNote(device string) string {
	holders, err := LoopHolders(device)
	if err != nil || len(holders) == 0 {
		return ""
	}
	return holdersNote(device, holders)
}

func holdersNote(device string, holders []LoopHolder) string {
	steps := StopCommands(holders)
	steps = append(steps, "losetup -d "+device)
	return fmt.Sprintf("; it is held by %s, devices the host assembled from its partitions, so it stays until they are stopped (%s)", HolderLabels(holders), strings.Join(steps, ", then "))
}

// LoopHeldError is the error for a loop device that an unmap left attached,
// held by holders (HeldAfterUnmap).
func LoopHeldError(device string, holders []LoopHolder) error {
	if len(holders) == 0 {
		return fmt.Errorf("PBS loop device %s remains attached after cleanup although the file behind it is gone%s", device, unheldNote(device))
	}
	return fmt.Errorf("PBS loop device %s remains attached after cleanup although the file behind it is gone%s", device, holdersNote(device, holders))
}

// unheldNote says, for a loop device that stays attached with no md or dm
// device holding it, what else can: a mount of it or of a partition of it, or
// a process that has it open. The kernel releases it by itself once they let go.
func unheldNote(device string) string {
	return fmt.Sprintf("; no md or dm device holds it, so a mount or a process that has it open does (lsblk %s shows where it and its partitions are mounted, fuser -v %s which processes have it open); the kernel releases it once they let go", device, device)
}

// attachmentVerdict is what the kernel's disk sequence number says of a loop
// device the run recorded.
type attachmentVerdict int

const (
	// attachmentUnknown: no number was recorded, or the current one or the
	// boot cannot be read; the backing path decides.
	attachmentUnknown attachmentVerdict = iota
	// attachmentSame: the device is still the attachment the run made.
	attachmentSame
	// attachmentOther: the run's attachment is gone (another number, or
	// another boot: no loop attachment survives a reboot).
	attachmentOther
)

func (h holderHost) attachment(loop journal.TrackedLoop) attachmentVerdict {
	if loop.DiskSeq == 0 || strings.TrimSpace(loop.BootID) == "" || h.bootID == nil {
		return attachmentUnknown
	}
	boot, err := h.bootID()
	boot = strings.TrimSpace(boot)
	switch {
	case err != nil || boot == "":
		return attachmentUnknown
	case boot != strings.TrimSpace(loop.BootID):
		return attachmentOther
	}
	seq, err := loopDiskSeq(h.sysBlock, loop.Device)
	switch {
	case err != nil:
		return attachmentUnknown
	case seq == loop.DiskSeq:
		return attachmentSame
	}
	return attachmentOther
}

// reusedLoopReleaseError is the answer for a recorded loop device whose backing
// is not the recorded file any more: nil when the run's attachment is shown
// gone, the error that says what remains otherwise. Nothing is changed.
//
// The attachment's disk sequence number decides when it was recorded: the same
// number in the same boot is the run's attachment, still there whatever its
// backing reads ("/" once the map's FUSE file is gone); another number is
// another attachment, and the run's is gone. Without a number the backing
// path decides: a real other file is another operation's loop, but a stale
// backing ("/", deleted, empty) is never called released, because a mount or
// an open file descriptor can keep the run's attachment there without any md or
// dm device holding it.
func (h holderHost) reusedLoopReleaseError(loop journal.TrackedLoop) error {
	device := loop.Device
	data, err := os.ReadFile(filepath.Join(h.sysBlock, filepath.Base(device), "loop", "backing_file"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot confirm that %s was released: %w", device, err)
	}
	current := strings.TrimSuffix(strings.TrimSpace(string(data)), " (deleted)")
	switch h.attachment(loop) {
	case attachmentOther:
		return nil
	case attachmentSame:
		holders, err := h.loopHolders(device)
		note := unheldNote(device)
		switch {
		case err != nil:
			note = fmt.Sprintf("; what holds it cannot be read: %v", err)
		case len(holders) > 0:
			note = holdersNote(device, holders)
		}
		return fmt.Errorf("PBS loop device %s is still the attachment this run made (disk sequence number %d), although its backing reads %q: the kernel has not released it%s", device, loop.DiskSeq, current, note)
	}
	if !staleBacking(current) {
		if current != strings.TrimSuffix(strings.TrimSpace(loop.Backing), " (deleted)") {
			return nil
		}
		return fmt.Errorf("PBS loop device %s remains mapped after it was unmapped", device)
	}
	holders, err := h.loopHolders(device)
	if err != nil {
		return fmt.Errorf("PBS loop device %s remains attached with stale backing; cannot inspect its holders: %w", device, err)
	}
	return LoopHeldError(device, holders)
}

// LoopRemainsError is the error for a loop device that still backs the PBS
// map the run recorded after the unmap.
func LoopRemainsError(device string) error {
	return fmt.Errorf("PBS loop device %s remains mapped after cleanup%s", device, HoldersNote(device))
}

// AwaitLoopReleased waits for the loop device a run has just unmapped to leave
// the kernel, which can take a moment (something that has it open lets go), up
// to attempts looks, interval apart. loop is what the run recorded of it (see
// journal.TrackedLoop). A loop device that is gone, or that is shown to be
// another attachment now, is released. One that still backs the recorded map,
// that is still the run's attachment by its disk sequence number, or that has
// a stale backing with no number to tell, is not: the error names the loop and
// what holds it. A device whose state cannot be read is not shown released
// either.
func AwaitLoopReleased(loop journal.TrackedLoop, attempts int, interval time.Duration) error {
	return awaitLoopReleased(hostHolders(), loop, attempts, interval)
}

func awaitLoopReleased(h holderHost, loop journal.TrackedLoop, attempts int, interval time.Duration) error {
	device, recorded := loop.Device, loop.Backing
	var lastErr, remains error
	for attempt := 1; ; attempt++ {
		lastErr, remains = nil, nil
		state, err := h.checkLoop(device, recorded)
		switch {
		case err != nil:
			lastErr = fmt.Errorf("cannot confirm that %s was released: %w", device, err)
			// A loop that reads nothing at all (its file is gone) and is held.
			if holders, held := h.heldAfterUnmap(device); held {
				lastErr, remains = nil, LoopHeldError(device, holders)
			}
		case state == LoopGone:
			return nil
		case state == LoopReused:
			remains = h.reusedLoopReleaseError(loop)
			if remains == nil {
				return nil
			}
		default:
			holders, _ := h.loopHolders(device)
			remains = fmt.Errorf("PBS loop device %s remains mapped after it was unmapped", device)
			if len(holders) > 0 {
				remains = fmt.Errorf("PBS loop device %s remains mapped after it was unmapped%s", device, holdersNote(device, holders))
			}
		}
		if attempt >= attempts {
			break
		}
		h.sleep(interval)
	}
	if lastErr != nil {
		return lastErr
	}
	return remains
}

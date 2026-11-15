// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/recoverhint"
)

// pbsMapRunDir is where proxmox-backup-client map keeps each map's FUSE
// file and the pid file of the daemon serving it.
const pbsMapRunDir = "/run/pbs-loopdev"

// mapLeakWindow bounds when a map begun at an intent's time can have been
// created: the client's own two-minute map timeout plus slack. The window
// starts a second before the intent, for file time granularity.
const mapLeakWindow = 3 * time.Minute

// LeakedMap is a loop device a map left that no journal tracks.
type LeakedMap struct {
	Device  string
	Backing string
}

// leakFinder finds maps an intent left behind. Its roots are variables so
// tests can use a fake sysfs, run directory and mount table.
type leakFinder struct {
	sysBlock  string // /sys/block
	runDir    string // /run/pbs-loopdev
	mountInfo string // /proc/self/mountinfo
	fuseConns string // /sys/fs/fuse/connections
}

var hostLeakFinder = leakFinder{sysBlock: "/sys/block", runDir: pbsMapRunDir, mountInfo: "/proc/self/mountinfo", fuseConns: "/sys/fs/fuse/connections"}

// IsPBSMapBacking is whether backing, a loop's backing file as the journal
// recorded it, is the FUSE file of a proxmox-backup-client map: a file directly
// in the map run directory. A run journals a loop only right after its PBS map
// attached it, so a loop on any other file is not one a run made.
func IsPBSMapBacking(backing string) bool {
	backing = strings.TrimSuffix(strings.TrimSpace(backing), " (deleted)")
	return filepath.IsAbs(backing) && filepath.Clean(backing) == backing && filepath.Dir(backing) == hostLeakFinder.runDir
}

// verdict is what recovery makes of a map process.
type verdict int

const (
	verdictOurs     verdict = iota // the interrupted run's own map
	verdictOther                   // provably another operation's
	verdictUnproven                // cannot be told from the run's: left, and reported
)

// mapEvidence is what recovery knows about an intent's map processes when
// it looks at the map's loop devices and files. A leftover is the map's
// only when this proves it.
type mapEvidence struct {
	// ours are the processes recovery proved to be the map's own, in this
	// attempt or an earlier one (MapIntent.Processes), by PID.
	ours map[int]journal.Process
	// gone reports whether one of ours no longer runs.
	gone func(journal.Process) bool
	// daemonAlive reports whether a PID may run a live proxmox-backup-client
	// (one that cannot be read may).
	daemonAlive func(pid int) bool
	// judge says what the live proxmox-backup-client under a PID is to the
	// map: verdictOther when it provably is another operation's map, else
	// unproven, with why. Nil judges nothing another operation's.
	judge func(pid int) (verdict, string)
	// running is set while any map of the snapshot and archive may run, or
	// when that is not known.
	running bool
}

// mapClaim is what recovery makes of one leftover of an intent's map.
type mapClaim int

const (
	claimOthers   mapClaim = iota // provably another operation's: left alone
	claimOurs                     // the intent's map: recovery releases it
	claimUnproven                 // left, and reported: nothing proves whose it is
	claimPidless                  // no pid file: settled with the intent's other such leftovers
	// claimDeadUnknown: its pid file names a process that is gone and that
	// recovery never identified, written in the intent's window: settled with
	// the intent's other leftovers (settleDeadUnknown).
	claimDeadUnknown
	// claimRunning: the intent's map is its own process, which still runs (its
	// failed stop is reported): left alone, and the one map the intent made.
	claimRunning
)

// claim judges the map named base in the run directory, a name ending with
// the intent's suffix, by its pid file. What is not provably another
// operation's is claimed or reported, never dropped:
//   - one written before the intent existed cannot be its map's;
//   - one naming a process of the map's own is judged by that process,
//     however late the file was written: it is the map's once that process is
//     gone, and left while it runs (its failed stop is reported). A PID that
//     a live proxmox-backup-client holds now is not the process the run
//     journaled, and proves nothing;
//   - one naming a live proxmox-backup-client is judged by it: left when it
//     provably is another operation's map (another repository or namespace,
//     another map's token, not the form CertiStack runs), reported otherwise;
//   - one naming a process recovery never identified, now gone, and written
//     within the intent's window (a map killed with the worker, before recovery
//     could see its process) is the map's only if settleDeadUnknown finds it
//     the intent's one candidate (claimDeadUnknown); written after the window it
//     proves nothing, and the map is reported;
//   - any other pid file (one naming no process, or one that is not a regular
//     file) proves nothing, and the map is reported.
//
// It reads only the pid file, never the map file.
func (f leakFinder) claim(intent journal.MapIntent, base string, ev mapEvidence) (mapClaim, string) {
	pidFile := filepath.Join(f.runDir, strings.TrimSuffix(base, filepath.Ext(base))+".pid")
	info, err := os.Lstat(pidFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return claimPidless, ""
	case err != nil:
		return claimUnproven, "its pid file cannot be read: " + pathless(err)
	case !info.Mode().IsRegular():
		return claimUnproven, "its pid file is not a regular file"
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return claimUnproven, "its pid file cannot be read: " + pathless(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return claimUnproven, "its pid file names no process"
	}
	if info.ModTime().Before(intent.At.Add(-time.Second)) {
		return claimOthers, "" // written before the intent existed: not its daemon's
	}
	if own, ok := ev.ours[pid]; ok {
		switch {
		case !ev.gone(own):
			return claimRunning, ""
		case ev.daemonAlive(pid):
			return claimUnproven, fmt.Sprintf("its pid file names PID %d, which the run's map process had and a live proxmox-backup-client has now", pid)
		}
		return claimOurs, ""
	}
	if ev.daemonAlive(pid) {
		if ev.judge != nil {
			v, why := ev.judge(pid)
			if v == verdictOther {
				return claimOthers, ""
			}
			return claimUnproven, why
		}
		return claimUnproven, fmt.Sprintf("its pid file names the live proxmox-backup-client %d, and nothing shows whose map it is", pid)
	}
	why := fmt.Sprintf("its map process %d is gone, and recovery never identified it as the run's", pid)
	if info.ModTime().After(intent.At.Add(mapLeakWindow)) {
		return claimUnproven, why // written long after the map began: not shown to be its daemon's
	}
	return claimDeadUnknown, why
}

// census counts an intent's leftovers, for the one case that depends on how
// many there are (settleDeadUnknown). A map is begun once and leaves one map
// file, so a leftover is the run's only if it is the only one that is not
// provably another operation's.
type census struct {
	// deadUnknown counts the leftovers claim finds claimDeadUnknown.
	deadUnknown int
	// other counts the leftovers that are neither that nor provably another
	// operation's: claimed, still running, reported or pid-less.
	other int
	// err is set when the leftovers could not all be found, so that these
	// counts may be short.
	err error
}

// census looks at every leftover of the intent a loop device or a map file
// stands for, by the map file's name: a loop device (tracked or not) whose
// backing file is in the run directory and ends with the intent's suffix, and
// each such file no loop uses (orphans looks for those). A map file and the
// loop that uses it are one leftover, and so is a map file whose loop was
// released since; two loop devices on one map file are two. It reads only the
// pid files.
func (f leakFinder) census(intent journal.MapIntent, ev mapEvidence) census {
	var c census
	var errs []error
	units := map[string]int{} // map file name -> leftovers
	backings, _ := filepath.Glob(filepath.Join(f.sysBlock, "loop*", "loop", "backing_file"))
	for _, backingFile := range backings {
		data, err := os.ReadFile(backingFile)
		if errors.Is(err, fs.ErrNotExist) {
			continue // detached since it was listed
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot read what a loop device is attached to: %s", pathless(err)))
			continue
		}
		backing := strings.TrimSuffix(strings.TrimRight(string(data), "\n"), " (deleted)")
		if filepath.Dir(backing) == f.runDir && strings.HasSuffix(filepath.Base(backing), intent.NameSuffix) {
			units[filepath.Base(backing)]++
		}
	}
	files, fileErrs := f.candidateFiles(intent)
	errs = append(errs, fileErrs...)
	for backing := range files {
		if name := filepath.Base(backing); units[name] == 0 {
			units[name] = 1
		}
	}
	for name, n := range units {
		switch kind, _ := f.claim(intent, name, ev); kind {
		case claimOthers:
		case claimDeadUnknown:
			c.deadUnknown += n
		default:
			c.other += n
		}
	}
	c.err = errors.Join(errs...)
	return c
}

// settleDeadUnknown decides the leftovers of an intent whose pid file names a
// process that is gone and that recovery never identified, written in the
// intent's window: the map a killed worker had begun, whose daemon died with
// the worker before recovery could see its process. They are the map's only
// when
//   - no map of the snapshot and archive runs, or may run: such a map could be
//     making them, or be the run's own daemon, which recovery would have
//     identified by its token;
//   - the journal records the owner and token the map was begun with: only then
//     would recovery have identified the daemon, had it lived, so that a dead
//     one is the one that is left;
//   - the census is complete, and finds exactly one such leftover and no other
//     that is not provably another operation's: a map leaves one file, and a
//     name carries the repository only as a prefix that recovery cannot
//     compute, so a second candidate is as likely the run's as the first.
//
// Otherwise nothing shows whose they are, and they are reported. The text says
// why, to follow the leftover's own.
func settleDeadUnknown(intent journal.MapIntent, c census, ev mapEvidence) (mapClaim, string) {
	switch {
	case ev.running:
		return claimUnproven, "a map of the same snapshot and archive runs, or recovery could not tell"
	case intent.Owner == "" || intent.Token == "":
		return claimUnproven, "the journal does not record the owner and token the map was begun with, so recovery could not have identified its process"
	case c.err != nil:
		return claimUnproven, "recovery could not list every leftover of the same snapshot and archive, so it cannot show this is the only one"
	case c.deadUnknown > 1:
		return claimUnproven, fmt.Sprintf("%d leftovers of the same snapshot and archive are in that state, and nothing shows which is the run's", c.deadUnknown)
	case c.other > 0:
		return claimUnproven, "another leftover of the same snapshot and archive is not provably another operation's, and an interrupted map leaves one"
	}
	return claimOurs, ""
}

// deadUnknownSettler returns a function that settles the intent's leftovers
// with a dead, unidentified pid, once: the census is taken the first time it
// is called, and its answer is the same for all of them.
func (f leakFinder) deadUnknownSettler(intent journal.MapIntent, ev mapEvidence) func() (mapClaim, string) {
	var settled bool
	var kind mapClaim
	var refusal string
	return func() (mapClaim, string) {
		if !settled {
			kind, refusal = settleDeadUnknown(intent, f.census(intent, ev), ev)
			settled = true
		}
		return kind, refusal
	}
}

// deadUnknownWhy is the text for a leftover settleDeadUnknown refused: its
// own reason (claim's), then why it was not claimed.
func deadUnknownWhy(why, refusal string) string {
	return why + "; it is not claimed because " + refusal
}

// settlePidless decides the leftovers of an intent that have no pid file:
// a daemon stopped around when it attaches its loop can leave its loop, or
// its FUSE mount, without one. They are the map's only
// when no map of the snapshot and archive runs, recovery stopped one of
// the map's own processes (in this attempt or an earlier one), none of
// those wrote a pid file that is still there (then its leftovers are known
// by it, and these are not), and there is exactly one. Otherwise nothing
// shows whose they are, and they are reported: also while another map of the
// snapshot and archive runs, which may be making them, or may be the
// run's own daemon's leftover.
func settlePidless(count int, ev mapEvidence, oursWrotePidFile bool) (mapClaim, string) {
	mayBeOurs := len(ev.ours) > 0 && !oursWrotePidFile
	switch {
	case ev.running:
		return claimUnproven, "it has no pid file, and a map of the same snapshot and archive still runs"
	case len(ev.ours) == 0:
		return claimUnproven, "it has no pid file, and recovery found no process of the run's map"
	case !mayBeOurs:
		return claimUnproven, "it has no pid file, and the run's map process left its own"
	case count > 1:
		return claimUnproven, fmt.Sprintf("it has no pid file, and neither do %d others of the same snapshot and archive", count-1)
	}
	return claimOurs, ""
}

// oursWrotePidFile reports whether a pid file of the intent's map names one
// of the map's own processes. An error means that is not known.
func (f leakFinder) oursWrotePidFile(intent journal.MapIntent, ev mapEvidence) (bool, error) {
	entries, err := os.ReadDir(f.runDir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("cannot list %s to find the pid files of the PBS map of %s %s: %s", f.runDir, intent.Snapshot, intent.Archive, pathless(err))
	}
	pidTail := strings.TrimSuffix(intent.NameSuffix, ".img") + ".pid"
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), pidTail) || !entry.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(f.runDir, entry.Name()))
		if errors.Is(err, fs.ErrNotExist) {
			continue // removed since it was listed
		}
		if err != nil {
			// Whether the run's own process wrote this file is not known.
			return true, fmt.Errorf("cannot read a pid file of the PBS map of %s %s (%s), so it cannot be shown that the run's own process did not write it", intent.Snapshot, intent.Archive, pathless(err))
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			if _, ok := ev.ours[pid]; ok {
				return true, nil
			}
		}
	}
	return false, nil
}

// abortMapConnection aborts the FUSE connection that serves a PBS map's
// file, found through the mount table, and reports whether there was one.
// A map daemon killed while one of its threads waits on its own file (the
// loop's partition scan reads the loop, which reads the FUSE file) never
// exits, so its connection is never closed. Every open of the loop then
// hangs in the kernel: losetup -d, udev, and PVE's vgs, which freezes the
// node's status. Aborting fails those reads, and the daemon's
// threads exit. Call it only for a map recovery owns and is removing.
func (f leakFinder) abortMapConnection(backing string) (bool, error) {
	if filepath.Dir(backing) != f.runDir {
		return false, nil
	}
	device, err := f.mountDevice(backing)
	if err != nil {
		return false, err
	}
	major, minor, ok := strings.Cut(device, ":")
	if !ok || major != "0" {
		return false, nil
	}
	if _, err := strconv.ParseUint(minor, 10, 32); err != nil {
		return false, nil
	}
	file, err := os.OpenFile(filepath.Join(f.fuseConns, minor, "abort"), os.O_WRONLY, 0)
	if os.IsNotExist(err) {
		return false, nil // not FUSE, or the connection is already gone
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	if _, err := file.WriteString("1"); err != nil {
		return false, err
	}
	return true, nil
}

// mountDevice is the major:minor of the mount at path, or "".
func (f leakFinder) mountDevice(path string) (string, error) {
	mounts, err := f.mounts()
	for _, m := range mounts {
		if m.point == path {
			return m.device, nil
		}
	}
	return "", err
}

// find returns the loop devices a map for intent created that tracked does
// not name and that are provably the map's (claim, settlePidless,
// settleDeadUnknown), and reports each that looks like the map's but is not
// proved to be. A device is looked at only when its sysfs backing file is in
// the map run directory and its name ends with the intent's escaped snapshot
// and archive, compared byte for byte and never unescaped.
//
// It never opens the backing file itself: opening a map's FUSE file drops
// its page cache.
func (f leakFinder) find(intent journal.MapIntent, tracked map[string]bool, ev mapEvidence) ([]LeakedMap, []error) {
	if intent.NameSuffix == "" {
		return nil, nil
	}
	backings, _ := filepath.Glob(filepath.Join(f.sysBlock, "loop*", "loop", "backing_file"))
	var leaked, pidless []LeakedMap
	var errs []error
	settleDead := f.deadUnknownSettler(intent, ev)
	for _, backingFile := range backings {
		data, err := os.ReadFile(backingFile)
		if errors.Is(err, fs.ErrNotExist) {
			continue // detached since it was listed
		}
		if err != nil {
			// An unreadable loop may be the map's: it is neither claimed nor
			// passed over in silence, and a recovery that finds nothing else
			// does not end clean.
			errs = append(errs, fmt.Errorf("cannot read what loop device /dev/%s is attached to (%s), so it cannot be shown not to be the interrupted run's PBS map of %s %s; recovery left it; "+recoverhint.Again, filepath.Base(filepath.Dir(filepath.Dir(backingFile))), pathless(err), intent.Snapshot, intent.Archive))
			continue
		}
		backing := strings.TrimSuffix(strings.TrimRight(string(data), "\n"), " (deleted)")
		if filepath.Dir(backing) != f.runDir || !strings.HasSuffix(filepath.Base(backing), intent.NameSuffix) {
			continue
		}
		device := "/dev/" + filepath.Base(filepath.Dir(filepath.Dir(backingFile)))
		if tracked[device] {
			continue
		}
		leak := LeakedMap{Device: device, Backing: backing}
		switch claim, why := f.claim(intent, filepath.Base(backing), ev); claim {
		case claimOurs:
			leaked = append(leaked, leak)
		case claimPidless:
			pidless = append(pidless, leak)
		case claimDeadUnknown:
			if kind, refusal := settleDead(); kind == claimOurs {
				leaked = append(leaked, leak)
			} else {
				errs = append(errs, unprovenLoop(intent, device, deadUnknownWhy(why, refusal)))
			}
		case claimUnproven:
			errs = append(errs, unprovenLoop(intent, device, why))
		}
	}
	if len(pidless) > 0 {
		wrote, err := f.oursWrotePidFile(intent, ev)
		if err != nil {
			errs = append(errs, err)
		}
		switch claim, why := settlePidless(len(pidless), ev, wrote); claim {
		case claimOurs:
			leaked = append(leaked, pidless...)
		case claimUnproven:
			for _, leak := range pidless {
				errs = append(errs, unprovenLoop(intent, leak.Device, why))
			}
		}
	}
	sort.Slice(leaked, func(i, j int) bool { return leaked[i].Device < leaked[j].Device })
	return leaked, errs
}

// unprovenLoop reports a loop device that looks like intent's map but is
// not proved to be.
func unprovenLoop(intent journal.MapIntent, device, why string) error {
	return fmt.Errorf("%s looks like the interrupted run's PBS map of %s %s, but nothing proves it is (%s); recovery left it. If nothing uses it, release it (proxmox-backup-client unmap %s) and "+recoverhint.Again, device, intent.Snapshot, intent.Archive, why, device)
}

// orphans returns the map files of intent that no loop device uses any
// more and that are provably the map's (claim, settlePidless,
// settleDeadUnknown), sorted, and reports each that looks like the map's but
// is not proved to be. A daemon killed before or after it created its loop
// leaves its FUSE mount and map file behind, and the client's own cleanup of
// unused map files fails on the stale mount.
//
// A map file is found by its name (the intent's escaped snapshot and
// archive, byte for byte) in the run directory, in the mount table, or
// through its pid file.
//
// It never stats or opens a map file: a dead FUSE mount answers ENOTCONN,
// and opening a live map's file drops its page cache.
func (f leakFinder) orphans(intent journal.MapIntent, ev mapEvidence) ([]string, []error) {
	if intent.NameSuffix == "" {
		return nil, nil
	}
	attached := map[string]bool{}
	var attachErrs []error
	backings, _ := filepath.Glob(filepath.Join(f.sysBlock, "loop*", "loop", "backing_file"))
	for _, backingFile := range backings {
		data, err := os.ReadFile(backingFile)
		if errors.Is(err, fs.ErrNotExist) {
			continue // detached since it was listed
		}
		if err != nil {
			attachErrs = append(attachErrs, fmt.Errorf("cannot read what loop device /dev/%s is attached to (%s)", filepath.Base(filepath.Dir(filepath.Dir(backingFile))), pathless(err)))
			continue
		}
		attached[strings.TrimSuffix(strings.TrimRight(string(data), "\n"), " (deleted)")] = true
	}
	candidates, errs := f.candidateFiles(intent)
	if len(attachErrs) > 0 {
		// A map file looks unused only when every loop device was read. With one
		// unreadable, this map's file may well be the one it serves, so no file is
		// removed.
		return nil, append(errs, fmt.Errorf("the map files of %s %s were left in place: %w", intent.Snapshot, intent.Archive, errors.Join(attachErrs...)))
	}
	var orphans, pidless []string
	settleDead := f.deadUnknownSettler(intent, ev)
	for backing := range candidates {
		if attached[backing] {
			continue
		}
		switch claim, why := f.claim(intent, filepath.Base(backing), ev); claim {
		case claimOurs:
			orphans = append(orphans, backing)
		case claimPidless:
			pidless = append(pidless, backing)
		case claimDeadUnknown:
			if kind, refusal := settleDead(); kind == claimOurs {
				orphans = append(orphans, backing)
			} else {
				errs = append(errs, f.unprovenFiles(intent, deadUnknownWhy(why, refusal)))
			}
		case claimUnproven:
			errs = append(errs, f.unprovenFiles(intent, why))
		}
	}
	if len(pidless) > 0 {
		wrote, err := f.oursWrotePidFile(intent, ev)
		if err != nil {
			errs = append(errs, err)
		}
		switch claim, why := settlePidless(len(pidless), ev, wrote); claim {
		case claimOurs:
			orphans = append(orphans, pidless...)
		case claimUnproven:
			errs = append(errs, f.unprovenFiles(intent, why))
		}
	}
	sort.Strings(orphans)
	return orphans, errs
}

// candidateFiles are the map files that may be intent's: those named in the
// run directory (by the file, or by its pid file) and in the mount table, with
// an error for each place that could not be read.
func (f leakFinder) candidateFiles(intent journal.MapIntent) (map[string]bool, []error) {
	var errs []error
	pidTail := strings.TrimSuffix(intent.NameSuffix, ".img") + ".pid"
	candidates := map[string]bool{}
	entries, err := os.ReadDir(f.runDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("cannot list %s to find the leftover files of the PBS map of %s %s: %s", f.runDir, intent.Snapshot, intent.Archive, pathless(err)))
	}
	for _, entry := range entries {
		switch name := entry.Name(); {
		case strings.HasSuffix(name, pidTail):
			candidates[filepath.Join(f.runDir, strings.TrimSuffix(name, ".pid")+".img")] = true
		case strings.HasSuffix(name, intent.NameSuffix):
			candidates[filepath.Join(f.runDir, name)] = true
		}
	}
	mounts, err := f.mountsIn(f.runDir)
	if err != nil {
		errs = append(errs, fmt.Errorf("cannot read the mount table to find the leftover FUSE mounts of the PBS map of %s %s: %v", intent.Snapshot, intent.Archive, err))
	}
	for _, mount := range mounts {
		if strings.HasSuffix(filepath.Base(mount), intent.NameSuffix) {
			candidates[mount] = true
		}
	}
	return candidates, errs
}

// unprovenFiles reports a leftover map file that looks like intent's map
// but is not proved to be.
func (f leakFinder) unprovenFiles(intent journal.MapIntent, why string) error {
	return fmt.Errorf("a leftover PBS map file %s looks like the interrupted run's map of %s %s, but nothing proves it is (%s); recovery left it. If nothing uses it, detach it (umount -l), remove it and its .pid file, and "+recoverhint.Again, f.mapLabel(intent), intent.Snapshot, intent.Archive, why)
}

// mapLabel names intent's map files for an operator without the
// repository their names start with, whose user part can name an API
// token: the run directory and the name's end.
func (f leakFinder) mapLabel(intent journal.MapIntent) string {
	return f.runDir + "/*" + intent.NameSuffix
}

// pathless is err without the path an os error carries: a path in the map
// run directory starts with the escaped repository.
func pathless(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}

// mountEntry is one mount in the mount table.
type mountEntry struct {
	point  string // mount point, unescaped
	device string // major:minor
}

// mounts reads the mount table.
func (f leakFinder) mounts() ([]mountEntry, error) {
	file, err := os.Open(f.mountInfo)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var mounts []mountEntry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		// ID parent major:minor root mount-point options ... - type source
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		mounts = append(mounts, mountEntry{point: unescapeMountField(fields[4]), device: fields[2]})
	}
	return mounts, scanner.Err()
}

// mountsIn is the mount points directly in dir, from the mount table.
func (f leakFinder) mountsIn(dir string) ([]string, error) {
	all, err := f.mounts()
	var mounts []string
	for _, m := range all {
		if filepath.Dir(m.point) == dir {
			mounts = append(mounts, m.point)
		}
	}
	return mounts, err
}

// mounted reports whether path is a mount point in the mount table.
func (f leakFinder) mounted(path string) (bool, error) {
	mounts, err := f.mountsIn(filepath.Dir(path))
	for _, mount := range mounts {
		if mount == path {
			return true, nil
		}
	}
	return false, err
}

// unescapeMountField undoes the kernel's octal escapes in a mount table
// field (\040 space, \011 tab, \012 newline, \134 backslash). A map's name
// has literal backslashes from systemd's escaping, which the table shows as
// \134.
func unescapeMountField(field string) string {
	if !strings.Contains(field, `\`) {
		return field
	}
	var b strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+3 < len(field) {
			if n, err := strconv.ParseUint(field[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(field[i])
	}
	return b.String()
}

// trackedLoops is every loop device r records.
func trackedLoops(r journal.Record) map[string]bool {
	tracked := map[string]bool{}
	for _, loop := range r.Loops {
		tracked[loop.Device] = true
	}
	if r.LoopDevice != "" {
		tracked[r.LoopDevice] = true
	}
	return tracked
}

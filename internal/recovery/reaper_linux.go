//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"golang.org/x/sys/unix"
)

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat start times; it is
// 100 on every Linux architecture PVE runs on.
const clockTicks = 100

// mapStopGrace is how long a map process has to exit on SIGINT before it
// is killed.
const mapStopGrace = 20 * time.Second

// mapReapWait is how long a killed map process has to be gone before the
// map's files are looked at. A process that has just been sent SIGKILL can
// still be exiting and look alive for a moment.
const mapReapWait = 5 * time.Second

// mapReaper ends the proxmox-backup-client processes a map under an intent
// still runs. The client the worker starts dies with it (Pdeathsig), but it
// forks a detached daemon. The daemon fetches the index, and only then creates
// the map file, its pid file and the loop device, possibly after recovery
// has already looked for them. It signals only processes it can
// prove are the intent's own (identify). Its fields are replaceable for
// tests.
type mapReaper struct {
	procRoot string
	bootTime func() (time.Time, error)
	// signal sends a signal to a process only while its PID still names
	// that process.
	signal   func(p journal.Process, sig syscall.Signal) error
	sleep    func(time.Duration)
	grace    time.Duration
	reapWait time.Duration
	// readTimeout is how long a read of a process's command line or
	// environment may take (procReadTimeout); zero waits for ever.
	readTimeout time.Duration
	// pidfdOpen opens a pidfd for a PID (unix.PidfdOpen); tests replace it.
	pidfdOpen func(pid, flags int) (int, error)
	// daemonWait is how long stopMapDaemon waits for the daemon it signaled to
	// exit; zero is mapCommandWatchdog.
	daemonWait time.Duration
}

var hostMapReaper = mapReaper{
	procRoot:    "/proc",
	bootTime:    hostBootTime,
	signal:      signalRecorded,
	sleep:       time.Sleep,
	grace:       mapStopGrace,
	reapWait:    mapReapWait,
	readTimeout: procReadTimeout,
}

// procReadTimeout is how long recovery waits for a process's command line or
// environment. Reading them takes the process's memory lock, which a
// process wedged in the kernel (a map daemon whose thread waits on its own
// FUSE file) can hold for ever: such a read is an error, like any
// other that cannot be answered, not a hang.
const procReadTimeout = 10 * time.Second

// readProc reads a /proc file of a process that needs the process's memory
// lock (cmdline, environ), giving up after r.readTimeout.
func (r mapReaper) readProc(path string) ([]byte, error) {
	if r.readTimeout <= 0 {
		return os.ReadFile(path)
	}
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := os.ReadFile(path)
		done <- result{data, err}
	}()
	select {
	case res := <-done:
		return res.data, res.err
	case <-time.After(r.readTimeout):
		return nil, fmt.Errorf("no answer within %s: %w", r.readTimeout, syscall.ETIMEDOUT)
	}
}

// procEntry is a running process: its identity, start time and argv.
type procEntry struct {
	identity journal.Process
	started  time.Time
	argv     []string
}

// processes returns the running processes whose argv match accepts. A
// process that exits while it is read is left out. Any other failure to
// read /proc is an error: then nobody can say that no map process runs.
func (r mapReaper) processes(match func(argv []string) bool) ([]procEntry, error) {
	boot, err := r.bootTime()
	if err != nil {
		return nil, fmt.Errorf("cannot read the host's boot time, which dates PBS map processes: %w", err)
	}
	entries, err := os.ReadDir(r.procRoot)
	if err != nil {
		return nil, fmt.Errorf("cannot list the host's processes to find PBS map processes: %w", err)
	}
	var found []procEntry
	var errs []error
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		cmdline, err := r.readProc(filepath.Join(r.procRoot, entry.Name(), "cmdline"))
		if gone(err) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot read the command line of process %d: %w", pid, err))
			continue
		}
		argv := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if !match(argv) {
			continue
		}
		stat, err := os.ReadFile(filepath.Join(r.procRoot, entry.Name(), "stat"))
		if gone(err) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot read the state of PBS map process %d: %w", pid, err))
			continue
		}
		identity, err := process.ParseIdentity(pid, string(stat))
		if err != nil {
			errs = append(errs, fmt.Errorf("cannot read the state of PBS map process %d: %w", pid, err))
			continue
		}
		ticks, _ := strconv.ParseInt(identity.StartTicks, 10, 64)
		started := boot.Add(time.Duration(ticks) * (time.Second / clockTicks))
		found = append(found, procEntry{identity: identity, started: started, argv: argv})
	}
	return found, errors.Join(errs...)
}

// mapCandidate is a process whose command line is a CertiStack map of an
// intent's snapshot and archive, with what it maps from (pbs.MapOwner), the
// token it carries (pbs.MapTokenEnv) and whether it started in the intent's
// window.
type mapCandidate struct {
	proc     journal.Process
	owner    string
	token    string
	envErr   error // the environment, which says both, cannot be read
	inWindow bool
}

// inWindow reports whether a process that started at started can be the
// intent's map by when it started.
func inWindow(started time.Time, intent journal.MapIntent) bool {
	return !started.Before(intent.At.Add(-2*time.Second)) && !started.After(intent.At.Add(mapLeakWindow))
}

// describe reads what a proxmox-backup-client map process in exactly the form
// a run starts it maps from and carries. ok is false when the process is gone
// by the time it is read.
func (r mapReaper) describe(p procEntry, intent journal.MapIntent) (c mapCandidate, ok bool) {
	c = mapCandidate{proc: p.identity, inWindow: inWindow(p.started, intent)}
	m, _ := pbs.ParseMapCommand(p.argv)
	env, envErr := r.mapEnv(filepath.Join(r.procRoot, strconv.Itoa(p.identity.PID), "environ"))
	// What was read is this process's only if it still runs as itself.
	if gone(envErr) || !r.alive(p.identity) {
		return c, false
	}
	if c.envErr = envErr; envErr == nil {
		c.owner, c.token = m.Owner(env), env[pbs.MapTokenEnv]
	}
	return c, true
}

// candidates are the processes that may be intent's map: a
// proxmox-backup-client map in exactly the form a run starts it
// (pbs.ParseMapCommand) of the intent's snapshot and archive, whenever it
// started: the window is a heuristic for a process without the run's token,
// never a condition on one that carries it.
func (r mapReaper) candidates(intent journal.MapIntent) ([]mapCandidate, error) {
	if intent.Snapshot == "" || intent.Archive == "" {
		return nil, nil
	}
	procs, err := r.processes(func(argv []string) bool {
		m, ok := pbs.ParseMapCommand(argv)
		return ok && m.Snapshot == intent.Snapshot && m.Archive == intent.Archive
	})
	var found []mapCandidate
	for _, p := range procs {
		if c, ok := r.describe(p, intent); ok {
			found = append(found, c)
		}
	}
	return found, err
}

// reason says why judge reached its verdict.
type reason int

const (
	reasonToken         reason = iota // it carries the intent's token, from the intent's source
	reasonEnvironment                 // its environment cannot be read
	reasonTokenSource                 // it carries the intent's token from another source
	reasonOtherToken                  // it carries another map's token
	reasonOtherSource                 // it maps from another repository or namespace, without a token
	reasonOutsideWindow               // it has no token and started outside the intent's window
	reasonNoToken                     // it may be the map's by when it started and where it reads from, and has no token
)

// judge decides what a map process in CertiStack's command form is to the
// intent.
//   - The intent's token, from the intent's repository and namespace, proves
//     it the run's own: only the run's map and the daemon forked from it have
//     it. Nothing else is looked at: not even when it started.
//   - Another map's token, or another repository or namespace, proves it
//     another operation's.
//   - Without a token nothing proves it either way. One that started outside
//     the window cannot be the run's map, and one that did not is reported; so
//     is one whose environment cannot be read.
//
// A journal from before tokens has nothing to tell a run's map by:
// its candidates are the ones that started in the window, all unproven.
func judge(intent journal.MapIntent, c mapCandidate) (verdict, reason) {
	sameSource := intent.Owner == "" || c.owner == intent.Owner
	switch {
	case c.envErr != nil:
		return verdictUnproven, reasonEnvironment
	case intent.Token != "" && c.token == intent.Token && sameSource:
		return verdictOurs, reasonToken
	case intent.Token != "" && c.token == intent.Token:
		return verdictUnproven, reasonTokenSource
	case intent.Token != "" && c.token != "":
		return verdictOther, reasonOtherToken // every map has its own token, and its daemon has no other
	case intent.Token != "" && !sameSource:
		return verdictOther, reasonOtherSource
	case !c.inWindow:
		return verdictOther, reasonOutsideWindow
	}
	return verdictUnproven, reasonNoToken
}

// identify returns the processes that are provably intent's map, and says
// why each other candidate is left running.
//
// A process is the map's own when
//   - an earlier attempt journaled it (intent.Processes) and it still runs as
//     itself: with its start time (a PID and a start time name a process within
//     one boot, which the journal records), and as a map of the intent's
//     snapshot and archive; or
//   - it is a candidate that judge finds the run's: it carries the intent's
//     token and maps from the intent's repository and namespace.
//
// The others are left running; those that judge cannot tell from the run's
// map are reported. A journal from before tokens has nothing to tell a
// run's map by, and the snapshot and archive are what every operation that
// maps them has: none of its candidates is signaled, and they are reported.
func (r mapReaper) identify(intent journal.MapIntent) ([]journal.Process, []error) {
	var ours []journal.Process
	var errs []error
	known := map[int]bool{}
	for _, p := range intent.Processes {
		running, err := r.stillRuns(p, intent)
		if err != nil {
			errs = append(errs, err)
		}
		if running {
			ours = append(ours, p)
			known[p.PID] = true
		}
	}
	candidates, err := r.candidates(intent)
	if err != nil {
		errs = append(errs, err)
	}
	var legacy []string // candidates of an intent without a token that started in its window
	for _, c := range candidates {
		if known[c.proc.PID] {
			continue
		}
		pid := c.proc.PID
		v, why := judge(intent, c)
		switch {
		case v == verdictOurs:
			ours = append(ours, c.proc)
		case v == verdictOther && why == reasonOtherToken:
			slog.Info("leaving a PBS map process of the same snapshot and archive that another map started", "pid", pid, "snapshot", intent.Snapshot, "archive", intent.Archive)
			say("INFO", "Left PBS map process %d of %s %s alone: another map started it, not the interrupted run.", pid, intent.Snapshot, intent.Archive)
		case v == verdictOther && why == reasonOtherSource:
			slog.Info("leaving a PBS map process of the same snapshot and archive that maps from another repository or namespace", "pid", pid, "snapshot", intent.Snapshot, "archive", intent.Archive)
			say("INFO", "Left PBS map process %d of %s %s alone: it maps from another repository or namespace than the interrupted run.", pid, intent.Snapshot, intent.Archive)
		case v == verdictOther:
			slog.Info("leaving a PBS map process of the same snapshot and archive that started outside the interrupted run's window", "pid", pid, "snapshot", intent.Snapshot, "archive", intent.Archive)
		case why == reasonEnvironment:
			errs = append(errs, fmt.Errorf("cannot read the environment of PBS map process %d of %s %s (%s), which shows whether the interrupted run started it; recovery left it running. If the run started it, stop it (kill -INT %d) and "+recoverhint.Again, pid, intent.Snapshot, intent.Archive, pathless(c.envErr), pid))
		case why == reasonTokenSource:
			errs = append(errs, fmt.Errorf("PBS map process %d of %s %s carries the interrupted run's token but maps from another repository or namespace than the run's; recovery left it running. If the run started it, stop it (kill -INT %d) and "+recoverhint.Again, pid, intent.Snapshot, intent.Archive, pid))
		case intent.Token == "":
			legacy = append(legacy, strconv.Itoa(pid))
		default:
			errs = append(errs, fmt.Errorf("PBS map process %d of %s %s maps from the interrupted run's repository and namespace, but nothing shows the run started it (it lacks the run's token); recovery left it running. If the run started it, stop it (kill -INT %d) and "+recoverhint.Again, pid, intent.Snapshot, intent.Archive, pid))
		}
	}
	if len(legacy) > 0 {
		errs = append(errs, fmt.Errorf("cannot tell whether the interrupted run started PBS map process %s of %s %s: its journal, written by an earlier version, holds no token that marks a run's map processes, so recovery stopped none. If the run started one, stop it (kill -INT <pid>), release what it made, and "+recoverhint.Again, strings.Join(legacy, ", "), intent.Snapshot, intent.Archive))
	}
	return ours, errs
}

// currentBootID is this boot's identity, "" when it cannot be read.
func (r mapReaper) currentBootID() string {
	data, err := os.ReadFile(filepath.Join(r.procRoot, "sys", "kernel", "random", "boot_id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// stillRuns reports whether p, which an earlier attempt journaled as one of
// intent's map processes, still runs as itself. That takes the journaled PID
// and start time (which name one process for as long as the host runs, and the
// journal records the boot they belong to: a process of an earlier boot does
// not run), and a command line that is a map of the intent's snapshot and
// archive, or none (a process that is exiting). A process whose command line
// cannot be read counts as running, with the reason: recovery cannot tell
// that it is gone, and signaling it is safe, because the signal goes through
// a pidfd only after the PID and start time are checked again.
func (r mapReaper) stillRuns(p journal.Process, intent journal.MapIntent) (bool, error) {
	if intent.BootID != "" {
		boot := r.currentBootID()
		switch {
		case boot == "":
			// A PID and start time name a process only within one boot, so with
			// this boot's identity unreadable the journaled process cannot be
			// shown to be of this boot: it is not taken for the run's, and so
			// is not signaled.
			return false, fmt.Errorf("cannot read this boot's identity, so PBS map process %d of %s %s, which the interrupted run journaled in a boot that cannot be compared with this one, is not taken for the run's and was not stopped. If it is the run's map, stop it (kill -INT %d) and "+recoverhint.Again, p.PID, intent.Snapshot, intent.Archive, p.PID)
		case boot != intent.BootID:
			return false, nil
		}
	}
	if !r.alive(p) {
		return false, nil
	}
	cmdline, err := r.readProc(filepath.Join(r.procRoot, strconv.Itoa(p.PID), "cmdline"))
	switch {
	case gone(err):
		return false, nil
	case err != nil:
		return true, fmt.Errorf("cannot read the command line of PBS map process %d of %s %s, which the interrupted run started (%s); recovery cannot tell whether it is gone", p.PID, intent.Snapshot, intent.Archive, pathless(err))
	case len(cmdline) == 0:
		return true, nil // exiting: its memory is gone, and it is not yet reaped
	}
	m, ok := pbs.ParseMapCommand(strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00"))
	return ok && m.Snapshot == intent.Snapshot && m.Archive == intent.Archive, nil
}

// judgePID judges the live proxmox-backup-client that has pid, which a pid
// file names, as intent's map: another operation's map is provably so; a
// process recovery cannot read, or one that is not a map of the intent's
// snapshot and archive at all (the pid file's daemon is gone and its PID was
// reused), is unproven. The text says why.
func (r mapReaper) judgePID(pid int, intent journal.MapIntent) (verdict, string) {
	dir := filepath.Join(r.procRoot, strconv.Itoa(pid))
	cmdline, err := r.readProc(filepath.Join(dir, "cmdline"))
	if err != nil {
		return verdictUnproven, fmt.Sprintf("the proxmox-backup-client process %d that its pid file names cannot be read (%s)", pid, pathless(err))
	}
	argv := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	if !isMapCommand(argv, intent) {
		return verdictUnproven, fmt.Sprintf("its pid file names PID %d, which runs another proxmox-backup-client command than a map of this snapshot and archive: its map process is gone, and recovery never identified it as the run's", pid)
	}
	if _, exact := pbs.ParseMapCommand(argv); !exact {
		return verdictOther, "" // CertiStack never starts a map in this form
	}
	boot, err := r.bootTime()
	if err != nil {
		return verdictUnproven, fmt.Sprintf("the start time of process %d that its pid file names cannot be dated (%s)", pid, err)
	}
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return verdictUnproven, fmt.Sprintf("the state of process %d that its pid file names cannot be read (%s)", pid, pathless(err))
	}
	identity, err := process.ParseIdentity(pid, string(stat))
	if err != nil {
		return verdictUnproven, fmt.Sprintf("the state of process %d that its pid file names cannot be read (%s)", pid, err)
	}
	ticks, _ := strconv.ParseInt(identity.StartTicks, 10, 64)
	c, ok := r.describe(procEntry{identity: identity, started: boot.Add(time.Duration(ticks) * (time.Second / clockTicks)), argv: argv}, intent)
	if !ok {
		return verdictUnproven, fmt.Sprintf("process %d that its pid file names exited while it was read", pid)
	}
	v, why := judge(intent, c)
	switch {
	case v == verdictOther:
		return v, ""
	case v == verdictOurs:
		return v, fmt.Sprintf("process %d that its pid file names carries the run's token, and recovery did not stop it", pid)
	case why == reasonEnvironment:
		return v, fmt.Sprintf("the environment of process %d that its pid file names cannot be read (%s)", pid, pathless(c.envErr))
	}
	return v, fmt.Sprintf("process %d that its pid file names maps the same snapshot and archive from the run's repository and namespace, and nothing shows it is another operation's or the run's", pid)
}

// stop ends intent's map processes. It journals them in intent (through
// persist) before it signals them, and sends each SIGINT, which makes the
// daemon release its loop device and map file itself (it is what
// `proxmox-backup-client unmap` sends). One still running after the grace
// period is killed, and stop waits up to reapWait for it to be gone, so
// that what it leaves is seen as dead.
//
// A map process that is still running after all that, or a candidate stop
// cannot tell apart from the map's own, is an error: the journal then stays
// unclean, and the next recovery tries again, stopping the journaled
// processes that still run.
func (r mapReaper) stop(intent *journal.MapIntent, persist func() error) error {
	ours, errs := r.identify(*intent)
	if len(ours) == 0 {
		return errors.Join(errs...)
	}
	changed := false
	if boot := r.currentBootID(); boot != "" && intent.BootID != boot {
		if intent.BootID != "" {
			intent.Processes = nil // journaled in an earlier boot: none of them runs
		}
		intent.BootID, changed = boot, true
	}
	before := len(intent.Processes)
	for _, p := range ours {
		intent.AddProcess(p)
	}
	if persist != nil && (changed || len(intent.Processes) > before) {
		// Still stopped when this fails: they are the run's. A later attempt
		// then cannot tie their leftovers to them, and reports them.
		if err := persist(); err != nil {
			errs = append(errs, fmt.Errorf("journal the PBS map processes of %s %s recovery stops: %w", intent.Snapshot, intent.Archive, err))
		}
	}
	failed := map[int][]string{}
	for _, p := range ours {
		slog.Warn("stopping a PBS map a previous worker began", "pid", p.PID, "snapshot", intent.Snapshot, "archive", intent.Archive)
		say("WARN", "Stopping the PBS map process %d of %s %s, which the interrupted run started.", p.PID, intent.Snapshot, intent.Archive)
		if err := r.signal(p, syscall.SIGINT); err != nil {
			failed[p.PID] = append(failed[p.PID], fmt.Sprintf("SIGINT: %v", err))
		}
	}
	deadline := time.Now().Add(r.grace)
	var killed []journal.Process
	for _, p := range ours {
		for r.alive(p) && time.Now().Before(deadline) {
			r.sleep(250 * time.Millisecond)
		}
		if r.alive(p) {
			killed = append(killed, p)
		}
	}
	for _, p := range killed {
		slog.Warn("killing a PBS map process that ignored SIGINT", "pid", p.PID)
		say("WARN", "Killing PBS map process %d, which did not stop in %s.", p.PID, r.grace)
		if err := r.signal(p, syscall.SIGKILL); err != nil {
			failed[p.PID] = append(failed[p.PID], fmt.Sprintf("SIGKILL: %v", err))
		}
	}
	reaped := time.Now().Add(r.reapWait)
	for _, p := range killed {
		for r.alive(p) && time.Now().Before(reaped) {
			r.sleep(100 * time.Millisecond)
		}
		if r.alive(p) {
			why := ""
			if len(failed[p.PID]) > 0 {
				why = " (" + strings.Join(failed[p.PID], "; ") + ")"
			}
			slog.Warn("a killed PBS map process is still running", "pid", p.PID)
			errs = append(errs, fmt.Errorf("PBS map process %d of %s %s still runs after SIGINT and SIGKILL%s; its map stays, and the journal keeps it for the next recovery. See what it waits on (cat /proc/%d/stack) and "+recoverhint.Again, p.PID, intent.Snapshot, intent.Archive, why, p.PID))
		}
	}
	return errors.Join(errs...)
}

// mapRunning reports whether any process that may map the intent's
// snapshot and archive runs, whenever it started and whoever started it.
// It errs toward yes: it only decides whether a leftover without a pid
// file may still be such a map's. An error means that is not known.
func (r mapReaper) mapRunning(intent journal.MapIntent) (bool, error) {
	procs, err := r.processes(func(argv []string) bool { return isMapCommand(argv, intent) })
	for _, p := range procs {
		if r.alive(p.identity) {
			return true, err
		}
	}
	return false, err
}

// isMapCommand reports whether argv is a proxmox-backup-client map that has
// the intent's snapshot and archive among its arguments, in any form of the
// command. It is deliberately broad, for mapRunning; the processes recovery
// stops are the narrower candidates.
func isMapCommand(argv []string, intent journal.MapIntent) bool {
	if len(argv) < 2 || filepath.Base(argv[0]) != "proxmox-backup-client" || argv[1] != "map" || intent.Snapshot == "" || intent.Archive == "" {
		return false
	}
	var snapshot, archive bool
	for _, arg := range argv[2:] {
		switch arg {
		case intent.Snapshot:
			snapshot = true
		case intent.Archive:
			archive = true
		}
	}
	return snapshot && archive
}

// evidence is what recovery knows about intent's map processes when it
// looks at the map's loop devices and files.
func (r mapReaper) evidence(intent journal.MapIntent, running bool) mapEvidence {
	ours := map[int]journal.Process{}
	// Processes journaled in a boot count as the run's only when this boot is
	// that one: an unreadable boot identity admits none of them.
	if intent.BootID == "" || intent.BootID == r.currentBootID() {
		for _, p := range intent.Processes {
			ours[p.PID] = p
		}
	}
	return mapEvidence{
		ours:        ours,
		gone:        func(p journal.Process) bool { return !r.alive(p) },
		daemonAlive: r.daemonAlive,
		judge:       func(pid int) (verdict, string) { return r.judgePID(pid, intent) },
		running:     running,
	}
}

// holder is what runs under a PID now.
type holder int

const (
	holderNone    holder = iota // no process, or one that has exited
	holderClient                // a live proxmox-backup-client
	holderOther                 // a live program that is not
	holderUnknown               // what runs cannot be read, or never answers
)

// holderOf says what runs under pid. A pid file can outlive its daemon, and
// the PID be reused: by another program, or by another PBS client.
func (r mapReaper) holderOf(pid int) holder {
	stat, err := os.ReadFile(filepath.Join(r.procRoot, strconv.Itoa(pid), "stat"))
	switch {
	case gone(err):
		return holderNone
	case err != nil:
		return holderUnknown
	case exited(string(stat)):
		return holderNone
	}
	cmdline, err := r.readProc(filepath.Join(r.procRoot, strconv.Itoa(pid), "cmdline"))
	switch {
	case gone(err):
		return holderNone
	case err != nil:
		return holderUnknown
	}
	argv0, _, _ := strings.Cut(string(cmdline), "\x00")
	if filepath.Base(argv0) == "proxmox-backup-client" {
		return holderClient
	}
	return holderOther
}

// daemonAlive reports whether pid may run a proxmox-backup-client that has
// not exited: a zombie, or a PID reused by another program, is a dead
// daemon. A process that cannot be read counts as alive: it is the safe
// answer wherever this decides whether to touch what the daemon serves.
func (r mapReaper) daemonAlive(pid int) bool {
	h := r.holderOf(pid)
	return h == holderClient || h == holderUnknown
}

// isMapDaemon reports whether pid runs proxmox-backup-client.
func (r mapReaper) isMapDaemon(pid int) bool { return r.holderOf(pid) == holderClient }

// unmapGuard is what recovery finds out before it stops the daemon a map's
// pid file names, and before it does anything else to the map.
type unmapGuard int

const (
	// unmapStopDaemon: the pid file names no live process, or names the run's
	// own map daemon: the daemon, if there is one, may be stopped (stopMapDaemon,
	// which looks at it again).
	unmapStopDaemon unmapGuard = iota
	// unmapDetachOnly: it names something that is not the run's daemon (the
	// daemon is gone and its PID was reused): nothing is signaled, and the loop
	// is only detached.
	unmapDetachOnly
	// unmapUnknown: it cannot be established: nothing is done.
	unmapUnknown
)

// daemonVerdict is what checkDaemon finds under the PID a map's pid file names.
type daemonVerdict int

const (
	daemonGone    daemonVerdict = iota // no process runs there, or it has exited
	daemonOurs                         // the run's own map daemon
	daemonNotOurs                      // something that is not the run's map daemon
	daemonUnknown                      // it cannot be established
)

// mapPidFile is the pid file next to the map file backing, which the map's
// daemon writes and removes.
func mapPidFile(backing string) string {
	return strings.TrimSuffix(strings.TrimSuffix(backing, " (deleted)"), ".img") + ".pid"
}

// pidFileDaemon reads the pid file of the map served through backing. A pid
// it returns is non-zero and names a process to look at (checkDaemon); with
// pid zero the verdict is the answer, and why says it: a pid file that is
// not there names no daemon (gone), one that cannot be read is unknown, and
// one that holds no PID names no process (not ours).
func (r mapReaper) pidFileDaemon(backing string) (pid int, v daemonVerdict, why string) {
	data, err := os.ReadFile(mapPidFile(backing))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return 0, daemonGone, ""
	case err != nil:
		return 0, daemonUnknown, "the map's pid file cannot be read: " + pathless(err)
	}
	pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0, daemonNotOurs, "the map's pid file names no process"
	}
	return pid, daemonOurs, ""
}

// checkDaemon says whether the process under pid, which a map's pid file
// names, is the run's own map daemon. It is the run's own map daemon when it
// is an exact-form map of the intent's snapshot and archive that carries the
// intent's token; for an intent without a token the exact form of the
// snapshot and archive is all there is. An intent journaled in a boot other
// than this one has no daemon here (stillRuns); one whose boot cannot be
// compared is unknown. The identity it returns, with the start time read last,
// is of the process it has judged. The text says why it is not ours or not
// known.
func (r mapReaper) checkDaemon(pid int, intent journal.MapIntent) (daemonVerdict, journal.Process, string) {
	none := journal.Process{}
	if intent.BootID != "" {
		switch boot := r.currentBootID(); {
		case boot == "":
			return daemonUnknown, none, fmt.Sprintf("this boot's identity cannot be read, so PID %d, which the map's pid file names, cannot be compared with the boot the run's map was made in", pid)
		case boot != intent.BootID:
			return daemonNotOurs, none, fmt.Sprintf("the map's pid file names PID %d, but the run's map was made in an earlier boot", pid)
		}
	}
	switch r.holderOf(pid) {
	case holderNone:
		return daemonGone, none, ""
	case holderOther:
		return daemonNotOurs, none, fmt.Sprintf("the map's pid file names PID %d, which runs another program now", pid)
	case holderUnknown:
		return daemonUnknown, none, fmt.Sprintf("what runs under PID %d, which the map's pid file names, cannot be read", pid)
	}
	cmdline, err := r.readProc(filepath.Join(r.procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		if gone(err) {
			return daemonGone, none, ""
		}
		return daemonUnknown, none, fmt.Sprintf("the command line of PID %d, which the map's pid file names, cannot be read", pid)
	}
	argv := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	m, exact := pbs.ParseMapCommand(argv)
	if !exact || m.Snapshot != intent.Snapshot || m.Archive != intent.Archive {
		return daemonNotOurs, none, fmt.Sprintf("the map's pid file names PID %d, which runs another proxmox-backup-client command than the run's map now", pid)
	}
	if intent.Token != "" {
		env, err := r.mapEnv(filepath.Join(r.procRoot, strconv.Itoa(pid), "environ"))
		switch {
		case gone(err):
			return daemonGone, none, ""
		case err != nil:
			return daemonUnknown, none, fmt.Sprintf("the environment of PID %d, which the map's pid file names, cannot be read", pid)
		case env[pbs.MapTokenEnv] != intent.Token:
			return daemonNotOurs, none, fmt.Sprintf("the map's pid file names PID %d, a map that the run did not start", pid)
		}
	}
	// The start time, read after everything else, names the process judged: a
	// PID and a start time are one process for as long as the host runs.
	stat, err := os.ReadFile(filepath.Join(r.procRoot, strconv.Itoa(pid), "stat"))
	switch {
	case gone(err):
		return daemonGone, none, ""
	case err != nil:
		return daemonUnknown, none, fmt.Sprintf("the state of PID %d, which the map's pid file names, cannot be read", pid)
	case exited(string(stat)):
		return daemonGone, none, ""
	}
	identity, err := process.ParseIdentity(pid, string(stat))
	if err != nil {
		return daemonUnknown, none, fmt.Sprintf("the state of PID %d, which the map's pid file names, cannot be read", pid)
	}
	return daemonOurs, identity, ""
}

// unmapGuardFor decides, before anything is done to the loop that backs
// backing (the map file recorded for intent's loop), whether the daemon of
// its map may be stopped (stopMapDaemon): there is none, or it is the run's
// own (checkDaemon). It signals nothing itself.
func (r mapReaper) unmapGuardFor(backing string, intent journal.MapIntent) (unmapGuard, string) {
	pid, v, why := r.pidFileDaemon(backing)
	if pid != 0 {
		v, _, why = r.checkDaemon(pid, intent)
	}
	switch v {
	case daemonNotOurs:
		return unmapDetachOnly, why
	case daemonUnknown:
		return unmapUnknown, why
	}
	return unmapStopDaemon, ""
}

// openPidfd is pidfd_open of pid.
func (r mapReaper) openPidfd(pid int) (int, error) {
	if r.pidfdOpen != nil {
		return r.pidfdOpen(pid, 0)
	}
	return unix.PidfdOpen(pid, 0)
}

// stopMapDaemon stops the daemon of the map served through the map file
// backing, as proxmox-backup-client unmap does, but so that the process that is
// signaled is the one that was verified. The client rereads the pid file after
// the caller's check and signals that bare PID: the daemon can exit, and its
// PID be reused, in between.
//
//  1. It reads the pid file and looks at the process under the PID
//     (checkDaemon): the run's own map daemon, with its start time.
//  2. It opens a pidfd for that PID, and looks again, with the pidfd open: a
//     process that has taken the PID since, or whose start time differs, is not
//     the one that was looked at. A pidfd names one process for good, so what
//     is signaled through it is that process or nobody.
//  3. It sends SIGINT through the pidfd, which makes the daemon release its
//     loop device and map file itself (it is what the client's unmap sends), and
//     waits, up to daemonWait, for the process to exit: the pidfd, or a state
//     that is a zombie's, says so.
//
// A pid file that is not there, or names no live process, has no daemon to
// stop; one that names a process that is not the run's daemon, or a PID that
// changed hands, signals nothing, and the note says why: the caller detaches the
// loop alone. What cannot be established (a pid file that cannot be read, a
// process that cannot be read, a boot that cannot be compared, a PID that
// cannot be bound to a pidfd) signals nothing and is an error, as is a daemon
// that was signaled and is still there after the wait. The daemon is never
// killed, as the client's unmap never kills it.
func (r mapReaper) stopMapDaemon(backing string, intent journal.MapIntent) (note string, err error) {
	pid, v, why := r.pidFileDaemon(backing)
	if pid != 0 {
		var first journal.Process
		v, first, why = r.checkDaemon(pid, intent)
		if v == daemonOurs {
			return r.signalVerifiedDaemon(pid, first, intent)
		}
	}
	switch v {
	case daemonNotOurs:
		return why, nil
	case daemonUnknown:
		return "", errors.New(why)
	}
	return "", nil // no daemon to stop
}

// signalVerifiedDaemon is the second and third steps of stopMapDaemon, for the
// process first, which checkDaemon found to be the run's own map daemon.
func (r mapReaper) signalVerifiedDaemon(pid int, first journal.Process, intent journal.MapIntent) (string, error) {
	fd, err := r.openPidfd(pid)
	switch {
	case errors.Is(err, unix.ESRCH):
		return "", nil // it exited since: nothing is left to stop
	case err != nil:
		return "", fmt.Errorf("the PBS map daemon %d of %s %s cannot be bound to a pidfd (%v), so it was not signaled: a signal by PID could land on a process that took the PID in between. Stop it yourself (kill -INT %d), then "+recoverhint.Again, pid, intent.Snapshot, intent.Archive, err, pid)
	}
	defer unix.Close(fd)

	v, second, why := r.checkDaemon(pid, intent)
	switch {
	case v == daemonGone:
		return "", nil
	case v == daemonUnknown:
		return "", errors.New(why)
	case v == daemonNotOurs:
		return why, nil
	case second != first:
		return fmt.Sprintf("PID %d was taken by another process while the map's daemon was being looked at, so nothing was signaled", pid), nil
	}

	slog.Info("stopping a PBS map's daemon through its pidfd", "pid", pid, "snapshot", intent.Snapshot, "archive", intent.Archive)
	if err := unix.PidfdSendSignal(fd, unix.SIGINT, nil, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return "", nil
		}
		return "", fmt.Errorf("cannot signal the PBS map daemon %d of %s %s: %w; stop it yourself (kill -INT %d), then "+recoverhint.Again, pid, intent.Snapshot, intent.Archive, err, pid)
	}
	wait := r.daemonWait
	if wait <= 0 {
		wait = mapCommandWatchdog
	}
	deadline := time.Now().Add(wait)
	for {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 100)
		if err == nil && n > 0 && fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			break
		}
		// A daemon that has exited but whose thread group is held (a thread
		// waiting on its own FUSE file) shows as a zombie; the pidfd does not
		// say it exited.
		if !r.alive(second) {
			break
		}
		if !time.Now().Before(deadline) {
			slog.Warn("a PBS map daemon did not exit after SIGINT", "pid", pid, "waited", wait)
			return "", fmt.Errorf("the PBS map daemon %d of %s %s was sent SIGINT and has not exited after %s; its loop and map stay, and nothing was killed. See what it waits on (cat /proc/%d/stack), then "+recoverhint.Again, pid, intent.Snapshot, intent.Archive, wait, pid)
		}
	}
	slog.Info("a PBS map's daemon stopped", "pid", pid)
	return "", nil
}

// alive reports whether p still runs as the same process: not exited, not a
// zombie, and its PID not reused. A process whose state cannot be read for
// another reason counts as alive: recovery cannot tell that it is gone.
func (r mapReaper) alive(p journal.Process) bool {
	stat, err := os.ReadFile(filepath.Join(r.procRoot, strconv.Itoa(p.PID), "stat"))
	if gone(err) {
		return false
	}
	if err != nil {
		return true
	}
	current, err := process.ParseIdentity(p.PID, string(stat))
	if err != nil {
		return true
	}
	return current.StartTicks == p.StartTicks && !exited(string(stat))
}

// exited reports whether a /proc/<pid>/stat is a zombie's or a dead
// task's. A killed daemon whose thread still waits on its own FUSE file
// shows as a zombie: its main thread has exited.
func exited(stat string) bool {
	end := strings.LastIndex(stat, ")")
	if end < 0 {
		return false
	}
	fields := strings.Fields(stat[end+1:])
	return len(fields) > 0 && (fields[0] == "Z" || fields[0] == "X")
}

// gone reports whether err says a process no longer exists.
func gone(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

// mapEnv reads a process's PBS_REPOSITORY, PBS_NAMESPACE and map token
// from its environ file, and keeps nothing else: the rest of a map's
// environment holds the PBS password. Like getenv, it takes the first of a
// repeated name.
func (r mapReaper) mapEnv(path string) (map[string]string, error) {
	data, err := r.readProc(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	env := map[string]string{}
	for _, entry := range bytes.Split(data, []byte{0}) {
		name, value, ok := bytes.Cut(entry, []byte("="))
		if !ok {
			continue
		}
		if key := string(name); key == "PBS_REPOSITORY" || key == "PBS_NAMESPACE" || key == pbs.MapTokenEnv {
			if _, seen := env[key]; !seen {
				env[key] = string(value)
			}
		}
	}
	return env, nil
}

// signalRecorded sends sig to p through a pidfd, after checking that the
// PID still names p: a PID reused since recovery identified the process is
// never signaled. A process that is gone is not an error.
func signalRecorded(p journal.Process, sig syscall.Signal) error {
	fd, err := unix.PidfdOpen(p.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open process %d: %w", p.PID, err)
	}
	defer unix.Close(fd)
	current, err := process.ProcessIdentity(p.PID)
	if gone(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("verify process %d: %w", p.PID, err)
	}
	if current.StartTicks != p.StartTicks {
		return nil // p exited, and its PID is another process's
	}
	if err := unix.PidfdSendSignal(fd, sig, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

// hostBootTime reads btime from /proc/stat.
func hostBootTime() (time.Time, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if rest, ok := strings.CutPrefix(scanner.Text(), "btime "); ok {
			secs, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(secs, 0), nil
		}
	}
	return time.Time{}, errors.New("btime not found in /proc/stat")
}

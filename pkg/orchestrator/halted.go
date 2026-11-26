// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// haltPollInterval is how often a run checks, while it waits or probes,
// that its sandbox VMs have not stopped for good.
var haltPollInterval = 10 * time.Second

// statusUnknownLimit is how long a wait or a probe stage goes on when PVE
// will not say whether a sandbox VM runs. A read that fails is not evidence
// that the VM runs: the wait carries on through a short outage, as the
// client's own retries do, and ends the VM's wait as failed once it has gone
// this long since a status read last succeeded (or since the wait began, if
// none has). An authentication or permission refusal (HTTP 401 or 403) does not
// pass by itself, so it ends the wait at the first read.
var statusUnknownLimit = 2 * time.Minute

// A status poll must not inherit the PVE client's minute-long request and
// retry budget. Parent cancellation and earlier deadlines still win.
var vmStatusReadTimeout = 5 * time.Second

// vmHaltedError is a sandbox VM that stopped for good while the run waited
// or probed: a full overlay storage stops a guest on its first failed write,
// and its probes would otherwise time out as network errors.
type vmHaltedError struct {
	vmid   int
	reason string
}

func (e *vmHaltedError) Error() string {
	return fmt.Sprintf("VM %d %s", e.vmid, e.reason)
}

// vmUnobservableError is a sandbox VM whose state PVE would not report for
// statusUnknownLimit, or at all: the wait cannot say that the VM runs,
// and a stop in that time would have gone unseen. It fails the wait like a stop
// does, with the reads that failed and the last error PVE gave.
type vmUnobservableError struct {
	vmid   int
	reason string
}

func (e *vmUnobservableError) Error() string {
	return fmt.Sprintf("VM %d's state could not be read from PVE, so its liveness is unknown: %s", e.vmid, e.reason)
}

// vmStopCause is err when it is why a VM's wait or probes must end: a stop, or
// a VM whose state could not be read; nil for anything else.
func vmStopCause(err error) error {
	var halted *vmHaltedError
	var unobservable *vmUnobservableError
	if errors.As(err, &halted) || errors.As(err, &unobservable) {
		return err
	}
	return nil
}

// vmObservation is what one wait learned from its status reads of one VM, and
// what a soak's summary carries (probe.SoakEvidence status_reads and the two
// beside it): how many reads there were, how many failed, and the first
// failure's error, bounded.
type vmObservation struct {
	started time.Time
	lastOK  time.Time
	reads   int
	failed  int
	// firstErr is the first failed read's error, and lastErr the latest.
	firstErr, lastErr string
}

// ok is whether any read succeeded.
func (obs *vmObservation) ok() bool { return !obs.lastOK.IsZero() }

// unobserved is how long it has been since a read last succeeded, or since the
// observation began if none has.
func (obs *vmObservation) unobserved() time.Duration {
	since := obs.lastOK
	if since.IsZero() {
		since = obs.started
	}
	return time.Since(since)
}

// vmHalted reports why a sandbox VM has stopped for good, or nil while it
// runs or its state can't be read. PVE's status stays "running" when QEMU
// has stopped the guest; only its qmpstatus says so. It is the stop alone: a
// wait or a probe stage that must not take an unreadable state for a running
// VM reads it with observeVM.
func (o *Orchestrator) vmHalted(ctx context.Context, vmid int) error {
	if o.pveClient == nil {
		return nil
	}
	status, err := o.pveClient.GetVMStatus(ctx, o.opts.NodeName, vmid)
	if err != nil || status == nil {
		return nil
	}
	return o.haltFromStatus(vmid, status)
}

// haltFromStatus is the stop a VM's status reports, or nil.
func (o *Orchestrator) haltFromStatus(vmid int, status *pve.VMStatus) error {
	switch {
	case status.QMPStatus == "io-error":
		return &vmHaltedError{vmid: vmid, reason: "stopped on a disk write error (QEMU io-error). " + o.overlaySpaceHint()}
	case status.QMPStatus == "internal-error":
		return &vmHaltedError{vmid: vmid, reason: "stopped on a QEMU internal error"}
	case status.QMPStatus == "guest-panicked":
		return &vmHaltedError{vmid: vmid, reason: "stopped because its guest OS crashed (a kernel panic, or a Windows stop error)"}
	case status.Status == "stopped" || status.QMPStatus == "shutdown":
		return &vmHaltedError{vmid: vmid, reason: "is no longer running: its guest shut down, or QEMU exited"}
	}
	return nil
}

// observeVM reads the VM's status once and returns why its wait must end, or
// nil to go on: a stop (vmHaltedError), a VM PVE says does not exist, or a VM
// whose state has been unreadable for statusUnknownLimit or was refused to
// this token (vmUnobservableError). The reads and their failures are counted in
// obs. A read ended by the run's own cancellation is neither: the caller sees
// ctx.
func (o *Orchestrator) observeVM(ctx context.Context, vmid int, obs *vmObservation) error {
	return o.observeVMWithin(ctx, vmid, obs, time.Now().Add(vmStatusReadTimeout))
}

func (o *Orchestrator) observeVMWithin(ctx context.Context, vmid int, obs *vmObservation, deadline time.Time) error {
	if o.pveClient == nil {
		return nil
	}
	readCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	status, err := o.pveClient.GetVMStatus(readCtx, o.opts.NodeName, vmid)
	if ctx.Err() != nil {
		return nil
	}
	obs.reads++
	switch {
	case err != nil:
	case status == nil:
		err = errors.New("PVE returned no status")
	case status.Status == "" && status.QMPStatus == "":
		// PVE always names the state; an answer that does not is not a reading.
		err = errors.New("PVE's answer names no state for the VM")
	}
	if err != nil {
		obs.failed++
		obs.lastErr = boundedSoakError(err.Error())
		if obs.firstErr == "" {
			obs.firstErr = obs.lastErr
		}
		var apiErr *pve.APIError
		switch {
		case pve.IsVMNotFound(err, o.opts.NodeName, vmid):
			return &vmHaltedError{vmid: vmid, reason: "no longer exists on the node: PVE has no configuration for it"}
		case errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden):
			return &vmUnobservableError{vmid: vmid, reason: fmt.Sprintf("PVE refuses this token the VM's status (%s), so a stop could never be seen; the token needs VM.Audit on the VM (read %d of %d failed)", obs.lastErr, obs.failed, obs.reads)}
		case obs.unobserved() >= statusUnknownLimit:
			return &vmUnobservableError{vmid: vmid, reason: fmt.Sprintf("%d of %d status read(s) failed over %s with no success since; the last error was: %s", obs.failed, obs.reads, obs.unobserved().Round(time.Second), obs.lastErr)}
		}
		return nil
	}
	obs.lastOK = time.Now()
	return o.haltFromStatus(vmid, status)
}

// overlaySpaceHint says where the overlays are and how much room is left
// there, for a guest stopped on a write error.
func (o *Orchestrator) overlaySpaceHint() string {
	where, dir := "the scratch directory "+o.opts.ScratchDir, o.opts.ScratchDir
	if storage := o.opts.OverlayStorage; storage != "" {
		where, dir = "overlay storage "+storage, ""
		if o.overlayVolumePathFn != nil {
			if d, err := o.localOverlayStorageDir(context.Background(), storage); err == nil {
				dir = d
			}
		}
	}
	if dir != "" && o.freeBytesFn != nil {
		if free, err := o.freeBytesFn(dir); err == nil {
			return fmt.Sprintf("Its overlays are on %s, which has %d MiB free (%s): most likely it filled up. Make room there, or put overlays on storage with room for the sandboxes' writes.", where, free>>20, dir)
		}
	}
	return fmt.Sprintf("Its overlays are on %s: check that it has not filled up.", where)
}

// waitWatchingVMs waits d, checking the VMs every haltPollInterval, and
// returns those that stopped for good or whose state PVE would not report. It
// stops waiting when all of them have, and returns ctx's error when the run is
// interrupted.
func (o *Orchestrator) waitWatchingVMs(ctx context.Context, d time.Duration, vmids []int) (map[int]error, error) {
	halted, _, err := o.watchVMs(ctx, d, vmids, nil)
	return halted, err
}

// watchVMs is waitWatchingVMs that also runs check on each VM that has not
// stopped, every soakSampleInterval after the previous round of checks ended
// and once more when d is over (the soak's service checks), and returns
// what the status reads of each VM were. A check that returns an error fails
// its VM like a stop does: the error is the VM's entry in the result, and the
// VM is not checked again. A check that was ended by the run's interruption
// ends the wait with ctx's error. With no check it only waits and watches.
//
// A VM whose status was never read successfully in the whole wait is not
// "running": its wait fails as unobservable, however short it was.
func (o *Orchestrator) watchVMs(ctx context.Context, d time.Duration, vmids []int, check func(context.Context, int) error) (map[int]error, map[int]*vmObservation, error) {
	halted := map[int]error{}
	begin := time.Now()
	observed := make(map[int]*vmObservation, len(vmids))
	for _, vmid := range vmids {
		observed[vmid] = &vmObservation{started: begin}
	}
	deadline := begin.Add(d)
	nextCheck := deadline
	if check != nil && soakSampleInterval < d {
		nextCheck = time.Now().Add(soakSampleInterval)
	}
	pollHalts := func() {
		for _, vmid := range vmids {
			if _, done := halted[vmid]; done {
				continue
			}
			readDeadline := time.Now().Add(vmStatusReadTimeout)
			// One shared final budget bounds the wait's last rounds as a whole
			// for a VM that has been read, so a hung request cannot hold a
			// wait past the answer it already has. A VM never read
			// successfully has nothing but this read to be judged by, and is
			// failed as unobservable without one: it gets a full budget of its
			// own, however long the VMs before it took.
			if observed[vmid].ok() {
				if end := deadline.Add(vmStatusReadTimeout); end.Before(readDeadline) {
					readDeadline = end
				}
			}
			if err := o.observeVMWithin(ctx, vmid, observed[vmid], readDeadline); err != nil {
				halted[vmid] = err
				progress.Error("Sandbox", "%s", err)
			}
		}
	}
	// finish ends the wait: a VM that was never read in it cannot be taken for
	// one that runs.
	finish := func() (map[int]error, map[int]*vmObservation, error) {
		if o.pveClient != nil {
			for _, vmid := range vmids {
				if _, done := halted[vmid]; !done && observed[vmid].reads == 0 {
					// A wait that ended before its first poll reads once.
					pollHalts()
					break
				}
			}
			for _, vmid := range vmids {
				if _, done := halted[vmid]; !done && !observed[vmid].ok() {
					obs := observed[vmid]
					halted[vmid] = &vmUnobservableError{vmid: vmid, reason: fmt.Sprintf("none of the %d status read(s) in this %s wait succeeded; the last error was: %s", obs.reads, d.Round(time.Second), obs.lastErr)}
					progress.Error("Sandbox", "%s", halted[vmid])
				}
			}
		}
		return halted, observed, nil
	}
	for {
		if len(halted) == len(vmids) {
			return halted, observed, nil
		}
		if check == nil && time.Until(deadline) <= 0 {
			return finish()
		}
		if check != nil && time.Until(nextCheck) <= 0 {
			// The round is final when the period is over: that check ends
			// the soak.
			final := time.Until(deadline) <= 0
			pollHalts()
			for _, vmid := range vmids {
				if _, done := halted[vmid]; done {
					continue
				}
				if err := check(ctx, vmid); err != nil {
					if ctxErr := ctx.Err(); ctxErr != nil {
						return halted, observed, ctxErr
					}
					halted[vmid] = err
					progress.Error("Sandbox", "VM %d: %s", vmid, err)
				}
			}
			if len(halted) == len(vmids) {
				return halted, observed, nil
			}
			if final {
				return finish()
			}
			nextCheck = time.Now().Add(soakSampleInterval)
			if nextCheck.After(deadline) {
				nextCheck = deadline
			}
			continue
		}
		next := deadline
		if check != nil {
			next = nextCheck
		}
		select {
		case <-ctx.Done():
			return halted, observed, ctx.Err()
		case <-time.After(min(time.Until(next), haltPollInterval)):
		}
		pollHalts()
	}
}

// watchHalt cancels ctx with the VM's halt as its cause once the VM stops
// for good, or its state cannot be read for statusUnknownLimit, so its probes
// stop waiting for a guest that will not answer.
func (o *Orchestrator) watchHalt(ctx context.Context, vmid int, cancel context.CancelCauseFunc, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	obs := &vmObservation{started: time.Now()}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := o.observeVM(ctx, vmid, obs); err != nil {
				progress.Error("Sandbox", "%s", err)
				cancel(err)
				return
			}
		}
	}
}

// soakStatus is what a soak's status reads of one VM go into its summary as.
func soakStatus(evidence *probe.SoakEvidence, obs *vmObservation) {
	if obs == nil {
		return
	}
	evidence.StatusReads = obs.reads
	evidence.StatusReadFailures = obs.failed
	evidence.FirstStatusError = obs.firstErr
}

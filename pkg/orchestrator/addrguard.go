// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/progress"
)

// A run gives the worker a probe address on the sandbox bridge, and wire probes
// bind it as their source. The address is not in the node's network
// configuration, so any network reload on the node removes it and turns IPv4
// forwarding back on for the bridge: PVE reloads every node's network at each
// cluster-wide SDN apply, whether another run, an administrator or Terraform
// made it. The nftables containment table is keyed on the interface name and
// survives. The guard looks at the three every few seconds, read-only, and
// puts back what a reload took away; the probe that follows a reload then does
// not fail with "bind: cannot assign requested address".

// defaultAddrGuardInterval is how often the guard looks; tests set another.
const defaultAddrGuardInterval = 2 * time.Second

// What the guard keeps an occurrence of: each is reported once while it lasts.
const (
	guardInspect    = "inspect"
	guardForwarding = "forwarding"
	guardTable      = "table"
	guardAddress    = "address"
)

// addrGuard owns the goroutine that watches one run's probe address. The
// interface and CIDR are fixed when it is made: it never repairs another
// interface or another address.
type addrGuard struct {
	host        hostAddressManager
	iface, cidr string
	interval    time.Duration
	// failClosed stops the run when the containment cannot be restored.
	failClosed func(error)
	log        *slog.Logger

	// stopping is set when stop begins: no repair starts after it.
	stopping atomic.Bool

	mu sync.Mutex
	// reported holds the occurrences already reported, until they are over.
	reported map[string]bool
	// baseIfindex is the interface's index when the guard started; 0 unknown.
	baseIfindex int
	// baseForwardingOn names the forwarding switches that were on when the guard
	// started: the platform's own setting on a pre-provisioned bridge, which a
	// reload did not change and the guard leaves alone. Only a switch that was
	// off and is on now is put back.
	baseForwardingOn map[string]bool
	// goneErr is set when the bridge is gone or is another interface than the
	// run's: the guard repairs nothing more.
	goneErr error
	// failure is why the run was stopped (the containment could not be restored).
	failure error
	// staleIdentity is set when the guard installed the containment table
	// again, so the journal's record of the table's handle is out of date.
	staleIdentity bool
	stopped       bool
	repairs       int

	// lifeMu guards the goroutine's handles. It is never held with mu, so that
	// stop can reach the cancel of a check that holds mu while it waits on a
	// command.
	lifeMu  sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	started bool
}

func newAddrGuard(host hostAddressManager, iface, cidr string, interval time.Duration, failClosed func(error)) *addrGuard {
	if interval <= 0 {
		interval = defaultAddrGuardInterval
	}
	return &addrGuard{
		host:       host,
		iface:      iface,
		cidr:       cidr,
		interval:   interval,
		failClosed: failClosed,
		log:        slog.Default(),
		reported:   make(map[string]bool),
	}
}

// start reads the interface's identity and starts the goroutine, which stops
// when ctx ends or stop is called. It is called once.
func (g *addrGuard) start(ctx context.Context) {
	g.lifeMu.Lock()
	defer g.lifeMu.Unlock()
	if g.started || g.stopping.Load() {
		return
	}
	g.started = true
	if state, err := g.host.InspectHostAddress(ctx, g.iface, g.cidr); err == nil && state.BridgePresent {
		g.mu.Lock()
		g.baseIfindex = state.Ifindex
		g.baseForwardingOn = map[string]bool{}
		for _, family := range state.ForwardingOn {
			g.baseForwardingOn[family] = true
		}
		g.mu.Unlock()
	}
	loopCtx, cancel := context.WithCancel(ctx)
	g.cancel = cancel
	g.done = make(chan struct{})
	go g.loop(loopCtx, g.done)
}

func (g *addrGuard) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		_ = g.check(ctx)
		if g.finished() {
			return
		}
	}
}

// finished says the guard has nothing more to do: the bridge is gone or the
// run was stopped for lost containment.
func (g *addrGuard) finished() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.goneErr != nil || g.failure != nil
}

// stop ends the goroutine and waits for it. After it returns, no repair is
// running and none will start, so the address and the table can be removed.
// It may be called more than once, and before start.
func (g *addrGuard) stop() {
	g.stopping.Store(true)
	g.lifeMu.Lock()
	cancel, done := g.cancel, g.done
	g.lifeMu.Unlock()
	if cancel != nil {
		cancel() // kills the command a running check waits on
	}
	if done != nil {
		<-done
	}
	// A check running on the caller's goroutine (a probe's) holds mu until it ends.
	g.mu.Lock()
	g.stopped = true
	g.mu.Unlock()
}

// failureErr is why the guard stopped the run, or nil.
func (g *addrGuard) failureErr() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failure
}

// takeStaleIdentity says whether the guard installed the table again since the
// last call. The journal's record of the table's handle is then out of date;
// the orchestrator, which owns the journal, records it again.
func (g *addrGuard) takeStaleIdentity() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	stale := g.staleIdentity
	g.staleIdentity = false
	return stale
}

// repairCount is how many repairs the guard has made.
func (g *addrGuard) repairCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.repairs
}

// check reads the three facts about the run's bridge and puts back what is
// missing, forwarding first, then the containment, then the address (as
// AddInterfaceAddress orders them: the address comes last). The error is
// what could not be read or put back; it has been reported already. The
// goroutine and the probes' synchronous ensure share it.
func (g *addrGuard) check(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case g.stopping.Load() || g.stopped:
		return nil
	case g.goneErr != nil:
		return g.goneErr
	case g.failure != nil:
		return g.failure
	case ctx.Err() != nil:
		return ctx.Err()
	}

	state, err := g.host.InspectHostAddress(ctx, g.iface, g.cidr)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		g.reportOnce(guardInspect, slog.LevelWarn, fmt.Sprintf("could not check the probe address %s on %s, its containment table and its forwarding switches; it will check again: %v", g.cidr, g.iface, err))
		return err
	}
	g.over(guardInspect)

	switch {
	case !state.BridgePresent:
		g.goneErr = fmt.Errorf("the sandbox bridge %s does not exist", g.iface)
		g.say(slog.LevelWarn, fmt.Sprintf("the sandbox bridge %s is gone (its zone was removed, or the node's network was reconfigured): the probe address %s went with it and cannot be put back; the guard has stopped watching", g.iface, g.cidr))
		return g.goneErr
	case g.baseIfindex != 0 && state.Ifindex != 0 && state.Ifindex != g.baseIfindex:
		g.goneErr = fmt.Errorf("the interface %s is not the sandbox bridge the run started with", g.iface)
		g.say(slog.LevelWarn, fmt.Sprintf("the interface %s has index %d now, not the index %d of the sandbox bridge this run used: it was removed and created again, so what is on it is not this run's; nothing is put back on it and the guard has stopped watching", g.iface, state.Ifindex, g.baseIfindex))
		return g.goneErr
	}

	var errs []error
	// A switch that was already on when the guard started is not a reload's
	// doing (a pre-provisioned bridge is the platform's); only one that was off
	// and is on now is put back.
	var turnedOn []string
	for _, family := range state.ForwardingOn {
		if !g.baseForwardingOn[family] {
			turnedOn = append(turnedOn, family)
		}
	}
	if len(turnedOn) == 0 {
		g.over(guardForwarding)
	} else if err := g.restoreForwarding(ctx, turnedOn); err != nil {
		errs = append(errs, err)
	}
	if g.stopping.Load() || ctx.Err() != nil {
		return errors.Join(errs...)
	}
	if state.TablePresent {
		g.over(guardTable)
	} else if err := g.restoreTable(ctx); err != nil {
		errs = append(errs, err)
		if g.failure != nil {
			return errors.Join(errs...)
		}
	}
	if g.stopping.Load() || ctx.Err() != nil {
		return errors.Join(errs...)
	}
	if state.AddressPresent {
		g.over(guardAddress)
	} else if err := g.restoreAddress(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (g *addrGuard) restoreForwarding(ctx context.Context, on []string) error {
	what := strings.Join(on, " and ")
	if err := g.host.DisableForwardingOf(ctx, g.iface, on); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		g.reportOnce(guardForwarding, slog.LevelWarn, fmt.Sprintf("%s forwarding is on again for %s and could not be turned off: %v; the containment table still drops what is forwarded through the bridge", what, g.iface, err))
		return err
	}
	g.repairs++
	g.over(guardForwarding)
	g.say(slog.LevelWarn, fmt.Sprintf("%s forwarding was turned back on for %s: a network reload on this node (an SDN apply by this or another run, an administrator or Terraform does that) turns it on for every SDN bridge; it has been turned off again", what, g.iface))
	return nil
}

// restoreTable installs the containment table again. The table is the
// isolation boundary: when it cannot be restored the run is stopped.
func (g *addrGuard) restoreTable(ctx context.Context) error {
	table := sysutil.IsolationTableName(g.iface, g.cidr)
	err := g.host.RestoreContainment(ctx, g.iface, g.cidr)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		g.failure = fmt.Errorf("the sandbox's isolation could not be restored: the containment table %s for %s was removed from this node's nftables, and installing it again failed: %w; the run is stopping and tearing down", table, g.iface, err)
		g.say(slog.LevelError, g.failure.Error())
		if g.failClosed != nil {
			g.failClosed(g.failure)
		}
		return g.failure
	}
	g.repairs++
	g.staleIdentity = true
	g.over(guardTable)
	g.say(slog.LevelError, fmt.Sprintf("the containment table %s that keeps the sandbox %s off the host was removed from this node's nftables by something other than this run; it has been installed again", table, g.iface))
	return nil
}

func (g *addrGuard) restoreAddress(ctx context.Context) error {
	err := g.host.RestoreAddress(ctx, g.iface, g.cidr)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, sysutil.ErrInterfaceGone) {
			g.goneErr = fmt.Errorf("the sandbox bridge %s does not exist", g.iface)
			g.say(slog.LevelWarn, fmt.Sprintf("the sandbox bridge %s is gone (its zone was removed, or the node's network was reconfigured): the probe address %s went with it and cannot be put back; the guard has stopped watching", g.iface, g.cidr))
			return g.goneErr
		}
		g.reportOnce(guardAddress, slog.LevelWarn, fmt.Sprintf("the probe address %s was removed from %s (a network reload on this node does that) and could not be put back: %v; wire probes cannot bind it until it is", g.cidr, g.iface, err))
		return err
	}
	g.repairs++
	g.over(guardAddress)
	g.say(slog.LevelWarn, fmt.Sprintf("the probe address %s was removed from %s: a network reload on this node (an SDN apply by this or another run, an administrator or Terraform does that) removes it; it has been put back", g.cidr, g.iface))
	return nil
}

// reportOnce reports a problem the first time it is seen in an occurrence.
func (g *addrGuard) reportOnce(key string, level slog.Level, message string) {
	if g.reported[key] {
		return
	}
	g.reported[key] = true
	g.say(level, message)
}

// over ends an occurrence, so the next one is reported.
func (g *addrGuard) over(key string) { delete(g.reported, key) }

// say writes a message to the log and, for a controller watching the worker, to
// the progress channel.
func (g *addrGuard) say(level slog.Level, message string) {
	g.log.Log(context.Background(), level, message, "interface", g.iface, "cidr", g.cidr)
	if level >= slog.LevelError {
		progress.Error("Network", "%s", message)
	} else {
		progress.Warn("Network", "%s", message)
	}
}

// localHostAddressManager's side of the guard.

func (localHostAddressManager) InspectHostAddress(ctx context.Context, iface, cidr string) (sysutil.HostAddressState, error) {
	return sysutil.InspectHostAddress(ctx, iface, cidr)
}

func (localHostAddressManager) HostAddressTaken(ctx context.Context, iface, cidr string) (string, error) {
	return sysutil.HostAddressTaken(ctx, iface, cidr)
}

func (localHostAddressManager) RestoreAddress(ctx context.Context, iface, cidr string) error {
	return sysutil.RestoreInterfaceAddress(ctx, iface, cidr)
}

func (localHostAddressManager) RestoreContainment(ctx context.Context, iface, cidr string) error {
	return sysutil.RestoreInterfaceContainment(ctx, iface, cidr)
}

// startAddrGuard makes the guard for the probe address just added and registers
// its stop, which the LIFO cleanup runs before the address and the table are
// removed (it is pushed right after their removal). The guard starts watching
// with watchAddrGuard, once the address is journaled.
func (o *Orchestrator) startAddrGuard(iface, cidr string) {
	g := newAddrGuard(o.hostAddresses, iface, cidr, o.addrGuardEvery, func(cause error) {
		if o.cancelRun != nil {
			o.cancelRun(cause)
		}
	})
	o.addrGuard = g
	o.cleanup.Push(fmt.Sprintf("stop watching host probe address %s on %s", cidr, iface), func() error {
		g.stop()
		// A table the guard installed again has a new handle; the journal
		// records it before the teardown that removes it.
		o.syncGuardIdentity(context.Background())
		return nil
	})
}

// watchAddrGuard starts the goroutine of the guard startAddrGuard made.
func (o *Orchestrator) watchAddrGuard(ctx context.Context) {
	if o.addrGuard != nil {
		o.addrGuard.start(ctx)
	}
}

// ensureProbeAddress looks at the probe address, its containment and the
// bridge's forwarding right now, and puts back what is missing, so that a probe
// never starts into an address a reload has removed. It runs on the goroutine
// that runs the probes.
func (o *Orchestrator) ensureProbeAddress(ctx context.Context) {
	g := o.addrGuard
	if g == nil {
		return
	}
	if err := g.check(ctx); err != nil && ctx.Err() == nil {
		slog.Debug("the probe address could not be checked or restored before a probe", "interface", g.iface, "error", err)
	}
	o.syncGuardIdentity(ctx)
}

// syncGuardIdentity records the identity of a containment table the guard
// installed again, as setupNetwork did for the first one, so that recovery
// removes the table now there. The journal is the orchestrator's alone, so
// this runs on its goroutine, never the guard's.
func (o *Orchestrator) syncGuardIdentity(ctx context.Context) {
	g := o.addrGuard
	if g == nil || !g.takeStaleIdentity() {
		return
	}
	o.recordHostAddressIdentity(ctx, g.iface, g.cidr)
	if err := o.flushJournal(); err != nil {
		slog.Warn("could not record the identity of the containment table the run installed again; recovery would remove it by name", "interface", g.iface, "error", err)
	}
}

// isolationFailure is why the guard stopped the run, or nil.
func (o *Orchestrator) isolationFailure() error {
	if o.addrGuard == nil {
		return nil
	}
	return o.addrGuard.failureErr()
}

// withIsolationFailure puts the loss of the sandbox's isolation, which stopped
// the run, in front of the cancellation it caused (or in place of a result
// that would otherwise read as complete).
func withIsolationFailure(err, failure error) error {
	if failure == nil || (err != nil && errors.Is(err, failure)) {
		return err
	}
	if err == nil {
		return failure
	}
	detail := strings.TrimSuffix(strings.TrimSuffix(err.Error(), context.Canceled.Error()), ": ")
	if detail == "" {
		return failure
	}
	return fmt.Errorf("%w; the run was at: %s", failure, detail)
}

// addressUnavailableHint is what a wire probe's failure gets when it could not
// bind the probe address: the address is not on the bridge, and why.
func addressUnavailableHint(res *probe.Result, probeType, iface, address string) {
	if res == nil || res.Passed || !config.IsWireProbe(probeType) || address == "" {
		return
	}
	if !strings.Contains(strings.ToLower(res.Error), "cannot assign requested address") {
		return
	}
	res.Error += fmt.Sprintf(" (the probe address %s was not on %s when this probe dialed from it: a network reload on this node removes it, and CertiStack puts it back within a few seconds; the run's warnings say when it did)", address, iface)
}

// withAddressCheck makes a wire probe look at the probe address before each of
// its attempts.
func (o *Orchestrator) withAddressCheck(inner probe.Prober) probe.Prober {
	if o.addrGuard == nil {
		return inner
	}
	return probe.ProberFunc(func(ctx context.Context) probe.Result {
		o.ensureProbeAddress(ctx)
		return inner.Probe(ctx)
	})
}

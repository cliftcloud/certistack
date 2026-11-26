// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

const (
	guardTestIface = "csVnet3"
	guardTestCIDR  = "192.0.2.1/24"
)

// reloadHost is the node as the address guard sees it: the bridge, the probe
// address, the containment table and the forwarding switches, which a
// "network reload" (reload) changes the way ifreload -a does. The guard calls
// it from its own goroutine, so everything is behind a lock. Every call is
// kept, with the interface and CIDR it was given.
type reloadHost struct {
	*fakeHostAddressManager

	mu          sync.Mutex
	events      []string
	bridge      bool
	ifindex     int
	address     bool
	table       bool
	forwarding  []string
	handle      uint64 // the containment table's kernel handle
	inspectErr  error
	addressErr  error
	tableErr    error
	inspecting  chan struct{} // closed when an inspection is blocked
	blockInspec bool
}

func newReloadHost() *reloadHost {
	return &reloadHost{fakeHostAddressManager: &fakeHostAddressManager{}, bridge: true, ifindex: 7, address: true, table: true, handle: 11}
}

func (h *reloadHost) note(format string, args ...any) {
	h.events = append(h.events, fmt.Sprintf(format, args...))
}

// reload is what `ifreload -a` does to the run's bridge: the address that is
// not in the configuration goes, and forwarding comes on.
func (h *reloadHost) reload() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.address, h.forwarding = false, []string{"IPv4"}
}

func (h *reloadHost) set(change func(*reloadHost)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	change(h)
}

func (h *reloadHost) log() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.events...)
}

// count is how many calls start with prefix.
func (h *reloadHost) count(prefix string) int {
	n := 0
	for _, event := range h.log() {
		if strings.HasPrefix(event, prefix) {
			n++
		}
	}
	return n
}

// HostAddressTaken is not the guard's call; a clean host.
func (h *reloadHost) HostAddressTaken(context.Context, string, string) (string, error) {
	return "", nil
}

func (h *reloadHost) InspectHostAddress(ctx context.Context, iface, cidr string) (sysutil.HostAddressState, error) {
	h.mu.Lock()
	h.note("inspect %s %s", iface, cidr)
	err, block, inspecting := h.inspectErr, h.blockInspec, h.inspecting
	state := sysutil.HostAddressState{BridgePresent: h.bridge, Ifindex: h.ifindex, AddressPresent: h.address, TablePresent: h.table, TableHandle: h.handle, ForwardingOn: append([]string(nil), h.forwarding...)}
	h.mu.Unlock()
	if block {
		close(inspecting)
		<-ctx.Done() // a command the context kills
		return sysutil.HostAddressState{}, ctx.Err()
	}
	return state, err
}

func (h *reloadHost) RestoreAddress(_ context.Context, iface, cidr string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.note("restore-address %s %s", iface, cidr)
	if h.addressErr != nil {
		return h.addressErr
	}
	h.address = true
	return nil
}

func (h *reloadHost) RestoreContainment(_ context.Context, iface, cidr string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.note("restore-table %s %s", iface, cidr)
	if h.tableErr != nil {
		return h.tableErr
	}
	h.table, h.handle = true, h.handle+1 // a new table has a new handle
	return nil
}

// Identify is the kernel's identity of the bridge and the table now.
func (h *reloadHost) Identify(context.Context, string, string) (int, uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ifindex, h.handle, nil
}

func (h *reloadHost) DisableForwarding(_ context.Context, bridge string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.note("disable-forwarding %s", bridge)
	h.forwarding = nil
	return nil
}

// DisableForwardingOf turns off only the named families, as the real one does.
func (h *reloadHost) DisableForwardingOf(_ context.Context, bridge string, families []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.note("disable-forwarding-of %s %s", bridge, strings.Join(families, ","))
	var left []string
	for _, on := range h.forwarding {
		off := false
		for _, family := range families {
			if family == on {
				off = true
			}
		}
		if !off {
			left = append(left, on)
		}
	}
	h.forwarding = left
	return nil
}

func (h *reloadHost) Add(ctx context.Context, iface, cidr string) error {
	h.mu.Lock()
	h.note("add %s %s", iface, cidr)
	h.mu.Unlock()
	return h.fakeHostAddressManager.Add(ctx, iface, cidr)
}

// Remove takes the address and the table with it, as the real removal does.
func (h *reloadHost) Remove(ctx context.Context, iface, cidr string) error {
	h.mu.Lock()
	h.note("remove-address %s %s", iface, cidr)
	h.address, h.table = false, false
	h.mu.Unlock()
	return h.fakeHostAddressManager.Remove(ctx, iface, cidr)
}

// lockedBuffer collects the guard's log from two goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// lines are the log lines at level that contain every one of parts.
func (b *lockedBuffer) lines(level string, parts ...string) []string {
	var out []string
	for _, line := range strings.Split(b.String(), "\n") {
		if !strings.Contains(line, "level="+level) {
			continue
		}
		match := true
		for _, part := range parts {
			match = match && strings.Contains(line, part)
		}
		if match {
			out = append(out, line)
		}
	}
	return out
}

type guardRig struct {
	host   *reloadHost
	guard  *addrGuard
	logs   *lockedBuffer
	closed chan error // what failClosed was given
}

// newGuardRig is a guard on the test bridge that has not started: the tests
// call check themselves, or start the goroutine on an interval of a millisecond.
func newGuardRig(t *testing.T) *guardRig {
	t.Helper()
	rig := &guardRig{host: newReloadHost(), logs: &lockedBuffer{}, closed: make(chan error, 4)}
	rig.guard = newAddrGuard(rig.host, guardTestIface, guardTestCIDR, time.Millisecond, func(err error) { rig.closed <- err })
	rig.guard.log = slog.New(slog.NewTextHandler(rig.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(rig.guard.stop)
	return rig
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// A reload removes the address: it is added again, once, by the repair that
// adds nothing else, and the occurrence is logged once with its cause.
func TestGuardPutsBackARemovedAddressAndSaysWhy(t *testing.T) {
	rig := newGuardRig(t)
	ctx := context.Background()
	if err := rig.guard.check(ctx); err != nil || rig.host.count("restore") != 0 {
		t.Fatalf("a healthy bridge was changed: %v, %v", err, rig.host.log())
	}

	rig.host.set(func(h *reloadHost) { h.address = false })
	if err := rig.guard.check(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rig.host.count("restore-address csVnet3 192.0.2.1/24"); got != 1 {
		t.Fatalf("the address was restored %d times: %v", got, rig.host.log())
	}
	if rig.host.count("restore-table") != 0 || rig.host.count("add") != 0 || rig.host.count("disable-forwarding") != 0 || rig.host.count("remove") != 0 {
		t.Errorf("the repair did more than put the address back: %v", rig.host.log())
	}
	warnings := rig.logs.lines("WARN", "probe address 192.0.2.1/24 was removed from csVnet3", "a network reload on this node", "an SDN apply by this or another run, an administrator or Terraform", "it has been put back")
	if len(warnings) != 1 {
		t.Fatalf("want one warning that explains the cause, got %d in:\n%s", len(warnings), rig.logs.String())
	}

	// Healthy again: nothing more is done or said.
	if err := rig.guard.check(ctx); err != nil || rig.host.count("restore") != 1 || len(rig.logs.lines("WARN")) != 1 {
		t.Fatalf("a restored bridge was repaired or reported again: %v\n%s", rig.host.log(), rig.logs.String())
	}

	// A second reload is a second occurrence: put back, and reported again.
	rig.host.reload()
	if err := rig.guard.check(ctx); err != nil {
		t.Fatal(err)
	}
	if rig.host.count("restore-address") != 2 || len(rig.logs.lines("WARN", "probe address")) != 2 {
		t.Fatalf("second occurrence: %v\n%s", rig.host.log(), rig.logs.String())
	}
	if rig.guard.repairCount() != 3 { // two addresses and the forwarding the second reload turned on
		t.Errorf("repairs = %d, want 3", rig.guard.repairCount())
	}
}

func TestGuardTurnsForwardingOffAgain(t *testing.T) {
	rig := newGuardRig(t)
	rig.host.set(func(h *reloadHost) { h.forwarding = []string{"IPv4", "IPv6"} })
	if err := rig.guard.check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rig.host.count("disable-forwarding-of csVnet3 IPv4,IPv6") != 1 || rig.host.count("restore") != 0 {
		t.Fatalf("events = %v", rig.host.log())
	}
	if lines := rig.logs.lines("WARN", "IPv4 and IPv6 forwarding was turned back on for csVnet3", "a network reload", "turned off again"); len(lines) != 1 {
		t.Fatalf("log:\n%s", rig.logs.String())
	}
	if err := rig.guard.check(context.Background()); err != nil || rig.host.count("disable-forwarding") != 1 || len(rig.logs.lines("WARN")) != 1 {
		t.Fatalf("forwarding that is off was turned off again or reported: %v\n%s", rig.host.log(), rig.logs.String())
	}
}

// A pre-provisioned bridge is the platform's: a forwarding switch that was already
// on when the guard started (such as IPv6 on the VNet) is not a reload's doing
// and is left as it is, even on the first look; only a switch that was off and
// is on now is put back, and only that one is written.
func TestGuardLeavesAForwardingSwitchThatWasOnAtTheStart(t *testing.T) {
	rig := newGuardRig(t)
	rig.host.set(func(h *reloadHost) { h.forwarding = []string{"IPv6"} })
	rig.guard.start(context.Background())
	time.Sleep(20 * time.Millisecond) // many looks at a bridge that is as it started
	if rig.host.count("disable-forwarding") != 0 || len(rig.logs.lines("WARN")) != 0 {
		t.Fatalf("a switch that was on at the start was touched or reported: %v\n%s", rig.host.log(), rig.logs.String())
	}

	// A reload turns IPv4 forwarding on as well.
	rig.host.set(func(h *reloadHost) { h.forwarding = []string{"IPv6", "IPv4"} })
	waitFor(t, "IPv4 forwarding to be turned off", func() bool { return rig.host.count("disable-forwarding-of csVnet3 IPv4") == 1 })
	rig.guard.stop()
	if rig.host.count("disable-forwarding-of csVnet3 IPv4,IPv6") != 0 || rig.host.count("disable-forwarding-of csVnet3 IPv6") != 0 {
		t.Errorf("the switch that was on at the start was written: %v", rig.host.log())
	}
	rig.host.mu.Lock()
	left := strings.Join(rig.host.forwarding, ",")
	rig.host.mu.Unlock()
	if left != "IPv6" {
		t.Errorf("forwarding left on = %q, want only the IPv6 switch the platform had on", left)
	}
	if lines := rig.logs.lines("WARN", "IPv4 forwarding was turned back on for csVnet3"); len(lines) != 1 {
		t.Errorf("want one warning naming only IPv4:\n%s", rig.logs.String())
	}
	if len(rig.logs.lines("WARN", "IPv6")) != 0 {
		t.Errorf("IPv6 was reported:\n%s", rig.logs.String())
	}
}

// The containment table is the isolation boundary: its loss is an error, and
// it is installed again as the add installs it.
func TestGuardInstallsAMissingContainmentTableAndLogsAnError(t *testing.T) {
	rig := newGuardRig(t)
	rig.host.set(func(h *reloadHost) { h.table = false })
	if err := rig.guard.check(context.Background()); err != nil {
		t.Fatal(err)
	}
	table := sysutil.IsolationTableName(guardTestIface, guardTestCIDR)
	if rig.host.count("restore-table csVnet3 192.0.2.1/24") != 1 {
		t.Fatalf("events = %v", rig.host.log())
	}
	if lines := rig.logs.lines("ERROR", table, "removed from this node's nftables", "installed again"); len(lines) != 1 {
		t.Fatalf("log:\n%s", rig.logs.String())
	}
	if rig.guard.failureErr() != nil || len(rig.closed) != 0 {
		t.Fatal("a table that could be installed again stopped the run")
	}
	// The journal's record of the table's handle is out of date, once.
	if !rig.guard.takeStaleIdentity() || rig.guard.takeStaleIdentity() {
		t.Fatal("the guard did not say, exactly once, that the table's identity changed")
	}
}

// Fail closed: a containment that cannot be installed stops the run, with an
// error that says so, and the guard does not try again.
func TestGuardStopsTheRunWhenTheContainmentCannotBeRestored(t *testing.T) {
	rig := newGuardRig(t)
	rig.host.set(func(h *reloadHost) {
		h.table, h.address, h.tableErr = false, false, errors.New("nft: Operation not permitted")
	})
	err := rig.guard.check(context.Background())
	if err == nil {
		t.Fatal("a containment that could not be restored was not an error")
	}
	var given error
	select {
	case given = <-rig.closed:
	default:
		t.Fatal("the run was not stopped")
	}
	for _, want := range []string{"isolation could not be restored", sysutil.IsolationTableName(guardTestIface, guardTestCIDR), "csVnet3", "Operation not permitted", "tearing down"} {
		if !strings.Contains(given.Error(), want) {
			t.Errorf("the stop reason lacks %q: %v", want, given)
		}
	}
	if rig.guard.failureErr() == nil || len(rig.logs.lines("ERROR", "isolation could not be restored")) != 1 {
		t.Fatalf("log:\n%s", rig.logs.String())
	}
	// The address is not put back into a bridge whose containment is gone.
	if rig.host.count("restore-address") != 0 {
		t.Errorf("an address was restored without its containment: %v", rig.host.log())
	}
	// No second attempt, no second stop.
	before := len(rig.host.log())
	if err := rig.guard.check(context.Background()); err == nil || len(rig.host.log()) != before || len(rig.closed) != 0 {
		t.Errorf("the guard tried again after it stopped the run: %v", rig.host.log())
	}
}

// A bridge that is gone (its zone was removed) is said once; the guard stops
// looking and never spins.
func TestGuardSaysOnceThatTheBridgeIsGoneAndStops(t *testing.T) {
	rig := newGuardRig(t)
	rig.host.set(func(h *reloadHost) { h.bridge = false })
	for i := 0; i < 5; i++ {
		if err := rig.guard.check(context.Background()); err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("check %d = %v", i, err)
		}
	}
	if rig.host.count("inspect") != 1 || rig.host.count("restore") != 0 {
		t.Fatalf("the guard went on after the bridge was gone: %v", rig.host.log())
	}
	if lines := rig.logs.lines("WARN", "csVnet3 is gone", "cannot be put back"); len(lines) != 1 || len(rig.logs.lines("WARN")) != 1 {
		t.Fatalf("log:\n%s", rig.logs.String())
	}
	if len(rig.closed) != 0 {
		t.Error("a removed zone stopped the run: its VMs are off the network and the table still contains the interface name")
	}

	// The goroutine ends by itself.
	rig2 := newGuardRig(t)
	rig2.host.set(func(h *reloadHost) { h.bridge = false })
	rig2.guard.start(context.Background())
	select {
	case <-rig2.guard.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the guard goroutine kept running after the bridge was gone")
	}
}

// The zone can also go between the look and the add.
func TestGuardTreatsAnAddToAMissingInterfaceAsAGoneBridge(t *testing.T) {
	rig := newGuardRig(t)
	rig.host.set(func(h *reloadHost) { h.address, h.addressErr = false, fmt.Errorf("add: %w", sysutil.ErrInterfaceGone) })
	for i := 0; i < 3; i++ {
		_ = rig.guard.check(context.Background())
	}
	if rig.host.count("restore-address") != 1 || len(rig.logs.lines("WARN", "is gone")) != 1 {
		t.Fatalf("events %v\n%s", rig.host.log(), rig.logs.String())
	}
}

// What is not the run's is not repaired: another interface of the same name
// (it has another index), and any other interface or address.
func TestGuardRepairsNothingThatIsNotTheRuns(t *testing.T) {
	rig := newGuardRig(t)
	rig.guard.interval = time.Hour // started for the baseline read; the goroutine never ticks
	rig.guard.start(context.Background())

	// The bridge was removed and created again: other index, no address.
	rig.host.set(func(h *reloadHost) { h.ifindex, h.address, h.forwarding = 9, false, []string{"IPv4"} })
	if err := rig.guard.check(context.Background()); err == nil {
		t.Fatal("a replacement interface was taken for the run's")
	}
	if rig.host.count("restore") != 0 || rig.host.count("disable-forwarding") != 0 {
		t.Fatalf("a replacement interface was repaired: %v", rig.host.log())
	}
	if lines := rig.logs.lines("WARN", "index 9", "index 7", "not this run's"); len(lines) != 1 {
		t.Fatalf("log: %s", rig.logs.String())
	}
	// And it stays unrepaired.
	_ = rig.guard.check(context.Background())
	if rig.host.count("restore") != 0 || rig.host.count("inspect") != 2 { // the baseline and one look
		t.Fatalf("events = %v", rig.host.log())
	}
}

func TestGuardOnlyTouchesItsOwnInterfaceAndAddress(t *testing.T) {
	rig := newGuardRig(t)
	rig.host.set(func(h *reloadHost) { h.address, h.table, h.forwarding = false, false, []string{"IPv4"} })
	if err := rig.guard.check(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, event := range rig.host.log() {
		if !strings.Contains(event, "csVnet3") {
			t.Errorf("%q does not name the run's interface", event)
		}
		if strings.Contains(event, "restore") || strings.HasPrefix(event, "inspect") {
			if !strings.HasSuffix(event, " 192.0.2.1/24") {
				t.Errorf("%q does not name the run's address", event)
			}
		}
	}
	if rig.host.count("restore-table")+rig.host.count("restore-address")+rig.host.count("disable-forwarding") != 3 {
		t.Fatalf("events = %v", rig.host.log())
	}
	// Forwarding, then the containment, then the address: the order the add uses.
	events := rig.host.log()
	order := []string{"disable-forwarding", "restore-table", "restore-address"}
	at := 0
	for _, event := range events {
		if at < len(order) && strings.HasPrefix(event, order[at]) {
			at++
		}
	}
	if at != len(order) {
		t.Errorf("repairs ran out of order: %v", events)
	}
}

// A look that fails is not a repair, and is said once while it lasts.
func TestGuardReportsAnUnreadableStateOnce(t *testing.T) {
	rig := newGuardRig(t)
	rig.host.set(func(h *reloadHost) { h.inspectErr = errors.New("ip: exec: not found") })
	for i := 0; i < 4; i++ {
		if err := rig.guard.check(context.Background()); err == nil {
			t.Fatal("an unreadable state was read as healthy")
		}
	}
	if rig.host.count("restore") != 0 || len(rig.logs.lines("WARN", "could not check the probe address")) != 1 {
		t.Fatalf("events %v\n%s", rig.host.log(), rig.logs.String())
	}
	rig.host.set(func(h *reloadHost) { h.inspectErr = nil })
	if err := rig.guard.check(context.Background()); err != nil {
		t.Fatal(err)
	}
	rig.host.set(func(h *reloadHost) { h.inspectErr = errors.New("ip: exec: not found") })
	_ = rig.guard.check(context.Background())
	if len(rig.logs.lines("WARN", "could not check the probe address")) != 2 {
		t.Fatalf("a new occurrence was not reported:\n%s", rig.logs.String())
	}
}

// An address that cannot be put back is retried each time and reported once.
func TestGuardReportsAFailedAddressRepairOnce(t *testing.T) {
	rig := newGuardRig(t)
	rig.host.set(func(h *reloadHost) { h.address, h.addressErr = false, errors.New("the node uses 192.0.2.0/24") })
	for i := 0; i < 3; i++ {
		if err := rig.guard.check(context.Background()); err == nil {
			t.Fatal("a failed repair was not an error")
		}
	}
	if rig.host.count("restore-address") != 3 || len(rig.logs.lines("WARN", "could not be put back", "the node uses 192.0.2.0/24")) != 1 {
		t.Fatalf("events %v\n%s", rig.host.log(), rig.logs.String())
	}
	rig.host.set(func(h *reloadHost) { h.addressErr = nil })
	if err := rig.guard.check(context.Background()); err != nil || len(rig.logs.lines("WARN", "it has been put back")) != 1 {
		t.Fatalf("recovery: %v\n%s", err, rig.logs.String())
	}
}

// The goroutine does the work on its own interval.
func TestGuardGoroutinePutsTheAddressBack(t *testing.T) {
	rig := newGuardRig(t)
	rig.guard.start(context.Background())
	rig.host.reload()
	waitFor(t, "the address to be put back", func() bool {
		return rig.host.count("restore-address") >= 1 && rig.host.count("disable-forwarding") >= 1
	})
	rig.guard.stop()
	if got := rig.host.count("restore-address"); got != 1 {
		t.Errorf("the address was restored %d times for one reload", got)
	}
}

// Stopping cancels a check that is running, waits for it, and nothing is
// repaired afterwards, so the address and the table can be removed.
func TestGuardStopWaitsForAnInFlightCheckAndRepairsNothingAfterIt(t *testing.T) {
	rig := newGuardRig(t)
	rig.guard.start(context.Background())
	rig.host.set(func(h *reloadHost) { h.blockInspec, h.inspecting = true, make(chan struct{}) })
	waitFor(t, "an inspection to block", func() bool {
		rig.host.mu.Lock()
		defer rig.host.mu.Unlock()
		select {
		case <-rig.host.inspecting:
			return true
		default:
			return false
		}
	})

	stopped := make(chan struct{})
	go func() { rig.guard.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("stop did not return: the blocked check was not canceled")
	}
	select {
	case <-rig.guard.done:
	default:
		t.Fatal("stop returned while the goroutine was still running")
	}

	before := len(rig.host.log())
	rig.host.set(func(h *reloadHost) {
		h.blockInspec = false
		h.address, h.table, h.forwarding = false, false, []string{"IPv4"}
	})
	if err := rig.guard.check(context.Background()); err != nil {
		t.Fatalf("a check after stop = %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if after := rig.host.log(); len(after) != before {
		t.Fatalf("the guard acted after it was stopped: %v", after[before:])
	}
	rig.guard.stop() // and again
}

func TestGuardStopsWhenTheContextEnds(t *testing.T) {
	rig := newGuardRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	rig.guard.start(ctx)
	cancel()
	select {
	case <-rig.guard.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the guard goroutine outlived its context")
	}
	rig.host.reload()
	if err := rig.guard.check(ctx); err == nil || rig.host.count("restore") != 0 {
		t.Fatalf("a repair ran under a canceled context: %v %v", err, rig.host.log())
	}
}

func TestGuardStopBeforeStartIsHarmless(t *testing.T) {
	rig := newGuardRig(t)
	rig.guard.stop()
	rig.guard.stop()
	rig.guard.start(context.Background()) // too late: it never starts
	if rig.guard.done != nil || rig.host.count("inspect") != 0 {
		t.Fatalf("a stopped guard started: %v", rig.host.log())
	}
}

// Before a wire probe's attempt the address is looked at, so a probe never
// starts into an address a reload took away.
func TestWireProbeLooksAtTheAddressBeforeEachAttempt(t *testing.T) {
	rig := newGuardRig(t)
	orch := &Orchestrator{addrGuard: rig.guard}
	rig.host.reload()
	var sawAddress []bool
	inner := probe.ProberFunc(func(context.Context) probe.Result {
		rig.host.mu.Lock()
		defer rig.host.mu.Unlock()
		sawAddress = append(sawAddress, rig.host.address)
		return probe.Result{Passed: true}
	})
	prober := orch.withAddressCheck(inner)
	for i := 0; i < 3; i++ {
		if res := prober.Probe(context.Background()); !res.Passed {
			t.Fatal("the probe was not run")
		}
	}
	if len(sawAddress) != 3 || !sawAddress[0] || !sawAddress[1] || !sawAddress[2] {
		t.Fatalf("the probe started without its address: %v", sawAddress)
	}
	if rig.host.count("restore-address") != 1 || rig.host.count("inspect") != 3 {
		t.Fatalf("events = %v", rig.host.log())
	}

	// A run without a guard probes as it did.
	events := len(rig.host.log())
	if res := (&Orchestrator{}).withAddressCheck(inner).Probe(context.Background()); !res.Passed || len(rig.host.log()) != events {
		t.Fatal("a run without a guard changed its prober")
	}
}

// ensure runs on the probes' goroutine, and a table it installs again is
// recorded in the journal by that goroutine.
func TestEnsureRecordsAnInstalledAgainTable(t *testing.T) {
	rig := newGuardRig(t)
	orch := &Orchestrator{addrGuard: rig.guard, hostAddresses: rig.host, opts: Options{StateDir: t.TempDir()}}
	orch.record.AddHostAddress(guardTestIface, guardTestCIDR)
	orch.record.SetHostAddressIdentity(guardTestIface, guardTestCIDR, 7, 11)

	rig.host.set(func(h *reloadHost) { h.table = false })
	orch.ensureProbeAddress(context.Background())
	if rig.host.count("restore-table") != 1 {
		t.Fatalf("events = %v", rig.host.log())
	}
	if got := orch.record.HostAddresses[0]; got.IfIndex != 7 || got.TableHandle != 12 {
		t.Fatalf("the journal records %+v, want the new table's handle 12 on interface 7", got)
	}
	// Recorded once.
	if rig.guard.takeStaleIdentity() {
		t.Fatal("the journal was told twice")
	}
}

func TestAddressUnavailableHint(t *testing.T) {
	const bindError = "TCP handshake failed: dial tcp 192.0.2.1:0->192.0.2.10:8081: bind: cannot assign requested address (last answered attempt; later attempts ran out of time)"
	res := probe.Result{Type: "tcp", Error: bindError}
	addressUnavailableHint(&res, "tcp", "csVnet3", "192.0.2.1")
	if !strings.HasPrefix(res.Error, bindError) {
		t.Fatalf("the existing message was changed: %q", res.Error)
	}
	for _, want := range []string{"192.0.2.1", "csVnet3", "network reload", "puts it back"} {
		if !strings.Contains(strings.TrimPrefix(res.Error, bindError), want) {
			t.Errorf("hint lacks %q: %q", want, res.Error)
		}
	}

	for name, tc := range map[string]struct {
		res       probe.Result
		probeType string
	}{
		"another error":    {probe.Result{Error: "TCP handshake failed: connection refused"}, "tcp"},
		"a passed probe":   {probe.Result{Passed: true, Error: bindError}, "tcp"},
		"a non-wire probe": {probe.Result{Error: bindError}, "qga"},
	} {
		before := tc.res.Error
		addressUnavailableHint(&tc.res, tc.probeType, "csVnet3", "192.0.2.1")
		if tc.res.Error != before {
			t.Errorf("%s: the message was changed: %q", name, tc.res.Error)
		}
	}
	for _, probeType := range []string{"tcp", "tcp_handshake", "http", "http_get", "dns", "ldap", "mssql", "smb"} {
		if !config.IsWireProbe(probeType) {
			t.Fatalf("%s is not a wire probe", probeType)
		}
		r := probe.Result{Error: strings.ToUpper(bindError[:20]) + bindError[20:]}
		addressUnavailableHint(&r, probeType, "csVnet3", "192.0.2.1")
		if !strings.Contains(r.Error, "network reload") {
			t.Errorf("%s probe got no hint", probeType)
		}
	}
}

func TestWithIsolationFailure(t *testing.T) {
	failure := errors.New("the sandbox's isolation could not be restored: table gone")
	if got := withIsolationFailure(context.Canceled, failure); got.Error() != failure.Error() {
		t.Errorf("a bare cancellation = %q", got)
	}
	got := withIsolationFailure(fmt.Errorf("VM 9101 restore: %w", context.Canceled), failure)
	if !errors.Is(got, failure) || !strings.Contains(got.Error(), "the run was at: VM 9101 restore") {
		t.Errorf("a cancellation with detail = %q", got)
	}
	if got := withIsolationFailure(nil, failure); got != failure {
		t.Errorf("a run that looked complete = %v", got)
	}
	if got := withIsolationFailure(failure, failure); got != failure {
		t.Errorf("a failure already named = %v", got)
	}
	if got := withIsolationFailure(context.Canceled, nil); got != context.Canceled {
		t.Errorf("no failure changed the error: %v", got)
	}
}

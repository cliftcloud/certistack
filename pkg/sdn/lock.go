// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// ErrPendingSDNChanges means the cluster's SDN configuration holds changes
// nobody has applied. Applying SDN is all or nothing, on every node, so
// applying the sandbox's objects would apply them too: an administrator's
// unfinished change could reach production networking.
var ErrPendingSDNChanges = errors.New("the cluster's SDN configuration has changes that have not been applied")

// PendingChangesAdvice is what a refusal over pending SDN changes tells the
// reader to do. The changes are someone else's work in progress: the way out is
// to ask whoever made them, never to apply or discard what you did not make.
const PendingChangesAdvice = "Ask whoever changed SDN to apply or discard the change (Datacenter > SDN), then run again. Do not apply someone else's change yourself."

// ErrSDNLockHeld means PVE's SDN configuration lock stands and is not this
// manager's to take: PVE refuses a lock with "invalid lock token" only
// while one is taken.
var ErrSDNLockHeld = errors.New("PVE's SDN configuration lock is held by another client")

// ErrSDNLockUnknown means a request for PVE's SDN lock got no definite
// answer: PVE may have taken the lock for it, with a token that never
// reached CertiStack. PVE's lock has no expiry and no owner but its token,
// so such a lock can only be released by force, by an operator who knows
// no one else is changing SDN.
var ErrSDNLockUnknown = errors.New("a request for PVE's SDN configuration lock got no definite answer, so PVE may hold the lock for it with a token CertiStack never received")

// ErrSDNLockLost means the lock the manager held was gone when it came to
// apply, with nothing pending: its change was applied already, or never
// made. The manager applies nothing then.
var ErrSDNLockLost = errors.New("the SDN configuration lock CertiStack held was released before its apply")

// errSDNLockBusy is a refusal of the lock that says nothing of whether one
// stands, such as PVE's cluster file system lock timing out.
var errSDNLockBusy = errors.New("PVE could not take its SDN configuration lock just now")

// A lock another client holds is waited for, between these bounds, up to
// lockWait. CertiStack itself holds it for seconds.
var (
	lockRetryInitial = 2 * time.Second
	lockRetryMax     = 15 * time.Second
	lockWait         = 2 * time.Minute
)

// SetLockWait bounds how long Lock and EnsureLock wait for a lock another
// client holds; zero is the default, 2 minutes.
func (m *Manager) SetLockWait(wait time.Duration) { m.lockWait = wait }

func (m *Manager) lockWaitBound() time.Duration {
	if m.lockWait > 0 {
		return m.lockWait
	}
	return lockWait
}

// lockEndpoint is the SDN lock's path: POST takes the lock, DELETE releases it.
//
// PVE 8 has no SDN configuration lock: PVE 8.4.0 (libpve-network-perl 0.11.2)
// has no /cluster/sdn/lock (pvesh: "no such resource"), where PVE 9 has it. Its
// HTTP layer answers a request for an unknown path "Method 'POST
// /cluster/sdn/lock' not implemented" with status 501 (a proxy, or another
// build, may say 404), and its schema refuses a lock-token or release-lock
// parameter on a write or the apply as undefined. A manager whose lock request
// is answered so works without a lock for the rest of its life (noLockAPI):
//
//   - it sends no lock-token and no release-lock, anywhere;
//   - Lock and EnsureLock take nothing, and Unlock has nothing to release;
//   - the journal is told that no lock is requested or held, so that recovery
//     never looks for one;
//   - PVE refuses nothing over an administrator's unapplied change there, so
//     the manager itself reads the pending zones, VNets, controllers and
//     subnets (noLockGuard) when it would have taken the lock and before each
//     apply, and writes or applies nothing over a change that is not its run's
//     own. IPAM and DNS objects are not read: on PVE 8.4.0 their list calls
//     refuse the pending parameter (checked read-only on a lab node, October
//     2026), so those objects have no pending state to read, and an apply
//     does not carry them: PVE 8's commit_config (pve-network,
//     src/PVE/Network/SDN.pm, branch stable-bookworm, read November 2026)
//     writes only the vnets, zones, controllers and subnets to the running
//     configuration.
//
// What PVE 8 cannot give, CertiStack cannot add: PVE 8 does not serialize SDN
// changes across clients. Two controllers (or a controller and an
// administrator) changing one cluster's SDN at the same moment are not held off
// by PVE, and the pending-change reads are a check, not a lock: they leave a
// window of two requests between the read and the write or the apply. What the
// product relies on instead is the host lock (one CertiStack operation per node
// at a time), the VNet ownership checks (a VNet is deleted only while it
// carries the run's marker), the zone and VNet IDs PVE refuses to create twice,
// and the wait for its own earlier apply. Runs on different nodes of one PVE 8
// cluster can therefore overlap, and one's apply can commit the other's
// objects pending in that window.
const lockEndpoint = "cluster/sdn/lock"

// lockEndpointMissing reports whether err is PVE's answer to the request for
// the SDN lock that the endpoint does not exist: HTTP 501 (PVE's "Method ...
// not implemented"), or 404 from a proxy or another PVE build. It is meant for
// the answer to the lock request itself and for nothing else: a 404 or 501
// from any other SDN path is an error like any other, and tryLock is its only
// caller, so a missing zone or task is never read as a missing lock API.
func lockEndpointMissing(err error) bool {
	var apiErr *pve.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusNotImplemented || apiErr.StatusCode == http.StatusNotFound
}

// NoLockAPI reports that PVE answered the SDN lock request as a missing
// endpoint (a PVE 8 cluster): the manager then works without a lock.
func (m *Manager) NoLockAPI() bool { return m.noLockAPI }

// enterNoLockAPI records, once, that this PVE has no SDN lock, and settles
// what the manager and its journal believed about one: nothing was granted,
// nothing is requested, and a token adopted from a journal (written for another
// PVE) has nothing to release.
func (m *Manager) enterNoLockAPI(ctx context.Context, cause error) error {
	m.noLockAPI = true
	m.lockToken, m.lockHeld, m.lockUnknown, m.lockStood = "", false, false, false
	slog.Warn("this PVE has no SDN configuration lock (PVE 8 does not have POST /cluster/sdn/lock): CertiStack works without one, reads the pending SDN changes itself, and cannot hold other clients off while it changes SDN", "answer", apiMessage(cause))
	// The request was journaled before it was sent. PVE's answer says no lock
	// can exist, so the journal must stop saying one may; when it cannot be
	// written the journal keeps the request, which only asks recovery to look.
	m.noteRefusal()
	return m.noLockGuard(ctx)
}

// noLockGuard is what PVE's lock refusal over pending changes would be, made
// by the manager on a PVE that has no lock: the cluster's unapplied SDN
// changes (zones, VNets, controllers and, here, subnets, as pendingEntries
// reads them) must be this run's own, since an apply commits all of them on
// every node. A read that fails is an error, never "nothing pending".
func (m *Manager) noLockGuard(ctx context.Context) error {
	foreign, err := m.ForeignPending(ctx)
	if err != nil {
		return fmt.Errorf("read the cluster's pending SDN changes (this PVE has no SDN lock to refuse them): %w", err)
	}
	if len(foreign) > 0 {
		return fmt.Errorf("%w (%s). This PVE has no SDN configuration lock, so CertiStack read the pending changes itself. Applying the sandbox network would apply them too, on every node, so CertiStack does not. "+PendingChangesAdvice, ErrPendingSDNChanges, strings.Join(foreign, ", "))
	}
	return nil
}

// LockState is what the manager journals about PVE's SDN lock, so that
// recovery can finish, or release, what a dead process left (SetPersist).
type LockState struct {
	// Token is the token of the lock held, or "" for none.
	Token string
	// Requested is true from a lock request until PVE's answer is known,
	// and stays true when none came (ErrSDNLockUnknown).
	Requested bool
	// ApplyTask is the UPID of the last apply's task.
	ApplyTask string
	// ApplyUnknown is true while an apply's outcome is unknown: its reply was
	// lost, or named no task, so its reload may still be running.
	ApplyUnknown bool
}

// SetPersist makes the manager journal its lock state through persist:
// before each lock request, and whenever the token or the apply task
// changes. A lock request is not sent unless it is journaled, and a token
// that cannot be journaled is released at once, never used.
func (m *Manager) SetPersist(persist func(LockState) error) { m.persist = persist }

func (m *Manager) note(requested bool) error {
	if m.persist == nil {
		return nil
	}
	return m.persist(LockState{Token: m.lockToken, Requested: requested || m.lockUnknown, ApplyTask: m.reloadTask, ApplyUnknown: m.applyUnknown})
}

// noteRefusal journals a definite refusal of the lock. When that fails the
// journal still says the lock was requested, which asks recovery to find
// out: the safe side.
func (m *Manager) noteRefusal() {
	if err := m.note(false); err != nil {
		slog.Warn("could not journal PVE's refusal of the SDN lock", "error", err)
	}
}

// Lock takes PVE's global SDN configuration lock, so that what CertiStack
// applies is its own change and nothing else. PVE refuses the lock while
// the configuration has pending changes; the error then names them. While
// the manager holds the lock, its writes and its Reload use the token, and
// Reload releases it.
func (m *Manager) Lock(ctx context.Context) error {
	deadline := time.Now().Add(m.lockWaitBound())
	wait := lockRetryInitial
	for {
		err := m.tryLock(ctx)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrSDNLockHeld) && !errors.Is(err, errSDNLockBusy) || time.Now().Add(wait).After(deadline) {
			return err
		}
		// Another client holds it.
		if err := sleepCtx(ctx, wait); err != nil {
			return fmt.Errorf("take PVE's SDN configuration lock: %w", err)
		}
		if wait *= 2; wait > lockRetryMax {
			wait = lockRetryMax
		}
	}
}

// EnsureLock makes sure the manager may write under PVE's SDN lock. It
// keeps a lock it took itself and takes one when it has none. A token it
// adopted, or may have spent (an apply or release whose answer was lost),
// is kept only while a lock stands: PVE refuses a write whose token is not
// the standing lock's, so the writes that follow tell whether it is this
// one; but PVE takes any token while no lock stands at all, so a stale one
// would apply everything pending. When no lock stands, the token is
// dropped and a lock taken anew.
func (m *Manager) EnsureLock(ctx context.Context) error {
	switch {
	case m.lockToken != "" && m.lockHeld:
		return nil
	case m.lockToken == "":
		return m.Lock(ctx)
	}
	deadline := time.Now().Add(m.lockWaitBound())
	wait := lockRetryInitial
	for {
		err := m.tryLock(ctx)
		if errors.Is(err, ErrSDNLockHeld) {
			// A lock stands; whether it is this token's, a write PVE accepts
			// with the token will tell (acceptedUnderLock).
			m.lockStood = true
			return nil
		}
		if err == nil {
			return nil
		}
		if !errors.Is(err, errSDNLockBusy) || time.Now().Add(wait).After(deadline) {
			return err
		}
		if err := sleepCtx(ctx, wait); err != nil {
			return fmt.Errorf("take PVE's SDN configuration lock: %w", err)
		}
		if wait *= 2; wait > lockRetryMax {
			wait = lockRetryMax
		}
	}
}

// tryLock asks PVE for the SDN lock once, journaling the request first.
// PVE's answer also says whether a lock stands (its token check comes
// before its pending check): it grants one only when none stands and
// nothing is pending, so any token the manager had is stale, and refuses
// over pending changes only when none stands. Any answer that is not PVE's
// own leaves the request's outcome unknown.
func (m *Manager) tryLock(ctx context.Context) error {
	if m.noLockAPI {
		// PVE answered the lock path as missing earlier: it is not asked again.
		return m.noLockGuard(ctx)
	}
	wasUnknown := m.lockUnknown
	if err := m.note(true); err != nil {
		return fmt.Errorf("journal the SDN lock request before sending it: %w", err)
	}
	var token string
	err := m.client.Do(ctx, "POST", lockEndpoint, map[string]interface{}{}, &token)
	if err != nil && lockEndpointMissing(err) {
		return m.enterNoLockAPI(ctx, err)
	}
	if err == nil && token != "" {
		m.lockToken, m.lockHeld, m.lockUnknown, m.lockStood = token, true, false, false
		if err := m.note(false); err != nil {
			// A token the journal lacks is never used: after a crash
			// nobody could release it.
			return fmt.Errorf("journal PVE's SDN lock token: %w", errors.Join(err, m.release(ctx)))
		}
		return nil
	}
	if err != nil && pve.NotSent(err) {
		// The request provably never reached PVE (the client is not
		// configured, the call was cancelled before it was sent, or no
		// connection was made): it left no lock behind, and the journal
		// need not say it may have.
		m.lockUnknown = wasUnknown
		m.noteRefusal()
		return fmt.Errorf("take PVE's SDN configuration lock: %w", err)
	}
	if err == nil || !definite(err) {
		// The journal says the lock was requested, and keeps saying so.
		m.lockUnknown = true
		if err == nil {
			err = errors.New("PVE answered without a lock token")
		}
		return fmt.Errorf("take PVE's SDN configuration lock: %w: %v", ErrSDNLockUnknown, err)
	}
	// PVE's own message says why; the error's text also names the request
	// path, which contains "lock".
	message := apiMessage(err)
	switch {
	case strings.Contains(message, "pending"):
		// No lock stands: none is this manager's, or a lost request's.
		m.lockToken, m.lockHeld, m.lockUnknown = "", false, false
		m.noteRefusal()
		return m.pendingError(ctx, err)
	case strings.Contains(message, "invalid lock token"):
		m.noteRefusal()
		return fmt.Errorf("take PVE's SDN configuration lock: %w. PVE: %v", ErrSDNLockHeld, err)
	case strings.Contains(message, "lock"):
		m.noteRefusal()
		return fmt.Errorf("take PVE's SDN configuration lock: %w. PVE: %v", errSDNLockBusy, err)
	default:
		m.noteRefusal()
		return fmt.Errorf("take PVE's SDN configuration lock: %w", err)
	}
}

// definite reports whether err is PVE's own answer, so that a request it
// refused changed nothing: an HTTP error status, other than a gateway's or
// pveproxy's report of a request or reply lost in transit. A transport
// error, a reply that cannot be read, or a cancelled request is not.
func definite(err error) bool {
	var apiErr *pve.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, 596, 597:
		return false
	}
	return true
}

// apiMessage is PVE's message in err, lower-cased, or "".
func apiMessage(err error) string {
	var apiErr *pve.APIError
	if errors.As(err, &apiErr) {
		return strings.ToLower(apiErr.Message)
	}
	return ""
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// pendingError is the refusal to lock over pending changes, naming them
// when they can be read.
func (m *Manager) pendingError(ctx context.Context, cause error) error {
	names := ""
	if pending, err := m.PendingChanges(ctx); err == nil && len(pending) > 0 {
		names = " (" + strings.Join(pending, ", ") + ")"
	}
	return fmt.Errorf("%w%s. Applying the sandbox network would apply them too, on every node, so CertiStack does not. "+PendingChangesAdvice+" PVE: %v", ErrPendingSDNChanges, names, cause)
}

// pendingEntry is one zone, VNet, controller or subnet with a change nobody
// applied. vnet is a subnet's VNet, "" for the other kinds.
type pendingEntry struct{ kind, id, state, vnet string }

func (e pendingEntry) String() string { return fmt.Sprintf("%s %s (%s)", e.kind, e.id, e.state) }

// maxForeignVNetsRead bounds the requests of the subnet read: a run on a PVE
// without an SDN lock reads the pending subnets of every VNet the cluster lists
// (one request each), the run's own always and the others up to this many. A
// cluster with more VNets than that cannot be shown to have no unapplied subnet
// change, and the guard then refuses (see pendingSubnets).
const maxForeignVNetsRead = 64

// pendingEntries reads the zones, VNets and controllers with changes that
// have not been applied. PVE reports more kinds of SDN object; these are the
// ones an administrator most often edits. On a PVE without an SDN lock (PVE 8)
// the subnets are read as well (pendingSubnets): there the lock does not stand
// guard over the objects this read does not see.
func (m *Manager) pendingEntries(ctx context.Context) ([]pendingEntry, error) {
	var pending []pendingEntry
	// vnets are all the VNets the cluster lists, changed or not: the pending
	// read lists every VNet, with a state on the changed ones only.
	var vnets []pendingEntry
	for _, list := range []struct{ kind, path, key string }{
		{"zone", "cluster/sdn/zones?pending=1", "zone"},
		{"VNet", "cluster/sdn/vnets?pending=1", "vnet"},
		{"controller", "cluster/sdn/controllers?pending=1", "controller"},
	} {
		entries, err := m.readList(ctx, list.path)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			// An entry is read in full or the read is an error: one whose
			// identity or state is malformed could be an administrator's
			// pending change, and "nothing pending" would let an apply
			// commit it. A state that is absent is an unchanged entry.
			id, err := entryString(entry, list.key)
			if err != nil || id == "" {
				return nil, fmt.Errorf("PVE's list %s has an entry without a usable %q, so the cluster's pending SDN changes cannot be read in full", list.path, list.key)
			}
			state, err := entryString(entry, "state")
			if err != nil {
				return nil, fmt.Errorf("PVE's list %s has a malformed state for %s %q, so the cluster's pending SDN changes cannot be read in full", list.path, list.kind, id)
			}
			if list.kind == "VNet" {
				vnets = append(vnets, pendingEntry{kind: list.kind, id: id, state: state})
			}
			if state == "" {
				continue
			}
			pending = append(pending, pendingEntry{kind: list.kind, id: id, state: state})
		}
	}
	if m.noLockAPI {
		subnets, err := m.pendingSubnets(ctx, vnets)
		if err != nil {
			return nil, err
		}
		pending = append(pending, subnets...)
	}
	return pending, nil
}

// pendingSubnets reads, for each VNet the cluster lists, the subnets with
// changes that have not been applied (GET cluster/sdn/vnets/<vnet>/subnets
// ?pending=1). A subnet change is not a change of its VNet, so the VNet list
// does not show it; without PVE's lock to refuse an apply over it, an
// administrator's unapplied subnet would be applied with the run's.
//
// The requests are one per VNet: the run's own VNets always, the others up to
// maxForeignVNetsRead. A VNet that is pending deletion is not read (it is gone
// from the configuration, and its own entry is the change). Beyond the bound,
// or when any read fails, this is an error and not "nothing pending": a list
// nobody could read, or read in part, proves nothing about the rest.
func (m *Manager) pendingSubnets(ctx context.Context, vnets []pendingEntry) ([]pendingEntry, error) {
	var own, others []string
	seen := map[string]bool{}
	for _, vnet := range vnets {
		if vnet.state == "deleted" || seen[strings.ToLower(vnet.id)] {
			continue
		}
		seen[strings.ToLower(vnet.id)] = true
		if m.owns("VNet", vnet.id) {
			own = append(own, vnet.id)
		} else {
			others = append(others, vnet.id)
		}
	}
	if len(others) > maxForeignVNetsRead {
		return nil, fmt.Errorf("the cluster has %d VNets besides the run's own, more than the %d whose pending subnets CertiStack reads, so it cannot show that none has an unapplied subnet change and, with no SDN lock to refuse an apply over one, does not change SDN. Use a pre-provisioned sandbox (network.lifecycle: preprovisioned), which changes nothing", len(others), maxForeignVNetsRead)
	}
	var pending []pendingEntry
	for _, vnet := range append(own, others...) {
		subnets, err := m.readList(ctx, "cluster/sdn/vnets/"+url.PathEscape(vnet)+"/subnets?pending=1")
		if err != nil {
			return nil, fmt.Errorf("read the pending subnets of VNet %s: %w", vnet, err)
		}
		for _, entry := range subnets {
			id := ""
			for _, key := range []string{"subnet", "cidr", "id"} {
				if value, err := entryString(entry, key); err == nil && value != "" {
					id = value
					break
				}
			}
			if id == "" {
				return nil, fmt.Errorf("a subnet of VNet %s in PVE's pending read names no subnet, so its pending SDN changes cannot be read in full", vnet)
			}
			state, err := entryString(entry, "state")
			if err != nil {
				return nil, fmt.Errorf("PVE's pending read of VNet %s has a malformed state for subnet %q, so its pending SDN changes cannot be read in full", vnet, id)
			}
			if state == "" {
				continue
			}
			pending = append(pending, pendingEntry{kind: "subnet", id: vnet + "/" + id, state: state, vnet: vnet})
		}
	}
	return pending, nil
}

// PendingChanges lists the zones, VNets and controllers with changes that
// have not been applied, as "zone csLab70 (new)".
func (m *Manager) PendingChanges(ctx context.Context) ([]string, error) {
	entries, err := m.pendingEntries(ctx)
	if err != nil {
		return nil, err
	}
	var pending []string
	for _, entry := range entries {
		pending = append(pending, entry.String())
	}
	sort.Strings(pending)
	return pending, nil
}

// ForeignPending lists the pending changes that are not to a zone or VNet
// this manager's run owns (SetOwnObjects). Any controller change is foreign.
func (m *Manager) ForeignPending(ctx context.Context) ([]string, error) {
	entries, err := m.pendingEntries(ctx)
	if err != nil {
		return nil, err
	}
	var foreign []string
	for _, entry := range entries {
		if !m.ownsEntry(entry) {
			foreign = append(foreign, entry.String())
		}
	}
	sort.Strings(foreign)
	return foreign, nil
}

// ownsEntry reports whether a pending change is to something this manager's run
// owns: its zone or VNet, or a subnet of its VNet. Any other kind (a controller)
// is foreign.
func (m *Manager) ownsEntry(entry pendingEntry) bool {
	if entry.kind == "subnet" {
		return m.owns("VNet", entry.vnet)
	}
	return m.owns(entry.kind, entry.id)
}

// owns reports whether the zone or VNet (kind "zone" or "VNet") is one this
// manager's run owns (SetOwnObjects).
func (m *Manager) owns(kind, id string) bool {
	var own []string
	switch kind {
	case "zone":
		own = m.ownZones
	case "VNet":
		own = m.ownVNets
	}
	for _, o := range own {
		if strings.EqualFold(o, id) {
			return true
		}
	}
	return false
}

// OwnUnappliedOnly reports whether the pending changes, read now, are all and
// only the run's own never-applied creations: there is at least one, each is
// to a zone or VNet the run owns and is new (never applied), and every one of
// the zones and vnets named is among them. Only then does deleting those
// objects without PVE's lock leave nothing pending. The states are the ones
// PVE gives with this read, not an earlier one: an object applied since (by
// an administrator's apply) is no longer new, and its deletion would be a
// pending change nobody applies.
func (m *Manager) OwnUnappliedOnly(ctx context.Context, zones, vnets []string) (bool, error) {
	entries, err := m.pendingEntries(ctx)
	if err != nil {
		return false, err
	}
	if len(entries) == 0 {
		return false, nil
	}
	isNew := map[string]bool{}
	for _, entry := range entries {
		if entry.state != "new" || !m.ownsEntry(entry) {
			return false, nil
		}
		isNew[entry.kind+"/"+strings.ToLower(entry.id)] = true
	}
	for _, id := range zones {
		if !isNew["zone/"+strings.ToLower(id)] {
			return false, nil
		}
	}
	for _, id := range vnets {
		if !isNew["VNet/"+strings.ToLower(id)] {
			return false, nil
		}
	}
	return true, nil
}

// LockToken is the token of the SDN lock the manager holds, or "".
func (m *Manager) LockToken() string { return m.lockToken }

// AdoptLock makes the manager use a lock taken earlier, as recorded in a
// run's journal. Whether it still stands is unknown until EnsureLock asks.
// A manager that knows its PVE has no SDN lock (NoLockAPI) adopts nothing:
// there is no lock for a token to be.
func (m *Manager) AdoptLock(token string) {
	if m.noLockAPI {
		return
	}
	m.lockToken, m.lockHeld = token, false
}

// AdoptLockRequest records a lock request, from a run's journal, whose
// answer never came: until PVE grants a lock or refuses one over pending
// changes (either proves no lock stands), the lock may be standing for it.
// PVE answering the lock path as missing (NoLockAPI) proves it too.
func (m *Manager) AdoptLockRequest() {
	if m.noLockAPI {
		return
	}
	m.lockUnknown = true
}

// LockRequestUnresolved reports a lock request whose answer never came and
// that no later answer has settled.
func (m *Manager) LockRequestUnresolved() bool { return m.lockUnknown }

// Unlock releases the SDN lock without applying anything. PVE releases a
// lock only for its own token, and answers "invalid lock token" while
// another stands: either way the manager holds none after. Any other
// failure keeps the token, journaled, for a later release.
func (m *Manager) Unlock(ctx context.Context) error {
	if m.lockToken == "" {
		return nil
	}
	m.unlockedForeign = false
	err := m.client.Do(ctx, "DELETE", lockEndpoint+"?lock-token="+url.QueryEscape(m.lockToken), nil, nil)
	switch {
	case err == nil:
	case definite(err) && strings.Contains(apiMessage(err), "invalid lock token"):
		slog.Warn("PVE's SDN lock is another client's: the lock CertiStack held was released already", "error", err)
		m.unlockedForeign = true
	default:
		if !definite(err) {
			// The release may have happened.
			m.lockHeld = false
		}
		return fmt.Errorf("release PVE's SDN configuration lock: %w", err)
	}
	m.lockToken, m.lockHeld = "", false
	return m.note(false)
}

// UnlockedForeign reports that the last Unlock found PVE's lock to be another
// client's: the lock the manager held had been released already.
func (m *Manager) UnlockedForeign() bool { return m.unlockedForeign }

// ReleaseAdoptedToken releases the lock token adopted from a run's journal
// (AdoptLock), as Unlock does, and understands one more answer: a journal
// written by a run on a PVE with an SDN lock (PVE 9), recovered against a PVE
// without one (PVE 8, say after the cluster was reinstalled), holds a token that
// nothing can hold, and the release of it is answered as a missing endpoint
// (HTTP 501, or 404).
//
// That answer to the release is not taken for the proof: a proxy or another
// build may say 404 for a PVE that has the lock, and dropping a token that
// still holds a lock would leave it standing for good. Only PVE's answer to a
// request for the lock itself says whether the lock API exists (tryLock, the one
// place that reads it): when that is answered as missing too the manager enters
// the no-lock mode, which drops the token and journals that, and noLockAPI is
// true. When the request is granted a lock, or refused over pending changes,
// no lock stood (PVE grants one only while none stands, and refuses over
// pending changes only then), so nothing held the token either and it is
// dropped; the lock the request was granted is released again. In every other
// case the lock may stand: the error of the release is returned, and the token
// is kept. An error of the release that is not a missing endpoint is returned
// as it is, as Unlock gives it. Only the release of this path is read so: a 404
// or 501 anywhere else is an error as it always was.
func (m *Manager) ReleaseAdoptedToken(ctx context.Context) (noLockAPI bool, err error) {
	err = m.Unlock(ctx)
	if err == nil {
		return m.noLockAPI, nil
	}
	if !lockEndpointMissing(err) {
		return false, err
	}
	adopted := m.lockToken
	probeErr := m.tryLock(ctx)
	switch {
	case m.noLockAPI:
		// Whatever the pending reads found there (the guard enterNoLockAPI ends
		// with) is the next write's to refuse: nothing is written here.
		return true, nil
	case probeErr == nil:
		// A lock was granted: none stood, and the token held nothing. Give the
		// probe's own lock back.
		if err := m.Unlock(ctx); err != nil {
			return false, err
		}
		m.unlockedForeign = true
		return false, nil
	case errors.Is(probeErr, ErrPendingSDNChanges):
		m.unlockedForeign = true
		return false, nil
	}
	m.lockToken, m.lockHeld = adopted, false
	return false, fmt.Errorf("%w; PVE's answer to a request for the lock, asked to tell a PVE without an SDN lock from one that has it, was: %v", err, probeErr)
}

// release gives the lock back when its token cannot be journaled.
func (m *Manager) release(ctx context.Context) error {
	if err := m.client.Do(ctx, "DELETE", lockEndpoint+"?lock-token="+url.QueryEscape(m.lockToken), nil, nil); err != nil {
		return fmt.Errorf("release PVE's SDN configuration lock, whose token is not journaled: %w", err)
	}
	m.lockToken, m.lockHeld = "", false
	return nil
}

// locked adds the lock token to a write's parameters, when one is held.
func (m *Manager) locked(body map[string]interface{}) map[string]interface{} {
	if m.lockToken != "" {
		body["lock-token"] = m.lockToken
	}
	return body
}

// lockedPath adds the lock token to a DELETE's query, when one is held.
func (m *Manager) lockedPath(path string) string {
	if m.lockToken == "" {
		return path
	}
	return path + "?lock-token=" + url.QueryEscape(m.lockToken)
}

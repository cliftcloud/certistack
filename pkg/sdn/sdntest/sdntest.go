// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package sdntest is a fake of PVE's SDN API for tests: the SDN
// configuration, the running configuration its last apply made, and the
// global SDN lock, with PVE's own semantics (pve-network ce388c5,
// src/PVE/Network/SDN.pm and src/PVE/API2/Network/SDN.pm):
//
//   - every write checks the lock first: while a lock stands, a write whose
//     token is not the lock's is refused ("invalid lock token provided!");
//     while none stands, any token, or none, is taken;
//   - the lock is granted only while none stands and nothing is pending,
//     and a refusal over pending changes therefore means none stands;
//   - a zone or VNet whose ID is defined already is not created again;
//   - an apply commits the whole configuration and, with release-lock,
//     releases the lock in the same step;
//   - a release with the lock's token, or while none stands, succeeds.
//
// PVE.NoLockAPI turns the fake into a PVE 8, which has no SDN lock at all.
//
// Faults are injected per request ("METHOD path", the path after
// /api2/json/ without its query): refused before it is made, made and its
// reply then lost, truncated, or delayed, or answered with success without
// being made.
package sdntest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// Fault is what happens to one request.
type Fault struct {
	// Refuse answers HTTP Status (500 when 0) with this message, and makes
	// no change.
	Refuse string
	Status int
	// Lose makes the change, then closes the connection without a reply.
	Lose bool
	// Truncate makes the change, then answers with cut-off JSON.
	Truncate bool
	// Delay makes the change, then waits this long before the reply.
	Delay time.Duration
	// Answer makes the change, then answers this JSON as the data.
	Answer string
	// Before runs first, with the fake's lock not held.
	Before func()
	// Skip answers success and makes no change: a delete whose reply is not
	// proof that the object is gone.
	Skip bool
}

// PVE is the fake. Its exported maps may be set before the first request
// and read after the last; during requests, use Do.
type PVE struct {
	mu sync.Mutex

	// Zones and VNets (VNet to zone) and Subnets (VNet to subnet IDs) in
	// the configuration, and as the last apply left them running.
	Zones, RunningZones     map[string]bool
	VNets, RunningVNets     map[string]string
	Subnets, RunningSubnets map[string][]string
	// Aliases is each VNet's alias (its free-text field), as POST vnets sets it,
	// and RunningAliases as the last apply left them. PVE's pending view shows a
	// running VNet whose deletion is not applied with its running values, so its
	// alias stays readable until the deletion is applied.
	Aliases, RunningAliases map[string]string
	// ChangedSubnets are subnets whose configuration differs from the running
	// one in a property (the fake models no properties): keyed "vnet/subnet",
	// they are pending with the state "changed" until an apply commits them.
	ChangedSubnets map[string]bool
	// Lock is the standing lock's token, "" for none.
	Lock string
	// TaskStatus is the answer to a task status read.
	TaskStatus pve.TaskStatus
	// Tasks is the cluster's task list (GET cluster/tasks), as PVE gives it:
	// each entry {"type": "reloadnetworkall", "endtime": 0 while running, ...}.
	Tasks []map[string]interface{}
	// Faults are consumed by the first matching request, in order.
	Faults map[string][]Fault
	// Requests lists every request: "METHOD path?query body".
	Requests []string
	// Applies counts committed applies.
	Applies int
	// OnRequest, when set, sees every request before it is handled, with
	// the fake's lock not held.
	OnRequest func(method, path string, query map[string]string)

	// NoLockAPI makes the fake a PVE 8, which has no SDN lock (checked on PVE
	// 8.4.0: pvesh answers "no such resource" for /cluster/sdn/lock): POST and
	// DELETE cluster/sdn/lock are answered "Method '<verb> /cluster/sdn/lock'
	// not implemented" with NoLockStatus (501, as PVE's HTTP layer does, when
	// 0; 404 is what a proxy may say), and any request that carries a
	// lock-token or release-lock parameter, in its body or its query, is refused
	// with HTTP 400 as PVE 8's schema refuses a parameter it does not define,
	// so that a leftover token fails the test that sent it.
	NoLockAPI    bool
	NoLockStatus int

	tokens int
}

// New is an empty cluster: no SDN object, no lock, tasks ended OK.
func New() *PVE {
	return &PVE{
		Zones: map[string]bool{}, RunningZones: map[string]bool{},
		VNets: map[string]string{}, RunningVNets: map[string]string{},
		Subnets: map[string][]string{}, RunningSubnets: map[string][]string{},
		Aliases: map[string]string{}, RunningAliases: map[string]string{}, ChangedSubnets: map[string]bool{},
		TaskStatus: pve.TaskStatus{Status: "stopped", ExitStatus: "OK"},
		Faults:     map[string][]Fault{},
	}
}

// Applied adds a zone and a VNet with one subnet, configured and running.
func (p *PVE) Applied(zone, vnet, subnet string) *PVE {
	p.Zones[zone], p.RunningZones[zone] = true, true
	p.VNets[vnet], p.RunningVNets[vnet] = zone, zone
	p.Subnets[vnet] = []string{subnet}
	p.RunningSubnets[vnet] = []string{subnet}
	return p
}

// Do runs fn with the fake's state locked.
func (p *PVE) Do(fn func(p *PVE)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(p)
}

// Fault queues a fault for the next request matching key.
func (p *PVE) Fault(key string, fault Fault) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Faults[key] = append(p.Faults[key], fault)
}

// Writes are the requests that are not reads.
func (p *PVE) Writes() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, r := range p.Requests {
		if !strings.HasPrefix(r, "GET ") {
			out = append(out, r)
		}
	}
	return out
}

// Pending reports whether the configuration differs from the running one.
func (p *PVE) Pending() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pending()
}

func (p *PVE) pending() bool {
	return fmt.Sprint(p.Zones) != fmt.Sprint(p.RunningZones) ||
		fmt.Sprint(p.VNets) != fmt.Sprint(p.RunningVNets) ||
		fmt.Sprint(p.Subnets) != fmt.Sprint(p.RunningSubnets) ||
		len(p.ChangedSubnets) > 0
}

// Serve starts the fake and returns a client for it.
func (p *PVE) Serve(t *testing.T) *pve.Client {
	t.Helper()
	return pve.NewClient(pve.Config{BaseURL: p.Start(t).URL})
}

// Start starts the fake's server.
func (p *PVE) Start(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(p.serveHTTP))
	t.Cleanup(server.Close)
	return server
}

type apiError struct {
	status  int
	message string
	// fields are PVE's per-parameter errors (the "errors" member of a 400).
	fields map[string]string
}

// pve8Schema is what PVE 8's API does with a request that carries a parameter
// of the SDN lock, which its endpoints do not define.
func (p *PVE) pve8Schema(method, path string, params map[string]string) *apiError {
	if path == "cluster/sdn/lock" {
		status := p.NoLockStatus
		if status == 0 {
			status = http.StatusNotImplemented
		}
		return &apiError{status: status, message: fmt.Sprintf("Method '%s /%s' not implemented", method, path)}
	}
	fields := map[string]string{}
	for _, name := range []string{"lock-token", "release-lock"} {
		if _, ok := params[name]; ok {
			fields[name] = "property is not defined in schema and the schema does not allow additional properties"
		}
	}
	if len(fields) > 0 {
		return &apiError{status: http.StatusBadRequest, message: "Parameter verification failed.", fields: fields}
	}
	return nil
}

func (p *PVE) serveHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api2/json/")
	body, _ := io.ReadAll(r.Body)
	params := map[string]string{}
	for key := range r.URL.Query() {
		params[key] = r.URL.Query().Get(key)
	}
	var fields map[string]interface{}
	_ = json.Unmarshal(body, &fields)
	for key, value := range fields {
		params[key] = fmt.Sprint(value)
	}
	line := r.Method + " " + path
	if r.URL.RawQuery != "" {
		line += "?" + r.URL.RawQuery
	}
	if len(body) > 2 {
		line += " " + string(body)
	}

	p.mu.Lock()
	p.Requests = append(p.Requests, line)
	key := r.Method + " " + path
	var fault Fault
	if queue := p.Faults[key]; len(queue) > 0 {
		fault, p.Faults[key] = queue[0], queue[1:]
	}
	hook := p.OnRequest
	p.mu.Unlock()
	if hook != nil {
		hook(r.Method, path, params)
	}
	if fault.Before != nil {
		fault.Before()
	}
	if fault.Refuse != "" {
		status := fault.Status
		if status == 0 {
			status = http.StatusInternalServerError
		}
		writeJSON(w, status, map[string]interface{}{"data": nil, "message": fault.Refuse + "\n"})
		return
	}

	var data interface{}
	var failure *apiError
	if !fault.Skip {
		p.mu.Lock()
		data, failure = p.handle(r.Method, path, params)
		p.mu.Unlock()
	}

	switch {
	case fault.Lose:
		if hijacker, ok := w.(http.Hijacker); ok {
			if conn, _, err := hijacker.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		panic("sdntest: cannot drop the connection")
	case fault.Truncate:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":"to`)
		return
	case fault.Answer != "":
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":`+fault.Answer+`}`)
		return
	case fault.Delay > 0:
		time.Sleep(fault.Delay)
	}
	if failure != nil {
		reply := map[string]interface{}{"data": nil, "message": failure.message + "\n"}
		if len(failure.fields) > 0 {
			reply["errors"] = failure.fields
		}
		writeJSON(w, failure.status, reply)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": data})
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// checkToken is PVE's lock_sdn_config: a standing lock admits only its own
// token.
func (p *PVE) checkToken(params map[string]string, errmsg string) *apiError {
	if p.Lock != "" && params["lock-token"] != p.Lock {
		return &apiError{status: http.StatusInternalServerError, message: errmsg + ": invalid lock token provided!"}
	}
	return nil
}

func (p *PVE) handle(method, path string, params map[string]string) (interface{}, *apiError) {
	parts := strings.Split(path, "/")
	if p.NoLockAPI {
		if err := p.pve8Schema(method, path, params); err != nil {
			return nil, err
		}
	}
	switch {
	case method == "POST" && path == "cluster/sdn/lock":
		if err := p.checkToken(map[string]string{}, "could not acquire lock for SDN config"); err != nil {
			return nil, err
		}
		if p.pending() {
			return nil, &apiError{status: http.StatusInternalServerError, message: "could not acquire lock for SDN config: configuration has pending changes"}
		}
		p.tokens++
		p.Lock = fmt.Sprintf("tok-%d", p.tokens)
		return p.Lock, nil
	case method == "DELETE" && path == "cluster/sdn/lock":
		if params["force"] != "1" {
			if err := p.checkToken(params, "could not release lock"); err != nil {
				return nil, err
			}
		}
		p.Lock = ""
		return nil, nil
	case method == "PUT" && path == "cluster/sdn":
		if err := p.checkToken(params, "could not commit SDN config"); err != nil {
			return nil, err
		}
		p.RunningZones, p.RunningVNets, p.RunningSubnets = copyBools(p.Zones), copyStrings(p.VNets), copySubnets(p.Subnets)
		p.RunningAliases = copyStrings(p.Aliases)
		p.ChangedSubnets = map[string]bool{}
		if params["lock-token"] != "" && params["release-lock"] != "0" {
			p.Lock = ""
		}
		p.Applies++
		return fmt.Sprintf("UPID:node1:%08X:1:1:reloadnetworkall::root@pam:", p.Applies), nil
	case method == "GET" && path == "cluster/sdn/zones":
		return p.list("zone", keys(p.Zones), keys(p.RunningZones), nil, nil, params["pending"] == "1"), nil
	case method == "GET" && path == "cluster/sdn/vnets":
		out := p.list("vnet", keysS(p.VNets), keysS(p.RunningVNets), p.VNets, p.RunningVNets, params["pending"] == "1")
		for _, entry := range out {
			if alias := p.Aliases[entry["vnet"]]; alias != "" {
				entry["alias"] = alias
			} else if alias := p.RunningAliases[entry["vnet"]]; alias != "" && params["pending"] == "1" && entry["state"] == "deleted" {
				entry["alias"] = alias
			}
		}
		return out, nil
	case method == "GET" && path == "cluster/sdn/controllers":
		return []interface{}{}, nil
	case method == "GET" && path == "cluster/tasks":
		tasks := p.Tasks
		if tasks == nil {
			tasks = []map[string]interface{}{}
		}
		return tasks, nil
	case method == "GET" && path == "nodes":
		return []map[string]string{{"node": "node1"}}, nil
	case method == "GET" && len(parts) == 5 && parts[0] == "nodes" && parts[2] == "tasks" && parts[4] == "status":
		return p.TaskStatus, nil
	case len(parts) == 5 && parts[2] == "vnets" && parts[4] == "subnets":
		vnet := parts[3]
		if _, ok := p.VNets[vnet]; !ok {
			return nil, &apiError{status: http.StatusInternalServerError, message: fmt.Sprintf("sdn vnet '%s' does not exist", vnet)}
		}
		switch method {
		case "GET":
			if params["pending"] == "1" {
				// Every subnet configured or running, with its state as PVE
				// gives it (absent when unchanged).
				return p.pendingSubnets(vnet), nil
			}
			out := []map[string]string{}
			for _, id := range p.Subnets[vnet] {
				out = append(out, map[string]string{"id": id, "subnet": id, "vnet": vnet, "type": "subnet"})
			}
			return out, nil
		case "POST":
			if err := p.checkToken(params, "create sdn subnet object failed"); err != nil {
				return nil, err
			}
			id := p.VNets[vnet] + "-" + strings.ReplaceAll(params["subnet"], "/", "-")
			p.Subnets[vnet] = append(p.Subnets[vnet], id)
			return nil, nil
		}
	case method == "DELETE" && len(parts) == 6 && parts[2] == "vnets" && parts[4] == "subnets":
		if err := p.checkToken(params, "delete sdn subnet object failed"); err != nil {
			return nil, err
		}
		vnet, id := parts[3], parts[5]
		var kept []string
		found := false
		for _, s := range p.Subnets[vnet] {
			if s == id {
				found = true
				continue
			}
			kept = append(kept, s)
		}
		if !found {
			return nil, &apiError{status: http.StatusInternalServerError, message: fmt.Sprintf("sdn subnet '%s' does not exist", id)}
		}
		if len(kept) == 0 {
			delete(p.Subnets, vnet)
		} else {
			p.Subnets[vnet] = kept
		}
		return nil, nil
	case method == "DELETE" && len(parts) == 4 && parts[2] == "vnets":
		if err := p.checkToken(params, "delete sdn vnet object failed"); err != nil {
			return nil, err
		}
		vnet := parts[3]
		if _, ok := p.VNets[vnet]; !ok {
			return nil, &apiError{status: http.StatusInternalServerError, message: fmt.Sprintf("sdn vnet '%s' does not exist", vnet)}
		}
		if len(p.Subnets[vnet]) > 0 {
			return nil, &apiError{status: http.StatusInternalServerError, message: "delete sdn vnet object failed: 400 Parameter verification failed."}
		}
		// A running VNet keeps its running alias until the deletion is applied
		// (tests often set Aliases for a VNet they made running directly).
		if _, running := p.RunningVNets[vnet]; running && p.RunningAliases[vnet] == "" {
			p.RunningAliases[vnet] = p.Aliases[vnet]
		}
		delete(p.VNets, vnet)
		delete(p.Aliases, vnet)
		return nil, nil
	case method == "DELETE" && len(parts) == 4 && parts[2] == "zones":
		if err := p.checkToken(params, "delete sdn zone object failed"); err != nil {
			return nil, err
		}
		zone := parts[3]
		if !p.Zones[zone] {
			return nil, &apiError{status: http.StatusInternalServerError, message: fmt.Sprintf("sdn zone '%s' does not exist", zone)}
		}
		for vnet, z := range p.VNets {
			if z == zone {
				return nil, &apiError{status: http.StatusInternalServerError, message: fmt.Sprintf("delete sdn zone object failed: zone %s is used by vnet %s", zone, vnet)}
			}
		}
		delete(p.Zones, zone)
		return nil, nil
	case method == "POST" && path == "cluster/sdn/zones":
		if err := p.checkToken(params, "create sdn zone object failed"); err != nil {
			return nil, err
		}
		if p.Zones[params["zone"]] {
			return nil, &apiError{status: http.StatusInternalServerError, message: fmt.Sprintf("create sdn zone object failed: sdn zone object ID '%s' already defined", params["zone"])}
		}
		p.Zones[params["zone"]] = true
		return nil, nil
	case method == "POST" && path == "cluster/sdn/vnets":
		if err := p.checkToken(params, "create sdn vnet object failed"); err != nil {
			return nil, err
		}
		if _, ok := p.VNets[params["vnet"]]; ok {
			return nil, &apiError{status: http.StatusInternalServerError, message: fmt.Sprintf("create sdn vnet object failed: sdn vnet object ID '%s' already defined", params["vnet"])}
		}
		p.VNets[params["vnet"]] = params["zone"]
		if params["alias"] != "" {
			p.Aliases[params["vnet"]] = params["alias"]
		}
		return nil, nil
	}
	return nil, &apiError{status: http.StatusNotImplemented, message: fmt.Sprintf("sdntest: %s %s is not faked", method, path)}
}

// pendingSubnets is PVE's pending list of one VNet's subnets: those configured
// or running, "new" when only configured, "deleted" when only running, and
// "changed" for ChangedSubnets.
func (p *PVE) pendingSubnets(vnet string) []map[string]string {
	state := map[string]string{}
	running := map[string]bool{}
	for _, id := range p.RunningSubnets[vnet] {
		running[id] = true
		state[id] = "deleted"
	}
	for _, id := range p.Subnets[vnet] {
		switch {
		case !running[id]:
			state[id] = "new"
		case p.ChangedSubnets[vnet+"/"+id]:
			state[id] = "changed"
		default:
			state[id] = ""
		}
	}
	out := []map[string]string{}
	for _, id := range sortedKeys(state) {
		entry := map[string]string{"id": id, "subnet": id, "vnet": vnet, "type": "subnet"}
		if state[id] != "" {
			entry["state"] = state[id]
		}
		out = append(out, entry)
	}
	return out
}

// list is PVE's list of zones or VNets: the configured ones, or with
// pending=1 every one configured or running, with its state.
func (p *PVE) list(key string, config, running []string, configZone, runningZone map[string]string, pending bool) []map[string]string {
	ids := map[string]string{}
	for _, id := range config {
		ids[id] = ""
	}
	if pending {
		inRunning := map[string]bool{}
		for _, id := range running {
			inRunning[id] = true
			if _, ok := ids[id]; !ok {
				ids[id] = "deleted"
			}
		}
		for _, id := range config {
			if !inRunning[id] {
				ids[id] = "new"
			}
		}
	}
	out := []map[string]string{}
	for _, id := range sortedKeys(ids) {
		entry := map[string]string{key: id}
		if ids[id] != "" {
			entry["state"] = ids[id]
		}
		if zone := configZone[id]; zone != "" {
			entry["zone"] = zone
		} else if zone := runningZone[id]; zone != "" {
			entry["zone"] = zone
		}
		out = append(out, entry)
	}
	return out
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keysS(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]string) []string { return keysS(m) }

func copyBools(m map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyStrings(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copySubnets(m map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range m {
		out[k] = append([]string(nil), v...)
	}
	return out
}

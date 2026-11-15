// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseTaskReadsOnlyAFullHandle(t *testing.T) {
	task, ok := ParseTask("UPID:pve1:0000A1B2:00C3D4E5:66A1B2C3:qmdestroy:9102:root@pam!certistack:")
	if !ok || task != (TaskHandle{Node: "pve1", Type: "qmdestroy", ID: "9102", User: "root@pam!certistack"}) {
		t.Fatalf("ParseTask = %+v, %v", task, ok)
	}
	// A task without an object (an SDN apply) is still a full handle.
	if task, ok := ParseTask("UPID:pve1:00000001:00000002:00000003:reloadnetworkall::root@pam:"); !ok || task.Type != "reloadnetworkall" || task.ID != "" {
		t.Fatalf("ParseTask of an SDN apply = %+v, %v", task, ok)
	}
	for _, handle := range []string{
		"", "OK", "UPID::pid:task", "UPID:pve1:pid:", "UPID:pve1:test:task", "UPID:pve1:1:1:1:1:1:",
		"UPID:pve1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9102:root@pam",       // no closing colon
		"UPID:pve1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9102:root@pam::",     // extra field
		"UPID:pve1:xyz:00C3D4E5:66A1B2C3:qmstop:9102:root@pam:",           // pid not hexadecimal
		"UPID:pve1:0000A1B2:00C3D4E5:66A1B2C3::9102:root@pam:",            // no type
		"UPID:pve1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9102::",              // no user
		"UPID:pve/1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9102:root@pam:",     // node that alters a path
		"XPID:pve1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9102:root@pam:",      // not a UPID
		"UPID:pve1:0000A1B2:00C3D4E5:66A1B2C3:qmstop: 9102:root@pam:foo:", // one field too many
	} {
		if task, ok := ParseTask(handle); ok {
			t.Errorf("ParseTask(%q) = %+v, want it refused as not a full handle", handle, task)
		}
	}
}

// StopVM and DestroyVM returned whatever handle PVE's envelope held,
// and callers took the success of that task for the VM's stop or removal. A
// full handle must now be the operation's own task for the VM.
func TestStopAndDestroyVMBindTheTaskToTheOperationAndTheVM(t *testing.T) {
	var handle string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": handle})
	}))
	defer server.Close()
	client := NewClient(Config{BaseURL: server.URL})

	const (
		stop    = "UPID:pve1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9102:root@pam:"
		haStop  = "UPID:pve1:0000A1B2:00C3D4E5:66A1B2C3:hastop:9102:root@pam:"
		destroy = "UPID:pve1:0000A1B3:00C3D4E6:66A1B2C4:qmdestroy:9102:root@pam:"
		foreign = "UPID:pve1:00001234:00005678:00000001:vzdump:foreign-backup:root@pam:"
	)
	for name, tc := range map[string]struct {
		handle  string
		destroy bool
		want    string // "" is accepted, else in the error
	}{
		"stop task":                     {handle: stop},
		"stop task of an HA-managed VM": {handle: haStop},
		"unrelated task for a stop":     {handle: foreign, want: `PVE answered the stop of VM 9102 with a "vzdump" task for "foreign-backup"`},
		"another VM's stop task":        {handle: strings.Replace(stop, ":9102:", ":9103:", 1), want: `"qmstop" task for "9103"`},
		"a destroy task for a stop":     {handle: destroy, want: `"qmdestroy" task for "9102", not a stop`},
		"destroy task":                  {handle: destroy, destroy: true},
		"unrelated task for a destroy":  {handle: foreign, destroy: true, want: `PVE answered the destruction of VM 9102 with a "vzdump" task for "foreign-backup"`},
		"a stop task for a destroy":     {handle: stop, destroy: true, want: `"qmstop" task for "9102", not a destruction`},
		"another VM's destroy task":     {handle: strings.Replace(destroy, ":9102:", ":9103:", 1), destroy: true, want: `"qmdestroy" task for "9103"`},
		// A handle that is not in the full form cannot be bound; the VM's own
		// status is the proof, asked by the caller.
		"a short handle": {handle: "UPID:pve1:test:task"},
	} {
		handle = tc.handle
		var err error
		if tc.destroy {
			_, err = client.DestroyVM(context.Background(), "pve1", 9102)
		} else {
			_, err = client.StopVM(context.Background(), "pve1", 9102)
		}
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error %v, want one containing %q", name, err, tc.want)
		}
	}
}

// A status answer that names another task than the one polled is
// refused, not read as this task's success.
func TestWaitForTaskRefusesAStatusOfAnotherTask(t *testing.T) {
	const handle = "UPID:pve1:0000A1B3:00C3D4E6:66A1B2C4:qmdestroy:9102:root@pam:"
	var status map[string]any
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": status})
	}))
	defer server.Close()
	client := NewClient(Config{BaseURL: server.URL})

	for name, tc := range map[string]struct {
		status map[string]any
		want   string
	}{
		"its own status":                   {status: map[string]any{"status": "stopped", "exitstatus": "OK", "node": "pve1", "type": "qmdestroy", "id": "9102"}},
		"a status that names nothing":      {status: map[string]any{"status": "stopped", "exitstatus": "OK"}},
		"another type":                     {status: map[string]any{"status": "stopped", "exitstatus": "OK", "type": "vzdump", "id": "9102"}, want: `describes a "vzdump" task`},
		"another object":                   {status: map[string]any{"status": "stopped", "exitstatus": "OK", "type": "qmdestroy", "id": "9103"}, want: `for "9103"`},
		"another node":                     {status: map[string]any{"status": "stopped", "exitstatus": "OK", "node": "pve2", "type": "qmdestroy", "id": "9102"}, want: "on pve2"},
		"another task while still running": {status: map[string]any{"status": "running", "type": "vzdump", "id": "9102"}, want: `describes a "vzdump" task`},
	} {
		status = tc.status
		polls = 0
		err := client.WaitForTask(context.Background(), "pve1", handle, 5*time.Millisecond, 2*time.Second)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error %v, want one containing %q", name, err, tc.want)
		case tc.want != "" && polls != 1:
			t.Errorf("%s: polled %d times; a status of another task is final, not retried", name, polls)
		}
	}
}

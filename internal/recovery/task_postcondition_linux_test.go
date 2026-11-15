//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/pve"
)

const (
	taskStop    = "UPID:node1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9102:root@pam:"
	taskDestroy = "UPID:node1:0000A1B3:00C3D4E6:66A1B2C4:qmdestroy:9102:root@pam:"
	// An unrelated backup task of the same node: well shaped, and its
	// status reads stopped/OK. This is the case the original report used.
	taskForeign = "UPID:node1:00001234:00005678:00000001:vzdump:foreign-backup:root@pam:"

	stopCall    = "POST /api2/json/nodes/node1/qemu/9102/status/stop"
	destroyCall = "DELETE /api2/json/nodes/node1/qemu/9102"
)

// taskScenario scripts PVE for sandbox VM 9102 on node1, owned by run
// run-task. The VM answers vmInitial ("running" when unset) until a stop is
// requested, then vmAfterStop, then, once a destroy is requested,
// vmAfterDestroy (vmAfterStop when unset); each is "running", "stopped",
// "gone", "blank" (an answer without a status) or "unreadable" (the read is
// refused). The two handles are what PVE returns for a stop and a destroy;
// taskExit is both tasks' exit status ("OK" when unset).
type taskScenario struct {
	vmInitial, vmAfterStop, vmAfterDestroy string
	stopHandle, destroyHandle              string
	taskExit                               string

	mu        *sync.Mutex // set by serve, so a scenario can be copied
	stage     int
	calls     []string
	taskPolls int
}

func (s *taskScenario) vmAnswer(w http.ResponseWriter) {
	kind := s.vmInitial
	switch s.stage {
	case 1:
		kind = s.vmAfterStop
	case 2:
		kind = s.vmAfterDestroy
		if kind == "" {
			kind = s.vmAfterStop
		}
	}
	if kind == "" {
		kind = "running"
	}
	switch kind {
	case "gone":
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "message": "Configuration file 'nodes/node1/qemu-server/9102.conf' does not exist"})
	case "unreadable":
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "message": "permission denied"})
	case "blank":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"vmid": 9102, "status": kind}})
	}
}

func (s *taskScenario) serve(t *testing.T) {
	t.Helper()
	s.mu = new(sync.Mutex)
	if s.destroyHandle == "" {
		s.destroyHandle = taskDestroy
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		call := r.Method + " " + r.URL.Path
		s.calls = append(s.calls, call)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case call == "GET /api2/json/nodes/node1/qemu/9102/status/current":
			s.vmAnswer(w)
		case call == "GET /api2/json/nodes/node1/qemu/9102/config":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"tags": "certistack,run-task", "description": "owner=certistack; run_id=run-task"}})
		case call == stopCall:
			s.stage = 1
			_ = json.NewEncoder(w).Encode(map[string]any{"data": s.stopHandle})
		case call == destroyCall:
			s.stage = 2
			_ = json.NewEncoder(w).Encode(map[string]any{"data": s.destroyHandle})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/node1/tasks/"):
			s.taskPolls++
			handle := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api2/json/nodes/node1/tasks/"), "/status")
			exit := s.taskExit
			if exit == "" {
				exit = "OK"
			}
			status := map[string]any{"status": "stopped", "exitstatus": exit, "node": "node1"}
			if task, ok := pve.ParseTask(handle); ok { // a status names its own task, as PVE's does
				status["type"], status["id"], status["user"] = task.Type, task.ID, task.User
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": status})
		default:
			t.Errorf("unexpected PVE request %s", call)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("PVE_URL", server.URL)
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "synthetic-token")
	t.Setenv("PVE_TLS_INSECURE", "")
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", "")
}

func (s *taskScenario) requested(call string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		if c == call {
			return true
		}
	}
	return false
}

func taskJournal(t *testing.T) string {
	t.Helper()
	stateDir := t.TempDir()
	record := journal.Record{RunID: "run-task", Phase: "running", UpdatedAt: time.Now().UTC()}
	record.AddVM(9102, "node1", 0, "")
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	return stateDir
}

func journalPhase(t *testing.T, stateDir string) journal.Record {
	t.Helper()
	after, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	return after
}

// Recovery took a task's success for the VM's stop or destruction,
// and cleaned the journal while the VM still ran. The handle PVE returns is
// bound to the operation and the VM, and only the VM's own status, asked
// after each stop and destroy, is the proof: a VM still there or an
// unreadable answer keeps the journal, with the VM's identity, for the retry.
func TestRecoveryRequiresTheVMItselfToShowStoppedAndGone(t *testing.T) {
	for name, tc := range map[string]struct {
		scenario taskScenario
		want     string // in the error
		// wantDestroy is whether the destroy is requested; wantPolls how many
		// times the tasks are polled (a handle refused up front never is).
		wantDestroy bool
		wantPolls   int
	}{
		// The reported case: an unrelated same-node task that reports OK
		// while the VM keeps running.
		"unrelated task answers the stop": {
			scenario: taskScenario{stopHandle: taskForeign, destroyHandle: taskForeign, vmAfterStop: "running"},
			want:     `PVE answered the stop of VM 9102 with a "vzdump" task for "foreign-backup", not a stop of that VM`,
		},
		"unrelated task answers the destroy": {
			scenario:    taskScenario{stopHandle: taskStop, destroyHandle: taskForeign, vmAfterStop: "stopped"},
			want:        `PVE answered the destruction of VM 9102 with a "vzdump" task for "foreign-backup", not a destruction of that VM`,
			wantDestroy: true,
			wantPolls:   1,
		},
		"another VM's stop task": {
			scenario: taskScenario{stopHandle: "UPID:node1:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9103:root@pam:", vmAfterStop: "running"},
			want:     `"qmstop" task for "9103", not a stop of that VM`,
		},
		"the right stop task, and the VM still runs": {
			scenario:  taskScenario{stopHandle: taskStop, vmAfterStop: "running"},
			want:      "recorded VM 9102 on node1 is still running, although its stop task reported success",
			wantPolls: 1,
		},
		"the right stop task, and the VM is unreadable": {
			scenario:  taskScenario{stopHandle: taskStop, vmAfterStop: "unreadable"},
			want:      "recorded VM 9102 on node1 cannot be confirmed stopped, although its stop task reported success",
			wantPolls: 1,
		},
		"the right stop task, and an answer without a status": {
			scenario:  taskScenario{stopHandle: taskStop, vmAfterStop: "blank"},
			want:      "although its stop task reported success",
			wantPolls: 1,
		},
		"the right destroy task, and the VM remains": {
			scenario:    taskScenario{stopHandle: taskStop, vmAfterStop: "stopped"},
			want:        "the destroy task of recorded VM 9102 reported success, but sandbox VM 9102 on node1 still exists (status: stopped)",
			wantDestroy: true,
			wantPolls:   2,
		},
		"the right destroy task, and the VM is unreadable": {
			scenario:    taskScenario{stopHandle: taskStop, vmAfterStop: "stopped", vmAfterDestroy: "unreadable"},
			want:        "the destroy task of recorded VM 9102 reported success, but sandbox VM 9102 on node1 cannot be confirmed gone",
			wantDestroy: true,
			wantPolls:   2,
		},
		"the right destroy task, and an answer without a status": {
			scenario:    taskScenario{stopHandle: taskStop, vmAfterStop: "stopped", vmAfterDestroy: "blank"},
			want:        "the destroy task of recorded VM 9102 reported success, but sandbox VM 9102 on node1 still exists",
			wantDestroy: true,
			wantPolls:   2,
		},
		"a destroy task that failed, and the VM remains": {
			scenario:    taskScenario{vmInitial: "stopped", vmAfterStop: "stopped", taskExit: "unable to remove VM 9102"},
			want:        "still exists (status: stopped)",
			wantDestroy: true,
			wantPolls:   1,
		},
		// Handles PVE could not have issued: nothing is polled or believed.
		"a bare word for a stop handle": {
			scenario: taskScenario{stopHandle: "OK", vmAfterStop: "running"},
			want:     "invalid PVE task identifier",
		},
		"a handle without a node": {
			scenario: taskScenario{stopHandle: "UPID::pid:task", vmAfterStop: "running"},
			want:     "invalid PVE task identifier",
		},
		"a handle of another node": {
			scenario: taskScenario{stopHandle: "UPID:node2:0000A1B2:00C3D4E5:66A1B2C3:qmstop:9102:root@pam:", vmAfterStop: "running"},
			want:     `PVE task node "node2" does not match requested node "node1"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := tc.scenario
			s.serve(t)
			stateDir := taskJournal(t)

			err := RecoverLocked(stateDir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("recovery = %v, want an error containing %q", err, tc.want)
			}
			if got := s.requested(destroyCall); got != tc.wantDestroy {
				t.Errorf("destroy requested = %v, want %v (calls %v)", got, tc.wantDestroy, s.calls)
			}
			if s.taskPolls != tc.wantPolls {
				t.Errorf("tasks polled %d times, want %d (calls %v)", s.taskPolls, tc.wantPolls, s.calls)
			}
			after := journalPhase(t, stateDir)
			if after.Phase != "cleanup_failed" || len(after.VMs) != 1 || after.VMs[0].VMID != 9102 || len(after.CleanupErrors) == 0 {
				t.Fatalf("journal after recovery = %+v, want cleanup_failed with VM 9102 kept for the retry", after)
			}
		})
	}
}

// Controls: the journal is cleaned once PVE answers that the VM is
// gone, whatever the destroy task said; and a journal a failed attempt kept
// is cleaned by the retry once the VM is gone.
func TestRecoveryCleansTheJournalOnceTheVMIsConfirmedGone(t *testing.T) {
	t.Run("stopped, then destroyed and confirmed gone", func(t *testing.T) {
		s := &taskScenario{stopHandle: taskStop, vmAfterStop: "stopped", vmAfterDestroy: "gone"}
		s.serve(t)
		stateDir := taskJournal(t)
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		if !s.requested(stopCall) || !s.requested(destroyCall) || s.taskPolls != 2 {
			t.Fatalf("calls %v, task polls %d; want a stop, a destroy and both tasks followed", s.calls, s.taskPolls)
		}
		if after := journalPhase(t, stateDir); after.Phase != "cleaned" {
			t.Fatalf("journal phase = %q, want cleaned", after.Phase)
		}
	})
	t.Run("gone by the time the stop task ended", func(t *testing.T) {
		s := &taskScenario{stopHandle: taskStop, vmAfterStop: "gone"}
		s.serve(t)
		stateDir := taskJournal(t)
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		if s.requested(destroyCall) {
			t.Fatalf("destroyed a VM PVE reported gone: %v", s.calls)
		}
		if after := journalPhase(t, stateDir); after.Phase != "cleaned" {
			t.Fatalf("journal phase = %q, want cleaned", after.Phase)
		}
	})
	// The task's own words are not what decides: a destroy task that failed
	// for a VM that is gone anyway (another recovery got there first) is a
	// clean journal.
	t.Run("destroy task failed, VM gone", func(t *testing.T) {
		s := &taskScenario{vmInitial: "stopped", vmAfterDestroy: "gone", taskExit: "unable to remove VM 9102"}
		s.serve(t)
		stateDir := taskJournal(t)
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatal(err)
		}
		if after := journalPhase(t, stateDir); after.Phase != "cleaned" {
			t.Fatalf("journal phase = %q, want cleaned", after.Phase)
		}
	})
	t.Run("a retry finds the VM gone", func(t *testing.T) {
		s := &taskScenario{stopHandle: taskStop, vmAfterStop: "stopped"}
		s.serve(t)
		stateDir := taskJournal(t)
		if err := RecoverLocked(stateDir); err == nil {
			t.Fatal("recovery succeeded with the VM still there")
		}
		s.mu.Lock()
		s.vmAfterDestroy = "gone" // an operator removed it, or PVE caught up
		s.mu.Unlock()
		if err := RecoverLocked(stateDir); err != nil {
			t.Fatalf("retry = %v", err)
		}
		if after := journalPhase(t, stateDir); after.Phase != "cleaned" {
			t.Fatalf("journal phase = %q, want cleaned", after.Phase)
		}
	})
}

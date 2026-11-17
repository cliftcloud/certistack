// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/nodeapi"
	progresspkg "github.com/cliftcloud/certistack/pkg/progress"
)

// sshExit is an ssh exit status, as exec reports it.
type sshExit struct {
	code int
	msg  string
}

func (e sshExit) Error() string { return e.msg }
func (e sshExit) ExitCode() int { return e.code }

func lostConnection(reason string) error {
	return fmt.Errorf("ssh failed: %w: %s", sshExit{code: 255, msg: "exit status 255"}, reason)
}

// A silent worker command left a crashed node undetected until TCP
// keepalive, about two hours: every ssh and scp asks the node for a
// reply and gives up after a minute without one.
func TestSSHAndSCPGiveUpOnANodeThatStopsAnswering(t *testing.T) {
	fake := &fakeCommandRunner{}
	e := &Executor{runner: fake}
	cfg := SSHConfig{Host: "pve.example", User: "root", KnownHostsFile: "/etc/certistack/known_hosts"}
	if _, err := e.remoteCommand(context.Background(), cfg, []string{"/usr/bin/true"}); err != nil {
		t.Fatal(err)
	}
	if err := e.copyToStaging(context.Background(), cfg, "worker", "/tmp/staging"); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("calls = %d, want ssh and scp", len(fake.calls))
	}
	for _, call := range fake.calls {
		joined := strings.Join(call.args, " ")
		for _, option := range []string{"ServerAliveInterval=15", "ServerAliveCountMax=4", "ConnectTimeout=20", "BatchMode=yes", "StrictHostKeyChecking=yes"} {
			if !strings.Contains(joined, "-o "+option) {
				t.Errorf("%s %s lacks -o %s", call.name, joined, option)
			}
		}
	}
	if sshDeadPeerSeconds != 60 {
		t.Fatalf("dead-peer detection = %d s, want 60", sshDeadPeerSeconds)
	}
}

// scp reads "user@host:path" and splits at the first colon after the host, so
// an IPv6 literal must be bracketed in the copy destination; ssh takes the
// literal as it is.
func TestSCPDestinationBracketsAnIPv6Literal(t *testing.T) {
	for _, tc := range []struct {
		host, want string
	}{
		{"pve.example", "root@pve.example:/tmp/staging/"},
		{"192.0.2.10", "root@192.0.2.10:/tmp/staging/"},
		{"2001:db8::1", "root@[2001:db8::1]:/tmp/staging/"},
		{"[2001:db8::1]", "root@[2001:db8::1]:/tmp/staging/"},
	} {
		fake := &fakeCommandRunner{}
		e := &Executor{runner: fake}
		cfg := SSHConfig{Host: tc.host, User: "root", KnownHostsFile: "/etc/certistack/known_hosts"}
		if err := e.copyToStaging(context.Background(), cfg, "worker", "/tmp/staging"); err != nil {
			t.Fatalf("%s: %v", tc.host, err)
		}
		if len(fake.calls) != 1 {
			t.Fatalf("%s: calls = %d, want one scp", tc.host, len(fake.calls))
		}
		args := fake.calls[0].args
		if got := args[len(args)-1]; got != tc.want {
			t.Errorf("host %q: scp destination = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestStreamedErrorDetailKeepsTheCauseNotTheStream(t *testing.T) {
	event := progresspkg.EventPrefix + `{"level":"INFO","stage":"Boot","message":"Waiting 900 s for services."}`
	stderr := strings.Join([]string{
		event,
		"recorded run is already marked cleaned",
		strings.Repeat("x", 9000),
		event,
		"Timeout, server pve.example not responding.",
		"",
	}, "\n")
	if got := streamedErrorDetail(stderr, true); got != "Timeout, server pve.example not responding." {
		t.Fatalf("lost connection detail = %q, want ssh's reason alone", got)
	}
	got := streamedErrorDetail(stderr, false)
	if strings.Contains(got, progresspkg.EventPrefix) {
		t.Fatalf("detail repeats progress events the operator saw: %.200q", got)
	}
	if len(got) > maxSSHErrorDetail+3 || !strings.HasSuffix(got, "not responding.") {
		t.Fatalf("detail = %d bytes ending %q, want at most %d ending with the last line", len(got), got[len(got)-20:], maxSSHErrorDetail)
	}
}

// A real exit status 255 is ssh's own failure; the helper process stands in
// for ssh.
func TestRunCommandSummarizesALostConnection(t *testing.T) {
	var progress bytes.Buffer
	_, err := runCommand(context.Background(), os.Args[0], []string{"-test.run=^TestSSHHelperProcess$", "--", "certistack-ssh-helper"}, &progress)
	if err == nil || !sshTransportFailed(err) {
		t.Fatalf("runCommand error = %v, want an ssh transport failure", err)
	}
	if !strings.HasSuffix(err.Error(), ": Timeout, server pve.example not responding.") || strings.Contains(err.Error(), "earlier output") {
		t.Fatalf("error = %q, want it to end with ssh's reason alone", err)
	}
	if !strings.Contains(progress.String(), "earlier output") {
		t.Fatalf("stderr did not stream: %q", progress.String())
	}
}

func TestSSHHelperProcess(t *testing.T) {
	for _, arg := range os.Args {
		if arg == "certistack-ssh-helper" {
			fmt.Fprintln(os.Stderr, "earlier output")
			fmt.Fprintln(os.Stderr, "Timeout, server pve.example not responding.")
			os.Exit(255)
		}
	}
}

func TestSSHTransportFailedOnlyForExitStatus255(t *testing.T) {
	lost := fmt.Errorf("SSH command on pve: %w", lostConnection("client_loop: send disconnect: Broken pipe"))
	if !sshTransportFailed(lost) {
		t.Fatal("exit status 255 is ssh's own failure")
	}
	if got := sshReason(lost); got != "client_loop: send disconnect: Broken pipe" {
		t.Fatalf("sshReason = %q, want ssh's own words", got)
	}
	if got := sshReason(fmt.Errorf("ssh failed: %w: ", sshExit{code: 255, msg: "exit status 255"})); got != "ssh failed: exit status 255:" {
		t.Fatalf("sshReason without ssh's words = %q", got)
	}
	for _, err := range []error{
		sshExit{code: 1, msg: "exit status 1"},
		sshExit{code: 143, msg: "exit status 143"},
		errors.New("ssh session ended"),
		context.Canceled,
	} {
		if sshTransportFailed(err) {
			t.Fatalf("%v is not an ssh transport failure", err)
		}
	}
}

// A blade reseated under a run. The controller must notice within
// a minute, wait for the node, say it rebooted, and clean up once it
// answers.
func TestExecutorRunWaitsForALostNodeAndSaysItRebooted(t *testing.T) {
	defer shortenNodeRetry(t)()
	opts := preflightTestOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	bootIDs := []string{"0b6c3a52-5bd1-4f3e-a7c9-7e0a1d2c3b4f", "5f1e2d3c-4b5a-4687-9a0b-1c2d3e4f5a6b"}
	stops, unanswered := 0, 2
	fake := &fakeCommandRunner{
		workerStopResult: "gone",
		nodeRunError:     lostConnection("Timeout, server pve.example not responding."),
		recoverStderr:    progresspkg.EventPrefix + `{"level":"INFO","stage":"Recovery","message":"Destroyed sandbox VM 937011."}` + "\n",
	}
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		switch {
		case strings.Contains(joined, "boot_id") && !strings.Contains(joined, "kill -TERM"):
			id := bootIDs[0]
			bootIDs = bootIDs[1:]
			return []byte(id + "\n"), nil, true
		case strings.Contains(joined, "$pinned_proc_dir/exe"):
			if stops++; stops == 1 {
				return nil, lostConnection("ssh: connect to host pve.example port 22: No route to host"), true
			}
		case strings.Contains(joined, "'/usr/bin/true'") && unanswered > 0:
			unanswered--
			return nil, lostConnection("ssh: connect to host pve.example port 22: No route to host"), true
		}
		return nil, nil, false
	}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.HasPrefix(err.Error(), "lost contact with node pve-01 during the run") {
		t.Fatalf("Run error = %v, want lost contact", err)
	}
	if len(err.Error()) > 300 {
		t.Fatalf("final error is %d bytes: %q", len(err.Error()), err)
	}
	out := progress.String()
	for _, want := range []string{
		"Lost contact with node pve-01: Timeout, server pve.example not responding.",
		"Node pve-01 does not answer (ssh: connect to host pve.example port 22: No route to host); retrying for up to",
		"Node pve-01 answers again after",
		"Node pve-01 rebooted during the run (its boot ID changed)",
		"its temporary resources were reconciled once the node answered",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("progress lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "does not answer") != 1 {
		t.Errorf("waiting was reported more than once a minute:\n%s", out)
	}
	// What the controller's recovery did is shown, not captured and dropped.
	if !strings.Contains(out, "[Recovery] Destroyed sandbox VM 937011.") {
		t.Errorf("recovery's actions were not shown:\n%s", out)
	}
	if fake.recoverCalls == 0 {
		t.Fatal("the run's journal was not recovered once the node answered")
	}
}

// A node that never answers leaves the workspace for recovery, and the
// operator is told what happens next and the exact command to run there.
// Nothing more is tried over SSH: a try the deadline kills while it is still
// connecting ("signal: killed") is not reported as "could not be verified",
// and no staging removal follows.
func TestExecutorRunNamesTheRecoveryWhenTheNodeNeverAnswers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe func() error
	}{
		{"refused between tries", func() error {
			return lostConnection("ssh: connect to host pve.example port 22: Connection timed out")
		}},
		{"killed while connecting", func() error {
			time.Sleep(400 * time.Millisecond) // past the cleanup deadline
			return errors.New("ssh failed: signal: killed: ")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer shortenNodeRetry(t)()
			opts := preflightTestOptions(t)
			var progress bytes.Buffer
			opts.Writer = &progress
			cleanup, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			opts.CleanupContext = cleanup
			fake := &fakeCommandRunner{nodeRunError: lostConnection("Timeout, server pve.example not responding.")}
			lost := -1
			fake.hook = func(name, joined string) ([]byte, error, bool) {
				switch {
				case strings.Contains(joined, "node-run"):
					lost = len(fake.calls)
				case strings.Contains(joined, "$pinned_proc_dir/exe"):
					return nil, lostConnection("ssh: connect to host pve.example port 22: Connection timed out"), true
				case strings.Contains(joined, "'/usr/bin/true'"):
					return nil, tc.probe(), true
				}
				return nil, nil, false
			}
			_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
			if err == nil || !strings.HasPrefix(err.Error(), "lost contact with node pve-01 during the run, and it did not answer within") ||
				!strings.HasSuffix(err.Error(), "(ssh: connect to host pve.example port 22: Connection timed out)") {
				t.Fatalf("Run error = %v, want lost contact and ssh's last reason", err)
			}
			out := progress.String()
			for _, want := range []string{
				"Node pve-01 did not answer within",
				"cleans up by itself once the worker's lease is 90 s old",
				"its next CertiStack run recovers them before it starts",
				"certistack-node recover --state-dir /var/lib/certistack --env-file /var/lib/certistack/workers/",
				"warning: node pve-01 cannot be reached, so the controller removed nothing there. If the node still has this run's workspace (/var/lib/certistack/workers/",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("progress lacks %q:\n%s", want, out)
				}
			}
			for _, unwanted := range []string{"signal: killed", "retaining temporary node workspace", "could not be verified"} {
				if strings.Contains(out, unwanted) || strings.Contains(err.Error(), unwanted) {
					t.Errorf("output says %q:\n%s\nerror: %v", unwanted, out, err)
				}
			}
			for _, call := range fake.calls[lost:] {
				joined := strings.Join(call.args, " ")
				if strings.Contains(joined, "'/usr/bin/rm'") || strings.Contains(joined, "certistack-controller-") {
					t.Fatalf("the controller tried to remove something after giving up: %v", call.args)
				}
			}
		})
	}
}

// A node cut off from the controller recovers the run itself once the lease
// expires and removes the workspace, PID file and all. No PID
// file then does not prove the worker never started: the journal decides.
func TestReconcileInterruptedWorkerChecksTheJournalWithoutAPIDFile(t *testing.T) {
	workspace := "/var/lib/certistack/workers/3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	ours := workerRunID(workspace)
	for _, tc := range []struct {
		name        string
		fake        *fakeCommandRunner
		selfCleaned bool
		wantErr     string
	}{
		{"recovered by the node", &fakeCommandRunner{workerStopResult: "absent", journalReads: []string{ours + " cleaned"}}, true, ""},
		{"never started", &fakeCommandRunner{workerStopResult: "absent", journalState: "absent"}, false, ""},
		{"another run since", &fakeCommandRunner{workerStopResult: "absent", journalReads: []string{"run-other cleaned"}}, false, ""},
		{"stopped by the controller", &fakeCommandRunner{workerStopResult: "stopped", journalReads: []string{ours + " cleaned"}}, false, ""},
		{"left behind", &fakeCommandRunner{workerStopResult: "absent", journalReads: []string{ours + " running"}, workspaceState: "absent"}, false, "workspace is absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selfCleaned, err := (&Executor{runner: tc.fake}).reconcileInterruptedWorker(context.Background(), SSHConfig{Host: "pve.example", User: "root"},
				"/var/lib/certistack/workers", workspace, "/var/lib/certistack", nodeContact{name: "pve-01"})
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("reconcile = %v, want %q", err, tc.wantErr)
			}
			if selfCleaned != tc.selfCleaned {
				t.Fatalf("selfCleaned = %v, want %v", selfCleaned, tc.selfCleaned)
			}
		})
	}
}

// A renewal ssh killed by its own timeout reports "ssh failed: signal:
// killed:"; the warning says the renewal timed out.
func TestWorkerLeaseWarningSaysARenewalTimedOut(t *testing.T) {
	interval, after, timeout := workerLeaseRenewInterval, leaseWarnAfter, workerLeaseRenewTimeout
	workerLeaseRenewInterval, leaseWarnAfter, workerLeaseRenewTimeout = 5*time.Millisecond, 20*time.Millisecond, 10*time.Millisecond
	defer func() { workerLeaseRenewInterval, leaseWarnAfter, workerLeaseRenewTimeout = interval, after, timeout }()
	warned := make(chan string, 4)
	workspace := "/var/lib/certistack/workers/3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	stop := (&Executor{runner: hangingRunner{}}).startWorkerLease(context.Background(), SSHConfig{Host: "pve.example", User: "root"},
		"/var/lib/certistack/workers", workspace, workspace+"/controller.lease",
		func(format string, args ...interface{}) { warned <- fmt.Sprintf(format, args...) })
	defer stop()
	select {
	case warning := <-warned:
		if !strings.Contains(warning, "renew the worker's lease (no answer within 0 s)") || strings.Contains(warning, "killed") {
			t.Fatalf("warning = %q, want the timeout named", warning)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no warning")
	}
}

// hangingRunner is an ssh that never answers until it is killed.
type hangingRunner struct{}

func (hangingRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	<-ctx.Done()
	return nil, errors.New("ssh failed: signal: killed: ")
}

// The node stopped the run and cleaned up by itself at lease expiry, and the
// controller says so instead of claiming the work.
func TestExecutorRunSaysTheNodeCleanedUpByItself(t *testing.T) {
	defer shortenNodeRetry(t)()
	opts := preflightTestOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	fake := &fakeCommandRunner{workerStopResult: "absent", nodeRunError: lostConnection("Timeout, server pve.example not responding.")}
	workspaceID := regexp.MustCompile(`workers/([0-9a-f-]{36})/worker\.pid`)
	var runID string
	// The network was cut: the node does not answer when ssh gives up, and does
	// once it is back, after its lease ran out.
	unanswered := 1
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		if m := workspaceID.FindStringSubmatch(joined); m != nil {
			runID = "run-" + m[1]
		}
		if strings.Contains(joined, "'/usr/bin/true'") && unanswered > 0 {
			unanswered--
			return nil, lostConnection("ssh: connect to host pve.example port 22: No route to host"), true
		}
		if runID != "" && strings.Contains(joined, "active.json") && strings.Contains(joined, "'/usr/bin/cat'") {
			return []byte(`{"run_id":"` + runID + `","phase":"cleaned"}`), nil, true
		}
		return nil, nil, false
	}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.HasPrefix(err.Error(), "lost contact with node pve-01 during the run") {
		t.Fatalf("Run error = %v, want lost contact", err)
	}
	if !strings.Contains(progress.String(), "the node stopped the run and cleaned up by itself; its journal confirms it") {
		t.Fatalf("progress does not say the node cleaned up by itself:\n%s", progress.String())
	}
	if fake.recoverCalls != 0 {
		t.Fatalf("recover ran %d times on a clean journal", fake.recoverCalls)
	}
}

func shortenNodeRetry(t *testing.T) func() {
	t.Helper()
	initial, max := nodeRetryInitial, nodeRetryMax
	nodeRetryInitial, nodeRetryMax = time.Millisecond, 5*time.Millisecond
	return func() { nodeRetryInitial, nodeRetryMax = initial, max }
}

// leaseRunner fails lease renewals while down is set.
type leaseRunner struct {
	mu   sync.Mutex
	down bool
}

func (r *leaseRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.down {
		return nil, lostConnection("ssh: connect to host pve.example port 22: No route to host")
	}
	return nil, nil
}

func (r *leaseRunner) setDown(down bool) {
	r.mu.Lock()
	r.down = down
	r.mu.Unlock()
}

func TestWorkerLeaseWarnsWhileTheNodeCannotBeReachedAndWhenItIsBack(t *testing.T) {
	interval, after := workerLeaseRenewInterval, leaseWarnAfter
	workerLeaseRenewInterval, leaseWarnAfter = 5*time.Millisecond, 20*time.Millisecond
	defer func() { workerLeaseRenewInterval, leaseWarnAfter = interval, after }()

	runner := &leaseRunner{down: true}
	var mu sync.Mutex
	var warnings []string
	warned := make(chan struct{}, 8)
	workspace := "/var/lib/certistack/workers/3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	stop := (&Executor{runner: runner}).startWorkerLease(context.Background(), SSHConfig{Host: "pve.example", User: "root"},
		"/var/lib/certistack/workers", workspace, workspace+"/controller.lease",
		func(format string, args ...interface{}) {
			mu.Lock()
			warnings = append(warnings, fmt.Sprintf(format, args...))
			mu.Unlock()
			warned <- struct{}{}
		})
	defer stop()

	waitFor := func(what string) {
		t.Helper()
		select {
		case <-warned:
		case <-time.After(5 * time.Second):
			t.Fatalf("no warning %s", what)
		}
	}
	waitFor("while renewals fail")
	time.Sleep(50 * time.Millisecond) // more failures warn no more
	runner.setDown(false)
	waitFor("once contact is back")
	stop()

	mu.Lock()
	defer mu.Unlock()
	if len(warnings) != 2 {
		t.Fatalf("warnings = %q, want one while unreachable and one when back", warnings)
	}
	if !strings.Contains(warnings[0], "Cannot reach node pve.example over SSH to renew the worker's lease (ssh: connect to host pve.example port 22: No route to host);") ||
		!strings.Contains(warnings[0], "once the lease is 90 s old") {
		t.Fatalf("unreachable warning = %q", warnings[0])
	}
	if !strings.Contains(warnings[1], "Contact with node pve.example is back") {
		t.Fatalf("restored warning = %q", warnings[1])
	}
}

// One scp of the worker that loses its connection must not fail the run
// before anything is created. Staging steps are idempotent, so a lost
// connection is tried again.
func TestStagingRetriesALostConnection(t *testing.T) {
	waits := setupRetries
	setupRetries = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { setupRetries = waits }()
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
	scps, mkdirs := 0, 0
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		switch {
		case name == "scp":
			if scps++; scps == 1 {
				return nil, errors.New("scp failed: exit status 1: lost connection"), true
			}
		case strings.Contains(joined, "/tmp/certistack-controller-") && strings.Contains(joined, "/usr/bin/mkdir"):
			if mkdirs++; mkdirs == 1 {
				return nil, lostConnection("kex_exchange_identification: read: Connection reset by peer"), true
			}
		}
		return nil, nil, false
	}
	if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err != nil {
		t.Fatalf("Run = %v, want the lost connections retried", err)
	}
	if mkdirs != 2 {
		t.Fatalf("staging directory tries = %d, want 2", mkdirs)
	}
}

// A remote command that fails for its own reasons is not tried again.
func TestSetupDoesNotRetryARealFailure(t *testing.T) {
	tries := 0
	err := retrySetup(context.Background(), func() error {
		tries++
		return errors.New("ssh failed: exit status 1: install: cannot create directory: Permission denied")
	})
	if err == nil || tries != 1 {
		t.Fatalf("tries = %d, err = %v; want one try", tries, err)
	}
}

// 206184d on -11: the worker run's ssh never connected ("Connection timed
// out"), and the case failed as "lost contact during the run" although the
// worker never started. It is started again.
func TestExecutorRunStartsTheWorkerAgainWhenSSHNeverConnected(t *testing.T) {
	waits := setupRetries
	setupRetries = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { setupRetries = waits }()
	opts := completedWorkerTeardownOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
	runs := 0
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		if strings.Contains(joined, "node-run") {
			if runs++; runs == 1 {
				return nil, lostConnection("ssh: connect to host 192.0.2.41 port 22: Connection timed out"), true
			}
		}
		return nil, nil, false
	}
	if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err != nil {
		t.Fatalf("Run = %v, want the worker started again", err)
	}
	if runs != 2 || !strings.Contains(progress.String(), "Could not start the worker on node pve-01 (ssh: connect to host 192.0.2.41 port 22: Connection timed out); trying again in") {
		t.Fatalf("runs = %d, progress:\n%s", runs, progress.String())
	}
}

func TestWorkerNeverStartedOnlyBeforeTheSession(t *testing.T) {
	for reason, want := range map[string]bool{
		"ssh: connect to host 192.0.2.41 port 22: Connection timed out":  true,
		"ssh: connect to host pve port 22: Connection refused":           true,
		"kex_exchange_identification: read: Connection reset by peer":    true,
		"Connection closed by 192.0.2.41 port 22":                        true,
		"Connection timed out during banner exchange":                    true,
		"ssh: Could not resolve hostname pve: Name or service not known": true,
		"Timeout, server 192.0.2.41 not responding.":                     false,
		"client_loop: send disconnect: Broken pipe":                      false,
		"client_loop: send disconnect: Connection reset by peer":         false,
		"Connection to 192.0.2.41 closed by remote host.":                false,
	} {
		if got := workerNeverStarted(lostConnection(reason)); got != want {
			t.Errorf("workerNeverStarted(%q) = %v, want %v", reason, got, want)
		}
	}
	if workerNeverStarted(sshExit{code: 1, msg: "exit status 1"}) {
		t.Error("a remote command's own failure is not a failed start")
	}
}

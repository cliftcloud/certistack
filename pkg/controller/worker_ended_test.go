// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
	progresspkg "github.com/cliftcloud/certistack/pkg/progress"
)

// The worker's own structured log line, as the node's local clock wrote it: the
// last line a killed worker left in its progress log.
const workerLogLine = `time=2026-11-15T09:30:01.123-07:00 level=INFO msg="creating ephemeral delta overlay"`

// A worker killed with -9 mid-scan ends its ssh with status 255 and the last
// line of its log. When the node answers at once, the node is up: the worker
// ended without a result, and the message says so and where its log is, not
// "Lost contact with node ... The node may have crashed, rebooted or lost its
// network" with that log line quoted as ssh's reason.
func TestExecutorRunSaysTheWorkerEndedWhenTheNodeAnswersAtOnce(t *testing.T) {
	for _, tc := range []struct {
		name, stop, progress, errorPrefix string
	}{
		{"the worker was already gone", "gone",
			"The node worker on node pve-01 ended without a result (killed or crashed); the node itself answered. Its log is on the node: journalctl -u certistack-worker-",
			"the node worker on node pve-01 ended without a result (killed or crashed); the node itself answered"},
		{"the worker still ran and the controller stopped it", "stopped",
			"The ssh connection to node pve-01 ended while the node worker was still running, and the node answered again at once; the controller stopped the worker. Its log is on the node: journalctl -u certistack-worker-",
			"the ssh connection to node pve-01 ended while the node worker was still running"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer shortenNodeRetry(t)()
			opts := preflightTestOptions(t)
			var progress bytes.Buffer
			opts.Writer = &progress
			fake := &fakeCommandRunner{workerStopResult: tc.stop, nodeRunError: lostConnection(workerLogLine)}
			workspaceID := regexp.MustCompile(`workers/([0-9a-f-]{36})/`)
			var workspace string
			fake.hook = func(name, joined string) ([]byte, error, bool) {
				if m := workspaceID.FindStringSubmatch(joined); m != nil {
					workspace = m[1]
				}
				return nil, nil, false // every other command answers at once
			}
			_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
			if err == nil {
				t.Fatal("Run succeeded")
			}
			out := progress.String()
			if !strings.Contains(out, tc.progress) {
				t.Errorf("progress lacks %q:\n%s", tc.progress, out)
			}
			if !strings.HasPrefix(err.Error(), tc.errorPrefix) {
				t.Errorf("error = %v, want it to start %q", err, tc.errorPrefix)
			}
			if !strings.Contains(out, "journalctl -u certistack-worker-"+workspace) {
				t.Errorf("the worker's unit is not named (workspace %q):\n%s", workspace, out)
			}
			for _, unwanted := range []string{"Lost contact", "may have crashed", "level=INFO", "creating ephemeral delta overlay"} {
				if strings.Contains(out, unwanted) || strings.Contains(err.Error(), unwanted) {
					t.Errorf("says %q although the node answered and the log line is not ssh's:\n%s\nerror: %v", unwanted, out, err)
				}
			}
			if strings.HasPrefix(err.Error(), "lost contact") {
				t.Errorf("error = %v, want the worker's end, not a lost node", err)
			}
		})
	}
}

// The node that does not answer is still lost contact, and the worker's log
// line is not what it names as ssh's reason.
func TestALostNodeNamesSSHsReasonNotTheWorkersLogLine(t *testing.T) {
	defer shortenNodeRetry(t)()
	opts := preflightTestOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	fake := &fakeCommandRunner{workerStopResult: "gone", nodeRunError: lostConnection(workerLogLine)}
	unanswered := 2
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		if strings.Contains(joined, "'/usr/bin/true'") && unanswered > 0 {
			unanswered--
			return nil, lostConnection("ssh: connect to host pve.example port 22: No route to host"), true
		}
		return nil, nil, false
	}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.HasPrefix(err.Error(), "lost contact with node pve-01 during the run") {
		t.Fatalf("Run error = %v, want lost contact", err)
	}
	out := progress.String()
	if !strings.Contains(out, "Lost contact with node pve-01: ") || !strings.Contains(out, "The node may have crashed, rebooted or lost its network") {
		t.Errorf("a node that does not answer lost its lost-contact message:\n%s", out)
	}
	for _, unwanted := range []string{"level=INFO", "creating ephemeral delta overlay"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("quotes the worker's log line as ssh's reason (%q):\n%s", unwanted, out)
		}
	}
}

// The same through the real command runner: a session that ended with status
// 255 after the worker's last log line, and with nothing from ssh, keeps no
// reason in its error; the helper process stands in for ssh.
func TestRunCommandKeepsNoWorkerLogLineAsAReason(t *testing.T) {
	var progress bytes.Buffer
	_, err := runCommand(context.Background(), os.Args[0], []string{"-test.run=^TestSSHWorkerLogHelperProcess$", "--", "certistack-ssh-worker-log-helper"}, &progress)
	if err == nil || !sshTransportFailed(err) {
		t.Fatalf("runCommand error = %v, want an ssh transport failure", err)
	}
	if strings.Contains(err.Error(), "level=") || strings.Contains(err.Error(), "creating ephemeral delta overlay") {
		t.Errorf("error = %q, want no worker log line as a reason", err)
	}
	if !strings.Contains(progress.String(), "creating ephemeral delta overlay") {
		t.Errorf("the worker's log did not stream to the operator: %q", progress.String())
	}
}

func TestSSHWorkerLogHelperProcess(t *testing.T) {
	for _, arg := range os.Args {
		if arg == "certistack-ssh-worker-log-helper" {
			fmt.Fprintln(os.Stderr, progresspkg.EventPrefix+`{"level":"INFO","stage":"Scan","message":"5 GiB verified."}`)
			fmt.Fprintln(os.Stderr, workerLogLine)
			os.Exit(255)
		}
	}
}

// ssh's reason is ssh's own last line. A worker's structured log line is the
// worker's, and is never given as ssh's.
func TestSSHReasonIsNeverAWorkerLogLine(t *testing.T) {
	for _, line := range []string{
		workerLogLine,
		`level=INFO msg="recorded run is already marked cleaned"`,
		`time=2026-11-15T09:30:01.123-07:00 level=ERROR msg="x"`,
	} {
		if got := sshReason(lostConnection(line)); strings.Contains(got, "level=") {
			t.Errorf("sshReason(%q) = %q", line, got)
		}
	}
	// ssh's own words, and a message that only looks like a log line, stay.
	for line, want := range map[string]string{
		"Timeout, server pve.example not responding.": "Timeout, server pve.example not responding",
		"the level=3 setting is not valid":            "the level=3 setting is not valid",
	} {
		if got := sshReason(lostConnection(line)); got != want {
			t.Errorf("sshReason(%q) = %q, want %q", line, got, want)
		}
	}
	event := progresspkg.EventPrefix + `{"level":"INFO","stage":"Boot","message":"Waiting."}`
	if got := streamedErrorDetail(strings.Join([]string{event, workerLogLine, ""}, "\n"), true); got != "" {
		t.Errorf("a lost connection's detail = %q, want nothing: ssh said nothing, and the worker's log line is not ssh's", got)
	}
	if got := streamedErrorDetail(strings.Join([]string{workerLogLine, "Connection to pve.example closed by remote host.", ""}, "\n"), true); got != "Connection to pve.example closed by remote host." {
		t.Errorf("a lost connection's detail = %q, want ssh's own last line", got)
	}
}

// init --inspect decides the same way: a worker that ended while its node
// answers is the worker's end, with its unit named, and not a lost node.
func TestInspectSaysTheWorkerEndedWhenTheNodeAnswersAtOnce(t *testing.T) {
	opts := inspectOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	fake := answering(initplan.Inspection{}, lostConnection(workerLogLine))
	fake.workerStopResult = "gone"
	fake.journalPhase = "running"
	_, err := (&Executor{runner: fake}).Inspect(context.Background(), opts, inspectReq)
	if err == nil || !strings.Contains(err.Error(), "the node worker on node pve1 ended without a result (killed or crashed); the node itself answered") {
		t.Fatalf("Inspect error = %v, want the worker's end", err)
	}
	out := progress.String()
	for _, want := range []string{"The node worker on node pve1 ended without a result (killed or crashed); the node itself answered.", "journalctl -u certistack-worker-"} {
		if !strings.Contains(out, want) {
			t.Errorf("progress lacks %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"Lost contact", "level=INFO"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("progress says %q:\n%s", unwanted, out)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// A cleanup that cannot be verified says what is left and what to run next,
// not a 30-line error and "retaining temporary node workspace".
func TestUnverifiedCleanupSaysWhatIsLeftAndWhatToRun(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.TeardownEvidence = &attest.TeardownEvidence{CleanupErrors: []string{
		"delete SDN VNet csVnet1: failed to delete SDN VNet csVnet1: PVE API error (HTTP 500): delete sdn vnet object failed: 400 Parameter verification failed.",
		"delete SDN zone csZone1: failed to delete SDN zone csZone1: zone csZone1 is used by vnet csVnet1",
	}}
	fake := &fakeCommandRunner{
		nodeResult:          nodeapi.RunResult{Report: report},
		workerRecoveryError: errors.New("ssh failed: exit status 2: time=... level=INFO msg=one\ntime=... level=INFO msg=two\nError: failed to delete SDN VNet csVnet1: PVE API error (HTTP 500)"),
	}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || strings.Contains(err.Error(), "\n") || !strings.HasSuffix(err.Error(), "Error: failed to delete SDN VNet csVnet1: PVE API error (HTTP 500)") {
		t.Fatalf("Run error = %q, want one line ending with what failed", err)
	}
	out := progress.String()
	for _, want := range []string{
		"Some temporary resources could not be removed (delete SDN VNet csVnet1; delete SDN zone csZone1)",
		"on node pve-01, run: /var/lib/certistack/workers/",
		"/certistack-node recover --state-dir /var/lib/certistack --env-file /var/lib/certistack/workers/",
		"The node's next CertiStack run tries this recovery first and refuses to start if it fails",
		"/var/lib/certistack/logs/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("progress lacks %q:\n%s", want, out)
		}
	}
}

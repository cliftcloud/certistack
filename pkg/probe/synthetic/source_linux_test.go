// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"testing"
	"time"
)

// Binding narrows where a probe may go; it must still reach a listener on
// the interface it is bound to (on a worker, the guest on the sandbox VNet).
func TestBoundProbeReachesListenerOnItsInterface(t *testing.T) {
	allowLocalTargets(t)
	port := startLocalTCPListener(t)
	tcp := NewTCPProber("127.0.0.1", port, 2*time.Second, "bound to lo")
	tcp.Source = Source{Interface: "lo", Address: "127.0.0.1"}
	if res := tcp.Probe(context.Background()); !res.Passed {
		t.Fatalf("probe bound to lo did not reach a listener on lo: %s", res.Error)
	}
}

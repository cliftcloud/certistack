// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package synthetic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/cliftcloud/certistack/pkg/probe"
)

// interruptOnCancel closes conn when ctx is canceled, so a read or write
// blocked on a peer that says nothing returns at once instead of at the
// probe's deadline. A deadline needs no help: the connection carries it. Call
// the returned function when the exchange is over.
func interruptOnCancel(ctx context.Context, conn net.Conn) (stop func()) {
	stopWatching := context.AfterFunc(ctx, func() {
		if errors.Is(ctx.Err(), context.Canceled) {
			_ = conn.Close()
		}
	})
	return func() { stopWatching() }
}

// finishProbe is applied to the result of a wire probe: a pass reached only
// after the probe's budget ran out, or after it was interrupted, does not
// count, and an interruption is reported as one rather than as the closed
// connection it caused.
func finishProbe(ctx context.Context, res probe.Result) probe.Result {
	err := probe.Expired(ctx)
	switch {
	case err == nil:
	case res.Passed:
		res.Passed, res.Skipped, res.Detail = false, false, ""
		res.Error = fmt.Sprintf("the answer was accepted only after the probe was interrupted or out of time (%v), so it does not count", err)
	case errors.Is(ctx.Err(), context.Canceled) && strings.Contains(res.Error, "use of closed network connection"):
		res.Error = fmt.Sprintf("the probe was interrupted (%v)", context.Cause(ctx))
	}
	return res
}

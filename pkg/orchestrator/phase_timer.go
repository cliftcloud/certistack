// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import "time"

// phaseTimer adds the time a phase took to its field of the report's phase
// timings, whichever way the phase ends. A phase whose time was added only
// after it succeeded left a failed run's report with zero for the work that
// failed or stalled and the time unexplained: a run that spent two seconds
// waiting for admission showed no admission time, and one whose SDN setup
// failed after a quarter of a second showed no SDN time.
//
// The first stop counts and later ones do nothing, so a phase can be stopped
// where it ends and also deferred, to cover every early return between.
type phaseTimer struct {
	started time.Time
	seconds *float64
	stopped bool
}

// startPhase starts timing a phase that accumulates into seconds.
func startPhase(seconds *float64) *phaseTimer {
	return &phaseTimer{started: time.Now(), seconds: seconds}
}

// stop adds the time since startPhase to the phase, once.
func (p *phaseTimer) stop() {
	if p == nil || p.stopped {
		return
	}
	p.stopped = true
	*p.seconds += time.Since(p.started).Seconds()
}

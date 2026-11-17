// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runphase

import (
	"fmt"
	"math"
	"regexp"
	"sync"
	"time"
)

// The integrity scan is the one phase that knows how much it has to do (the
// size the snapshot's manifest records for the image) and how much it has done,
// so it is the one phase that can say how long it has left. The estimate is
// the rate over the last minute carried to the end, and it is left out while a
// rate would be a guess: before the scan has run ten seconds or read a twentieth
// of the image, with no progress between two reports, or when the end is days
// off.
const (
	scanQuietPeriod  = 10 * time.Second
	scanQuietPercent = 5
	scanRateWindow   = time.Minute
	scanLongest      = 48 * time.Hour
)

type scanSample struct {
	at   time.Time
	done int64
}

// ScanEstimator turns the byte counts a scan reports as it goes into what an
// operator reads: of how much, what share, and about how long is left.
type ScanEstimator struct {
	mu      sync.Mutex
	total   int64
	now     func() time.Time
	started time.Time
	samples []scanSample
}

// NewScanEstimator starts the clock of a scan of total bytes (0 when the size
// is not known, which gives no share and no estimate). now is time.Now when nil.
func NewScanEstimator(total int64, now func() time.Time) *ScanEstimator {
	if now == nil {
		now = time.Now
	}
	started := now()
	return &ScanEstimator{total: total, now: now, started: started, samples: []scanSample{{at: started}}}
}

// ScanProgress is what a scan has done at one report.
type ScanProgress struct {
	Done, Total int64
	// Percent is the share done, rounded down; -1 when it is not known (no
	// total, or more read than the total says).
	Percent int
	// Remaining is the time left at the recent rate, when HaveRemaining.
	Remaining     time.Duration
	HaveRemaining bool
}

// Observe records that done bytes of the scan are read and returns what that
// says.
func (e *ScanEstimator) Observe(done int64) ScanProgress {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	progress := ScanProgress{Done: done, Total: e.total, Percent: -1}
	if e.total > 0 && done >= 0 && done <= e.total {
		progress.Percent = percentOf(done, e.total)
	}
	e.samples = append(e.samples, scanSample{at: now, done: done})
	// The rate is over the samples of the last minute, and over the last two
	// reports at least: a scan that reads a gibibyte a minute has one report
	// in its window.
	from := len(e.samples) - 2
	for from > 0 && now.Sub(e.samples[from-1].at) <= scanRateWindow {
		from--
	}
	reference := e.samples[from]
	e.samples = e.samples[from:]

	if progress.Percent < 0 || done >= e.total {
		return progress
	}
	if now.Sub(e.started) < scanQuietPeriod || progress.Percent < scanQuietPercent {
		return progress
	}
	seconds := now.Sub(reference.at).Seconds()
	read := done - reference.done
	if seconds <= 0 || read <= 0 {
		return progress
	}
	left := float64(e.total-done) / (float64(read) / seconds)
	if left <= 0 || left > scanLongest.Seconds() {
		return progress
	}
	progress.Remaining, progress.HaveRemaining = time.Duration(left*float64(time.Second)), true
	return progress
}

// percentOf is done of total as a whole percent, rounded down, for 0 <= done <=
// total and 0 < total. It is exact in integers, so 29 of 100 is 29 and not 28.
func percentOf(done, total int64) int {
	if done > math.MaxInt64/100 {
		return int(float64(done) / float64(total) * 100)
	}
	return int(done * 100 / total)
}

// Suffix is what a scan's report adds to "N GiB verified": " of 12 GiB (58%),
// about 1 min left". It is empty when the total is not known or the scan has
// read more than the total says, and has no time left to give when
// Remaining is not known.
func (p ScanProgress) Suffix() string {
	if p.Total <= 0 || p.Percent < 0 {
		return ""
	}
	text := fmt.Sprintf(" of %s (%d%%)", FormatSize(p.Total), p.Percent)
	if p.HaveRemaining {
		text += ", " + remainingClause(p.Remaining)
	}
	return text
}

// remainingClause says a time left in round numbers: "under 10 s left", "about
// 45 s left", "about 3 min left", "about 1 h 20 min left".
func remainingClause(d time.Duration) string {
	seconds := int((d + 500*time.Millisecond) / time.Second)
	nearest := (seconds + 2) / 5 * 5
	switch {
	case nearest < 10:
		return "under 10 s left"
	case nearest < 60:
		return fmt.Sprintf("about %d s left", nearest)
	}
	minutes := (seconds + 30) / 60
	if minutes < 60 {
		return fmt.Sprintf("about %d min left", minutes)
	}
	hours, rest := minutes/60, (minutes%60+2)/5*5
	if rest == 60 {
		hours, rest = hours+1, 0
	}
	if rest == 0 {
		return fmt.Sprintf("about %d h left", hours)
	}
	return fmt.Sprintf("about %d h %d min left", hours, rest)
}

var estimateExpr = regexp.MustCompile(`, (?:under 10 s|about [0-9]+ (?:s|min|h(?: [0-9]+ min)?)) left(\.?)$`)

// WithoutEstimate removes the time left that a scan's report ends with. A line
// shown again later (the heartbeat repeats the last report while the next
// gibibyte is read) must not repeat a time left that has passed.
func WithoutEstimate(message string) string {
	return estimateExpr.ReplaceAllString(message, "$1")
}

// FormatSize writes a size in the largest unit that keeps it readable: whole
// gibibytes as "12 GiB", others with one decimal ("10.5 GiB"), then MiB and KiB.
// A size is never rounded up to a number it is not: below 10 MiB a size that is
// not whole shows one decimal ("1.0 MiB" for 1 MiB and 123 bytes), and from 10
// MiB it is rounded to the nearest MiB.
func FormatSize(n int64) string {
	const kib, mib, gib = int64(1) << 10, int64(1) << 20, int64(1) << 30
	switch {
	case n >= gib && n%gib == 0:
		return fmt.Sprintf("%d GiB", n/gib)
	case n >= gib:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(gib))
	case n >= mib && n%mib == 0:
		return fmt.Sprintf("%d MiB", n/mib)
	case n >= mib && n < 10*mib:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(mib))
	case n >= mib:
		return fmt.Sprintf("%d MiB", (n+mib/2)/mib)
	case n >= kib:
		return fmt.Sprintf("%d KiB", n/kib)
	}
	return fmt.Sprintf("%d B", n)
}

// Elapsed writes a time that has passed the way the run's own clock does:
// "45s", "2m09s", "1h02m09s".
func Elapsed(d time.Duration) string {
	seconds := int(d.Round(time.Second) / time.Second)
	if seconds < 0 {
		seconds = 0
	}
	switch {
	case seconds < 60:
		return fmt.Sprintf("%ds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%dm%02ds", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%dh%02dm%02ds", seconds/3600, seconds%3600/60, seconds%60)
}

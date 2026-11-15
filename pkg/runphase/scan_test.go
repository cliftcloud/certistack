// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runphase

import (
	"fmt"
	"math"
	"testing"
	"time"
)

const gib = int64(1) << 30

// clock is a clock a test moves.
type clock struct{ now time.Time }

func newClock() *clock { return &clock{now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time { return c.now }

func (c *clock) advance(seconds float64) {
	c.now = c.now.Add(time.Duration(seconds * float64(time.Second)))
}

// report is one report of a scan: seconds after the last one, the bytes read so
// far, and what the line adds to "N GiB verified".
type report struct {
	after float64
	done  int64
	want  string
}

func runScan(t *testing.T, total int64, reports []report) {
	t.Helper()
	c := newClock()
	estimator := NewScanEstimator(total, c.Now)
	for i, r := range reports {
		c.advance(r.after)
		if got := estimator.Observe(r.done).Suffix(); got != r.want {
			t.Errorf("report %d (%d GiB at +%gs): suffix %q, want %q", i+1, r.done/gib, r.after, got, r.want)
		}
	}
}

// The estimate is the rate over the last minute carried to the end, and it is
// left out while a rate would be a guess.
func TestScanEstimate(t *testing.T) {
	for _, test := range []struct {
		name    string
		total   int64
		reports []report
	}{
		{"a steady scan: 10 s a gibibyte of 12", 12 * gib, []report{
			// At 1 GiB per 10 s the rest is (12 - n) x 10 s: 110 s, 100 s, 90 s...
			{10, 1 * gib, " of 12 GiB (8%), about 2 min left"},
			{10, 2 * gib, " of 12 GiB (16%), about 2 min left"},
			{10, 3 * gib, " of 12 GiB (25%), about 2 min left"},
			{10, 4 * gib, " of 12 GiB (33%), about 1 min left"},
			{10, 5 * gib, " of 12 GiB (41%), about 1 min left"},
			{10, 6 * gib, " of 12 GiB (50%), about 1 min left"},
			{10, 7 * gib, " of 12 GiB (58%), about 50 s left"},
			{10, 8 * gib, " of 12 GiB (66%), about 40 s left"},
			{10, 9 * gib, " of 12 GiB (75%), about 30 s left"},
			{10, 10 * gib, " of 12 GiB (83%), about 20 s left"},
			{10, 11 * gib, " of 12 GiB (91%), about 10 s left"},
			{10, 12 * gib, " of 12 GiB (100%)"},
		}},
		{"no estimate in the first ten seconds", 12 * gib, []report{
			{5, 1 * gib, " of 12 GiB (8%)"},
			{4, 2 * gib, " of 12 GiB (16%)"}, // 9 s in
			// 11 s in, 3 GiB read: the 9 GiB left take 33 s, said to the nearest 5.
			{2, 3 * gib, " of 12 GiB (25%), about 35 s left"},
		}},
		{"no estimate under five percent, however long it has run", 100 * gib, []report{
			{30, 1 * gib, " of 100 GiB (1%)"},
			{30, 4 * gib, " of 100 GiB (4%)"},
			// 5 per cent: the last minute read 4 GiB, so the other 95 GiB take 95 x 15 s.
			{30, 5 * gib, " of 100 GiB (5%), about 24 min left"},
		}},
		{"a scan that has stopped has no rate", 12 * gib, []report{
			{20, 3 * gib, " of 12 GiB (25%), about 1 min left"},
			// 70 s later, the window holds nothing but this report and the one before it.
			{70, 3 * gib, " of 12 GiB (25%)"},
		}},
		{"a count that went back has a negative rate", 12 * gib, []report{
			{20, 3 * gib, " of 12 GiB (25%), about 1 min left"},
			{70, 2 * gib, " of 12 GiB (16%)"},
		}},
		{"two reports at one instant have no rate", 12 * gib, []report{
			{100, 3 * gib, " of 12 GiB (25%), about 5 min left"},
			{0, 4 * gib, " of 12 GiB (33%)"},
		}},
		{"the recent rate, not the average", 12 * gib, []report{
			// A slow start: a gibibyte every 100 s for 300 s...
			{100, 1 * gib, " of 12 GiB (8%), about 18 min left"},
			{100, 2 * gib, " of 12 GiB (16%), about 17 min left"},
			{100, 3 * gib, " of 12 GiB (25%), about 15 min left"},
			// ...then a gibibyte every 5 s. The window (a minute) holds only the fast
			// reports and the last slow one: 0.2 GiB/s, not 9 GiB in 330 s (a quarter of that).
			{5, 4 * gib, " of 12 GiB (33%), about 40 s left"},
			{5, 5 * gib, " of 12 GiB (41%), about 35 s left"},
			{5, 6 * gib, " of 12 GiB (50%), about 30 s left"},
			{5, 7 * gib, " of 12 GiB (58%), about 25 s left"},
			{5, 8 * gib, " of 12 GiB (66%), about 20 s left"},
			{5, 9 * gib, " of 12 GiB (75%), about 15 s left"},
		}},
		{"one report in a window still gives a rate", 12 * gib, []report{
			{300, 1 * gib, " of 12 GiB (8%), about 55 min left"},
			{300, 2 * gib, " of 12 GiB (16%), about 50 min left"},
		}},
		{"an end days away is not said", 100 * gib, []report{
			{36000, 5 * gib, " of 100 GiB (5%)"}, // 190 hours to go
			// The last ten hours read 45 GiB: 50 GiB more take 11 h 7 min, said to 5 min.
			{36000, 50 * gib, " of 100 GiB (50%), about 11 h 5 min left"},
		}},
		{"a size that is not a whole number of gibibytes", 10*gib + 512<<20, []report{
			// 2 GiB in 30 s; the other 8.5 GiB take 127.5 s.
			{30, 2 * gib, " of 10.5 GiB (19%), about 2 min left"},
		}},
		{"no total: no share and no time", 0, []report{
			{30, 1 * gib, ""},
			{30, 2 * gib, ""},
		}},
		{"more read than the total says: nothing is claimed", 12 * gib, []report{
			{30, 13 * gib, ""},
		}},
		{"a scan that has read all of it", 12 * gib, []report{
			{30, 12 * gib, " of 12 GiB (100%)"},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			runScan(t, test.total, test.reports)
		})
	}
}

// A clock that goes backwards, or a NaN's worth of a rate, never produces a time.
func TestScanEstimateNeverInventsATime(t *testing.T) {
	c := newClock()
	estimator := NewScanEstimator(12*gib, c.Now)
	c.advance(-60)
	if p := estimator.Observe(3 * gib); p.HaveRemaining {
		t.Errorf("a clock that went back gave %v left", p.Remaining)
	}
	c.advance(120)
	p := estimator.Observe(6 * gib)
	if !p.HaveRemaining || p.Remaining <= 0 || math.IsNaN(p.Remaining.Seconds()) {
		t.Errorf("a plain scan gave Remaining = %v, %v", p.Remaining, p.HaveRemaining)
	}
}

// The estimator works with the real clock when it is given none, and its
// samples do not pile up over a long scan.
func TestScanEstimatorKeepsOnlyTheWindow(t *testing.T) {
	c := newClock()
	estimator := NewScanEstimator(1000*gib, c.Now)
	for i := 1; i <= 500; i++ {
		c.advance(2)
		estimator.Observe(int64(i) * gib)
	}
	if n := len(estimator.samples); n > 40 {
		t.Errorf("%d samples kept for a one-minute window of reports 2 s apart", n)
	}
	if NewScanEstimator(gib, nil).now == nil {
		t.Error("no clock given, none used")
	}
}

func TestRemainingClause(t *testing.T) {
	for _, test := range []struct {
		d    time.Duration
		want string
	}{
		{0, "under 10 s left"},
		{4 * time.Second, "under 10 s left"},
		{7 * time.Second, "under 10 s left"},
		{8 * time.Second, "about 10 s left"},
		{44 * time.Second, "about 45 s left"},
		{57 * time.Second, "about 55 s left"},
		{58 * time.Second, "about 1 min left"},
		{89 * time.Second, "about 1 min left"},
		{90 * time.Second, "about 2 min left"},
		{20 * time.Minute, "about 20 min left"},
		{59*time.Minute + 40*time.Second, "about 1 h left"},
		{80 * time.Minute, "about 1 h 20 min left"},
		{2*time.Hour + 31*time.Minute, "about 2 h 30 min left"},
		{47 * time.Hour, "about 47 h left"},
	} {
		if got := remainingClause(test.d); got != test.want {
			t.Errorf("remainingClause(%v) = %q, want %q", test.d, got, test.want)
		}
	}
}

// The heartbeat shows the last report again, less the time it said was left.
func TestWithoutEstimate(t *testing.T) {
	for message, want := range map[string]string{
		"VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%), about 1 min left.":     "VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%).",
		"VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%), under 10 s left.":      "VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%).",
		"VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%), about 1 h 20 min left": "VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%)",
		"VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%).":                       "VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%).",
		"VM 9100 full mapped-image integrity scan: 7 GiB verified.":                                       "VM 9100 full mapped-image integrity scan: 7 GiB verified.",
		"Applied dhcp profile for VM 9100, about 3 min left over for later.":                              "Applied dhcp profile for VM 9100, about 3 min left over for later.",
		"": "",
	} {
		if got := WithoutEstimate(message); got != want {
			t.Errorf("WithoutEstimate(%q) = %q, want %q", message, got, want)
		}
	}
	// Whatever the estimator says is what WithoutEstimate removes.
	for _, seconds := range []int{0, 3, 8, 30, 58, 61, 600, 3599, 3600, 5400, 7500, 90000} {
		suffix := ScanProgress{Total: 12 * gib, Percent: 58, HaveRemaining: true, Remaining: time.Duration(seconds) * time.Second}.Suffix()
		line := fmt.Sprintf("VM 9100 full mapped-image integrity scan: 7 GiB verified%s.", suffix)
		if got, want := WithoutEstimate(line), "VM 9100 full mapped-image integrity scan: 7 GiB verified of 12 GiB (58%)."; got != want {
			t.Errorf("%d s left: WithoutEstimate(%q) = %q", seconds, line, got)
		}
	}
}

func TestFormatSize(t *testing.T) {
	for n, want := range map[int64]string{
		0:                    "0 B",
		512:                  "512 B",
		4096:                 "4 KiB",
		36 << 20:             "36 MiB",
		gib:                  "1 GiB",
		12 * gib:             "12 GiB",
		10*gib + 512<<20:     "10.5 GiB",
		gib + 1:              "1.0 GiB",
		2048 * gib:           "2048 GiB",
		(1 << 20) + (1 << 9): "1.0 MiB",
		(1 << 20) + 123:      "1.0 MiB", // not "2 MiB" (chaos L9)
		5<<20 + 600<<10:      "5.6 MiB",
		36<<20 + 123:         "36 MiB",
		10<<20 + 1<<19 + 1:   "11 MiB",
	} {
		if got := FormatSize(n); got != want {
			t.Errorf("FormatSize(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestElapsed(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Second:                          "0s",
		0:                                     "0s",
		499 * time.Millisecond:                "0s",
		45 * time.Second:                      "45s",
		59*time.Second + 600*time.Millisecond: "1m00s",
		2*time.Minute + 9*time.Second:         "2m09s",
		59*time.Minute + 59*time.Second:       "59m59s",
		time.Hour + 2*time.Minute + 9*time.Second:    "1h02m09s",
		26*time.Hour + 3*time.Minute + 4*time.Second: "26h03m04s",
	} {
		if got := Elapsed(d); got != want {
			t.Errorf("Elapsed(%v) = %q, want %q", d, got, want)
		}
	}
}

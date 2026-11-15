// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package support

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	for _, tc := range []struct {
		in           string
		known        bool
		major, minor int
		raw          string
	}{
		{"8.4.0", true, 8, 4, "8.4.0"},
		{"9.1.1", true, 9, 1, "9.1.1"},
		{"9.2.11", true, 9, 2, "9.2.11"},
		{"8.4", true, 8, 4, "8.4"}, // PVE answers 8.4 in some fixtures and releases
		{"10.0", true, 10, 0, "10.0"},
		{"8.99", true, 8, 99, "8.99"},
		{"7.4-20", true, 7, 4, "7.4-20"},       // pve-manager's package spelling
		{"8.4.0~rc1", true, 8, 4, "8.4.0~rc1"}, // a pre-release
		{"3.4.0-1", true, 3, 4, "3.4.0-1"},     // a Debian revision
		{"4.2.7", true, 4, 2, "4.2.7"},
		{" 9.1.1\r\n", true, 9, 1, "9.1.1"}, // trimmed
		{"9", true, 9, 0, "9"},
		{"", false, 0, 0, ""},
		{"   ", false, 0, 0, ""},
		{"garbage", false, 0, 0, ""},
		{"unknown", false, 0, 0, ""},
		{"v9.1", false, 0, 0, ""},
		{"9.x", false, 0, 0, ""},
		{"8.4junk", false, 0, 0, ""},
		{"-1.2", false, 0, 0, ""},
		{"99999.1", false, 0, 0, ""},
		{"9.1.1 (build 4)", false, 0, 0, ""},                 // one token, or it is not a version
		{"9.1\x1b[31m", false, 0, 0, ""},                     // nothing a terminal would act on
		{"9.1.1\n8.0.0", false, 0, 0, ""},                    // two lines are not one version
		{"9.1.1" + strings.Repeat("a", 80), false, 0, 0, ""}, // bounded
	} {
		got := ParseVersion(tc.in)
		if got.Known() != tc.known || got.Major != tc.major || got.Minor != tc.minor || got.Raw != tc.raw {
			t.Errorf("ParseVersion(%q) = %+v, want known=%v %d.%d raw %q", tc.in, got, tc.known, tc.major, tc.minor, tc.raw)
		}
		if !tc.known && got.String() != "unknown" {
			t.Errorf("ParseVersion(%q).String() = %q, want unknown", tc.in, got.String())
		}
		if tc.known && got.String() != tc.raw {
			t.Errorf("ParseVersion(%q).String() = %q, want %q", tc.in, got.String(), tc.raw)
		}
	}
}

// The classification of every pair the release statement and the edge
// versions of each rule are pinned here. A pair becomes tested by editing
// Pairs, and this table with it.
func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		name            string
		pve, pbs, cli   string
		want            Level
		verdict         string
		reasonContains  string
		unreadContained []string
	}{
		{"the tested pair", "9.1.1", "4.2.7", "4.2.5", Tested, "tested", "release evidence", nil},
		{"a test cluster's pair", "9.2.11", "4.2.7", "4.2.7", Tested, "tested", "", nil},
		{"PVE 9.0 with PBS 4.0", "9.0", "4.0.0", "4.0.0", Tested, "tested", "", nil},
		{"PVE 8.4 with PBS 4.x and the 3.x client it ships", "8.4.0", "4.2.7", "3.3.7", Tested, "tested", "release evidence", nil},
		{"PVE 8.4 with PBS 4.x but a 4.x client", "8.4.0", "4.2.7", "4.2.5", Untested, "untested", "not of major 3", nil},
		{"PVE 8.4 with PBS 3.x", "8.4.0", "3.4.0", "3.3.7", Tested, "tested", "release evidence", nil},
		{"PVE 8.3 with PBS 3.x", "8.3.5", "3.4.0", "3.3.7", Untested, "untested", "not yet exercised by the release evidence", nil},
		{"PVE 8.4 with PBS 3.x but a 4.x client", "8.4.0", "3.4.0", "4.2.5", Untested, "untested", "same major", nil},
		{"PVE 8.0 with PBS 3.0", "8.0", "3.0.0", "3.0.0", Untested, "untested", "not yet exercised by the release evidence", nil},
		{"PVE 8.99 with a Debian revision", "8.99", "3.4.0-1", "3.3.7", Untested, "untested", "", nil},
		{"a pre-release PVE 8.4 counts as 8.4", "8.4.0~rc1", "3.4.0-1", "3.3.7", Tested, "tested", "", nil},
		{"PVE 9 with PBS 3.x and the 4.x client it ships", "9.1.1", "3.4.0", "4.2.5", Tested, "tested", "release evidence", nil},
		{"PVE 9 with PBS 3.x but a 3.x client", "9.1.1", "3.4.0", "3.3.7", Untested, "untested", "not of major 4", nil},
		{"PVE 10.0 is newer than the evidence", "10.0", "4.2.7", "4.2.5", Untested, "untested", "not yet exercised by the release evidence", nil},
		{"PBS 5 is newer than the evidence", "9.1.1", "5.0.1", "5.0.1", Untested, "untested", "not yet exercised by the release evidence", nil},
		{"PVE 7.4 is older than the release supports", "7.4-20", "4.2.7", "4.2.5", Unsupported, "unsupported", "PVE 8", nil},
		{"PVE 6 is older still", "6.4-1", "3.4.0", "3.3.7", Unsupported, "unsupported", "PVE 8", nil},
		{"PBS 2.x is older than the release supports", "9.1.1", "2.4.7", "2.4.7", Unsupported, "unsupported", "PBS 3", nil},
		{"PBS 2.x beside PVE 8", "8.4.0", "2.4.7", "2.4.7", Unsupported, "unsupported", "PBS 3", nil},
		{"a client older than the release supports", "9.1.1", "4.2.7", "2.4.7", Unsupported, "unsupported", "proxmox-backup-client 3", nil},
		{"an old PVE is refused although PBS was not read", "7.4-20", "", "", Unsupported, "unsupported", "PVE 8", nil},
		{"an old PBS is refused although PVE was not read", "", "2.4.7", "", Unsupported, "unsupported", "PBS 3", nil},
		{"nothing could be read", "", "", "", Untested, "unknown", "could not be read", []string{"PVE", "PBS", "proxmox-backup-client"}},
		{"PVE could not be read", "", "4.2.7", "4.2.5", Untested, "unknown", "could not be read", []string{"PVE"}},
		{"PBS could not be read", "9.1.1", "", "4.2.5", Untested, "unknown", "could not be read", []string{"PBS"}},
		{"the client could not be read", "9.1.1", "4.2.7", "", Untested, "unknown", "could not be read", []string{"proxmox-backup-client"}},
		{"garbage is not a version", "garbage", "4.2.7", "4.2.5", Untested, "unknown", "could not be read", []string{"PVE"}},
		{"a client of another major than the server", "9.1.1", "4.2.7", "3.3.7", Untested, "untested", "3.3.7", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(ParseVersion(tc.pve), ParseVersion(tc.pbs), ParseVersion(tc.cli))
			if got.Level != tc.want {
				t.Fatalf("Classify(%q, %q, %q) = %s (%s), want %s", tc.pve, tc.pbs, tc.cli, got.Level, got.Reason, tc.want)
			}
			if got.Verdict() != tc.verdict {
				t.Errorf("verdict = %q, want %q", got.Verdict(), tc.verdict)
			}
			if got.Reason == "" {
				t.Error("the classification gives no reason")
			}
			if !strings.Contains(got.Reason, tc.reasonContains) {
				t.Errorf("reason %q lacks %q", got.Reason, tc.reasonContains)
			}
			for _, name := range tc.unreadContained {
				if !strings.Contains(strings.Join(got.Unread, ","), name) {
					t.Errorf("unread %v lacks %q", got.Unread, name)
				}
			}
			if tc.verdict != "unknown" && tc.want != Unsupported && len(got.Unread) > 0 {
				t.Errorf("unread %v for versions that were all read", got.Unread)
			}
			line := got.Describe()
			for _, v := range []Version{got.PVE, got.PBS, got.Client} {
				if !strings.Contains(line, v.String()) {
					t.Errorf("Describe() %q does not name %q", line, v.String())
				}
			}
			if strings.ContainsAny(line, "\r\n") {
				t.Errorf("Describe() is not one line: %q", line)
			}
			if !strings.Contains(line, tc.want.String()) {
				t.Errorf("Describe() %q does not say %s", line, tc.want)
			}
			if tc.want == Untested && !strings.Contains(line, "not covered by the release evidence") {
				t.Errorf("Describe() %q does not say that results are not covered by the release evidence", line)
			}
			if (got.Refusal() != nil) != (tc.want == Unsupported) {
				t.Errorf("Refusal() = %v for %s", got.Refusal(), tc.want)
			}
		})
	}
}

// An unsupported pair is refused with the text doctor, run and plan all show.
func TestRefusalIsTheDescription(t *testing.T) {
	status := Classify(ParseVersion("7.4-20"), ParseVersion("3.4.0"), ParseVersion("3.3.7"))
	err := status.Refusal()
	if err == nil || err.Error() != status.Describe() {
		t.Fatalf("Refusal() = %v, want the description %q", err, status.Describe())
	}
	var refusal *UnsupportedError
	if !errors.As(err, &refusal) || refusal.Status.PVE.Raw != "7.4-20" {
		t.Fatalf("Refusal() is not an *UnsupportedError carrying the status: %#v", err)
	}
	for _, want := range []string{"PVE 7.4-20", "PBS 3.4.0", "proxmox-backup-client 3.3.7", "unsupported"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q lacks %q", err, want)
		}
	}
	if Classify(ParseVersion("9.1.1"), ParseVersion("4.2.7"), ParseVersion("4.2.5")).Refusal() != nil {
		t.Error("a tested pair was refused")
	}
}

// The initial content of the table: one tested pair, and every other pair of
// the supported majors listed as untested. Whoever flips a pair after live
// evidence edits Pairs and this list.
func TestPairsHoldTheReleaseStatement(t *testing.T) {
	tested := map[string]bool{}
	seen := map[string]bool{}
	for _, p := range Pairs {
		key := p.Describe()
		if seen[key] {
			t.Errorf("pair %s is listed twice", key)
		}
		seen[key] = true
		if strings.TrimSpace(p.Reason) == "" {
			t.Errorf("pair %s has no reason", key)
		}
		if p.Level == Unsupported {
			t.Errorf("pair %s is unsupported; unsupported is decided by MinPVEMajor and MinPBSMajor, not by a pair", key)
		}
		if p.Level == Tested {
			tested[key] = true
		}
	}
	if len(tested) != 4 || !tested["PVE 9.x with PBS 4.x"] || !tested["PVE 9.x with PBS 3.x"] || !tested["PVE 8.4 with PBS 4.x"] || !tested["PVE 8.4 with PBS 3.x"] {
		t.Errorf("tested pairs = %v, want PVE 9.x and PVE 8.4, each with PBS 3.x and PBS 4.x", tested)
	}
	for _, want := range []string{"PVE 9.x with PBS 3.x", "PVE 8.x with PBS 3.x", "PVE 8.x with PBS 4.x"} {
		if !seen[want] {
			t.Errorf("pair %s is not listed", want)
		}
	}
	if MinPVEMajor != 8 || MinPBSMajor != 3 {
		t.Errorf("minimums are PVE %d and PBS %d, want PVE 8 and PBS 3", MinPVEMajor, MinPBSMajor)
	}
}

// A pair the table does not list is untested, not tested and not refused.
func TestUnlistedPairIsUntested(t *testing.T) {
	got := Classify(ParseVersion("12.3"), ParseVersion("9.1"), ParseVersion("9.1"))
	if got.Level != Untested || !strings.Contains(got.Reason, "not yet exercised") {
		t.Fatalf("unlisted pair = %s (%s)", got.Level, got.Reason)
	}
}

func TestDetectReadsTheSourcesAndNeverFails(t *testing.T) {
	ctx := context.Background()
	got := Detect(ctx, Sources{
		PVE: func(context.Context) (string, error) { return "9.1.1", nil },
		PBS: func(context.Context) (string, string, error) { return "4.2.5", "4.2.7", nil },
	})
	if got.Level != Tested || got.PVE.Raw != "9.1.1" || got.PBS.Raw != "4.2.7" || got.Client.Raw != "4.2.5" {
		t.Fatalf("Detect = %+v", got)
	}

	// A version that cannot be read is unknown, never an error by itself.
	for name, sources := range map[string]Sources{
		"no sources":   {},
		"both fail":    {PVE: func(context.Context) (string, error) { return "", errors.New("refused") }, PBS: func(context.Context) (string, string, error) { return "", "", errors.New("not found") }},
		"garbage":      {PVE: func(context.Context) (string, error) { return "<html>", nil }, PBS: func(context.Context) (string, string, error) { return "??", "??", nil }},
		"client only":  {PBS: func(context.Context) (string, string, error) { return "4.2.5", "", nil }},
		"server error": {PVE: func(context.Context) (string, error) { return "9.1.1", nil }, PBS: func(context.Context) (string, string, error) { return "4.2.5", "", errors.New("could not connect") }},
	} {
		got := Detect(ctx, sources)
		if got.Level != Untested || got.Verdict() != "unknown" || got.Refusal() != nil || len(got.Unread) == 0 {
			t.Errorf("%s: Detect = %+v (%s), want untested, unknown, never refused", name, got, got.Verdict())
		}
	}

	// A source that answers with an error and a version at once is read by
	// its version: the error says only that the command did not finish well.
	got = Detect(ctx, Sources{PBS: func(context.Context) (string, string, error) { return "4.2.5", "4.2.7", errors.New("exit status 1") }})
	if got.Client.Raw != "4.2.5" || got.PBS.Raw != "4.2.7" {
		t.Errorf("versions of a source that also returned an error were dropped: %+v", got)
	}
}

func TestDetectPassesItsContext(t *testing.T) {
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "marker")
	var pveSaw, pbsSaw any
	Detect(ctx, Sources{
		PVE: func(c context.Context) (string, error) { pveSaw = c.Value(key{}); return "", nil },
		PBS: func(c context.Context) (string, string, error) { pbsSaw = c.Value(key{}); return "", "", nil },
	})
	if pveSaw != "marker" || pbsSaw != "marker" {
		t.Fatalf("sources did not get the caller's context: %v %v", pveSaw, pbsSaw)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package support is the one place that says which Proxmox versions this
// release has been tested with. A node reports a Proxmox VE version, a PBS
// server version and a proxmox-backup-client version; Classify matches them
// against the table in Pairs and says whether the pair is tested, untested or
// unsupported, with a reason. certistack doctor, run, plan and the signed
// report all take their answer from here, so the statement the guides make
// ("see the version check in certistack doctor") is the code's.
//
// A version that cannot be read is unknown, which is untested and never an
// error by itself: a node that does not answer is not a node that is
// unsupported.
package support

import (
	"context"
	"fmt"
	"strings"
)

// Level is how far the release evidence reaches for a pair of versions.
type Level string

const (
	// Tested pairs are the ones the release evidence was gathered on.
	Tested Level = "tested"
	// Untested pairs are not refused, but nothing the release evidence shows
	// applies to them.
	Untested Level = "untested"
	// Unsupported versions are refused before anything is created.
	Unsupported Level = "unsupported"
)

func (l Level) String() string { return string(l) }

// MinPVEMajor and MinPBSMajor are the oldest releases this one accepts. The
// proxmox-backup-client must be at least MinPBSMajor too. Anything older is
// Unsupported whatever the other versions are.
const (
	MinPVEMajor = 8
	MinPBSMajor = 3
)

// AnyMinor in a Pair matches every minor release of its PVE major.
const AnyMinor = -1

// Pair classifies one (PVE release, PBS major) combination. It is the table
// to edit when live evidence moves a pair to Tested: change its Level and
// Reason, and the test that pins the table. A combination that Pairs does not
// list, and that is not older than the minimums, is Untested with
// DefaultReason.
type Pair struct {
	PVEMajor int
	PVEMinor int // AnyMinor, or the one minor release of PVEMajor
	PBSMajor int
	// ClientMajor is the major of proxmox-backup-client the evidence ran with;
	// 0 means the PBS major. PVE 8 ships the 3.x client, so its evidence with a
	// PBS 4 server ran with a client of another major than the server's.
	ClientMajor int
	Level       Level
	Reason      string
}

// Describe names the pair the way the guides do: "PVE 9.x with PBS 4.x".
func (p Pair) Describe() string {
	minor := "x"
	if p.PVEMinor != AnyMinor {
		minor = fmt.Sprint(p.PVEMinor)
	}
	return fmt.Sprintf("PVE %d.%s with PBS %d.x", p.PVEMajor, minor, p.PBSMajor)
}

func (p Pair) matches(pve, pbs Version) bool {
	return pve.Major == p.PVEMajor && (p.PVEMinor == AnyMinor || pve.Minor == p.PVEMinor) && pbs.Major == p.PBSMajor
}

const (
	// TestedReason is the reason of a Tested pair.
	TestedReason = "the pair the release evidence covers"
	// DefaultReason is the reason of a pair that has not been exercised.
	DefaultReason = "not yet exercised by the release evidence"
)

// Pairs is the support table, the first match winning. The untested rows
// repeat what the default would say; they are here so that flipping a pair
// to Tested is one edit of one row.
var Pairs = []Pair{
	{PVEMajor: 9, PVEMinor: AnyMinor, PBSMajor: 4, Level: Tested, Reason: TestedReason},
	// PVE 8.4 ships proxmox-backup-client 3.x, so with a PBS 4 server the client is of another major.
	{PVEMajor: 8, PVEMinor: 4, PBSMajor: 4, ClientMajor: 3, Level: Tested, Reason: TestedReason},
	{PVEMajor: 8, PVEMinor: 4, PBSMajor: 3, Level: Tested, Reason: TestedReason},
	// PVE 9 ships proxmox-backup-client 4.x, so with a PBS 3 server the client is of another major.
	{PVEMajor: 9, PVEMinor: AnyMinor, PBSMajor: 3, ClientMajor: 4, Level: Tested, Reason: TestedReason},
	{PVEMajor: 8, PVEMinor: AnyMinor, PBSMajor: 4, Level: Untested, Reason: DefaultReason},
	{PVEMajor: 8, PVEMinor: AnyMinor, PBSMajor: 3, Level: Untested, Reason: DefaultReason},
}

// Version is a version a node reported. The zero value is a version that
// could not be read.
type Version struct {
	// Raw is the version as the node wrote it ("9.1.1", "7.4-20",
	// "4.2.7"), cleaned to one bounded token; empty when it was not read.
	Raw          string
	Major, Minor int
}

// Known reports whether the version was read.
func (v Version) Known() bool { return v.Raw != "" }

// String is the version as read, or "unknown".
func (v Version) String() string {
	if !v.Known() {
		return "unknown"
	}
	return v.Raw
}

// maxVersionLen bounds a version taken from a node: it goes into a signed
// report and onto an operator's terminal.
const maxVersionLen = 48

// ParseVersion reads a version such as "8.4.0", "9.1.1", "7.4-20",
// "8.4.0~rc1" or "3.4.0-1": a major, usually a minor, and anything a package
// version adds after a ".", "-", "~" or "+". It accepts one short token of
// letters, digits and ".+~:_-" and nothing else, so what it keeps can be
// printed and signed. Anything else, including an empty string, is unknown.
func ParseVersion(s string) Version {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxVersionLen {
		return Version{}
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case strings.ContainsRune(".+~:_-", r):
		default:
			return Version{}
		}
	}
	major, i, ok := leadingNumber(s, 0)
	if !ok {
		return Version{}
	}
	minor := 0
	if i < len(s) && s[i] == '.' {
		n, next, ok := leadingNumber(s, i+1)
		if !ok {
			return Version{}
		}
		minor, i = n, next
	}
	if i < len(s) && !strings.ContainsRune(".-~+", rune(s[i])) {
		return Version{}
	}
	return Version{Raw: s, Major: major, Minor: minor}
}

// leadingNumber reads one to four digits of s at i.
func leadingNumber(s string, i int) (n, next int, ok bool) {
	next = i
	for next < len(s) && s[next] >= '0' && s[next] <= '9' {
		n = n*10 + int(s[next]-'0')
		next++
	}
	if digits := next - i; digits == 0 || digits > 4 {
		return 0, i, false
	}
	return n, next, true
}

// Status is the classification of the versions a node reported.
type Status struct {
	Level  Level
	Reason string
	// PVE is the Proxmox VE version, PBS the PBS server's and Client the
	// proxmox-backup-client's.
	PVE, PBS, Client Version
	// Unread names the versions that could not be read.
	Unread []string
}

// Classify matches the three versions against the minimums and Pairs. An
// unsupported version decides the answer whatever else was read; otherwise a
// version that could not be read makes the pair untested.
func Classify(pve, pbs, client Version) Status {
	s := Status{PVE: pve, PBS: pbs, Client: client}
	if !pve.Known() {
		s.Unread = append(s.Unread, "PVE version")
	}
	if !pbs.Known() {
		s.Unread = append(s.Unread, "PBS server version")
	}
	if !client.Known() {
		s.Unread = append(s.Unread, "proxmox-backup-client version")
	}

	var refusals []string
	if pve.Known() && pve.Major < MinPVEMajor {
		refusals = append(refusals, fmt.Sprintf("PVE %s is older than PVE %d, the oldest this release supports", pve.Raw, MinPVEMajor))
	}
	if pbs.Known() && pbs.Major < MinPBSMajor {
		refusals = append(refusals, fmt.Sprintf("PBS %s is older than PBS %d, the oldest this release supports", pbs.Raw, MinPBSMajor))
	}
	if client.Known() && client.Major < MinPBSMajor {
		refusals = append(refusals, fmt.Sprintf("proxmox-backup-client %s is older than proxmox-backup-client %d, the oldest this release supports", client.Raw, MinPBSMajor))
	}
	if len(refusals) > 0 {
		s.Level, s.Reason = Unsupported, strings.Join(refusals, "; ")
		return s
	}

	if len(s.Unread) > 0 {
		s.Level = Untested
		s.Reason = "the " + joinAnd(s.Unread) + " could not be read, so the pair cannot be matched to the release evidence"
		return s
	}

	s.Level, s.Reason = Untested, DefaultReason
	clientMajor := pbs.Major
	for _, p := range Pairs {
		if p.matches(pve, pbs) {
			s.Level, s.Reason = p.Level, p.Reason
			if p.ClientMajor != 0 {
				clientMajor = p.ClientMajor
			}
			break
		}
	}
	if s.Level == Tested && client.Major != clientMajor {
		s.Level = Untested
		if clientMajor == pbs.Major {
			s.Reason = fmt.Sprintf("proxmox-backup-client %s is not of the same major as PBS %s, and the release evidence ran them together", client.Raw, pbs.Raw)
		} else {
			s.Reason = fmt.Sprintf("proxmox-backup-client %s is not of major %d, the one the release evidence ran with PBS %s on this Proxmox VE", client.Raw, clientMajor, pbs.Raw)
		}
	}
	return s
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", the ") + " and the " + items[len(items)-1]
}

// Verdict is what doctor and the signed report call the status: "tested",
// "untested" or "unsupported", and "unknown" for a status that is untested
// because a version could not be read.
func (s Status) Verdict() string {
	if s.Level != Unsupported && len(s.Unread) > 0 {
		return "unknown"
	}
	return s.Level.String()
}

// Describe is the status on one line. It names the three versions, the level
// and its reason, and for an untested pair says that the release evidence
// does not cover results with it. doctor prints it, and run and plan refuse
// with it.
func (s Status) Describe() string {
	versions := fmt.Sprintf("PVE %s, PBS %s, proxmox-backup-client %s", s.PVE, s.PBS, s.Client)
	switch s.Level {
	case Tested:
		return fmt.Sprintf("%s: tested (%s)", versions, s.Reason)
	case Unsupported:
		return fmt.Sprintf("%s: unsupported (%s); this release refuses to run with them", versions, s.Reason)
	}
	return fmt.Sprintf("%s: untested (%s); results with this pair are not covered by the release evidence", versions, s.Reason)
}

// UnsupportedError is the refusal of an unsupported status. Its text is the
// status's description.
type UnsupportedError struct{ Status Status }

func (e *UnsupportedError) Error() string { return e.Status.Describe() }

// Refusal is nil unless the status is unsupported.
func (s Status) Refusal() error {
	if s.Level != Unsupported {
		return nil
	}
	return &UnsupportedError{Status: s}
}

// Sources read the versions of a node. A nil source reads nothing. An error
// from a source is not an error of Detect: the version it would have read is
// unknown, and a source that returns versions along with an error (a command
// that printed its version and then failed) is read by them.
type Sources struct {
	// PVE returns the Proxmox VE version.
	PVE func(ctx context.Context) (string, error)
	// PBS returns the proxmox-backup-client version and the PBS server's.
	PBS func(ctx context.Context) (client, server string, err error)
}

// Detect reads the versions from s and classifies them. It never fails.
func Detect(ctx context.Context, s Sources) Status {
	var pve, client, server string
	if s.PVE != nil {
		pve, _ = s.PVE(ctx)
	}
	if s.PBS != nil {
		client, server, _ = s.PBS(ctx)
	}
	return Classify(ParseVersion(pve), ParseVersion(server), ParseVersion(client))
}

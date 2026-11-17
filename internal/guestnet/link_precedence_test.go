// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"path"
	"sort"
	"strings"
	"testing"
)

const linkTestMAC = "BC:24:11:90:01:01"

// effectiveLink is the .link file systemd (udev's link_config) applies to a
// NIC with this MAC in a guest tree: the first, in file-name order across all
// its directories, whose [Match] selects it. A file hides a file of the same
// name in a later directory, and a link to /dev/null hides it altogether. It
// understands the match keys the fixtures use (MACAddress, OriginalName with
// "*"); a file with any other key does not match.
func effectiveLink(g *memGuest, mac string) (name, contents string) {
	owner := map[string]string{}
	for _, dir := range systemdSearchDirs(".link") {
		for file := range g.files {
			if rest, ok := strings.CutPrefix(file, dir+"/"); ok && !strings.Contains(rest, "/") && strings.HasSuffix(rest, ".link") {
				if _, taken := owner[rest]; !taken {
					owner[rest] = file
				}
			}
		}
	}
	var names []string
	for n, file := range owner {
		if target, link := strings.CutPrefix(g.files[file], "-> "); link {
			if !path.IsAbs(target) {
				target = path.Join(path.Dir(file), target)
			}
			if path.Clean(target) == "/dev/null" {
				continue
			}
		}
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		text := g.files[owner[n]]
		if matchesLinkFixture(text, mac) {
			return owner[n], text
		}
	}
	return "", ""
}

func matchesLinkFixture(text, mac string) bool {
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || section != "[Match]" {
			continue
		}
		switch strings.TrimSpace(key) {
		case "MACAddress":
			if !containsMAC(strings.Fields(value), mac) {
				return false
			}
		case "OriginalName":
			if strings.TrimSpace(value) != "*" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func linkFixture(match, name string) string {
	return "[Match]\n" + match + "\n\n[Link]\nNamePolicy=\nName=" + name + "\n"
}

func applyWithName(t *testing.T, files map[string]string, name string) (*memGuest, Result, error) {
	t.Helper()
	all := map[string]string{ifupdownConfig: "auto eth0\niface eth0 inet dhcp\n"}
	for file, contents := range files {
		all[file] = contents
	}
	guest := newMemGuest(t, all, ifupdownDir)
	cfg := multiDiskConfig(bootOverlayPath)
	cfg.MAC, cfg.Mode, cfg.InterfaceName, cfg.OnlyNIC = linkTestMAC, modeIfupdown, name, true
	result, err := guest.adapter().Apply(context.Background(), cfg)
	return guest, result, err
}

// A valid .link file of the guest that sorts before the generated one and
// matches the recovered MAC would be applied first by udev, naming the NIC
// "earlier0" while the ifupdown stanza and the generated rule say "requested0".
// The generated rule must be the one udev applies.
func TestAnEarlierLinkFileDoesNotDefeatTheRequestedName(t *testing.T) {
	earlier := "/etc/systemd/network/00-audit-earlier.link"
	earlierText := linkFixture("MACAddress="+linkTestMAC, "earlier0")
	guest, result, err := applyWithName(t, map[string]string{earlier: earlierText}, "requested0")
	if err != nil {
		t.Fatal(err)
	}
	name, text := effectiveLink(guest, linkTestMAC)
	if !strings.Contains(text, "Name=requested0\n") || path.Base(name) == "00-audit-earlier.link" {
		t.Fatalf("udev applies %s, which names the NIC:\n%s\nwant the generated rule naming requested0", name, text)
	}
	if !containsString(result.Files, name) {
		t.Fatalf("the signed result %v does not list the rule udev applies, %s", result.Files, name)
	}
	if guest.files[earlier] != earlierText {
		t.Fatal("the guest's own .link file was changed")
	}
	if stanza := guest.files[ifupdownConfig]; !strings.Contains(stanza, "iface requested0 inet static") {
		t.Fatalf("ifupdown profile:\n%s", stanza)
	}
}

// The rest of the effective .link set: a rule in any of systemd's directories
// can sort first.
func TestTheGeneratedLinkRuleSortsBeforeEveryRuleThatMayMatch(t *testing.T) {
	matching := linkFixture("OriginalName=*", "vendor0")
	otherMAC := linkFixture("MACAddress=02:00:00:00:00:99", "other0")
	cases := []struct {
		name  string
		files map[string]string
		want  string // the generated rule's file name
	}{
		{"nothing else", nil, "00-certistack-recovery.link"},
		{"a rule that sorts after", map[string]string{"/etc/systemd/network/99-late.link": matching}, "00-certistack-recovery.link"},
		{"a rule for another MAC", map[string]string{"/etc/systemd/network/00-aaa.link": otherMAC}, "00-certistack-recovery.link"},
		{"an earlier rule in /etc", map[string]string{"/etc/systemd/network/00-aaa.link": matching}, "0-certistack-recovery.link"},
		{"an earlier rule in /run", map[string]string{"/run/systemd/network/00-aaa.link": matching}, "0-certistack-recovery.link"},
		{"an earlier rule in /usr/local/lib", map[string]string{"/usr/local/lib/systemd/network/00-aaa.link": matching}, "0-certistack-recovery.link"},
		{"an earlier rule in /usr/lib", map[string]string{"/usr/lib/systemd/network/00-aaa.link": matching}, "0-certistack-recovery.link"},
		{"an earlier rule in /lib", map[string]string{"/lib/systemd/network/00-aaa.link": matching}, "0-certistack-recovery.link"},
		{"the vendor's usual rules sort after", map[string]string{"/usr/lib/systemd/network/99-default.link": linkFixture("OriginalName=*", "kernel"), "/usr/lib/systemd/network/73-usb-net-by-mac.link": matching}, "00-certistack-recovery.link"},
		{"a rule in /etc hides a matching one of its name in /usr/lib", map[string]string{"/etc/systemd/network/00-aaa.link": otherMAC, "/usr/lib/systemd/network/00-aaa.link": matching}, "00-certistack-recovery.link"},
		{"a link to /dev/null hides a matching rule of its name", map[string]string{"/etc/systemd/network/00-aaa.link": "-> /dev/null", "/usr/lib/systemd/network/00-aaa.link": matching}, "00-certistack-recovery.link"},
		{"a relative link to /dev/null hides it too", map[string]string{"/etc/systemd/network/00-aaa.link": "-> ../../../dev/null", "/lib/systemd/network/00-aaa.link": matching}, "00-certistack-recovery.link"},
		{"two earlier rules", map[string]string{"/etc/systemd/network/00-aaa.link": matching, "/run/systemd/network/00-bbb.link": matching}, "0-certistack-recovery.link"},
		{"a rule that sorts before the second name too", map[string]string{"/usr/lib/systemd/network/0-aaa.link": matching}, "-certistack-recovery.link"},
		{"a rule with a drop-in directory may match", map[string]string{"/usr/lib/systemd/network/00-aaa.link": otherMAC, "/etc/systemd/network/00-aaa.link.d/x.conf": "[Match]\nOriginalName=*\n"}, "0-certistack-recovery.link"},
		{"a rule that is a link to a file may match", map[string]string{"/usr/lib/systemd/network/00-aaa.link": "-> /usr/share/x.link", "/usr/share/x.link": matching}, "0-certistack-recovery.link"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest, _, err := applyWithName(t, tc.files, "requested0")
			if err != nil {
				t.Fatal(err)
			}
			name, text := effectiveLink(guest, linkTestMAC)
			if path.Base(name) != tc.want || !strings.Contains(text, "Name=requested0\n") {
				t.Fatalf("udev applies %s:\n%s\nwant the generated %s naming requested0", name, text, tc.want)
			}
			if guest.files["/etc/systemd/network/"+tc.want] == "" {
				t.Fatalf("the generated rule is not in /etc/systemd/network/%s", tc.want)
			}
		})
	}
}

// Nothing the recovery can name sorts before a rule called "-aaa.link": it
// stops before writing, with the file named.
func TestALinkRuleSortingBeforeEveryRecoveryNameStopsTheRecovery(t *testing.T) {
	for _, dir := range []string{"/etc/systemd/network", "/usr/lib/systemd/network"} {
		guest, _, err := applyWithName(t, map[string]string{dir + "/-aaa.link": linkFixture("OriginalName=*", "vendor0")}, "requested0")
		if err == nil || !strings.Contains(err.Error(), "-aaa.link") || !strings.Contains(err.Error(), "preserve") {
			t.Fatalf("%s: Apply = %v, want the rule named and preserve offered", dir, err)
		}
		if guest.mutated() {
			t.Fatalf("%s: something was written", dir)
		}
	}
}

// Looking at the other directories costs two guestfish runs, and none when
// no rule could sort first.
func TestLookingAtTheOtherLinkDirectoriesIsCheap(t *testing.T) {
	guest := newMemGuest(t, map[string]string{"/usr/lib/systemd/network/99-default.link": linkFixture("OriginalName=*", "kernel")})
	detection := newDetection(guest.adapter(), []string{bootOverlayPath}, linkTestMAC)
	if _, err := detection.firstMatchFile(context.Background(), ".link"); err != nil {
		t.Fatal(err)
	}
	// /etc is checked, then the others' kinds and listings; nothing sorts first, so nothing is read.
	if len(guest.calls) != 3 {
		t.Fatalf("guestfish runs = %d, want 3: %#v", len(guest.calls), guest.calls)
	}
	if _, err := detection.firstMatchFile(context.Background(), ".link"); err != nil || len(guest.calls) != 3 {
		t.Fatalf("a second look ran guestfish again (%d runs, %v)", len(guest.calls), err)
	}
}

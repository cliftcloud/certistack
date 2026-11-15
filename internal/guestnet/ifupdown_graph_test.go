// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// ifupdownFragments is the conventional default include directory. It is
// active only when the main file sources it.
const ifupdownFragments = ifupdownDir + "/interfaces.d"

const (
	customDir  = ifupdownDir + "/custom.d"
	iface0     = "auto eth0\niface eth0 inet dhcp\n"
	iface1     = "auto eth1\niface eth1 inet dhcp\n"
	iface2     = "auto eth2\niface eth2 inet dhcp\n"
	ifaceEnp   = "auto enp6s18\niface enp6s18 inet dhcp\n"
	sourceAll  = "source /etc/network/interfaces.d/*\n"
	sourceCust = "source /etc/network/custom.d/*\n"
)

func ifupdownGuest(t *testing.T, files map[string]string) *memGuest {
	t.Helper()
	return newMemGuest(t, files, ifupdownDir)
}

func ifupdownNames(t *testing.T, guest *memGuest, onlyNIC bool) ([]string, error) {
	t.Helper()
	return guest.adapter().ifupdownRecoveryNames(context.Background(), []string{bootOverlayPath}, onlyNIC)
}

// referenced reports whether any guestfish call named the path or a path
// beneath it.
func referenced(calls [][]string, prefix string) bool {
	for _, call := range calls {
		for _, arg := range guestfishCommand(call) {
			if arg == prefix || strings.HasPrefix(arg, prefix+"/") {
				return true
			}
		}
	}
	return false
}

// The reported case, in both directions. The main file declares
// enp6s18 and includes nothing; a stale fragment in the default directory
// declares eth1. And the reverse: the main file sources a directory of its own
// where the profile is. Explicit ifupdown mode, as the reporter ran it.
func TestIfupdownDiscoveryFollowsTheConfiguredSourceGraph(t *testing.T) {
	cfg := multiDiskConfig(bootOverlayPath)
	cfg.Mode = modeIfupdown

	t.Run("an unreferenced default fragment is not read", func(t *testing.T) {
		guest := ifupdownGuest(t, map[string]string{
			ifupdownConfig:                    ifaceEnp,
			ifupdownFragments + "/stale-eth1": iface1,
		})
		result, err := guest.adapter().Apply(context.Background(), cfg)
		if err != nil {
			t.Fatalf("Apply = %v, want enp6s18 alone (the stale fragment is not in the include graph)", err)
		}
		if result.Strategy != modeIfupdown {
			t.Fatalf("strategy = %q", result.Strategy)
		}
		if referenced(guest.calls, ifupdownFragments) {
			t.Fatalf("the unreferenced fragment directory was read: %#v", guest.calls)
		}
		written := guest.files[ifupdownConfig]
		if !strings.Contains(written, "iface enp6s18 inet static") || strings.Contains(written, "eth1") {
			t.Fatalf("recovery interfaces:\n%s", written)
		}
	})

	t.Run("a profile in a directory the main file sources is found", func(t *testing.T) {
		guest := ifupdownGuest(t, map[string]string{
			ifupdownConfig:         sourceCust,
			customDir + "/primary": ifaceEnp,
		})
		result, err := guest.adapter().Apply(context.Background(), cfg)
		if err != nil {
			t.Fatalf("Apply = %v, want the sourced enp6s18 profile found", err)
		}
		if result.Strategy != modeIfupdown {
			t.Fatalf("strategy = %q", result.Strategy)
		}
		if !referenced(guest.calls, customDir) {
			t.Fatalf("the sourced directory was never read: %#v", guest.calls)
		}
		if !strings.Contains(guest.files[ifupdownConfig], "iface enp6s18 inet static") {
			t.Fatalf("recovery interfaces:\n%s", guest.files[ifupdownConfig])
		}
	})

	t.Run("inline control", func(t *testing.T) {
		guest := ifupdownGuest(t, map[string]string{ifupdownConfig: ifaceEnp})
		if _, err := guest.adapter().Apply(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
	})
}

func TestIfupdownIncludeGraphShapes(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		onlyNIC bool
		want    []string
	}{
		{
			name:  "source-directory takes only run-parts names",
			files: map[string]string{ifupdownConfig: "source-directory /etc/network/interfaces.d\n", ifupdownFragments + "/50-cloud-init": iface0, ifupdownFragments + "/old.bak": iface1, ifupdownFragments + "/x.dpkg-old": iface2},
			want:  []string{"eth0"},
		},
		{
			name:    "source with a wildcard takes every match but hidden files",
			files:   map[string]string{ifupdownConfig: sourceAll, ifupdownFragments + "/a": iface0, ifupdownFragments + "/b.bak": iface1, ifupdownFragments + "/.hidden": iface2},
			onlyNIC: true,
			want:    []string{"eth0", "eth1"},
		},
		{
			name:  "a wildcard that must match a dot says so",
			files: map[string]string{ifupdownConfig: "source /etc/network/interfaces.d/.*\n", ifupdownFragments + "/a": iface0, ifupdownFragments + "/.hidden": iface2},
			want:  []string{"eth2"},
		},
		{
			name:    "a character class and a question mark",
			files:   map[string]string{ifupdownConfig: "source /etc/network/custom.d/[ab]?\n", customDir + "/a1": iface0, customDir + "/b2": iface1, customDir + "/c3": iface2},
			onlyNIC: true,
			want:    []string{"eth0", "eth1"},
		},
		{
			name:  "a negated class",
			files: map[string]string{ifupdownConfig: "source /etc/network/custom.d/[!a]*\n", customDir + "/a1": iface0, customDir + "/b2": iface1},
			want:  []string{"eth1"},
		},
		{
			name:  "a relative path is relative to the file that names it",
			files: map[string]string{ifupdownConfig: "source custom.d/*\n", customDir + "/p": iface0},
			want:  []string{"eth0"},
		},
		{
			name: "a relative path in a nested file is relative to that file",
			files: map[string]string{
				ifupdownConfig:         "source custom.d/first\n",
				customDir + "/first":   "source extra/*\n",
				customDir + "/extra/s": iface1,
			},
			want: []string{"eth1"},
		},
		{
			name: "includes nest",
			files: map[string]string{
				ifupdownConfig:          "source /etc/network/l1\n",
				ifupdownDir + "/l1":     "source /etc/network/l2\n",
				ifupdownDir + "/l2":     "source-directory /etc/network/l3.d\n",
				ifupdownDir + "/l3.d/z": iface2,
			},
			want: []string{"eth2"},
		},
		{
			name: "the file's own stanzas come first, then its includes in order",
			files: map[string]string{
				ifupdownConfig:   "source /etc/network/custom.d/z\nsource /etc/network/custom.d/a\n" + iface0,
				customDir + "/z": iface1,
				customDir + "/a": iface2,
			},
			onlyNIC: true,
			want:    []string{"eth0", "eth1", "eth2"},
		},
		{
			name: "a wildcard in a directory position matches directories only",
			files: map[string]string{
				ifupdownConfig:            "source /etc/network/*.d/*\n",
				customDir + "/f1":         iface0,
				ifupdownFragments + "/f2": iface1,
				ifupdownDir + "/x.d":      iface2, // a file, not a directory
			},
			onlyNIC: true,
			want:    []string{"eth0", "eth1"},
		},
		{
			name: "unmatched wildcards and missing paths include nothing",
			files: map[string]string{
				ifupdownConfig:            iface0 + "source /etc/network/none.d/*\nsource-directory /etc/network/missing\nsource /etc/network/literal-missing\nsource /etc/network/custom.d/*\n",
				customDir + "/readme.txt": "# nothing here\n",
			},
			want: []string{"eth0"},
		},
		{
			name: "a directory among the matches is skipped",
			files: map[string]string{
				ifupdownConfig:       sourceCust,
				customDir + "/p":     iface0,
				customDir + "/sub/q": iface1,
			},
			want: []string{"eth0"},
		},
		{
			name: "a cycle ends and each file is read once",
			files: map[string]string{
				ifupdownConfig:     "source /etc/network/a\n",
				ifupdownDir + "/a": "source /etc/network/interfaces\nsource /etc/network/a\n" + iface0,
			},
			want: []string{"eth0"},
		},
		{
			name:  "a commented include is not followed",
			files: map[string]string{ifupdownConfig: "# source /etc/network/custom.d/*\n  # source /etc/network/custom.d/*\n" + ifaceEnp, customDir + "/p": iface1},
			want:  []string{"enp6s18"},
		},
		{
			name: "an include continued over lines, with several operands",
			files: map[string]string{
				ifupdownConfig:   "source /etc/network/custom.d/p \\\n   /etc/network/custom.d/q\n",
				customDir + "/p": iface0,
				customDir + "/q": iface1,
			},
			onlyNIC: true,
			want:    []string{"eth0", "eth1"},
		},
		{
			name: "an interface in two files is one interface, virtual if either says so",
			files: map[string]string{
				ifupdownConfig:   sourceCust + "iface eth0 inet manual\n",
				customDir + "/p": "iface eth0 inet static\n    bridge_ports eth1\n" + iface1,
			},
			want: []string{"eth1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest := ifupdownGuest(t, tc.files)
			got, err := ifupdownNames(t, guest, tc.onlyNIC)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("names = %v, want %v", got, tc.want)
			}
		})
	}
}

// The default directory is not read when nothing includes it, whatever it
// holds, and a hidden or non-matching file of a sourced one is not either.
func TestIfupdownReadsOnlyWhatTheGraphReaches(t *testing.T) {
	guest := ifupdownGuest(t, map[string]string{
		ifupdownConfig:               "source-directory /etc/network/custom.d\n",
		customDir + "/ok":            iface0,
		customDir + "/skipped.bak":   iface1,
		ifupdownFragments + "/other": iface2,
	})
	if _, err := ifupdownNames(t, guest, false); err != nil {
		t.Fatal(err)
	}
	for _, call := range guest.calls {
		command := guestfishCommand(call)
		if len(command) > 1 && command[0] == "cat" && command[1] != ifupdownConfig && command[1] != customDir+"/ok" {
			t.Fatalf("read %s, which the include graph does not reach: %#v", command[1], guest.calls)
		}
	}
	if referenced(guest.calls, ifupdownFragments) {
		t.Fatalf("the default directory was touched: %#v", guest.calls)
	}
}

func TestIfupdownRefusesWhatItCannotEvaluateOffline(t *testing.T) {
	for _, operand := range []string{"$HOME/x", "${DIR}/x", "$(cat /etc/dir)", "`cat /etc/dir`", `"/etc/network/a b"`, `'/etc/network/a'`, `/etc/network/a\ b`, "~/x", "~root/x", "/etc/a;b", "/etc/a|b", "/etc/a>b"} {
		for _, directive := range []string{"source", "source-directory"} {
			t.Run(directive+" "+operand, func(t *testing.T) {
				guest := ifupdownGuest(t, map[string]string{ifupdownConfig: directive + " " + operand + "\n" + iface0})
				_, err := ifupdownNames(t, guest, false)
				// A quoted operand with a space is two words to the splitter; the
				// first carries the quote.
				word := strings.Fields(operand)[0]
				if err == nil || !strings.Contains(err.Error(), "cannot be evaluated offline") || !strings.Contains(err.Error(), word) || !strings.Contains(err.Error(), "interface_name") {
					t.Fatalf("error = %v, want %q refused with the way out", err, word)
				}
			})
		}
	}
}

func TestIfupdownMainFileMustExist(t *testing.T) {
	guest := ifupdownGuest(t, map[string]string{customDir + "/p": iface0})
	if _, err := ifupdownNames(t, guest, false); err == nil || !strings.Contains(err.Error(), "read ifupdown configuration") {
		t.Fatalf("error = %v, want the missing main file refused", err)
	}
}

func TestIfupdownIncludeGraphIsBounded(t *testing.T) {
	t.Run("a wildcard that matches too many files", func(t *testing.T) {
		files := map[string]string{ifupdownConfig: sourceCust}
		for i := 0; i <= maxIfupdownFiles; i++ {
			files[fmt.Sprintf("%s/f%03d", customDir, i)] = iface0
		}
		if _, err := ifupdownNames(t, ifupdownGuest(t, files), false); err == nil || !strings.Contains(err.Error(), "matches more than") {
			t.Fatalf("error = %v, want the match count refused", err)
		}
	})
	t.Run("a graph of too many files", func(t *testing.T) {
		// Each file includes the next, so no one directive matches many.
		files := map[string]string{ifupdownConfig: "source /etc/network/f0\n"}
		for i := 0; i < maxIfupdownFiles+2; i++ {
			files[fmt.Sprintf("%s/f%d", ifupdownDir, i)] = fmt.Sprintf("source /etc/network/f%d\n", i+1)
		}
		if _, err := ifupdownNames(t, ifupdownGuest(t, files), false); err == nil || !strings.Contains(err.Error(), "levels deep") && !strings.Contains(err.Error(), "more than") {
			t.Fatalf("error = %v, want the chain refused", err)
		}
	})
	t.Run("includes nested too deep", func(t *testing.T) {
		files := map[string]string{ifupdownConfig: "source /etc/network/d1\n"}
		for i := 1; i <= maxIfupdownDepth+2; i++ {
			files[fmt.Sprintf("%s/d%d", ifupdownDir, i)] = fmt.Sprintf("source /etc/network/d%d\n", i+1)
		}
		if _, err := ifupdownNames(t, ifupdownGuest(t, files), false); err == nil || !strings.Contains(err.Error(), "levels deep") {
			t.Fatalf("error = %v, want the nesting refused", err)
		}
	})
	t.Run("nesting at the limit is read", func(t *testing.T) {
		files := map[string]string{ifupdownConfig: "source /etc/network/d1\n"}
		for i := 1; i < maxIfupdownDepth; i++ {
			files[fmt.Sprintf("%s/d%d", ifupdownDir, i)] = fmt.Sprintf("source /etc/network/d%d\n", i+1)
		}
		files[fmt.Sprintf("%s/d%d", ifupdownDir, maxIfupdownDepth)] = iface0
		names, err := ifupdownNames(t, ifupdownGuest(t, files), false)
		if err != nil || !slices.Equal(names, []string{"eth0"}) {
			t.Fatalf("names = %v, %v; want eth0 at depth %d", names, err, maxIfupdownDepth)
		}
	})
	t.Run("too much text", func(t *testing.T) {
		files := map[string]string{ifupdownConfig: sourceCust, customDir + "/big": "# " + strings.Repeat("x", maxIfupdownBytes) + "\n"}
		if _, err := ifupdownNames(t, ifupdownGuest(t, files), false); err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("error = %v, want the size refused", err)
		}
	})
	t.Run("wildcards that cost too many directory reads", func(t *testing.T) {
		files := map[string]string{ifupdownConfig: "source /etc/network/*/*/*\n"}
		for i := 0; i < maxIfupdownQueries+2; i++ {
			files[fmt.Sprintf("%s/d%03d/e/f", ifupdownDir, i)] = iface0
		}
		if _, err := ifupdownNames(t, ifupdownGuest(t, files), false); err == nil || !strings.Contains(err.Error(), "directory reads") && !strings.Contains(err.Error(), "matches more than") {
			t.Fatalf("error = %v, want the cost refused", err)
		}
	})
}

func TestIfupdownLogicalLines(t *testing.T) {
	got := ifupdownLogicalLines("# comment\n\n  auto eth0  \r\niface eth0 inet static \\\n    address 10.0.0.2/24\n  # another\nsource a b\\\n  c\n")
	want := [][]string{
		{"auto", "eth0"},
		{"iface", "eth0", "inet", "static", "address", "10.0.0.2/24"},
		{"source", "a", "b", "c"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("lines = %v, want %v", got, want)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"strings"
	"testing"
)

const (
	bootLinkTarget = "../certistack-network-recovery.service"
	lateLinkTarget = "../certistack-network-recovery-late.service"
)

func diagnosticConfig() Config {
	cfg := multiDiskConfig(bootOverlayPath)
	cfg.Mode, cfg.CaptureDiagnostics = modeNetworkManager, true
	return cfg
}

func linksIn(commands [][]string) []string {
	var links []string
	for _, command := range commands {
		if command[0] == "ln-s" {
			links = append(links, command[2])
		}
	}
	return links
}

// A plain ln -s fails with EEXIST on the very link that is wanted, so a guest
// that already holds the correct enablement link could not use
// capture_diagnostics: the whole Apply would fail before the sandbox VM
// existed. A link that is already correct is left alone.
func TestAnAlreadyCorrectDiagnosticLinkIsLeftAlone(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"both links there":  {diagnosticLink: "-> " + bootLinkTarget, diagnosticLateLink: "-> " + lateLinkTarget},
		"the first only":    {diagnosticLink: "-> " + bootLinkTarget},
		"the second only":   {diagnosticLateLink: "-> " + lateLinkTarget},
		"no link (control)": nil,
	} {
		t.Run(name, func(t *testing.T) {
			guest := newMemGuest(t, files, networkManagerDir)
			result, err := guest.adapter().Apply(context.Background(), diagnosticConfig())
			if err != nil {
				t.Fatal(err)
			}
			wantCreated := 0
			for _, link := range []string{diagnosticLink, diagnosticLateLink} {
				if _, there := files[link]; !there {
					wantCreated++
				}
			}
			if created := linksIn(batchCommands(lastBatch(guest.calls))); len(created) != wantCreated {
				t.Fatalf("the batch creates %v, want %d link(s): only what is missing", created, wantCreated)
			}
			for link, target := range map[string]string{diagnosticLink: bootLinkTarget, diagnosticLateLink: lateLinkTarget} {
				if guest.files[link] != "-> "+target {
					t.Fatalf("%s = %q, want a link to %s", link, guest.files[link], target)
				}
				// The reported list still says what is in the guest.
				if !containsString(result.Files, link+" -> "+target) {
					t.Fatalf("the reported list lacks %s: %v", link, result.Files)
				}
			}
		})
	}
}

// A second Apply over a guest that already carries the first one's files and
// links works the same.
func TestApplyingTheDiagnosticsTwiceWorks(t *testing.T) {
	guest := newMemGuest(t, nil, networkManagerDir)
	for run := 1; run <= 2; run++ {
		if _, err := guest.adapter().Apply(context.Background(), diagnosticConfig()); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
	}
	if links := linksIn(batchCommands(lastBatch(guest.calls))); len(links) != 0 {
		t.Fatalf("the second run created %v again", links)
	}
}

// What is not the wanted link is not replaced: a blind force would undo that
// lesson and overwrite whatever the guest keeps there.
func TestADiagnosticLinkPathHoldingSomethingElseIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		wantErr string
	}{
		{"a link to another unit", map[string]string{diagnosticLink: "-> ../other.service"}, `pointing to "../other.service"`},
		{"a dangling link elsewhere", map[string]string{diagnosticLateLink: "-> /nonexistent"}, `pointing to "/nonexistent"`},
		{"the right target written absolute", map[string]string{diagnosticLink: "-> /etc/systemd/system/certistack-network-recovery.service"}, "pointing to"},
		{"a regular file", map[string]string{diagnosticLink: "[Unit]\n"}, "a regular file"},
		{"a directory", map[string]string{diagnosticLateLink + "/inner": "x"}, "a directory"},
		{"a named pipe", map[string]string{diagnosticLink: "!fifo"}, "a named pipe"},
		{"the first correct, the second not", map[string]string{diagnosticLink: "-> " + bootLinkTarget, diagnosticLateLink: "-> " + bootLinkTarget}, `pointing to "` + bootLinkTarget + `"`},
		{"the first wrong, the second correct", map[string]string{diagnosticLink: "-> " + lateLinkTarget, diagnosticLateLink: "-> " + lateLinkTarget}, `pointing to "` + lateLinkTarget + `"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest := newMemGuest(t, tc.files, networkManagerDir)
			_, err := guest.adapter().Apply(context.Background(), diagnosticConfig())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "preserve") {
				t.Fatalf("Apply = %v, want it refused with %q and the way out", err, tc.wantErr)
			}
			if guest.mutated() {
				t.Fatal("something was written before the refusal")
			}
		})
	}
}

// The link is read back after the batch: a guest that silently did not create
// it is the run's failure.
func TestADiagnosticLinkThatWasNotCreatedStopsTheRun(t *testing.T) {
	guest := newMemGuest(t, nil, networkManagerDir)
	adapter := guest.adapter()
	dropCommands(adapter, "ln-s")
	if _, err := adapter.Apply(context.Background(), diagnosticConfig()); err == nil || !strings.Contains(err.Error(), "readlink") {
		t.Fatalf("Apply = %v, want the missing link refused at the read-back", err)
	}
}

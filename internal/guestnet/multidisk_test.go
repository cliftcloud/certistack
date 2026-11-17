// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

const (
	bootOverlayPath = "/audit/overlays/vm9001-scsi0.qcow2"
	rootOverlayPath = "/audit/overlays/vm9001-scsi1-root.qcow2"
	dataOverlayPath = "/audit/overlays/vm9001-scsi2-data.qcow2"
)

func multiDiskConfig(overlays ...string) Config {
	return Config{
		VMID: 9001, Overlays: overlays, MAC: "BC:24:11:90:01:01",
		Address: "10.100.0.10", CIDR: "10.100.0.0/24",
	}
}

// requireEveryDrive fails the test unless every guestfish call, the mutating
// batch included, added exactly these overlays in this order, each after its
// own --format=qcow2.
func requireEveryDrive(t *testing.T, guest *memGuest, want []string) {
	t.Helper()
	if len(guest.calls) == 0 {
		t.Fatal("guestfish was never called")
	}
	for _, call := range guest.calls {
		if got := guestfishOverlays(call); !slices.Equal(got, want) {
			t.Fatalf("guestfish call added drives %v, want every restored overlay %v: %#v", got, want, call)
		}
		for i, arg := range call {
			if arg == "-a" && (i == 0 || call[i-1] != "--format=qcow2") {
				t.Fatalf("drive %s has no explicit format: %#v", call[i+1], call)
			}
		}
	}
	if !guest.mutated() {
		t.Fatal("no mutating guestfish batch ran")
	}
}

// A guest restored from two disks (scsi0 boots, scsi1 holds the root
// filesystem) gets every overlay in each of its guestfish calls, the mutating
// batch included. Inspection of such a guest needs both disks, so the
// fixture's guest is inspectable only when both are added, as libguestfs's own
// multi-device model says.
func TestApplyOpensEveryOverlayOfAMultiDiskGuest(t *testing.T) {
	existing := map[string]string{networkManagerDir + "/existing.nmconnection": "[connection]\nid=existing\n"}
	cases := []struct {
		name     string
		overlays []string
		needs    []string
	}{
		{"boot disk plus a separate root disk", []string{bootOverlayPath, rootOverlayPath}, []string{bootOverlayPath, rootOverlayPath}},
		{"volume group across three disks", []string{bootOverlayPath, rootOverlayPath, dataOverlayPath}, []string{bootOverlayPath, rootOverlayPath, dataOverlayPath}},
		{"ordinary data disks beside a self-contained boot disk", []string{bootOverlayPath, rootOverlayPath, dataOverlayPath}, []string{bootOverlayPath}},
		{"one disk", []string{bootOverlayPath}, []string{bootOverlayPath}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest := newMemGuest(t, existing, networkManagerDir)
			guest.needs = tc.needs
			result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(tc.overlays...))
			if err != nil {
				t.Fatal(err)
			}
			if result.Strategy != modeNetworkManager {
				t.Fatalf("strategy = %q, want networkmanager", result.Strategy)
			}
			if _, written := guest.files[networkManagerProfile]; !written {
				t.Fatalf("the recovery profile was not written: %v", guest.files)
			}
			requireEveryDrive(t, guest, tc.overlays)
		})
	}
}

// A required overlay that is not given is an error, not a guest
// that is silently inspected without it, and nothing is written.
func TestApplyFailsClosedWithoutARequiredOverlay(t *testing.T) {
	guest := newMemGuest(t, map[string]string{networkManagerDir + "/existing.nmconnection": "[connection]\n"}, networkManagerDir)
	guest.needs = []string{bootOverlayPath, rootOverlayPath}
	_, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
	if err == nil || !strings.Contains(err.Error(), "no operating system was found") {
		t.Fatalf("Apply with only the boot overlay = %v, want guestfish's refusal", err)
	}
	if guest.mutated() {
		t.Fatal("a profile was written although the guest could not be inspected")
	}
}

// An overlay file that is gone makes guestfish itself fail, and the
// failure reaches the caller before any write.
func TestApplyFailsClosedWhenAnOverlayFileIsMissing(t *testing.T) {
	guest := newMemGuest(t, map[string]string{networkManagerDir + "/existing.nmconnection": "[connection]\n"}, networkManagerDir)
	adapter := guest.adapter()
	inner := adapter.run
	adapter.run = func(ctx context.Context, args ...string) (string, error) {
		if slices.Contains(guestfishOverlays(args), rootOverlayPath) {
			return "", errors.New("guestfish: " + rootOverlayPath + ": No such file or directory: exit status 1")
		}
		return inner(ctx, args...)
	}
	_, err := adapter.Apply(context.Background(), multiDiskConfig(bootOverlayPath, rootOverlayPath))
	if err == nil || !strings.Contains(err.Error(), rootOverlayPath) {
		t.Fatalf("Apply = %v, want the missing overlay named", err)
	}
	if guest.mutated() {
		t.Fatal("a profile was written although an overlay was missing")
	}
}

// Opening every restored disk together means a data disk that holds a second
// operating system defeats guestfish -i. The refusal says so and what to do.
func TestMultiBootGuestfishFailureNamesTheRemedy(t *testing.T) {
	guest := newMemGuest(t, map[string]string{networkManagerDir + "/existing.nmconnection": "[connection]\n"}, networkManagerDir)
	adapter := guest.adapter()
	adapter.run = func(context.Context, ...string) (string, error) {
		return "", errors.New("exit status 1: guestfish: multi-boot operating systems are not supported by the -i option")
	}
	_, err := adapter.Apply(context.Background(), multiDiskConfig(bootOverlayPath, dataOverlayPath))
	if err == nil || !strings.Contains(err.Error(), "more than one restored disk holds an operating system") || !strings.Contains(err.Error(), "network_recovery.mode: preserve") {
		t.Fatalf("Apply = %v, want the multi-boot remedy", err)
	}
}

func TestValidateOverlays(t *testing.T) {
	cases := []struct {
		name     string
		overlays []string
		wantErr  string
	}{
		{"one", []string{"/a/one.qcow2"}, ""},
		{"several", []string{"/a/one.qcow2", "/a/two.qcow2"}, ""},
		{"none", nil, "overlay of every restored disk"},
		{"an empty entry", []string{"/a/one.qcow2", ""}, "absolute safe overlay path"},
		{"a relative entry", []string{"/a/one.qcow2", "two.qcow2"}, "absolute safe overlay path"},
		{"a newline", []string{"/a/one\n.qcow2"}, "absolute safe overlay path"},
		{"a carriage return", []string{"/a/one\r.qcow2"}, "absolute safe overlay path"},
		{"a NUL", []string{"/a/one\x00.qcow2"}, "absolute safe overlay path"},
		{"a duplicate", []string{"/a/one.qcow2", "/a/two.qcow2", "/a/./one.qcow2"}, "twice"},
		{"too many", make([]string, maxOverlays+1), "at most"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOverlays(tc.overlays)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("validateOverlays = %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("validateOverlays = %v, want %q", err, tc.wantErr)
			}
		})
	}
	// Apply refuses before it starts guestfish.
	adapter := &Adapter{scratchDir: t.TempDir(), run: func(context.Context, ...string) (string, error) {
		t.Fatal("guestfish started with an invalid overlay list")
		return "", nil
	}}
	if _, err := adapter.Apply(context.Background(), multiDiskConfig(bootOverlayPath, "")); err == nil {
		t.Fatal("Apply accepted an empty overlay entry")
	}
}

// Each drive is added with its own explicit format, in the given order, for
// read-only inspection and for the one mutating batch alike.
func TestGuestfishArgsOpenEveryOverlayInOrder(t *testing.T) {
	overlays := []string{bootOverlayPath, rootOverlayPath, dataOverlayPath}
	drives := []string{"--format=qcow2", "-a", bootOverlayPath, "--format=qcow2", "-a", rootOverlayPath, "--format=qcow2", "-a", dataOverlayPath, "-i"}

	read := guestfishReadArgs(overlays, "is-dir", "/etc")
	if want := append(append([]string{"--ro", "--keys-from-stdin"}, drives...), "is-dir", "/etc"); !slices.Equal(read, want) {
		t.Fatalf("read args = %#v, want %#v", read, want)
	}
	batch := guestfishBatchArgs(overlays, [][]string{{"mkdir-p", "/etc/x"}, {"chmod", "384", "/etc/x/y"}})
	if want := append(append([]string{"--rw", "--keys-from-stdin"}, drives...), "--", "mkdir-p", "/etc/x", ":", "chmod", "384", "/etc/x/y"); !slices.Equal(batch, want) {
		t.Fatalf("batch args = %#v, want %#v", batch, want)
	}
}

// The failed-VM fallback reads the diagnostic from the overlays after
// QEMU stops. The guest's root, and so the file, may be on any disk, so it
// opens every one the profile was written against.
func TestReadDiagnosticsOpensEveryOverlay(t *testing.T) {
	overlays := []string{bootOverlayPath, rootOverlayPath}
	var seen [][]string
	older, newer := "network-recovery.txt.0000000100.321", "network-recovery.txt.0000000900.654"
	run := func(_ context.Context, args ...string) (string, error) {
		seen = append(seen, append([]string(nil), args...))
		if guestfishCommand(args)[0] == "ls" {
			return older + "\n" + newer + "\nsomething-else\n", nil
		}
		return "  [interfaces]\n  ens18 10.100.0.10/24\n\n", nil
	}
	got, err := readDiagnostics(context.Background(), run, overlays)
	if err != nil {
		t.Fatal(err)
	}
	if got != "[interfaces]\n  ens18 10.100.0.10/24" {
		t.Fatalf("diagnostic = %q", got)
	}
	// The diagnostic directory is listed and the newest capture read, each
	// read-only with both overlays.
	if len(seen) != 2 {
		t.Fatalf("guestfish calls = %#v, want a listing and a read", seen)
	}
	for _, call := range seen {
		if !slices.Equal(guestfishOverlays(call), overlays) || call[0] != "--ro" {
			t.Fatalf("guestfish call %#v is not a read-only call with both overlays", call)
		}
	}
	if !slices.Equal(guestfishCommand(seen[0]), []string{"ls", diagnosticDir}) ||
		!slices.Equal(guestfishCommand(seen[1]), []string{"pread", diagnosticDir + "/" + newer, "16385", "0"}) {
		t.Fatalf("guestfish commands = %v, %v", guestfishCommand(seen[0]), guestfishCommand(seen[1]))
	}

	// A guest that never wrote a capture is "", not an error.
	for name, listing := range map[string]string{"an empty directory": "", "only other files": "other.txt\n.capture.AbC123\nnetwork-recovery.txt\nnetwork-recovery.txt.1.2\n"} {
		none := func(_ context.Context, args ...string) (string, error) {
			if guestfishCommand(args)[0] != "ls" {
				t.Fatalf("%s: a capture was read", name)
			}
			return listing, nil
		}
		if got, err := readDiagnostics(context.Background(), none, overlays); err != nil || got != "" {
			t.Fatalf("%s: diagnostic = %q, %v; want empty and no error", name, got, err)
		}
	}
	other := func(context.Context, ...string) (string, error) { return "", errors.New("guestfish: boom") }
	if _, err := readDiagnostics(context.Background(), other, overlays); err == nil {
		t.Fatal("a guestfish failure was swallowed")
	}

	// With no overlay there is nothing to read: refused before guestfish.
	never := func(context.Context, ...string) (string, error) {
		t.Fatal("guestfish started without an overlay")
		return "", nil
	}
	if _, err := readDiagnostics(context.Background(), never, nil); err == nil {
		t.Fatal("no overlay accepted")
	}
}

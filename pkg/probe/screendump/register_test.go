// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package screendump

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe/qmp"
)

func captureWith(t *testing.T, frame []byte, fail bool, opts ...Option) (*Artifact, string, error) {
	t.Helper()
	client, err := qmp.Dial(qmpServer(t, frame, fail), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	scratch := t.TempDir()
	if err := os.Chmod(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := Capture(context.Background(), client, 9931, scratch, opts...)
	return artifact, scratch, err
}

var diagnosticName = regexp.MustCompile(`^certistack-failure-vm9931-[0-9]+-[0-9a-f]{8}\.(ppm|png)$`)

// The files of a capture are named to the caller before QEMU is asked to write
// the first of them, so a worker killed mid-capture leaves a record of exactly
// what may exist: neither file exists yet when they are registered.
func TestCaptureNamesItsFilesBeforeQEMUWritesThem(t *testing.T) {
	var registered, removed []string
	var existedAtRegistration []bool
	_, scratch, err := captureWith(t, onePixel(7), false,
		WithRegister(func(paths ...string) error {
			registered = append(registered, paths...)
			for _, p := range paths {
				_, statErr := os.Stat(p)
				existedAtRegistration = append(existedAtRegistration, statErr == nil)
			}
			return nil
		}),
		WithRemoved(func(paths ...string) { removed = append(removed, paths...) }))
	if err != nil {
		t.Fatal(err)
	}
	if len(registered) != 2 {
		t.Fatalf("registered %v, want the raw frame and the PNG", registered)
	}
	for i, p := range registered {
		if existedAtRegistration[i] {
			t.Errorf("%s existed when it was registered; it must be named before QEMU writes it", p)
		}
		if filepath.Dir(p) != scratch || !diagnosticName.MatchString(filepath.Base(p)) {
			t.Errorf("%s is not a unique diagnostic file name in the scratch directory", p)
		}
	}
	// The raw frame is gone and reported removed; the PNG of a successful capture
	// is the caller's, so it still exists and is not reported removed.
	ppm, png := registered[0], registered[1]
	if _, err := os.Stat(ppm); err == nil {
		t.Error("the raw frame was left behind")
	}
	if _, err := os.Stat(png); err != nil {
		t.Errorf("the PNG of a successful capture is missing: %v", err)
	}
	if strings.Join(removed, ",") != ppm {
		t.Errorf("removed = %v, want only the raw frame %s", removed, ppm)
	}
}

func TestCaptureNamesAreUniqueWithinOneSecond(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		var got []string
		if _, _, err := captureWith(t, onePixel(1), false, WithRegister(func(paths ...string) error { got = paths; return nil })); err != nil {
			t.Fatal(err)
		}
		if seen[got[0]] {
			t.Fatalf("two captures used %s", got[0])
		}
		seen[got[0]] = true
	}
}

// A failed capture leaves nothing and says so: both names are reported removed,
// so the journal does not keep a record of files that cannot exist. A capture
// whose files cannot be recorded is not taken at all.
func TestCaptureDropsItsRecordWhenItFailsAndRefusesWhenItCannotRecord(t *testing.T) {
	var registered, removed []string
	_, scratch, err := captureWith(t, onePixel(7), true,
		WithRegister(func(paths ...string) error { registered = paths; return nil }),
		WithRemoved(func(paths ...string) { removed = append(removed, paths...) }))
	if err == nil {
		t.Fatal("a screendump QEMU failed was reported as taken")
	}
	if len(removed) != 2 || len(registered) != 2 || removed[0] != registered[1] && removed[1] != registered[1] {
		t.Fatalf("registered %v, removed %v; want both reported removed", registered, removed)
	}
	if entries, _ := os.ReadDir(scratch); len(entries) != 0 {
		t.Fatalf("files left in scratch: %v", entries)
	}

	artifact, scratch, err := captureWith(t, onePixel(7), false,
		WithRegister(func(...string) error { return errors.New("the journal is not writable") }))
	if err == nil || artifact != nil || !strings.Contains(err.Error(), "could not be recorded") {
		t.Fatalf("capture = %v, %v; want it refused because its files cannot be recorded", artifact, err)
	}
	if entries, _ := os.ReadDir(scratch); len(entries) != 0 {
		t.Fatalf("a refused capture asked QEMU anyway: %v", entries)
	}
}

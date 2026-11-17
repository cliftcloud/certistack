// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The reader took any guestfish error that said "No such file or directory" for
// "the guest wrote no diagnostic", and so a missing overlay (guestfish:
// <overlay>: No such file or directory) came back as an empty diagnostic and a
// teardown line saying the guest produced none. Only the diagnostic's own
// absence is that.
func TestReadDiagnosticsDoesNotTakeAMissingOverlayForAMissingDiagnostic(t *testing.T) {
	overlays := []string{bootOverlayPath, rootOverlayPath}
	capture := "network-recovery.txt.0000000100.321"
	for name, tc := range map[string]struct {
		message string
		onRead  bool // the failure is the read of the capture, not the listing
		empty   bool
	}{
		"the diagnostic directory is not there":       {message: "guestfish: libguestfs: error: ls: " + diagnosticDir + ": No such file or directory: exit status 1", empty: true},
		"an overlay is gone":                          {message: "guestfish: " + rootOverlayPath + ": No such file or directory: exit status 1"},
		"the first overlay is gone":                   {message: "guestfish: " + bootOverlayPath + ": No such file or directory"},
		"an overlay of the diagnostic's directory":    {message: "guestfish: " + diagnosticDir + "/vm9001-scsi0.qcow2: No such file or directory"},
		"the parent directory is gone":                {message: "guestfish: ls: /var/lib: No such file or directory"},
		"another failure":                             {message: "guestfish: boom"},
		"the capture vanished before it was read":     {message: "guestfish: libguestfs: error: pread: " + diagnosticDir + "/" + capture + ": No such file or directory", onRead: true},
		"an overlay is gone when the capture is read": {message: "guestfish: " + rootOverlayPath + ": No such file or directory", onRead: true},
	} {
		t.Run(name, func(t *testing.T) {
			run := func(_ context.Context, args ...string) (string, error) {
				reading := guestfishCommand(args)[0] == "pread"
				if reading != tc.onRead {
					if reading {
						t.Fatal("a capture was read although the listing failed")
					}
					return capture + "\n", nil
				}
				return "", errors.New(tc.message)
			}
			got, err := readDiagnostics(context.Background(), run, overlays)
			switch {
			case tc.empty && (err != nil || got != ""):
				t.Fatalf("readDiagnostics = %q, %v; want an empty diagnostic and no error", got, err)
			case !tc.empty && (err == nil || !strings.Contains(err.Error(), tc.message)):
				t.Fatalf("readDiagnostics = %q, %v; want the failure reported", got, err)
			}
		})
	}
}

//go:build unix

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// runVerifyWithin runs verify-report and fails the test if it does not return,
// as one waiting on a FIFO's writer would not.
func runVerifyWithin(t *testing.T, args ...string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := runVerify(t, args...)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("verify-report %q waited on a FIFO instead of refusing it", args)
		return nil
	}
}

// A FIFO as the report never keeps verify-report waiting. Invalid
// trust-source combinations are refused from the arguments before it is
// opened, and with valid arguments it is refused as not a regular file. No
// writer ever opens the FIFO, so a wait for one would never end.
func TestVerifyReportNeverWaitsOnAReportFIFO(t *testing.T) {
	dir := t.TempDir()
	reportPath, pub, _ := signedReportFile(t, dir)
	fifo := filepath.Join(dir, "report.fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("named pipes unavailable: %v", err)
	}
	keyHex := hex.EncodeToString(pub)
	keyring := filepath.Join(dir, "keyring")
	pubFile := filepath.Join(dir, "signer.pub")
	if err := os.WriteFile(keyring, []byte(keyHex+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubFile, []byte(keyHex+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no trust source":         {[]string{fifo}, "an explicit --keyring, --public-key, or --trusted-key is required"},
		"keyring and public key":  {[]string{"--keyring", keyring, "--public-key", pubFile, fifo}, "mutually exclusive"},
		"unsupported format":      {[]string{"--format", "xml", "--keyring", keyring, fifo}, "unsupported --format"},
		"valid keyring":           {[]string{"--keyring", keyring, fifo}, "a named pipe, not a regular file"},
		"valid public key":        {[]string{"--public-key", pubFile, fifo}, "a named pipe, not a regular file"},
		"valid inline key":        {[]string{"--trusted-key", keyHex, fifo}, "a named pipe, not a regular file"},
		"json format":             {[]string{"--format", "json", "--trusted-key", keyHex, fifo}, "a named pipe, not a regular file"},
		"expectation on the FIFO": {[]string{"--expect-node", "node-a", "--trusted-key", keyHex, fifo}, "a named pipe, not a regular file"},
		"FIFO as the plan":        {[]string{"--expect-plan", fifo, "--trusted-key", keyHex, reportPath}, "load --expect-plan: expected plan"},
	} {
		if err := runVerifyWithin(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: verify-report = %v, want an error containing %q", name, err, tc.want)
		}
	}

	// Control: the real report is verified, also through a link to it.
	link := filepath.Join(dir, "report-link.json")
	if err := os.Symlink(reportPath, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	for _, path := range []string{reportPath, link} {
		if err := runVerifyWithin(t, "--keyring", keyring, path); err != nil {
			t.Errorf("verify-report %s: %v", filepath.Base(path), err)
		}
	}
}

// A FIFO as the keyring or the public key file is refused without
// waiting for a writer.
func TestVerifyReportNeverWaitsOnATrustFileFIFO(t *testing.T) {
	dir := t.TempDir()
	reportPath, _, _ := signedReportFile(t, dir)
	fifo := filepath.Join(dir, "trust.fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("named pipes unavailable: %v", err)
	}
	for _, flag := range []string{"--keyring", "--public-key"} {
		err := runVerifyWithin(t, flag, fifo, reportPath)
		if err == nil || !strings.Contains(err.Error(), "a named pipe, not a regular file") {
			t.Errorf("%s given a FIFO: %v", flag, err)
		}
	}
}

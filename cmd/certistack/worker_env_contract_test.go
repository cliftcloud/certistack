// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// Every variable the controller writes into a worker's environment file must
// be on the worker's allowlist: the worker refuses the whole file otherwise.
// An earlier build failed this way ("unsupported node worker environment
// variable") because only the controller knew a new variable.
func TestWorkerAcceptsEveryKeyTheControllerWrites(t *testing.T) {
	for _, key := range controller.WorkerEnvironmentKeys {
		if _, ok := workerEnvironmentNames[key]; !ok {
			t.Errorf("the controller writes %s but the worker refuses it", key)
		}
	}
}

// byteForByteCredentials are the shapes of a credential the controller can write
// into a worker's environment file: whitespace at either end, quotes in every
// position, shell syntax, and bytes that are not UTF-8.
var byteForByteCredentials = []string{
	"ordinary-synthetic-password",
	"  synthetic password  ",
	"\tsynthetic-password\t",
	" synthetic-password ",
	"\u0085synthetic-password ",
	`"synthetic-password"`,
	"'synthetic-password'",
	`"synthetic-password`,
	"'synthetic-password",
	`synthetic-password"`,
	"synthetic-password'",
	`"`,
	"'",
	`""`,
	" ",
	"synthetic-$(audit-no-command)-${NO_EXPANSION}-`audit-literal`",
	`synthetic-'quoted'-"password"`,
	"#not-a-comment",
	"a=b=c",
	"\xff\xfe-not-utf8",
}

// The controller wrote each credential after KEY= as it was, and the
// worker's parser trimmed its surrounding whitespace and took a leading
// quote as quoting: five password shapes changed on the way and two made
// the worker refuse its whole environment. Every value the controller can
// write now reaches the worker byte for byte.
func TestWorkerEnvironmentRoundTripsCredentialsByteForByte(t *testing.T) {
	for key := range controllerEnvironmentNames {
		t.Setenv(key, os.Getenv(key))
	}
	values := byteForByteCredentials
	for _, value := range values {
		data, err := controller.EncodeWorkerEnvironment(map[string]string{
			"PVE_URL":                 "https://pve.example:8006",
			"PBS_PASSWORD":            value,
			"PBS_ENCRYPTION_PASSWORD": value,
		})
		if err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		file := filepath.Join(t.TempDir(), "runtime.env")
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		values, err := loadWorkerEnvironment(file)
		if err != nil {
			t.Fatalf("%q: the worker refused the controller's file: %v", value, err)
		}
		for _, key := range []string{"PBS_PASSWORD", "PBS_ENCRYPTION_PASSWORD"} {
			if got := values[key]; got != value {
				t.Errorf("%s = %q, want %q", key, got, value)
			}
		}
		if got := values["PVE_URL"]; got != "https://pve.example:8006" {
			t.Errorf("PVE_URL = %q", got)
		}
	}
	for _, value := range []string{"synthetic\nnewline", "synthetic\rreturn", "synthetic\x00nul"} {
		if _, err := controller.EncodeWorkerEnvironment(map[string]string{"PBS_PASSWORD": value}); err == nil || !strings.Contains(err.Error(), "PBS_PASSWORD contains a prohibited control character") {
			t.Errorf("%q: err = %v, want a clear refusal", value, err)
		}
	}
}

// The apply half of the same round trip. The test above reads the file the
// controller writes with the loader, which returns values without touching the
// process; since the loaders became pure, nothing checked that what
// useCommandEnvironment puts in the process (os.Setenv) is what os.Getenv gives
// back to the PBS and PVE clients, byte for byte, and that the file's value
// replaces the inherited one whole.
func TestWorkerEnvironmentAppliesCredentialsByteForByte(t *testing.T) {
	for key := range workerEnvironmentNames {
		t.Setenv(key, "")
	}
	for _, value := range byteForByteCredentials {
		if runtime.GOOS == "windows" && !utf8.ValidString(value) {
			continue // the Windows environment is UTF-16; bytes that are not text have no place in it
		}
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			t.Setenv("PBS_PASSWORD", "inherited-"+value)
			// A variable the file leaves out is not the command's: the file
			// replaces the whole allowlist, so an inherited value of it is gone
			// while the command runs, and is back after.
			t.Setenv("PBS_FINGERPRINT", "inherited-fingerprint")
			data, err := controller.EncodeWorkerEnvironment(map[string]string{
				"PVE_URL":                 "https://pve.example:8006",
				"PBS_PASSWORD":            value,
				"PBS_ENCRYPTION_PASSWORD": value,
			})
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "runtime.env")
			if err := os.WriteFile(file, data, 0o600); err != nil {
				t.Fatal(err)
			}
			restore, err := useCommandEnvironment(file, true)
			if err != nil {
				t.Fatalf("the worker refused the controller's file: %v", err)
			}
			for _, key := range []string{"PBS_PASSWORD", "PBS_ENCRYPTION_PASSWORD"} {
				if got, present := os.LookupEnv(key); !present || got != value {
					t.Errorf("%s in the process = %q (set: %v), want %q", key, got, present, value)
				}
			}
			if got := os.Getenv("PVE_URL"); got != "https://pve.example:8006" {
				t.Errorf("PVE_URL = %q", got)
			}
			if got, present := os.LookupEnv("PBS_FINGERPRINT"); present {
				t.Errorf("an inherited PBS_FINGERPRINT (%q) the file does not give reached the command", got)
			}
			restore()
			if got := os.Getenv("PBS_PASSWORD"); got != "inherited-"+value {
				t.Errorf("after the command PBS_PASSWORD = %q, want the inherited value back", got)
			}
			if got := os.Getenv("PBS_FINGERPRINT"); got != "inherited-fingerprint" {
				t.Errorf("after the command PBS_FINGERPRINT = %q, want the inherited value back", got)
			}
		})
	}
}

func TestEnvironmentLoadsAndClearsExplicitLabTLSOptIn(t *testing.T) {
	for name, load := range map[string]func(string) error{"controller": func(p string) error { return applyTestControllerEnvironment(t, p) }, "worker": func(p string) error { return applyTestWorkerEnvironment(t, p) }} {
		t.Run(name, func(t *testing.T) {
			// These loaders replace the whole allowlist. Restore every variable
			// at test exit, including values omitted from the test environment.
			for key := range controllerEnvironmentNames {
				t.Setenv(key, os.Getenv(key))
			}
			file := filepath.Join(t.TempDir(), "runtime.env")
			for _, contents := range []string{"PVE_TLS_INSECURE=true\n" + pve.InsecureTLSLabOptInEnv + "=true\n", "PVE_TLS_INSECURE=true\n"} {
				if err := os.WriteFile(file, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
				if err := load(file); err != nil {
					t.Fatal(err)
				}
				want := ""
				if len(contents) > len("PVE_TLS_INSECURE=true\n") {
					want = "true"
				}
				if got := os.Getenv(pve.InsecureTLSLabOptInEnv); got != want {
					t.Fatalf("lab opt-in = %q, want %q", got, want)
				}
			}
		})
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pve"
)

func TestStagePBSKeyfileChecksOriginalSource(t *testing.T) {
	for _, kind := range []string{"private", "public", "symlink", "empty", "oversized", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			source, destination := filepath.Join(dir, "source.key"), filepath.Join(dir, "staged.key")
			data := []byte(`{"kdf":null}`)
			if kind == "empty" {
				data = nil
			} else if kind == "oversized" {
				data = bytes.Repeat([]byte("x"), maxKeyfileSourceBytes+1)
			}
			if err := os.WriteFile(source, data, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "public":
				if runtime.GOOS == "windows" {
					t.Skip("Windows file permissions use ACLs")
				}
				if err := os.Chmod(source, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := filepath.Join(dir, "link.key")
				if err := os.Symlink(source, link); err != nil {
					if runtime.GOOS == "windows" {
						t.Skipf("symlinks unavailable: %v", err)
					}
					t.Fatal(err)
				}
				source = link
			case "directory":
				source = dir
			}
			err := stagePBSKeyfile(source, destination, "")
			if kind != "private" {
				if err == nil {
					t.Fatal("unsafe source accepted")
				}
				if _, err := os.Stat(destination); !os.IsNotExist(err) {
					t.Fatal("unsafe source was staged")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(destination)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("staged key differs: %v", err)
			}
			info, err := os.Stat(destination)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Fatalf("staged key mode = %o", info.Mode().Perm())
			}
		})
	}
}

func TestStagePBSKeyfileChecksPassphrase(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.key")
	if err := os.WriteFile(source, []byte(`{"kdf":{"scrypt":{}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stagePBSKeyfile(source, filepath.Join(dir, "staged.key"), ""); err == nil || !strings.Contains(err.Error(), "PBS_ENCRYPTION_PASSWORD") {
		t.Fatalf("missing passphrase: %v", err)
	}
}

func TestControllerForwardsExplicitLabTLSOptIn(t *testing.T) {
	for _, key := range []string{"PVE_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET", "PBS_REPOSITORY", "PBS_PASSWORD"} {
		t.Setenv(key, "synthetic-test-value")
	}
	t.Setenv("PVE_TLS_INSECURE", "true")
	for _, optIn := range []string{"true", ""} {
		t.Setenv(pve.InsecureTLSLabOptInEnv, optIn)
		values, err := controllerRuntimeEnv("/var/lib/certistack/workers/test")
		if err != nil {
			t.Fatal(err)
		}
		envPath := filepath.Join(t.TempDir(), "runtime.env")
		if err := writeEnvFile(envPath, values); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(envPath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), pve.InsecureTLSLabOptInEnv+"=true\n") != (optIn == "true") {
			t.Fatalf("worker environment did not preserve explicit opt-in %q", optIn)
		}
	}
}

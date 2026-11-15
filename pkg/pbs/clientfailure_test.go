// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// What a first-time user saw for a wrong PBS_PASSWORD, and for a self-signed
// PBS certificate without PBS_FINGERPRINT, was only
// "list PBS snapshots for vm/100: exit status 255 (client output withheld; 29
// bytes)". The client's words stay withheld, since they can carry the
// repository and the token, but a failure with a known cause is now named in
// CertiStack's own fixed sentence, with the variable to check.
//
// The captured outputs are the real stderr of proxmox-backup-client 4.2
// against a stock PBS 4.2 (`snapshot list --repository R --ns NS
// --output-format json`, exit 255), byte for byte.
const (
	capturedUnpinnedCertificate = "certificate validation failed - Certificate fingerprint was not confirmed.\n" +
		"Error: client error (Connect)\nCaused by:\n" +
		"    0: error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify failed:../ssl/statem/statem_clnt.c:2124:\n" +
		"    1: error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify failed:../ssl/statem/statem_clnt.c:2124:\n"
	capturedWrongPassword    = "Error: authentication failed\n"
	capturedHiddenDatastore  = "Error: permission check failed - missing Datastore.Audit|Datastore.Backup on /datastore/nosuchstore/walkthrough\n"
	capturedMissingNamespace = "Error: ENOENT: No such file or directory\n"
	capturedNoRoute          = "Error: client error (Connect)\nCaused by:\n    error connecting to https://192.168.100.99:8007/ - tcp connect error: No route to host (os error 113)\n"
)

// capturedWrongFingerprint is the unpinned failure preceded by the client's
// warning, with an all-zero fingerprint configured.
var capturedWrongFingerprint = "WARNING: certificate fingerprint does not match expected fingerprint!\n" +
	"expected:    " + strings.TrimSuffix(strings.Repeat("00:", 32), ":") + "\n" + capturedUnpinnedCertificate

// Three of the six texts, as handed over, are one byte shorter than the byte
// counts of the captures (378, 557 and 147 against 379, 558 and 148): the
// transcription lost a byte somewhere in the "Error: client error (Connect)"
// lines. The classes do not depend on it. The other three are exact.
func TestCapturedClientOutputsHaveTheCapturedSizes(t *testing.T) {
	for output, size := range map[string]int{
		capturedUnpinnedCertificate: 378,
		capturedWrongFingerprint:    557,
		capturedNoRoute:             147,
		capturedWrongPassword:       29,
		capturedHiddenDatastore:     112,
		capturedMissingNamespace:    41,
	} {
		if len(output) != size {
			t.Errorf("%q is %d bytes, want %d", output, len(output), size)
		}
	}
}

func TestCommandFailureNamesTheCauseOfAKnownClientFailure(t *testing.T) {
	const (
		repository = "certistack@pbs!restore@pbs.lab.example:backup-store"
		secret     = "hunter2-do-not-log"
	)
	for _, tc := range []struct {
		name, output string
		want         []string
	}{
		{"wrong PBS_PASSWORD or token name (captured)", capturedWrongPassword,
			[]string{"PBS refused the login", "PBS_PASSWORD", "PBS_REPOSITORY"}},
		{"unauthorized", "Error: 401 Unauthorized: invalid credentials for " + repository + "\n",
			[]string{"PBS refused the login", "PBS_PASSWORD"}},
		{"self-signed certificate, no PBS_FINGERPRINT (captured)", capturedUnpinnedCertificate,
			[]string{"TLS certificate was not confirmed", "PBS_FINGERPRINT is not set", "Show Fingerprint"}},
		{"wrong PBS_FINGERPRINT (captured)", capturedWrongFingerprint,
			[]string{"PBS_FINGERPRINT does not match the certificate the server presents", "Show Fingerprint"}},
		{"certificate question on a client with a terminal", "fingerprint: aa:bb:cc\nAre you sure you want to continue connecting? (y/n): \nError: certificate validation failed\n",
			[]string{"TLS certificate was not confirmed", "PBS_FINGERPRINT"}},
		{"datastore the token cannot see (captured)", capturedHiddenDatastore,
			[]string{"denied access", "DatastoreReader", "PBS_REPOSITORY", "PBS_NAMESPACE", "an API token needs the permission itself"}},
		{"namespace that does not exist (captured)", capturedMissingNamespace,
			[]string{"no such namespace or datastore path", "PBS_NAMESPACE", "pbs_namespace"}},
		{"host unreachable (captured)", capturedNoRoute,
			[]string{"connection to the PBS server failed", "PBS_REPOSITORY"}},
		{"connection refused", "Error: client error (Connect)\nCaused by:\n    error connecting to https://192.168.100.99:8007/ - tcp connect error: Connection refused (os error 111)\n",
			[]string{"connection to the PBS server failed", "PBS_REPOSITORY"}},
		{"connection timed out", "Error: client error (Connect)\nCaused by:\n    error connecting to https://192.168.100.99:8007/ - tcp connect error: Connection timed out (os error 110)\n",
			[]string{"connection to the PBS server failed", "PBS_REPOSITORY"}},
		{"name does not resolve", "Error: error trying to connect: dns error: failed to lookup address information: Name or service not known\n",
			[]string{"connection to the PBS server failed", "PBS_REPOSITORY"}},
		{"no such datastore", "Error: no such datastore 'backup-store'\n",
			[]string{"no such datastore", "PBS_REPOSITORY"}},
		{"datastore that cannot be opened", "Error: unable to open datastore 'backup-store' - chunk store does not exist\n",
			[]string{"no such datastore", "PBS_REPOSITORY"}},
		{"namespace named in the error", "Error: namespace 'tenant/a' does not exist\n",
			[]string{"no such namespace", "PBS_NAMESPACE"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exit := errors.New("exit status 255")
			// The client's output is also given a repository and a secret
			// to echo: none of it may come through. A bare errno with
			// anything after it is no longer the whole error, so it is not
			// the namespace sentence but withheld as unknown.
			noisy := tc.output + "repository " + repository + " password " + secret + "\n"
			for _, output := range []string{tc.output, noisy} {
				err := listFailure("list PBS snapshots for vm/100", exit, []byte(output))
				if output == noisy && tc.output == capturedMissingNamespace {
					if !strings.Contains(err.Error(), "client output withheld") || strings.Contains(err.Error(), secret) {
						t.Errorf("output %q: %v, want it withheld", output, err)
					}
					continue
				}
				for _, want := range append(tc.want, "list PBS snapshots for vm/100: ") {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("output %q: %v lacks %q", output, err, want)
					}
				}
				for _, leaked := range []string{"pbs.lab.example", "certistack@pbs", "backup-store", secret, "aa:bb:cc", "00:00:00", "192.168.100.99", "nosuchstore", "walkthrough", "statem_clnt", "os error", "Error:", "Caused by", "exit status", "withheld", "tenant/a"} {
					if strings.Contains(err.Error(), leaked) {
						t.Errorf("output %q: the message holds %q: %v", output, leaked, err)
					}
				}
				if !errors.Is(err, exit) {
					t.Errorf("output %q: the command's own error is no longer reachable from %v", output, err)
				}
			}
		})
	}
}

// The wrong-fingerprint warning is what tells a pinned fingerprint that does
// not fit from none being set; the failure after it is the same text.
func TestWrongFingerprintIsToldApartFromNoFingerprint(t *testing.T) {
	exit := errors.New("exit status 255")
	unpinned := listFailure("list PBS snapshots for vm/100", exit, []byte(capturedUnpinnedCertificate)).Error()
	wrong := listFailure("list PBS snapshots for vm/100", exit, []byte(capturedWrongFingerprint)).Error()
	if unpinned == wrong || !strings.Contains(unpinned, "is not set") || strings.Contains(wrong, "is not set") || !strings.Contains(wrong, "does not match") {
		t.Errorf("unpinned: %s\nwrong: %s", unpinned, wrong)
	}
}

// The same ENOENT from anything but a listing (a restore, a map) says nothing
// of a namespace and stays withheld.
func TestBareENOENTIsANamespaceOnlyForListings(t *testing.T) {
	exit := errors.New("exit status 255")
	err := commandFailure("restore PBS image drive-scsi0", exit, []byte(capturedMissingNamespace))
	if !strings.Contains(err.Error(), "client output withheld; 41 bytes") || strings.Contains(err.Error(), "namespace") {
		t.Errorf("restore: %v", err)
	}
	err = listFailure("list PBS snapshots", exit, []byte(capturedMissingNamespace))
	if !strings.Contains(err.Error(), "no such namespace or datastore path") {
		t.Errorf("listing: %v", err)
	}
}

// An output that matches no known cause is not guessed at: it is withheld and
// only its size is reported, as before.
func TestCommandFailureStillWithholdsUnknownClientOutput(t *testing.T) {
	for _, output := range []string{
		"Error: something nobody has seen for " + "certistack@pbs!restore@pbs.lab.example:backup-store",
		"Error: ENOENT: No such file or directory\n",
		"Error: snapshot 'vm/100/2026-09-20T03:00:09Z' does not exist in datastore\n",
	} {
		err := commandFailure("restore PBS image drive-scsi0", errors.New("exit status 255"), []byte(output))
		if !strings.Contains(err.Error(), "exit status 255 (client output withheld; ") || strings.Contains(err.Error(), "pbs.lab.example") || strings.Contains(err.Error(), "ENOENT") {
			t.Errorf("output %q: %v", output, err)
		}
	}
}

// A refusal that CertiStack already names (a wrong key passphrase) keeps its
// own sentence when the output also reads like a login failure.
func TestKnownRefusalsComeBeforeTheCauseClasses(t *testing.T) {
	err := commandFailure("restore PBS VM configuration", errors.New("exit status 255"), []byte("Error: decryption failed - wrong password? authentication failed\n"))
	if !strings.Contains(err.Error(), "does not unlock CERTISTACK_PBS_KEYFILE") || strings.Contains(err.Error(), "PBS refused the login") {
		t.Fatalf("%v", err)
	}
}

// The phrases are searched in the first 64 KiB: a failure later in a large
// output is not matched (and is withheld as unknown).
func TestClassifyClientFailureLooksOnlyAtTheStart(t *testing.T) {
	early := append([]byte("Error: authentication failed\n"), make([]byte, 128<<10)...)
	if _, ok := classifyClientFailure(early); !ok {
		t.Error("a failure at the start of a large output was not matched")
	}
	late := append(make([]byte, 128<<10), []byte("Error: authentication failed\n")...)
	if _, ok := classifyClientFailure(late); ok {
		t.Error("a phrase past the first 64 KiB was matched")
	}
}

// End to end: the failing client of the report, a fake that answers a snapshot
// listing as 4.x does for a wrong password and for a missing namespace.
func TestListingFailuresNameTheirCauseEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	for _, tc := range []struct {
		name, stderr string
		want         []string
	}{
		{"wrong password", "Error: authentication failed", []string{"list PBS snapshots for vm/100: PBS refused the login", "PBS_PASSWORD"}},
		{"missing namespace", "Error: ENOENT: No such file or directory", []string{"list PBS snapshots for vm/100: PBS found no such namespace or datastore path", "PBS_NAMESPACE"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			script := "#!/bin/sh\necho '" + tc.stderr + "' >&2\nexit 255\n"
			if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			client := New(Config{Repository: "certistack@pbs!restore@pbs.lab.example:backup-store", Password: "hunter2-do-not-log", Namespace: "walkthrough"})
			_, err := client.LatestSnapshot(context.Background(), "vm/100")
			if err == nil {
				t.Fatal("a failing client listed snapshots")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%v lacks %q", err, want)
				}
			}
			for _, leaked := range []string{"withheld", "exit status", "pbs.lab.example", "hunter2", "walkthrough"} {
				if strings.Contains(err.Error(), leaked) {
					t.Errorf("%v holds %q", err, leaked)
				}
			}
		})
	}
}

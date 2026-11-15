// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// pipeDial is a DialFunc whose "network" is an in-memory connection to an SSH
// server that holds the given host keys and accepts any client: no socket is
// opened. It records the address it was asked for.
func pipeDial(t *testing.T, requested *string, hostKeys ...ssh.Signer) DialFunc {
	t.Helper()
	return func(_ context.Context, _, address string) (net.Conn, error) {
		if requested != nil {
			*requested = address
		}
		client, server := memPipe()
		config := &ssh.ServerConfig{NoClientAuth: true}
		for _, key := range hostKeys {
			config.AddHostKey(key)
		}
		go func() {
			defer server.Close()
			conn, channels, requests, err := ssh.NewServerConn(server, config)
			if err != nil {
				return
			}
			defer conn.Close()
			go ssh.DiscardRequests(requests)
			for channel := range channels {
				_ = channel.Reject(ssh.Prohibited, "no sessions")
			}
		}()
		return client, nil
	}
}

func TestFetchHostKeyReturnsTheEd25519KeyAndItsFingerprint(t *testing.T) {
	signer := newSigner(t)
	var requested string
	got, err := FetchHostKey(context.Background(), pipeDial(t, &requested, signer), "PVE-Node-01.Example.com", 2222)
	if err != nil {
		t.Fatal(err)
	}
	if requested != "pve-node-01.example.com:2222" {
		t.Errorf("dialled %q", requested)
	}
	if want := ssh.FingerprintSHA256(signer.PublicKey()); got.Fingerprint != want || !strings.HasPrefix(want, "SHA256:") {
		t.Errorf("fingerprint %q, want %q", got.Fingerprint, want)
	}
	if string(got.Key.Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Error("the key returned is not the key the server holds")
	}
}

func TestFetchHostKeyPrefersEd25519WhenTheServerHasSeveralKeys(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, err := ssh.NewSignerFromKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	edSigner := newSigner(t)
	got, err := FetchHostKey(context.Background(), pipeDial(t, nil, ecSigner, edSigner), "pve.example", 22)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key.Type() != ssh.KeyAlgoED25519 || got.Fingerprint != ssh.FingerprintSHA256(edSigner.PublicKey()) {
		t.Errorf("got %s %s", got.Key.Type(), got.Fingerprint)
	}
}

func TestFetchHostKeyNamesTheMissingEd25519Key(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, err := ssh.NewSignerFromKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = FetchHostKey(context.Background(), pipeDial(t, nil, ecSigner), "pve.example", 22)
	if err == nil || !strings.Contains(err.Error(), "does not offer an ED25519 host key") {
		t.Fatalf("error = %v", err)
	}
}

func TestFetchHostKeyRefusesWhatCouldNameManyHostsBeforeDialling(t *testing.T) {
	dialled := false
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialled = true
		return nil, errors.New("no network in tests")
	}
	for _, host := range []string{"", "pve,other", "*.example.com", "pve example", "!pve", "|1|abc", "root@pve", "pve/x", "#pve", "-pve"} {
		if _, err := FetchHostKey(context.Background(), dial, host, 22); err == nil {
			t.Errorf("accepted host %q", host)
		}
	}
	for _, port := range []int{0, -1, 65536} {
		if _, err := FetchHostKey(context.Background(), dial, "pve.example", port); err == nil {
			t.Errorf("accepted port %d", port)
		}
	}
	if dialled {
		t.Error("a refused host or port was dialled")
	}
}

func TestFetchHostKeyReportsAConnectionFailure(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connection refused") }
	_, err := FetchHostKey(context.Background(), dial, "pve.example", 22)
	if err == nil || !strings.Contains(err.Error(), "connect to pve.example:22: connection refused") {
		t.Fatalf("error = %v", err)
	}
}

func TestFetchHostKeyStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// A server that never answers: the pipe's other end is left alone.
	dial := func(context.Context, string, string) (net.Conn, error) {
		client, _ := memPipe()
		return client, nil
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	done := make(chan error, 1)
	go func() {
		_, err := FetchHostKey(ctx, dial, "pve.example", 22)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("FetchHostKey did not return after its context ended")
	}
}

func TestKnownHostsLineIsWhatSSHLooksUp(t *testing.T) {
	signer := newSigner(t)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	for _, c := range []struct {
		host string
		port int
		want string
	}{
		{"pve.example.com", 22, "pve.example.com " + key},
		{"pve.example.com", 2222, "[pve.example.com]:2222 " + key},
		{"192.0.2.10", 22, "192.0.2.10 " + key},
		{"2001:db8::10", 22, "2001:db8::10 " + key},
		{"2001:db8::10", 2222, "[2001:db8::10]:2222 " + key},
	} {
		if got := KnownHostsLine(c.host, c.port, signer.PublicKey()); got != c.want {
			t.Errorf("KnownHostsLine(%q, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"PVE.Example.com": "pve.example.com",
		" pve01 ":         "pve01",
		"[2001:DB8::1]":   "2001:db8::1",
		"192.0.2.10":      "192.0.2.10",
		"pve_01.lab":      "pve_01.lab",
	} {
		if got, err := NormalizeHost(in); err != nil || got != want {
			t.Errorf("NormalizeHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestInspectKnownHosts(t *testing.T) {
	trusted, other := newSigner(t), newSigner(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")

	// No file: unknown, and nothing is created by looking.
	if got, err := InspectKnownHosts(path, "pve.example", 22, trusted.PublicKey()); err != nil || got.State != HostUnknown {
		t.Fatalf("no file: %+v, %v", got, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspecting created the file")
	}

	content := KnownHostsLine("pve.example", 22, trusted.PublicKey()) + "\n" +
		KnownHostsLine("other.example", 22, other.PublicKey()) + "\n" +
		KnownHostsLine("pve.example", 2222, other.PublicKey()) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		host string
		port int
		key  ssh.PublicKey
		want KnownHostsState
	}{
		{"same key", "pve.example", 22, trusted.PublicKey(), HostTrusted},
		{"host name case", "PVE.example", 22, trusted.PublicKey(), HostTrusted},
		{"a different key for the host", "pve.example", 22, other.PublicKey(), HostKeyChanged},
		{"another host", "third.example", 22, trusted.PublicKey(), HostUnknown},
		{"the port is part of the name", "pve.example", 2223, trusted.PublicKey(), HostUnknown},
		{"the other port's key", "pve.example", 2222, trusted.PublicKey(), HostKeyChanged},
	}
	for _, c := range cases {
		got, err := InspectKnownHosts(path, c.host, c.port, c.key)
		if err != nil || got.State != c.want {
			t.Errorf("%s: state %v, error %v; want %v", c.name, got.State, err, c.want)
		}
		if c.want == HostKeyChanged && len(got.Held) == 0 {
			t.Errorf("%s: the held keys are not named", c.name)
		}
	}
}

func TestInspectKnownHostsRefusesAFileItCannotRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte("pve.example ssh-ed25519 not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectKnownHosts(path, "pve.example", 22, newSigner(t).PublicKey()); err == nil {
		t.Fatal("a malformed known_hosts file was accepted")
	}
}

func TestAppendKnownHostCreatesPrivateFileAndDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secure", "certistack", "known_hosts")
	if err := AppendKnownHost(path, "pve.example ssh-ed25519 AAAA"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "pve.example ssh-ed25519 AAAA\n" {
		t.Fatalf("content %q, %v", data, err)
	}
	if runtime.GOOS != "windows" {
		fileInfo, _ := os.Stat(path)
		dirInfo, _ := os.Stat(filepath.Dir(path))
		if fileInfo.Mode().Perm() != 0o600 {
			t.Errorf("file mode %04o, want 0600", fileInfo.Mode().Perm())
		}
		if dirInfo.Mode().Perm() != 0o700 {
			t.Errorf("directory mode %04o, want 0700", dirInfo.Mode().Perm())
		}
	}
}

func TestAppendKnownHostKeepsEarlierLinesAndAddsMissingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte("first ssh-ed25519 AAAA"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := AppendKnownHost(path, "second ssh-ed25519 BBBB"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "first ssh-ed25519 AAAA\nsecond ssh-ed25519 BBBB\n" {
		t.Fatalf("content %q", data)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
			t.Errorf("an existing file's mode was changed to %04o", info.Mode().Perm())
		}
	}
	if err := AppendKnownHost(path, "bad\nline"); err == nil {
		t.Error("a line with a newline was accepted")
	}
}

func TestHasHostEntryFindsAHostByNameAndPortWhateverItsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if got, err := HasHostEntry(path, "pve.example", 22); err != nil || got {
		t.Fatalf("no file: %v, %v", got, err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, err := ssh.NewSignerFromKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	content := KnownHostsLine("pve.example", 22, newSigner(t).PublicKey()) + "\n" +
		KnownHostsLine("pve.example", 2222, newSigner(t).PublicKey()) + "\n" +
		KnownHostsLine("pve-ecdsa.example", 22, ecSigner.PublicKey()) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{"pve.example": true, "PVE.example": true, "other.example": false, "pve-ecdsa.example": true} {
		if got, err := HasHostEntry(path, host, 22); err != nil || got != want {
			t.Errorf("%s:22 = %v, %v; want %v", host, got, err, want)
		}
	}
	if got, err := HasHostEntry(path, "pve.example", 2222); err != nil || !got {
		t.Errorf("pve.example:2222 = %v, %v", got, err)
	}
	if got, err := HasHostEntry(path, "pve.example", 2223); err != nil || got {
		t.Errorf("pve.example:2223 = %v, %v", got, err)
	}
}

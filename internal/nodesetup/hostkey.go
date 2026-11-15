// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package nodesetup holds what `certistack setup` does without a node to
// talk to through the controller's SSH access: reading a node's SSH host key
// so an operator can approve it, validating and writing the PVE cluster CA,
// and writing the shell script that creates the PVE and PBS accounts. Nothing
// here weakens strict host-key checking: the host-key code only ever adds a
// line to a known_hosts file, and only for a key the caller has been told to
// confirm.
package nodesetup

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/cliftcloud/certistack/internal/sysutil"
)

const (
	// dialTimeout bounds making the TCP connection.
	dialTimeout = 15 * time.Second
	// handshakeTimeout bounds the whole exchange up to the node's host key.
	handshakeTimeout = 20 * time.Second
)

// DialFunc opens a network connection; net.Dialer.DialContext is the real one.
// A test gives the code a connection that never touches a network.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// NetDial is the DialFunc that connects to the network.
func NetDial(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: dialTimeout}
	return dialer.DialContext(ctx, network, address)
}

// HostKey is the ED25519 host key a node offered.
type HostKey struct {
	Key ssh.PublicKey
	// Fingerprint is the key's SHA-256 fingerprint as `ssh-keygen -l` prints it:
	// SHA256: and unpadded base64.
	Fingerprint string
}

// hostLabel is what a host name may contain. It excludes every character that
// is special in a known_hosts host field (a comma separates names, * ? and !
// are patterns, | starts a hash, and a space ends the field), so the line that
// is written names exactly one host.
var hostLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// NormalizeHost returns host as the known_hosts file spells it: without the
// brackets of an IPv6 literal, in lower case, as ssh looks a host up. It
// refuses anything that could name more than one host or none.
func NormalizeHost(host string) (string, error) {
	h := strings.TrimSpace(host)
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	if h == "" || !hostLabel.MatchString(h) {
		return "", fmt.Errorf("invalid host %q: use the name or address you connect to, without a user, a port or wildcards", host)
	}
	return strings.ToLower(h), nil
}

// CheckPort refuses a port that is not a TCP port.
func CheckPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: use a number from 1 to 65535", port)
	}
	return nil
}

// KnownHostsName is how a known_hosts file names host on port: the bare host
// for port 22 and [host]:port for any other, which is what ssh looks up.
func KnownHostsName(host string, port int) string {
	return knownhosts.Normalize(net.JoinHostPort(host, strconv.Itoa(port)))
}

// KnownHostsLine is the exact line to add to a known_hosts file for key.
func KnownHostsLine(host string, port int, key ssh.PublicKey) string {
	return KnownHostsName(host, port) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// errKeyRead stops the SSH handshake as soon as the host key is in hand: no
// credentials are offered and no session is opened.
var errKeyRead = errors.New("host key read")

// FetchHostKey reads the ED25519 host key host offers on port. It performs the
// SSH key exchange, which is where the server proves it holds the key, and
// stops there. It offers no credentials and trusts nothing: the caller decides
// whether the key is the node's.
func FetchHostKey(ctx context.Context, dial DialFunc, host string, port int) (HostKey, error) {
	host, err := NormalizeHost(host)
	if err != nil {
		return HostKey{}, err
	}
	if err := CheckPort(port); err != nil {
		return HostKey{}, err
	}
	if dial == nil {
		dial = NetDial
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return HostKey{}, fmt.Errorf("connect to %s: %w", address, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-finished:
		}
	}()

	var offered ssh.PublicKey
	config := &ssh.ClientConfig{
		User:              "certistack-trust-node",
		ClientVersion:     "SSH-2.0-certistack-trust-node",
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			offered = key
			return errKeyRead
		},
	}
	_, _, _, handshakeErr := ssh.NewClientConn(conn, address, config)
	if offered != nil {
		if offered.Type() != ssh.KeyAlgoED25519 {
			return HostKey{}, fmt.Errorf("%s offered a %s host key, not an ED25519 one", address, offered.Type())
		}
		return HostKey{Key: offered, Fingerprint: ssh.FingerprintSHA256(offered)}, nil
	}
	if err := ctx.Err(); err != nil {
		return HostKey{}, err
	}
	if handshakeErr != nil && strings.Contains(handshakeErr.Error(), "no common algorithm for host key") {
		return HostKey{}, fmt.Errorf("%s does not offer an ED25519 host key (the SSH server's own message: %v); CertiStack records ED25519 host keys only, so enable one on the node (HostKey /etc/ssh/ssh_host_ed25519_key in sshd_config) or record the key yourself", address, handshakeErr)
	}
	return HostKey{}, fmt.Errorf("read the SSH host key of %s: %w", address, handshakeErr)
}

// KnownHostsState says what a known_hosts file holds for a host.
type KnownHostsState int

const (
	// HostUnknown: the file has no line for the host (or does not exist).
	HostUnknown KnownHostsState = iota
	// HostTrusted: the file already holds exactly this key for the host.
	HostTrusted
	// HostKeyChanged: the file holds a different ED25519 key for the host.
	HostKeyChanged
	// HostOtherKeyTypes: the file holds keys of other types for the host and
	// none that conflicts with this one.
	HostOtherKeyTypes
)

// KnownHostsInspection is the result of InspectKnownHosts.
type KnownHostsInspection struct {
	State KnownHostsState
	// Held are the fingerprints of the keys the file holds for the host, when
	// it holds any that differ from the key.
	Held []string
}

// InspectKnownHosts reads path (which need not exist) and says what it holds
// for host on port, compared with key. A file that cannot be parsed is an
// error: whether the host is already trusted cannot be told, and adding a line
// to a file that is not understood could change what it means.
func InspectKnownHosts(path, host string, port int, key ssh.PublicKey) (KnownHostsInspection, error) {
	host, err := NormalizeHost(host)
	if err != nil {
		return KnownHostsInspection{}, err
	}
	if info, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return KnownHostsInspection{State: HostUnknown}, nil
	} else if err != nil {
		return KnownHostsInspection{}, fmt.Errorf("read %s: %w", path, err)
	} else if !info.Mode().IsRegular() {
		return KnownHostsInspection{}, fmt.Errorf("%s is not a regular file but %s, which reading would wait on; give --known-hosts a file", path, sysutil.FileKind(info.Mode()))
	} else if err := sysutil.UnsafeToTrust(path, info, sysutil.KnownHostsWhat, sysutil.KnownHostsRisk); err != nil {
		// What is written to a file that others can change is not trusted.
		return KnownHostsInspection{}, err
	}
	callback, err := knownhosts.New(path)
	if err != nil {
		return KnownHostsInspection{}, fmt.Errorf("%s is not a known_hosts file this tool can read (%v); fix or remove the line it names, or give --known-hosts another file", path, err)
	}
	remote := &net.TCPAddr{IP: net.IPv4zero, Port: port}
	err = callback(net.JoinHostPort(host, strconv.Itoa(port)), remote, key)
	var keyErr *knownhosts.KeyError
	switch {
	case err == nil:
		return KnownHostsInspection{State: HostTrusted}, nil
	case errors.As(err, &keyErr):
		if len(keyErr.Want) == 0 {
			return KnownHostsInspection{State: HostUnknown}, nil
		}
		inspection := KnownHostsInspection{State: HostOtherKeyTypes}
		for _, known := range keyErr.Want {
			inspection.Held = append(inspection.Held, known.Key.Type()+" "+ssh.FingerprintSHA256(known.Key))
			if known.Key.Type() == key.Type() {
				inspection.State = HostKeyChanged
			}
		}
		return inspection, nil
	default:
		return KnownHostsInspection{}, fmt.Errorf("check %s: %w", path, err)
	}
}

// AppendKnownHost adds line to the known_hosts file at path. It creates the
// file with mode 0600, and its directory with mode 0700 if that is missing,
// and never changes an existing file's mode or earlier lines. The line goes
// out in one write.
func AppendKnownHost(path, line string) error {
	if strings.ContainsAny(line, "\r\n") {
		return errors.New("a known_hosts line is one line")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create the directory for %s: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return fmt.Errorf("%s is not a regular file", path)
	}
	prefix := ""
	if info.Size() > 0 {
		last := make([]byte, 1)
		if _, err := file.ReadAt(last, info.Size()-1); err != nil {
			_ = file.Close()
			return fmt.Errorf("read %s: %w", path, err)
		}
		if last[0] != '\n' {
			prefix = "\n"
		}
	}
	if _, err := file.WriteString(prefix + line + "\n"); err != nil {
		_ = file.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return file.Close()
}

// probeKey is a key nobody holds, which HasHostEntry offers to a known_hosts
// file to learn whether it has any line for a host.
var probeKey = func() ssh.PublicKey {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	key, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		panic(err)
	}
	return key
}()

// HasHostEntry reports whether the known_hosts file at path has a line, of any
// key type, for host on port. It says nothing about whether the key in it is
// the node's: ssh decides that when it connects.
func HasHostEntry(path, host string, port int) (bool, error) {
	inspection, err := InspectKnownHosts(path, host, port, probeKey)
	if err != nil {
		return false, err
	}
	return inspection.State != HostUnknown, nil
}

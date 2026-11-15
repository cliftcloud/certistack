// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
)

// MapNameSuffix is how the name of the file proxmox-backup-client map
// creates under /run/pbs-loopdev ends for an archive of a snapshot. The
// whole name is the systemd unit escape of "<repository>:<snapshot>/<archive
// without .fidx>". The repository part is printed the way the client
// normalizes it, so recovery matches only this suffix: the escaped
// ":<snapshot>/<archive>". The name carries no namespace.
func MapNameSuffix(snapshot, drive string) (string, error) {
	if !validSnapshotPath(snapshot) {
		return "", fmt.Errorf("invalid PBS snapshot path %q", snapshot)
	}
	archive, err := normalizeDriveArchive(drive)
	if err != nil {
		return "", err
	}
	return escapeUnit(":" + snapshot + "/" + archive), nil
}

// MapRunDir is where proxmox-backup-client map creates the file a map's loop
// device is attached to.
const MapRunDir = "/run/pbs-loopdev"

// IsMapFile reports whether backing, the file the kernel says a loop device is
// attached to, is a map's file in MapRunDir whose name ends with nameSuffix
// (MapNameSuffix): a file of a map of that snapshot's archive.
func IsMapFile(backing, nameSuffix string) bool {
	return nameSuffix != "" && path.Dir(backing) == MapRunDir && strings.HasSuffix(path.Base(backing), nameSuffix)
}

// escapeUnit is proxmox_sys::systemd::escape_unit(s, false): "/" becomes
// "-", ASCII letters, digits, "_" and "." (except as the first character)
// stay, and every other byte becomes a literal backslash, "x" and its
// lowercase hex value.
func escapeUnit(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '/':
			b.WriteByte('-')
		case c == '_' || (c == '.' && i > 0) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%x`, c)
		}
	}
	return b.String()
}

// MapArchiveName is the archive argument CertiStack gives
// proxmox-backup-client map for drive: its name without ".fidx".
func MapArchiveName(drive string) (string, error) { return normalizeDriveArchive(drive) }

// MapOwner fingerprints what a map of snapshot's archive reads from: the
// repository and namespace proxmox-backup-client map uses. A run journals
// it with each map it begins, so recovery can tell that map's processes
// from a map of the same snapshot and archive in another repository or
// namespace. It is a hex SHA-256, so the journal never holds the
// repository, whose user part can name an API token.
func MapOwner(repository, namespace, snapshot, archive string) string {
	h := sha256.New()
	for _, part := range []string{"certistack pbs map owner v1", repository, namespace, snapshot, archive} {
		h.Write([]byte(part))
		h.Write([]byte{0}) // no part holds a NUL: it comes from argv or environ
	}
	return hex.EncodeToString(h.Sum(nil))
}

// MapOwner is MapOwner of the repository and namespace this client's Map
// uses for snapshot and drive.
func (c *Client) MapOwner(snapshot, drive string) (string, error) {
	archive, err := normalizeDriveArchive(drive)
	if err != nil {
		return "", err
	}
	return MapOwner(c.cfg.Repository, c.cfg.Namespace, snapshot, archive), nil
}

// MapTokenEnv names the environment variable that carries a map's token into
// its proxmox-backup-client process. The map's daemon is forked from that
// process and keeps its environment across the fork and setsid, so the token
// is how recovery knows a daemon it finds later started from this run's map
// (the run journals the token). It is a marker, not a credential.
const MapTokenEnv = "CERTISTACK_MAP_TOKEN"

// NewMapToken returns a fresh token for one map: 128 random bits in hex.
func NewMapToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("cannot make a token for the PBS map: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// validMapToken reports whether token has the form NewMapToken returns.
func validMapToken(token string) bool {
	if len(token) != 32 {
		return false
	}
	for _, r := range token {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// mapArgs is the command line Map runs, after the program name.
// ParseMapCommand recognizes exactly this form. The namespace is given as
// --ns, as for every command that reads a namespace (targetArgs): the 3.x
// client ignores PBS_NAMESPACE.
func (c *Client) mapArgs(snapshot, archive string, keyArgs []string) []string {
	args := append([]string{"map"}, c.targetArgs()...)
	args = append(args, keyArgs...)
	return append(args, snapshot, archive)
}

// MapCommand is a proxmox-backup-client map command line in the form Map
// runs it.
type MapCommand struct {
	Snapshot, Archive string
	// Repository is the --repository argument, when HasRepository.
	Repository    string
	HasRepository bool
	// Namespace is the --ns argument, when HasNamespace.
	Namespace    string
	HasNamespace bool
}

// ParseMapCommand reads argv as Map builds it: proxmox-backup-client, map,
// then at most one each of --repository, --ns and --keyfile (each "--name
// value" or "--name=value"), then exactly the snapshot and the archive. A map
// started without --ns (no namespace, or by a build that gave the namespace
// only in PBS_NAMESPACE) is of the same form. Nothing else is one of
// CertiStack's maps: not a restore whose target is named "map", and not a map
// with an option Map never passes, such as --verbose, or with an empty --ns.
func ParseMapCommand(argv []string) (MapCommand, bool) {
	var m MapCommand
	if len(argv) < 4 || path.Base(argv[0]) != "proxmox-backup-client" || argv[1] != "map" {
		return m, false
	}
	seen := map[string]bool{}
	i := 2
	for ; i < len(argv) && strings.HasPrefix(argv[i], "-"); i++ {
		name, value, inline := strings.Cut(argv[i], "=")
		if (name != "--repository" && name != "--ns" && name != "--keyfile") || seen[name] {
			return m, false
		}
		seen[name] = true
		if !inline {
			if i+1 >= len(argv) {
				return m, false
			}
			i++
			value = argv[i]
		}
		switch name {
		case "--repository":
			m.Repository, m.HasRepository = value, true
		case "--ns":
			// Map never gives an empty namespace; the client would read it as
			// the root namespace, whatever PBS_NAMESPACE says.
			if value == "" {
				return m, false
			}
			m.Namespace, m.HasNamespace = value, true
		}
	}
	if len(argv)-i != 2 || strings.HasPrefix(argv[i+1], "-") {
		return m, false
	}
	m.Snapshot, m.Archive = argv[i], argv[i+1]
	return m, true
}

// Owner is MapOwner of the repository and namespace the command maps
// from, the way the client resolves them: --repository, else
// PBS_REPOSITORY, and --ns, else PBS_NAMESPACE (an option beats the variable,
// as in the client). A map started by a build that gave the namespace only in
// the variable has no --ns and is owned by the variable's value, which is what
// that build journaled. env holds the process's environment variables of
// those names; a variable the process lacks is absent.
func (m MapCommand) Owner(env map[string]string) string {
	repository := env["PBS_REPOSITORY"]
	if m.HasRepository {
		repository = m.Repository
	}
	namespace := env["PBS_NAMESPACE"]
	if m.HasNamespace {
		namespace = m.Namespace
	}
	return MapOwner(repository, namespace, m.Snapshot, m.Archive)
}

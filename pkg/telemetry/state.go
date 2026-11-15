// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// StateFileName is the state file in the per-user configuration directory.
	StateFileName = "telemetry.json"

	// maxStateBytes is the largest file ReadState believes, and so the largest
	// WriteState writes: a state the reader refuses reads as corrupt, which
	// turns telemetry off and loses the install id.
	maxStateBytes = 64 << 10
	// maxClusters is the most cluster entries a readable file may hold.
	maxClusters = 4096
	// clusterCap is the most clusters a run records. An indented entry is 72
	// bytes, so this many leave the whole state far below maxStateBytes (about
	// 900 would not fit); past it a run keeps the cap as its count and the
	// install id, the answer and the entries as they are.
	clusterCap = 512
)

// State is telemetry.json: the user's answers and the local bookkeeping the
// report is built from. Only the five Payload fields are ever derived from it;
// Salt and Clusters never leave the machine.
//
// An install (InstallID and Salt) with Enabled false is the install that an
// opt-in through CERTISTACK_TELEMETRY=1 keeps: the environment says yes on
// every run, and the file only holds what a report needs to be counted once a
// day. Answered then says only whether the user was ever asked, as before.
type State struct {
	Answered    bool     `json:"answered"`
	Enabled     bool     `json:"enabled"`
	BusinessUse bool     `json:"business_use"`
	InstallID   string   `json:"install_id"`
	Salt        string   `json:"salt"`
	Clusters    []string `json:"clusters"`
	LastTestRun string   `json:"last_test_run"`
	LastSent    string   `json:"last_sent"`
}

// StateStatus says how reading the state file went.
type StateStatus int

const (
	// StateMissing: no file, so the user was never asked. Off.
	StateMissing StateStatus = iota
	// StateOK: the file was read and is consistent.
	StateOK
	// StateCorrupt: unreadable, not a regular file, too large, not JSON, or
	// inconsistent. Off: never a crash, never a send.
	StateCorrupt
)

func (s StateStatus) String() string {
	switch s {
	case StateMissing:
		return "missing"
	case StateOK:
		return "ok"
	}
	return "corrupt"
}

// DefaultStatePath is the per-user state file: telemetry.json under the user's
// configuration directory (XDG_CONFIG_HOME, else ~/.config on Linux).
func DefaultStatePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("no per-user configuration directory: %w", err)
	}
	return filepath.Join(dir, "certistack", StateFileName), nil
}

var (
	uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hex64Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("make an install id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// NewInstall is the state of a user who just opted in: a fresh random install
// id and salt, no clusters, nothing sent.
func NewInstall(business bool) (State, error) {
	id, err := newUUIDv4()
	if err != nil {
		return State{}, err
	}
	var salt [32]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return State{}, fmt.Errorf("make a salt: %w", err)
	}
	return State{Answered: true, Enabled: true, BusinessUse: business, InstallID: id, Salt: hex.EncodeToString(salt[:]), Clusters: []string{}}, nil
}

// HasInstall says the state holds an install, an id and a salt, whether or not
// a yes is stored with it.
func (s State) HasInstall() bool { return s.InstallID != "" && s.Salt != "" }

// NewEnvironmentInstall is the state an opt-in through the environment keeps: a
// fresh install with no yes stored. answered carries over whether the user was
// ever asked, so a stored no is not turned into "never asked".
func NewEnvironmentInstall(answered, business bool) (State, error) {
	st, err := NewInstall(business)
	if err != nil {
		return State{}, err
	}
	st.Answered, st.Enabled = answered, false
	return st, nil
}

// Declined is the state of a user who answered no: asked once, nothing kept.
func Declined() State {
	return State{Answered: true, Clusters: []string{}}
}

// ClusterHash is the salted digest a cluster identity is stored as.
func ClusterHash(salt, identity string) string {
	sum := sha256.Sum256([]byte(salt + "\x00" + strings.ToLower(strings.TrimSpace(identity))))
	return hex.EncodeToString(sum[:])
}

// AddCluster remembers a cluster the installation has validated, by its salted
// hash, once. An empty identity is ignored.
func (s *State) AddCluster(identity string) error {
	if strings.TrimSpace(identity) == "" {
		return nil
	}
	if !hex64Pattern.MatchString(s.Salt) {
		return errors.New("no salt: the cluster would be stored unsalted")
	}
	hash := ClusterHash(s.Salt, identity)
	for _, have := range s.Clusters {
		if have == hash {
			return nil
		}
	}
	if len(s.Clusters) >= clusterCap {
		return nil
	}
	s.Clusters = append(s.Clusters, hash)
	return nil
}

func validDate(s string) bool {
	d, err := time.Parse(DateLayout, s)
	return err == nil && d.Format(DateLayout) == s
}

// validate is the consistency a readable file must have to be believed.
func (s State) validate() error {
	if s.InstallID != "" && !uuidV4Pattern.MatchString(s.InstallID) {
		return errors.New("install_id is not a UUID v4")
	}
	if s.Salt != "" && !hex64Pattern.MatchString(s.Salt) {
		return errors.New("salt is not 64 hex characters")
	}
	if len(s.Clusters) > maxClusters {
		return errors.New("too many cluster entries")
	}
	seen := map[string]bool{}
	for _, c := range s.Clusters {
		if !hex64Pattern.MatchString(c) || seen[c] {
			return errors.New("a cluster entry is not a unique 64-hex digest")
		}
		seen[c] = true
	}
	if s.LastTestRun != "" && !validDate(s.LastTestRun) {
		return errors.New("last_test_run is not a YYYY-MM-DD date")
	}
	if s.LastSent != "" {
		if _, err := time.Parse(time.RFC3339, s.LastSent); err != nil {
			return errors.New("last_sent is not an RFC 3339 time")
		}
	}
	if s.Enabled && (!s.Answered || s.InstallID == "" || s.Salt == "") {
		return errors.New("enabled without an answer, an install id and a salt")
	}
	return nil
}

// ReadState reads path. A missing file is StateMissing; anything that cannot
// be believed is StateCorrupt, with the zero (off) state either way.
func ReadState(path string) (State, StateStatus) {
	// Look before opening: opening a named pipe would wait for a writer, and a
	// command must never hang on a file it did not expect.
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, StateMissing
		}
		return State{}, StateCorrupt
	}
	if !info.Mode().IsRegular() {
		return State{}, StateCorrupt
	}
	f, err := os.Open(path)
	if err != nil {
		return State{}, StateCorrupt
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil || len(data) > maxStateBytes {
		return State{}, StateCorrupt
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var decoded *State // a JSON null leaves it nil
	if err := dec.Decode(&decoded); err != nil || decoded == nil {
		return State{}, StateCorrupt
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return State{}, StateCorrupt
	}
	if err := decoded.validate(); err != nil {
		return State{}, StateCorrupt
	}
	return *decoded, StateOK
}

func marshalState(s State) ([]byte, error) {
	if s.Clusters == nil {
		s.Clusters = []string{}
	}
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// WriteState replaces path atomically with mode 0600 (its directory, if made,
// 0700). It refuses a state ReadState would not believe.
func WriteState(path string, s State) error {
	if err := s.validate(); err != nil {
		return fmt.Errorf("refusing to write an inconsistent telemetry state: %w", err)
	}
	data, err := marshalState(s)
	if err != nil {
		return err
	}
	if len(data) > maxStateBytes {
		return fmt.Errorf("refusing to write a telemetry state of %d bytes: it is too large for ReadState (limit %d), which would count it as corrupt", len(data), maxStateBytes)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, StateFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	// os.CreateTemp makes the file 0600, so the data is never readable by
	// anyone else, not even before the rename.
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// DeleteState removes the state file; an absent file is not an error.
func DeleteState(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package attest builds the report of a disaster recovery validation, defines the
// Signer through which the Enterprise Edition signs it, and verifies a signed one.
// The Community Edition has no code that reads a private key, generates a key pair
// or makes a signature; see signer.go and the attesttest package.
package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/gowebpki/jcs"
)

// Canonicalize converts an arbitrary JSON data structure to deterministic RFC 8785 canonical JSON.
func Canonicalize(v interface{}) ([]byte, error) {
	rawJSON, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	canonical, err := jcs.Transform(rawJSON)
	if err != nil {
		return nil, fmt.Errorf("RFC 8785 JSON canonicalization failed: %w", err)
	}

	return canonical, nil
}

// VerifyCanonical verifies that a hex-encoded signature is valid for the canonical bytes and public key.
// A malformed signature or public key, or a public key that cannot anchor trust (a small-order or
// non-curve point), is an error, never a panic and never a valid signature.
func VerifyCanonical(canonicalBytes []byte, hexSig string, pubKey ed25519.PublicKey) (bool, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid Ed25519 public key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(pubKey))
	}
	// Go's ed25519.Verify accepts forged signatures under small-order keys.
	if err := checkPublicKey(pubKey); err != nil {
		return false, fmt.Errorf("unusable Ed25519 public key: %w", err)
	}
	sigBytes, err := hex.DecodeString(hexSig)
	if err != nil {
		return false, fmt.Errorf("failed to decode hex signature: %w", err)
	}

	if len(sigBytes) != ed25519.SignatureSize {
		return false, errors.New("invalid signature length")
	}

	valid := ed25519.Verify(pubKey, canonicalBytes, sigBytes)
	return valid, nil
}

// Fingerprint returns the RFC-compliant SHA-256 fingerprint of an Ed25519 public key.
func Fingerprint(pubKey ed25519.PublicKey) string {
	hash := sha256.Sum256(pubKey)
	return fmt.Sprintf("SHA256:%s", hex.EncodeToString(hash[:]))
}

// FingerprintFromHex computes the fingerprint from a hex-encoded public key string.
func FingerprintFromHex(pubKeyHex string) string {
	b, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return ""
	}
	return Fingerprint(ed25519.PublicKey(b))
}

// TrustedSigner defines a recognized entity in an operator-managed keyring.
type TrustedSigner struct {
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Node        string `json:"node,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// Keyring represents a collection of authorized signers for DR audit reports.
type Keyring struct {
	TrustedSigners []TrustedSigner `json:"trusted_signers"`
}

// LoadKeyringFile loads either a JSON keyring ({ "trusted_signers": [...] })
// or a legacy newline-delimited hex list from path (blank lines and lines
// starting with # are ignored). The file must be a regular file no larger than
// MaxKeyringFileBytes, and its entries must form a coherent trust set, as
// Validate defines it: a keyring with an entry that cannot be used as a trust
// anchor is refused with the entry named, never loaded with that entry
// silently dropped. A keyring with no entries at all is loaded; it trusts no
// one.
func LoadKeyringFile(path string) (*Keyring, error) {
	data, err := ReadRegularFile(path, "keyring", MaxKeyringFileBytes)
	if err != nil {
		return nil, err
	}
	return parseKeyring(data, path)
}

// parseKeyring parses and validates the content of a keyring file; path only
// names the file in errors.
func parseKeyring(data []byte, path string) (*Keyring, error) {
	data = bytes.TrimPrefix(data, utf8BOM)

	var kr Keyring
	var label func(int) string
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		if err := scanJSON(data, keyringLimits); err != nil {
			return nil, fmt.Errorf("invalid JSON keyring %s: %w", path, err)
		}
		if err := checkKeyringMembers(data); err != nil {
			return nil, fmt.Errorf("invalid JSON keyring %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &kr); err != nil {
			return nil, fmt.Errorf("invalid JSON keyring %s: %w", path, err)
		}
		if kr.TrustedSigners == nil {
			return nil, fmt.Errorf("invalid JSON keyring %s: it has no \"trusted_signers\" list (write an empty list for a keyring that trusts no one)", path)
		}
		label = kr.entryLabel
	} else {
		var lines []int
		for i, line := range strings.Split(string(data), "\n") {
			l := strings.TrimSpace(line)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			kr.TrustedSigners = append(kr.TrustedSigners, TrustedSigner{Name: fmt.Sprintf("Key-%d", i+1), PublicKey: l})
			lines = append(lines, i+1)
		}
		label = func(i int) string { return fmt.Sprintf("line %d", lines[i]) }
	}
	if problems := kr.problems(label); len(problems) > 0 {
		return nil, fmt.Errorf("keyring %s is not a valid set of trusted signers:%s", path, listProblems(problems))
	}
	// Every entry is now known to be usable: keep its key and fingerprint in
	// their one canonical spelling, whatever case or spacing the file used.
	for i := range kr.TrustedSigners {
		key, _ := hex.DecodeString(strings.TrimSpace(kr.TrustedSigners[i].PublicKey)) // validated above
		kr.TrustedSigners[i].PublicKey = hex.EncodeToString(key)
		kr.TrustedSigners[i].Fingerprint = Fingerprint(ed25519.PublicKey(key))
	}
	return &kr, nil
}

// The member names a JSON keyring documents, at its top level and in each entry.
var (
	keyringMemberNames = []string{"trusted_signers"}
	signerMemberNames  = []string{"name", "public_key", "fingerprint", "node", "created_at"}
)

// checkKeyringMembers refuses a member name that reads as a documented one
// without being it. encoding/json matches a member to a field ignoring case
// and Unicode case folding (the Kelvin sign U+212A is a k, the long s U+017F
// an s) and the last match wins, so "Public_Key" beside "public_key" would
// override the key a reader sees, while the duplicate check compares names
// exactly. It also refuses a member that marks an entry revoked, by its name or
// by its text value: revocation is not evaluated, so the key would
// silently stay trusted. Other members are ignored, so a newer release can add
// members.
func checkKeyringMembers(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return err
	}
	if err := checkMemberNames(top, keyringMemberNames, "the keyring"); err != nil {
		return err
	}
	var entries []json.RawMessage
	if json.Unmarshal(top["trusted_signers"], &entries) != nil {
		return nil // a list of the wrong type is reported when it is decoded
	}
	for i, entry := range entries {
		var members map[string]json.RawMessage
		if json.Unmarshal(entry, &members) != nil {
			continue
		}
		if err := checkMemberNames(members, signerMemberNames, fmt.Sprintf("entry %d", i+1)); err != nil {
			return err
		}
	}
	return nil
}

func checkMemberNames(members map[string]json.RawMessage, known []string, where string) error {
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if slices.Contains(known, name) {
			continue
		}
		for _, documented := range known {
			if strings.EqualFold(name, documented) {
				return fmt.Errorf("%s: member %s reads as %q but is not spelled exactly like it; write %q", where, quoteShort(name), documented, documented)
			}
		}
		if saysRevoked(name) {
			return fmt.Errorf("%s: member %s marks a key as revoked, which this release does not evaluate, so the key would still be trusted; remove the entry to revoke a key", where, quoteShort(name))
		}
		// A mark in the value ("status": "revoked", as other tools write it)
		// is the same mark.
		var text string
		if json.Unmarshal(members[name], &text) == nil && saysRevoked(text) {
			return fmt.Errorf("%s: member %s says %s, which marks a key as revoked; this release does not evaluate that, so the key would still be trusted; remove the entry to revoke a key", where, quoteShort(name), quoteShort(strings.TrimSpace(text)))
		}
	}
	return nil
}

// saysRevoked is whether text, as a member name or a value, marks a key as
// revoked: it starts with "revok" or "revoc", in any case.
func saysRevoked(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	return strings.HasPrefix(lower, "revok") || strings.HasPrefix(lower, "revoc")
}

// Validate reports whether the keyring is a coherent trust set. Every entry
// must hold a public key of exactly 32 bytes as hexadecimal, in either case;
// an entry's fingerprint, when it has one, must be the fingerprint of that
// key; and no key may appear twice, in any case, so the name and node a
// verifier reports for a signer never depend on the order of the entries.
// (Two different keys may share a name: a rotation keeps the retiring and the
// new key of one signer.) The error names every offending entry, up to a
// limit. LoadKeyringFile applies it; call it on a keyring built by hand,
// because PublicKeys skips an entry that is not a valid key.
func (k *Keyring) Validate() error {
	if k == nil {
		return nil
	}
	if problems := k.problems(k.entryLabel); len(problems) > 0 {
		return fmt.Errorf("the keyring is not a valid set of trusted signers:%s", listProblems(problems))
	}
	return nil
}

// entryLabel names entry i of the keyring in an error: its position, counted
// from 1, and its name.
func (k *Keyring) entryLabel(i int) string {
	if name := k.TrustedSigners[i].Name; name != "" {
		return fmt.Sprintf("entry %d (%s)", i+1, quoteShort(name))
	}
	return fmt.Sprintf("entry %d", i+1)
}

// problems lists what keeps the keyring from being a coherent trust set, one
// line per fault, each starting with the label of the entry it is in.
func (k *Keyring) problems(label func(int) string) []string {
	var problems []string
	firstWith := make(map[string]int)
	for i, signer := range k.TrustedSigners {
		key, err := parsePublicKeyHex(signer.PublicKey)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", label(i), err))
			continue
		}
		if given := strings.TrimSpace(signer.Fingerprint); given != "" && !strings.EqualFold(given, Fingerprint(key)) {
			problems = append(problems, fmt.Sprintf("%s: its fingerprint %s does not match its public key, whose fingerprint is %s; correct or remove the fingerprint",
				label(i), quoteShort(given), Fingerprint(key)))
		}
		if first, repeated := firstWith[string(key)]; repeated {
			problems = append(problems, fmt.Sprintf("%s: it holds the same public key as %s; keep each key once", label(i), label(first)))
		} else {
			firstWith[string(key)] = i
		}
	}
	return problems
}

// maxListedProblems bounds how many faults of one keyring an error lists.
const maxListedProblems = 10

func listProblems(problems []string) string {
	var b strings.Builder
	for i, problem := range problems {
		if i == maxListedProblems {
			fmt.Fprintf(&b, "\n  - and %d more", len(problems)-i)
			break
		}
		b.WriteString("\n  - " + problem)
	}
	return b.String()
}

// quoteShort quotes text from a file for an error message, cut to a readable
// length, so a hostile file cannot flood or spoof a terminal.
func quoteShort(text string) string {
	const limit = 80
	if runes := []rune(text); len(runes) > limit {
		text = string(runes[:limit]) + "..."
	}
	return strconv.Quote(text)
}

// ParsePublicKeyHex decodes an Ed25519 public key written as 64 hexadecimal
// digits in either case, ignoring surrounding whitespace, and refuses one that
// cannot anchor trust: an encoding that is not a canonical curve point, or a
// small-order point such as 64 zeros, for which anyone can forge a signature.
// Its errors describe the fault without quoting the text.
func ParsePublicKeyHex(text string) (ed25519.PublicKey, error) {
	key, err := parsePublicKeyHex(text)
	if err != nil {
		return nil, errors.New(strings.TrimPrefix(err.Error(), "its "))
	}
	return key, nil
}

// parsePublicKeyHex is ParsePublicKeyHex with errors that begin "its public
// key ..." or "it has ...", to follow the label of a keyring entry.
func parsePublicKeyHex(text string) (ed25519.PublicKey, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("it has no public key")
	}
	raw, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("its public key is not %d hexadecimal digits (it has %d characters)", 2*ed25519.PublicKeySize, len(text))
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("its public key is %d bytes; an Ed25519 public key is %d bytes (%d hexadecimal digits)", len(raw), ed25519.PublicKeySize, 2*ed25519.PublicKeySize)
	}
	if err := checkPublicKey(raw); err != nil {
		return nil, fmt.Errorf("its public key is not a usable Ed25519 key: %w", err)
	}
	return ed25519.PublicKey(raw), nil
}

// LoadPublicKeyFile loads one Ed25519 public key from path: 64 hexadecimal
// digits (surrounding whitespace, a CRLF line end and a UTF-8 byte-order mark
// are ignored), as a hex key file is written, or 32 raw bytes. The file must
// be a regular file no larger than MaxPublicKeyFileBytes. Exactly 32 bytes are
// a raw key whatever they are, because no hex encoding of a key fits in 32
// bytes; so a raw key made only of hex digits is still a raw key.
func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	data, err := ReadRegularFile(path, "public key", MaxPublicKeyFileBytes)
	if err != nil {
		return nil, err
	}
	if len(data) == ed25519.PublicKeySize {
		if err := checkPublicKey(data); err != nil {
			return nil, fmt.Errorf("invalid public key in %s: it is not a usable Ed25519 key: %w", path, err)
		}
		return ed25519.PublicKey(data), nil
	}
	key, err := parsePublicKeyHex(string(bytes.TrimPrefix(data, utf8BOM)))
	if err != nil {
		return nil, fmt.Errorf("invalid public key format in %s: %s", path, strings.TrimPrefix(err.Error(), "its "))
	}
	return key, nil
}

// FindSigner searches the keyring for a matching public key hex.
func (k *Keyring) FindSigner(pubKeyHex string) *TrustedSigner {
	if k == nil {
		return nil
	}
	pubKeyHex = strings.ToLower(strings.TrimSpace(pubKeyHex))
	for _, s := range k.TrustedSigners {
		if strings.ToLower(strings.TrimSpace(s.PublicKey)) == pubKeyHex {
			signerCopy := s
			return &signerCopy
		}
	}
	return nil
}

// PublicKeys returns all valid ed25519.PublicKey objects in the keyring.
func (k *Keyring) PublicKeys() []ed25519.PublicKey {
	if k == nil {
		return nil
	}
	var keys []ed25519.PublicKey
	for _, s := range k.TrustedSigners {
		if key, err := parsePublicKeyHex(s.PublicKey); err == nil {
			keys = append(keys, key)
		}
	}
	return keys
}

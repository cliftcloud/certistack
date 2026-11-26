// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeInput(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// allocatedBy returns how many bytes f allocates, as Go's cumulative
// allocation counter sees it.
func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// growFile makes path n bytes longer, as a writer that keeps writing while the
// file is being read. It allocates nothing, so a test can measure what the
// reader allocates.
func growFile(path string, n int64) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.Truncate(path, info.Size()+n)
}

// Keyring, public key and report inputs are read through one bounded
// reader: the limit is accepted, one byte over is refused, a file that grows
// past the limit is refused with bounded reading, a directory is refused, and
// an entry replaced after it was inspected is refused unread.
func TestReadRegularFileBounds(t *testing.T) {
	dir := t.TempDir()
	const limit = 100

	for size, wantErr := range map[int]string{0: "", 1: "", limit - 1: "", limit: "", limit + 1: "larger than", 10 * limit: "larger than"} {
		path := writeInput(t, dir, fmt.Sprintf("size-%d", size), bytes.Repeat([]byte("k"), size))
		data, err := ReadRegularFile(path, "keyring", limit)
		switch {
		case wantErr == "" && (err != nil || len(data) != size):
			t.Errorf("%d bytes: (%d bytes, %v), want them all", size, len(data), err)
		case wantErr != "" && (err == nil || data != nil || !strings.Contains(err.Error(), wantErr)):
			t.Errorf("%d bytes: (%d bytes, %v), want an error containing %q", size, len(data), err, wantErr)
		}
	}

	growing := writeInput(t, dir, "growing", []byte("small"))
	withFileStep(t, func(step, path string) error {
		if step == "input-opened" && path == growing {
			return growFile(growing, 16<<20)
		}
		return nil
	})
	var err error
	if allocated := allocatedBy(func() { _, err = ReadRegularFile(growing, "report", 1<<20) }); err == nil || !strings.Contains(err.Error(), "larger than") || allocated > 8<<20 {
		t.Errorf("a file growing past the limit: err=%v, allocated %d bytes", err, allocated)
	}
	withFileStep(t, func(string, string) error { return nil })

	if _, err := ReadRegularFile(dir, "keyring", limit); err == nil || !strings.Contains(err.Error(), "a directory, not a regular file") {
		t.Errorf("a directory: %v", err)
	}
	missing := filepath.Join(dir, "missing")
	if _, err := ReadRegularFile(missing, "keyring", limit); err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("a missing file: %v", err)
	}

	original := writeInput(t, dir, "original", []byte("checked"))
	replacement := writeInput(t, dir, "replacement", []byte("planted"))
	withFileStep(t, func(step, path string) error {
		if step == "input-inspected" && path == original {
			return os.Rename(replacement, original)
		}
		return nil
	})
	if data, err := ReadRegularFile(original, "keyring", limit); err == nil || data != nil || !strings.Contains(err.Error(), "was replaced") {
		t.Errorf("an entry replaced after its inspection: (%q, %v)", data, err)
	}
}

// A symbolic link to a regular file is followed for these public
// inputs, and a link to anything else is refused.
func TestReadRegularFileFollowsLinksToRegularFilesOnly(t *testing.T) {
	symlinksSupported(t)
	dir := t.TempDir()
	target := writeInput(t, dir, "target", []byte("content"))
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadRegularFile(link, "keyring", 100); err != nil || string(data) != "content" {
		t.Fatalf("link to a regular file: (%q, %v)", data, err)
	}
	dirLink := filepath.Join(dir, "dirlink")
	if err := os.Symlink(dir, dirLink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(dirLink, "keyring", 100); err == nil {
		t.Fatal("a link to a directory was read")
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nothing"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(dangling, "keyring", 100); err == nil {
		t.Fatal("a dangling link was read")
	}
}

// The loaders refuse a 16 MiB file after reading none of it, and allocate
// nothing in proportion to its size. A report is refused the same way one byte
// over its own limit (MaxReportFileBytes).
func TestTrustFileLoadersRefuseHugeFilesWithoutReadingThem(t *testing.T) {
	pub, _ := newKey(t)
	dir := t.TempDir()
	huge := func(name string, size int64) string {
		path := writeInput(t, dir, name, []byte(publicKeyFile(pub)))
		if err := os.Truncate(path, size); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, tc := range map[string]struct {
		size int64
		load func(string) error
	}{
		"keyring":    {16 << 20, func(p string) error { _, err := LoadKeyringFile(p); return err }},
		"public key": {16 << 20, func(p string) error { _, err := LoadPublicKeyFile(p); return err }},
		"report":     {MaxReportFileBytes + 1, func(p string) error { _, err := ReadRegularFile(p, "report", MaxReportFileBytes); return err }},
	} {
		path := huge(strings.ReplaceAll(name, " ", "-"), tc.size)
		var err error
		if allocated := allocatedBy(func() { err = tc.load(path) }); err == nil || !strings.Contains(err.Error(), "larger than") || allocated > 2<<20 {
			t.Errorf("%s: a file of %d bytes: err=%v, allocated %d bytes", name, tc.size, err, allocated)
		}
	}
}

// A public key file is 64 hex digits, however the editor that wrote it ended
// its lines, or 32 raw bytes, told apart by size alone; it is bounded like the
// other inputs.
func TestLoadPublicKeyFile(t *testing.T) {
	pub, _ := newKey(t)
	keyHex := hex.EncodeToString(pub)
	allA := bytes.Repeat([]byte("a"), ed25519.PublicKeySize)
	dir := t.TempDir()

	for _, tc := range []struct {
		name    string
		content []byte
		want    ed25519.PublicKey
	}{
		{"hex with a line end", []byte(keyHex + "\n"), pub},
		{"hex without a line end", []byte(keyHex), pub},
		{"hex with CRLF", []byte(keyHex + "\r\n"), pub},
		{"hex in upper case", []byte(strings.ToUpper(keyHex)), pub},
		{"hex with a byte-order mark", append(append([]byte(nil), utf8BOM...), []byte(keyHex+"\r\n")...), pub},
		{"hex with surrounding whitespace", []byte(" \t" + keyHex + "  \n\n"), pub},
		{"raw key", []byte(pub), pub},
	} {
		path := writeInput(t, dir, "ok.pub", tc.content)
		if got, err := LoadPublicKeyFile(path); err != nil || !bytes.Equal(got, tc.want) {
			t.Errorf("%s: LoadPublicKeyFile = (%x, %v), want %x", tc.name, got, err, []byte(tc.want))
		}
	}

	// Exactly 32 bytes are a raw key whatever they are, and 64 hex digits are
	// hex, told apart by size alone. These values are not keys, so what is
	// checked is the reading: the outcome must follow whether the bytes read
	// the intended way are a curve point (an independent oracle decides), and
	// an error must never be about the wrong encoding.
	edge := append(append([]byte{'\n'}, allA[:30]...), '\n')
	for name, tc := range map[string]struct{ content, key []byte }{
		"32 ASCII a bytes are a raw key":            {allA, allA},
		"whitespace at both ends of 32 bytes stays": {edge, edge},
		"64 hex digits are hex, not a raw key":      {bytes.Repeat([]byte("a"), 2*ed25519.PublicKeySize), bytes.Repeat([]byte{0xaa}, ed25519.PublicKeySize)},
	} {
		got, err := LoadPublicKeyFile(writeInput(t, dir, "shape.pub", tc.content))
		if onCurveOracle(tc.key) != (err == nil) || (err == nil && !bytes.Equal(got, tc.key)) {
			t.Errorf("%s: LoadPublicKeyFile = (%x, %v), want the key read as intended, accepted only if it is a curve point", name, got, err)
		}
		if err != nil && strings.Contains(err.Error(), "hexadecimal") {
			t.Errorf("%s: read as the wrong encoding: %v", name, err)
		}
	}

	for name, content := range map[string][]byte{
		"empty":                       nil,
		"whitespace only":             []byte(" \n"),
		"31 raw bytes":                bytes.Repeat([]byte{0x9c}, 31),
		"33 raw bytes":                bytes.Repeat([]byte{0x9c}, 33),
		"62 hex characters":           []byte(keyHex[:62]),
		"66 hex characters":           []byte(keyHex + "00"),
		"63 hex characters":           []byte(keyHex[:63]),
		"hex with an inner space":     []byte(keyHex[:20] + " " + keyHex[20:]),
		"hex with a 0x prefix":        []byte("0x" + keyHex),
		"two keys on two lines":       []byte(keyHex + "\n" + keyHex + "\n"),
		"a comment after the key":     []byte(keyHex + " # trusted\n"),
		"4 KiB and one byte of hex":   append(bytes.Repeat([]byte(" "), MaxPublicKeyFileBytes-len(keyHex)+1), keyHex...),
		"64 hex characters and a NUL": append([]byte(keyHex), 0),
	} {
		path := writeInput(t, dir, "bad.pub", content)
		if key, err := LoadPublicKeyFile(path); err == nil || key != nil {
			t.Errorf("%s: LoadPublicKeyFile = (%x, %v), want an error", name, key, err)
		}
	}

	// The limit itself is accepted.
	atLimit := append(bytes.Repeat([]byte(" "), MaxPublicKeyFileBytes-len(keyHex)), keyHex...)
	if got, err := LoadPublicKeyFile(writeInput(t, dir, "limit.pub", atLimit)); err != nil || !bytes.Equal(got, pub) {
		t.Errorf("a public key file of exactly %d bytes: %v", MaxPublicKeyFileBytes, err)
	}
}

func keyringFixture(t *testing.T, content string) string {
	t.Helper()
	return writeInput(t, t.TempDir(), "keyring", []byte(content))
}

func jsonKeyring(t *testing.T, entries ...map[string]string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"trusted_signers": entries})
	if err != nil {
		t.Fatal(err)
	}
	return keyringFixture(t, string(raw))
}

// A contradictory keyring (a key labeled with another key's fingerprint, a
// malformed anchor, and the first key again in upper case with other metadata)
// is refused whole, and the error names each entry.
func TestKeyringWithContradictoryEntriesIsRefused(t *testing.T) {
	pubA, _ := newKey(t)
	pubB, _ := newKey(t)
	keyA := hex.EncodeToString(pubA)
	path := jsonKeyring(t,
		map[string]string{"name": "first-conflicting-label", "node": "wrong-node.example", "public_key": keyA, "fingerprint": Fingerprint(pubB)},
		map[string]string{"name": "malformed-anchor", "public_key": "not-an-ed25519-key"},
		map[string]string{"name": "duplicate-conflicting-label", "node": "other-node.example", "public_key": strings.ToUpper(keyA), "fingerprint": Fingerprint(pubA)},
	)
	kr, err := LoadKeyringFile(path)
	if err == nil || kr != nil {
		t.Fatalf("LoadKeyringFile accepted the contradictory keyring: (%v, %v)", kr != nil, err)
	}
	for _, want := range []string{
		`entry 1 ("first-conflicting-label"): its fingerprint "` + Fingerprint(pubB) + `" does not match its public key, whose fingerprint is ` + Fingerprint(pubA),
		`entry 2 ("malformed-anchor"): its public key is not 64 hexadecimal digits`,
		`entry 3 ("duplicate-conflicting-label"): it holds the same public key as entry 1 ("first-conflicting-label")`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lacks %q:\n%v", want, err)
		}
	}
	if keys, err := LoadKeyring(path); err == nil || keys != nil {
		t.Errorf("LoadKeyring accepted the contradictory keyring: (%d keys, %v)", len(keys), err)
	}
}

// Each fault alone is refused, and the matching controls load.
func TestKeyringEntryFaultsAreEachRefused(t *testing.T) {
	pubA, _ := newKey(t)
	pubB, _ := newKey(t)
	keyA, keyB := hex.EncodeToString(pubA), hex.EncodeToString(pubB)

	refused := map[string]struct {
		entries []map[string]string
		want    string
	}{
		"missing public key":       {[]map[string]string{{"name": "n"}}, "it has no public key"},
		"non-hex public key":       {[]map[string]string{{"name": "n", "public_key": strings.Repeat("z", 64)}}, "not 64 hexadecimal digits"},
		"31-byte public key":       {[]map[string]string{{"name": "n", "public_key": keyA[:62]}}, "is 31 bytes"},
		"33-byte public key":       {[]map[string]string{{"name": "n", "public_key": keyA + "00"}}, "is 33 bytes"},
		"odd-length public key":    {[]map[string]string{{"name": "n", "public_key": keyA[:63]}}, "not 64 hexadecimal digits"},
		"key with an inner space":  {[]map[string]string{{"name": "n", "public_key": keyA[:32] + " " + keyA[32:]}}, "not 64 hexadecimal digits"},
		"key with a 0x prefix":     {[]map[string]string{{"name": "n", "public_key": "0x" + keyA}}, "not 64 hexadecimal digits"},
		"mismatched fingerprint":   {[]map[string]string{{"name": "n", "public_key": keyA, "fingerprint": Fingerprint(pubB)}}, "does not match its public key"},
		"fingerprint without sha":  {[]map[string]string{{"name": "n", "public_key": keyA, "fingerprint": strings.TrimPrefix(Fingerprint(pubA), "SHA256:")}}, "does not match its public key"},
		"exact duplicate":          {[]map[string]string{{"name": "n", "public_key": keyA}, {"name": "n", "public_key": keyA}}, "same public key as entry 1"},
		"case-variant duplicate":   {[]map[string]string{{"name": "n", "public_key": keyA}, {"name": "m", "public_key": strings.ToUpper(keyA)}}, "same public key as entry 1"},
		"padded duplicate":         {[]map[string]string{{"name": "n", "public_key": keyA}, {"name": "m", "public_key": " " + keyA + "\n"}}, "same public key as entry 1"},
		"fault after a good entry": {[]map[string]string{{"name": "good", "public_key": keyA}, {"name": "bad", "public_key": "abcd"}}, `entry 2 ("bad")`},
	}
	for name, tc := range refused {
		kr, err := LoadKeyringFile(jsonKeyring(t, tc.entries...))
		if err == nil || kr != nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: LoadKeyringFile = (%v, %v), want an error containing %q", name, kr != nil, err, tc.want)
		}
	}

	// Controls: no fingerprint, a matching fingerprint (also in upper case),
	// spacing around a key, and a key in upper case all load, and are kept in
	// one canonical spelling.
	for name, entries := range map[string][]map[string]string{
		"no fingerprint":               {{"name": "n", "public_key": keyA}},
		"matching fingerprint":         {{"name": "n", "public_key": keyA, "fingerprint": Fingerprint(pubA)}},
		"matching upper-case":          {{"name": "n", "public_key": keyA, "fingerprint": strings.ToUpper(Fingerprint(pubA))}},
		"upper-case and padded key":    {{"name": "n", "public_key": "  " + strings.ToUpper(keyA) + "\r\n"}},
		"no name":                      {{"public_key": keyA}},
		"two different keys, one name": {{"name": "prod", "public_key": keyA}, {"name": "prod", "public_key": keyB}},
	} {
		kr, err := LoadKeyringFile(jsonKeyring(t, entries...))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, signer := range kr.TrustedSigners {
			key, _ := parsePublicKeyHex(signer.PublicKey)
			if signer.PublicKey != hex.EncodeToString(key) || signer.PublicKey != strings.ToLower(signer.PublicKey) || signer.Fingerprint != Fingerprint(key) {
				t.Errorf("%s: entry kept as %+v, want the canonical key and fingerprint", name, signer)
			}
		}
		if len(kr.PublicKeys()) != len(entries) {
			t.Errorf("%s: %d usable keys for %d entries", name, len(kr.PublicKeys()), len(entries))
		}
	}
}

// A rotation keeps a retiring and a new key under one name; each key
// keeps its own attribution, whatever the order of the entries.
func TestKeyringRotationKeepsEachKeysAttribution(t *testing.T) {
	oldPub, _ := newKey(t)
	newPub, _ := newKey(t)
	oldHex, newHex := hex.EncodeToString(oldPub), hex.EncodeToString(newPub)
	for _, entries := range [][]map[string]string{
		{{"name": "prod", "node": "pve1", "public_key": oldHex}, {"name": "prod", "node": "pve2", "public_key": newHex}},
		{{"name": "prod", "node": "pve2", "public_key": newHex}, {"name": "prod", "node": "pve1", "public_key": oldHex}},
	} {
		kr, err := LoadKeyringFile(jsonKeyring(t, entries...))
		if err != nil {
			t.Fatal(err)
		}
		if got := kr.FindSigner(strings.ToUpper(oldHex)); got == nil || got.Node != "pve1" {
			t.Errorf("the retiring key was attributed to %+v", got)
		}
		if got := kr.FindSigner(newHex); got == nil || got.Node != "pve2" {
			t.Errorf("the new key was attributed to %+v", got)
		}
	}
}

// A keyring that lists revoked-then-removed keys works: removing an
// entry removes that key from the trust set, and the last one leaves a set
// that accepts nothing.
func TestKeyringRevocationRemovesTheKey(t *testing.T) {
	pubA, privA := newKey(t)
	pubB, _ := newKey(t)
	dir := t.TempDir()
	both := writeInput(t, dir, "both", []byte(hex.EncodeToString(pubA)+"\n"+hex.EncodeToString(pubB)+"\n"))
	onlyB := writeInput(t, dir, "only-b", []byte(hex.EncodeToString(pubB)+"\n"))
	none := writeInput(t, dir, "none", []byte("# every signer was revoked\n"))
	report := signedReport(t, privA)
	for path, wantValid := range map[string]bool{both: true, onlyB: false, none: false} {
		keys, err := LoadKeyring(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, valid, err := VerifyReport(report, keys); valid != wantValid || (err == nil) != wantValid {
			t.Errorf("%s: VerifyReport = (%v, %v), want valid=%v", filepath.Base(path), valid, err, wantValid)
		}
	}
}

// The legacy list is validated too, and an error names the line of
// the file, not a count of the entries kept.
func TestLegacyKeyringLinesAreValidated(t *testing.T) {
	pubA, _ := newKey(t)
	pubB, _ := newKey(t)
	keyA, keyB := hex.EncodeToString(pubA), hex.EncodeToString(pubB)

	for name, tc := range map[string]struct{ content, want string }{
		"non-hex line":             {"# signers\n" + keyA + "\nzzzz\n", "line 3: its public key is not 64 hexadecimal digits"},
		"short key":                {keyA + "\n" + keyB[:60] + "\n", "line 2: its public key is 30 bytes"},
		"trailing comment":         {keyA + " # prod\n", "line 1: its public key is not 64 hexadecimal digits"},
		"two keys on one line":     {keyA + " " + keyB + "\n", "line 1"},
		"case-variant duplicate":   {keyA + "\n\n" + keyB + "\n" + strings.ToUpper(keyA) + "\n", "line 4: it holds the same public key as line 1"},
		"JSON array by mistake":    {"[\n\"" + keyA + "\"\n]\n", "line 1"},
		"key file of an odd shape": {keyA[:63] + "\n", "line 1"},
	} {
		kr, err := LoadKeyringFile(keyringFixture(t, tc.content))
		if err == nil || kr != nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: LoadKeyringFile = (%v, %v), want an error containing %q", name, kr != nil, err, tc.want)
		}
	}

	// The list keeps loading as it always has, and its entries are named after
	// their line in the file.
	content := "\r\n# trusted signers\r\n" + strings.ToUpper(keyA) + "\r\n\r\n  " + keyB + "  \r\n"
	kr, err := LoadKeyringFile(keyringFixture(t, content))
	if err != nil {
		t.Fatal(err)
	}
	if len(kr.TrustedSigners) != 2 || kr.TrustedSigners[0].Name != "Key-3" || kr.TrustedSigners[1].Name != "Key-5" ||
		kr.TrustedSigners[0].PublicKey != keyA || kr.TrustedSigners[1].Fingerprint != Fingerprint(pubB) {
		t.Errorf("legacy list loaded as %+v", kr.TrustedSigners)
	}
	// keygen --public writes a one-key list; a Windows editor may add a byte-order mark.
	for _, content := range []string{keyA + "\n", string(utf8BOM) + keyA + "\r\n"} {
		if kr, err := LoadKeyringFile(keyringFixture(t, content)); err != nil || len(kr.PublicKeys()) != 1 {
			t.Errorf("one-key list %q: %v", content[:4], err)
		}
	}
}

// JSON keyring structure that would silently change what is trusted
// is refused: a missing list, a repeated member, data after the document. A
// byte-order mark does not make the file read as a list of junk keys.
func TestJSONKeyringStructureIsStrict(t *testing.T) {
	pub, _ := newKey(t)
	entry := `{"name":"n","public_key":"` + hex.EncodeToString(pub) + `"}`
	for name, tc := range map[string]struct{ content, want string }{
		"no trusted_signers":       {`{}`, "no \"trusted_signers\" list"},
		"misspelled list":          {`{"trusted_signer":[` + entry + `]}`, "no \"trusted_signers\" list"},
		"null list":                {`{"trusted_signers":null}`, "no \"trusted_signers\" list"},
		"list of the wrong type":   {`{"trusted_signers":"` + hex.EncodeToString(pub) + `"}`, "invalid JSON keyring"},
		"repeated list":            {`{"trusted_signers":[],"trusted_signers":[` + entry + `]}`, "duplicate JSON object key"},
		"repeated member in entry": {`{"trusted_signers":[{"name":"a","name":"b","public_key":"` + hex.EncodeToString(pub) + `"}]}`, "duplicate JSON object key"},
		"data after the document":  {`{"trusted_signers":[` + entry + `]} {"trusted_signers":[]}`, "invalid JSON keyring"},
		"truncated":                {`{"trusted_signers":[` + entry, "invalid JSON keyring"},
	} {
		kr, err := LoadKeyringFile(keyringFixture(t, tc.content))
		if err == nil || kr != nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: LoadKeyringFile = (%v, %v), want an error containing %q", name, kr != nil, err, tc.want)
		}
	}

	for name, content := range map[string]string{
		"with a byte-order mark":        string(utf8BOM) + `{"trusted_signers":[` + entry + `]}`,
		"with CRLF and indentation":     "{\r\n  \"trusted_signers\": [\r\n    " + entry + "\r\n  ]\r\n}\r\n",
		"with members a newer release":  `{"version":2,"trusted_signers":[{"name":"n","public_key":"` + hex.EncodeToString(pub) + `","status":"active"}],"comment":"x"}`,
		"preceded by whitespace":        "\n\n  " + `{"trusted_signers":[` + entry + `]}`,
		"an explicitly empty list":      `{"trusted_signers":[]}`,
		"an empty file (trusts no one)": ``,
	} {
		kr, err := LoadKeyringFile(keyringFixture(t, content))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		want := 1
		if strings.Contains(name, "empty") {
			want = 0
		}
		if len(kr.PublicKeys()) != want {
			t.Errorf("%s: %d keys, want %d", name, len(kr.PublicKeys()), want)
		}
	}
}

// An error lists a bounded number of faults, and quotes a name from
// the file so it cannot forge lines of the message.
func TestKeyringErrorsAreBoundedAndQuoted(t *testing.T) {
	var entries []map[string]string
	for i := 0; i < 25; i++ {
		entries = append(entries, map[string]string{"name": fmt.Sprintf("bad-%d", i), "public_key": "x"})
	}
	_, err := LoadKeyringFile(jsonKeyring(t, entries...))
	if err == nil || !strings.Contains(err.Error(), "and 15 more") || strings.Contains(err.Error(), "bad-10") {
		t.Errorf("25 faulty entries: %v", err)
	}

	forged := "evil\n  - entry 9: it is fine\x1b[2J" + strings.Repeat("x", 200)
	_, err = LoadKeyringFile(jsonKeyring(t, map[string]string{"name": forged, "public_key": "x"}))
	if err == nil || strings.Contains(err.Error(), "\n  - entry 9") || strings.Contains(err.Error(), "\x1b") || strings.Contains(err.Error(), strings.Repeat("x", 100)) {
		t.Errorf("a name from the file was not quoted and cut: %q", err)
	}
	if lines := strings.Count(err.Error(), "\n"); lines != 1 {
		t.Errorf("the error has %d line breaks, want exactly the one before the entry", lines)
	}
}

// Validate applies the same rules to a keyring built by hand, whose
// PublicKeys would otherwise skip a bad entry silently.
func TestKeyringValidate(t *testing.T) {
	pub, _ := newKey(t)
	keyHex := hex.EncodeToString(pub)
	var nilRing *Keyring
	if err := nilRing.Validate(); err != nil {
		t.Errorf("nil keyring: %v", err)
	}
	if err := (&Keyring{}).Validate(); err != nil {
		t.Errorf("empty keyring: %v", err)
	}
	good := &Keyring{TrustedSigners: []TrustedSigner{{Name: "a", PublicKey: keyHex, Fingerprint: Fingerprint(pub)}}}
	if err := good.Validate(); err != nil {
		t.Errorf("valid keyring: %v", err)
	}
	bad := &Keyring{TrustedSigners: []TrustedSigner{
		{Name: "a", PublicKey: keyHex},
		{Name: "b", PublicKey: "nope"},
		{PublicKey: strings.ToUpper(keyHex)},
	}}
	err := bad.Validate()
	if err == nil || !strings.Contains(err.Error(), `entry 2 ("b")`) || !strings.Contains(err.Error(), "entry 3: it holds the same public key as entry 1") {
		t.Errorf("faulty keyring: %v", err)
	}
	if len(bad.PublicKeys()) != 2 {
		t.Errorf("PublicKeys of the faulty keyring = %d keys, want the two valid entries", len(bad.PublicKeys()))
	}
}

// A keyring made by keygen and a signer added by hand still verify a
// report end to end, with the signer's name shown from the keyring.
func TestKeyringVerifiesReportsOfListedSigners(t *testing.T) {
	pubA, privA := newKey(t)
	pubB, privB := newKey(t)
	_, privC := newKey(t)
	path := jsonKeyring(t,
		map[string]string{"name": "controller-a", "node": "pve1", "public_key": hex.EncodeToString(pubA)},
		map[string]string{"name": "controller-b", "public_key": strings.ToUpper(hex.EncodeToString(pubB)), "fingerprint": Fingerprint(pubB)},
	)
	keys, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, priv := range []ed25519.PrivateKey{privA, privB} {
		if _, valid, err := VerifyReport(signedReport(t, priv), keys); err != nil || !valid {
			t.Errorf("a listed signer's report: valid=%v err=%v", valid, err)
		}
	}
	if _, valid, err := VerifyReport(signedReport(t, privC), keys); err == nil || valid {
		t.Errorf("an unlisted signer's report verified: valid=%v err=%v", valid, err)
	}
}

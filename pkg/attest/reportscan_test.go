// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// generousLimits make scanJSON a pure checker of grammar, repeated names and
// unsignable numbers, for comparing it with the encoding/json based checker it
// replaced.
var generousLimits = &jsonLimits{
	what: "document", maxBytes: 1 << 30, maxDepth: 1 << 20, maxMembers: 1 << 30,
	maxElements: 1 << 30, maxKeyBytes: 1 << 30, maxStringBytes: 1 << 30, maxValues: 1 << 30,
	numbers: true,
}

// scannerAccepts is whether the new pipeline reads a document: the scan, then
// the one decode.
func scannerAccepts(data []byte) bool {
	if scanJSON(data, generousLimits) != nil {
		return false
	}
	_, err := oracleDecode(data)
	return err == nil
}

// A document is read by the scanner exactly when the reference pipeline reads
// it. Accepting what the reference checker refuses would sign or verify a
// report whose duplicate member or rounded integer the signature does not
// cover; refusing what it accepts would orphan a report already signed.
func TestScanJSONAgreesWithTheReferenceChecker(t *testing.T) {
	curated := []string{
		``, ` `, `null`, `true`, `false`, `1`, `"x"`, `[]`, `{}`, `{ }`, `[ ]`, ` {"a":1} `, "\t\r\n{\"a\":1}\n",
		`{"a":1,"b":2}`, `{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `{"a":[{"x":1},{"x":1}]}`, `{"a":[{"x":1,"x":1}]}`,
		`{"a":1,"a":2}`, `{"é":1,"é":2}`, `{"\ud800":1,"�":2}`, "{\"\xff\":1,\"\xfe\":2}", "{\"\xff\":1,\"�\":2}",
		`{"a":1}{"a":2}`, `{"a":1} x`, `{"a":1},`, `{"a":1`, `{"a"`, `{"a":}`, `{"a" 1}`, `{a:1}`, `{"a":1,}`, `[1,]`, `[,1]`, `[1 2]`,
		`{"a":01}`, `{"a":-}`, `{"a":1.}`, `{"a":.5}`, `{"a":1e}`, `{"a":1e+}`, `{"a":+1}`, `{"a":0x10}`, `{"a":-0}`, `{"a":-0.0e-0}`,
		`{"a":9007199254740991}`, `{"a":9007199254740992}`, `{"a":9007199254740993}`, `{"a":-9007199254740993}`, `{"a":9.007199254740993e15}`,
		`{"a":9007199254740992.0}`, `{"a":9007199254740992.5}`, `{"a":1e16}`, `{"a":1E400}`, `{"a":-1e400}`, `{"a":1e-400}`, `{"a":12345678901234567890}`,
		`{"a":123456789012345678901234567890.5}`, `{"a":0.1e1}`, `{"a":1.5E+3}`,
		`{"a":"\q"}`, `{"a":"\u12"}`, `{"a":"\u12G4"}`, `{"a":"\ud800"}`, `{"a":"\udc00\ud800"}`, `{"a":"😀"}`, "{\"a\":\"tab\there\"}", "{\"a\":\"\x01\"}", "{\"a\":\"\x7f\"}",
		"{\"a\":\"\xff\xfe\"}", "{\"a\":\"\xc3\x28\"}", "{\"a\":\"caf\xc3\xa9\"}", `{"a":"\/"}`, `{"a":"\b\f\n\r\t\\\""}`,
		"\xef\xbb\xbf{\"a\":1}", "\xff{\"a\":1}", `{"a":tru}`, `{"a":truee}`, `{"a":nul}`, `{"a":falsey}`, `{"a":True}`, `{"a":NaN}`, `{"a":Infinity}`,
		`[[[[[[[[[[1]]]]]]]]]]`, `[[[[[[[[[[1]]]]]]]]]`, `{"a":{"a":{"a":{"a":1}}}}`, `{"a":[],"b":{},"c":""}`,
		`{"":1,"":2}`, `{"":1}`, `{"a":1,"A":2}`, `{"a":[1,2,{"a":3}],"b":{"a":[{"a":1}]}}`,
		`"just a string"`, `[{"a":1,"a":2}]`, `3.14`, `-`, `--1`, `1 2`, `{"a":1}` + "\x00", "\x00",
	}
	var accepted, refused, compared int
	check := func(label string, data []byte) {
		t.Helper()
		got, want := scannerAccepts(data), oracleAccepts(data)
		if got != want {
			t.Errorf("%s %q: the scanner accepts %v, the reference checker %v (scan: %v)", label, truncateForLog(data), got, want, scanJSON(data, generousLimits))
			return
		}
		if !got {
			refused++
			return
		}
		accepted++
		// What both read must canonicalize to the same bytes, or a report
		// already signed would not verify.
		newCanonical, newErr := CanonicalizeReportJSON(data)
		oldCanonical, oldErr := oracleCanonicalize(data)
		if (newErr == nil) != (oldErr == nil) {
			// The product limits are stricter than the oracle (depth 32 and so
			// on); a difference is only a fault when the document is within them.
			if scanJSON(data, reportLimits) == nil {
				t.Errorf("%s %q: CanonicalizeReportJSON error %v, old pipeline error %v", label, truncateForLog(data), newErr, oldErr)
			}
			return
		}
		if newErr == nil && !bytes.Equal(newCanonical, oldCanonical) {
			t.Errorf("%s %q: canonical form differs\n new %q\n old %q", label, truncateForLog(data), newCanonical, oldCanonical)
		}
		compared++
	}
	for _, doc := range curated {
		check("curated", []byte(doc))
	}

	rng := rand.New(rand.NewSource(20260930))
	var valid [][]byte
	for i := 0; i < 20000; i++ {
		doc := []byte(randomDocument(rng, 0))
		valid = append(valid, doc)
		check("generated", doc)
	}
	// Single-byte damage to documents: deleting, changing or inserting a byte
	// is the usual way a document becomes almost valid.
	for _, doc := range valid[:8000] {
		if len(doc) == 0 {
			continue
		}
		at := rng.Intn(len(doc))
		for _, damaged := range [][]byte{
			append(append([]byte{}, doc[:at]...), doc[at+1:]...),
			append(append(append([]byte{}, doc[:at]...), byte(rng.Intn(256))), doc[at+1:]...),
			append(append(append([]byte{}, doc[:at]...), `,"a":1`...), doc[at:]...),
			append(append(append([]byte{}, doc[:at]...), byte(rng.Intn(256))), doc[at:]...),
		} {
			check("damaged", damaged)
		}
	}
	// A comparison in which one side never answers differently proves nothing.
	t.Logf("%d documents accepted by both, %d refused by both, %d canonical forms compared", accepted, refused, compared)
	if accepted < 500 || refused < 500 || compared < 300 {
		t.Errorf("the comparison is too narrow to mean anything: %d accepted, %d refused, %d compared", accepted, refused, compared)
	}
}

func truncateForLog(data []byte) string {
	if len(data) > 120 {
		return string(data[:120]) + "..."
	}
	return string(data)
}

// randomDocument writes a JSON text from a small grammar that leans on the
// cases the checks care about: repeated and equivalent member names, escapes,
// invalid UTF-8, numbers at the edge of the exact double range, and a few
// faults of grammar.
func randomDocument(rng *rand.Rand, depth int) string {
	keys := []string{`"a"`, `"b"`, `"c"`, `"a"`, `"A"`, `"k1"`, `"k1"`, `"é"`, `"é"`, "\"\xff\"", "\"\xfe\"", `"�"`, `"\ud800"`, `""`, `"x y"`, `"run_id"`}
	numbers := []string{"0", "-0", "1", "-1", "1.5", "2e3", "1E+2", "0.000001", "9007199254740991", "9007199254740992", "9007199254740993", "-9007199254740993", "1e16", "1e400", "123456789012345678901", "01", "1.", "-", ".5", "1e", "0.1e-5"}
	strs := []string{`""`, `"plain"`, `"with \"quote\" and \\ slash"`, `"é€"`, `"😀"`, `"\ud800"`, `"<tag>&amp;"`, `"  "`, "\"caf\xc3\xa9\"", "\"\xc3\x28\"", `"\q"`, "\"\x01\"", `"tab	"`}
	switch pick := rng.Intn(12); {
	case pick < 4 && depth < 6:
		var b strings.Builder
		b.WriteString("{")
		for i, n := 0, rng.Intn(5); i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(keys[rng.Intn(len(keys))])
			b.WriteString(":")
			b.WriteString(randomDocument(rng, depth+1))
		}
		if rng.Intn(40) == 0 {
			b.WriteString(",")
		}
		b.WriteString("}")
		return b.String()
	case pick < 6 && depth < 6:
		var b strings.Builder
		b.WriteString("[")
		for i, n := 0, rng.Intn(5); i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(randomDocument(rng, depth+1))
		}
		b.WriteString("]")
		return b.String()
	case pick < 8:
		return strs[rng.Intn(len(strs))]
	case pick < 10:
		return numbers[rng.Intn(len(numbers))]
	default:
		return []string{"true", "false", "null", "tru", "nul", "True", "{}", "[]"}[rng.Intn(8)]
	}
}

// FuzzScanJSONAgreesWithTheReferenceChecker: for any bytes, the scanner and
// the reference encoding/json pipeline accept the same documents. `go test`
// runs the seeds; `go test -fuzz=FuzzScanJSONAgreesWithTheReferenceChecker`
// explores further.
func FuzzScanJSONAgreesWithTheReferenceChecker(f *testing.F) {
	for _, seed := range []string{
		`{"a":1}`, `{"a":1,"a":2}`, `{"a":1,"a":2}`, `{"a":9007199254740993}`, `[1,2,{"x":[]}]`, `{"a":"\ud800"}`,
		"{\"\xff\":1,\"\xfe\":2}", `{"a":1e400}`, `{"a":tru}`, `{"a":1} `, `null`, `{"a":{"b":{"c":[{"d":1},{"d":2}]}}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if got, want := scannerAccepts(data), oracleAccepts(data); got != want {
			t.Fatalf("%q: the scanner accepts %v, the reference checker %v (scan: %v)", truncateForLog(data), got, want, scanJSON(data, generousLimits))
		}
	})
}

// baseMembers is a signed-report-shaped document as members, for adding the
// shape a test is about.
func baseMembers(t testing.TB) map[string]json.RawMessage {
	t.Helper()
	report := BuildReport(&config.Plan{PlanID: "report-limits", Name: "Report limits"}, "node.example", time.Second, true, nil, "")
	report.ValidationMode = ValidationModeFullIntegrity
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	return members
}

func objectOfMembers(n int) []byte {
	var b bytes.Buffer
	b.WriteString("{")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"k%07d":1`, n-i)
	}
	b.WriteString("}")
	return b.Bytes()
}

func nestedArrays(depth int) []byte {
	return []byte(strings.Repeat("[", depth) + strings.Repeat("]", depth))
}

func arrayOfInts(n int) []byte {
	var b bytes.Buffer
	b.WriteString("[")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("1")
	}
	b.WriteString("]")
	return b.Bytes()
}

// A genuinely signed report has a documented structure and size, and
// one outside it is refused before any of it is decoded. Each document below
// is signed over the canonical form the reference pipeline computes (it is
// valid and the reference verifier accepts it), then checked by the verifier:
// just inside each limit it verifies, one past it it is refused with
// ErrReportLimit, and the refusal costs neither memory nor time in proportion
// to the document.
func TestVerifyReportRefusesOutOfBoundsStructureAfterAValidSignature(t *testing.T) {
	pub, priv := newKey(t)
	trusted := []ed25519.PublicKey{pub}
	withFuture := func(value []byte) map[string]json.RawMessage {
		members := baseMembers(t)
		members["x_future"] = value
		return members
	}
	// depth: the report is level 1, x_future's value starts at level 2.
	insideDepth := nestedArrays(MaxReportDepth - 1)
	overDepth := nestedArrays(MaxReportDepth)
	for name, tc := range map[string]struct {
		inside, over []byte
		what         string
	}{
		"nesting depth":          {insideDepth, overDepth, "nested more than"},
		"members in one object":  {objectOfMembers(MaxReportMembers), objectOfMembers(MaxReportMembers + 1), "more than"},
		"elements in one array":  {arrayOfInts(MaxReportElements), arrayOfInts(MaxReportElements + 1), "more than"},
		"bytes in a member name": {[]byte(`{"` + strings.Repeat("n", MaxReportKeyBytes) + `":1}`), []byte(`{"` + strings.Repeat("n", MaxReportKeyBytes+1) + `":1}`), "longer than"},
	} {
		inside := signWithOracle(t, priv, withFuture(tc.inside))
		if report, valid, err := VerifyReport(inside, trusted); err != nil || !valid || report == nil {
			t.Errorf("%s: a report just inside the limit: valid=%v err=%v", name, valid, err)
		}
		over := signWithOracle(t, priv, withFuture(tc.over))
		if !oracleVerifies(t, over) {
			t.Fatalf("%s: the fixture is not validly signed: the old verifier would not accept it", name)
		}
		var report *Report
		var err error
		allocated := allocatedBy(func() { report, _, err = VerifyReport(over, trusted) })
		if !errors.Is(err, ErrReportLimit) || report != nil || !strings.Contains(err.Error(), tc.what) || !strings.Contains(err.Error(), "x_future") {
			t.Errorf("%s: one past the limit: report=%v err=%v; want ErrReportLimit naming x_future and %q", name, report != nil, err, tc.what)
		}
		if allocated > uint64(len(over))/4+1<<20 {
			t.Errorf("%s: refusing a %d-byte report allocated %d bytes; it must be refused before it is decoded", name, len(over), allocated)
		}
		if _, err := CanonicalizeReportJSON(over); !errors.Is(err, ErrReportLimit) {
			t.Errorf("%s: CanonicalizeReportJSON (which signing uses) = %v, want ErrReportLimit", name, err)
		}
	}
}

// oracleVerifies is whether the reference verifier accepts doc: its signature
// is good over the canonical form the reference pipeline computes, under the key the
// document embeds.
func oracleVerifies(t *testing.T, doc []byte) bool {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(doc, &members); err != nil {
		t.Fatal(err)
	}
	canonical, err := oracleCanonicalize(doc)
	if err != nil {
		return false
	}
	var sigHex, keyHex string
	_ = json.Unmarshal(members["signature"], &sigHex)
	_ = json.Unmarshal(members["public_key"], &keyHex)
	pub, err := parsePublicKeyHex(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyCanonical(canonical, sigHex, pub)
	return err == nil && ok
}

// A quadratic-cost shape. RFC 8785 sorting is quadratic in an object's
// members: 80,000 members would take 13 seconds to verify, a million more
// than nine minutes, from a file far under the file-size limit. A report with
// that many members is refused in milliseconds.
func TestVerifyReportWithManyMembersIsRefusedAtOnce(t *testing.T) {
	pub, _ := newKey(t)
	members := baseMembers(t)
	members["x_future"] = objectOfMembers(80000)
	members["public_key"], _ = json.Marshal(fmt.Sprintf("%x", []byte(pub)))
	members["signature"], _ = json.Marshal(strings.Repeat("00", 64))
	doc, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _, err = VerifyReport(doc, []ed25519.PublicKey{pub})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrReportLimit) {
		t.Fatalf("80,000 members: err = %v, want ErrReportLimit (after %s)", err, elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("refusing 80,000 members took %s", elapsed)
	}
}

// And a report at the member limit verifies in a bounded time, which
// is the point of choosing the limit.
func TestVerifyReportAtTheMemberLimitVerifiesQuickly(t *testing.T) {
	pub, priv := newKey(t)
	members := baseMembers(t)
	// Many such objects: the worst the value limit allows in the member limit.
	var b bytes.Buffer
	b.WriteString("[")
	const objects = 200
	for i := 0; i < objects; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.Write(objectOfMembers(MaxReportMembers))
	}
	b.WriteString("]")
	members["x_future"] = b.Bytes()
	doc := signWithOracle(t, priv, members)
	start := time.Now()
	report, valid, err := VerifyReport(doc, []ed25519.PublicKey{pub})
	elapsed := time.Since(start)
	if err != nil || !valid || report == nil {
		t.Fatalf("%d objects of %d members: valid=%v err=%v", objects, MaxReportMembers, valid, err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("verifying %d objects of %d members took %s", objects, MaxReportMembers, elapsed)
	}
	t.Logf("%d objects of %d members (%d bytes) verified in %s", objects, MaxReportMembers, len(doc), elapsed.Round(time.Millisecond))
}

// A valid signed report with a 16 MiB failure artifact is within the
// documented limits and verifies without tokenizing, decoding and marshalling
// the report three times over (which costs about 38 times the report), under
// verifyAllocationCeiling.
func TestVerifyingALargeReportStaysUnderTheAllocationCeiling(t *testing.T) {
	pub, priv := newKey(t)
	const payloadBytes = 16 << 20
	report := BuildReport(&config.Plan{PlanID: "report-json-resource-boundary", Name: "Report JSON resource boundary"}, "node.example", time.Second, false, nil, strings.Repeat("A", payloadBytes))
	report.FailureReason = "synthetic bounded audit payload"
	if err := report.SignReport(priv); err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	verified, valid, err := VerifyReport(doc, []ed25519.PublicKey{pub})
	runtime.ReadMemStats(&after)
	if err != nil || !valid || len(verified.FailureArtifact) != payloadBytes {
		t.Fatalf("the original report: valid=%v err=%v", valid, err)
	}
	ratio := float64(after.TotalAlloc-before.TotalAlloc) / float64(len(doc))
	t.Logf("verification allocated %.1f times the %d-byte report", ratio, len(doc))
	if ratio > verifyAllocationCeiling {
		t.Fatalf("verification allocated %.1f times the report; the ceiling is %.0f (a decode and a canonicalization pass per check cost 38.2)", ratio, verifyAllocationCeiling)
	}
	runtime.KeepAlive(verified)
}

// verifyAllocationCeiling is the most cumulative allocation, as a multiple of
// the report's size, the verification of a large report may cost.
const verifyAllocationCeiling = 26.0

// Limits that the scanner alone enforces (a document that would be
// expensive to build signed), with the real constants. Each is refused just
// past its limit with ErrReportLimit and accepted at it, and the error says
// where.
func TestScanJSONLimits(t *testing.T) {
	inside := func(doc string) { t.Helper(); mustScan(t, []byte(doc), reportLimits, "") }
	past := func(doc, where, what string) {
		t.Helper()
		mustScan(t, []byte(doc), reportLimits, where+"|"+what)
	}

	// values: the report object, the array x, and 1,271 arrays of 1,649 ints
	// are exactly MaxReportValues values (2 + 1271 * 1650 = 2^21); one more is
	// refused, at the element that is the one too many.
	var doc bytes.Buffer
	doc.WriteString(`{"x":[`)
	for i := 0; i < 1271; i++ {
		if i > 0 {
			doc.WriteString(",")
		}
		doc.Write(arrayOfInts(1649))
	}
	doc.WriteString(`]}`)
	if 2+1271*1650 != MaxReportValues {
		t.Fatalf("the values fixture is built for MaxReportValues = %d", 2+1271*1650)
	}
	mustScan(t, doc.Bytes(), reportLimits, "")
	over := append(append([]byte{}, doc.Bytes()[:doc.Len()-2]...), []byte(`,1]}`)...)
	mustScan(t, over, reportLimits, "values|$.x[1271]")

	inside(`{"a":"` + strings.Repeat("s", 1<<20) + `"}`)
	past(`{"a":{"b":"`+strings.Repeat("s", MaxReportStringBytes+1)+`"}}`, "$.a.b", "a string longer than")
	past(`{"`+strings.Repeat("n", MaxReportKeyBytes+1)+`":1}`, "$", "a member name longer than")
	inside(`{"a":` + string(nestedArrays(MaxReportDepth-1)) + `}`)
	past(`{"a":`+string(nestedArrays(MaxReportDepth))+`}`, "$.a", "nested more than")
	past(string(nestedArrays(MaxReportDepth+1)), "$", "nested more than")

	// bytes: one past the limit, refused before a byte is read.
	big := make([]byte, MaxReportFileBytes+1)
	err := scanJSON(big, reportLimits)
	if !errors.Is(err, ErrReportLimit) || !strings.Contains(err.Error(), fmt.Sprintf("is %d bytes", MaxReportFileBytes+1)) {
		t.Errorf("a document one byte over MaxReportFileBytes: %v", err)
	}
	exact := big[:MaxReportFileBytes]
	if err := scanJSON(exact, reportLimits); errors.Is(err, ErrReportLimit) {
		t.Errorf("a document of exactly MaxReportFileBytes bytes is refused for its size: %v", err)
	}
}

// mustScan checks scanJSON's verdict: want "" is acceptance; otherwise
// "where|what" is an ErrReportLimit naming both.
func mustScan(t *testing.T, doc []byte, limits *jsonLimits, want string) {
	t.Helper()
	err := scanJSON(doc, limits)
	if want == "" {
		if err != nil {
			t.Errorf("%q...: refused: %v", truncateForLog(doc), err)
		}
		return
	}
	where, what, _ := strings.Cut(want, "|")
	if !errors.Is(err, ErrReportLimit) || !strings.Contains(err.Error(), what) || !strings.Contains(err.Error(), where) {
		t.Errorf("%q...: err = %v, want ErrReportLimit with %q at %q", truncateForLog(doc), err, what, where)
	}
}

// Errors name the member path, and a fault of grammar its byte.
func TestScanJSONErrorsSayWhere(t *testing.T) {
	for doc, want := range map[string]string{
		`{"a":{"b":[1,2,{"c":1,"c":2}]}}`:          `duplicate JSON object key "c" at $.a.b[2]`,
		`{"a":{"b":[1,2,{"c":9007199254740993}]}}`: `at $.a.b[2].c`,
		`{"vm_records":[{"x":1},{"y":tru}]}`:       `invalid JSON at byte`,
		`{"a":1} {"a":2}`:                          `unexpected data after the top-level JSON value`,
		`{"a":1,`:                                  `invalid JSON at byte`,
	} {
		err := scanJSON([]byte(doc), reportLimits)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want it to contain %q", doc, err, want)
		}
	}
}

// A document is not scanned past its first fault, and the scan of a
// report allocates nothing for its values: it is what lets an out-of-bounds
// report be refused for free.
func TestScanJSONAllocatesNothingForValues(t *testing.T) {
	doc := []byte(`{"a":[` + strings.Repeat(`{"x":"yyyyyyyy","z":1.5,"n":null,"t":true},`, 50000) + `1]}`)
	if allocated := allocatedBy(func() {
		if err := scanJSON(doc, reportLimits); err != nil {
			t.Error(err)
		}
	}); allocated > 64<<10 {
		t.Errorf("scanning a %d-byte document allocated %d bytes", len(doc), allocated)
	}
}

// The scanner pipeline canonicalizes as the reference one does, for the
// report shapes CertiStack writes (unicode, HTML characters, line separators,
// every kind of number, nested records, an unknown future member), so every
// report already signed verifies.
func TestCanonicalFormIsUnchangedForWrittenReports(t *testing.T) {
	pub, priv := newKey(t)
	records := []probe.VMValidationRecord{{
		VMID: 9001, VerificationStatus: "verified", AllPassed: true,
		ProbeResults: []probe.Result{{Type: "http", Target: "https://10.0.0.1/<a>&b", Description: "café   \U0001f600 ‮", Passed: true, Origin: "worker_host"}},
	}}
	for _, name := range []string{"plain", "café 中文 \U0001f600", "<script>&'\"</script>", "line sep ", "tab\tnew\nline", "\x7f\u0080\u009f", "ends with slash\\"} {
		report := BuildReport(&config.Plan{PlanID: "canon", Name: name, Compliance: config.Compliance{Frameworks: []string{"SOC2", name}, RetentionDays: 2555}}, "node-é.example", 1500*time.Millisecond, true, records, "")
		report.RTOSeconds = 1234.5678e-3
		if err := report.SignReport(priv); err != nil {
			t.Fatal(err)
		}
		for _, indent := range []bool{false, true} {
			var doc []byte
			var err error
			if indent {
				doc, err = json.MarshalIndent(report, "", "  ")
			} else {
				doc, err = json.Marshal(report)
			}
			if err != nil {
				t.Fatal(err)
			}
			newForm, newErr := CanonicalizeReportJSON(doc)
			oldForm, oldErr := oracleCanonicalize(doc)
			if newErr != nil || oldErr != nil || !bytes.Equal(newForm, oldForm) {
				t.Errorf("%q indent=%v: new (%v) and old (%v) canonical forms differ:\n%s\n%s", name, indent, newErr, oldErr, newForm, oldForm)
			}
			if _, valid, err := VerifyReport(doc, []ed25519.PublicKey{pub}); err != nil || !valid {
				t.Errorf("%q indent=%v: a report signed by the old pipeline does not verify: valid=%v err=%v", name, indent, valid, err)
			}
		}
	}
}

// The biggest thing the controller writes verifies. A worker's
// result is bounded at 64 MiB of JSON, and the report holds it: the limits must
// let through what the product itself can produce, here a fleet of failing
// VMs with 0.5 MiB console screenshots (16 MiB in all) in the layout the
// controller writes, signed and saved indented.
func TestReportOfManyFailingVMsSignsSavesAndVerifies(t *testing.T) {
	pub, priv := newKey(t)
	var records []probe.VMValidationRecord
	for i := 0; i < 32; i++ {
		records = append(records, probe.VMValidationRecord{
			VMID: 9000 + i, VerificationStatus: "failed", AllPassed: false,
			FailureArtifact: strings.Repeat("Q", 512<<10),
			ProbeResults:    []probe.Result{{Type: "tcp", Target: "10.0.0.1:443", Description: "port", Passed: false, Origin: "worker_host"}},
		})
	}
	report := BuildReport(&config.Plan{PlanID: "many-failures", Name: "Many failures"}, "node.example", time.Second, false, records, "")
	report.ValidationMode = ValidationModeFullIntegrity
	if err := report.SignReport(priv); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/report.json"
	if err := report.Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := ReadRegularFile(path, "report", MaxReportFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got, valid, err := VerifyReport(data, []ed25519.PublicKey{pub}); err != nil || !valid || len(got.VMRecords) != 32 {
		t.Fatalf("a %d-byte report of 32 failing VMs: valid=%v err=%v", len(data), valid, err)
	}
}

// A report is refused when it is written if the verifier could not read
// it, so nothing the product saves is unverifiable. The saved file is indented,
// so it is larger than the signed bytes.
func TestSaveRefusesAReportTheVerifierCouldNotRead(t *testing.T) {
	_, priv := newKey(t)
	report := BuildReport(&config.Plan{PlanID: "too-big-to-check"}, "node.example", time.Second, true, nil, "")
	if err := report.SignReport(priv); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/report.json"
	if err := report.Save(path); err != nil {
		t.Fatalf("a small report: %v", err)
	}
	indented, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSavableReportSize(MaxReportFileBytes); err != nil {
		t.Errorf("a report of exactly MaxReportFileBytes: %v", err)
	}
	if err := checkSavableReportSize(MaxReportFileBytes + 1); err == nil || !strings.Contains(err.Error(), "verify-report") {
		t.Errorf("a report one byte over: %v", err)
	}
	// Through Save: the limit lowered to the size of this report.
	for limit, wantErr := range map[int]bool{len(indented): false, len(indented) - 1: true} {
		previous := savedReportLimit
		savedReportLimit = limit
		target := t.TempDir() + "/saved.json"
		err := report.Save(target)
		savedReportLimit = previous
		if (err != nil) != wantErr {
			t.Errorf("limit %d for a %d-byte report: err = %v", limit, len(indented), err)
		}
		if _, statErr := os.Stat(target); wantErr == (statErr == nil) {
			t.Errorf("limit %d: the report file exists = %v, want %v", limit, statErr == nil, !wantErr)
		}
	}
}

// And a report the verifier would refuse for its structure is refused
// at signing, where the controller can say so, not after the evidence is kept.
func TestSignReportRefusesWhatTheVerifierWouldRefuse(t *testing.T) {
	_, priv := newKey(t)
	report := BuildReport(&config.Plan{PlanID: "too-big-to-sign"}, "node.example", time.Second, false, nil, strings.Repeat("A", MaxReportStringBytes+1))
	err := report.SignReport(priv)
	if !errors.Is(err, ErrReportLimit) || report.Signature != "" || !strings.Contains(err.Error(), "failure_artifact") {
		t.Fatalf("a failure artifact over MaxReportStringBytes: err = %v, signature %q", err, report.Signature)
	}
}

// The keyring profile has its own, tighter structure limits, checked
// before the keyring is decoded.
func TestKeyringStructureLimits(t *testing.T) {
	pub, _ := newKey(t)
	good := `{"trusted_signers":[{"name":"a","public_key":"` + fmt.Sprintf("%x", []byte(pub)) + `"}]}`
	if err := scanJSON([]byte(good), keyringLimits); err != nil {
		t.Fatalf("an ordinary keyring: %v", err)
	}
	for name, doc := range map[string]string{
		"depth":   `{"trusted_signers":[],"x":` + strings.Repeat("[", keyringLimits.maxDepth) + strings.Repeat("]", keyringLimits.maxDepth) + `}`,
		"members": string(bytes.Replace(objectOfMembers(keyringLimits.maxMembers+1), []byte("{"), []byte(`{"trusted_signers":[],`), 1)),
		"string":  `{"trusted_signers":[],"x":"` + strings.Repeat("s", keyringLimits.maxStringBytes+1) + `"}`,
	} {
		if err := scanJSON([]byte(doc), keyringLimits); err == nil || !strings.Contains(err.Error(), "keyring exceeds a size or structure limit") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A keyring may hold integers a report may not: that is a property of what is signed.
	if err := scanJSON([]byte(`{"trusted_signers":[],"n":9007199254740993}`), keyringLimits); err != nil {
		t.Errorf("a large integer in a keyring: %v", err)
	}
	if err := scanJSON([]byte(`{"trusted_signers":[],"n":9007199254740993}`), reportLimits); err == nil {
		t.Error("a large integer in a report was accepted")
	}
}

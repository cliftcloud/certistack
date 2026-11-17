// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/telemetry"
)

func readRepoText(t *testing.T, parts ...string) string {
	t.Helper()
	data, err := os.ReadFile(repoFile(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// section is the text of the "## heading" section of a Markdown document,
// from its heading line to the next "## " heading. The heading may carry an
// explicit anchor ("## Heading {#anchor}").
func section(t *testing.T, doc, heading string) string {
	t.Helper()
	return headingSection(t, doc, "## ", heading)
}

// headingSection is the text under the heading of this level ("## " or "### ")
// whose text is heading, with or without an explicit {#anchor}, up to the
// next heading of the same or a higher level.
func headingSection(t *testing.T, doc, level, heading string) string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	start := -1
	for i, line := range lines {
		text, ok := strings.CutPrefix(line, level)
		if !ok {
			continue
		}
		text = strings.TrimSpace(attrID.ReplaceAllString(text, ""))
		if text == heading {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no \"%s%s\" section", level, heading)
	}
	depth := len(strings.TrimSpace(level))
	end := len(lines)
	fenced := false
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimLeft(lines[i], " "), "```") {
			fenced = !fenced
			continue
		}
		hashes := len(lines[i]) - len(strings.TrimLeft(lines[i], "#"))
		if !fenced && hashes >= 1 && hashes <= depth && strings.HasPrefix(lines[i][hashes:], " ") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// docs/telemetry.md lists the fields the code sends, no more and no fewer:
// its JSON example is the exact bytes the code encodes, the page says how many
// fields there are, and each field has a line that says what it is. A sixth
// field fails here until the page shows it and says what it is.
func TestTelemetryDocumentHoldsThePayloadToTheStruct(t *testing.T) {
	doc := readRepoText(t, "docs", "telemetry.md")
	fields := section(t, doc, "What is sent")

	var inCode []string
	typ := reflect.TypeOf(telemetry.Payload{})
	for i := 0; i < typ.NumField(); i++ {
		inCode = append(inCode, typ.Field(i).Tag.Get("json"))
	}
	sort.Strings(inCode)

	count := map[int]string{4: "Four", 5: "Five", 6: "Six", 7: "Seven"}[len(inCode)]
	if count == "" || !strings.Contains(fields, count+" fields") {
		t.Errorf("the \"What is sent\" section does not say %q, the number of fields telemetry.Payload has", count+" fields")
	}

	// Each field has a bullet that says what it is.
	bullet := regexp.MustCompile("(?m)^- `([a-z_]+)`: (.+)$")
	var inDoc []string
	for _, m := range bullet.FindAllStringSubmatch(fields, -1) {
		inDoc = append(inDoc, m[1])
		if len(strings.TrimSpace(m[2])) < 10 {
			t.Errorf("the %s line does not say what the field is", m[1])
		}
	}
	sort.Strings(inDoc)
	if !reflect.DeepEqual(inCode, inDoc) {
		t.Errorf("telemetry.Payload has the fields %v and docs/telemetry.md describes %v", inCode, inDoc)
	}

	// The JSON example is what `certistack telemetry show` prints: strictly
	// decodable into the struct, valid in every field, and byte for byte what
	// the code encodes it back to.
	block := regexp.MustCompile("(?s)```json\n(.*?)```").FindStringSubmatch(fields)
	if block == nil {
		t.Fatal("docs/telemetry.md has no ```json example under \"What is sent\"")
	}
	dec := json.NewDecoder(strings.NewReader(block[1]))
	dec.DisallowUnknownFields()
	var example telemetry.Payload
	if err := dec.Decode(&example); err != nil {
		t.Fatalf("the example is not a Payload: %v", err)
	}
	if !bytes.Equal(example.Encode(), []byte(block[1])) {
		t.Errorf("the example is not what the code encodes:\n%s\nwant:\n%s", block[1], example.Encode())
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(example.InstallID) {
		t.Errorf("the example install_id %q is not a UUID v4", example.InstallID)
	}
	if _, err := time.Parse(telemetry.DateLayout, example.LastTestRun); err != nil || example.Version != telemetry.SanitizeVersion(example.Version) {
		t.Errorf("the example last_test_run %q or version %q is not valid", example.LastTestRun, example.Version)
	}
}

// What the page promises is what the constants in pkg/telemetry say.
func TestTelemetryDocumentStatesTheBehaviourTheCodeHas(t *testing.T) {
	doc := strings.Join(strings.Fields(readRepoText(t, "docs", "telemetry.md")), " ")
	for _, want := range []string{
		telemetry.DefaultURL,
		"at most once every 24 hours",
		"45 days",
		"no retry",
		strings.TrimSuffix(strings.TrimSpace(telemetry.QuestionBusiness), " [y/N]"),
		telemetry.VarDoNotTrack, telemetry.VarTelemetry, telemetry.VarBusiness,
		"telemetry.json", "certistack telemetry reset", "certistack telemetry show", "certistack telemetry enable",
		"never from the node",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/telemetry.md does not say %q", want)
		}
	}
	if telemetry.Interval != 24*time.Hour {
		t.Errorf("the code sends at most once every %v, and the page states 24 hours", telemetry.Interval)
	}
	if !strings.HasPrefix(telemetry.DefaultURL, "https://") {
		t.Errorf("the default endpoint %q is not https", telemetry.DefaultURL)
	}
	if !strings.Contains(doc, "at most "+strconv.Itoa(telemetry.MaxVersionLen)+" characters") {
		t.Errorf("docs/telemetry.md does not state the version length the code enforces (at most %d characters)", telemetry.MaxVersionLen)
	}
}

// No document says CertiStack sends no telemetry at all: it sends none unless
// you opt in, and the pages that talk about the network boundary say so and
// point at the page.
func TestNoDocumentClaimsNoTelemetryAtAll(t *testing.T) {
	denial := regexp.MustCompile(`(?i)\bno telemetry\b|sends? no telemetry|never sends? telemetry|(does not|doesn't|will not) (send|collect|gather) (any )?telemetry|without telemetry|telemetry-free`)
	files := [][]string{
		{"SECURITY.md"}, {"README.md"}, {"SUPPORT.md"},
		{"deploy", "appliance", "README.md"}, {"deploy", "controller", "README.md"},
	}
	pages, err := filepath.Glob(repoFile("docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, page := range pages {
		files = append(files, []string{"docs", filepath.Base(page)})
	}
	if len(files) < 15 {
		t.Fatalf("found only %d documents to read", len(files))
	}
	for _, file := range files {
		text := readRepoText(t, file...)
		if m := denial.FindString(text); m != "" {
			t.Errorf("%s says %q: it must say the statistics are off by default and opt-in (docs/telemetry.md)", strings.Join(file, "/"), m)
		}
	}
	for _, file := range [][]string{{"SECURITY.md"}, {"README.md"}, {"docs", "index.md"}, {"docs", "configuration.md"}, {"deploy", "appliance", "README.md"}} {
		text := readRepoText(t, file...)
		if !strings.Contains(text, "telemetry.md") && !strings.Contains(text, "certistack.dev/docs/telemetry/") {
			t.Errorf("%s does not point at docs/telemetry.md", strings.Join(file, "/"))
		}
	}
	for _, file := range [][]string{{"SECURITY.md"}, {"README.md"}, {"docs", "index.md"}} {
		text := strings.ToLower(strings.Join(strings.Fields(readRepoText(t, file...)), " "))
		off := strings.Contains(text, "off by default") || strings.Contains(text, "off unless you opt in")
		if !off || !strings.Contains(text, "opt-in") && !strings.Contains(text, "opt in") {
			t.Errorf("%s does not say the statistics are off by default and opt-in", strings.Join(file, "/"))
		}
	}
}

func TestTelemetryIsInTheNavigationTheConfigurationAndTheCommandReference(t *testing.T) {
	if !strings.Contains(readRepoText(t, "mkdocs.yml"), "telemetry.md") {
		t.Error("mkdocs.yml has no navigation entry for telemetry.md")
	}
	configuration := readRepoText(t, "docs", "configuration.md")
	for _, name := range []string{telemetry.VarDoNotTrack, telemetry.VarTelemetry, telemetry.VarBusiness, telemetry.VarURL, "telemetry.json"} {
		if !strings.Contains(configuration, "`"+name+"`") {
			t.Errorf("docs/configuration.md does not document %s", name)
		}
	}
	command := headingSection(t, configuration, "### ", "telemetry")
	for _, sub := range []string{"status", "show", "enable", "disable", "reset"} {
		if !strings.Contains(command, "`"+sub+"`") {
			t.Errorf("the telemetry section of docs/configuration.md does not name the subcommand %s", sub)
		}
	}
	// The newest release notes mention the opt-in usage statistics.
	changelog := readRepoText(t, "CHANGELOG.md")
	first := strings.Index(changelog, "\n## [0.")
	if first < 0 {
		t.Fatal("CHANGELOG.md has no release section")
	}
	notes := changelog[first+1:]
	if next := strings.Index(notes[3:], "\n## ["); next >= 0 {
		notes = notes[:next+3]
	}
	if !strings.Contains(notes, "usage statistics") || !strings.Contains(notes, "telemetry") {
		t.Error("the newest CHANGELOG.md release does not mention the opt-in usage statistics")
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"bytes"
	"encoding/json"
	"os"
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

// section is the text of the "## heading" section of a Markdown document.
func section(t *testing.T, doc, heading string) string {
	t.Helper()
	start := strings.Index(doc, "\n## "+heading+"\n")
	if start < 0 {
		t.Fatalf("no \"## %s\" section", heading)
	}
	body := doc[start+1:]
	if end := strings.Index(body[3:], "\n## "); end >= 0 {
		body = body[:end+3]
	}
	return body
}

// docs/telemetry.md lists the five fields the code sends, no more and no
// fewer, and its example is the exact bytes the code encodes. A sixth field
// fails here until the page says what it is, why it exists, and shows it.
func TestTelemetryDocumentHoldsThePayloadToTheStruct(t *testing.T) {
	doc := readRepoText(t, "docs", "telemetry.md")
	fields := section(t, doc, "The five fields")

	var inCode []string
	typ := reflect.TypeOf(telemetry.Payload{})
	for i := 0; i < typ.NumField(); i++ {
		inCode = append(inCode, typ.Field(i).Tag.Get("json"))
	}
	sort.Strings(inCode)

	var inDoc []string
	rows := map[string]string{}
	for _, line := range strings.Split(fields, "\n") {
		if cells := strings.Split(line, "|"); len(cells) > 5 && strings.HasPrefix(strings.TrimSpace(cells[1]), "`") && strings.HasSuffix(strings.TrimSpace(cells[1]), "`") {
			name := strings.Trim(strings.TrimSpace(cells[1]), "`")
			inDoc = append(inDoc, name)
			rows[name] = line
			for column, what := range map[int]string{2: "an example", 3: "what it is", 4: "why it exists"} {
				if len(strings.TrimSpace(cells[column])) < 3 {
					t.Errorf("the %s row has no %s", name, what)
				}
			}
		}
	}
	sort.Strings(inDoc)
	if !reflect.DeepEqual(inCode, inDoc) {
		t.Fatalf("telemetry.Payload has the fields %v and docs/telemetry.md documents %v", inCode, inDoc)
	}

	// The JSON example is what `certistack telemetry show` prints: strictly
	// decodable into the struct, valid in every field, and byte for byte what
	// the code encodes it back to.
	block := regexp.MustCompile("(?s)```json\n(.*?)```").FindStringSubmatch(fields)
	if block == nil {
		t.Fatal("docs/telemetry.md has no ```json example under \"The five fields\"")
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
	// Each row's example is the example payload's own value.
	for name, want := range map[string]string{
		"install_id":    example.InstallID,
		"version":       example.Version,
		"cluster_count": strconv.Itoa(example.ClusterCount),
		"last_test_run": example.LastTestRun,
		"business_use":  strconv.FormatBool(example.BusinessUse),
	} {
		if !strings.Contains(rows[name], "`"+want+"`") {
			t.Errorf("the %s row does not show the example value %q", name, want)
		}
	}
}

// What the page promises is what the constants in pkg/telemetry say.
func TestTelemetryDocumentStatesTheBehaviourTheCodeHas(t *testing.T) {
	doc := readRepoText(t, "docs", "telemetry.md")
	for _, want := range []string{
		telemetry.DefaultURL,
		"Content-Type: application/json",
		telemetry.UserAgentPrefix + "<version>",
		"At most once every 24 hours",
		"Within 3 seconds",
		"at most 2 seconds",
		"45 days",
		"no retry",
		"redirect is not",
		"nothing is sent: disabled",
		strings.TrimSpace(telemetry.QuestionShare),
		strings.TrimSpace(telemetry.QuestionBusiness),
		telemetry.VarDoNotTrack, telemetry.VarTelemetry, telemetry.VarBusiness, telemetry.VarURL,
		"telemetry.json", "certistack telemetry reset", "certistack telemetry show", "certistack telemetry enable",
		"never from the PVE node",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/telemetry.md does not say %q", want)
		}
	}
	if telemetry.SendTimeout != 3*time.Second || telemetry.ExitBudget != 2*time.Second || telemetry.Interval != 24*time.Hour {
		t.Errorf("the code's timings (%v, %v, %v) are not the 3 s, 2 s and 24 h the page states", telemetry.SendTimeout, telemetry.ExitBudget, telemetry.Interval)
	}
	if !strings.HasPrefix(telemetry.DefaultURL, "https://") {
		t.Errorf("the default endpoint %q is not https", telemetry.DefaultURL)
	}
	if telemetry.MaxVersionLen != 64 || !strings.Contains(doc, "at most 64 characters") {
		t.Error("the version length the page states is not the one the code enforces")
	}
}

// Nothing in the repository still says CertiStack sends no telemetry at all:
// it sends none unless you opt in, and every place that talks about the
// network boundary says so and points at the page.
func TestNoDocumentStillClaimsNoTelemetryAtAll(t *testing.T) {
	denial := regexp.MustCompile(`(?i)\bno telemetry\b|sends? no telemetry|never sends? telemetry|(does not|doesn't|will not) (send|collect|gather) (any )?telemetry|without telemetry|telemetry-free`)
	for _, file := range [][]string{
		{"SECURITY.md"}, {"README.md"}, {"SUPPORT.md"},
		{"docs", "faq.md"}, {"docs", "manual-setup.md"}, {"docs", "configuration.md"}, {"docs", "index.md"}, {"docs", "quickstart.md"}, {"docs", "editions.md"},
		{"docs", "what-it-changes.md"}, {"docs", "going-further.md"}, {"docs", "architecture.md"},
		{"deploy", "appliance", "README.md"}, {"deploy", "controller", "README.md"},
	} {
		text := readRepoText(t, file...)
		if m := denial.FindString(text); m != "" {
			t.Errorf("%s still says %q: it must say the statistics are off by default and opt-in (docs/telemetry.md)", strings.Join(file, "/"), m)
		}
	}
	for _, file := range [][]string{{"SECURITY.md"}, {"README.md"}, {"docs", "faq.md"}, {"docs", "configuration.md"}, {"deploy", "appliance", "README.md"}} {
		text := readRepoText(t, file...)
		if !strings.Contains(text, "telemetry.md") {
			t.Errorf("%s does not point at docs/telemetry.md", strings.Join(file, "/"))
		}
	}
	for _, file := range [][]string{{"SECURITY.md"}, {"README.md"}, {"docs", "faq.md"}} {
		text := strings.ToLower(readRepoText(t, file...))
		if !strings.Contains(text, "off by default") || !strings.Contains(text, "opt-in") && !strings.Contains(text, "opt in") {
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
	reference := readRepoText(t, "docs", "cli-reference.md")
	if !strings.Contains(reference, "\n## telemetry\n") {
		t.Error("docs/cli-reference.md has no \"## telemetry\" section")
	}
	for _, sub := range []string{"status", "show", "enable", "disable", "reset"} {
		if !strings.Contains(section(t, reference, "telemetry"), "| `"+sub+"` |") {
			t.Errorf("the telemetry section of docs/cli-reference.md does not describe %s", sub)
		}
	}
	// The first release's notes say it: [Unreleased] is empty until the next change.
	changelog := readRepoText(t, "CHANGELOG.md")
	first := strings.Index(changelog, "\n## [0.1.0]")
	if first < 0 {
		t.Fatal("CHANGELOG.md has no [0.1.0] section")
	}
	notes := changelog[first+1:]
	if next := strings.Index(notes[3:], "\n## ["); next >= 0 {
		notes = notes[:next+3]
	}
	if !strings.Contains(notes, "usage statistics") || !strings.Contains(notes, "telemetry") {
		t.Error("CHANGELOG.md [0.1.0] does not mention the opt-in usage statistics")
	}
}

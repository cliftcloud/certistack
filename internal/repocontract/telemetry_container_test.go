// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cliftcloud/certistack/pkg/telemetry"
)

// The controller container has a read-only root and no home directory, and
// CERTISTACK_TELEMETRY=1 keeps its install in telemetry.json so that it reports
// once a day. So the per-user configuration directory is set to a path inside
// the one writable mount, in the Compose file and in the appliance wrapper
// alike, and the statistics' state ends up there.
const containerConfigHome = "/var/lib/certistack/.config"

func TestControllerContainersKeepTheUsageStateInTheirWritableMount(t *testing.T) {
	data, err := os.ReadFile(repoFile("deploy", "controller", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
			Volumes     []string          `yaml:"volumes"`
			ReadOnly    bool              `yaml:"read_only"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	service := doc.Services["controller"]
	if got := service.Environment["XDG_CONFIG_HOME"]; got != containerConfigHome {
		t.Errorf("compose.yaml sets XDG_CONFIG_HOME=%q, want %q", got, containerConfigHome)
	}
	writable := false
	for _, volume := range service.Volumes {
		if parts := strings.Split(volume, ":"); len(parts) == 2 && parts[1] == "/var/lib/certistack" {
			writable = true
		}
	}
	if !writable || !service.ReadOnly {
		t.Errorf("the controller service must keep a read-only root and mount /var/lib/certistack read-write: %v", service.Volumes)
	}

	wrapper := readRepoText(t, "deploy", "appliance", "files", "certistack-controller")
	if !strings.Contains(wrapper, "--env XDG_CONFIG_HOME="+containerConfigHome+" ") || !strings.Contains(wrapper, "--volume /var/lib/certistack:/var/lib/certistack:rw") {
		t.Error("the appliance wrapper does not give the container XDG_CONFIG_HOME inside its read-write /var/lib/certistack mount")
	}
	page := readRepoText(t, "docs", "telemetry.md")
	if !strings.Contains(page, containerConfigHome+"/certistack/telemetry.json") {
		t.Errorf("docs/telemetry.md does not say where the container keeps telemetry.json (%s/certistack/telemetry.json)", containerConfigHome)
	}
}

// In a container as shipped (no home directory, XDG_CONFIG_HOME in the writable
// mount) CERTISTACK_TELEMETRY=1 reports once and keeps the install; with no
// place to keep it the container sends nothing.
func TestContainerEnvironmentOptInReportsOnceADayAndFailsClosedWithoutAPlaceToKeepIt(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	env := map[string]string{telemetry.VarTelemetry: "1", telemetry.VarURL: server.URL + "/api/telemetry"}
	manager := func() *telemetry.Manager {
		return &telemetry.Manager{Version: "x", Getenv: func(k string) string { return env[k] }, Timeout: 2 * time.Second}
	}
	completed := telemetry.Completed{Cluster: "c", TestedAt: time.Now()}

	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if out := manager().AfterRun(context.Background(), completed); out.Sent || requests.Load() != 0 {
		t.Fatalf("a container with no configuration directory sent a report: %+v", out)
	}

	mount := t.TempDir() // stands for /var/lib/certistack
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(mount, ".config"))
	for i := 0; i < 3; i++ {
		manager().AfterRun(context.Background(), completed)
	}
	if requests.Load() != 1 {
		t.Fatalf("%d reports from three runs on one day, want 1", requests.Load())
	}
	if _, err := os.Stat(filepath.Join(mount, ".config", "certistack", "telemetry.json")); err != nil {
		t.Fatalf("the install was not kept in the mount: %v", err)
	}
}

// The environment opt-in keeps an install and reports at most once a day, and
// a cluster is counted by its CA: no page may still say it reports after every
// run, with a new install id, for one process, or counts nodes.
func TestNoDocumentStillDescribesTheOldEnvironmentOptInOrCountsNodes(t *testing.T) {
	stale := regexp.MustCompile(`(?i)after every (completed )?run|this process only|for this process|each time with a new|nothing is stored|nothing records the last send|distinct Proxmox VE nodes|nodes of one cluster count separately|how many.{0,40}nodes`)
	files, err := filepath.Glob(repoFile("docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, repoFile("README.md"), repoFile("CHANGELOG.md"), repoFile("SECURITY.md"),
		repoFile("deploy", "controller", "README.md"), repoFile("deploy", "appliance", "README.md"),
		repoFile("pkg", "telemetry", "payload.go"), repoFile("pkg", "telemetry", "manager.go"), repoFile("pkg", "telemetry", "control.go"),
		repoFile("cmd", "certistack", "cmd_telemetry.go"))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if m := stale.FindString(string(data)); m != "" {
			t.Errorf("%s still says %q", file, m)
		}
	}
	page := readRepoText(t, "docs", "telemetry.md")
	for _, want := range []string{
		"## What counts as a cluster", "CERTISTACK_PVE_CA_SOURCE", "keeps the install", "it sends nothing",
		"At most once every 24 hours", "XDG_CONFIG_HOME",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("docs/telemetry.md does not say %q", want)
		}
	}
}

// The automation page makes the scheduled job's account with no home, so a
// CERTISTACK_TELEMETRY=1 put in its unit, as telemetry.md says, kept nothing
// and sent nothing. The unit gives the account a configuration directory in
// its own StateDirectory (%S/certistack, /var/lib/certistack), beside the
// plans and reports the same account owns and in no file of theirs, and the
// page that tells how to opt a scheduled job in names the file. The fix the
// run prints when the state cannot be written is that same line.
func TestTheScheduledUnitKeepsTheUsageStateWhereItsAccountCanWrite(t *testing.T) {
	const line = "Environment=XDG_CONFIG_HOME=%S/certistack"
	automation := readRepoText(t, "docs", "automation.md")
	start := strings.Index(automation, "certistack-validate@.service >/dev/null <<'EOF'\n")
	if start < 0 {
		t.Fatal("docs/automation.md has no certistack-validate@.service unit")
	}
	unit := automation[start:]
	unit = unit[:strings.Index(unit, "\nEOF\n")]
	for _, want := range []string{"\nUser=certistack\n", "\nStateDirectory=certistack\n", "\n" + line + "\n"} {
		if !strings.Contains(unit, want) {
			t.Errorf("the service unit of docs/automation.md lacks %q:\n%s", strings.TrimSpace(want), unit)
		}
	}
	if !strings.Contains(automation, "useradd --system --no-create-home") {
		t.Error("docs/automation.md no longer makes the account without a home; check that the unit's configuration directory is still needed")
	}
	telemetryPage := readRepoText(t, "docs", "telemetry.md")
	scheduled := section(t, telemetryPage, "Scheduled runs")
	for _, want := range []string{"Environment=CERTISTACK_TELEMETRY=1", line, "/var/lib/certistack/certistack/telemetry.json", "Warning: no usage statistics were sent"} {
		if !strings.Contains(scheduled, want) {
			t.Errorf("docs/telemetry.md, Scheduled runs, does not say %q", want)
		}
	}
	if !strings.Contains(telemetry.UnwritableFix, line) || !strings.Contains(telemetry.UnwritableFix, "docs/telemetry.md#scheduled-runs") {
		t.Errorf("the warning's fix is not the unit's line and the page's section: %q", telemetry.UnwritableFix)
	}

	// The unit's environment: no home, the configuration directory under the
	// state directory, which also holds the plans and the reports.
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	state := filepath.Join(t.TempDir(), "var", "lib", "certistack") // %S/certistack
	for _, dir := range []string{"plans", "reports"} {
		if err := os.MkdirAll(filepath.Join(state, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home", "certistack")) // does not exist
	t.Setenv("XDG_CONFIG_HOME", state)
	env := map[string]string{telemetry.VarTelemetry: "1", telemetry.VarURL: server.URL + "/api/telemetry"}
	for i := 0; i < 2; i++ {
		manager := &telemetry.Manager{Version: "x", Getenv: func(k string) string { return env[k] }, Timeout: 2 * time.Second}
		if out := manager.AfterRun(context.Background(), telemetry.Completed{Cluster: "c", TestedAt: time.Now()}); out.UnwritableWarning() != "" {
			t.Fatalf("run %d: %s", i+1, out.UnwritableWarning())
		}
	}
	if requests.Load() != 1 {
		t.Errorf("%d reports from two runs, want 1", requests.Load())
	}
	if _, err := os.Stat(filepath.Join(state, "certistack", "telemetry.json")); err != nil {
		t.Errorf("the install is not in the unit's configuration directory: %v", err)
	}
	for _, dir := range []string{"plans", "reports"} {
		if entries, err := os.ReadDir(filepath.Join(state, dir)); err != nil || len(entries) != 0 {
			t.Errorf("%s holds %v (%v), want nothing of the statistics", dir, entries, err)
		}
	}
}

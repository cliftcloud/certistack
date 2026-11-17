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
// a cluster is counted by its CA: no document may say it reports after every
// run, with a new install id, for one process, or counts nodes, and the
// telemetry page says how it counts and when it sends nothing.
func TestNoDocumentSaysTheEnvironmentOptInReportsEveryRunOrCountsNodes(t *testing.T) {
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
			t.Errorf("%s says %q", file, m)
		}
	}
	page := strings.Join(strings.Fields(readRepoText(t, "docs", "telemetry.md")), " ")
	for _, want := range []string{
		"clusters", "CERTISTACK_PVE_CA_SOURCE", "at most once every 24 hours", "nothing is sent", "XDG_CONFIG_HOME",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("docs/telemetry.md does not say %q", want)
		}
	}
}

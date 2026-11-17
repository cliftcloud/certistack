// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/spf13/cobra"
)

// versionHost is a node whose PVE reports pveVersion and whose
// proxmox-backup-client prints clientOutput for `version`; the environment
// points doctor, plan and run at it.
//
// It returns what was asked of the node: the paths PVE got and the
// proxmox-backup-client subcommands that ran.
func versionHost(t *testing.T, pveVersion, clientOutput string) (pveRequests, clientCalls func() []string) {
	t.Helper()
	clearControllerEnvironment(t)
	var mu sync.Mutex
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/version") {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"version": pveVersion}})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	bin := t.TempDir()
	calls := filepath.Join(bin, "calls")
	script := "#!/bin/sh\necho \"$1\" >> " + calls + "\ncase \"$1\" in\n  version) printf '%s' '" + clientOutput + "' ;;\n  snapshot) echo '[]' ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(bin, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("PVE_URL", server.URL)
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!doctor")
	t.Setenv("PVE_TOKEN_SECRET", "secret")
	t.Setenv("PBS_REPOSITORY", "certistack@pbs!restore@pbs.lab.example:backup-store")
	t.Setenv("PBS_PASSWORD", "pbs-secret")
	return func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), paths...)
		}, func() []string {
			data, _ := os.ReadFile(calls)
			return strings.Fields(string(data))
		}
}

const (
	clientPBS4 = "client version: 4.2.5\nserver version: 4.2.7\n"
	clientPBS3 = "client version: 3.3.7\nserver version: 3.4.0\n"
)

// runDoctor runs the real doctor, with the real host checks, against the
// environment, and returns what it printed.
func runDoctor(t *testing.T, args ...string) string {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := doctorCmd()
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	if err := cmd.ParseFlags(append([]string{"--scratch", filepath.Join(root, "scratch"), "--state-dir", state}, args...)); err != nil {
		t.Fatal(err)
	}
	_ = cmd.RunE(cmd, nil) // the verdict of the whole host is not this test's concern
	return out.String()
}

var versionLine = regexp.MustCompile(`(?m)^  \[(.)\] version_support\s+: (.*)$`)

// doctor prints the detected versions and the pair's status as a check line
// of its own: a pass for a tested pair, a warning for an untested one or a
// version it could not read, a failure for an unsupported pair; and the same
// in its JSON, beside the members it always had.
func TestDoctorPrintsTheVersionCheck(t *testing.T) {
	for _, tc := range []struct {
		name, pve, client string
		icon              string
		contains          []string
		jsonSupport       string
	}{
		{"tested", "9.1.1", clientPBS4, "✓", []string{"PVE 9.1.1", "PBS 4.2.7", "proxmox-backup-client 4.2.5", "tested"}, "tested"},
		{"untested", "8.3.5", clientPBS3, "!", []string{"PVE 8.3.5", "PBS 3.4.0", "proxmox-backup-client 3.3.7", "untested", "not covered by the release evidence"}, "untested"},
		{"unsupported", "7.4-20", clientPBS4, "✗", []string{"PVE 7.4-20", "PBS 4.2.7", "unsupported", "older than PVE 8"}, "unsupported"},
		{"unreadable", "9.1.1", "no version here\n", "!", []string{"PVE 9.1.1", "PBS unknown", "proxmox-backup-client unknown", "could not be read"}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _ = versionHost(t, tc.pve, tc.client)

			text := runDoctor(t)
			match := versionLine.FindStringSubmatch(text)
			if match == nil {
				t.Fatalf("doctor printed no version_support line:\n%s", text)
			}
			if match[1] != tc.icon {
				t.Errorf("the line is marked %q, want %q: %s", match[1], tc.icon, match[2])
			}
			for _, want := range tc.contains {
				if !strings.Contains(match[2], want) {
					t.Errorf("version_support line %q lacks %q", match[2], want)
				}
			}
			if tc.jsonSupport == "unsupported" && !strings.Contains(text, "Preflight checks FAILED") {
				t.Errorf("an unsupported pair did not fail doctor:\n%s", text)
			}

			var result struct {
				Ready    bool              `json:"ready"`
				Checks   []json.RawMessage `json:"checks"`
				Versions *struct {
					PVE       string `json:"pve"`
					PBS       string `json:"pbs"`
					PBSClient string `json:"pbs_client"`
					Support   string `json:"support"`
					Reason    string `json:"reason"`
				} `json:"versions"`
			}
			if err := json.Unmarshal([]byte(runDoctor(t, "--json")), &result); err != nil {
				t.Fatalf("doctor --json is not JSON: %v", err)
			}
			if result.Versions == nil || result.Versions.Support != tc.jsonSupport || result.Versions.PVE != tc.pve || result.Versions.Reason == "" {
				t.Errorf("doctor --json versions = %+v, want support %q and PVE %q", result.Versions, tc.jsonSupport, tc.pve)
			}
			if tc.jsonSupport == "unsupported" && result.Ready {
				t.Error("doctor --json says an unsupported pair is ready")
			}
			if len(result.Checks) == 0 {
				t.Error("doctor --json lost its checks")
			}
		})
	}
}

// plan and run refuse an unsupported pair in the words doctor fails with, and
// do not refuse anything else.
func TestPlanRefusesWhatDoctorFails(t *testing.T) {
	_, _ = versionHost(t, "7.4-20", clientPBS4)
	var doctorDetail string
	var result struct {
		Checks []preflight.CheckItem `json:"checks"`
	}
	if err := json.Unmarshal([]byte(runDoctor(t, "--json")), &result); err != nil {
		t.Fatal(err)
	}
	for _, check := range result.Checks {
		if check.Name == "version_support" {
			doctorDetail = check.Detail
		}
	}
	if doctorDetail == "" {
		t.Fatal("doctor has no version_support check")
	}

	root := t.TempDir()
	loaded, err := config.LoadFromFile(writeValidationFixture(t, root, "plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	runPlan, err := computePlan(cmd, loaded, "pve1", filepath.Join(root, "scratch"), filepath.Join(root, "state"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(runPlan.Refusals) != 1 || runPlan.Refusals[0] != doctorDetail {
		t.Fatalf("plan refuses with %q, doctor fails with %q; they must say the same", runPlan.Refusals, doctorDetail)
	}
	var printed bytes.Buffer
	writePlan(&printed, runPlan)
	if !strings.Contains(printed.String(), "A run would refuse this plan") || !strings.Contains(printed.String(), "PVE 7.4-20") {
		t.Errorf("plan output does not show the refusal:\n%s", printed.String())
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var completed = func(cluster string, at time.Time) Completed { return Completed{Cluster: cluster, TestedAt: at} }

// The air-gapped promise: unless the user said yes, nothing reaches the
// network and nothing is written.
func TestDefaultAndDeclinedStatesSendZeroRequests(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, h *harness){
		"no state file at all": func(*testing.T, *harness) {},
		"answered false": func(t *testing.T, h *harness) {
			writeRaw(t, h.StatePath, `{"answered": false, "enabled": false}`)
		},
		"enabled true but answered false (inconsistent)": func(t *testing.T, h *harness) {
			writeRaw(t, h.StatePath, `{"answered": false, "enabled": true}`)
		},
		"declined": func(t *testing.T, h *harness) {
			if _, err := h.Disable(); err != nil {
				t.Fatal(err)
			}
		},
		"corrupt state": func(t *testing.T, h *harness) { writeRaw(t, h.StatePath, "{{{ not json") },
		"enabled, DO_NOT_TRACK=1": func(t *testing.T, h *harness) {
			mustEnable(t, h, false)
			h.env[VarDoNotTrack] = "1"
		},
		"enabled, CERTISTACK_TELEMETRY=off": func(t *testing.T, h *harness) {
			mustEnable(t, h, true)
			h.env[VarTelemetry] = "off"
		},
		"enabled, CERTISTACK_TELEMETRY unrecognised": func(t *testing.T, h *harness) {
			mustEnable(t, h, false)
			h.env[VarTelemetry] = "perhaps"
		},
		"CERTISTACK_TELEMETRY=1 but DO_NOT_TRACK=1": func(t *testing.T, h *harness) {
			h.env[VarTelemetry] = "1"
			h.env[VarDoNotTrack] = "1"
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newFakeServer(t, 200)
			h := newHarness(t, srv.URL)
			setup(t, h)
			before, _ := os.ReadFile(h.StatePath)
			out := h.AfterRun(context.Background(), completed("some-cluster", h.now))
			if out.Sent || srv.count() != 0 {
				t.Fatalf("sent=%v, %d requests; want none (%+v)", out.Sent, srv.count(), out)
			}
			after, _ := os.ReadFile(h.StatePath)
			if !bytes.Equal(before, after) {
				t.Errorf("a disabled run changed the state file:\n%s\n-->\n%s", before, after)
			}
		})
	}
}

func TestDisabledRunDoesNotEvenCreateTheStateDirectory(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	h.AfterRun(context.Background(), completed("c", h.now))
	if _, err := os.Stat(filepath.Dir(h.StatePath)); !os.IsNotExist(err) {
		t.Fatalf("the state directory exists after a disabled run: %v", err)
	}
}

func TestEnabledSendsExactlyTheDocumentedRequest(t *testing.T) {
	srv := newFakeServer(t, 204)
	h := newHarness(t, srv.URL)
	st := mustEnable(t, h, true)
	at := time.Date(2026, 10, 1, 23, 30, 0, 0, time.FixedZone("UTC-5", -5*3600)) // 2026-10-02 04:30 UTC

	out := h.AfterRun(context.Background(), completed("pve-lab", at))
	if !out.Sent || out.Err != nil {
		t.Fatalf("outcome = %+v", out)
	}
	if srv.count() != 1 {
		t.Fatalf("%d requests, want exactly 1", srv.count())
	}
	req := srv.last(t)
	if req.Method != "POST" || req.Path != "/api/telemetry" || req.Query != "" {
		t.Errorf("request = %s %s?%s", req.Method, req.Path, req.Query)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := req.Header.Get("User-Agent"); got != "certistack-telemetry/0.1.0-rc3" {
		t.Errorf("User-Agent = %q", got)
	}
	if got := strings.Join(headerNames(req.Header), ","); got != "Connection,Content-Length,Content-Type,User-Agent" {
		t.Errorf("request headers = %s, want only Connection (close), Content-Length, Content-Type and User-Agent", got)
	}
	if got := req.Header.Get("Connection"); got != "close" {
		t.Errorf("Connection = %q", got)
	}

	// The receiver's view: a strict decode into the five fields, then the bytes.
	dec := json.NewDecoder(bytes.NewReader(req.Body))
	dec.DisallowUnknownFields()
	var got Payload
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("strict decode: %v\n%s", err, req.Body)
	}
	want := Payload{InstallID: st.InstallID, Version: "0.1.0-rc3", ClusterCount: 1, LastTestRun: "2026-10-02", BusinessUse: true}
	if got != want {
		t.Errorf("payload = %+v, want %+v", got, want)
	}
	golden := "{\n  \"install_id\": \"" + st.InstallID + "\",\n  \"version\": \"0.1.0-rc3\",\n  \"cluster_count\": 1,\n  \"last_test_run\": \"2026-10-02\",\n  \"business_use\": true\n}\n"
	if string(req.Body) != golden {
		t.Errorf("body:\n%s\nwant:\n%s", req.Body, golden)
	}
}

func TestOnlyTheFiveFieldsAreEverInTheBody(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)
	h.AfterRun(context.Background(), completed("pve-lab", h.now))
	var members map[string]any
	if err := json.Unmarshal(srv.last(t).Body, &members); err != nil {
		t.Fatal(err)
	}
	var names []string
	for k := range members {
		names = append(names, k)
	}
	if got := strings.Join(sorted(names), ","); got != "business_use,cluster_count,install_id,last_test_run,version" {
		t.Fatalf("body members = %s", got)
	}
}

func TestAtMostOneReportEvery24Hours(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)

	if out := h.AfterRun(context.Background(), completed("cluster-a", h.now)); !out.Sent {
		t.Fatalf("first run: %+v", out)
	}
	h.advance(time.Hour)
	out := h.AfterRun(context.Background(), completed("cluster-b", h.now))
	if out.Sent || srv.count() != 1 {
		t.Fatalf("a second run an hour later sent (%v, %d requests)", out.Sent, srv.count())
	}
	// The run was still recorded: the next report counts it.
	if st := h.state(t); len(st.Clusters) != 2 {
		t.Fatalf("clusters after the skipped send = %d, want 2", len(st.Clusters))
	}
	h.advance(22*time.Hour + 59*time.Minute)
	if out := h.AfterRun(context.Background(), completed("cluster-b", h.now)); out.Sent || srv.count() != 1 {
		t.Fatalf("23h59m after the first send it sent again (%d requests)", srv.count())
	}
	h.advance(time.Minute)
	if out := h.AfterRun(context.Background(), completed("cluster-b", h.now)); !out.Sent || srv.count() != 2 {
		t.Fatalf("24h after the first send it did not send (%+v, %d requests)", out, srv.count())
	}
	var back Payload
	if err := json.Unmarshal(srv.last(t).Body, &back); err != nil || back.ClusterCount != 2 {
		t.Fatalf("second report: %+v %v, want cluster_count 2", back, err)
	}
}

func TestClockSetBackDoesNotSilenceTheReportForever(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)
	h.AfterRun(context.Background(), completed("c", h.now))
	h.advance(-30 * 24 * time.Hour) // the stored last_sent is now a month in the future
	if out := h.AfterRun(context.Background(), completed("c", h.now)); !out.Sent {
		t.Fatalf("a last_sent far in the future blocked the report: %+v", out)
	}
}

func TestClusterCountIsDistinctClustersAndLastTestRunIsAUTCDateThatNeverGoesBack(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)
	for _, cluster := range []string{"alpha", "beta", "alpha", "Beta ", "gamma"} {
		h.AfterRun(context.Background(), completed(cluster, h.now))
		h.advance(25 * time.Hour)
	}
	var back Payload
	if err := json.Unmarshal(srv.last(t).Body, &back); err != nil {
		t.Fatal(err)
	}
	if back.ClusterCount != 3 {
		t.Errorf("cluster_count = %d, want 3 (alpha, beta, gamma)", back.ClusterCount)
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(back.LastTestRun) {
		t.Errorf("last_test_run = %q is not a bare date", back.LastTestRun)
	}
	// An older test (a late-arriving report) does not move the date back.
	h.AfterRun(context.Background(), completed("alpha", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)))
	if st := h.state(t); st.LastTestRun != back.LastTestRun {
		t.Errorf("last_test_run went from %s to %s", back.LastTestRun, st.LastTestRun)
	}
}

// CERTISTACK_TELEMETRY=1 stores no answer, but it keeps the install in the
// state file like a stored yes does, so the install is one install and reports
// at most once a day (docs/telemetry.md, "When it is sent").
func TestEnvironmentOnKeepsOneInstallAndReportsOnceADay(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL, VarTelemetry, "yes", VarBusiness, "1")
	out := h.AfterRun(context.Background(), completed("pve-ci", h.now))
	if !out.Sent {
		t.Fatalf("outcome = %+v", out)
	}
	var first Payload
	if err := json.Unmarshal(srv.last(t).Body, &first); err != nil {
		t.Fatal(err)
	}
	if !first.BusinessUse || first.ClusterCount != 1 || !uuid4.MatchString(first.InstallID) {
		t.Errorf("payload = %+v", first)
	}
	// What the opt-in kept: the install and the time of the send, and no answer.
	kept := h.state(t)
	if kept.InstallID != first.InstallID || !kept.HasInstall() || kept.LastSent == "" || len(kept.Clusters) != 1 {
		t.Errorf("state after the first report = %+v", kept)
	}
	if kept.Enabled || kept.Answered {
		t.Errorf("the environment opt-in stored an answer: %+v", kept)
	}
	if info, err := os.Stat(h.StatePath); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Errorf("state file: %v %v, want mode 0600", info, err)
	}
	// It is still not a stored yes: with the environment gone it is off.
	delete(h.env, VarTelemetry)
	if d := h.Resolve().Decision; d.Enabled {
		t.Errorf("the kept install turned the report on without the environment: %+v", d)
	}
	h.env[VarTelemetry] = "yes"

	// A second run in the same hour is recorded and not reported; the next day it is, as the same install.
	h.advance(time.Hour)
	if out := h.AfterRun(context.Background(), completed("pve-ci-2", h.now)); out.Sent || srv.count() != 1 {
		t.Fatalf("a second run an hour later sent (%+v, %d requests)", out, srv.count())
	}
	h.advance(22*time.Hour + 59*time.Minute)
	if out := h.AfterRun(context.Background(), completed("pve-ci", h.now)); out.Sent || srv.count() != 1 {
		t.Fatalf("23h59m after the first send it sent again (%+v, %d requests)", out, srv.count())
	}
	h.advance(time.Minute)
	if out := h.AfterRun(context.Background(), completed("pve-ci", h.now)); !out.Sent || srv.count() != 2 {
		t.Fatalf("24h after the first send it did not send (%+v, %d requests)", out, srv.count())
	}
	var second Payload
	if err := json.Unmarshal(srv.last(t).Body, &second); err != nil {
		t.Fatal(err)
	}
	if second.InstallID != first.InstallID || second.ClusterCount != 2 {
		t.Errorf("second report = %+v, want install %s and 2 clusters", second, first.InstallID)
	}

	// business_use is false unless CERTISTACK_TELEMETRY_BUSINESS says so.
	h.advance(25 * time.Hour)
	h.env[VarBusiness] = ""
	h.AfterRun(context.Background(), completed("pve-ci", h.now))
	var third Payload
	_ = json.Unmarshal(srv.last(t).Body, &third)
	if srv.count() != 3 || third.BusinessUse {
		t.Errorf("%d requests, business_use = %v without CERTISTACK_TELEMETRY_BUSINESS", srv.count(), third.BusinessUse)
	}
}

// Where the install cannot be kept, the environment opt-in sends nothing: the
// report would otherwise go after every run, each time as a new install.
func TestEnvironmentOnFailsClosedWhereTheInstallCannotBeKept(t *testing.T) {
	cases := map[string]func(t *testing.T, h *harness){
		"a state directory that cannot be made": func(t *testing.T, h *harness) {
			// A regular file where the configuration directory should be.
			blocker := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			h.StatePath = filepath.Join(blocker, "certistack", StateFileName)
		},
		"a corrupt state file": func(t *testing.T, h *harness) { writeRaw(t, h.StatePath, "garbage") },
		"a state file that is a directory": func(t *testing.T, h *harness) {
			if err := os.MkdirAll(h.StatePath, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"a read-only state directory": func(t *testing.T, h *harness) {
			if runtime.GOOS == "windows" || os.Geteuid() == 0 {
				t.Skip("directory permissions do not stop this user")
			}
			writeRaw(t, h.StatePath, `{"answered": true, "enabled": false}`)
			dir := filepath.Dir(h.StatePath)
			if err := os.Chmod(dir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newFakeServer(t, 200)
			h := newHarness(t, srv.URL, VarTelemetry, "1")
			setup(t, h)
			before, _ := os.ReadFile(h.StatePath)
			if d := h.Resolve().Decision; d.Enabled || !strings.Contains(d.Reason, "nothing is sent") {
				t.Errorf("decision = %+v; want off, and a reason that says nothing is sent", d)
			}
			out := h.AfterRun(context.Background(), completed("c", h.now))
			if out.Sent || srv.count() != 0 {
				t.Fatalf("sent=%v, %d requests; want none (%+v)", out.Sent, srv.count(), out)
			}
			// A state that cannot be written is said once, at the end of the
			// run; one that cannot be read is said by telemetry status.
			if warning := out.UnwritableWarning(); name == "a read-only state directory" &&
				(!strings.Contains(warning, h.StatePath) || !strings.HasSuffix(warning, UnwritableFix)) ||
				name != "a read-only state directory" && warning != "" {
				t.Errorf("warning = %q", warning)
			}
			if _, body, err := h.Show(); err != nil || body != nil {
				t.Errorf("show = %q, %v; want nothing to show", body, err)
			}
			if after, _ := os.ReadFile(h.StatePath); !bytes.Equal(before, after) {
				t.Errorf("the state file changed:\n%s\n-->\n%s", before, after)
			}
		})
	}
}

// The directory can look writable when the decision is made and not be when
// the install is written: that run sends nothing either.
func TestEnvironmentOnSendsNothingWhenTheInstallCannotBeWritten(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions do not stop this user")
	}
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL, VarTelemetry, "1")
	writeRaw(t, h.StatePath, `{"answered": true, "enabled": false}`)
	dir := filepath.Dir(h.StatePath)
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	between(h, func() { _ = os.Chmod(dir, 0o500) })

	out := h.AfterRun(context.Background(), completed("c", h.now))
	if out.Sent || out.Err == nil || srv.count() != 0 {
		t.Fatalf("outcome = %+v, %d requests; want nothing sent and the reason", out, srv.count())
	}
	if warning := out.UnwritableWarning(); !strings.Contains(warning, "no usage statistics were sent") || !strings.Contains(warning, h.StatePath) {
		t.Errorf("warning = %q; want one that names %s", warning, h.StatePath)
	}
}

// A home that does not exist under a directory the account cannot write (a
// service account): the opt-in sends nothing and the outcome says why, with the file; with no configuration directory at all
// it says that. Nothing else warns: a sent report, a report already sent today,
// or statistics that are off.
func TestEnvironmentOnWithAStateItCannotWriteSaysSo(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions do not stop this user")
	}
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL, VarTelemetry, "1")
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	h.StatePath = filepath.Join(home, "certistack", ".config", "certistack", StateFileName)
	out := h.AfterRun(context.Background(), completed("c", h.now))
	want := "Warning: no usage statistics were sent: they are on, but the state file " + h.StatePath + " could not be written (" + home + " cannot be written (permission denied)). " + UnwritableFix
	if out.Sent || srv.count() != 0 || out.UnwritableWarning() != want {
		t.Errorf("sent %v, %d requests, warning\n%q\nwant\n%q", out.Sent, srv.count(), out.UnwritableWarning(), want)
	}

	h.StatePath = ""
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if warning := h.AfterRun(context.Background(), completed("c", h.now)).UnwritableWarning(); !strings.Contains(warning, "could not be written (no per-user configuration directory") {
		t.Errorf("no configuration directory: %q", warning)
	}

	h.StatePath = filepath.Join(t.TempDir(), "certistack", StateFileName)
	for i := 0; i < 2; i++ { // sent, then already sent today
		if out := h.AfterRun(context.Background(), completed("c", h.now)); out.UnwritableWarning() != "" {
			t.Errorf("run %d: %q", i+1, out.UnwritableWarning())
		}
	}
	h.env[VarTelemetry] = "0"
	if out := h.AfterRun(context.Background(), completed("c", h.now)); out.UnwritableWarning() != "" {
		t.Errorf("off: %q", out.UnwritableWarning())
	}
}

// A kept install is not an answer: a stored no stays a no, and a user who was
// never asked is still asked.
func TestEnvironmentOnKeepsTheAnswerTheFileHeld(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	if _, err := h.Disable(); err != nil { // a stored no
		t.Fatal(err)
	}
	h.env[VarTelemetry] = "1"
	if out := h.AfterRun(context.Background(), completed("c", h.now)); !out.Sent {
		t.Fatalf("outcome = %+v", out)
	}
	if st := h.state(t); !st.Answered || st.Enabled || !st.HasInstall() {
		t.Fatalf("state = %+v; want the no kept and an install beside it", st)
	}
	delete(h.env, VarTelemetry)
	if d := h.Resolve().Decision; d.Enabled || !strings.Contains(d.Reason, "chose not to share") {
		t.Errorf("decision without the environment = %+v", d)
	}

	fresh := newHarness(t, srv.URL, VarTelemetry, "1")
	fresh.AfterRun(context.Background(), completed("c", fresh.now))
	delete(fresh.env, VarTelemetry)
	if !fresh.ShouldPrompt("run", true, true) {
		t.Error("a user who was never asked is not asked after an environment opt-in")
	}
}

// Many controllers finishing at once under the environment opt-in: one install,
// one report.
func TestEnvironmentOnManyRunsAtOnceMakeOneInstallAndSendOnce(t *testing.T) {
	if !stateLockSerializes {
		t.Skip("this platform has no state-file lock: changes to the state are not serialized here")
	}
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL, VarTelemetry, "1")
	const runs = 12
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			concurrentTo(h).AfterRun(context.Background(), completed(fmt.Sprintf("cluster-%d", i), h.now))
		}(i)
	}
	wg.Wait()
	if srv.count() != 1 {
		t.Fatalf("%d reports went; want the one the day allows", srv.count())
	}
	if st := h.state(t); len(st.Clusters) != runs || !st.HasInstall() {
		t.Fatalf("state = %+v; want one install with all %d clusters", st, runs)
	}
}

// Show is what is sent once an install is kept; before that its install id is
// a sample and nothing is written.
func TestEnvironmentOnShowIsExactOnceKeptAndAWriteFreeSampleBefore(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL, VarTelemetry, "1")
	snap, sample, err := h.Show()
	if err != nil || sample == nil || snap.State.HasInstall() {
		t.Fatalf("show before the first report: %v %q %+v", err, sample, snap.State)
	}
	if _, err := os.Stat(filepath.Dir(h.StatePath)); !os.IsNotExist(err) {
		t.Fatalf("show wrote to the state directory: %v", err)
	}
	h.AfterRun(context.Background(), completed("c", h.now))
	_, shown, err := h.Show()
	if err != nil || !bytes.Equal(shown, srv.last(t).Body) {
		t.Fatalf("show:\n%s\nsent:\n%s\n%v", shown, srv.last(t).Body, err)
	}
}

// The commands that change the stored state work on the kept install: enabling
// joins it (one install, counted once), disabling forgets it, reset deletes it,
// and the first-run question keeps it too.
func TestTheKeptInstallIsJoinedForgottenAndDeletedByTheCommands(t *testing.T) {
	srv := newFakeServer(t, 200)
	keep := func() (*harness, State) {
		h := newHarness(t, srv.URL, VarTelemetry, "1")
		h.AfterRun(context.Background(), completed("c", h.now))
		delete(h.env, VarTelemetry)
		return h, h.state(t)
	}

	h, kept := keep()
	joined, err := h.Enable(true)
	if err != nil || joined.InstallID != kept.InstallID || joined.Salt != kept.Salt || len(joined.Clusters) != 1 || !joined.Enabled || !joined.Answered || !joined.BusinessUse {
		t.Fatalf("enable over the kept install: %+v %v; want the same install with the yes", joined, err)
	}

	h, kept = keep()
	if err := h.Record(Answer{Share: true, Business: false}); err != nil {
		t.Fatal(err)
	}
	if st := h.state(t); st.InstallID != kept.InstallID || !st.Enabled || !st.Answered {
		t.Errorf("the first-run yes over the kept install: %+v", st)
	}

	h, kept = keep()
	if forgotten, err := h.Disable(); err != nil || forgotten != kept.InstallID {
		t.Fatalf("disable returned %q %v; want the kept install %q", forgotten, err, kept.InstallID)
	}
	if st := h.state(t); st.HasInstall() || st.Enabled || !st.Answered {
		t.Errorf("state after disable: %+v", st)
	}

	h, kept = keep()
	if reset, err := h.Reset(); err != nil || reset.InstallID != kept.InstallID || !reset.Deleted {
		t.Fatalf("reset returned %+v %v; want the kept install %q", reset, err, kept.InstallID)
	}
	if _, err := os.Stat(h.StatePath); !os.IsNotExist(err) {
		t.Fatalf("reset left the state file: %v", err)
	}
}

// The off switches still win over a kept install, and leave the file as it is.
func TestOffSwitchesWinOverAKeptInstall(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"DO_NOT_TRACK":           {VarDoNotTrack: "1"},
		"CERTISTACK_TELEMETRY=0": {VarTelemetry: "0"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newFakeServer(t, 200)
			h := newHarness(t, srv.URL, VarTelemetry, "1")
			h.AfterRun(context.Background(), completed("c", h.now))
			before, _ := os.ReadFile(h.StatePath)
			h.env = map[string]string{VarURL: srv.URL + "/api/telemetry"}
			for k, v := range env {
				h.env[k] = v
			}
			h.advance(48 * time.Hour)
			if out := h.AfterRun(context.Background(), completed("c", h.now)); out.Sent || srv.count() != 1 {
				t.Fatalf("a run with the report forced off sent (%+v, %d requests)", out, srv.count())
			}
			if after, _ := os.ReadFile(h.StatePath); !bytes.Equal(before, after) {
				t.Error("a forced-off run changed the state file")
			}
		})
	}
}

func TestEnvironmentOnWithAStoredYesUsesTheStoredIdentity(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL, VarTelemetry, "1")
	st := mustEnable(t, h, true)
	h.AfterRun(context.Background(), completed("c", h.now))
	var back Payload
	_ = json.Unmarshal(srv.last(t).Body, &back)
	if back.InstallID != st.InstallID || !back.BusinessUse {
		t.Errorf("payload = %+v, want the stored identity", back)
	}
	if h.state(t).LastSent == "" {
		t.Error("a stored install did not record its send")
	}
}

func TestShowIsByteForByteWhatIsSent(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, true)
	h.AfterRun(context.Background(), completed("alpha", h.now))
	h.advance(time.Minute)

	snap, shown, err := h.Show()
	if err != nil || !snap.Decision.Enabled {
		t.Fatalf("show: %v %+v", err, snap.Decision)
	}
	if !bytes.Equal(shown, srv.last(t).Body) {
		t.Fatalf("show:\n%s\nsent:\n%s", shown, srv.last(t).Body)
	}
	// Before any run there is nothing to date; show says so with an empty string.
	fresh := newHarness(t, srv.URL)
	mustEnable(t, fresh, false)
	if _, body, _ := fresh.Show(); !strings.Contains(string(body), `"last_test_run": ""`) || !strings.Contains(string(body), `"cluster_count": 0`) {
		t.Errorf("show before any run:\n%s", body)
	}
}

func TestShowSaysNothingIsSentWhenDisabled(t *testing.T) {
	h := newHarness(t, "")
	snap, body, err := h.Show()
	if err != nil || body != nil || snap.Decision.Enabled {
		t.Fatalf("show with no state: %v %q %+v", err, body, snap.Decision)
	}
	mustEnable(t, h, false)
	h.env[VarDoNotTrack] = "1"
	snap, body, _ = h.Show()
	if body != nil || !strings.Contains(snap.Decision.Reason, "DO_NOT_TRACK") {
		t.Fatalf("show under DO_NOT_TRACK: %q %+v", body, snap.Decision)
	}
}

// Everything a run knows is seeded with something distinctive; none of it
// appears anywhere in the request: line, URL, headers, body.
func TestNoRunDataAppearsAnywhereInTheRequest(t *testing.T) {
	srv := newFakeServer(t, 200)
	secrets := []string{
		"pve-prod-07.corp.example.net", "10.99.88.77", "payroll-db-vm", "ad-controller-02",
		"tok-AbC123SecretValue", "/srv/secret-plans/dr.yaml", "root@pam!certistack",
		"alice", "WORKSTATION-9XK2", "00:16:3e:aa:bb:cc",
	}
	h := newHarness(t, srv.URL,
		"PVE_URL", "https://10.99.88.77:8006",
		"PVE_TOKEN_ID", "root@pam!certistack",
		"PVE_TOKEN_SECRET", "tok-AbC123SecretValue",
		"CERTISTACK_NODE", "pve-prod-07.corp.example.net",
		"HOSTNAME", "WORKSTATION-9XK2", "USER", "alice",
		"CERTISTACK_PLAN", "/srv/secret-plans/dr.yaml")
	mustEnable(t, h, true)
	out := h.AfterRun(context.Background(), completed("pve-prod-07.corp.example.net", h.now))
	if !out.Sent {
		t.Fatalf("outcome = %+v", out)
	}
	req := srv.last(t)
	lower := strings.ToLower(req.Dump)
	for _, secret := range secrets {
		if strings.Contains(lower, strings.ToLower(secret)) {
			t.Errorf("%q appears in the request:\n%s", secret, req.Dump)
		}
	}
}

func TestClusterHashesAndTheSaltNeverLeaveTheMachine(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	mustEnable(t, h, false)
	for _, c := range []string{"alpha", "beta"} {
		h.AfterRun(context.Background(), completed(c, h.now))
		h.advance(25 * time.Hour)
	}
	st := h.state(t)
	if len(st.Clusters) != 2 || srv.count() != 2 {
		t.Fatalf("setup: %d clusters, %d requests", len(st.Clusters), srv.count())
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, req := range srv.requests {
		for _, secret := range append([]string{st.Salt}, st.Clusters...) {
			if strings.Contains(req.Dump, secret) {
				t.Fatalf("%q is in a request:\n%s", secret, req.Dump)
			}
		}
		for _, short := range []string{st.Clusters[0][:12], st.Clusters[1][:12], st.Salt[:12]} {
			if strings.Contains(req.Dump, short) {
				t.Fatalf("the start of a hash or the salt (%q) is in a request", short)
			}
		}
	}
}

func TestVersionAndUserAgentAreSanitised(t *testing.T) {
	srv := newFakeServer(t, 200)
	h := newHarness(t, srv.URL)
	h.Version = "1.0\r\nX-Evil: 1é"
	mustEnable(t, h, false)
	h.AfterRun(context.Background(), completed("c", h.now))
	req := srv.last(t)
	if req.Header.Get("X-Evil") != "" || req.Header.Get("User-Agent") != "certistack-telemetry/1.0X-Evil: 1" {
		t.Errorf("User-Agent = %q, X-Evil = %q", req.Header.Get("User-Agent"), req.Header.Get("X-Evil"))
	}
	var back Payload
	_ = json.Unmarshal(req.Body, &back)
	if back.Version != "1.0X-Evil: 1" {
		t.Errorf("version = %q", back.Version)
	}
}

func TestEnableKeepsTheInstallDisableForgetsItResetDeletesIt(t *testing.T) {
	h := newHarness(t, "")
	first := mustEnable(t, h, false)
	st := h.state(t)
	_ = st.AddCluster("keep-me")
	if err := WriteState(h.StatePath, st); err != nil {
		t.Fatal(err)
	}
	again, err := h.Enable(true)
	if err != nil || again.InstallID != first.InstallID || len(again.Clusters) != 1 || !again.BusinessUse {
		t.Fatalf("enabling twice: %+v %v", again, err)
	}
	forgotten, err := h.Disable()
	if err != nil || forgotten != first.InstallID {
		t.Fatalf("disable returned %q %v", forgotten, err)
	}
	if st := h.state(t); !st.Answered || st.Enabled || st.InstallID != "" || st.Salt != "" || len(st.Clusters) != 0 {
		t.Fatalf("state after disable = %+v", st)
	}
	fresh, err := h.Enable(false)
	if err != nil || fresh.InstallID == first.InstallID {
		t.Fatalf("a new opt-in reused the old install id: %+v %v", fresh, err)
	}
	reset, err := h.Reset()
	if err != nil || reset.InstallID != fresh.InstallID || !reset.Deleted || reset.Path != h.StatePath {
		t.Fatalf("reset returned %+v %v", reset, err)
	}
	if _, err := os.Stat(h.StatePath); !os.IsNotExist(err) {
		t.Fatalf("reset left the state file: %v", err)
	}
	if reset, err := h.Reset(); err != nil || reset.Deleted || reset.InstallID != "" || reset.Path != h.StatePath {
		t.Fatalf("resetting nothing: %+v %v; want no error, nothing deleted, and the path looked at", reset, err)
	}
}

func TestEnableOverACorruptFileReplacesIt(t *testing.T) {
	h := newHarness(t, "")
	writeRaw(t, h.StatePath, "garbage")
	if _, err := h.Enable(false); err != nil {
		t.Fatal(err)
	}
	if st := h.state(t); !st.Enabled {
		t.Fatalf("state = %+v", st)
	}
}

func TestResolveReasons(t *testing.T) {
	h := newHarness(t, "")
	for _, tc := range []struct {
		setup   func()
		enabled bool
		contain string
	}{
		{func() {}, false, "not been asked"},
		{func() { writeRaw(t, h.StatePath, "x") }, false, "unreadable or inconsistent"},
		{func() { _, _ = h.Disable() }, false, "chose not to share"},
		{func() { _, _ = h.Enable(false) }, true, "you enabled it"},
		{func() { h.env[VarDoNotTrack] = "1" }, false, "DO_NOT_TRACK is set"},
		{func() { delete(h.env, VarDoNotTrack); h.env[VarTelemetry] = "0"; _, _ = h.Enable(false) }, false, "CERTISTACK_TELEMETRY=0"},
		{func() { h.env[VarTelemetry] = "1"; _ = DeleteState(h.StatePath) }, true, "no answer is stored"},
	} {
		tc.setup()
		d := h.Resolve().Decision
		if d.Enabled != tc.enabled || !strings.Contains(d.Reason, tc.contain) {
			t.Errorf("decision = %+v, want enabled=%v and a reason containing %q", d, tc.enabled, tc.contain)
		}
	}
}

// Production is the zero Manager: the process environment, the real clock and
// the per-user configuration directory (XDG on Linux).
func TestZeroManagerReadsTheProcessEnvironmentAndTheUserConfigDirectory(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("the configuration directory is checked on Linux and Windows")
	}
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("AppData", cfg)
	t.Setenv(VarDoNotTrack, "")
	t.Setenv(VarTelemetry, "")
	m := &Manager{Version: "x"}
	if m.Resolve().Decision.Enabled {
		t.Fatal("a fresh configuration directory is enabled")
	}
	if _, err := m.Enable(false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg, "certistack", "telemetry.json")); err != nil {
		t.Fatalf("the state is not in <config dir>/certistack/telemetry.json: %v", err)
	}
	if !m.Resolve().Decision.Enabled {
		t.Fatal("enable did not enable")
	}
	t.Setenv(VarDoNotTrack, "1")
	if m.Resolve().Decision.Enabled {
		t.Fatal("DO_NOT_TRACK in the process environment did not turn it off")
	}
}

func TestNoStateDirectoryMeansOff(t *testing.T) {
	// With neither HOME nor XDG_CONFIG_HOME there is nowhere to keep an answer.
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", "")
	h := newHarness(t, "")
	h.StatePath = ""
	if snap := h.Resolve(); snap.Decision.Enabled {
		t.Fatalf("enabled without a place to keep the answer: %+v", snap.Decision)
	}
}

func writeRaw(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustEnable(t *testing.T, h *harness, business bool) State {
	t.Helper()
	st, err := h.Enable(business)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

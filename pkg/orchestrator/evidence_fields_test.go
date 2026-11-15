// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/cleanup"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/probe/screendump"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// The signed report must say what a probe asserted and the policy it ran
// under. These tests run the real probe stage and the real report builder and
// signer, and assert on the report a run would sign: two runs that differ in
// one such property sign different bytes, and dropping the new fields brings
// back the reporter's collision (the same signed report for both), which shows
// the field is the only difference.

var evidenceKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))

// evidenceReportJSON is the signed report of a plan and one VM record, with
// its identity and time fixed so equal evidence gives equal bytes. It also
// checks that the report verifies.
func evidenceReportJSON(t *testing.T, record probe.VMValidationRecord) []byte {
	t.Helper()
	plan := &config.Plan{PlanID: "evidence-fields", Name: "Evidence fields"}
	report := attest.BuildReport(plan, "node.example", time.Second, true, []probe.VMValidationRecord{record}, "")
	report.ReportID = "00000000-0000-4000-8000-000000000110"
	report.Timestamp = "2026-09-30T00:00:00Z"
	if err := attesttest.SignReport(report, evidenceKey); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid, err := attest.VerifyReportSignatureOnly(data); err != nil || !valid {
		t.Fatalf("the report does not verify: valid=%v err=%v", valid, err)
	}
	return data
}

// stableResult is a result with what varies between runs of the same
// assertion removed: its timing.
func stableResult(result probe.Result) probe.Result {
	result.Duration = 0
	result.Detail = ""
	return result
}

// withoutEvidenceFields is a result as reports of schema 1.5 recorded it.
func withoutEvidenceFields(result probe.Result) probe.Result {
	result.ServerName, result.SourceInterface, result.SourceAddress = "", "", ""
	result.RequireQGA, result.TimeoutSec, result.Retries, result.Attempts = false, 0, 0, 0
	result.ImageSHA256 = ""
	return result
}

func resultRecord(result probe.Result) probe.VMValidationRecord {
	return probe.VMValidationRecord{VMID: 9900, Name: "restore", VerificationStatus: "verified", AllPassed: true, ProbeResults: []probe.Result{result}}
}

// requireDistinctEvidence asserts that the reports of a and b differ, and
// that they would not without the fields the fix added. normalize removes
// what a test's environment puts into a result besides those fields (a socket
// path in a temporary directory, an error that names the source address).
func requireDistinctEvidence(t *testing.T, a, b probe.Result, normalize ...func(*probe.Result)) {
	t.Helper()
	a, b = stableResult(a), stableResult(b)
	for _, apply := range normalize {
		apply(&a)
		apply(&b)
	}
	if bytes.Equal(evidenceReportJSON(t, resultRecord(a)), evidenceReportJSON(t, resultRecord(b))) {
		t.Fatalf("the signed reports of %+v and %+v are byte-identical", a, b)
	}
	if !bytes.Equal(evidenceReportJSON(t, resultRecord(withoutEvidenceFields(a))), evidenceReportJSON(t, resultRecord(withoutEvidenceFields(b)))) {
		t.Fatalf("results differ in more than the recorded evidence fields: %+v vs %+v", withoutEvidenceFields(a), withoutEvidenceFields(b))
	}
}

// Every setting CreateVM requests that shapes the guest is recorded
// in the signed restored_hardware, the CPU weight included.
func TestRestoredHardwareRecordsEverythingCreateVMRequests(t *testing.T) {
	// Every pve.Hardware field has a RestoredHardware field of the same name
	// and value, so a setting added to the request cannot be left out of the
	// evidence without this test failing.
	hardware := pve.Hardware{}
	value := reflect.ValueOf(&hardware).Elem()
	for i := 0; i < value.NumField(); i++ {
		switch field := value.Field(i); field.Kind() {
		case reflect.Int:
			field.SetInt(int64(7 + i))
		case reflect.String:
			field.SetString(fmt.Sprintf("value-%d", i))
		case reflect.Bool:
			field.SetBool(true)
		case reflect.Slice:
			if field.Type().Elem().Kind() != reflect.String {
				t.Fatalf("pve.Hardware field %s is a slice of %s, which this test does not fill", value.Type().Field(i).Name, field.Type().Elem().Kind())
			}
			field.Set(reflect.ValueOf([]string{fmt.Sprintf("value-%d", i), fmt.Sprintf("other-%d", i)}))
		default:
			t.Fatalf("pve.Hardware field %s has kind %s, which this test does not fill", value.Type().Field(i).Name, field.Kind())
		}
	}
	record := reflect.ValueOf(*restoredHardware(hardware, true, "scsi0", ""))
	for i := 0; i < value.NumField(); i++ {
		name := value.Type().Field(i).Name
		got := record.FieldByName(name)
		if !got.IsValid() {
			t.Errorf("pve.Hardware.%s is requested from PVE but RestoredHardware has no field for it", name)
			continue
		}
		if !reflect.DeepEqual(got.Interface(), value.Field(i).Interface()) {
			t.Errorf("RestoredHardware.%s = %v, want the requested %v", name, got.Interface(), value.Field(i).Interface())
		}
	}
}

// The reported case. Two VMs that differ only in CPU weight (50 and
// 500) get different create requests, and their signed evidence now differs
// too, carrying exactly the weight that was sent.
func TestDifferentCPUWeightsSignDifferentRestoredHardware(t *testing.T) {
	o := &Orchestrator{plan: &config.Plan{Network: config.Network{VNetID: "csVn01"}}, runID: "run-cpu-weight"}
	recordFor := func(weight int) (probe.VMValidationRecord, map[string]any) {
		vm := config.VM{VMID: 9900, Name: "restore", HardwareOverrides: config.HardwareOverrides{Cores: 4, Sockets: 2, MemoryMB: 8192, BalloonMB: 4096, CPUWeight: weight}}
		// The configuration and the record come from the method bootAndVerifyVM
		// builds them with, so the record is what CreateVM is sent (the
		// request is read back from the configuration it returns).
		record := probe.VMValidationRecord{VMID: 9900, Name: "restore", VerificationStatus: "verified", AllPassed: true}
		cfg := o.sandboxVMWithEvidence(context.Background(), vm, []pve.DiskOverlay{{Slot: "scsi0", Path: "/tmp/delta.qcow2"}}, "scsi0", nil, &record)
		params, err := cfg.CreateParams()
		if err != nil {
			t.Fatal(err)
		}
		return record, params
	}
	low, lowParams := recordFor(50)
	high, highParams := recordFor(500)
	for name, tc := range map[string]struct {
		record probe.VMValidationRecord
		params map[string]any
		want   int
	}{"50": {low, lowParams, 50}, "500": {high, highParams, 500}} {
		if got := tc.record.RestoredHardware.CPUWeight; got != tc.want || tc.params["cpuunits"] != tc.want {
			t.Errorf("weight %s: recorded %d, create request cpuunits %v, want both %d", name, got, tc.params["cpuunits"], tc.want)
		}
	}
	lowJSON, highJSON := evidenceReportJSON(t, low), evidenceReportJSON(t, high)
	if bytes.Equal(lowJSON, highJSON) {
		t.Fatal("VMs created with CPU weights 50 and 500 sign byte-identical reports")
	}
	if !bytes.Contains(lowJSON, []byte(`"cpu_weight":50`)) || !bytes.Contains(highJSON, []byte(`"cpu_weight":500`)) {
		t.Fatalf("the signed reports do not carry the weight: %s", highJSON)
	}
	if again := evidenceReportJSON(t, low); !bytes.Equal(lowJSON, again) {
		t.Fatal("identical hardware does not sign deterministically")
	}
	// A plan that leaves the weight out gets the orchestrator's default, which
	// is what the request sends and so what the evidence records.
	if def, params := recordFor(0); def.RestoredHardware.CPUWeight != 50 || params["cpuunits"] != 50 {
		t.Errorf("default weight recorded %d, sent %v, want 50", def.RestoredHardware.CPUWeight, params["cpuunits"])
	}
}

// probeStageResults runs the real probe stage over probes with the agent and
// socket directory given, and returns the results it would record.
func probeStageResults(t *testing.T, o *Orchestrator, vmid int, probes ...config.Probe) []probe.Result {
	t.Helper()
	results, _, _ := o.runProbes(context.Background(), config.VM{VMID: vmid, Probes: probes})
	if len(results) < len(probes) {
		t.Fatalf("probe stage results = %+v, want one per probe", results)
	}
	// A stage whose every probe was skipped adds a result saying so.
	return results[:len(probes)]
}

// The timeout each probe ran under is in its result, and so are the retry
// policy and the attempts it took.
func TestProbeResultsRecordTheirTimeoutRetriesAndAttempts(t *testing.T) {
	port := acceptingPort(t)
	o := &Orchestrator{}
	tcp := func(timeoutSec, retries int) probe.Result {
		return probeStageResults(t, o, 9910, config.Probe{Type: "tcp", TargetIP: "127.0.0.1", Port: port, Description: "service readiness", TimeoutSec: timeoutSec, Retries: retries})[0]
	}
	short, long := tcp(1, 0), tcp(3, 0)
	if !short.Passed || !long.Passed {
		t.Fatalf("results = %+v and %+v, want both passed", short, long)
	}
	if short.TimeoutSec != 1 || long.TimeoutSec != 3 || short.Attempts != 1 || long.Attempts != 1 || short.Retries != 0 || long.Retries != 0 {
		t.Fatalf("recorded policy = %d s/%d retries/%d attempts and %d s/%d retries/%d attempts, want 1 s and 3 s, no retries, one attempt each",
			short.TimeoutSec, short.Retries, short.Attempts, long.TimeoutSec, long.Retries, long.Attempts)
	}
	requireDistinctEvidence(t, short, long)

	capped := tcp(3, 4)
	if capped.Retries != 4 || capped.TimeoutSec != 3 {
		t.Fatalf("a probe with retries: 4 records %d retries under %d s", capped.Retries, capped.TimeoutSec)
	}
	requireDistinctEvidence(t, long, capped)
}

// flakyQGA is a guest agent whose guest-ping fails the first failures times
// and succeeds afterwards: a service that was not ready on its first checks.
func flakyQGA(t *testing.T, dir string, vmid, failures int) {
	t.Helper()
	var mu sync.Mutex
	pings := 0
	serveUnixSocket(t, filepath.Join(dir, fmt.Sprintf("%d.qga", vmid)), func(conn net.Conn) {
		reader, encoder := bufio.NewReader(conn), json.NewEncoder(conn)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var request struct {
				Execute   string         `json:"execute"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(line, &request); err != nil {
				return
			}
			var reply any
			switch request.Execute {
			case "guest-sync":
				reply = map[string]any{"return": request.Arguments["id"]}
			case "guest-ping":
				mu.Lock()
				pings++
				n := pings
				mu.Unlock()
				if n <= failures {
					reply = map[string]any{"error": map[string]any{"class": "GenericError", "desc": "agent not ready"}}
				} else {
					reply = map[string]any{"return": map[string]any{}}
				}
			default:
				reply = map[string]any{"error": map[string]any{"class": "CommandNotFound", "desc": "unexpected command"}}
			}
			if err := encoder.Encode(reply); err != nil {
				return
			}
		}
	})
}

// The reported case. A probe that passed on its third permitted
// execution and one that passed on its first no longer sign the same result.
func TestAProbePassingOnItsThirdAttemptSignsItsAttempts(t *testing.T) {
	ping := func(vmid, failures, retries int) probe.Result {
		dir := shortSocketDir(t)
		flakyQGA(t, dir, vmid, failures)
		o := &Orchestrator{opts: Options{QGASocketDir: dir}}
		return probeStageResults(t, o, vmid, config.Probe{Type: "qga", Command: "ping", Description: "agent answers", RequireQGA: true, TimeoutSec: 10, Retries: retries})[0]
	}
	retried := ping(9911, 2, 2)
	immediate := ping(9912, 0, 2)
	if !retried.Passed || !immediate.Passed {
		t.Fatalf("results = %+v and %+v, want both passed", retried, immediate)
	}
	if retried.Attempts != 3 || immediate.Attempts != 1 || retried.Retries != 2 || immediate.Retries != 2 {
		t.Fatalf("attempts = %d and %d, retries = %d and %d; want 3 and 1 attempts under retries: 2", retried.Attempts, immediate.Attempts, retried.Retries, immediate.Retries)
	}
	requireDistinctEvidence(t, retried, immediate)
}

// The reported case. A required and an optional QGA check that both
// succeeded sign different results, and an unreachable agent keeps its two
// outcomes (failed when required, skipped when optional), each recording the
// policy that produced it.
func TestQGAResultsRecordWhetherTheProbeWasRequired(t *testing.T) {
	answered := func(vmid int, required bool) probe.Result {
		dir := shortSocketDir(t)
		fakeQGA(t, dir, vmid, map[string]any{"guest-ping": map[string]any{"return": map[string]any{}}}, nil)
		o := &Orchestrator{opts: Options{QGASocketDir: dir}}
		return probeStageResults(t, o, vmid, config.Probe{Type: "qga", Command: "ping", Description: "agent answers", RequireQGA: required, TimeoutSec: 2, Retries: 1})[0]
	}
	required, optional := answered(9913, true), answered(9914, false)
	if !required.Passed || !optional.Passed || required.Skipped || optional.Skipped {
		t.Fatalf("results = %+v and %+v, want both to have run and passed", required, optional)
	}
	if !required.RequireQGA || optional.RequireQGA {
		t.Fatalf("require_qga recorded as %v for the required probe and %v for the optional one", required.RequireQGA, optional.RequireQGA)
	}
	requireDistinctEvidence(t, required, optional)
	if data := evidenceReportJSON(t, resultRecord(required)); !bytes.Contains(data, []byte(`"require_qga":true`)) {
		t.Fatalf("the signed report of a required probe does not say so: %s", data)
	}
	if data := evidenceReportJSON(t, resultRecord(optional)); bytes.Contains(data, []byte("require_qga")) {
		t.Fatalf("the signed report of an optional probe records a requirement: %s", data)
	}

	// Without an agent: required fails and optional skips, and the result
	// still says which policy applied.
	o := &Orchestrator{opts: Options{QGASocketDir: shortSocketDir(t)}}
	missingRequired := probeStageResults(t, o, 9915, config.Probe{Type: "qga", Command: "ping", Description: "agent answers", RequireQGA: true, TimeoutSec: 1})[0]
	missingOptional := probeStageResults(t, o, 9916, config.Probe{Type: "qga", Command: "ping", Description: "agent answers", TimeoutSec: 1})[0]
	if missingRequired.Passed || !missingRequired.RequireQGA || !missingOptional.Skipped || missingOptional.RequireQGA {
		t.Fatalf("unreachable agent: required = %+v, optional = %+v", missingRequired, missingOptional)
	}
	// The alias records the same policy as the canonical type.
	alias := probeStageResults(t, o, 9917, config.Probe{Type: "qga_ping", Description: "agent answers", RequireQGA: true, TimeoutSec: 1})[0]
	if !alias.RequireQGA {
		t.Fatalf("a qga_ping probe with require_qga: true records %+v", alias)
	}
}

// The reported case. A probe of a named virtual host and one of the
// bare address are different assertions, and the report says which was made:
// the Host header the server saw is the name the result records.
func TestHTTPResultsRecordTheAssertedVirtualHost(t *testing.T) {
	var mu sync.Mutex
	var hosts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, _ := net.SplitHostPort(parsed.Host)
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{}
	get := func(serverName string) probe.Result {
		return probeStageResults(t, o, 9918, config.Probe{Type: "http", TargetIP: host, Port: port, Path: "/", ServerName: serverName, ExpectedStatus: 200, TimeoutSec: 2, Description: "vhost check"})[0]
	}
	bare, first, second := get(""), get("app.example.com"), get("other.example.com")
	for _, result := range []probe.Result{bare, first, second} {
		if !result.Passed {
			t.Fatalf("result = %+v, want a pass", result)
		}
	}
	mu.Lock()
	seen := append([]string(nil), hosts...)
	mu.Unlock()
	if len(seen) != 3 || seen[0] != parsed.Host || seen[1] != "app.example.com" || seen[2] != "other.example.com" {
		t.Fatalf("Host headers the server saw = %v", seen)
	}
	if bare.ServerName != "" || first.ServerName != "app.example.com" || second.ServerName != "other.example.com" {
		t.Fatalf("recorded server names = %q, %q, %q", bare.ServerName, first.ServerName, second.ServerName)
	}
	requireDistinctEvidence(t, bare, first)
	requireDistinctEvidence(t, first, second)
}

// The source a wire probe is bound to is in its result. A dial from
// the sandbox's probe address to a worker-host address is refused, so the
// probe fails, and the failed result names the source it was bound to; the
// probers' own tests cover a probe that passed from each source.
func TestWireProbeResultsRecordTheirBoundSource(t *testing.T) {
	probeFrom := func(probeIP string) probe.Result {
		o := &Orchestrator{plan: &config.Plan{Network: config.Network{VNetID: "csVn01", ProbeIP: probeIP}}}
		results, passed, err := o.runProbes(context.Background(), config.VM{VMID: 9919, Probes: []config.Probe{
			{Type: "tcp", TargetIP: "127.0.0.1", Port: 9, Description: "bound probe", TimeoutSec: 1},
		}})
		if passed || err == nil || len(results) != 1 {
			t.Fatalf("passed=%v err=%v results=%+v, want the dial to a worker address refused", passed, err, results)
		}
		return results[0]
	}
	first, second := probeFrom("10.100.0.1"), probeFrom("10.100.0.2")
	if first.SourceInterface != "csVn01" || first.SourceAddress != "10.100.0.1" || second.SourceAddress != "10.100.0.2" {
		t.Fatalf("recorded sources = %s/%s and %s/%s", first.SourceInterface, first.SourceAddress, second.SourceInterface, second.SourceAddress)
	}
	requireDistinctEvidence(t, first, second, func(result *probe.Result) { result.Error = "" })

	// An unbound source (only unit tests run one) records none.
	unbound := probeStageResults(t, &Orchestrator{}, 9920, config.Probe{Type: "tcp", TargetIP: "127.0.0.1", Port: acceptingPort(t), Description: "unbound", TimeoutSec: 1})[0]
	if unbound.SourceInterface != "" || unbound.SourceAddress != "" {
		t.Fatalf("an unbound probe records a source: %+v", unbound)
	}
}

// fakeQMPFrame is a QMP monitor whose screendump writes frame, a P6 PPM.
func fakeQMPFrame(t *testing.T, dir string, vmid int, frame []byte) {
	t.Helper()
	serveUnixSocket(t, filepath.Join(dir, fmt.Sprintf("%d.qmp", vmid)), func(conn net.Conn) {
		reader, encoder := bufio.NewReader(conn), json.NewEncoder(conn)
		if err := encoder.Encode(map[string]any{"QMP": map[string]any{}}); err != nil {
			return
		}
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var command map[string]any
			if err := json.Unmarshal(line, &command); err != nil {
				return
			}
			if command["execute"] == "screendump" {
				arguments, _ := command["arguments"].(map[string]any)
				filename, _ := arguments["filename"].(string)
				if err := os.WriteFile(filename, frame, 0o600); err != nil {
					return
				}
			}
			if err := encoder.Encode(map[string]any{"return": map[string]any{}, "id": command["id"]}); err != nil {
				return
			}
		}
	})
}

func onePixelPPM(value byte) []byte {
	return append([]byte("P6\n1 1\n255\n"), value, value, value)
}

// The reported case. Two console images that differ only in their
// pixels (a black and a white frame) sign different results, each carrying the
// digest of its own image, and neither the image nor a scratch copy of it is
// kept.
func TestScreendumpResultsRecordTheImageDigestAndKeepNoImage(t *testing.T) {
	capture := func(vmid int, frame []byte) (probe.Result, string) {
		dir := shortSocketDir(t)
		fakeQMPFrame(t, dir, vmid, frame)
		scratch := t.TempDir()
		if err := os.Chmod(scratch, 0o700); err != nil {
			t.Fatal(err)
		}
		o := &Orchestrator{opts: Options{QMPSocketDir: dir, ScratchDir: scratch}}
		// A wire probe beside it: a screendump alone never passes the stage.
		results, passed, err := o.runProbes(context.Background(), config.VM{VMID: vmid, Probes: []config.Probe{
			{Type: "screendump", Description: "console", TimeoutSec: 2},
			{Type: "tcp", TargetIP: "127.0.0.1", Port: acceptingPort(t), Description: "service", TimeoutSec: 1},
		}})
		if !passed || err != nil {
			t.Fatalf("passed=%v err=%v results=%+v", passed, err, results)
		}
		left, readErr := os.ReadDir(scratch)
		if readErr != nil {
			t.Fatal(readErr)
		}
		names := make([]string, 0, len(left))
		for _, entry := range left {
			names = append(names, entry.Name())
		}
		return results[0], strings.Join(names, ",")
	}
	black, blackLeft := capture(9921, onePixelPPM(0))
	white, whiteLeft := capture(9922, onePixelPPM(255))
	if blackLeft != "" || whiteLeft != "" {
		t.Fatalf("the probe left files in the scratch directory: %q and %q", blackLeft, whiteLeft)
	}
	if len(black.ImageSHA256) != 64 || len(white.ImageSHA256) != 64 || black.ImageSHA256 == white.ImageSHA256 {
		t.Fatalf("image digests = %q and %q, want two different SHA-256 digests", black.ImageSHA256, white.ImageSHA256)
	}
	if !strings.Contains(black.Detail, "the image is not kept") {
		t.Fatalf("detail = %q, want it to say the image is not kept", black.Detail)
	}
	requireDistinctEvidence(t, black, white, func(result *probe.Result) { result.Target = "qmp" })
	if data := evidenceReportJSON(t, resultRecord(black)); !bytes.Contains(data, []byte(`"image_sha256":"`+black.ImageSHA256+`"`)) {
		t.Fatalf("the signed report does not carry the digest: %s", data)
	}
	// The digest identifies the image: the same frame gives the same digest.
	again, _ := capture(9923, onePixelPPM(0))
	if again.ImageSHA256 != black.ImageSHA256 {
		t.Fatalf("the same frame gave digests %q and %q", black.ImageSHA256, again.ImageSHA256)
	}
}

// A scratch image that cannot be removed when the probe ends is not
// forgotten: teardown is told to remove it and reports the failure.
func TestAScreendumpImageThatCannotBeRemovedNowIsLeftToTeardown(t *testing.T) {
	scratch := t.TempDir()
	stuck := filepath.Join(scratch, "certistack-failure-vm9924-1.png")
	// A non-empty directory cannot be removed by os.Remove.
	if err := os.MkdirAll(filepath.Join(stuck, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{cleanup: cleanup.New()}
	o.discardScreendump(&screendump.Artifact{PNGPath: stuck})
	if _, err := os.Stat(stuck); err != nil {
		t.Fatalf("the stuck path is gone: %v", err)
	}
	if errs := o.cleanup.Unwind(); len(errs) != 1 || !strings.Contains(errs[0].Step, "remove forensic screenshot") || errs[0].Err == nil {
		t.Fatalf("teardown errors = %+v, want the failed removal reported", errs)
	}
	// A file that is there is removed at once, and a path that is gone or
	// never written (a failed PNG write leaves it empty) is not an error.
	file := filepath.Join(scratch, "captured.png")
	if err := os.WriteFile(file, []byte("png"), 0o600); err != nil {
		t.Fatal(err)
	}
	o = &Orchestrator{cleanup: cleanup.New()}
	o.discardScreendump(&screendump.Artifact{PNGPath: file})
	o.discardScreendump(&screendump.Artifact{PNGPath: file})
	o.discardScreendump(&screendump.Artifact{})
	o.discardScreendump(nil)
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("the captured image was kept: %v", err)
	}
	if errs := o.cleanup.Unwind(); len(errs) != 0 {
		t.Fatalf("nothing was registered for teardown, but unwind = %+v", errs)
	}
}

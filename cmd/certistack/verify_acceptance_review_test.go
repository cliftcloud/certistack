// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/preflight"
	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/probe/qga"
	"github.com/cliftcloud/certistack/pkg/probe/synthetic"
	"github.com/cliftcloud/certistack/pkg/runner"
)

// Tests of the acceptance gates: each signs a report, or feeds a plan, that
// the verifier must judge by what it really proves.

func passReport(plan *config.Plan) *attest.Report {
	return fixtureReport(plan, reportFixture{mode: accept.OutcomePass})
}

func verdictReasons(t *testing.T, report *attest.Report, exp accept.Expectations) (bool, string) {
	t.Helper()
	acceptance := accept.Evaluate(report, exp)
	return acceptance.Verdict == accept.Accepted, strings.Join(acceptance.Reasons, "\n")
}

func expectRejected(t *testing.T, name string, report *attest.Report, exp accept.Expectations, want string) {
	t.Helper()
	accepted, reasons := verdictReasons(t, report, exp)
	if accepted {
		t.Errorf("%s: accepted", name)
		return
	}
	if !strings.Contains(reasons, want) {
		t.Errorf("%s: reasons %q do not include %q", name, reasons, want)
	}
}

func expectAccepted(t *testing.T, name string, report *attest.Report, exp accept.Expectations) {
	t.Helper()
	if accepted, reasons := verdictReasons(t, report, exp); !accepted {
		t.Errorf("%s: rejected: %s", name, reasons)
	}
}

// A probe result is matched to the plan's probe by type, description and
// the target the plan states, not only by type and description.
func TestReportAcceptanceComparesProbeTargets(t *testing.T) {
	plan := mustLoadFixturePlan()
	exp := fixtureExpectations(plan, accept.OutcomePass)
	expectAccepted(t, "the plan's own targets", passReport(plan), exp)

	for name, mutate := range map[string]func(*probe.Result){
		"a different tcp address": func(r *probe.Result) { r.Target = "203.0.113.99:22" },
		"a different tcp port":    func(r *probe.Result) { r.Target = "192.0.2.10:9999" },
	} {
		report := passReport(plan)
		mutate(&report.VMRecords[0].ProbeResults[0])
		expectRejected(t, name, report, exp, "targeted")
	}
	report := passReport(plan)
	report.VMRecords[2].ProbeResults[0].Target = "https://192.0.2.30:443/other"
	expectRejected(t, "a different http path", report, exp, `targeted "https://192.0.2.30:443/other"; the plan configures "https://192.0.2.30:443/health"`)
	report = passReport(plan)
	report.VMRecords[2].ProbeResults[1].Target = "https://192.0.2.30:8080/api/v1/status"
	expectRejected(t, "http where the plan says plain http", report, exp, "the plan configures \"http://192.0.2.30:8080/api/v1/status\"")
	report = passReport(plan)
	report.VMRecords[0].ProbeResults[2].Target = "systemctl is-active something-else"
	expectRejected(t, "a different guest command", report, exp, "the plan configures \"systemctl is-active samba-ad-dc\"")

	// Without the plan the target cannot be judged, and the verdict says so
	// through its bindings.
	report = passReport(plan)
	report.VMRecords[0].ProbeResults[0].Target = "203.0.113.99:22"
	expectAccepted(t, "an unbound verdict", report, accept.Expectations{})
}

// The targets the verifier expects are the ones the probers record. Each
// real prober runs against an already-canceled context, which records its
// target and sends nothing, so a change to a prober's target format fails here
// instead of silently rejecting every real report.
func TestExpectedProbeTargetMatchesProbers(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	const timeout = 200 * time.Millisecond
	socket := filepath.Join(t.TempDir(), "absent.qga")

	cases := []config.Probe{
		{Type: "tcp", TargetIP: "192.0.2.10", Port: 389},
		{Type: "tcp", TargetIP: "2001:db8::10", Port: 389},
		{Type: "http", TargetIP: "192.0.2.30", Port: 8080, Path: "/api/v1/status"},
		{Type: "http", TargetIP: "192.0.2.30", Port: 443, TLS: true, Path: "/health"},
		{Type: "http", TargetIP: "192.0.2.30", Port: 80},
		{Type: "http", TargetIP: "192.0.2.30", Port: 80, Path: "health"},
		// A target the client percent-encodes, and an IPv6 address the target
		// brackets: the report records what the prober sent (a genuine report of
		// such a plan must not be refused).
		{Type: "http", TargetIP: "192.0.2.30", Port: 443, TLS: true, Path: "/status page"},
		{Type: "http", TargetIP: "192.0.2.30", Port: 80, Path: "/café/health?a=b c"},
		{Type: "http", TargetIP: "192.0.2.30", Port: 80, Path: "/api/{id}"},
		{Type: "http", TargetIP: "fd00:99::10", Port: 80, Path: "/health"},
		{Type: "dns", TargetIP: "192.0.2.53", Domain: "host.example.test"},
		{Type: "dns", TargetIP: "192.0.2.53", Port: 5353, Transport: " TCP ", Domain: "host.example.test"},
		{Type: "dns", TargetIP: "2001:db8::53", Port: 53, Transport: "udp"},
		{Type: "ldap", TargetIP: "192.0.2.20", BaseDN: "DC=example,DC=test"},
		{Type: "ldap", TargetIP: "192.0.2.20", Port: 636},
		{Type: "ldap", TargetIP: "2001:db8::20", Port: 636},
		{Type: "ldap", TargetIP: "2001:db8::20"},
		{Type: "mssql", TargetIP: "192.0.2.21"},
		{Type: "mssql", TargetIP: "2001:db8::21", Port: 1444},
		{Type: "smb", TargetIP: "192.0.2.22"},
		{Type: "smb", TargetIP: "2001:db8::22", Port: 4455},
		{Type: "qga", Command: "systemctl is-active nginx", ExpectedOutput: "active"},
		{Type: "qga", Command: "ping"},
	}
	for _, configured := range cases {
		configured.Description = "probe " + configured.Type
		var prober probe.Prober
		switch configured.Type {
		case "tcp":
			prober = synthetic.NewTCPProber(configured.TargetIP, configured.Port, timeout, configured.Description)
		case "http":
			prober = synthetic.NewHTTPProber(configured.TargetIP, configured.Port, configured.Path, configured.TLS, configured.InsecureSkipVerify, configured.ExpectedStatus, timeout, configured.Description, configured.ServerName)
		case "dns":
			prober = synthetic.NewDNSProber(configured.TargetIP, configured.Port, configured.Domain, configured.Transport, timeout, configured.Description)
		case "ldap":
			prober = synthetic.NewLDAPProber(configured.TargetIP, configured.Port, configured.BaseDN, timeout, configured.Description)
		case "mssql":
			prober = synthetic.NewMSSQLProber(configured.TargetIP, configured.Port, timeout, configured.Description)
		case "smb":
			prober = synthetic.NewSMBProber(configured.TargetIP, configured.Port, timeout, configured.Description)
		case "qga":
			prober = qga.NewQGAProber(socket, configured.Command, configured.ExpectedOutput, configured.RequireQGA, timeout, configured.Description)
		}
		result := prober.Probe(canceled)
		want, carried := attest.ExpectedProbeTarget(configured)
		if !carried || result.Target != want {
			t.Errorf("%s %+v: the prober recorded target %q; attest.ExpectedProbeTarget = %q (carried %v)", configured.Type, configured, result.Target, want, carried)
		}
		if result.Type != configured.Type {
			t.Errorf("%s: the prober records type %q", configured.Type, result.Type)
		}
	}
	for _, configured := range []config.Probe{{Type: "qmp"}, {Type: "screendump"}} {
		if _, carried := attest.ExpectedProbeTarget(configured); carried {
			t.Errorf("%s records a socket path, not a plan target, but its target is compared", configured.Type)
		}
	}
}

// A report must carry evidence for every disk it claims, and for every
// disk the plan names; no slot twice, and the disk it booted among them.
func TestReportAcceptanceDiskEvidence(t *testing.T) {
	plan := mustLoadFixturePlan()
	exp := fixtureExpectations(plan, accept.OutcomePass)

	duplicate := passReport(plan)
	duplicate.VMRecords[0].SourceDisks = append(duplicate.VMRecords[0].SourceDisks, duplicate.VMRecords[0].SourceDisks[0])
	expectRejected(t, "a slot recorded twice", duplicate, exp, `records disk "scsi0" more than once`)

	booted := passReport(plan)
	booted.VMRecords[0].RestoredHardware = &probe.RestoredHardware{BootDisk: "scsi9"}
	expectRejected(t, "a boot disk with no evidence", booted, exp, `booted disk "scsi9", which has no integrity evidence`)
	booted.VMRecords[0].RestoredHardware.BootDisk = "scsi0"
	expectAccepted(t, "a recorded boot disk", booted, exp)

	// The plan names a second disk, and the report has evidence for one.
	twoDisks := mustLoadFixturePlan()
	vm := &twoDisks.Tiers[0].VMs[0]
	vm.SourcePBS.Drives = append(vm.SourcePBS.Drives, config.SourceDrive{Slot: "scsi1", Archive: "drive-scsi1"})
	missing := passReport(twoDisks)
	expectRejected(t, "a planned disk with no evidence", missing, fixtureExpectations(twoDisks, accept.OutcomePass), `no integrity evidence for disk "scsi1", which the plan restores`)
	missing.VMRecords[0].SourceDisks = append(missing.VMRecords[0].SourceDisks, probe.SourceDiskEvidence{
		Slot: "scsi1", Archive: "drive-scsi1", ManifestReference: "drive-scsi1.img.fidx", IntegrityStatus: "verified", ImageDigest: fixtureDigest(9001, "scsi1"),
	})
	expectAccepted(t, "every planned disk recorded", missing, fixtureExpectations(twoDisks, accept.OutcomePass))

	// Firmware disks are restored beyond the plan's drives, and a plan that
	// takes its disks from the backup's configuration names none.
	firmware := passReport(plan)
	firmware.VMRecords[0].SourceDisks = append(firmware.VMRecords[0].SourceDisks, probe.SourceDiskEvidence{
		Slot: "efidisk0", Archive: "drive-efidisk0", ManifestReference: "drive-efidisk0.img.fidx", IntegrityStatus: "verified", ImageDigest: fixtureDigest(9001, "efidisk0"),
	})
	expectAccepted(t, "a firmware disk beyond the plan's drives", firmware, exp)
	fromBackup := mustLoadFixturePlan()
	for tierIndex := range fromBackup.Tiers {
		for vmIndex := range fromBackup.Tiers[tierIndex].VMs {
			fromBackup.Tiers[tierIndex].VMs[vmIndex].SourcePBS.Drives = nil
			fromBackup.Tiers[tierIndex].VMs[vmIndex].SourcePBS.Drive = ""
		}
	}
	expectAccepted(t, "a plan that names no drives", firmware, fixtureExpectations(fromBackup, accept.OutcomePass))
}

// A VM that only answers QMP or screendump shows that it is powered on, not
// that a service in it works.
func TestReportAcceptanceNeedsAGuestLevelAssertion(t *testing.T) {
	withProbes := func(probes ...config.Probe) *config.Plan {
		plan := mustLoadFixturePlan()
		plan.Tiers[0].VMs[0].Probes = probes
		return plan
	}
	qmpProbe := config.Probe{Type: "qmp", Description: "VM is running"}
	screenProbe := config.Probe{Type: "screendump", Description: "Console screenshot"}
	tcpProbe := config.Probe{Type: "tcp", TargetIP: "192.0.2.10", Port: 389, Description: "LDAP handshake"}
	guestProbe := config.Probe{Type: "qga", Command: "ping", Description: "Guest agent answers"}
	requiredGuest := guestProbe
	requiredGuest.RequireQGA = true

	cases := []struct {
		name     string
		probes   []config.Probe
		skipped  []int
		accepted bool
	}{
		{name: "qmp only", probes: []config.Probe{qmpProbe}},
		{name: "qmp and screendump", probes: []config.Probe{qmpProbe, screenProbe}},
		{name: "qmp and a skipped guest-agent probe", probes: []config.Probe{qmpProbe, guestProbe}, skipped: []int{1}},
		{name: "qmp and a wire probe", probes: []config.Probe{qmpProbe, tcpProbe}, accepted: true},
		{name: "qmp and a guest-agent probe that ran", probes: []config.Probe{qmpProbe, guestProbe}, accepted: true},
		{name: "screendump and a required guest-agent probe", probes: []config.Probe{screenProbe, requiredGuest}, accepted: true},
	}
	for _, test := range cases {
		plan := withProbes(test.probes...)
		report := passReport(plan)
		for _, index := range test.skipped {
			report.VMRecords[0].ProbeResults[index].Skipped = true
		}
		exp := fixtureExpectations(plan, accept.OutcomePass)
		if test.accepted {
			expectAccepted(t, test.name, report, exp)
		} else {
			expectRejected(t, test.name, report, exp, "VM 9001 has no guest-level assertion that ran")
			expectRejected(t, test.name+" (unbound)", report, accept.Expectations{}, "VM 9001 has no guest-level assertion that ran")
		}
	}
}

// A schema this verifier does not know is refused with a way forward,
// not guessed at.
func TestReportAcceptanceSchemaVersions(t *testing.T) {
	plan := mustLoadFixturePlan()
	exp := fixtureExpectations(plan, accept.OutcomePass)
	known := attest.CurrentReportSchemaVersion
	for _, version := range []string{"1.0", "1.4", "1.5", known} {
		report := passReport(plan)
		report.ReportSchemaVersion = version
		expectAccepted(t, "schema "+version, report, exp)
	}
	cases := map[string]string{
		"1.99":   "newer than this verifier understands (1." + strings.TrimPrefix(known, "1.") + "); verify it with CertiStack of the same or a later release",
		"1.5000": "newer than this verifier understands",
		"1.05":   "is not a supported 1.x schema",
		"1.":     "is not a supported 1.x schema",
		"1.5.1":  "is not a supported 1.x schema",
		"1.x":    "is not a supported 1.x schema",
		"2.0":    "is not a supported 1.x schema",
		"":       "is not a supported 1.x schema",
	}
	// The next minor is newer than any this build writes, whatever that is.
	cases[fmt.Sprintf("1.%d", accept.SchemaMinor(known)+1)] = "newer than this verifier understands"
	for version, want := range cases {
		report := passReport(plan)
		report.ReportSchemaVersion = version
		expectRejected(t, "schema "+version, report, exp, want)
	}
}

// The population is (sandbox VM, source VM) pairs. A plan that restores
// one source into two sandbox VMs is valid, and its honest report is accepted;
// a wrong pair, a missing pair and a repeated sandbox VM are not.
func TestReportAcceptanceSameSourceRestoredTwice(t *testing.T) {
	plan := mustLoadFixturePlan()
	plan.Tiers[1].VMs[0].SourceVMID = 100 // VM 9002 restores the same source as VM 9001
	if errs := config.ValidateForWorker(plan); len(errs) != 0 {
		t.Fatalf("a plan restoring one source twice no longer validates (%v); the population rule needs revisiting", errs)
	}
	exp := fixtureExpectations(plan, accept.OutcomePass)
	expectAccepted(t, "an honest report of the same source twice", passReport(plan), exp)
	expectAccepted(t, "an unbound report of the same source twice", passReport(plan), accept.Expectations{})

	wrong := passReport(plan)
	wrong.VMRecords[1].SourceVMID = 200
	expectRejected(t, "the wrong source for the second sandbox VM", wrong, exp, "VM 9002 records source VM 200; the plan restores source VM 100")

	repeated := passReport(plan)
	repeated.VMRecords[2] = repeated.VMRecords[1]
	expectRejected(t, "the second sandbox VM recorded twice", repeated, exp, "VM 9002 is recorded more than once")
	expectRejected(t, "a planned pair missing", repeated, exp, "planned VM 9003")
}

// A guard denial is a capacity denial. The signed failure reason decides;
// any other failure before a restore, or text further into the reason that a
// plan or a guest controls, is not one.
func TestReportAcceptanceDeniedNeedsACapacityDenial(t *testing.T) {
	plan := mustLoadFixturePlan()
	exp := fixtureExpectations(plan, accept.OutcomeDenied)
	denied := func(reason string) *attest.Report {
		return fixtureReport(plan, reportFixture{mode: accept.OutcomeDenied, reason: reason})
	}
	accepted := []string{
		fixtureAdmissionReason,
		"admission control guardrail triggered: admission denied: RAM usage 91.20% exceeds max 5.00%",
		"admission control guardrail triggered: the plan can never be admitted on this node: its sandbox VMs reserve 200 GiB of memory",
		fixturePreflightReason,
		"node preflight failed: memory: the plan can never be admitted on this node: its sandbox VMs reserve 112 GiB of memory (all tiers stay up until teardown), more than this node can ever hold within max_host_ram_percent 80% of its 126 GiB (101 GiB); split the plan into smaller ones or run it on a node with more memory",
		fixtureAdmissionReason + "; recovery time objective exceeded: completed in 12.0s, target was 5.0s",
		"node preflight failed: memory: available RAM 512 MB is below required 4096 MB; scratch_space: scratch directory /var/lib/certistack/scratch has 1.0 GiB free, but 5 GiB is required",
	}
	for _, reason := range accepted {
		expectAccepted(t, reason, denied(reason), exp)
	}
	rejected := []string{
		fixtureSDNFailure,
		"admission control guardrail triggered: failed to read host metrics: failed to read RAM usage: open /proc/meminfo: no such file",
		"admission control guardrail triggered: context canceled",
		"node preflight failed: kvm: open /dev/kvm: no such file or directory; memory: available RAM 512 MB is below required 4096 MB",
		"node preflight failed: scratch_space: scratch directory /var/lib/certistack/scratch has 1.0 GiB free, but 5 GiB is required",
		"node preflight failed: memory: plan schema errors: tier 1 recovery memory reservation overflows",
		"node preflight failed: preflight did not report a specific failed check",
		fixtureSDNFailure + " (" + fixtureAdmissionReason + ")",
		"recovery tier 1 (Single restore) failed: VM 9001 probes: " + fixtureAdmissionReason,
		"validation failed: node preflight failed: memory: available RAM 512 MB is below required 4096 MB",
		" " + fixtureAdmissionReason,
		"",
	}
	for _, reason := range rejected {
		want := "the failure reason is not an admission or preflight capacity denial"
		if reason == "" {
			want = "records no failure reason"
		}
		expectRejected(t, "reason "+reason, denied(reason), exp, want)
	}
}

// The strings accept.CapacityDenial recognizes are the ones the product emits.
// Each is built from the product's own errors, sent through the same failure
// sanitizer the report uses, and the orchestrator's prefix, which lives in a
// string literal, is pinned in its source: a change to any of them fails here
// rather than silently rejecting (or accepting) every guard.
func TestCapacityDenialStringsMatchProduct(t *testing.T) {
	admissionErrors := map[string]error{
		"admission denied":  fmt.Errorf("%w: RAM usage %.2f%% exceeds max %.2f%%", admission.ErrAdmissionDenied, 91.2, 5.0),
		"retries exhausted": admission.ErrMaxRetriesExceeded,
		"never admissible":  fmt.Errorf("%w: its sandbox VMs reserve %s of memory", admission.ErrNeverAdmissible, "200 GiB"),
	}
	for name, cause := range admissionErrors {
		// pkg/orchestrator wraps the admission error exactly like this.
		reason := runner.SafeFailureReason(fmt.Errorf(accept.AdmissionDenialPrefix+"%w", cause))
		if !accept.CapacityDenial(reason) {
			t.Errorf("%s: %q is not recognized as a capacity denial", name, reason)
		}
	}

	source, err := os.ReadFile(filepath.Join("..", "..", "pkg", "orchestrator", "orchestrator.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), `fmt.Errorf("`+accept.AdmissionDenialPrefix+`%w", err)`) {
		t.Errorf("pkg/orchestrator no longer wraps the admission error with %q; update accept.AdmissionDenialPrefix and this test", accept.AdmissionDenialPrefix)
	}

	plan := mustLoadFixturePlan()
	preflightResult := func(detail string) preflight.Result {
		return preflight.Result{Checks: []preflight.CheckItem{{Name: "memory", Status: "failed", Detail: detail}}}
	}
	neverAdmissible := fmt.Errorf("%w: its sandbox VMs reserve 200 GiB of memory", admission.ErrNeverAdmissible).Error()
	for name, detail := range map[string]string{
		"never admissible": neverAdmissible,
		"shortage":         "available RAM 512 MB is below required 4096 MB",
	} {
		result := preflightFailureResult(plan, "node-a", preflightResult(detail), false)
		for field, reason := range map[string]string{"error": result.Error, "report failure_reason": result.Report.FailureReason} {
			if !accept.CapacityDenial(reason) {
				t.Errorf("preflight %s (%s): %q is not recognized as a capacity denial", name, field, reason)
			}
		}
	}
	other := preflightFailureResult(plan, "node-a", preflight.Result{Checks: []preflight.CheckItem{{Name: "kvm", Status: "failed", Detail: "no /dev/kvm"}}}, false)
	if accept.CapacityDenial(other.Report.FailureReason) {
		t.Errorf("a failed kvm check %q is recognized as a capacity denial", other.Report.FailureReason)
	}
}

// Through the command: a guard plan whose run failed on SDN setup verifies,
// but is not a denial. A test-mode report and an
// untrusted signer keep exit status 2, not 1: the report is not trusted
// evidence at all, which is a different problem from a rejected verdict.
func TestVerifyReportExitStatuses(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plan := mustLoadFixturePlan()
	dir := t.TempDir()
	trusted := hex.EncodeToString(public)
	write := func(fixture reportFixture, key ed25519.PrivateKey) string {
		return writeSignedFixture(t, dir, fixtureReport(plan, fixture), key)
	}
	expect := []string{"--expect-plan", fixturePlanPath, "--expect-node", fixtureNode}

	cases := []struct {
		name string
		path string
		args []string
		want int
	}{
		{"accepted", write(reportFixture{mode: accept.OutcomePass}, private), append([]string{"--expect-outcome", "pass"}, expect...), 0},
		{"rejected verdict", write(reportFixture{mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.VMRecords = nil }}, private), expect, exitCodeValidationFailed},
		{"a guard plan that failed on SDN setup", write(reportFixture{mode: accept.OutcomeDenied, reason: fixtureSDNFailure}, private), append([]string{"--expect-outcome", "denied"}, expect...), exitCodeValidationFailed},
		{"a test-mode report without --allow-test-mode", write(reportFixture{mode: accept.OutcomePass, testMode: true}, private), expect, exitCodeInfrastructure},
		{"an untrusted signer", write(reportFixture{mode: accept.OutcomePass}, otherKey), expect, exitCodeInfrastructure},
		{"an unsupported outcome", write(reportFixture{mode: accept.OutcomePass}, private), []string{"--expect-outcome", "passed"}, exitCodeInfrastructure},
	}
	for _, test := range cases {
		args := append([]string{"--format", "json", "--trusted-key", trusted}, test.args...)
		_, err := runVerifyReport(append(args, test.path)...)
		if got := exitCodeForError(err); got != test.want {
			t.Errorf("%s: exit status %d (err %v), want %d", test.name, got, err, test.want)
		}
	}
}

// The fault plan's shapes the verdict must handle: tiers written out of level
// order (the run goes by level), and a same-tier peer that ran clean.
func TestReportAcceptanceFaultPlanShapes(t *testing.T) {
	// Tiers listed level 2 first: the fault target is the first VM as written,
	// VM 9002; level 1's VM 9001 ran before it and passed; level 3 never began.
	reordered := mustLoadFixturePlan()
	reordered.Tiers[0], reordered.Tiers[1] = reordered.Tiers[1], reordered.Tiers[0]
	report := fixtureReport(reordered, reportFixture{mode: accept.OutcomeFault})
	report.VMRecords = []probe.VMValidationRecord{passedRecordFor(reordered, 9001), failedRecord(passedRecordFor(reordered, 9002))}
	expectAccepted(t, "tiers written out of level order", report, fixtureExpectations(reordered, accept.OutcomeFault))

	// A peer VM in the fault target's tier is probed and passes.
	peers := mustLoadFixturePlan()
	peer := peers.Tiers[1].VMs[0]
	peer.VMID, peer.SourceVMID = 9005, 500
	peers.Tiers[0].VMs = append(peers.Tiers[0].VMs, peer)
	peers.Tiers = append(peers.Tiers[:1], peers.Tiers[2:]...)
	report = fixtureReport(peers, reportFixture{mode: accept.OutcomeFault})
	report.VMRecords = []probe.VMValidationRecord{failedRecord(passedRecordFor(peers, 9001)), passedRecordFor(peers, 9005)}
	expectAccepted(t, "a clean same-tier peer", report, fixtureExpectations(peers, accept.OutcomeFault))
	report.VMRecords = report.VMRecords[:1]
	expectRejected(t, "a same-tier peer that never ran", report, fixtureExpectations(peers, accept.OutcomeFault), "planned VM 9005")
}

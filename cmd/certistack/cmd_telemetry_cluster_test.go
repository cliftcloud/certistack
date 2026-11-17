// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/telemetry"
)

// telemetryTestCA is a CA certificate in PEM, distinct for each seed, with the
// SHA-256 of its DER (what the report counts a cluster by, before it is salted).
func telemetryTestCA(t *testing.T, seed byte, isCA bool) (pemData []byte, fingerprint string) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(seed)),
		Subject:               pkix.Name{CommonName: "Proxmox Virtual Environment", Organization: []string{"PVE Cluster Manager CA"}, OrganizationalUnit: []string{"cluster-" + string('a'+rune(seed))}},
		NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), hex.EncodeToString(sum[:])
}

func writeTelemetryTestFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The cluster a run is counted by is the cluster CA the controller pins: every
// node of one cluster shares it and a standalone node has its own. Without a
// usable CA file the node name stands in.
func TestTheReportCountsAClusterByItsCACertificate(t *testing.T) {
	caA, fingerprintA := telemetryTestCA(t, 1, true)
	caB, _ := telemetryTestCA(t, 2, true)
	leaf, _ := telemetryTestCA(t, 3, false)
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("never read, never hashed")})
	pathA := writeTelemetryTestFile(t, "pve-root-ca.pem", caA)
	pathB := writeTelemetryTestFile(t, "other.pem", caB)

	t.Setenv("CERTISTACK_PVE_CA_SOURCE", pathA)
	first := telemetryClusterIdentity("pve-01.example.net")
	if second := telemetryClusterIdentity("pve-02.example.net"); first != second {
		t.Errorf("two nodes of one cluster (one CA file) are two clusters: %q and %q", first, second)
	}
	if strings.Contains(first, "pve-0") || !strings.Contains(first, fingerprintA) {
		t.Errorf("identity %q is not the CA certificate's SHA-256 %s", first, fingerprintA)
	}
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", pathB)
	if other := telemetryClusterIdentity("pve-01.example.net"); other == first {
		t.Error("two clusters (two CA files) have one identity")
	}

	// The same CA in a bundle with a certificate that is not a CA, or beside a
	// key, is still that cluster; the CA is taken, not the first block.
	bundle := writeTelemetryTestFile(t, "bundle.pem", append(append(append([]byte{}, privateKey...), leaf...), caA...))
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", bundle)
	if got := telemetryClusterIdentity("n"); got != first {
		t.Errorf("a bundle's CA identity = %q, want %q", got, first)
	}

	// Nothing usable: the node name.
	for name, source := range map[string]string{
		"no CA source":         "",
		"a missing file":       filepath.Join(t.TempDir(), "absent.pem"),
		"a file with no cert":  writeTelemetryTestFile(t, "key.pem", privateKey),
		"a file that is junk":  writeTelemetryTestFile(t, "junk.pem", []byte("not pem at all")),
		"a directory":          t.TempDir(),
		"only blanks in a var": "  ",
	} {
		t.Setenv("CERTISTACK_PVE_CA_SOURCE", source)
		if got := telemetryClusterIdentity("pve-01.example.net"); got != "pve-01.example.net" {
			t.Errorf("%s: identity = %q, want the node name", name, got)
		}
	}
}

// Through `run`: two nodes that share a CA file are one cluster in the install's
// record; a node with another CA is a second.
func TestRunRecordsClustersByCAFileNotByNodeName(t *testing.T) {
	caA, _ := telemetryTestCA(t, 1, true)
	caB, _ := telemetryTestCA(t, 2, true)
	pathA := writeTelemetryTestFile(t, "a.pem", caA)
	pathB := writeTelemetryTestFile(t, "b.pem", caB)
	srv := newCountingServer(t, nil)
	rig := newTelemetryRig(t)
	rig.env["CERTISTACK_TELEMETRY_URL"] = srv.URL + "/api/telemetry"
	if _, err := rig.execute("telemetry", "enable"); err != nil {
		t.Fatal(err)
	}
	runOn := func(node, ca string) {
		t.Helper()
		t.Setenv("CERTISTACK_PVE_CA_SOURCE", ca)
		result := finishedRun(true)
		result.Report.NodeFQDN = node
		stubRun(t, result, nil)
		if _, err := rig.execute("run", "plan.yaml"); err != nil {
			t.Fatal(err)
		}
	}
	runOn("pve-01", pathA)
	runOn("pve-02", pathA)
	runOn("pve-03", pathA)
	if got := len(rig.state().Clusters); got != 1 {
		t.Fatalf("three nodes of one cluster recorded %d clusters, want 1", got)
	}
	runOn("pve-standalone", pathB)
	if got := len(rig.state().Clusters); got != 2 {
		t.Fatalf("a second CA recorded %d clusters in all, want 2", got)
	}
	runOn("pve-no-ca", "")
	if got := len(rig.state().Clusters); got != 3 {
		t.Fatalf("a run with no CA file recorded %d clusters in all, want 3 (it counts by node name)", got)
	}
	shown, err := rig.execute("telemetry", "show")
	var payload telemetry.Payload
	if err != nil || json.Unmarshal([]byte(shown), &payload) != nil || payload.ClusterCount != 3 {
		t.Fatalf("show = %q %v; want cluster_count 3", shown, err)
	}
}

// What the CA identifies a cluster by never reaches the server: not the file's
// path, its fingerprint, the certificate itself or the salted hash, whether
// the report is on through a stored yes or through the environment.
func TestTheCAThatIdentifiesAClusterNeverReachesTheServer(t *testing.T) {
	for name, optIn := range map[string]func(r *telemetryRig){
		"a stored yes":           func(r *telemetryRig) { _, _ = r.execute("telemetry", "enable") },
		"CERTISTACK_TELEMETRY=1": func(r *telemetryRig) { r.env["CERTISTACK_TELEMETRY"] = "1" },
	} {
		t.Run(name, func(t *testing.T) {
			ca, fingerprint := telemetryTestCA(t, 7, true)
			dir := filepath.Join(t.TempDir(), "secret-ca-dir")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "pve-root-ca-of-payroll.pem")
			if err := os.WriteFile(path, ca, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CERTISTACK_PVE_CA_SOURCE", path)
			srv := newCountingServer(t, nil)
			rig := newTelemetryRig(t)
			rig.env["CERTISTACK_TELEMETRY_URL"] = srv.URL + "/api/telemetry"
			optIn(rig)
			stubRun(t, finishedRun(true), nil)
			if _, err := rig.execute("run", "plan.yaml"); err != nil {
				t.Fatal(err)
			}
			if srv.count() != 1 {
				t.Fatalf("%d requests, want 1", srv.count())
			}
			st := rig.state()
			der, _ := pem.Decode(ca)
			everything := strings.ToLower(srv.dumps[0])
			planted := []string{
				fingerprint, "pve-ca-sha256", "secret-ca-dir", "payroll", strings.ToLower(st.Salt),
				strings.ToLower(base64.StdEncoding.EncodeToString(der.Bytes)[:40]),
				strings.ToLower(base64.StdEncoding.EncodeToString(sha256Of(der.Bytes))),
			}
			for _, hash := range st.Clusters {
				planted = append(planted, hash[:16])
			}
			for _, secret := range planted {
				if strings.Contains(everything, secret) {
					t.Errorf("%q reached the server:\n%s", secret, srv.dumps[0])
				}
			}
			var body telemetry.Payload
			if err := json.Unmarshal([]byte(srv.bodies[0]), &body); err != nil || body.ClusterCount != 1 {
				t.Errorf("body = %q %v", srv.bodies[0], err)
			}
		})
	}
}

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// CERTISTACK_TELEMETRY=1 reports once a day through `run`, as the same install,
// and `status`, `disable` and `reset` speak of what it keeps.
func TestRunUnderTheEnvironmentOptInReportsOnceADayAsOneInstall(t *testing.T) {
	srv := newCountingServer(t, nil)
	rig := newTelemetryRig(t)
	rig.env["CERTISTACK_TELEMETRY_URL"] = srv.URL + "/api/telemetry"
	rig.env["CERTISTACK_TELEMETRY"] = "1"

	out, err := rig.execute("telemetry", "status")
	if err != nil || !strings.Contains(out, "telemetry: on") || !strings.Contains(out, "install id: none yet") || !strings.Contains(out, "no answer is stored") {
		t.Fatalf("status before the first report: %v\n%s", err, out)
	}
	for i := 0; i < 3; i++ {
		stubRun(t, finishedRun(true), nil)
		if _, err := rig.execute("run", "plan.yaml"); err != nil {
			t.Fatal(err)
		}
	}
	if srv.count() != 1 {
		t.Fatalf("%d reports from three runs on one day under CERTISTACK_TELEMETRY=1, want 1", srv.count())
	}
	st := rig.state()
	if st.Enabled || st.Answered || st.InstallID == "" || st.Salt == "" || st.LastSent == "" {
		t.Fatalf("state = %+v; want an install and its last send, and no answer", st)
	}
	var sent telemetry.Payload
	if err := json.Unmarshal([]byte(srv.bodies[0]), &sent); err != nil || sent.InstallID != st.InstallID {
		t.Fatalf("sent %q %v, want the kept install %s", srv.bodies[0], err, st.InstallID)
	}
	if shown, _ := rig.execute("telemetry", "show"); shown != srv.bodies[0] {
		t.Fatalf("show:\n%s\nsent:\n%s", shown, srv.bodies[0])
	}
	if out, _ = rig.execute("telemetry", "status"); !strings.Contains(out, "install id: "+st.InstallID) {
		t.Fatalf("status after the first report:\n%s", out)
	}

	// Disable and reset forget the install, and say the environment still turns the report on.
	out, err = rig.execute("telemetry", "disable")
	if err != nil || !strings.Contains(out, st.InstallID) || !strings.Contains(out, "still on") || strings.Contains(out, "Nothing is sent") {
		t.Fatalf("disable under the environment opt-in: %v\n%s", err, out)
	}
	if _, err := rig.execute("telemetry", "enable"); err != nil {
		t.Fatal(err)
	}
	out, err = rig.execute("telemetry", "reset")
	if err != nil || !strings.Contains(out, "deleted") || !strings.Contains(out, "still on") || rig.hasState() {
		t.Fatalf("reset under the environment opt-in: %v\n%s", err, out)
	}
}

// CERTISTACK_TELEMETRY=1 where the install cannot be kept sends nothing, and
// status says why.
func TestRunUnderTheEnvironmentOptInSendsNothingWhereTheInstallCannotBeKept(t *testing.T) {
	srv := newCountingServer(t, nil)
	rig := newTelemetryRig(t)
	rig.env["CERTISTACK_TELEMETRY_URL"] = srv.URL + "/api/telemetry"
	rig.env["CERTISTACK_TELEMETRY"] = "1"
	blocker := writeTelemetryTestFile(t, "a-file", []byte("x"))
	rig.statePath = filepath.Join(blocker, "certistack", "telemetry.json")

	stubRun(t, finishedRun(true), nil)
	if _, err := rig.execute("run", "plan.yaml"); err != nil {
		t.Fatal(err)
	}
	if srv.count() != 0 {
		t.Fatalf("%d reports where the install cannot be kept", srv.count())
	}
	out, err := rig.execute("telemetry", "status")
	if err != nil || !strings.Contains(out, "telemetry: off") || !strings.Contains(out, "nothing is sent") {
		t.Fatalf("status: %v\n%s", err, out)
	}
}

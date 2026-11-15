// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Backup logs from a test cluster's 2026-09-27 backup run, trimmed to the lines
// before the data transfer.
const (
	logQuiesced = `2026-09-26 21:00:09 INFO: Starting Backup of VM 7011 (qemu)
2026-09-26 21:00:09 INFO: status = running
2026-09-26 21:00:09 INFO: VM Name: cs-http-rocky-01
2026-09-26 21:00:09 INFO: include disk 'scsi0' 'iscsi-vm:vm-7011-disk-0' 32G
2026-09-26 21:00:09 INFO: backup mode: snapshot
2026-09-26 21:00:09 INFO: creating Proxmox Backup Server archive 'vm/7011/2026-09-27T03:00:09Z'
2026-09-26 21:00:10 INFO: issuing guest-agent 'fs-freeze' command
2026-09-26 21:00:11 INFO: starting backup via QMP command
2026-09-26 21:00:12 INFO: issuing guest-agent 'fs-thaw' command
2026-09-26 21:00:12 INFO: started backup task 'b3c1e5a0-0000-4000-8000-000000000001'
2026-09-26 21:00:12 INFO: resuming VM again
`
	// SELinux denied the freeze on 41 RHEL-family database VMs.
	logFreezeDenied = `2026-09-26 21:08:42 INFO: Starting Backup of VM 7128 (qemu)
2026-09-26 21:08:42 INFO: status = running
2026-09-26 21:08:42 INFO: VM Name: cs-matrix-rhel-8-postgresql
2026-09-26 21:08:43 INFO: backup mode: snapshot
2026-09-26 21:08:43 INFO: issuing guest-agent 'fs-freeze' command
2026-09-26 21:08:43 ERROR: unable to freeze guest fs - failed to open /var/lib/pgsql: Permission denied
2026-09-26 21:08:43 INFO: starting backup via QMP command
2026-09-26 21:08:44 INFO: issuing guest-agent 'fs-thaw' command
2026-09-26 21:08:44 INFO: started backup task '2d8f3124-9485-46ed-a9c3-6c85a5b35a36'
`
	logAgentNotRunning = `2026-09-26 21:01:28 INFO: Starting Backup of VM 7040 (qemu)
2026-09-26 21:01:28 INFO: status = running
2026-09-26 21:01:28 INFO: backup mode: snapshot
2026-09-26 21:01:31 INFO: skipping guest filesystem freeze - agent configured but not running?
2026-09-26 21:01:31 INFO: starting backup via QMP command
2026-09-26 21:01:43 INFO: started backup task '2fa011fb-4017-4e42-b1f6-2280f9c00d46'
`
	// A Windows Server 2022 DC: the backup job started 29 s after the
	// freeze, past VSS's 10 s limit, and the thaw reported it.
	logVSSExpired = `2026-09-26 21:34:27 INFO: Starting Backup of VM 7435 (qemu)
2026-09-26 21:34:27 INFO: status = running
2026-09-26 21:34:28 INFO: backup mode: snapshot
2026-09-26 21:34:29 INFO: issuing guest-agent 'fs-freeze' command
2026-09-26 21:34:58 INFO: starting backup via QMP command
2026-09-26 21:35:10 INFO: issuing guest-agent 'fs-thaw' command
2026-09-26 21:35:47 ERROR: Agent error: couldn't hold writes: fsfreeze is limited up to 10 seconds: Windows error 0x80042314:
2026-09-26 21:35:47 INFO: started backup task '03407787-2ab1-4cdc-8c74-0b4617311e33'
2026-09-26 21:35:47 INFO: resuming VM again
`
	logStopped = `2026-09-26 21:50:39 INFO: Starting Backup of VM 7990 (qemu)
2026-09-26 21:50:39 INFO: status = stopped
2026-09-26 21:50:39 INFO: backup mode: stop
2026-09-26 21:50:41 INFO: starting kvm to execute backup task
2026-09-26 21:50:46 INFO: started backup task '945386c6-96a5-4b51-a53e-5458442a1226'
`
)

func TestParseBackupLog(t *testing.T) {
	for _, tc := range []struct {
		name, log, state, detail string
	}{
		{"frozen", logQuiesced, ConsistencyQuiesced, "froze the file systems"},
		{"freeze denied", logFreezeDenied, ConsistencyCrash, "could not freeze the file systems: failed to open /var/lib/pgsql: Permission denied"},
		{"agent not running", logAgentNotRunning, ConsistencyCrash, "not frozen: agent configured but not running?"},
		{"VSS hold expired", logVSSExpired, ConsistencyCrash, "did not hold until the snapshot: Agent error: couldn't hold writes"},
		{"powered off", logStopped, ConsistencyPoweredOff, "not running"},
		{"stop mode", "INFO: status = running\nINFO: backup mode: stop\nINFO: stopping virtual guest\nINFO: started backup task 'x'\n", ConsistencyPoweredOff, "shut down for the backup"},
		{"suspend mode", "INFO: status = running\nINFO: backup mode: suspend\nINFO: suspending guest\nINFO: started backup task 'x'\n", ConsistencyCrash, "suspended"},
		{"no agent", "INFO: status = running\nINFO: backup mode: snapshot\nINFO: starting backup via QMP command\nINFO: started backup task 'x'\n", ConsistencyCrash, "no guest agent"},
		{"not a backup log", "hello\nworld\n", ConsistencyUnknown, "does not describe"},
		{"empty", "", ConsistencyUnknown, "does not describe"},
	} {
		got := ParseBackupLog(tc.log)
		if got.State != tc.state || !strings.Contains(got.Detail, tc.detail) {
			t.Errorf("%s: %+v, want %s containing %q", tc.name, got, tc.state, tc.detail)
		}
	}
}

// "issuing ... fs-freeze" is written before the freeze is tried, so
// a log that ends before the freeze, thaw and task sequence is complete
// proves nothing: it is unknown, and require_quiesced_backup refuses it.
// A recognized problem stays conclusive even in a short log.
func TestParseBackupLogNeedsTheCompleteSequence(t *testing.T) {
	head := "INFO: status = running\nINFO: backup mode: snapshot\n"
	freeze := "INFO: issuing guest-agent 'fs-freeze' command\n"
	qmp := "INFO: starting backup via QMP command\n"
	thaw := "INFO: issuing guest-agent 'fs-thaw' command\n"
	task := "INFO: started backup task 'b3c1e5a0'\n"
	for _, tc := range []struct {
		name, log, state string
	}{
		{"freeze marker only (the reporter's 97-byte prefix)", head + freeze, ConsistencyUnknown},
		{"freeze and thaw, no task", head + freeze + qmp + thaw, ConsistencyUnknown},
		{"freeze and task, no thaw", head + freeze + qmp + task, ConsistencyUnknown},
		{"thaw before the freeze", head + thaw + freeze + qmp + task, ConsistencyUnknown},
		{"stopped VM, cut before the task", "INFO: status = stopped\nINFO: backup mode: stop\n", ConsistencyUnknown},
		{"no agent, cut before the task", head + qmp, ConsistencyUnknown},
		{"freeze refused, cut short", head + freeze + "ERROR: unable to freeze guest fs - synthetic refusal\n", ConsistencyCrash},
		{"complete (control)", head + freeze + qmp + thaw + task, ConsistencyQuiesced},
	} {
		got := ParseBackupLog(tc.log)
		if got.State != tc.state {
			t.Errorf("%s: %+v, want %s", tc.name, got, tc.state)
		}
		if unmet := QuiescedRequirementUnmet(got.State, got.Detail); (unmet == "") != (tc.state == ConsistencyQuiesced) {
			t.Errorf("%s: requirement %q", tc.name, unmet)
		}
	}
}

// Through the real API reader: an HTTP 200 that carries only the
// start of the log, and a log whose freeze refusal lies past the 1 MiB read
// limit, are both unknown and fail require_quiesced_backup. A long log
// whose sequence completes inside the limit is still read.
func TestBackupConsistencyRefusesAnIncompleteLog(t *testing.T) {
	head := "INFO: status = running\nINFO: backup mode: snapshot\n"
	freeze := "INFO: issuing guest-agent 'fs-freeze' command\n"
	padding := "INFO: " + strings.Repeat("x", maxClientLogBytes-len(head)-len(freeze)-7) + "\n"
	for _, tc := range []struct {
		name, log, state, detail string
	}{
		{"97-byte prefix", head + freeze, ConsistencyUnknown, "ends before the backup task started"},
		{"refusal past the limit", head + padding + freeze + "ERROR: unable to freeze guest fs - synthetic refusal\nINFO: started backup task 'audit'\n", ConsistencyUnknown, "only its first 1 MiB was read"},
		{"long log, complete sequence (control)", logQuiesced + strings.Repeat("INFO:  1% (1.0 GiB of 32.0 GiB) in 3s\n", 30000), ConsistencyQuiesced, "froze"},
	} {
		server, fingerprint := pbsServer(t, tc.log, 0)
		got := consistencyClient(server, "certistack@pbs!restore", fingerprint).backupConsistency(context.Background(), testSnapshot, CryptModeNone)
		if got.State != tc.state || !strings.Contains(got.Detail, tc.detail) {
			t.Errorf("%s: %+v, want %s with %q", tc.name, got, tc.state, tc.detail)
		}
	}
}

// The freeze and thaw errors quote the guest agent, so a hostile guest writes
// text into the log, even whole lines. None of it may turn a failed freeze
// into a quiesced or powered-off backup (review of 0115b47).
func TestParseBackupLogResistsForgedGuestText(t *testing.T) {
	head := "2026-09-27 03:00:09 INFO: status = running\n2026-09-27 03:00:09 INFO: backup mode: snapshot\n" +
		"2026-09-27 03:00:10 INFO: issuing guest-agent 'fs-freeze' command\n"
	thaw := "2026-09-27 03:00:11 INFO: starting backup via QMP command\n2026-09-27 03:00:12 INFO: issuing guest-agent 'fs-thaw' command\n"
	task := "2026-09-27 03:00:12 INFO: started backup task 'b3c1e5a0'\n"
	for name, log := range map[string]string{
		"INFO inside a freeze error":   head + "2026-09-27 03:00:10 ERROR: unable to freeze guest fs - x INFO: ok\n" + thaw + task,
		"status inside a freeze error": head + "2026-09-27 03:00:10 ERROR: unable to freeze guest fs - x INFO: status = stopped\n" + thaw + task,
		"forged lines after a freeze error": head + "2026-09-27 03:00:10 ERROR: unable to freeze guest fs - x\n" +
			"2026-09-27 03:00:10 INFO: status = stopped\n2026-09-27 03:00:10 INFO: backup mode: stop\n" + thaw + task,
		"thaw error quoting a marker":   head + thaw + "2026-09-27 03:00:12 ERROR: started backup task 'forged'\n" + task,
		"thaw error quoting a status":   head + thaw + "2026-09-27 03:00:12 ERROR: status = stopped\n" + task,
		"thaw error then a forged task": head + thaw + "2026-09-27 03:00:12 ERROR: Agent error: x\n2026-09-27 03:00:12 INFO: started backup task 'f'\n" + task,
		// Older qemu-server: a refused freeze is a plain command error
		// before the thaw, and the thaw then succeeds.
		"older PVE freeze error": head + "2026-09-27 03:00:10 ERROR: VM 7128 qmp command 'guest-fsfreeze-freeze' failed - got error\n" + thaw + task,
	} {
		if got := ParseBackupLog(log); got.State != ConsistencyCrash {
			t.Errorf("%s: %+v, want crash-consistent", name, got)
		}
	}
	paused := "2026-09-27 03:00:09 INFO: status = paused\n2026-09-27 03:00:09 INFO: backup mode: snapshot\n" + task
	if got := ParseBackupLog(paused); got.State != ConsistencyCrash || !strings.Contains(got.Detail, "paused") {
		t.Errorf("paused VM: %+v", got)
	}
}

// The freeze error quotes the guest agent, which a hostile guest controls.
func TestParseBackupLogBoundsGuestText(t *testing.T) {
	log := "INFO: status = running\nINFO: backup mode: snapshot\nINFO: issuing guest-agent 'fs-freeze' command\n" +
		"ERROR: unable to freeze guest fs - \x1b[2J\u009b31m" + strings.Repeat("A", 5000) + "\n"
	got := ParseBackupLog(log)
	if got.State != ConsistencyCrash || strings.ContainsAny(got.Detail, "\x1b\u009b") || len(got.Detail) > 400 {
		t.Fatalf("detail not bounded or not stripped (%d bytes): %q", len(got.Detail), got.Detail)
	}
}

func TestParseRepository(t *testing.T) {
	for in, want := range map[string]apiEndpoint{
		"store":                         {"root@pam", "localhost", "8007", "store"},
		"pbs.lab:store":                 {"root@pam", "pbs.lab", "8007", "store"},
		"backup@pbs@pbs.lab:8007:store": {"backup@pbs", "pbs.lab", "8007", "store"},
		"certistack@pbs!restore@192.0.2.5:pbs-data": {"certistack@pbs!restore", "192.0.2.5", "8007", "pbs-data"},
		"root@pam@[fd00::5]:8443:store":             {"root@pam", "fd00::5", "8443", "store"},
		"root@pam@[fd00::5]:store":                  {"root@pam", "fd00::5", "8007", "store"},
	} {
		got, err := parseRepository(in)
		if err != nil || got != want {
			t.Errorf("parseRepository(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "host:", "root@pam@host:99999:store", "root@pam@[fd00::5:store", "bad user@host:store",
		"root@pam@host/../x:store", "root@pam@[not-ip]:store", "root@pam@host:store/x"} {
		if got, err := parseRepository(bad); err == nil {
			t.Errorf("parseRepository(%q) = %+v, want an error", bad, got)
		}
	}
}

// pbsServer is a PBS API stand-in with a certificate no system trusts. It
// serves log for vm/7011 at 2026-09-27T03:00:09Z to the token
// certistack@pbs!restore with secret "s3cret", or to a ticket for the user
// certistack@pbs with the same password.
func pbsServer(t *testing.T, log string, status int) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/access/ticket":
			if r.Method != http.MethodPost || r.FormValue("username") != "certistack@pbs" || r.FormValue("password") != "s3cret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"ticket":"PBS:certistack@pbs:66F6A1B2::c2lnbmF0dXJl+/=","CSRFPreventionToken":"x"}}`))
		case "/api2/json/admin/datastore/pbs-data/download-decoded":
			cookie, _ := url.QueryUnescape(strings.TrimPrefix(r.Header.Get("Cookie"), "PBSAuthCookie="))
			if r.Header.Get("Authorization") != "PBSAPIToken=certistack@pbs!restore:s3cret" && cookie != "PBS:certistack@pbs:66F6A1B2::c2lnbmF0dXJl+/=" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			q := r.URL.Query()
			if q.Get("backup-type") != "vm" || q.Get("backup-id") != "7011" || q.Get("backup-time") != "1790478009" ||
				q.Get("file-name") != "client.log.blob" || q.Get("ns") != "certistack-test" {
				t.Errorf("unexpected query %s", r.URL.RawQuery)
			}
			if status != 0 {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"data":null,"message":"unable to open file - No such file or directory (os error 2)\n"}`))
				return
			}
			_, _ = w.Write([]byte(log))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	sum := sha256.Sum256(server.Certificate().Raw)
	return server, hex.EncodeToString(sum[:])
}

func consistencyClient(server *httptest.Server, user, fingerprint string) *Client {
	host := strings.TrimPrefix(server.URL, "https://")
	return &Client{cfg: Config{Repository: user + "@" + host + ":pbs-data", Password: "s3cret", Fingerprint: fingerprint, Namespace: "certistack-test"}}
}

const testSnapshot = "vm/7011/2026-09-27T03:00:09Z"

func TestBackupConsistencyReadsTheLogThroughTheAPI(t *testing.T) {
	server, fingerprint := pbsServer(t, logFreezeDenied, 0)
	// PBS shows fingerprints as colon-separated upper- or lower-case hex.
	var pairs []string
	for i := 0; i < len(fingerprint); i += 2 {
		pairs = append(pairs, strings.ToUpper(fingerprint[i:i+2]))
	}
	for i, user := range []string{"certistack@pbs!restore", "certistack@pbs"} {
		configured := strings.Join(pairs, ":")
		if i == 1 {
			configured = "SHA256:" + configured
		}
		got := consistencyClient(server, user, configured).backupConsistency(context.Background(), testSnapshot, CryptModeNone)
		if got.State != ConsistencyCrash || !strings.Contains(got.Detail, "/var/lib/pgsql") {
			t.Fatalf("%s: %+v", user, got)
		}
	}
}

func TestBackupConsistencyTrustsOnlyAVerifiedPBS(t *testing.T) {
	server, _ := pbsServer(t, logQuiesced, 0)
	for fingerprint, want := range map[string]string{
		"":                       "not trusted and no fingerprint",
		strings.Repeat("ab", 32): "does not match the configured fingerprint",
	} {
		got := consistencyClient(server, "certistack@pbs!restore", fingerprint).backupConsistency(context.Background(), testSnapshot, CryptModeNone)
		if got.State != ConsistencyUnknown || !strings.Contains(got.Detail, want) {
			t.Fatalf("fingerprint %q: %+v, want unknown with %q", fingerprint, got, want)
		}
	}
}

// A proxy's HTML error page is not PBS's answer and can name hosts; only the
// status reaches the report.
func TestAPIStatusErrorKeepsOnlyPBSMessages(t *testing.T) {
	for body, want := range map[string]string{
		`{"data":null,"message":"permission check failed"}`:         "PBS API answered HTTP 403: permission check failed",
		`<html><body>502 from proxy.internal.example</body></html>`: "PBS API answered HTTP 403",
	} {
		recorder := httptest.NewRecorder()
		recorder.WriteHeader(http.StatusForbidden)
		_, _ = recorder.WriteString(body)
		if got := apiStatusError(recorder.Result()).Error(); got != want {
			t.Fatalf("body %q: %q, want %q", body, got, want)
		}
	}
}

func TestBackupConsistencyUnknownCases(t *testing.T) {
	missing, fingerprint := pbsServer(t, "", http.StatusBadRequest)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := listener.Addr().String()
	listener.Close()
	for _, tc := range []struct {
		name      string
		client    *Client
		cryptMode string
		want      string
	}{
		{"no log", consistencyClient(missing, "certistack@pbs!restore", fingerprint), CryptModeNone, "has no backup log"},
		{"encrypted", &Client{cfg: Config{Repository: "u@pbs!t@127.0.0.1:1:s", Password: "x"}}, CryptModeEncrypt, "encrypted"},
		{"no repository", &Client{}, CryptModeNone, "no PBS repository"},
		{"no secret", &Client{cfg: Config{Repository: "u@pbs!t@127.0.0.1:1:s"}}, CryptModeNone, "no PBS password"},
		{"unreachable", &Client{cfg: Config{Repository: "u@pbs!t@" + closed + ":s", Password: "x"}}, CryptModeNone, "unreachable"},
	} {
		got := tc.client.backupConsistency(context.Background(), testSnapshot, tc.cryptMode)
		if got.State != ConsistencyUnknown || !strings.Contains(got.Detail, tc.want) {
			t.Fatalf("%s: %+v, want unknown with %q", tc.name, got, tc.want)
		}
		// The reason goes into the signed report; the server's address does not.
		if strings.Contains(got.Detail, "127.0.0.1") {
			t.Fatalf("%s: detail names the server: %q", tc.name, got.Detail)
		}
	}
}

func TestLayoutRecordsBackupConsistency(t *testing.T) {
	fakeBackupClient(t, `[{"filename":"drive-scsi0.img.fidx","crypt-mode":"none"},{"filename":"qemu-server.conf.blob","crypt-mode":"none"}]`, "scsi0: pbs:vm-7011-disk-0\n")
	client := &Client{cfg: Config{Repository: "u@pbs!t@pbs.lab:store", Password: "x"}}
	client.clientLogReader = func(_ context.Context, snapshot string) ([]byte, error) {
		if snapshot != testSnapshot {
			t.Errorf("log read for %q", snapshot)
		}
		return []byte(logVSSExpired), nil
	}
	layout, err := client.LoadVMLayout(context.Background(), testSnapshot, t.TempDir())
	if err != nil || layout.Consistency.State != ConsistencyCrash {
		t.Fatalf("layout consistency = %+v, %v", layout.Consistency, err)
	}
	profile, err := client.LoadVMProfile(context.Background(), testSnapshot, t.TempDir())
	if err != nil || profile.Consistency != layout.Consistency {
		t.Fatalf("profile consistency = %+v, %v", profile.Consistency, err)
	}
}

func TestQuiescedRequirementUnmet(t *testing.T) {
	for _, tc := range []struct{ state, detail, want string }{
		{ConsistencyQuiesced, "", ""},
		{ConsistencyPoweredOff, "", ""},
		{ConsistencyCrash, "fsfreeze failed", "but this one is crash-consistent: fsfreeze failed"},
		{ConsistencyUnknown, "log not readable", "but this one is unknown: log not readable"},
		{"", "", "but this one is unknown: no backup log was read"},
	} {
		got := QuiescedRequirementUnmet(tc.state, tc.detail)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("QuiescedRequirementUnmet(%q, %q) = %q, want %q", tc.state, tc.detail, got, tc.want)
		}
	}
}

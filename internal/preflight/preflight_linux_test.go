// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
)

func TestCheckPVEConnectivityAuthenticatesWithToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "PVEAPIToken=certistack@pam!doctor=secret" {
			t.Errorf("authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"version": "8.4"}})
	}))
	defer server.Close()

	version, err := checkPVEConnectivity(context.Background(), server.URL, false, "", "certistack@pam!doctor", "secret")
	if err != nil {
		t.Fatalf("connectivity check failed: %v", err)
	}
	if version != "8.4" {
		t.Fatalf("connectivity check read PVE version %q, want the 8.4 the node answered", version)
	}
}

func TestCheckRequiredPVEConnectivityRejectsMissingWorkerCredentials(t *testing.T) {
	result := Check(context.Background(), nil, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir(), RequirePVEConnectivity: true})
	var pveItem *CheckItem
	for index := range result.Checks {
		if result.Checks[index].Name == "pve_connectivity" {
			pveItem = &result.Checks[index]
			break
		}
	}
	if result.Ready || pveItem == nil || pveItem.Status != "failed" || !strings.Contains(pveItem.Detail, "PVE_URL is required") {
		t.Fatalf("required PVE preflight result = %+v; want failed missing-endpoint check", result)
	}
}

// node-run (RequirePVEConnectivity) and doctor (diagnostic) both reach PVE
// before the runner's own gate; neither may send the token over an
// unverified connection without the lab opt-in.
func TestCheckInsecurePVETLSWithoutLabOptInSendsNoRequest(t *testing.T) {
	t.Setenv("CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB", "")
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"version": "8.4"}})
	}))
	defer server.Close()

	for _, required := range []bool{true, false} {
		result := Check(context.Background(), nil, Options{
			ScratchDir:             t.TempDir(),
			StateDir:               t.TempDir(),
			PVEURL:                 server.URL,
			PVETLSInsecure:         true,
			PVETokenID:             "certistack@pam!doctor",
			PVETokenSecret:         "secret",
			RequirePVEConnectivity: required,
		})
		var pveItem *CheckItem
		for index := range result.Checks {
			if result.Checks[index].Name == "pve_connectivity" {
				pveItem = &result.Checks[index]
				break
			}
		}
		if pveItem == nil || pveItem.Status == "passed" || !strings.Contains(pveItem.Detail, "PVE_TLS_INSECURE is forbidden") {
			t.Fatalf("required=%v: pve_connectivity = %+v; want the insecure-TLS refusal", required, pveItem)
		}
	}
	if requests != 0 {
		t.Fatalf("preflight sent %d PVE request(s) with verification disabled and no lab opt-in", requests)
	}
}

func TestParseAvailableMemory(t *testing.T) {
	meminfo := `MemTotal:       16384000 kB
MemFree:         4096000 kB
MemAvailable:    8192000 kB
Buffers:          500000 kB
Cached:          3000000 kB`

	avail, err := parseAvailableMemory(strings.NewReader(meminfo))
	if err != nil {
		t.Fatalf("parseAvailableMemory failed: %v", err)
	}

	expected := uint64(8192000) * 1024
	if avail != expected {
		t.Errorf("expected %d bytes, got %d", expected, avail)
	}
}

func TestSafePath(t *testing.T) {
	valid := filepath.Join(t.TempDir(), "scratch")
	if err := os.Mkdir(valid, 0700); err != nil {
		t.Fatal(err)
	}
	if err := SafePath(valid); err != nil {
		t.Errorf("expected private path %s to be safe, got error: %v", valid, err)
	}

	invalid := []string{"", "/tmp", "/var/tmp", "relative/path", "/tmp/../etc/passwd", "../foo"}
	for _, p := range invalid {
		if err := SafePath(p); err == nil {
			t.Errorf("expected path %s to be rejected, but it passed", p)
		}
	}
}

func TestFreeBytes(t *testing.T) {
	bytes, err := FreeBytes("/tmp")
	if err != nil {
		t.Fatalf("FreeBytes(/tmp) failed: %v", err)
	}
	if bytes == 0 {
		t.Errorf("expected >0 free bytes on /tmp")
	}
}

func checkItem(result Result, name string) *CheckItem {
	for index := range result.Checks {
		if result.Checks[index].Name == name {
			return &result.Checks[index]
		}
	}
	return nil
}

func TestCheckNamesMissingSandboxToolsOnlyWhenThePlanNeedsThem(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no nft, no guestfish
	wire := &config.Plan{
		PlanID:  "wire",
		Network: config.Network{IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		Tiers: []config.Tier{{VMs: []config.VM{{VMID: 9001, Probes: []config.Probe{
			{Type: "tcp", TargetIP: "10.100.0.10", Port: 80, TimeoutSec: 5, Description: "web"},
		}}}}},
	}
	result := Check(context.Background(), wire, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()})
	for name, want := range map[string]string{"nft": "nftables", "guestfish": "libguestfs-tools"} {
		item := checkItem(result, name)
		if item == nil || item.Status != "failed" || !strings.Contains(item.Detail, want) {
			t.Errorf("%s check = %+v, want a failure naming %q", name, item, want)
		}
	}

	qgaOnly := &config.Plan{PlanID: "qga", Tiers: []config.Tier{{VMs: []config.VM{{VMID: 9002, Probes: []config.Probe{
		{Type: "qga_ping", TimeoutSec: 5, Description: "agent"},
	}}}}}}
	result = Check(context.Background(), qgaOnly, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()})
	if checkItem(result, "nft") != nil || checkItem(result, "guestfish") != nil {
		t.Fatalf("a plan without wire probes was held to nft/guestfish: %+v", result.Checks)
	}
}

func TestCheckValidatesTheConfiguredPBSKey(t *testing.T) {
	key := filepath.Join(t.TempDir(), "pbs.enc")
	if err := os.WriteFile(key, []byte(`{"kdf":null,"data":"AAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	result := Check(context.Background(), nil, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir(), PBSKeyfile: key})
	if item := checkItem(result, "pbs_keyfile"); item == nil || item.Status != "failed" || !strings.Contains(item.Detail, "readable by other users") {
		t.Fatalf("pbs_keyfile check = %+v", item)
	}
}

// Under-privileged token: preflight lists every privilege a run
// would miss, before the run creates anything; the documented role passes.
func TestPreflightListsEveryMissingPrivilege(t *testing.T) {
	grant := map[string]int{"VM.Allocate": 1, "VM.Audit": 1, "VM.PowerMgmt": 1, "VM.Console": 1, "VM.Config.Disk": 1, "VM.Config.CPU": 1, "VM.Config.Memory": 1, "VM.Config.Network": 1, "VM.Config.Options": 1, "VM.Config.HWType": 1, "VM.Config.CDROM": 1, "SDN.Allocate": 1, "SDN.Audit": 1, "SDN.Use": 1, "Sys.Audit": 1, "Datastore.AllocateSpace": 1, "Datastore.Audit": 1}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{path: grant}})
	}))
	defer server.Close()
	plan := &config.Plan{
		Network: config.Network{ZoneID: "csLab70", VNetID: "csVn70"},
		Storage: config.Storage{OverlayStorage: "certistack-scratch"},
		Tiers:   []config.Tier{{VMs: []config.VM{{VMID: 717011}}}},
	}
	opts := Options{PVEURL: server.URL, PVETokenID: "certistack-underpriv@pve!run", PVETokenSecret: "s", NodeName: "pve-node-02"}
	run := func() (status, detail string) {
		record := func(s string) func(string, error, string) {
			return func(name string, err error, success string) {
				if name != "pve_privileges" {
					return
				}
				status, detail = s, success
				if err != nil {
					detail = err.Error()
				} else {
					status = "passed"
				}
			}
		}
		checkPVEPrivileges(context.Background(), plan, opts, record("failed"), record("warning"))
		return status, detail
	}

	if status, detail := run(); status != "passed" || !strings.Contains(detail, "documented CertiStackRole") {
		t.Fatalf("documented role: %s %q", status, detail)
	}
	delete(grant, "SDN.Allocate")
	delete(grant, "VM.Allocate")
	status, detail := run()
	if status != "failed" {
		t.Fatalf("underprivileged token: %s %q", status, detail)
	}
	for _, want := range []string{"SDN.Allocate on /sdn ", "SDN.Allocate on /sdn/zones ", "VM.Allocate on /vms/717011 "} {
		if !strings.Contains(detail, want) {
			t.Errorf("refusal lacks %q: %s", want, detail)
		}
	}
	grant["SDN.Allocate"], grant["VM.Allocate"] = 1, 1
	delete(grant, "VM.Config.CDROM")
	if status, detail := run(); status != "warning" || !strings.Contains(detail, "VM.Config.CDROM on /vms/717011") {
		t.Fatalf("missing only CDROM: %s %q", status, detail)
	}
}

// The warning puts aborting the waiting connection before detaching the
// loop: while reads wait, losetup -d itself hangs.
func TestStaleLoopsWarningOrdersTheFix(t *testing.T) {
	if staleLoopsWarning(nil, nil) != nil {
		t.Fatal("warned about nothing")
	}
	err := staleLoopsWarning([]sysutil.StaleFUSELoop{{Device: "/dev/loop0", Bytes: 32 << 30, Stuck: true}}, []sysutil.OrphanedFUSEConnection{{Minor: "53", Waiting: 1}})
	msg := err.Error()
	abort := strings.Index(msg, "echo 1 > /sys/fs/fuse/connections/53/abort")
	detach := strings.Index(msg, "losetup -d /dev/loop0")
	if abort < 0 || detach < 0 || abort > detach || !strings.Contains(msg, "32.0 GiB, reads stuck") {
		t.Fatalf("warning = %s", msg)
	}
}

// A guest's RAID, which the host assembled from the loop's partitions, can hold
// the loop, and losetup -d alone then only marks it for removal. The warning
// names what holds it and gives the commands that work, in their order; a loop
// nothing holds gets the plain warning.
func TestStaleLoopsWarningNamesWhatHoldsTheLoops(t *testing.T) {
	both := []sysutil.LoopHolder{{Name: "md126"}, {Name: "md127"}}
	err := staleLoopsWarning([]sysutil.StaleFUSELoop{
		{Device: "/dev/loop0", Bytes: 32 << 30, Holders: both},
		{Device: "/dev/loop1", Bytes: 32 << 30, Holders: both},
	}, nil)
	if err == nil {
		t.Fatal("no warning")
	}
	msg := err.Error()
	for _, want := range []string{
		"/dev/loop0: md126, md127; /dev/loop1: md126, md127",
		"losetup -d cannot release a loop device they hold until they are stopped",
		"stop what holds them: mdadm --stop /dev/md126 /dev/md127",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning lacks %q:\n%s", want, msg)
		}
	}
	stop, detach := strings.Index(msg, "mdadm --stop /dev/md126 /dev/md127"), strings.Index(msg, "losetup -d /dev/loop0 /dev/loop1")
	if stop < 0 || detach < 0 || stop > detach {
		t.Fatalf("the stop must come before the detach:\n%s", msg)
	}
	if strings.Count(msg, "mdadm --stop") != 1 {
		t.Fatalf("an array that holds both loops is named once:\n%s", msg)
	}

	// With a FUSE connection too: abort, then stop, then detach.
	err = staleLoopsWarning([]sysutil.StaleFUSELoop{{Device: "/dev/loop0", Bytes: 32 << 30, Holders: []sysutil.LoopHolder{{Name: "dm-0", DMName: "rl-root"}}}}, []sysutil.OrphanedFUSEConnection{{Minor: "53", Waiting: 1}})
	msg = err.Error()
	abort, stop, detach := strings.Index(msg, "echo 1 > /sys/fs/fuse/connections/53/abort"), strings.Index(msg, "dmsetup remove rl-root"), strings.Index(msg, "losetup -d /dev/loop0")
	if abort < 0 || stop < abort || detach < stop {
		t.Fatalf("want abort, stop, detach in that order:\n%s", msg)
	}

	// Nothing holds it: the text is the one without holders.
	err = staleLoopsWarning([]sysutil.StaleFUSELoop{{Device: "/dev/loop0", Bytes: 32 << 30}}, nil)
	want := "/dev/loop0 (32.0 GiB): read-only loop device(s) attached to a FUSE file that is no longer mounted; nothing can read them. To fix, release them: losetup -d /dev/loop0"
	if err == nil || err.Error() != want {
		t.Fatalf("warning = %v, want %q", err, want)
	}
}

// A scratch directory that does not exist yet is judged by the file system it
// would be created on: FreeBytes walks up to the first directory that exists,
// and reports a path that cannot be on any file system as an error.
func TestFreeBytesWalksUpToTheFirstExistingParent(t *testing.T) {
	dir := t.TempDir()
	want, err := FreeBytes(dir)
	if err != nil || want == 0 {
		t.Fatalf("FreeBytes(%s) = %d, %v", dir, want, err)
	}
	got, err := FreeBytes(filepath.Join(dir, "not-yet", "deeper", "still"))
	if err != nil || got == 0 {
		t.Fatalf("FreeBytes of a path that does not exist yet = %d, %v; want its parent's file system", got, err)
	}
	// Both reads see the same file system; allow the free space to move a little.
	if diff := int64(got) - int64(want); diff > 64<<20 || diff < -64<<20 {
		t.Fatalf("FreeBytes of the missing path (%d) is not the parent's (%d)", got, want)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FreeBytes(filepath.Join(file, "below")); err == nil {
		t.Fatal("a path below a regular file was given free space")
	}
}

// A symlink anywhere in the scratch path, as the last component or in the
// middle, is refused: a link can be pointed somewhere else after the check.
func TestSafePathRefusesASymlinkedComponent(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(real, "scratch"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := SafePath(real); err != nil {
		t.Fatalf("the real private directory was refused: %v", err)
	}
	if err := SafePath(link); err == nil {
		t.Error("a symlink to a private directory was accepted")
	}
	if err := SafePath(filepath.Join(link, "scratch")); err == nil {
		t.Error("a path through a symlinked parent was accepted")
	}
}

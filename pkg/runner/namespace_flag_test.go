// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// The 3.x proxmox-backup-client (every PVE 8 node's) ignores PBS_NAMESPACE, so
// a command without --ns reads the root namespace. init, plan, doctor and a run
// reach the client through the same pbs.Client; this is the proof that each of
// them hands it the namespace of its own configuration as --ns, against a
// stand-in client that, like 3.3.7, reads no variable. The root namespace has a
// snapshot of the group too (older, encrypted), so a missed --ns shows as the
// wrong snapshot, not only as a missing argument.

const (
	nsTenant = "tenant-a"
	// The namespace's newest snapshot of vm/7011, and the root's.
	nsTenantLatest = "vm/7011/2026-09-27T03:00:00Z"
	nsRootLatest   = "vm/7011/2026-09-02T00:00:00Z"
)

const nsClientScript = `#!/bin/sh
dir=$(dirname "$0")
sub=$1
case "$1" in snapshot|group) sub="$1 $2";; esac
ns=; has=0; prev=
for a in "$@"; do
  case "$a" in
    --ns=*) ns=${a#--ns=}; has=$((has+1));;
    *) if [ "$prev" = "--ns" ]; then ns=$a; has=$((has+1)); fi;;
  esac
  prev=$a
done
printf '%s|%s|%s|%s\n' "$sub" "$has" "$ns" "$*" >> "$dir/calls"
d="$dir/ns/${ns:-root}"
snap=; grp=; conf=
for a in "$@"; do
  case "$a" in
    vm/*/*) snap=$a;;
    vm/*) grp=$a;;
    qemu-server.conf.blob) conf=1;;
  esac
done
fkey() { printf '%s' "$1" | tr '/:' '--'; }
case "$sub" in
  "snapshot list")
    if [ -n "$grp" ]; then f="$d/list-$(fkey "$grp").json"; else f="$d/list.json"; fi
    if [ -f "$f" ]; then cat "$f"; else echo '[]'; fi;;
  "snapshot files")
    f="$d/files-$(fkey "$snap").json"
    if [ -f "$f" ]; then cat "$f"; else echo "Error: ENOENT: No such file or directory" >&2; exit 1; fi;;
  restore)
    for last; do :; done
    printf 'cores: 2\nmemory: 2048\nbios: seabios\nscsi0: local:vm-7011-disk-0,size=1G\nboot: order=scsi0\n' > "$last";;
  version) printf 'client version: 3.3.7\nserver version: 3.4.1\n';;
  *) echo "unexpected: $*" >&2; exit 2;;
esac
`

// nsNode installs the stand-in client, with a root namespace and the
// namespace nsTenant that hold different snapshots of vm/7011 (and the
// tenant's also vm/7012), and a PVE that answers its version.
type nsNode struct {
	t   *testing.T
	dir string
}

func newNSNode(t *testing.T) nsNode {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	newVersionNode(t, "8.3.5", pbs3) // the PVE, and the PBS_* variables of a node
	// No secret: the backup log is read through the PBS API, and a test makes
	// no request to a server.
	t.Setenv("PBS_PASSWORD", "")
	dir := t.TempDir()
	n := nsNode{t: t, dir: dir}
	n.write(filepath.Join(dir, "proxmox-backup-client"), nsClientScript, 0o755)
	entry := func(snapshot, crypt string) string {
		parts := strings.Split(snapshot, "/")
		return `{"backup-type":"vm","backup-id":"` + parts[1] + `","backup-time":` + unix(parts[2]) + `,"files":[{"filename":"index.json.blob","crypt-mode":"none"},{"filename":"drive-scsi0.img.fidx","crypt-mode":"` + crypt + `"}]}`
	}
	files := func(crypt string) string {
		return `[{"filename":"qemu-server.conf.blob","crypt-mode":"` + crypt + `","size":512},{"filename":"drive-scsi0.img.fidx","crypt-mode":"` + crypt + `","size":1048576},{"filename":"index.json.blob","crypt-mode":"none","size":300}]`
	}
	key := func(s string) string { return strings.NewReplacer("/", "-", ":", "-").Replace(s) }
	rootOld, rootLatest := entry("vm/7011/2026-09-01T00:00:00Z", "encrypt"), entry(nsRootLatest, "encrypt")
	tenantOld, tenantLatest := entry("vm/7011/2026-09-26T03:00:00Z", "none"), entry(nsTenantLatest, "none")
	tenantVM2 := entry("vm/7012/2026-09-27T04:00:00Z", "none")
	n.put("root", "list.json", "["+rootOld+","+rootLatest+"]")
	n.put("root", "list-vm-7011.json", "["+rootOld+","+rootLatest+"]")
	n.put("root", "files-"+key(nsRootLatest)+".json", files("encrypt"))
	n.put(nsTenant, "list.json", "["+tenantOld+","+tenantLatest+","+tenantVM2+"]")
	n.put(nsTenant, "list-vm-7011.json", "["+tenantOld+","+tenantLatest+"]")
	n.put(nsTenant, "list-vm-7012.json", "["+tenantVM2+"]")
	for _, snapshot := range []string{"vm/7011/2026-09-26T03:00:00Z", nsTenantLatest, "vm/7012/2026-09-27T04:00:00Z"} {
		n.put(nsTenant, "files-"+key(snapshot)+".json", files("none"))
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return n
}

func unix(rfc3339 string) string {
	when, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		panic(err)
	}
	return strconv.FormatInt(when.Unix(), 10)
}

func (n nsNode) write(path, content string, perm os.FileMode) {
	n.t.Helper()
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		n.t.Fatal(err)
	}
}

func (n nsNode) put(namespace, name, content string) {
	n.t.Helper()
	dir := filepath.Join(n.dir, "ns", namespace)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		n.t.Fatal(err)
	}
	n.write(filepath.Join(dir, name), content, 0o644)
}

// nsCall is one call of the client: its subcommand, the number of --ns it
// was given, the namespace it read, and its arguments.
type nsCall struct {
	sub   string
	flags int
	ns    string
	args  string
}

func (n nsNode) calls() []nsCall {
	data, _ := os.ReadFile(filepath.Join(n.dir, "calls"))
	var calls []nsCall
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		p := strings.SplitN(line, "|", 4)
		call := nsCall{sub: p[0], ns: p[2], args: p[3]}
		if p[1] == "1" {
			call.flags = 1
		} else if p[1] != "0" {
			call.flags = 2
		}
		calls = append(calls, call)
	}
	return calls
}

// requireNamespace fails for any call of a command that takes --ns that read
// another namespace than ns, and requires that the commands that read backups
// were run at all.
func (n nsNode) requireNamespace(t *testing.T, ns string, want ...string) {
	t.Helper()
	seen := map[string]bool{}
	for _, call := range n.calls() {
		seen[call.sub] = true
		switch call.sub {
		case "snapshot list", "snapshot files", "map", "restore":
			if call.flags != 1 || call.ns != ns {
				t.Errorf("%s read namespace %q with %d --ns, want exactly one --ns %s\n  arguments: %s", call.sub, call.ns, call.flags, ns, call.args)
			}
		default:
			if call.flags != 0 {
				t.Errorf("%s was given --ns", call.sub)
			}
		}
	}
	for _, sub := range want {
		if !seen[sub] {
			t.Errorf("the client was never run for %q; it ran for %v", sub, seen)
		}
	}
}

func oneVMPlan(namespace string) *config.Plan {
	plan := boundedPlan("namespace")
	plan.Network = config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"}
	plan.Storage.PBSNamespace = namespace
	plan.Tiers = []config.Tier{{Level: 1, VMs: []config.VM{
		{VMID: 9001, Name: "app", SourceVMID: 7011, SourcePBS: config.SourcePBS{Snapshot: "latest"}},
	}}}
	return plan
}

// init lists the backups of the namespace it is given (--namespace, else
// PBS_NAMESPACE), through the client Discover builds.
func TestInitListsTheBackupsOfTheNamespace(t *testing.T) {
	for name, tc := range map[string]struct{ request, env string }{
		"--namespace":   {request: nsTenant},
		"PBS_NAMESPACE": {env: nsTenant},
	} {
		t.Run(name, func(t *testing.T) {
			node := newNSNode(t)
			t.Setenv("PBS_NAMESPACE", tc.env)
			previous := initplanDiscover
			t.Cleanup(func() { initplanDiscover = previous })
			var listed []pbs.VMBackups
			initplanDiscover = func(ctx context.Context, backups initplan.Backups, _ initplan.Cluster, req initplan.Request, _ string) (*initplan.Discovery, error) {
				var err error
				listed, err = backups.ListVMBackups(ctx)
				return &initplan.Discovery{Node: req.Node, Namespace: req.Namespace}, err
			}
			discovery, err := Discover(context.Background(), initplan.Request{Node: "pve1", Namespace: tc.request}, "")
			if err != nil {
				t.Fatal(err)
			}
			var ids []int
			for _, vm := range listed {
				ids = append(ids, vm.VMID)
			}
			if !reflect.DeepEqual(ids, []int{7011, 7012}) || listed[0].Latest != nsTenantLatest {
				t.Fatalf("init listed %+v, want the namespace's VMs 7011 (latest %s) and 7012: this is the root's if the client was not told the namespace", listed, nsTenantLatest)
			}
			if discovery == nil {
				t.Fatal("no discovery")
			}
			node.requireNamespace(t, nsTenant, "snapshot list")
		})
	}
}

// plan and run both prepare a plan with prepareRun: the version check, the
// resolution of "latest", and the reading of each backup's layout and
// configuration. A plan reads the namespace its storage names, or
// PBS_NAMESPACE where that is set.
func TestPlanAndRunResolveAndReadBackupsInTheNamespace(t *testing.T) {
	for name, tc := range map[string]struct{ planNS, env string }{
		"plan storage": {planNS: nsTenant},
		"environment":  {env: nsTenant},
	} {
		t.Run(name, func(t *testing.T) {
			node := newNSNode(t)
			t.Setenv("PBS_NAMESPACE", tc.env)
			plan := oneVMPlan(tc.planNS)
			if _, _, err := prepareRun(context.Background(), plan, Options{NodeName: "pve1", StateDir: t.TempDir(), ScratchDir: t.TempDir()}, t.TempDir()); err != nil {
				t.Fatalf("prepareRun = %v", err)
			}
			if got := plan.Tiers[0].VMs[0].SourcePBS.Snapshot; got != nsTenantLatest {
				t.Fatalf("latest resolved to %s, want the namespace's %s (the root's is %s)", got, nsTenantLatest, nsRootLatest)
			}
			node.requireNamespace(t, nsTenant, "version", "snapshot list", "snapshot files", "restore")
		})
	}
}

// doctor reads each source the way a run does, through CheckSources.
func TestDoctorChecksTheBackupsOfTheNamespace(t *testing.T) {
	node := newNSNode(t)
	t.Setenv("PBS_NAMESPACE", "")
	checks, err := CheckSources(context.Background(), oneVMPlan(nsTenant), Options{NodeName: "pve1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || checks[0].Status != SourcePassed || !strings.Contains(checks[0].Detail, nsTenantLatest) {
		t.Fatalf("checks = %+v, want the source to pass at the namespace's %s", checks, nsTenantLatest)
	}
	node.requireNamespace(t, nsTenant, "snapshot list", "snapshot files", "restore")
}

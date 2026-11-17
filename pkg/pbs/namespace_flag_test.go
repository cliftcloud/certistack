// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The product handed proxmox-backup-client its PBS namespace only as
// PBS_NAMESPACE. The 3.x client, the one on every PVE 8 node, ignores that
// variable and silently reads the ROOT namespace: the same group vm/7011 listed
// the 4 snapshots of the root namespace instead of the 2 of the namespace asked
// for, so a node would have listed, mapped and restored another tenant's data.
// These tests run the product against a stand-in client that behaves as 3.3.7
// does about the namespace, and in a second mode as 4.x, and hold every code
// path that runs the client to the same account: the namespace goes as --ns on
// each command that takes one, the data that comes back is the namespace's, and
// the environment variable is still set.

const (
	// nsTenant is a nested namespace, so that a path separator in the value
	// is shown to arrive whole.
	nsTenant = "tenant-a/site-1"
	// nsShared is a snapshot the root namespace and the tenant's both have,
	// with different content; nsTenantOnly is the tenant's newest, which the
	// root lacks. A client that reads the wrong namespace returns the root's
	// data for the first and a different "latest" for the group.
	nsShared     = "vm/7011/2026-09-26T03:00:00Z"
	nsTenantOnly = "vm/7011/2026-09-27T03:00:00Z"
	nsRootOld    = "vm/7011/2026-09-01T00:00:00Z"
	nsTenantVM2  = "vm/7012/2026-09-27T04:00:00Z"
	nsRootVM     = "vm/9000/2026-09-25T00:00:00Z"
)

// nsClientScript is proxmox-backup-client as 3.3.7 behaves about the
// namespace: it takes it from --ns and from nothing else. In mode "4x" it
// also reads PBS_NAMESPACE when no --ns is given, as 4.x does. It answers each
// command from the files of the namespace it ends up reading (the root's when
// none), rejects --ns where no client version accepts one (group list, unmap,
// version), and logs "subcommand|number of --ns|namespace read|PBS_NAMESPACE|
// arguments" for every call.
const nsClientScript = `#!/bin/sh
dir=$(dirname "$0")
mode=$(cat "$dir/mode")
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
if [ "$mode" = 4x ] && [ "$has" = 0 ] && [ -n "$PBS_NAMESPACE" ]; then ns=$PBS_NAMESPACE; fi
printf '%s|%s|%s|%s|%s\n' "$sub" "$has" "$ns" "${PBS_NAMESPACE-unset}" "$*" >> "$dir/calls"
case "$sub" in
  "group list"|unmap|version)
    if [ "$has" != 0 ]; then echo "Error: unknown option '--ns'" >&2; exit 1; fi;;
esac
key=$(printf '%s' "${ns:-root}" | tr / %)
d="$dir/ns/$key"
snap=; grp=; conf=
for a in "$@"; do
  case "$a" in
    vm/*/*|ct/*/*) snap=$a;;
    vm/*|ct/*) grp=$a;;
    qemu-server.conf.blob) conf=1;;
  esac
done
fkey() { printf '%s' "$1" | tr '/:' '--'; }
enoent() { echo "Error: ENOENT: No such file or directory" >&2; exit 1; }
case "$sub" in
  "group list") cat "$dir/ns/root/groups.json";;
  "snapshot list")
    if [ -z "$grp" ] && [ -f "$d/toobig" ]; then yes xxxxxxxxxxxxxxx | head -c "$(cat "$d/toobig")"; exit 0; fi
    if [ -n "$grp" ]; then f="$d/list-$(fkey "$grp").json"; else f="$d/list.json"; fi
    if [ -f "$f" ]; then cat "$f"; else echo '[]'; fi;;
  "snapshot files")
    f="$d/files-$(fkey "$snap").json"
    if [ -f "$f" ]; then cat "$f"; else enoent; fi;;
  restore)
    [ -f "$d/files-$(fkey "$snap").json" ] || enoent
    for last; do :; done
    if [ -n "$conf" ]; then
      printf '#ns=%s snapshot=%s\ncores: 2\nmemory: 2048\nbios: seabios\nscsi0: local:vm-7011-disk-0,size=1G\nboot: order=scsi0\n' "$key" "$snap" > "$last"
    else
      printf 'ns=%s snapshot=%s\n' "$key" "$snap" > "$last"
    fi;;
  map)
    [ -f "$d/files-$(fkey "$snap").json" ] || enoent
    if [ "$key" = root ]; then echo "Image 'drive-scsi0.img' mapped on /dev/loop8"; else echo "Image 'drive-scsi0.img' mapped on /dev/loop9"; fi;;
  version) printf 'client version: 3.3.7\nserver version: 3.4.1\n';;
  *) echo "unexpected: $*" >&2; exit 2;;
esac
`

// nsFake is the stand-in client installed on PATH, with the files it answers
// from.
type nsFake struct {
	t   *testing.T
	dir string
}

// nsEntry is one `snapshot list` entry.
func nsEntry(snapshot, crypt, fingerprint, comment string) string {
	parts := strings.Split(snapshot, "/")
	when, err := time.Parse(time.RFC3339, parts[2])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf(`{"backup-type":"%s","backup-id":"%s","backup-time":%d,"comment":"%s","fingerprint":"%s","files":[{"filename":"index.json.blob","crypt-mode":"none"},{"filename":"drive-scsi0.img.fidx","crypt-mode":"%s"}]}`,
		parts[0], parts[1], when.Unix(), comment, fingerprint, crypt)
}

// nsFiles is a `snapshot files` listing.
func nsFiles(crypt string) string {
	return fmt.Sprintf(`[{"filename":"qemu-server.conf.blob","crypt-mode":"%s","size":512},{"filename":"drive-scsi0.img.fidx","crypt-mode":"%s","size":1048576},{"filename":"index.json.blob","crypt-mode":"none","size":300}]`, crypt, crypt)
}

func nsFileKey(s string) string { return strings.NewReplacer("/", "-", ":", "-").Replace(s) }

const (
	nsRootFingerprint   = "aa:bb:cc:dd:ee:ff:00:11"
	nsTenantFingerprint = "11:22:33:44:55:66:77:88"
)

// newNSFake installs the stand-in client as mode ("3x" or "4x"), with a root
// namespace and the namespace nsTenant that answer differently:
//
//	root:      vm/7011 at nsRootOld and nsShared (encrypted, root key), vm/9000
//	nsTenant:  vm/7011 at nsShared and nsTenantOnly (not encrypted, tenant key), vm/7012
func newNSFake(t *testing.T, mode string) *nsFake {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	f := &nsFake{t: t, dir: t.TempDir()}
	f.write("proxmox-backup-client", nsClientScript, 0o755)
	f.write("mode", mode, 0o644)

	rootOld := nsEntry(nsRootOld, "encrypt", nsRootFingerprint, "root-old")
	rootShared := nsEntry(nsShared, "encrypt", nsRootFingerprint, "root-shared")
	rootVM := nsEntry(nsRootVM, "none", "", "root-9000")
	f.put("root", "list.json", "["+strings.Join([]string{rootOld, rootShared, rootVM}, ",")+"]")
	f.put("root", "list-vm-7011.json", "["+rootOld+","+rootShared+"]")
	f.put("root", "list-vm-9000.json", "["+rootVM+"]")
	f.put("root", "groups.json", `[{"backup-type":"vm","backup-id":"7011"},{"backup-type":"vm","backup-id":"9000"}]`)
	for _, snapshot := range []string{nsRootOld, nsShared} {
		f.put("root", "files-"+nsFileKey(snapshot)+".json", nsFiles("encrypt"))
	}
	f.put("root", "files-"+nsFileKey(nsRootVM)+".json", nsFiles("none"))

	key := strings.ReplaceAll(nsTenant, "/", "%")
	tenantShared := nsEntry(nsShared, "none", nsTenantFingerprint, "tenant-shared")
	tenantOnly := nsEntry(nsTenantOnly, "none", nsTenantFingerprint, "tenant-latest")
	tenantVM2 := nsEntry(nsTenantVM2, "none", "", "tenant-7012")
	f.put(key, "list.json", "["+strings.Join([]string{tenantShared, tenantOnly, tenantVM2}, ",")+"]")
	f.put(key, "list-vm-7011.json", "["+tenantShared+","+tenantOnly+"]")
	f.put(key, "list-vm-7012.json", "["+tenantVM2+"]")
	for _, snapshot := range []string{nsShared, nsTenantOnly, nsTenantVM2} {
		f.put(key, "files-"+nsFileKey(snapshot)+".json", nsFiles("none"))
	}

	t.Setenv("PATH", f.dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return f
}

func (f *nsFake) write(name, content string, perm os.FileMode) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(content), perm); err != nil {
		f.t.Fatal(err)
	}
}

func (f *nsFake) put(namespaceKey, name, content string) {
	f.t.Helper()
	dir := filepath.Join(f.dir, "ns", namespaceKey)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// nsCall is one logged call of the stand-in client.
type nsCall struct {
	Sub   string // "snapshot list", "map", "unmap" ...
	Flags int    // how many --ns it was given
	NS    string // the namespace the client read ("" is the root)
	EnvNS string // PBS_NAMESPACE as the client saw it, "unset" if absent
	Args  string
}

func (f *nsFake) calls() []nsCall {
	data, _ := os.ReadFile(filepath.Join(f.dir, "calls"))
	var calls []nsCall
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		p := strings.SplitN(line, "|", 5)
		flags, _ := strconv.Atoi(p[1])
		calls = append(calls, nsCall{Sub: p[0], Flags: flags, NS: p[2], EnvNS: p[3], Args: p[4]})
	}
	return calls
}

func (f *nsFake) reset() { _ = os.Remove(filepath.Join(f.dir, "calls")) }

// takesNS are the subcommands that take --ns in every client version (2.4.7,
// 3.3.7 and 4.2.5); group list, unmap and version take none.
var takesNS = map[string]bool{"snapshot list": true, "snapshot files": true, "map": true, "restore": true}

// checkNSCalls fails for any call that is not how the product must run the
// client for a configuration with namespace ns: the namespace as one --ns
// where the command takes it and none where it does not, the namespace the
// client read, and PBS_NAMESPACE still set.
func checkNSCalls(t *testing.T, calls []nsCall, ns string) {
	t.Helper()
	for _, call := range calls {
		switch {
		case takesNS[call.Sub] && (call.Flags != 1 || call.NS != ns):
			t.Errorf("%s was run with %d --ns and read namespace %q, want exactly one --ns %s\n  arguments: %s", call.Sub, call.Flags, call.NS, ns, call.Args)
		case !takesNS[call.Sub] && call.Flags != 0:
			t.Errorf("%s was given --ns, which no client version accepts there\n  arguments: %s", call.Sub, call.Args)
		}
		if ns != "" && call.EnvNS != ns {
			t.Errorf("%s ran with PBS_NAMESPACE=%q, want %q: the variable stays set for the 4.x client", call.Sub, call.EnvNS, ns)
		}
	}
}

type nsCase struct {
	// name is the function of this package that runs the client.
	name string
	// subs are the client subcommands it runs, in order.
	subs []string
	run  func(t *testing.T, c *Client)
}

func nsCases() []nsCase {
	ctx := context.Background()
	must := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	return []nsCase{
		{"LatestSnapshot", []string{"snapshot list"}, func(t *testing.T, c *Client) {
			got, err := c.LatestSnapshot(ctx, "vm/7011")
			must(t, err)
			if got != nsTenantOnly {
				t.Fatalf("latest of vm/7011 = %s, want the namespace's %s", got, nsTenantOnly)
			}
		}},
		{"ResolveSnapshot", []string{"snapshot list", "snapshot list"}, func(t *testing.T, c *Client) {
			for _, selector := range []string{"latest", "vm/7011/latest"} {
				got, err := c.ResolveSnapshot(ctx, selector, 7011)
				must(t, err)
				if got != nsTenantOnly {
					t.Fatalf("%s = %s, want the namespace's %s", selector, got, nsTenantOnly)
				}
			}
		}},
		{"ListVMBackups", []string{"snapshot list"}, func(t *testing.T, c *Client) {
			got, err := c.ListVMBackups(ctx)
			must(t, err)
			var ids []int
			for _, vm := range got {
				ids = append(ids, vm.VMID)
			}
			if !reflect.DeepEqual(ids, []int{7011, 7012}) || got[0].Latest != nsTenantOnly || got[0].Count != 2 || got[0].Comment != "tenant-latest" {
				t.Fatalf("ListVMBackups = %+v, want the namespace's VMs 7011 (latest %s, 2 snapshots) and 7012, not the root's", got, nsTenantOnly)
			}
		}},
		{"snapshotFiles", []string{"snapshot files"}, func(t *testing.T, c *Client) {
			files, err := c.snapshotFiles(ctx, nsShared)
			must(t, err)
			if mode, err := ParseSnapshotCryptMode(files); err != nil || mode != CryptModeNone {
				t.Fatalf("crypt mode of %s = %q, %v; want %q: the root's copy is encrypted (the live symptom, \"snapshot is encrypted\")", nsShared, mode, err, CryptModeNone)
			}
		}},
		{"missingSnapshot", []string{"snapshot files", "snapshot list"}, func(t *testing.T, c *Client) {
			_, err := c.snapshotFiles(ctx, "vm/7011/2026-09-20T03:00:00Z")
			if err == nil || !strings.Contains(err.Error(), `in PBS namespace "`+nsTenant+`"`) || !strings.Contains(err.Error(), "The newest snapshot of vm/7011 is "+nsTenantOnly) {
				t.Fatalf("the missing snapshot is explained as %v, want the namespace's newest, %s", err, nsTenantOnly)
			}
		}},
		{"snapshotKeyFingerprint", []string{"snapshot list"}, func(t *testing.T, c *Client) {
			got, err := c.snapshotKeyFingerprint(ctx, nsShared)
			must(t, err)
			if want := normalizeFingerprint(nsTenantFingerprint); got != want {
				t.Fatalf("key fingerprint of %s = %q, want the namespace's %q", nsShared, got, want)
			}
		}},
		{"restoreSourceConfig", []string{"restore"}, func(t *testing.T, c *Client) {
			data, err := c.restoreSourceConfig(ctx, nsShared, t.TempDir(), nil)
			must(t, err)
			if want := "#ns=" + strings.ReplaceAll(nsTenant, "/", "%") + " snapshot=" + nsShared; !strings.HasPrefix(string(data), want) {
				t.Fatalf("restored configuration starts %q, want %q: it came from another namespace", firstLine(data), want)
			}
		}},
		{"RestoreImage", []string{"restore"}, func(t *testing.T, c *Client) {
			target := filepath.Join(t.TempDir(), "efivars.raw")
			must(t, c.RestoreImage(ctx, nsShared, "drive-efidisk0", target))
			data, err := os.ReadFile(target)
			must(t, err)
			if want := "ns=" + strings.ReplaceAll(nsTenant, "/", "%") + " snapshot=" + nsShared; strings.TrimSpace(string(data)) != want {
				t.Fatalf("restored image = %q, want %q: it came from another namespace", data, want)
			}
		}},
		{"MapWithToken", []string{"map"}, func(t *testing.T, c *Client) {
			token, err := NewMapToken()
			must(t, err)
			device, err := c.MapWithToken(ctx, nsShared, "drive-scsi0", token)
			must(t, err)
			if device != "/dev/loop9" {
				t.Fatalf("mapped %s on %s, want the namespace's map (/dev/loop9), not the root's (/dev/loop8)", nsShared, device)
			}
		}},
		{"LoadVMLayout", []string{"snapshot files", "restore"}, func(t *testing.T, c *Client) {
			layout, err := c.LoadVMLayout(ctx, nsShared, t.TempDir())
			must(t, err)
			if layout.CryptMode != CryptModeNone || !reflect.DeepEqual(layout.Disks, []string{"scsi0"}) {
				t.Fatalf("layout = %+v, want the namespace's: not encrypted, disk scsi0", layout)
			}
		}},
		{"LoadVMProfile", []string{"snapshot files", "restore"}, func(t *testing.T, c *Client) {
			profile, err := c.LoadVMProfile(ctx, nsShared, t.TempDir())
			must(t, err)
			if profile.CryptMode != CryptModeNone || profile.Cores != 2 || profile.MemoryMB != 2048 {
				t.Fatalf("profile = %+v, want the namespace's", profile)
			}
		}},
	}
}

func firstLine(data []byte) string {
	line, _, _ := strings.Cut(string(data), "\n")
	return line
}

// Every code path that runs the client for a configuration with a namespace
// gives it as --ns, on the commands that take one, and the data that comes
// back is the namespace's. The client stand-in reads no PBS_NAMESPACE (3.x),
// or reads it only when no --ns is given (4.x); the account is the same.
func TestEveryClientCommandIsGivenTheNamespaceAsAnOption(t *testing.T) {
	for _, mode := range []string{"3x", "4x"} {
		for _, tc := range nsCases() {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				fake := newNSFake(t, mode)
				c := New(Config{Repository: "certistack@pbs!restore@pbs.example:8007:pbs-data", Namespace: nsTenant})
				tc.run(t, c)
				calls := fake.calls()
				var subs []string
				for _, call := range calls {
					subs = append(subs, call.Sub)
				}
				if !reflect.DeepEqual(subs, tc.subs) {
					t.Fatalf("the client was run for %v, want %v", subs, tc.subs)
				}
				checkNSCalls(t, calls, nsTenant)
			})
		}
	}
}

// The same paths without a namespace read the root and give no --ns: nothing
// changes for a configuration that has none.
func TestWithoutANamespaceNoCommandIsGivenOne(t *testing.T) {
	fake := newNSFake(t, "3x")
	c := New(Config{Repository: "certistack@pbs!restore@pbs.example:8007:pbs-data"})
	ctx := context.Background()
	if got, err := c.LatestSnapshot(ctx, "vm/7011"); err != nil || got != nsShared {
		t.Fatalf("latest of vm/7011 in the root = %q, %v, want %s", got, err, nsShared)
	}
	if _, err := c.snapshotFiles(ctx, nsShared); err != nil {
		t.Fatal(err)
	}
	if device, err := c.Map(ctx, nsShared, "drive-scsi0"); err != nil || device != "/dev/loop8" {
		t.Fatalf("Map = %q, %v", device, err)
	}
	calls := fake.calls()
	if len(calls) != 3 {
		t.Fatalf("calls = %+v", calls)
	}
	for _, call := range calls {
		if call.Flags != 0 || call.EnvNS != "unset" || strings.Contains(call.Args, "--ns") {
			t.Errorf("%s was given a namespace for a configuration without one: %+v", call.Sub, call)
		}
	}
}

// A namespace that begins with "-" is joined to the option, never read as an
// option of the command.
func TestANamespaceThatBeginsWithADashIsJoinedToTheOption(t *testing.T) {
	c := New(Config{Namespace: "-x"})
	if got := c.namespaceArgs(); !reflect.DeepEqual(got, []string{"--ns=-x"}) {
		t.Fatalf("namespaceArgs = %q", got)
	}
	if got := New(Config{Namespace: "a/b"}).namespaceArgs(); !reflect.DeepEqual(got, []string{"--ns", "a/b"}) {
		t.Fatalf("namespaceArgs = %q", got)
	}
	if got := New(Config{}).namespaceArgs(); got != nil {
		t.Fatalf("namespaceArgs without a namespace = %q", got)
	}
}

// Nor does version, which reads no backup data.
func TestVersionIsGivenNoNamespaceOption(t *testing.T) {
	fake := newNSFake(t, "3x")
	client, server, err := New(Config{Namespace: nsTenant}).Versions(context.Background())
	if err != nil || client != "3.3.7" || server != "3.4.1" {
		t.Fatalf("Versions = %q, %q, %v", client, server, err)
	}
	checkNSCalls(t, fake.calls(), nsTenant)
	if calls := fake.calls(); len(calls) != 1 || calls[0].Sub != "version" {
		t.Fatalf("calls = %+v", calls)
	}
}

// A new place that runs the client must be added to the table above, so that
// it is held to the same account. This lists every function of the package
// that runs the client, through command, run or runLimited, and every file of
// the product that starts the program.
func TestEveryPlaceThatRunsTheClientIsInTheNamespaceTable(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range nsCases() {
		covered[tc.name] = true
	}
	// Covered by tests of their own. (Unmap runs no client command at all:
	// TestUnmapRunsNoClientCommand.)
	for _, name := range []string{"Versions", "listBackupGroups", "listVMBackupsByGroup"} {
		covered[name] = true
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	callers := map[string]bool{}
	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == "run" || fn.Name.Name == "runLimited" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if receiver, ok := selector.X.(*ast.Ident); ok && receiver.Name == "c" {
					switch selector.Sel.Name {
					case "command", "run", "runLimited":
						callers[fn.Name.Name] = true
					}
				}
				return true
			})
		}
	}
	var names []string
	for name := range callers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !covered[name] {
			t.Errorf("%s runs the client but is in no namespace test: add it to nsCases", name)
		}
	}
	if len(names) < 10 {
		t.Fatalf("found only %v: the search for the client's call sites is broken", names)
	}

	// Outside this package no place starts the client: recovery stops the map's
	// daemon itself instead of running the client's `unmap` (which takes no --ns).
	starts := map[string]bool{}
	for _, root := range []string{"../../pkg", "../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(parsed, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (selector.Sel.Name != "Command" && selector.Sel.Name != "CommandContext") {
					return true
				}
				for _, arg := range call.Args {
					if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value == `"proxmox-backup-client"` {
						starts[strings.TrimPrefix(filepath.ToSlash(path), "../../")] = true
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]bool{"pkg/pbs/pbs.go": true}
	if !reflect.DeepEqual(starts, want) {
		t.Fatalf("files that start proxmox-backup-client: %v, want %v; a new one must give the namespace as --ns", starts, want)
	}
}

// The client's `group list` takes no --ns in any version, and the 3.x client
// ignores PBS_NAMESPACE, so for a namespace the backup groups of a repository
// whose whole snapshot list is too long to read come from the PBS API, which
// takes the namespace; the root's own list is never read instead.
func TestListVMBackupsOfALargeNamespaceReadsItsGroupsThroughTheAPI(t *testing.T) {
	var apiRequests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiRequests = append(apiRequests, r.URL.Path+"?"+r.URL.RawQuery)
		if r.URL.Path != "/api2/json/admin/datastore/pbs-data/groups" || r.Header.Get("Authorization") != "PBSAPIToken=certistack@pbs!restore:s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Query().Get("ns") {
		case nsTenant:
			_, _ = w.Write([]byte(`{"data":[{"backup-type":"vm","backup-id":"7012","backup-count":1},{"backup-type":"ct","backup-id":"200"},` +
				`{"backup-type":"vm","backup-id":"7011","backup-count":2},{"backup-type":"host","backup-id":"pve1"}]}`))
		case "forbidden":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"data":null,"message":"permission check failed"}`))
		case "null":
			_, _ = w.Write([]byte(`{"data":null}`))
		default: // the root, or any namespace that is not asked for: another tenant's list
			_, _ = w.Write([]byte(`{"data":[{"backup-type":"vm","backup-id":"9000"}]}`))
		}
	}))
	t.Cleanup(server.Close)
	sum := sha256.Sum256(server.Certificate().Raw)
	repository := "certistack@pbs!restore@" + strings.TrimPrefix(server.URL, "https://") + ":pbs-data"
	config := func(namespace, password string) Config {
		return Config{Repository: repository, Password: password, Fingerprint: hex.EncodeToString(sum[:]), Namespace: namespace}
	}
	tooBig := func(f *nsFake, namespaceKey string) {
		f.put(namespaceKey, "toobig", strconv.Itoa(pbsListOutputLimit+1))
	}
	ctx := context.Background()

	for _, mode := range []string{"3x", "4x"} {
		t.Run(mode, func(t *testing.T) {
			fake := newNSFake(t, mode)
			tooBig(fake, strings.ReplaceAll(nsTenant, "/", "%"))
			apiRequests = nil
			got, err := New(config(nsTenant, "s3cret")).ListVMBackups(ctx)
			if err != nil {
				t.Fatalf("ListVMBackups = %v", err)
			}
			var ids []int
			for _, vm := range got {
				ids = append(ids, vm.VMID)
			}
			if !reflect.DeepEqual(ids, []int{7011, 7012}) || got[0].Latest != nsTenantOnly {
				t.Fatalf("ListVMBackups = %+v, want the namespace's VMs 7011 and 7012", got)
			}
			var subs []string
			for _, call := range fake.calls() {
				subs = append(subs, call.Sub+" "+firstWord(call.Args, "vm/"))
			}
			if want := []string{"snapshot list ", "snapshot list vm/7011", "snapshot list vm/7012"}; !reflect.DeepEqual(subs, want) {
				t.Fatalf("the client was run for %q, want %q: the whole list, then each VM's, and no group list", subs, want)
			}
			checkNSCalls(t, fake.calls(), nsTenant)
			if len(apiRequests) != 1 || !strings.HasSuffix(apiRequests[0], "?ns=tenant-a%2Fsite-1") {
				t.Fatalf("API requests = %q, want one for the groups of the namespace", apiRequests)
			}
		})
	}

	t.Run("refusals name the namespace and the cause, and list nothing", func(t *testing.T) {
		fake := newNSFake(t, "3x")
		for _, tc := range []struct {
			name, namespace, password, want string
		}{
			{"the API refuses the user", "forbidden", "s3cret", "HTTP 403: permission check failed"},
			{"the API answers with no list", "null", "s3cret", "no list of backup groups"},
			{"no secret to ask the API with", nsTenant, "", "no PBS password or API token secret is configured"},
		} {
			fake.put(strings.ReplaceAll(tc.namespace, "/", "%"), "toobig", strconv.Itoa(pbsListOutputLimit+1))
			got, err := New(config(tc.namespace, tc.password)).ListVMBackups(ctx)
			if err == nil || got != nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), `namespace "`+tc.namespace+`"`) {
				t.Errorf("%s: ListVMBackups = %+v, %v; want a failure naming the namespace and %q, and no list", tc.name, got, err, tc.want)
			}
		}
	})

	t.Run("a repository without a namespace keeps the client's group list", func(t *testing.T) {
		fake := newNSFake(t, "3x")
		tooBig(fake, "root")
		apiRequests = nil
		got, err := New(config("", "s3cret")).ListVMBackups(ctx)
		if err != nil {
			t.Fatalf("ListVMBackups = %v", err)
		}
		if len(got) != 2 || got[0].VMID != 7011 || got[1].VMID != 9000 {
			t.Fatalf("ListVMBackups = %+v, want the root's VMs 7011 and 9000", got)
		}
		var subs []string
		for _, call := range fake.calls() {
			subs = append(subs, call.Sub)
			if call.Flags != 0 {
				t.Errorf("%s was given --ns", call.Sub)
			}
		}
		if want := []string{"snapshot list", "group list", "snapshot list", "snapshot list"}; !reflect.DeepEqual(subs, want) {
			t.Fatalf("calls %q, want %q", subs, want)
		}
		if len(apiRequests) != 0 {
			t.Fatalf("the API was asked for the groups of the root: %q", apiRequests)
		}
	})
}

// firstWord is the first word of args that begins with prefix, or "".
func firstWord(args, prefix string) string {
	for _, word := range strings.Fields(args) {
		if strings.HasPrefix(word, prefix) {
			return word
		}
	}
	return ""
}

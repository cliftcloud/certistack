// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// largeRepository installs a proxmox-backup-client for a repository with VMs 100,
// 101, 102 and 103 (and a container). Its whole snapshot list is longer than the
// 16 MiB CertiStack reads when tooBig is set, as a repository of a few tens of
// thousands of snapshots is; its group list and the per-group snapshot lists are
// small either way. Every call and the PBS_NAMESPACE it saw are logged.
func largeRepository(t *testing.T, tooBig bool, groupList string) (calls func() string) {
	t.Helper()
	_, calls = largeRepositoryAt(t, tooBig, groupList)
	return calls
}

// largeRepositoryAt is largeRepository that also says where its files are, so
// that a test can change what one group's listing answers.
func largeRepositoryAt(t *testing.T, tooBig bool, groupList string) (dir string, calls func() string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	dir = t.TempDir()
	vm100 := `{"backup-type":"vm","backup-id":"100","backup-time":1790000000,"files":[{"filename":"drive-scsi0.img.fidx"},{"filename":"index.json.blob"}],"comment":"web\u0007 01"}`
	vm101 := `{"backup-type":"vm","backup-id":"101","backup-time":1790000000,"files":[{"filename":"drive-scsi0.img.fidx"},{"filename":"index.json.blob"}],"comment":"db01"},` +
		`{"backup-type":"vm","backup-id":"101","backup-time":1790086400,"files":[{"filename":"drive-scsi0.img.fidx"},{"filename":"index.json.blob"}],"comment":"db01-new"},` +
		`{"backup-type":"vm","backup-id":"101","backup-time":1790172800,"files":[{"filename":"drive-scsi0.img.fidx"}]}`
	vm102 := `{"backup-type":"vm","backup-id":"102","backup-time":1790000000,"files":[{"filename":"drive-scsi0.img.fidx"}]}`
	vm103 := `{"backup-type":"vm","backup-id":"103","backup-time":1790000000}`
	ct200 := `{"backup-type":"ct","backup-id":"200","backup-time":1790000000,"files":[{"filename":"index.json.blob"}]}`
	files := map[string]string{
		"vm-100": "[" + vm100 + "]",
		"vm-101": "[" + vm101 + "]",
		"vm-102": "[" + vm102 + "]",
		"vm-103": "[" + vm103 + "]",
		"ct-200": "[" + ct200 + "]",
		"whole":  "[" + strings.Join([]string{vm100, vm101, vm102, vm103, ct200}, ",") + "]",
		"groups": groupList,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wholeCommand := `cat "$dir/whole.json"`
	if tooBig {
		wholeCommand = `yes xxxxxxxxxxxxxxx | head -c ` + strconv.Itoa(pbsListOutputLimit+1)
	}
	script := `#!/bin/sh
dir=$(dirname "$0")
echo "$* ns=${PBS_NAMESPACE}" >> "$dir/calls"
case "$1 $2" in
"group list") cat "$dir/groups.json"; exit 0;;
"snapshot list")
  case "$3" in
  --output-format) ` + wholeCommand + `; exit 0;;
  vm/*|ct/*) cat "$dir/$(echo "$3" | tr / -).json"; exit $?;;
  esac;;
esac
echo "unexpected: $*" >&2
exit 2
`
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir, func() string {
		data, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return string(data)
	}
}

const largeGroups = `[{"backup-type":"vm","backup-id":"103"},{"backup-type":"ct","backup-id":"200"},{"backup-type":"vm","backup-id":"100"},` +
	`{"backup-type":"host","backup-id":"pve1"},{"backup-type":"vm","backup-id":"102"},{"backup-type":"vm","backup-id":"101"},{"backup-type":"vm","backup-id":"not-a-number"}]`

// A repository whose whole snapshot list is longer than the cap could not be
// listed by init's discovery: it failed, fail closed, at about 25,000 snapshots.
// It is now read VM by VM, and the result is what the whole list gives.
func TestListVMBackupsReadsALargeRepositoryVMByVM(t *testing.T) {
	// No namespace: the client's group list reads the root namespace only, so
	// it is used for nothing else (the listing of a namespace's groups is
	// TestListVMBackupsOfALargeNamespaceReadsItsGroupsThroughTheAPI).
	client := New(Config{Repository: "u@pbs!tok@pbs.example:store"})

	calls := largeRepository(t, false, largeGroups)
	want, err := client.ListVMBackups(context.Background())
	if err != nil || len(want) != 3 {
		t.Fatalf("ListVMBackups = %+v, %v; want VMs 100, 101 and 103 from one listing", want, err)
	}
	if got := strings.TrimSpace(calls()); strings.Contains(got, "\n") || !strings.HasPrefix(got, "snapshot list --output-format json") {
		t.Fatalf("a repository that fits is listed once; calls:\n%s", got)
	}

	calls = largeRepository(t, true, largeGroups)
	got, err := client.ListVMBackups(context.Background())
	if err != nil {
		t.Fatalf("ListVMBackups of a repository over the cap = %v; want it listed VM by VM", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("listed VM by VM: %+v\nlisted at once: %+v", got, want)
	}
	log := calls()
	for _, line := range []string{
		"group list --output-format json --repository u@pbs!tok@pbs.example:store ns=",
		"snapshot list vm/100 --output-format json --repository u@pbs!tok@pbs.example:store ns=",
		"snapshot list vm/101 --output-format json --repository u@pbs!tok@pbs.example:store ns=",
		"snapshot list vm/102 --output-format json --repository u@pbs!tok@pbs.example:store ns=",
		"snapshot list vm/103 --output-format json --repository u@pbs!tok@pbs.example:store ns=",
	} {
		if !strings.Contains(log, line+"\n") {
			t.Errorf("calls:\n%s\nlack %q", log, line)
		}
	}
	if strings.Contains(log, "ct/200") || strings.Contains(log, "host") || strings.Contains(log, "not-a-number") {
		t.Errorf("calls:\n%s\nasked about a container, a host or a bad ID", log)
	}
}

// It does not become a partial list: a listing that fails fails the whole.
func TestListVMBackupsByGroupNeverReturnsAPartialList(t *testing.T) {
	client := New(Config{Repository: "u@pbs!tok@pbs.example:store"})

	// A group whose snapshots the client cannot list.
	largeRepository(t, true, `[{"backup-type":"vm","backup-id":"100"},{"backup-type":"vm","backup-id":"999"},{"backup-type":"vm","backup-id":"101"}]`)
	if got, err := client.ListVMBackups(context.Background()); err == nil || got != nil || !strings.Contains(err.Error(), "vm/999") {
		t.Fatalf("ListVMBackups = %+v, %v; want the failure naming vm/999 and no list", got, err)
	}

	// A group list that is not a list.
	largeRepository(t, true, `{"not":"a list"}`)
	if got, err := client.ListVMBackups(context.Background()); err == nil || got != nil || !strings.Contains(err.Error(), "backup group list") {
		t.Fatalf("ListVMBackups = %+v, %v; want the group list refused", got, err)
	}

	// Past its own cap the group list is refused as any listing is.
	largeRepository(t, true, "["+strings.Repeat(`{"backup-type":"vm","backup-id":"100"},`, pbsListOutputLimit/30)+`{"backup-type":"vm","backup-id":"101"}]`)
	if got, err := client.ListVMBackups(context.Background()); err == nil || got != nil || !strings.Contains(err.Error(), "wrote more output than CertiStack accepts") {
		t.Fatalf("ListVMBackups = %+v, %v; want the oversized group list refused", got, err)
	}

	// A cancelled listing stops between groups.
	largeRepository(t, true, largeGroups)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := client.ListVMBackups(ctx); err == nil || got != nil {
		t.Fatalf("ListVMBackups with a cancelled context = %+v, %v", got, err)
	}
}

// The ListVMBackups follow-up: two defences of the listing by VM that its
// report called tested were not. A client that answers a request for one VM's
// snapshots with another VM's must be refused, not merged, or one VM's backups
// would be listed under another's number; and a listing whose context ends
// between two groups stops there, with the cancellation, and does not ask about
// the rest.
func TestListVMBackupsByGroupRefusesAClientThatAnswersForAnotherGroup(t *testing.T) {
	client := New(Config{Repository: "u@pbs!tok@pbs.example:store"})
	vm102 := `[{"backup-type":"vm","backup-id":"102","backup-time":1790000000,"files":[{"filename":"drive-scsi0.img.fidx"},{"filename":"index.json.blob"}]}]`
	both := `[{"backup-type":"vm","backup-id":"101","backup-time":1790000000,"files":[{"filename":"drive-scsi0.img.fidx"},{"filename":"index.json.blob"}]},` +
		`{"backup-type":"vm","backup-id":"102","backup-time":1790000000,"files":[{"filename":"drive-scsi0.img.fidx"},{"filename":"index.json.blob"}]}]`
	for name, answer := range map[string]string{"another VM's snapshots": vm102, "this VM's and another's": both} {
		t.Run(name, func(t *testing.T) {
			dir, _ := largeRepositoryAt(t, true, largeGroups)
			if err := os.WriteFile(filepath.Join(dir, "vm-101.json"), []byte(answer), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := client.ListVMBackups(context.Background())
			if err == nil || got != nil || !strings.Contains(err.Error(), "list PBS snapshots for vm/101: the client listed snapshots of other backup groups") {
				t.Fatalf("ListVMBackups = %+v, %v; want the answer for the wrong group refused and no list", got, err)
			}
		})
	}
}

func TestListVMBackupsByGroupStopsBetweenGroupsWhenItsContextEnds(t *testing.T) {
	client := New(Config{Repository: "u@pbs!tok@pbs.example:store"})
	calls := largeRepository(t, true, largeGroups)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	previous := groupListed
	t.Cleanup(func() { groupListed = previous })
	groupListed = func(vmid int) {
		if vmid == 100 {
			cancel() // the first group has been listed in full; the run is interrupted
		}
	}
	got, err := client.ListVMBackups(ctx)
	if err == nil || got != nil || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "list PBS snapshots by VM") {
		t.Fatalf("ListVMBackups = %+v, %v; want the cancellation, from the check between groups, and no list", got, err)
	}
	if log := calls(); !strings.Contains(log, "snapshot list vm/100 ") || strings.Contains(log, "snapshot list vm/101 ") {
		t.Errorf("calls:\n%s\nwant the first group listed and the second never asked about", log)
	}
}

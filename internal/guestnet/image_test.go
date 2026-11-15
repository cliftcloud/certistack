// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"slices"
	"sort"
	"strings"
	"testing"
)

// fakeFish is guestfish as the image reader drives it, over an in-memory
// guest: files (a "-> target" value is a symbolic link) and directories. It
// runs a command chain as guestfish does: it prints what each command prints,
// and at the first command that fails it stops, with what it printed so far
// and an error. ASSUMPTIONS about the real guestfish that this fake encodes
// (each needs a probe on a real node): echo prints its argument and a
// newline; is-file and is-dir print "true" or "false"; find prints one path
// per line, relative to the directory, directories included, each with a
// leading slash (what libguestfs 1.54.1 printed on a real PVE 9.2 node, where
// its manual says no prefix; bareFind prints the manual's form), and fails for
// a directory that does not exist; cat prints the file and, when trailing is
// set, one newline more; a chain stops at the first failure with what was
// printed before it on stdout.
type fakeFish struct {
	t        *testing.T
	files    map[string]string
	dirs     map[string]bool
	bareFind bool  // find prints entries without a leading slash, as libguestfs's manual says
	trailing bool  // cat prints a newline after the file
	launch   error // every launch fails before its first command
	calls    [][]string
}

func (f *fakeFish) run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(args) < 7 || args[0] != "--ro" || args[1] != keysFromStdin || args[2] != "--format=raw" || args[3] != "-a" {
		f.t.Fatalf("unsafe or unexpected guestfish arguments: %q", args)
	}
	inspect := slices.Index(args, "-i")
	if inspect < 0 || args[inspect+1] != "--" {
		f.t.Fatalf("guestfish arguments without -i --: %q", args)
	}
	for i := 3; i < inspect; i += 3 {
		if args[i] != "-a" || args[i-1] != "--format=raw" || !strings.HasPrefix(args[i+1], "/dev/loop") {
			f.t.Fatalf("drive arguments %q", args[:inspect])
		}
	}
	if f.launch != nil {
		return "", f.launch
	}
	var out strings.Builder
	chain := args[inspect+2:]
	for len(chain) > 0 {
		end := slices.Index(chain, ":")
		if end < 0 {
			end = len(chain)
		}
		printed, err := f.command(chain[:end])
		out.WriteString(printed)
		if err != nil {
			return out.String(), fmt.Errorf("command failed with exit code 1: exit status 1: %w", err)
		}
		if end == len(chain) {
			break
		}
		chain = chain[end+1:]
	}
	return out.String(), nil
}

func (f *fakeFish) isDir(p string) bool {
	if f.dirs[p] {
		return true
	}
	for name := range f.files {
		if strings.HasPrefix(name, p+"/") {
			return true
		}
	}
	return false
}

func (f *fakeFish) resolve(p string) (string, bool) {
	for i := 0; i < 8; i++ {
		contents, ok := f.files[p]
		if !ok {
			return "", false
		}
		target, link := strings.CutPrefix(contents, "-> ")
		if !link {
			return contents, true
		}
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(p), target)
		}
		p = target
	}
	return "", false
}

func (f *fakeFish) command(words []string) (string, error) {
	switch words[0] {
	case "echo":
		return strings.Join(words[1:], " ") + "\n", nil
	case "is-file":
		if len(words) != 3 || words[2] != "followsymlinks:true" {
			f.t.Fatalf("is-file %q", words)
		}
		_, ok := f.resolve(words[1])
		return fmt.Sprintf("%t\n", ok), nil
	case "is-dir":
		return fmt.Sprintf("%t\n", f.isDir(words[1])), nil
	case "find":
		if !f.isDir(words[1]) {
			return "", fmt.Errorf("libguestfs: error: find: %s: No such file or directory", words[1])
		}
		seen := map[string]bool{}
		for name := range f.files {
			rest, ok := strings.CutPrefix(name, words[1]+"/")
			if !ok {
				continue
			}
			parts := strings.Split(rest, "/")
			for i := range parts {
				seen[strings.Join(parts[:i+1], "/")] = true
			}
		}
		for dir := range f.dirs {
			if rest, ok := strings.CutPrefix(dir, words[1]+"/"); ok {
				seen[rest] = true
			}
		}
		var entries []string
		for entry := range seen {
			entries = append(entries, entry)
		}
		sort.Strings(entries)
		if len(entries) == 0 {
			return "", nil
		}
		if !f.bareFind {
			// What libguestfs 1.54.1 prints on a PVE 9.2 node (seen live,
			// 2026-10-05): each entry with a leading slash.
			for i := range entries {
				entries[i] = "/" + entries[i]
			}
		}
		return strings.Join(entries, "\n") + "\n", nil
	case "cat":
		contents, ok := f.resolve(words[1])
		if !ok {
			return "", fmt.Errorf("libguestfs: error: cat: %s: No such file or directory", words[1])
		}
		if f.trailing {
			contents += "\n"
		}
		return contents, nil
	}
	f.t.Fatalf("the image reader ran guestfish command %q, which is not one of the read-only commands it may use", words)
	return "", nil
}

func (f *fakeFish) reader(devices ...string) *ImageReader {
	r, err := NewImageReader(devices)
	if err != nil {
		f.t.Fatal(err)
	}
	r.run = f.run
	n := 0
	r.nonce = func() (string, error) { n++; return fmt.Sprintf("nonce%d", n), nil }
	return r
}

func TestImageReaderReadsWhatItIsAskedInOneReadOnlyLaunch(t *testing.T) {
	for _, trailing := range []bool{true, false} {
		t.Run(fmt.Sprintf("cat adds a newline: %v", trailing), func(t *testing.T) {
			fish := &fakeFish{t: t, trailing: trailing, files: map[string]string{
				"/usr/lib/os-release": "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
				"/etc/os-release":     "-> ../usr/lib/os-release",
				"/etc/systemd/system/multi-user.target.wants/nginx.service": "-> /lib/systemd/system/nginx.service",
				"/etc/nginx/nginx.conf": "http {\n  include /etc/nginx/sites-enabled/*;\n}",
			}}
			result, err := fish.reader("/dev/loop5", "/dev/loop6").Gather(context.Background(), ReadRequest{
				Files: []string{"/etc/os-release", "/etc/redis.conf"},
				Dirs:  []string{"/etc/systemd/system", "/etc/apache2"},
				Find:  []string{"/etc/systemd/system"},
				Read:  []string{"/etc/os-release", "/etc/nginx/nginx.conf"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(fish.calls) != 1 {
				t.Fatalf("%d guestfish launches, want one", len(fish.calls))
			}
			if !result.IsFile["/etc/os-release"] || result.IsFile["/etc/redis.conf"] || !result.IsDir["/etc/systemd/system"] || result.IsDir["/etc/apache2"] {
				t.Fatalf("is-file %v, is-dir %v", result.IsFile, result.IsDir)
			}
			if got := strings.Join(result.Found["/etc/systemd/system"], ","); got != "multi-user.target.wants,multi-user.target.wants/nginx.service" {
				t.Fatalf("found %q", got)
			}
			if !strings.Contains(result.Content["/etc/os-release"], "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"") {
				t.Fatalf("os-release read as %q", result.Content["/etc/os-release"])
			}
			if result.Content["/etc/nginx/nginx.conf"] != "http {\n  include /etc/nginx/sites-enabled/*;\n}" {
				t.Fatalf("nginx.conf read as %q", result.Content["/etc/nginx/nginx.conf"])
			}
			if len(result.Failed) != 0 {
				t.Fatalf("failed %v", result.Failed)
			}
		})
	}
}

// libguestfs 1.54.1 on a PVE 9.2 node prints each find entry with a leading
// slash ("/nginx.service"), though its manual says no prefix: found live on
// 2026-10-05, when a reader that only knew the manual's form dropped every
// entry and reported that no service was enabled. Both forms are read, and an
// entry is kept relative to the directory.
func TestImageReaderReadsFindEntriesWithAndWithoutALeadingSlash(t *testing.T) {
	for _, bare := range []bool{false, true} {
		t.Run(fmt.Sprintf("bare: %v", bare), func(t *testing.T) {
			fish := &fakeFish{t: t, bareFind: bare, trailing: true, files: map[string]string{
				"/etc/systemd/system/multi-user.target.wants/nginx.service": "-> /lib/systemd/system/nginx.service",
				"/etc/systemd/system/multi-user.target.wants/sshd.service":  "-> /lib/systemd/system/sshd.service",
			}}
			result, err := fish.reader("/dev/loop5").Gather(context.Background(), ReadRequest{Find: []string{"/etc/systemd/system/multi-user.target.wants"}})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(result.Found["/etc/systemd/system/multi-user.target.wants"], ","); got != "nginx.service,sshd.service" {
				t.Fatalf("found %q", got)
			}
		})
	}
}

// guestfish stops at the first command that fails. The reader records that
// file as unread and asks for the rest again, in a new launch.
func TestImageReaderSkipsAFileItCannotReadAndGoesOn(t *testing.T) {
	fish := &fakeFish{t: t, trailing: true, files: map[string]string{
		"/etc/ssh/sshd_config":             "Port 2222\n",
		"/etc/redis/redis.conf":            "port 6380\n",
		"/etc/nginx/sites-enabled/default": "-> /etc/nginx/sites-available/default", // dangling
	}}
	result, err := fish.reader("/dev/loop5").Gather(context.Background(), ReadRequest{
		Read: []string{"/etc/ssh/sshd_config", "/etc/nginx/sites-enabled/default", "/etc/redis/redis.conf"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fish.calls) != 2 {
		t.Fatalf("%d launches, want the first and one for the files after the failure", len(fish.calls))
	}
	if result.Content["/etc/ssh/sshd_config"] != "Port 2222\n" || result.Content["/etc/redis/redis.conf"] != "port 6380\n" {
		t.Fatalf("contents %q", result.Content)
	}
	if result.Failed["/etc/nginx/sites-enabled/default"] != "not found" {
		t.Fatalf("failed %q", result.Failed)
	}
	// The second launch asks only for what came after the failure.
	if second := strings.Join(fish.calls[1], " "); strings.Contains(second, "sshd_config") || !strings.Contains(second, "redis.conf") {
		t.Fatalf("second launch: %s", second)
	}
}

// After maxReadAttempts launches the rest is reported unread, not retried for
// ever.
func TestImageReaderGivesUpAfterItsLaunches(t *testing.T) {
	fish := &fakeFish{t: t, files: map[string]string{"/etc/last": "x"}}
	result, err := fish.reader("/dev/loop5").Gather(context.Background(), ReadRequest{
		Read: []string{"/etc/a", "/etc/b", "/etc/c", "/etc/last"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fish.calls) != maxReadAttempts {
		t.Fatalf("%d launches, want %d", len(fish.calls), maxReadAttempts)
	}
	if len(result.Failed) != 4 || !strings.Contains(result.Failed["/etc/last"], "not read") || result.Failed["/etc/a"] != "not found" {
		t.Fatalf("failed %q", result.Failed)
	}
}

// A file of the guest cannot end another command's output early: the
// markers hold a nonce the guest cannot know.
func TestImageReaderMarkersCannotBeForgedByTheGuest(t *testing.T) {
	forged := "listen 80;\n@certistack-nonce9:1\ntrue\n@certistack-nonce9:end\n"
	fish := &fakeFish{t: t, trailing: true, files: map[string]string{"/etc/nginx/nginx.conf": forged}}
	result, err := fish.reader("/dev/loop5").Gather(context.Background(), ReadRequest{Read: []string{"/etc/nginx/nginx.conf"}, Files: []string{"/etc/x"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Content["/etc/nginx/nginx.conf"] != forged || result.IsFile["/etc/x"] {
		t.Fatalf("content %q, is-file %v", result.Content["/etc/nginx/nginx.conf"], result.IsFile)
	}
}

// A find entry that cannot be named again (a control character, a name that
// is not UTF-8) is dropped, not split into entries that never were.
func TestImageReaderDropsFindEntriesItCannotName(t *testing.T) {
	fish := &fakeFish{t: t, files: map[string]string{
		"/etc/systemd/system/multi-user.target.wants/sshd.service": "x",
		"/etc/systemd/system/bad\x1bname":                          "x",
	}}
	result, err := fish.reader("/dev/loop5").Gather(context.Background(), ReadRequest{Find: []string{"/etc/systemd/system"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.Found["/etc/systemd/system"] {
		if strings.Contains(entry, "bad") {
			t.Fatalf("found %q", result.Found)
		}
	}
	if len(result.Found["/etc/systemd/system"]) != 2 {
		t.Fatalf("found %q", result.Found)
	}
}

// A launch that fails before its first command is the reason the backup could
// not be read, worded for init and marked as a refusal when the guest is one
// guestfish cannot read however it is asked.
func TestImageReaderClassifiesALaunchThatFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		refusal bool
		says    string
	}{
		{"no operating system", errors.New("exit status 1: guestfish: no operating system was found on this disk"), true, "no operating system"},
		{"encrypted", errors.New("exit status 1: libguestfs: error: could not read key from user"), true, "LUKS-encrypted"},
		{"multi-boot", errors.New("exit status 1: guestfish: multi-boot operating systems are not supported"), true, "more than one"},
		{"FreeBSD layout", errors.New("exit status 1: libguestfs: error: inspect_os: Invalid partition table"), true, "partition layout"},
		{"not installed", fmt.Errorf("command execution error: %w", exec.ErrNotFound), false, "libguestfs-tools"},
		{"other", errors.New("exit status 1: libguestfs: error: could not create appliance"), false, "could not open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fish := &fakeFish{t: t, launch: tc.err}
			_, err := fish.reader("/dev/loop5").Gather(context.Background(), ReadRequest{Files: []string{"/etc/os-release"}})
			if err == nil || IsRefusal(err) != tc.refusal || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err %v (refusal %v), want %q (refusal %v)", err, IsRefusal(err), tc.says, tc.refusal)
			}
		})
	}
}

// Nothing reaches guestfish that is not a clean absolute guest path, and only
// mapped devices are opened.
func TestImageReaderRefusesWhatItCannotAskSafely(t *testing.T) {
	fish := &fakeFish{t: t}
	r := fish.reader("/dev/loop5")
	for _, bad := range []string{"etc/os-release", "/etc/../root/.ssh/id_rsa", "/etc/x\nfind", ":", "/etc//x"} {
		if _, err := r.Gather(context.Background(), ReadRequest{Read: []string{bad}}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if len(fish.calls) != 0 {
		t.Fatalf("guestfish was started: %q", fish.calls)
	}
	for _, devices := range [][]string{nil, {"/var/lib/vz/images/100/vm-100-disk-0.qcow2"}, {"/dev/sda"}} {
		if _, err := NewImageReader(devices); err == nil {
			t.Errorf("devices %q were accepted", devices)
		}
	}
}

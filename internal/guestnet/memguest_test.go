// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// memGuest is an in-memory guest file tree behind the guestfish runner: the
// read-only commands the adapter uses, and the write batch it ends with
// (mkdir-p, chmod, cp-a, upload, ln-s), applied to the same tree so a test
// can read the guest back the way the guest will. Files map a path to its
// contents; "-> target" makes a symlink. A directory exists when it is listed
// or has an entry.
//
// A file whose contents are "!chardev", "!blockdev", "!fifo" or "!socket" is
// that kind of special file. Writes behave as guestfish's do: upload and
// chmod follow a symbolic link at the path and reuse the inode of an existing
// file (every name it has), "cp -a" copies a link as a link.
type memGuest struct {
	t     *testing.T
	files map[string]string
	dirs  map[string]bool
	// attrs are what an inode carries besides its contents: owner, permission
	// bits and SELinux label. A path without an entry is root:root, 0644 and
	// unlabeled. cp -a copies them to the new inode; an upload into an
	// existing file keeps them (the inode is reused), and a new file gets
	// none.
	attrs map[string]memAttr
	// inodes group the names of one file: paths with the same number are
	// hard links of each other.
	inodes map[string]int
	calls  [][]string
	// needs are overlays that every guestfish call must add for the guest to
	// be inspectable at all (a root filesystem on a second disk, a volume
	// group across disks).
	needs []string
}

// memAttr is an inode's owner, permission bits and SELinux label.
type memAttr struct {
	uid, gid int
	perm     int // 0 means the default, 0644
	label    string
}

func (a memAttr) permBits() int {
	if a.perm == 0 {
		return 0o644
	}
	return a.perm
}

func newMemGuest(t *testing.T, files map[string]string, dirs ...string) *memGuest {
	t.Helper()
	g := &memGuest{t: t, files: map[string]string{}, dirs: map[string]bool{}, attrs: map[string]memAttr{}, inodes: map[string]int{}}
	for name, contents := range files {
		g.files[name] = contents
	}
	for _, dir := range dirs {
		g.dirs[dir] = true
	}
	return g
}

func (g *memGuest) adapter() *Adapter {
	return &Adapter{scratchDir: g.t.TempDir(), run: g.run}
}

func (g *memGuest) isDir(p string) bool {
	if g.dirs[p] {
		return true
	}
	prefix := strings.TrimSuffix(p, "/") + "/"
	for name := range g.files {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	for dir := range g.dirs {
		if strings.HasPrefix(dir, prefix) {
			return true
		}
	}
	return false
}

// resolve follows symlinks the way the guest does.
func (g *memGuest) resolve(p string) (string, bool) {
	for i := 0; i < 8; i++ {
		contents, ok := g.files[p]
		if !ok {
			return p, false
		}
		target, link := strings.CutPrefix(contents, "-> ")
		if !link {
			return p, true
		}
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(p), target)
		}
		if target == "/dev/null" {
			return target, true
		}
		p = target
	}
	return p, false
}

func (g *memGuest) run(_ context.Context, args ...string) (string, error) {
	g.calls = append(g.calls, append([]string(nil), args...))
	if len(args) < 6 {
		return "", nil
	}
	// A multi-disk guest is whole only when every disk it is spread over is
	// added: guestfish -i finds no operating system otherwise.
	for _, need := range g.needs {
		if !slices.Contains(guestfishOverlays(args), need) {
			return "", fmt.Errorf("guestfish: no operating system was found on this disk (the guest also needs %s): exit status 1", need)
		}
	}
	command := guestfishCommand(args)
	if args[0] == "--rw" {
		return "", g.write(command[1:])
	}
	if args[0] != "--ro" {
		g.t.Fatalf("unexpected guestfish access %q", args[0])
	}
	// "-- cmd : cmd ..." runs several read-only commands in one boot and
	// prints their results one after the other.
	if command[0] == "--" {
		var output strings.Builder
		batch := command[1:]
		for len(batch) > 0 {
			end := slices.Index(batch, ":")
			if end < 0 {
				end = len(batch)
			}
			one, err := g.read(batch[:end])
			if err != nil {
				return "", err
			}
			output.WriteString(one)
			if end == len(batch) {
				break
			}
			batch = batch[end+1:]
		}
		return output.String(), nil
	}
	return g.read(command)
}

// kind is what is at a path, without following a final symbolic link: "" for
// nothing, else symlink, dir, file, chardev, blockdev, fifo or socket.
func (g *memGuest) kind(p string) string {
	if contents, ok := g.files[p]; ok {
		if _, link := strings.CutPrefix(contents, "-> "); link {
			return "symlink"
		}
		if special, ok := strings.CutPrefix(contents, "!"); ok {
			return special
		}
		return "file"
	}
	if g.isDir(p) {
		return "dir"
	}
	return ""
}

// stat is the lstat of a path, as guestfish prints it.
func (g *memGuest) stat(p string) (string, error) {
	kind := g.kind(p)
	if kind == "" {
		return "", fmt.Errorf("guestfish: lstat: %s: No such file or directory", p)
	}
	typeBits := map[string]int{"symlink": 0o120000, "dir": 0o040000, "file": 0o100000, "chardev": 0o020000, "blockdev": 0o060000, "fifo": 0o010000, "socket": 0o140000}[kind]
	attr := g.attrs[p]
	perm := attr.permBits()
	if kind == "symlink" {
		perm = 0o777
	}
	nlink := 1
	if id := g.inodes[p]; id != 0 {
		nlink = len(g.names(p))
	}
	return fmt.Sprintf("dev: 2049\nino: 1\nmode: %d\nnlink: %d\nuid: %d\ngid: %d\nrdev: 0\nsize: %d\nblksize: 4096\nblocks: 8\natime: 0\nmtime: 0\nctime: 0\n", typeBits|perm, nlink, attr.uid, attr.gid, len(g.files[p])), nil
}

// names are every name of the inode at p (p alone unless it has hard links).
func (g *memGuest) names(p string) []string {
	id := g.inodes[p]
	if id == 0 {
		return []string{p}
	}
	var names []string
	for name, other := range g.inodes {
		if other == id {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// hardLink makes name another name of the inode at existing.
func (g *memGuest) hardLink(existing, name string) {
	if g.inodes[existing] == 0 {
		g.inodes[existing] = len(g.inodes) + 1000
	}
	g.inodes[name] = g.inodes[existing]
	g.files[name] = g.files[existing]
	g.attrs[name] = g.attrs[existing]
}

// canon resolves the symbolic links among the parent directories of p (not a
// link at p itself), as the guest's path lookup does.
func (g *memGuest) canon(p string) string {
	for round := 0; round < 8; round++ {
		parts := strings.Split(strings.TrimPrefix(path.Clean(p), "/"), "/")
		redirected := false
		prefix := ""
		for i := 0; i < len(parts)-1; i++ {
			prefix += "/" + parts[i]
			if target, link := strings.CutPrefix(g.files[prefix], "-> "); link {
				if !path.IsAbs(target) {
					target = path.Join(path.Dir(prefix), target)
				}
				p = path.Join(append([]string{target}, parts[i+1:]...)...)
				redirected = true
				break
			}
		}
		if !redirected {
			return p
		}
	}
	return p
}

// follow is where a write that follows symbolic links lands.
func (g *memGuest) follow(p string) string {
	for i := 0; i < 8; i++ {
		target, link := strings.CutPrefix(g.files[p], "-> ")
		if !link {
			return p
		}
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(p), target)
		}
		p = target
	}
	return p
}

func (g *memGuest) read(command []string) (string, error) {
	boolean := func(v bool) (string, error) { return fmt.Sprintf("%t\n", v), nil }
	name, rest := command[0], append([]string(nil), command[1:]...)
	if len(rest) > 0 {
		rest[0] = g.canon(rest[0])
	}
	switch name {
	case "echo":
		return strings.Join(command[1:], " ") + "\n", nil
	case "is-dir":
		return boolean(g.kind(rest[0]) == "dir")
	case "is-file":
		follow := len(rest) > 1 && rest[1] == "followsymlinks:true"
		if g.kind(rest[0]) == "symlink" && follow {
			resolved, found := g.resolve(rest[0])
			return boolean(found && g.kind(resolved) == "file")
		}
		return boolean(g.kind(rest[0]) == "file")
	case "is-symlink":
		return boolean(g.kind(rest[0]) == "symlink")
	case "is-chardev", "is-blockdev", "is-fifo", "is-socket":
		return boolean(g.kind(rest[0]) == strings.TrimPrefix(name, "is-"))
	case "lstat":
		return g.stat(rest[0])
	case "readlink":
		target, link := strings.CutPrefix(g.files[rest[0]], "-> ")
		if !link {
			return "", fmt.Errorf("guestfish: readlink: %s: Invalid argument", rest[0])
		}
		return target + "\n", nil
	case "filesize":
		resolved, found := g.resolve(rest[0])
		if !found {
			return "", fmt.Errorf("guestfish: filesize: %s: No such file or directory", rest[0])
		}
		if resolved == "/dev/null" {
			return "0\n", nil
		}
		return fmt.Sprintf("%d\n", len(g.files[resolved])), nil
	case "cat":
		if g.isDir(rest[0]) {
			return "", fmt.Errorf("guestfish: cat: %s: Is a directory", rest[0])
		}
		resolved, found := g.resolve(rest[0])
		if _, exists := g.files[resolved]; !found || !exists {
			return "", fmt.Errorf("guestfish: cat: %s: No such file or directory", rest[0])
		}
		return g.files[resolved], nil
	case "ls":
		if !g.isDir(rest[0]) {
			return "", fmt.Errorf("guestfish: ls: %s: No such file or directory", rest[0])
		}
		names := map[string]bool{}
		prefix := strings.TrimSuffix(rest[0], "/") + "/"
		for name := range g.files {
			if entry, ok := strings.CutPrefix(name, prefix); ok {
				names[strings.SplitN(entry, "/", 2)[0]] = true
			}
		}
		for dir := range g.dirs {
			if entry, ok := strings.CutPrefix(dir, prefix); ok {
				names[strings.SplitN(entry, "/", 2)[0]] = true
			}
		}
		list := make([]string, 0, len(names))
		for name := range names {
			list = append(list, name)
		}
		sort.Strings(list)
		return strings.Join(list, "\n") + "\n", nil
	}
	g.t.Fatalf("memGuest does not implement guestfish command %q", name)
	return "", nil
}

func (g *memGuest) write(batch []string) error {
	for len(batch) > 0 {
		end := len(batch)
		for i, arg := range batch {
			if arg == ":" {
				end = i
				break
			}
		}
		command := append([]string(nil), batch[:end]...)
		// The paths a command names are resolved through symbolic links in their
		// parent directories, as the guest resolves them.
		for _, index := range map[string][]int{"mkdir-p": {1}, "chmod": {2}, "chown": {3}, "cp-a": {1, 2}, "upload": {2}, "ln-s": {2}}[command[0]] {
			command[index] = g.canon(command[index])
		}
		switch command[0] {
		case "mkdir-p":
			g.dirs[command[1]] = true
		case "chmod":
			target := g.follow(command[2])
			if g.kind(target) == "" {
				return fmt.Errorf("guestfish: chmod: %s: No such file or directory", command[2])
			}
			mode, err := strconv.Atoi(command[1])
			if err != nil {
				g.t.Fatalf("chmod %v: %v", command, err)
			}
			for _, name := range g.names(target) {
				attr := g.attrs[name]
				attr.perm = mode
				g.attrs[name] = attr
			}
		case "chown":
			target := g.follow(command[3])
			if g.kind(target) == "" {
				return fmt.Errorf("guestfish: chown: %s: No such file or directory", command[3])
			}
			uid, errUID := strconv.Atoi(command[1])
			gid, errGID := strconv.Atoi(command[2])
			if errUID != nil || errGID != nil {
				g.t.Fatalf("chown %v is not numeric", command)
			}
			for _, name := range g.names(target) {
				attr := g.attrs[name]
				attr.uid, attr.gid = uid, gid
				g.attrs[name] = attr
			}
		case "cp-a":
			source, destination := command[1], command[2]
			contents, ok := g.files[source]
			if !ok {
				g.t.Fatalf("cp-a of a file the guest does not have: %v", command)
			}
			if g.kind(source) == "symlink" {
				// cp -a copies a link as a link.
				g.files[destination] = contents
				g.attrs[destination] = g.attrs[source]
				delete(g.inodes, destination)
				break
			}
			// A regular file is copied through a link at the destination, over
			// the inode that is there, and gets the source's attributes.
			for _, name := range g.names(g.follow(destination)) {
				g.files[name] = contents
				g.attrs[name] = g.attrs[source]
			}
		case "upload":
			data, err := os.ReadFile(command[1])
			if err != nil {
				g.t.Fatal(err)
			}
			target := g.follow(command[2])
			switch kind := g.kind(target); kind {
			case "", "file":
			case "dir":
				return fmt.Errorf("guestfish: upload: %s: Is a directory", command[2])
			default:
				g.t.Fatalf("upload to the %s at %s would block or write to a device", kind, command[2])
			}
			// The inode that is there is reused (with its owner and label), under
			// every name it has.
			for _, name := range g.names(target) {
				g.files[name] = string(data)
			}
		case "ln-s":
			// guestfish's ln-s fails when anything is at the path, even the link
			// that is wanted.
			if g.kind(command[2]) != "" {
				return fmt.Errorf("guestfish: ln-s: %s: File exists", command[2])
			}
			g.files[command[2]] = "-> " + command[1]
		default:
			g.t.Fatalf("unexpected guestfish mutation %v", command)
		}
		if end == len(batch) {
			break
		}
		batch = batch[end+1:]
	}
	return nil
}

// mutated reports whether any write batch reached the overlay.
func (g *memGuest) mutated() bool {
	for _, call := range g.calls {
		if len(call) > 0 && call[0] == "--rw" {
			return true
		}
	}
	return false
}

// materialize writes the guest tree under a temporary root, symlinks
// included, for tools that read a guest root (netplan's generator).
func (g *memGuest) materialize() string {
	root := g.t.TempDir()
	for name, contents := range g.files {
		dest := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			g.t.Fatal(err)
		}
		if target, link := strings.CutPrefix(contents, "-> "); link {
			if err := os.Symlink(target, dest); err != nil {
				if runtime.GOOS == "windows" {
					// Windows lets an account create symbolic links only with a
					// privilege (Developer Mode, or an elevated shell). Without
					// it the guest tree cannot be written, and that says nothing
					// about the code under test.
					g.t.Skipf("this Windows account cannot create symbolic links (enable Developer Mode or run elevated): %v", err)
				}
				g.t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(dest, []byte(contents), 0o600); err != nil {
			g.t.Fatal(err)
		}
	}
	return root
}

const netplanGenerator = "/usr/libexec/netplan/generate"

// requireNetplanEnv names the environment variable that turns a missing
// netplan generator from a skip into a failure. CI sets it on the Linux jobs
// that install netplan, so the guard (what networkd really selects when
// the guest's own Netplan definitions compete with the recovery profile)
// cannot silently stop running on an image without it.
const requireNetplanEnv = "CERTISTACK_REQUIRE_NETPLAN"

// netplanState says what a test that needs the guest's own generator does:
// "run" where the generator exists, "fail" where it does not and require is
// set, and "skip" where it does not and nothing requires it (a development
// machine without netplan).
func netplanState(generator, require string) string {
	if _, err := os.Stat(generator); err == nil {
		return "run"
	}
	if require != "" {
		return "fail"
	}
	return "skip"
}

// needNetplan skips the calling test where the generator is not installed, and
// fails it where require is set.
func needNetplan(t testing.TB, generator, require string) {
	t.Helper()
	switch netplanState(generator, require) {
	case "fail":
		t.Fatalf("%s is not installed, and %s is set: CI installs netplan so the guest's own generator decides what networkd selects; install netplan (the netplan.io package) or fix the image", generator, requireNetplanEnv)
	case "skip":
		t.Skip("netplan is not installed; the guest's own generator cannot be run")
	}
}

// networkdSelection asks the real netplan generator what networkd is given
// for a guest tree and returns the .network file networkd applies to a link
// with this MAC: the first in file-name order across /etc/systemd/network and
// what netplan generates under /run/systemd/network, whose [Match] does not
// exclude the MAC. The test is skipped where netplan is not installed, and
// fails where CERTISTACK_REQUIRE_NETPLAN is set (CI). Only generation runs: no
// netplan apply, no daemon.
func (g *memGuest) networkdSelection(mac string) (name, contents string) {
	g.t.Helper()
	return g.generatedSelection(mac, 30*time.Second, false)
}

// generatedSelection is networkdSelection with a time limit. netplan 0.106's
// generator writes its files and finally asks `systemctl is-system-running`,
// which blocks on hosts whose systemd does not answer (WSL) and whenever
// NetworkManager renders a definition; tolerateHang reads what it had
// written by the limit. Without tolerateHang the generator's files count once
// it has written its udev rules, its last output, and the process is ended.
func (g *memGuest) generatedSelection(mac string, limit time.Duration, tolerateHang bool) (name, contents string) {
	g.t.Helper()
	needNetplan(g.t, netplanGenerator, os.Getenv(requireNetplanEnv))
	root := g.materialize()
	// netplan warns about world-readable configuration.
	if err := os.Chmod(filepath.Join(root, "etc", "netplan"), 0o700); err != nil && !os.IsNotExist(err) {
		g.t.Fatal(err)
	}
	cmd := exec.Command(netplanGenerator, "--root-dir", root)
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output
	ownProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		g.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.After(limit)
	rules := filepath.Join(root, "run", "udev", "rules.d", "90-netplan.rules")
	var seen time.Time
wait:
	for {
		select {
		case err := <-done:
			if err != nil {
				g.t.Fatalf("netplan generate: %v: %s", err, output.String())
			}
			break wait
		case <-deadline:
			if !tolerateHang {
				killProcessGroup(cmd)
				<-done
				g.t.Fatalf("netplan generate did not finish in %v: %s", limit, output.String())
			}
			killProcessGroup(cmd)
			<-done
			break wait
		case <-time.After(50 * time.Millisecond):
			if _, err := os.Stat(rules); err == nil {
				if seen.IsZero() {
					seen = time.Now()
				} else if time.Since(seen) > 300*time.Millisecond {
					killProcessGroup(cmd)
					<-done
					break wait
				}
			}
		}
	}
	networks := map[string]string{}
	for _, dir := range []string{"run/systemd/network", "etc/systemd/network"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".network") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(root, dir, entry.Name()))
			if err != nil {
				g.t.Fatal(err)
			}
			networks[entry.Name()] = string(data) // /etc masks /run of the same name
		}
	}
	names := make([]string, 0, len(networks))
	for n := range networks {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		// The link is the recovered NIC as this guest names it: its MAC and
		// name select the file, other conditions (a driver) may match.
		if systemdMayMatch(networks[n], mac) && matchesLinkName(networks[n], recoveryNIC) {
			return n, networks[n]
		}
	}
	g.t.Fatalf("no generated .network file matches %s: %v", mac, names)
	return "", ""
}

// recoveryNIC is the name the fixture guests give the recovered NIC.
const recoveryNIC = "ens18"

// matchesLinkName reports whether a .network file's Name= patterns (globs)
// allow a link of that name; a file without them allows any name.
func matchesLinkName(contents, link string) bool {
	section := ""
	var patterns []string
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok && section == "[Match]" && strings.TrimSpace(key) == "Name" {
			patterns = append(patterns, strings.Fields(value)...)
		}
	}
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "!") {
			return true
		}
		if ok, _ := path.Match(pattern, link); ok {
			return true
		}
	}
	return false
}

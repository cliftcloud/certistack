// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// gitIn runs git in dir, with a fixed identity and the given committer date.
func gitIn(t *testing.T, dir, date string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.invalid",
		"GIT_AUTHOR_DATE=2000-01-01T00:00:00+0000", "GIT_COMMITTER_DATE="+date,
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func copyRepoTree(t *testing.T, dest string, names ...string) {
	t.Helper()
	for _, name := range names {
		root := repoFile(name)
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(repoFile(), path)
			target := filepath.Join(dest, rel)
			if entry.IsDir() {
				return os.MkdirAll(target, 0o755)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// The build identity a binary carries comes from the commit it was built from
// (its full hash cut to a fixed 12 digits, and its commit time in UTC), not from
// the moment or the machine, so two builds of one commit match.
func TestBuildIdentityComesFromTheCommit(t *testing.T) {
	needTools(t, "make", "git")
	identity := func(dir, timezone string) map[string]string {
		cmd := exec.Command("make", "-s", "print-build-identity", "VERSION=v1.2.3")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TZ="+timezone, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("make print-build-identity in %s: %v\n%s", dir, err, out)
		}
		values := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			key, value, _ := strings.Cut(line, "=")
			values[key] = value
		}
		return values
	}

	repo := t.TempDir()
	copyRepoTree(t, repo, "Makefile")
	gitIn(t, repo, "2026-01-02T03:04:05+0000", "init", "-q")
	gitIn(t, repo, "2026-01-02T03:04:05+0000", "add", "Makefile")
	gitIn(t, repo, "2026-01-02T03:04:05+0000", "commit", "-q", "-m", "first")
	head := gitIn(t, repo, "2026-01-02T03:04:05+0000", "rev-parse", "HEAD")

	for _, timezone := range []string{"UTC", "America/Denver", "Pacific/Auckland"} {
		got := identity(repo, timezone)
		if got["version"] != "v1.2.3" || got["commit"] != head[:12] || got["built"] != "2026-01-02T03:04:05Z" {
			t.Errorf("TZ=%s: identity %v, want version v1.2.3, commit %s, built 2026-01-02T03:04:05Z", timezone, got, head[:12])
		}
	}

	// A later commit is a later identity; a committer date in another zone
	// is still written in UTC.
	if err := os.WriteFile(filepath.Join(repo, "next"), []byte("next\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, "2026-03-04T10:00:00-0600", "add", "next")
	gitIn(t, repo, "2026-03-04T10:00:00-0600", "commit", "-q", "-m", "second")
	if got := identity(repo, "UTC"); got["built"] != "2026-03-04T16:00:00Z" {
		t.Errorf("second commit: built %q, want 2026-03-04T16:00:00Z", got["built"])
	}

	// Without git, the identity says so: no invented date and no hash.
	bare := t.TempDir()
	copyRepoTree(t, bare, "Makefile")
	if got := identity(bare, "UTC"); got["commit"] != "unknown" || got["built"] != "unknown" {
		t.Errorf("a tree without git stamped %v, want unknown commit and date", got)
	}
}

const candidateGoStub = `#!/usr/bin/env bash
case "$*" in
  "env GOVERSION") echo "$STUB_GOVERSION" ;;
  "env GOHOSTOS") echo linux ;;
  "env GOHOSTARCH") echo amd64 ;;
  *) echo "go stub: unexpected $*" >&2; exit 64 ;;
esac
`

// The make stub leaves a program that prints what a build was asked to
// stamp, as the environment says it should.
const candidateMakeStub = `#!/usr/bin/env bash
[ "$1" = build-linux ] || { echo "make stub: unexpected $*" >&2; exit 64; }
printf '%s\n' "$*" >> "$STUB_LOG"
mkdir -p bin
printf '%s\n' '#!/bin/sh' 'printf "certistack %s\n  commit:    %s\n  built:     %s\n" "$STUB_VERSION" "$STUB_COMMIT" "$STUB_BUILT"' > bin/certistack-linux-amd64
chmod +x bin/certistack-linux-amd64
`

// scripts/release-candidate.sh builds only from a clean commit with
// the go.mod toolchain and a real stable tag, checks that the binary says the
// version, commit and commit time it was asked to, and prints the registry
// line; each condition failing is a refusal, not a warning.
func TestReleaseCandidateScriptRefusesWhatItCannotVouchFor(t *testing.T) {
	needTools(t, "git", "sha256sum", "date")
	if runtime.GOOS != "linux" {
		t.Skip("uses GNU date and Linux executables")
	}
	const commitDate = "2026-01-02T03:04:05+0000"
	repo := t.TempDir()
	script, err := os.ReadFile(repoFile("scripts", "release-candidate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(repo, "scripts", "release-candidate.sh"), string(script))
	for name, content := range map[string]string{
		"go.mod":     "module example.invalid/x\n\ngo 1.26.8\n",
		".gitignore": "bin/\n",
	} {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, repo, commitDate, "init", "-q")
	gitIn(t, repo, commitDate, "add", ".")
	gitIn(t, repo, commitDate, "commit", "-q", "-m", "release commit")
	head := gitIn(t, repo, commitDate, "rev-parse", "HEAD")

	stubs := t.TempDir()
	writeExecutable(t, filepath.Join(stubs, "go"), candidateGoStub)
	writeExecutable(t, filepath.Join(stubs, "make"), candidateMakeStub)
	// A git that works, except that "git status" fails with nothing on stdout
	// when STUB_GIT_STATUS_FAIL is set: a failed diagnostic, not a clean tree.
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(stubs, "git"), "#!/usr/bin/env bash\nif [ \"$1\" = status ] && [ -n \"${STUB_GIT_STATUS_FAIL:-}\" ]; then echo 'fatal: simulated status failure' >&2; exit 128; fi\nexec '"+realGit+"' \"$@\"\n")
	run := func(tag string, overrides map[string]string) (string, error) {
		env := map[string]string{
			"STUB_LOG": filepath.Join(stubs, "make.log"), "STUB_GOVERSION": "go1.26.8",
			"STUB_VERSION": "v1.2.3", "STUB_COMMIT": head[:12], "STUB_BUILT": "2026-01-02T03:04:05Z",
		}
		for k, v := range overrides {
			env[k] = v
		}
		return runStep(t, repo, shellEnv(t, stubs, t.TempDir(), env), "scripts/release-candidate.sh '"+tag+"'")
	}

	out, err := run("v1.2.3", nil)
	if err != nil {
		t.Fatalf("a clean commit with the pinned toolchain: %v\n%s", err, out)
	}
	binary, err := os.ReadFile(filepath.Join(repo, "bin", "certistack-linux-amd64"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	if want := "v1.2.3 " + head + " " + hex.EncodeToString(sum[:]); strings.TrimSpace(out) != want {
		t.Errorf("registry line %q, want %q", strings.TrimSpace(out), want)
	}
	if calls := readLog(t, filepath.Join(stubs, "make.log")); len(calls) != 1 || calls[0] != "build-linux VERSION=v1.2.3" {
		t.Errorf("make calls %q, want one build-linux with the tag as its version", calls)
	}

	// A release candidate tag is built like a release: the binary is
	// stamped with the tag, and the registry line names it. (The release
	// workflow never runs for one; see TestReleaseWorkflowStartsOnlyOnStableTags.)
	for _, tag := range []string{"v1.2.3-rc1", "v1.2.3-rc2", "v0.1.0-rc10", "v10.20.30-rc1"} {
		out, err := run(tag, map[string]string{"STUB_VERSION": tag})
		if err != nil {
			t.Errorf("release candidate %s was refused: %v\n%s", tag, err, out)
			continue
		}
		binary, err := os.ReadFile(filepath.Join(repo, "bin", "certistack-linux-amd64"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(binary)
		if want := tag + " " + head + " " + hex.EncodeToString(sum[:]); strings.TrimSpace(out) != want {
			t.Errorf("%s: registry line %q, want %q", tag, strings.TrimSpace(out), want)
		}
		if calls := readLog(t, filepath.Join(stubs, "make.log")); len(calls) == 0 || calls[len(calls)-1] != "build-linux VERSION="+tag {
			t.Errorf("%s: make calls %q, want a build-linux with the tag as its version", tag, calls)
		}
	}
	// A candidate whose binary reports the stable version is still refused.
	if out, err := run("v1.2.3-rc1", nil); err == nil || !strings.Contains(out, "reports version v1.2.3") {
		t.Errorf("a binary that reports another version was accepted for a release candidate: err=%v\n%s", err, out)
	}

	for _, c := range []struct {
		name, tag string
		env       map[string]string
		want      string
	}{
		{"a Go that is not the go.mod toolchain", "v1.2.3", map[string]string{"STUB_GOVERSION": "go1.27.1"}, "go1.27.1"},
		{"the binary claims another version", "v1.2.3", map[string]string{"STUB_VERSION": "v1.2.4"}, "reports version v1.2.4"},
		{"the binary claims another commit", "v1.2.3", map[string]string{"STUB_COMMIT": "0123456789ab"}, "reports commit 0123456789ab"},
		{"the binary claims another build date", "v1.2.3", map[string]string{"STUB_BUILT": "2026-05-05T05:05:05Z"}, "reports build date"},
		{"git status fails and prints nothing", "v1.2.3", map[string]string{"STUB_GIT_STATUS_FAIL": "1"}, "git status failed"},
		{"a tag without the v", "1.2.3", nil, "stable tag"},
		{"a release candidate without a number", "v1.2.3-rc", nil, "stable tag"},
		{"a release candidate numbered zero", "v1.2.3-rc0", nil, "stable tag"},
		{"a release candidate with a leading zero", "v1.2.3-rc01", nil, "stable tag"},
		{"a release candidate in capitals", "v1.2.3-RC1", nil, "stable tag"},
		{"a release candidate with a dash before the number", "v1.2.3-rc-1", nil, "stable tag"},
		{"another prerelease", "v1.2.3-beta1", nil, "stable tag"},
		{"a release candidate with build metadata", "v1.2.3-rc1+build5", nil, "stable tag"},
		{"a release candidate of a version with a leading zero", "v01.2.3-rc1", nil, "leading zeros"},
		{"a second suffix", "v1.2.3-rc1-2", nil, "stable tag"},
		{"a dangling dash", "v1.2.3-", nil, "stable tag"},
		{"a leading zero", "v01.2.3", nil, "leading zeros"},
		{"two components", "v1.2", nil, "stable tag"},
		{"no tag", "", nil, "usage"},
	} {
		out, err := run(c.tag, c.env)
		if err == nil || !strings.Contains(out, c.want) {
			t.Errorf("%s: err=%v, output %q, want a refusal saying %q", c.name, err, out, c.want)
		}
	}

	// Uncommitted work, tracked or not, is not a commit's build.
	for name, change := range map[string]func() error{
		"a modified tracked file": func() error {
			return os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module example.invalid/x\n\ngo 1.26.8\n// edit\n"), 0o644)
		},
		"an untracked file": func() error { return os.WriteFile(filepath.Join(repo, "stray.go"), []byte("package x\n"), 0o644) },
	} {
		if err := change(); err != nil {
			t.Fatal(err)
		}
		out, err := run("v1.2.3", nil)
		if err == nil || !strings.Contains(out, "not clean") {
			t.Errorf("%s: err=%v, output %q, want a refusal that the tree is not clean", name, err, out)
		}
		gitIn(t, repo, commitDate, "checkout", "--", "go.mod")
		_ = os.Remove(filepath.Join(repo, "stray.go"))
	}

	// A toolchain line, should go.mod gain one, is the version to build with,
	// and a go.mod that names no version leaves nothing to check the build by.
	for name, c := range map[string]struct{ gomod, want string }{
		"a newer toolchain line": {"module example.invalid/x\n\ngo 1.26.8\n\ntoolchain go1.26.9\n", "go1.26.9"},
		"no Go version":          {"module example.invalid/x\n", "no Go version"},
	} {
		if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte(c.gomod), 0o644); err != nil {
			t.Fatal(err)
		}
		gitIn(t, repo, commitDate, "commit", "-q", "-am", name)
		if out, err := run("v1.2.3", nil); err == nil || !strings.Contains(out, c.want) {
			t.Errorf("%s: err=%v, output %q, want a refusal saying %q", name, err, out, c.want)
		}
	}
}

// make fmt-check passes only when the scan finished and found nothing to
// format. A gofmt that fails (reporting only on stderr) or a find that fails
// part-way leaves empty output that must not read as "all formatted"; a file
// gofmt lists is refused.
func TestFmtCheckFailsWhenItsDiagnosticsFail(t *testing.T) {
	needTools(t, "make", "find", "xargs")
	dir := t.TempDir()
	copyRepoTree(t, dir, "Makefile")
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stubs := t.TempDir()
	// The gofmt stub does what STUB_GOFMT says; the find stub, when asked to
	// (STUB_FIND_FAIL), lists a file and then fails.
	writeExecutable(t, filepath.Join(stubs, "gofmt"), "#!/usr/bin/env bash\ncase \"${STUB_GOFMT:-clean}\" in\n  clean) ;;\n  unformatted) echo ./a.go ;;\n  fail) echo 'gofmt: simulated internal failure' >&2; exit 2 ;;\nesac\n")
	realFind, err := exec.LookPath("find")
	if err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(stubs, "find"), "#!/usr/bin/env bash\nif [ -n \"${STUB_FIND_FAIL:-}\" ]; then printf './a.go\\0'; echo 'find: simulated failure' >&2; exit 1; fi\nexec '"+realFind+"' \"$@\"\n")
	for _, c := range []struct {
		name string
		env  map[string]string
		pass bool
		want string
	}{
		{"every file formatted", nil, true, ""},
		{"a file gofmt lists", map[string]string{"STUB_GOFMT": "unformatted"}, false, "unformatted Go files:\n./a.go"},
		{"gofmt itself fails, listing nothing", map[string]string{"STUB_GOFMT": "fail"}, false, "gofmt"},
		{"find fails part-way, listing a file", map[string]string{"STUB_FIND_FAIL": "1"}, false, "find"},
	} {
		out, err := runStep(t, dir, shellEnv(t, stubs, t.TempDir(), c.env), "make fmt-check")
		switch {
		case c.pass && err != nil:
			t.Errorf("%s: refused: %v\n%s", c.name, err, out)
		case !c.pass && err == nil:
			t.Errorf("%s: make fmt-check passed\n%s", c.name, out)
		case !c.pass && !strings.Contains(out, c.want):
			t.Errorf("%s: output lacks %q:\n%s", c.name, c.want, out)
		}
	}
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// The release executable is reproducible. Built by the Makefile's
// own recipe from copies of the sources in two different directories, under
// different time zones, it is the same bytes, so the release workflow can
// rebuild the tested candidate and compare digests; changing only the stamped
// identity changes the bytes, so the digest does cover it; and the binary
// reports what it was stamped with.
func TestReleaseBinaryIsReproducibleAndStampedWithItsIdentity(t *testing.T) {
	needTools(t, "make", "go")
	if testing.Short() || raceEnabled {
		t.Skip("compiles the controller three times; the plain, non-short run does it")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("runs the linux/amd64 release binary")
	}
	build := func(name, timezone string, identity ...string) (dir, digest string) {
		dir = filepath.Join(t.TempDir(), name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		copyRepoTree(t, dir, "Makefile", "go.mod", "go.sum", "cmd", "pkg", "internal")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "make", append([]string{"build-linux"}, identity...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TZ="+timezone, "GOTOOLCHAIN=local")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("make build-linux in %s: %v\n%s", dir, err, out)
		}
		return dir, sha256File(t, filepath.Join(dir, "bin", "certistack-linux-amd64"))
	}
	stamp := []string{"VERSION=v9.9.9", "COMMIT=0123456789ab", "DATE=2026-01-02T03:04:05Z"}

	dirA, digestA := build("a", "UTC", stamp...)
	_, digestB := build("second-checkout", "Pacific/Auckland", stamp...)
	if digestA != digestB {
		t.Errorf("the same sources and identity built in two directories give %s and %s", digestA, digestB)
	}
	_, digestC := build("c", "UTC", "VERSION=v9.9.9", "COMMIT=0123456789ab", "DATE=2026-01-02T03:04:06Z")
	if digestC == digestA {
		t.Error("a different build date left the bytes unchanged, so the digest does not cover the stamped identity")
	}

	out, err := exec.Command(filepath.Join(dirA, "bin", "certistack-linux-amd64"), "version").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"certistack v9.9.9\n", "commit:    0123456789ab\n", "built:     2026-01-02T03:04:05Z\n"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("version output lacks %q:\n%s", want, out)
		}
	}
}

// One Go toolchain everywhere. go.mod's go line names it (a toolchain
// line equal to it is not canonical and the go command rejects it), the image
// that builds the controller and both workflows follow it, and a release
// build refuses any other Go (scripts/release-candidate.sh), since a newer
// local Go would otherwise build with itself.
func TestOneGoToolchainEverywhere(t *testing.T) {
	gomod, err := os.ReadFile(repoFile("go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	goLine := regexp.MustCompile(`(?m)^go (\d+\.\d+\.\d+)$`).FindSubmatch(gomod)
	if goLine == nil {
		t.Fatalf("go.mod has no go line naming a full version:\n%s", gomod)
	}
	if regexp.MustCompile(`(?m)^toolchain `).Match(gomod) {
		t.Fatal("go.mod gained a toolchain line; scripts/release-candidate.sh reads it in preference to the go line, so keep the two in step and update this test")
	}
	version := string(goLine[1])

	dockerfile, err := os.ReadFile(repoFile("deploy", "controller", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dockerfile), "FROM golang:"+version+"-alpine@sha256:") {
		t.Errorf("the Dockerfile's build stage is not golang:%s, the go.mod toolchain", version)
	}
}

// The released image is the verified executable. Its Dockerfile can
// take bin/certistack-linux-amd64 as the executable instead of compiling
// again, the ignore file lets that one file into the build context, and the
// Makefile builds the release image that way.
func TestReleaseImageCarriesTheVerifiedBinary(t *testing.T) {
	dockerfile, err := os.ReadFile(repoFile("deploy", "controller", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ARG BINARY_SOURCE=build\n",
		"FROM scratch AS release-binary\nCOPY bin/certistack-linux-amd64 /out/certistack\n",
		"FROM ${BINARY_SOURCE} AS binary\n",
		"COPY --from=binary /out/certistack /usr/local/bin/certistack\n",
	} {
		if !strings.Contains(string(dockerfile), want) {
			t.Errorf("the Dockerfile lacks %q", want)
		}
	}
	if strings.Contains(string(dockerfile), "COPY --from=build /out/certistack") {
		t.Error("the runtime stage copies the compiled executable directly, so the release binary can never be chosen")
	}
	ignore, err := os.ReadFile(repoFile(".dockerignore"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(ignore), "\n")
	excludeAll, reinclude := -1, -1
	for i, line := range lines {
		switch line {
		case "bin", "bin/", "bin/*":
			excludeAll = i
		case "!bin/certistack-linux-amd64":
			reinclude = i
		}
	}
	if excludeAll < 0 || reinclude < excludeAll {
		t.Errorf(".dockerignore must exclude bin/ and then re-include bin/certistack-linux-amd64 (exclude line %d, re-include line %d)", excludeAll, reinclude)
	}
	makefile, err := os.ReadFile(repoFile("Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^container-release:\n(\t.*\n)*\t\t--build-arg BINARY_SOURCE=release-binary`).Match(makefile) {
		t.Error("the Makefile's container-release does not build with BINARY_SOURCE=release-binary")
	}
}

const imageDockerStub = `#!/usr/bin/env bash
printf 'docker %s\n' "$*" >> "$STUB_LOG"
[ "$STUB_DOCKER" != fail ] || exit 1
printf '%s\n' "$STUB_INSIDE"
`

// scripts/check-image-binary.sh passes only when the executable
// inside the image has the digest of the file the image was built around.
func TestImageBinaryCheckComparesDigests(t *testing.T) {
	needTools(t, "sha256sum")
	script, err := os.ReadFile(repoFile("scripts", "check-image-binary.sh"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	stubs := filepath.Join(dir, "stubs")
	if err := os.MkdirAll(stubs, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(stubs, "docker"), imageDockerStub)
	writeExecutable(t, filepath.Join(dir, "check.sh"), string(script))
	binary := filepath.Join(dir, "certistack-linux-amd64")
	if err := os.WriteFile(binary, []byte("verified executable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256File(t, binary)
	for _, c := range []struct {
		name, inside, mode, want string
		pass                     bool
	}{
		{"the same executable", digest + "  /usr/local/bin/certistack", "", "carries " + digest, true},
		{"another executable", strings.Repeat("0", 64) + "  /usr/local/bin/certistack", "", "not the verified", false},
		{"no digest reported", "", "", "reported no digest", false},
		{"garbage reported", "sha256sum: /usr/local/bin/certistack: No such file or directory", "", "reported no digest", false},
		{"the engine fails", digest, "fail", "could not read", false},
	} {
		logPath := filepath.Join(dir, "docker.log")
		_ = os.Remove(logPath)
		out, err := runStep(t, dir, shellEnv(t, stubs, dir, map[string]string{"STUB_LOG": logPath, "STUB_INSIDE": c.inside, "STUB_DOCKER": c.mode}),
			"bash check.sh registry.example/certistack-controller:test "+binary)
		if (err == nil) != c.pass || !strings.Contains(out, c.want) {
			t.Errorf("%s: passed=%v, want %v containing %q\n%s", c.name, err == nil, c.pass, c.want, out)
		}
		if calls := readLog(t, logPath); len(calls) != 1 || calls[0] != "docker run --rm --entrypoint sha256sum registry.example/certistack-controller:test /usr/local/bin/certistack" {
			t.Errorf("%s: docker calls %q", c.name, calls)
		}
	}
}

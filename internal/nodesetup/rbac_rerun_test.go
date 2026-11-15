// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// pveumStub is a stand-in for pveum that keeps its state in $STUB_STATE: it
// refuses to add what exists, as the real one does, and prints a secret only
// when it creates a token. STUB_FAIL=<step> makes that step fail.
const pveumStub = `#!/bin/sh
S="$STUB_STATE"
echo "pveum $*" >> "$S/calls"
die() { echo "stub pveum: $*" >&2; exit 255; }
case "$1 $2" in
"role add")
  [ "${STUB_FAIL:-}" = "role-add" ] && die "role add refused"
  [ -e "$S/role.$3" ] && die "role '$3' already exists"
  printf '%s' "$5" > "$S/role.$3" ;;
"role modify")
  [ -e "$S/role.$3" ] || die "role '$3' does not exist"
  printf '%s' "$5" > "$S/role.$3" ;;
"role list")
  printf '[{"roleid":"Administrator","special":1}'
  for f in "$S"/role.*; do
    [ -e "$f" ] || continue
    b=${f##*/}
    printf ',{"roleid":"%s","privs":"%s"}' "${b#role.}" "$(cat "$f")"
  done
  echo ']' ;;
"user add")
  [ "${STUB_FAIL:-}" = "user-add" ] && die "user add refused"
  [ -e "$S/user.$3" ] && die "user '$3' already exists"
  : > "$S/user.$3" ;;
"user list")
  printf '[{"userid":"root@pam","enable":1}'
  for f in "$S"/user.*; do
    [ -e "$f" ] || continue
    b=${f##*/}
    printf ',{"userid":"%s","enable":1}' "${b#user.}"
  done
  echo ']' ;;
"user token")
  case "$3" in
  add)
    [ "${STUB_FAIL:-}" = "token-add" ] && die "token add refused"
    [ -e "$S/user.$4" ] || die "no such user ('$4')"
    [ -e "$S/token.$4!$5" ] && die "Token already exists"
    : > "$S/token.$4!$5"
    echo "STUB-SECRET-$4!$5" >> "$S/secrets"
    echo "value  STUB-SECRET-$4!$5" ;;
  list)
    printf '['
    sep=
    for f in "$S"/token."$4"!*; do
      [ -e "$f" ] || continue
      b=${f##*!}
      printf '%s{"tokenid":"%s","privsep":1}' "$sep" "$b"
      sep=,
    done
    echo ']' ;;
  remove) rm -f "$S/token.$4!$5" ;;
  permissions) echo "stub permissions" ;;
  *) die "unexpected: $*" ;;
  esac ;;
"acl modify")
  grep -qxF "$*" "$S/acl" 2>/dev/null || echo "$*" >> "$S/acl" ;;
*) die "unexpected: $*" ;;
esac
`

// pbmStub is the same for proxmox-backup-manager.
const pbmStub = `#!/bin/sh
S="$STUB_STATE"
echo "proxmox-backup-manager $*" >> "$S/calls"
die() { echo "stub pbm: $*" >&2; exit 255; }
case "$1 $2" in
"user create")
  [ "${STUB_FAIL:-}" = "pbs-user-create" ] && die "user create refused"
  [ -e "$S/pbsuser.$3" ] && die "user '$3' already exists"
  : > "$S/pbsuser.$3" ;;
"user list")
  printf '[{"userid":"root@pam","enable":true}'
  for f in "$S"/pbsuser.*; do
    [ -e "$f" ] || continue
    b=${f##*/}
    printf ',{"userid":"%s","enable":true}' "${b#pbsuser.}"
  done
  echo ']' ;;
"user generate-token")
  [ "${STUB_FAIL:-}" = "pbs-generate-token" ] && die "generate-token refused"
  [ -e "$S/pbsuser.$3" ] || die "no such user ('$3')"
  [ -e "$S/pbstoken.$3!$4" ] && die "token already exists"
  : > "$S/pbstoken.$3!$4"
  echo "STUB-SECRET-$3!$4" >> "$S/secrets"
  echo "{\"tokenid\":\"$3!$4\",\"value\":\"STUB-SECRET-$3!$4\"}" ;;
"user list-tokens")
  printf '['
  sep=
  for f in "$S"/pbstoken."$3"!*; do
    [ -e "$f" ] || continue
    b=${f##*!}
    printf '%s{"tokenid":"%s!%s","enable":true}' "$sep" "$3" "$b"
    sep=,
  done
  echo ']' ;;
"acl update")
  if [ "${7:-}" = "--delete" ]; then
    if [ -e "$S/acl" ]; then
      grep -vxF "acl update $3 $4 $5 $6" "$S/acl" > "$S/acl.new" || true
      mv "$S/acl.new" "$S/acl"
    fi
  else
    grep -qxF "$*" "$S/acl" 2>/dev/null || echo "$*" >> "$S/acl"
  fi ;;
"acl list")
  # As PBS prints it with --output-format json: one compact line.
  printf '['
  sep=
  if [ -e "$S/acl" ]; then
    while read -r verb _ path role _ id; do
      [ "$verb" = acl ] || continue
      printf '%s{"path":"%s","ugid":"%s","ugid_type":"user","propagate":true,"roleid":"%s"}' "$sep" "$path" "$id" "$role"
      sep=,
    done < "$S/acl"
  fi
  echo ']' ;;
*) die "unexpected: $*" ;;
esac
`

// rbacSandbox runs a generated script with sh against the stubs.
type rbacSandbox struct {
	t       *testing.T
	script  string
	bin     string
	state   string
	command string
}

func newRBACSandbox(t *testing.T, params RBACParams) *rbacSandbox {
	t.Helper()
	return newRBACSandboxWith(t, params, "pveum", "proxmox-backup-manager")
}

// newRBACSandboxWith is a host that has only the named tools: "pveum" alone is a
// Proxmox VE node, "proxmox-backup-manager" alone a Proxmox Backup Server.
func newRBACSandboxWith(t *testing.T, params RBACParams, tools ...string) *rbacSandbox {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("runs the generated script with sh and stub executables")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	s := &rbacSandbox{t: t, command: sh, bin: filepath.Join(dir, "bin"), state: filepath.Join(dir, "state")}
	for _, d := range []string{s.bin, s.state} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bodies := map[string]string{"pveum": pveumStub, "proxmox-backup-manager": pbmStub}
	for _, name := range tools {
		if err := os.WriteFile(filepath.Join(s.bin, name), []byte(bodies[name]), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s.script = filepath.Join(dir, "access.sh")
	if err := os.WriteFile(s.script, []byte(scriptFor(t, params)), 0o644); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *rbacSandbox) run(extraEnv ...string) (stdout, stderr string, code int) {
	s.t.Helper()
	cmd := exec.Command(s.command, s.script)
	cmd.Env = append([]string{"PATH=" + s.bin + string(os.PathListSeparator) + os.Getenv("PATH"), "STUB_STATE=" + s.state, "HOME=" + s.state, "LC_ALL=C"}, extraEnv...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		s.t.Fatalf("running the script: %v", err)
	}
	return out.String(), errOut.String(), code
}

func (s *rbacSandbox) read(name string) string {
	data, err := os.ReadFile(filepath.Join(s.state, name))
	if err != nil && !os.IsNotExist(err) {
		s.t.Fatal(err)
	}
	return string(data)
}

// called counts the calls of the stubs that start with prefix.
func (s *rbacSandbox) called(prefix string) int {
	n := 0
	for _, line := range strings.Split(s.read("calls"), "\n") {
		if strings.HasPrefix(line, prefix) {
			n++
		}
	}
	return n
}

func (s *rbacSandbox) secrets() int {
	return len(strings.Fields(s.read("secrets")))
}

var rbacWithPBS = RBACParams{Node: "pve-node-01", OverlayStorage: "certistack-scratch", PBSDatastore: "datastore1"}

// A newcomer who runs the script twice (or after a half-finished first run)
// must not be stopped by what the first run created.
func TestRBACScriptCanBeRunAgain(t *testing.T) {
	s := newRBACSandbox(t, rbacWithPBS)
	stdout, stderr, code := s.run()
	if code != 0 {
		t.Fatalf("first run exited %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "STUB-SECRET-certistack-svc@pve!automation") || !strings.Contains(stdout, "STUB-SECRET-certistack-ro@pbs!ro") {
		t.Errorf("the first run did not show the two token secrets:\n%s", stdout)
	}
	if s.secrets() != 2 {
		t.Fatalf("first run created %d tokens, want 2", s.secrets())
	}
	acls := s.read("acl")

	stdout, stderr, code = s.run()
	if code != 0 {
		t.Fatalf("second run exited %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if s.secrets() != 2 {
		t.Errorf("after the second run %d tokens were created in all, want 2", s.secrets())
	}
	if strings.Contains(stdout+stderr, "STUB-SECRET") {
		t.Errorf("the second run printed a token secret:\n%s\n%s", stdout, stderr)
	}
	if got := s.read("acl"); got != acls {
		t.Errorf("the second run changed the ACLs:\nfirst:\n%s\nsecond:\n%s", acls, got)
	}
	if n := s.called("pveum role add "); n != 1 {
		t.Errorf("pveum role add was called %d times, want 1 (the second run must modify)", n)
	}
	if n := s.called("pveum user add "); n != 1 {
		t.Errorf("pveum user add was called %d times, want 1", n)
	}
	if n := s.called("proxmox-backup-manager user create "); n != 1 {
		t.Errorf("proxmox-backup-manager user create was called %d times, want 1", n)
	}
}

// An existing token is not an error: the script says its secret was shown once,
// how to replace it, and goes on to the ACLs.
func TestRBACScriptExplainsAnExistingTokenAndCarriesOn(t *testing.T) {
	s := newRBACSandbox(t, rbacWithPBS)
	if _, _, code := s.run(); code != 0 {
		t.Fatalf("first run exited %d", code)
	}
	if err := os.Remove(filepath.Join(s.state, "acl")); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := s.run()
	if code != 0 {
		t.Fatalf("second run exited %d\n%s\n%s", code, stdout, stderr)
	}
	both := stdout + stderr
	for _, want := range []string{
		"certistack-svc@pve!automation",
		"cannot be shown again",
		"pveum user token remove certistack-svc@pve automation",
		"run this script again",
		"certistack-ro@pbs!ro",
		"proxmox-backup-manager user delete-token certistack-ro@pbs ro",
	} {
		if !strings.Contains(both, want) {
			t.Errorf("the second run's output lacks %q:\n%s", want, both)
		}
	}
	// The ACL steps ran although both tokens existed.
	if got := strings.Count(s.read("acl"), "\n"); got != 5+2 {
		t.Errorf("the second run applied %d ACLs, want %d:\n%s", got, 5+2, s.read("acl"))
	}
	// Replacing the token as told creates exactly one new secret.
	if _, _, code := s.runCommand("pveum", "user", "token", "remove", "certistack-svc@pve", "automation"); code != 0 {
		t.Fatalf("removing the token: exit %d", code)
	}
	stdout, _, code = s.run()
	if code != 0 || !strings.Contains(stdout, "STUB-SECRET-certistack-svc@pve!automation") {
		t.Errorf("after removing the token the script did not create a new one (exit %d):\n%s", code, stdout)
	}
	if s.secrets() != 3 {
		t.Errorf("%d secrets issued in all, want 3 (two, then the replacement)", s.secrets())
	}
}

func (s *rbacSandbox) runCommand(name string, args ...string) (stdout, stderr string, code int) {
	s.t.Helper()
	cmd := exec.Command(filepath.Join(s.bin, name), args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "STUB_STATE=" + s.state}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			s.t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	return out.String(), errOut.String(), code
}

// A role left by an older CertiStack is brought to this version's list.
func TestRBACScriptSetsTheCurrentPrivilegesOnAnExistingRole(t *testing.T) {
	s := newRBACSandbox(t, RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch"})
	if err := os.WriteFile(filepath.Join(s.state, "role.CertiStackRole"), []byte("VM.Audit"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := s.run()
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if got, want := s.read("role.CertiStackRole"), strings.Join(RolePrivileges, " "); got != want {
		t.Errorf("the role holds %q, want the current list %q", got, want)
	}
	if n := s.called("pveum role add "); n != 0 {
		t.Errorf("pveum role add was called for a role that exists")
	}
}

// Review R2-10. A user or a token that exists is left as it is, and the script
// now says so in so many words: which object it found, and that it was not
// examined or changed. A user that is disabled, or a token that expired or was
// made by hand without privilege separation, stays so, and a later 401 would
// otherwise have nothing to point at.
func TestRBACScriptSaysWhichExistingObjectsItFoundAndLeftUntouched(t *testing.T) {
	s := newRBACSandbox(t, rbacWithPBS)
	if _, _, code := s.run(); code != 0 {
		t.Fatalf("first run exited %d", code)
	}
	stdout, stderr, code := s.run()
	if code != 0 {
		t.Fatalf("second run exited %d\n%s\n%s", code, stdout, stderr)
	}
	both := stdout + stderr
	for _, want := range []string{
		"Found the existing user certistack-svc@pve",
		"Found the existing API token certistack-svc@pve!automation",
		"Found the existing PBS user certistack-ro@pbs",
		"Found the existing PBS API token certistack-ro@pbs!ro",
	} {
		if !strings.Contains(both, want) {
			t.Errorf("the second run does not say %q:\n%s", want, both)
		}
	}
	// Each of the four says it was not examined or changed.
	if got := strings.Count(both, "not examined or changed"); got != 4 {
		t.Errorf("\"not examined or changed\" appears %d times, want 4 (user and token on PVE and on PBS):\n%s", got, both)
	}
	// Nothing was changed: no second user, no second token.
	if s.secrets() != 2 {
		t.Errorf("%d secrets issued, want 2", s.secrets())
	}
}

// A first run that died half way (the token step failed) is finished by the
// next one, which creates the token once.
func TestRBACScriptFinishesAHalfDoneFirstRun(t *testing.T) {
	for _, step := range []string{"token-add", "user-add", "pbs-generate-token", "pbs-user-create"} {
		t.Run(step, func(t *testing.T) {
			s := newRBACSandbox(t, rbacWithPBS)
			stdout, stderr, code := s.run("STUB_FAIL=" + step)
			if code == 0 {
				t.Fatalf("a failing %s did not stop the script:\n%s", step, stdout)
			}
			if !strings.Contains(stderr, "stopped while") {
				t.Errorf("no clear message on stderr:\n%s", stderr)
			}
			stdout, stderr, code = s.run()
			if code != 0 {
				t.Fatalf("the re-run exited %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if s.secrets() != 2 {
				t.Errorf("%d tokens in all, want 2", s.secrets())
			}
		})
	}
}

// A step that fails for a real reason still stops the script, with a message
// that says which step and what to do.
func TestRBACScriptStopsWithAClearMessageWhenAStepFails(t *testing.T) {
	s := newRBACSandbox(t, rbacWithPBS)
	stdout, stderr, code := s.run("STUB_FAIL=role-add")
	if code == 0 {
		t.Fatalf("a failing pveum role add did not stop the script:\n%s", stdout)
	}
	for _, want := range []string{"stopped while", "CertiStackRole", "run the script again"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if n := s.called("pveum user "); n != 0 {
		t.Errorf("the script went on after the role failed (%d later pveum user calls)", n)
	}
	if n := s.called("pveum acl "); n != 0 {
		t.Errorf("the script went on to the ACLs after the role failed")
	}
}

// The script holds no secret and never reads one: what it prints on a second
// run is only its own notes.
func TestRBACScriptHoldsNoSecret(t *testing.T) {
	script := scriptFor(t, rbacWithPBS)
	for _, forbidden := range []string{"--password", "PVE_TOKEN_SECRET=", "PBS_PASSWORD=", "$(pveum user token add", "$(proxmox-backup-manager user generate-token"} {
		for _, line := range strings.Split(script, "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, forbidden) {
				t.Errorf("the script captures or sets a secret (%s): %s", forbidden, line)
			}
		}
	}
}

// A namespace grant does not take back the grant on the whole datastore that an
// earlier run without a namespace made: the user could still read every
// namespace. The PBS part with a namespace looks for that grant, changing
// nothing. Printed, it says so and prints the commands that remove it; run by
// certistack setup, it reports who holds it on the capture descriptor, and
// setup offers to remove it. A grant that is not setup's own (another role) is
// not reported.
func TestRBACScriptFindsAnEarlierGrantOnTheWholeDatastore(t *testing.T) {
	whole := RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch", PBSDatastore: "datastore1", Part: PartPBS}
	s := newRBACSandboxWith(t, whole, "proxmox-backup-manager")
	if stdout, stderr, code := s.run(); code != 0 {
		t.Fatalf("the run without a namespace exited %d\n%s\n%s", code, stdout, stderr)
	}
	narrow := whole
	narrow.PBSNamespace = "prod"
	if err := os.WriteFile(s.script, []byte(scriptFor(t, narrow)), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := s.run()
	if code != 0 {
		t.Fatalf("the run with a namespace exited %d\n%s\n%s", code, stdout, stderr)
	}
	removals := []string{
		"proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id 'certistack-ro@pbs' --delete true",
		"proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id 'certistack-ro@pbs!ro' --delete true",
	}
	for _, want := range append([]string{"The PBS user can still read every namespace of the datastore datastore1"}, removals...) {
		if !strings.Contains(stdout, want) {
			t.Errorf("the printed script does not say %q:\n%s", want, stdout)
		}
	}
	// The commands it prints remove both grants, and only those.
	for _, removal := range removals {
		fields := strings.Fields(strings.ReplaceAll(removal, "'", ""))
		if _, _, code := s.runCommand(fields[0], fields[1:]...); code != 0 {
			t.Fatalf("%s: exit %d", removal, code)
		}
	}
	if acl := s.read("acl"); strings.Contains(acl, "/datastore/datastore1 ") || strings.Count(acl, "/datastore/datastore1/prod ") != 2 {
		t.Errorf("after the printed commands the ACLs are:\n%s", acl)
	}
	if stdout, _, _ := s.run(); strings.Contains(stdout, "can still read every namespace") {
		t.Errorf("the note is printed with no wider grant left:\n%s", stdout)
	}

	// Another role on the datastore is not setup's grant.
	if err := os.WriteFile(filepath.Join(s.state, "acl"), []byte("acl update /datastore/datastore1 DatastoreAudit --auth-id certistack-ro@pbs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if stdout, _, _ := s.run(); strings.Contains(stdout, "can still read every namespace") {
		t.Errorf("a grant of another role is reported:\n%s", stdout)
	}

	// Run by setup: one JSON line on the capture descriptor, nothing printed.
	if err := os.Remove(filepath.Join(s.state, "acl")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.script, []byte(scriptFor(t, whole)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := s.run(); code != 0 {
		t.Fatal("the run without a namespace failed")
	}
	narrow.Capture = true
	if err := os.WriteFile(s.script, []byte(scriptFor(t, narrow)), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = s.run()
	if code != 0 {
		t.Fatalf("the capture run exited %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, `{"wider_grant":"certistack-ro@pbs certistack-ro@pbs!ro"}`+"\n") || strings.Contains(stderr, "can still read every namespace") {
		t.Errorf("the capture run: stdout\n%s\nstderr\n%s", stdout, stderr)
	}
	if got := WiderGrantHolders(`certistack-ro@pbs certistack-ro@pbs!ro root@pam certistack-ro@pbs`); strings.Join(got, " ") != "certistack-ro@pbs certistack-ro@pbs!ro" {
		t.Errorf("WiderGrantHolders = %q", got)
	}
}

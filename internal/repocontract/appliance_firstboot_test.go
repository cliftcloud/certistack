// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The podman stub applies the wrapper's two bind mounts the only way a test
// without a mount namespace can: it maps the container paths they expose
// (/run/certistack-secrets and /var/lib/certistack) to host directories in
// every argument after the image, and in a copy of the environment file the
// wrapper names, then runs the real CLI with the empty environment a container
// starts with, from the image's working directory.
const firstBootPodman = `#!/bin/bash
printf '%s\n' "$@" > "$FB/podman.args"
secrets_host= state_host=
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [ "${args[i]}" = --volume ]; then
    case "${args[i+1]}" in
      *:/run/certistack-secrets:*) secrets_host=${args[i+1]%%:*} ;;
      *:/var/lib/certistack:*) state_host=${args[i+1]%%:*} ;;
    esac
  fi
done
[ -n "$secrets_host" ] && [ -n "$state_host" ] || { echo 'podman stub: the wrapper mounts neither directory' >&2; exit 64; }
translate() {
  case "$1" in
    /run/certistack-secrets*) printf '%s%s' "$secrets_host" "${1#/run/certistack-secrets}" ;;
    /var/lib/certistack*) printf '%s%s' "$state_host" "${1#/var/lib/certistack}" ;;
    *) printf '%s' "$1" ;;
  esac
}
rest=()
found=no
for ((i = 0; i < ${#args[@]}; i++)); do
  if [ $found = yes ]; then
    value=$(translate "${args[i]}")
    if [ "${args[i-1]}" = --env-file ]; then
      sed -e "s#/run/certistack-secrets#$secrets_host#g" -e "s#/var/lib/certistack#$state_host#g" "$value" > "$FB/env.translated"
      # The controller's default report directory is under the writable
      # /var/lib/certistack volume; the loader ignores the process environment.
      printf 'CERTISTACK_OUTPUT_DIR=%s\n' "$state_host/reports" >> "$FB/env.translated"
      chmod 0600 "$FB/env.translated"
      value=$FB/env.translated
    fi
    rest+=("$value")
  elif [ "${args[i]}" = "$STUB_IMAGE" ]; then
    found=yes
  fi
done
cd "$state_host"
exec env -i FB="$FB" PATH="$FB/stubs:/usr/bin:/bin" HOME="$FB" TMPDIR="$FB/tmp" "$FB/bin/certistack" "${rest[@]}"
`

// ssh answers the architecture check the way an amd64 node would; scp stops
// the run at the boundary the test is about: a controller that got this far
// has its environment and its CA settled.
const firstBootSSH = `#!/bin/sh
stub_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
printf 'ssh\n' >> "$stub_dir/transport.log"
case "$*" in *uname*-m*) printf '%s\n' x86_64 ;; esac
exit 0
`

const firstBootSCP = `#!/bin/sh
stub_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
printf 'scp\n' >> "$stub_dir/transport.log"
printf '%s\n' STUB_STOP_BEFORE_TRANSFER >&2
exit 86
`

var (
	controllerBuild     sync.Once
	controllerBuildPath string
	controllerBuildErr  error
)

// builtController compiles the CLI from this checkout, once per test binary.
func builtController(t *testing.T) string {
	t.Helper()
	controllerBuild.Do(func() {
		dir, err := os.MkdirTemp("", "certistack-firstboot-cli")
		if err != nil {
			controllerBuildErr = err
			return
		}
		controllerBuildPath = filepath.Join(dir, "certistack")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-o", controllerBuildPath, "./cmd/certistack")
		cmd.Dir = repoFile()
		if out, err := cmd.CombinedOutput(); err != nil {
			controllerBuildErr = &buildError{err: err, output: string(out)}
		}
	})
	if controllerBuildErr != nil {
		t.Fatalf("build the controller: %v", controllerBuildErr)
	}
	return controllerBuildPath
}

type buildError struct {
	err    error
	output string
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.output }

// readmeBlock returns the body of the appliance guide's code block under the
// "## " heading that contains the given text.
func readmeBlock(t *testing.T, heading, contains string) string {
	t.Helper()
	for _, block := range codeBlocks(t, repoFile("deploy", "appliance", "README.md")) {
		if block.heading == heading && strings.Contains(block.body, contains) {
			return block.body
		}
	}
	t.Fatalf("the appliance guide has no code block under %q containing %q", heading, contains)
	return ""
}

// firstBoot is one operator's walk through the appliance guide: the files in
// the guide's places, the guide's own commands, and the real controller
// behind the real wrapper, with only PVE and the container runtime replaced.
type firstBoot struct {
	t       *testing.T
	dir     string // the test's scratch root; the stubs see it as $FB
	wrapper string
	secrets string // /etc/certistack/secrets on the appliance
	state   string // /var/lib/certistack on the appliance
	work    string // where the operator has the files before installing them
}

func newFirstBoot(t *testing.T) *firstBoot {
	t.Helper()
	needTools(t, "sh", "go", "sed", "env")
	if testing.Short() || raceEnabled {
		t.Skip("compiles the controller; the plain, non-short run does it")
	}
	cli := builtController(t)
	wrapper, stubs, root, _ := applianceWrapperSetup(t)
	f := &firstBoot{t: t, dir: root, wrapper: wrapper}
	f.secrets = filepath.Join(root, "etc-certistack-secrets")
	f.state = filepath.Join(root, "var-lib-certistack")
	f.work = filepath.Join(root, "operator")
	for _, d := range []string{f.secrets, filepath.Join(f.state, "plans"), filepath.Join(f.state, "reports"), f.work, filepath.Join(root, "bin"), filepath.Join(root, "tmp")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The two bind mounts take their host side from this test's directories.
	script, err := os.ReadFile(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for old, replacement := range map[string]string{
		"--volume /var/lib/certistack:":         "--volume " + f.state + ":",
		"--volume /etc/certistack/secrets:/run": "--volume " + f.secrets + ":/run",
	} {
		if strings.Count(text, old) != 1 {
			t.Fatalf("the wrapper does not have exactly one %q to point at the test", old)
		}
		text = strings.Replace(text, old, replacement, 1)
	}
	writeExecutable(t, wrapper, text)
	if err := os.Symlink(cli, filepath.Join(root, "bin", "certistack")); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"podman":  firstBootPodman,
		"ssh":     firstBootSSH,
		"scp":     firstBootSCP,
		"sudo":    "#!/bin/sh\nexec \"$@\"\n",
		"install": installStub,
	} {
		writeExecutable(t, filepath.Join(stubs, name), body)
	}
	return f
}

func (f *firstBoot) env() []string {
	stubs := filepath.Join(f.dir, "stubs")
	return shellEnv(f.t, stubs+string(os.PathListSeparator)+filepath.Join(f.dir, "bin"), f.dir, map[string]string{
		"FB": f.dir, "STUB_LOG": filepath.Join(f.dir, "install.log"), "STUB_IMAGE": applianceTestImage,
	})
}

// runGuideBlock runs a code block from the guide as written, from the
// operator's working directory, with the appliance's /etc/certistack/secrets
// standing in the test's secrets directory.
func (f *firstBoot) runGuideBlock(body string) {
	f.t.Helper()
	body = strings.ReplaceAll(body, "/etc/certistack/secrets", f.secrets)
	if out, err := runStep(f.t, f.work, f.env(), body); err != nil {
		f.t.Fatalf("the guide's commands failed: %v\n%s\n%s", err, body, out)
	}
}

// prepare puts the operator's files in place the way the guide says and
// installs them with the guide's install command. mutateEnv edits the copy of
// controller.env.example that becomes controller.env.
func (f *firstBoot) prepare(mutateEnv func(string) string) {
	f.t.Helper()
	example, err := os.ReadFile(repoFile("deploy", "appliance", "files", "controller.env.example"))
	if err != nil {
		f.t.Fatal(err)
	}
	env := string(example)
	if mutateEnv != nil {
		env = mutateEnv(env)
	}
	for name, content := range map[string]string{
		"controller.env": env,
		"id_ed25519":     "synthetic identity\n",
		"known_hosts":    "pve-01.example.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFirstBootOnlySyntheticHostKey\n",
	} {
		if err := os.WriteFile(filepath.Join(f.work, name), []byte(content), 0o600); err != nil {
			f.t.Fatal(err)
		}
	}
	f.runGuideBlock(readmeBlock(f.t, "First boot", "sudo install -m 0600 -o 65532 -g 65532 controller.env"))

	plan, err := os.ReadFile(repoFile("examples", "minimal-single-vm.yaml"))
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.state, "plans", "my-first-plan.yaml"), plan, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// run is the guide's own first-boot invocation, through the real wrapper. It
// returns what the operator sees and which transport commands the controller
// reached.
func (f *firstBoot) run() (output, transport string) {
	f.t.Helper()
	var invocation []string
	for _, block := range codeBlocks(f.t, repoFile("deploy", "appliance", "README.md")) {
		if block.heading != "First boot" {
			continue
		}
		for _, command := range block.commands() {
			if fields := strings.Fields(command); len(fields) > 2 && fields[0] == "sudo" && fields[1] == "certistack-controller" {
				invocation = fields[2:]
			}
		}
	}
	if len(invocation) == 0 {
		f.t.Fatal("the guide's First boot section has no certistack-controller invocation")
	}
	cmd := exec.Command("sh", append([]string{f.wrapper}, invocation...)...)
	cmd.Env = f.env()
	out, _ := cmd.CombinedOutput()
	log, _ := os.ReadFile(filepath.Join(f.dir, "stubs", "transport.log"))
	return string(out), string(log)
}

// The guide's first boot, followed from empty state with the guide's own
// commands and the files it ships, reaches the controller's transfer boundary:
// it does not stop on the environment (PVE_URL is required), on a CA file the
// guide calls optional, or on a signing key (the Community controller needs
// none).
func TestApplianceFirstBootFollowsTheGuideToTheTransferBoundary(t *testing.T) {
	f := newFirstBoot(t)
	f.prepare(nil)
	out, transport := f.run()
	if !strings.Contains(out, "STUB_STOP_BEFORE_TRANSFER") || !strings.Contains(transport, "scp") {
		t.Fatalf("the guide's first boot does not reach the transfer:\n%s\ntransport: %q", out, transport)
	}
	for _, symptom := range []string{"report signing key", "is required", "stage PVE CA file", "no such file"} {
		if strings.Contains(out, symptom) {
			t.Errorf("the output mentions %q:\n%s", symptom, out)
		}
	}
}

// The same walk with one piece of the shipped files taken out, so the test
// above is known to stop on each of them, and with the CA the guide calls
// conditional installed the way the guide says.
func TestApplianceFirstBootStopsAtEachMissingPiece(t *testing.T) {
	for name, c := range map[string]struct {
		mutate   func(string) string
		caFile   bool
		want     string
		transfer bool
	}{
		"a signing key still named in controller.env": {
			mutate: func(env string) string {
				return env + "CERTISTACK_SIGN_KEY=/run/certistack-secrets/controller-signing.ed25519\n"
			},
			want: `unsupported controller environment variable "CERTISTACK_SIGN_KEY"`,
		},
		"the CA line active and no CA installed": {
			mutate: func(env string) string {
				return strings.Replace(env, "#CERTISTACK_PVE_CA_SOURCE=", "CERTISTACK_PVE_CA_SOURCE=", 1)
			},
			want: "stage PVE CA file",
		},
		"the CA line active and the CA installed as the guide says": {
			mutate: func(env string) string {
				return strings.Replace(env, "#CERTISTACK_PVE_CA_SOURCE=", "CERTISTACK_PVE_CA_SOURCE=", 1)
			},
			caFile:   true,
			transfer: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFirstBoot(t)
			f.prepare(c.mutate)
			if c.caFile {
				if err := os.WriteFile(filepath.Join(f.work, "pve-ca.pem"), []byte("synthetic CA\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				f.runGuideBlock(readmeBlock(t, "First boot", "install -m 0600 -o 65532 -g 65532 pve-ca.pem"))
			}
			out, transport := f.run()
			reached := strings.Contains(out, "STUB_STOP_BEFORE_TRANSFER") && strings.Contains(transport, "scp")
			if reached != c.transfer || (c.want != "" && !strings.Contains(out, c.want)) {
				t.Errorf("reached the transfer = %v, want %v; output should contain %q:\n%s", reached, c.transfer, c.want, out)
			}
		})
	}
}

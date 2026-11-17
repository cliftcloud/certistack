// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// installStub records what `install` would create and copies without needing
// root, so a recipe's owners and modes can be checked as an unprivileged user.
const installStub = `#!/usr/bin/env bash
mode= owner= group= dirs=false
args=()
while [ $# -gt 0 ]; do
  case $1 in
    -d) dirs=true ;;
    -m) mode=$2; shift ;;
    -o) owner=$2; shift ;;
    -g) group=$2; shift ;;
    *) args+=("$1") ;;
  esac
  shift
done
if $dirs; then
  for d in "${args[@]}"; do
    mkdir -p "$d"
    printf 'dir %s %s %s:%s\n' "$d" "$mode" "$owner" "$group" >> "$STUB_LOG"
  done
  exit 0
fi
last=$((${#args[@]} - 1))
dest=${args[$last]}
for ((i = 0; i < last; i++)); do
  target=$dest
  if [ -d "$dest" ]; then target=$dest/$(basename "${args[$i]}"); fi
  cp "${args[$i]}" "$target"
  printf 'file %s %s %s:%s\n' "$target" "$mode" "$owner" "$group" >> "$STUB_LOG"
done
`

func copyRepoFile(t *testing.T, root string, parts ...string) {
	t.Helper()
	data, err := os.ReadFile(repoFile(parts...))
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(append([]string{root}, parts...)...)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The container runs as UID 65532, which cannot read root-owned mode-0600
// files. Run from an empty checkout, the recipe gives every directory and
// secret file the container's owner and its mode as it writes it, and nothing
// in the secrets directory is copied any other way.
func TestControllerReadmeSetupHandsTheContainerItsFiles(t *testing.T) {
	needTools(t)
	readme := repoFile("deploy", "controller", "README.md")
	var setup []codeBlock
	for _, block := range codeBlocks(t, readme) {
		if block.heading == "Prepare controller secrets" && block.lang == "bash" {
			setup = append(setup, block)
		}
	}
	if len(setup) == 0 {
		t.Fatal("no bash block under the README's Prepare controller secrets")
	}

	// Every command that puts a file in the secrets directory is an install
	// naming the container's owner and 0600.
	owned := regexp.MustCompile(`^sudo install (-m 0600 -o 65532 -g 65532|-d -m 0700 -o 65532 -g 65532) `)
	for _, block := range setup {
		for _, command := range block.commands() {
			if !owned.MatchString(command) {
				t.Errorf("setup command %q does not give the container's UID its owner and mode", command)
			}
		}
	}

	// Run the first block from a checkout holding only what a fresh clone
	// gives it, with sudo and install stubbed.
	root := t.TempDir()
	stubs := filepath.Join(root, "stubs")
	if err := os.MkdirAll(stubs, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(stubs, "sudo"), "#!/bin/sh\nexec \"$@\"\n")
	writeExecutable(t, filepath.Join(stubs, "install"), installStub)
	checkout := filepath.Join(root, "checkout")
	copyRepoFile(t, checkout, "deploy", "controller", "secrets", "controller.env.example")
	copyRepoFile(t, checkout, "deploy", "controller", "secrets", "known_hosts.example")
	logPath := filepath.Join(root, "install.log")
	if out, err := runStep(t, checkout, shellEnv(t, stubs, root, map[string]string{"STUB_LOG": logPath}), setup[0].body); err != nil {
		t.Fatalf("the setup block failed from a fresh checkout: %v\n%s", err, out)
	}
	created := map[string]string{}
	for _, line := range readLog(t, logPath) {
		fields := strings.Fields(line)
		if len(fields) != 4 {
			t.Fatalf("unexpected install record %q", line)
		}
		created[fields[1]] = strings.Join(fields[2:], " ")
	}
	base := filepath.Join("deploy", "controller")
	for path, want := range map[string]string{
		filepath.Join(base, "secrets"):                   "0700 65532:65532",
		filepath.Join(base, "state"):                     "0700 65532:65532",
		filepath.Join(base, "plans"):                     "0700 65532:65532",
		filepath.Join(base, "secrets", "controller.env"): "0600 65532:65532",
		filepath.Join(base, "secrets", "known_hosts"):    "0600 65532:65532",
	} {
		if got := created[path]; got != want {
			t.Errorf("%s is created as %q, want %q", path, got, want)
		}
	}
	for _, name := range []string{"controller.env", "known_hosts"} {
		if _, err := os.Stat(filepath.Join(checkout, base, "secrets", name)); err != nil {
			t.Errorf("the recipe leaves no %s: %v", name, err)
		}
	}

	// The mounts Compose asks for are the directories the recipe makes.
	compose := composeFile(t)
	made := map[string]bool{"./secrets": true, "./state": true, "./plans": true}
	for _, volume := range compose.Services["controller"].Volumes {
		if source, _, _ := strings.Cut(volume, ":"); !made[source] {
			t.Errorf("Compose mounts %s, which the setup does not create", source)
		}
	}
	for _, file := range compose.Services["controller"].EnvFile {
		if file != "./secrets/controller.env" {
			t.Errorf("Compose reads env_file %s, not the file the setup creates", file)
		}
	}
}

type composeService struct {
	Image      string   `yaml:"image"`
	PullPolicy string   `yaml:"pull_policy"`
	EnvFile    []string `yaml:"env_file"`
	Volumes    []string `yaml:"volumes"`
}

type composeDocument struct {
	Services map[string]composeService `yaml:"services"`
}

func composeFile(t *testing.T) composeDocument {
	t.Helper()
	data, err := os.ReadFile(repoFile("deploy", "controller", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc composeDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Services["controller"]; !ok {
		t.Fatal("compose.yaml has no controller service")
	}
	return doc
}

// The guide is followed as one sequence from the repository root: it never
// changes directory, and every file a command names exists from there (after
// a `cd deploy/controller`, deploy/controller/compose.yaml would not).
func TestControllerReadmeCommandsRunFromTheRepositoryRoot(t *testing.T) {
	sawCompose := false
	for _, block := range codeBlocks(t, repoFile("deploy", "controller", "README.md")) {
		if block.lang != "bash" {
			continue
		}
		for _, command := range block.commands() {
			if regexp.MustCompile(`(^|[;&|] *)cd `).MatchString(command) {
				t.Errorf("the guide changes directory (%q), so later relative paths depend on where it left off", command)
			}
			if !strings.Contains(command, "docker ") {
				continue
			}
			fields := strings.Fields(command)
			for i, field := range fields {
				if field == "-f" && i+1 < len(fields) {
					if _, err := os.Stat(repoFile(fields[i+1])); err != nil {
						t.Errorf("%q names %s, which does not exist from the repository root", command, fields[i+1])
					}
					sawCompose = sawCompose || strings.HasSuffix(fields[i+1], "compose.yaml")
				}
			}
		}
	}
	if !sawCompose {
		t.Error("the guide has no docker compose command")
	}

	// The real Compose, where available, loads the file from the root.
	compose := dockerComposeConfig(t)
	if compose == "" {
		return
	}
	if !strings.Contains(compose, "pull_policy: missing") {
		t.Errorf("Compose resolves a policy other than missing:\n%s", compose)
	}
}

// dockerComposeConfig resolves the published Compose file with the real
// `docker compose config` against a checkout copy holding the secrets file,
// or returns "" when Compose is not installed. It talks to no daemon.
func dockerComposeConfig(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := append(os.Environ(), "DOCKER_HOST=unix:///nonexistent/certistack-test.sock", "DOCKER_CONFIG="+t.TempDir())
	probe := exec.CommandContext(ctx, "docker", "compose", "version")
	probe.Env = env
	if err := probe.Run(); err != nil {
		return ""
	}
	root := t.TempDir()
	copyRepoFile(t, root, "deploy", "controller", "compose.yaml")
	copyRepoFile(t, root, "deploy", "controller", "secrets", "controller.env.example")
	if err := os.Rename(filepath.Join(root, "deploy", "controller", "secrets", "controller.env.example"), filepath.Join(root, "deploy", "controller", "secrets", "controller.env")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", "deploy/controller/compose.yaml", "config")
	cmd.Dir = root
	cmd.Env = append(env, "CERTISTACK_CONTROLLER_IMAGE=certistack-controller:dev")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose config from the repository root: %v\n%s", err, out)
	}
	return string(out)
}

// The shared Compose service's pull policy is missing: an image the host has
// (the README's locally built certistack-controller:dev, or a digest-pinned
// image) is used as it is without a registry, and a pull is a deliberate
// --pull always.
func TestControllerComposeUsesTheLocalImageWithoutARegistry(t *testing.T) {
	service := composeFile(t).Services["controller"]
	if service.PullPolicy != "missing" {
		t.Errorf("pull_policy = %q; only missing uses a local image and needs no registry", service.PullPolicy)
	}
	if !strings.Contains(service.Image, "${CERTISTACK_CONTROLLER_IMAGE:?") {
		t.Errorf("image = %q; it must come from CERTISTACK_CONTROLLER_IMAGE, which the guide exports", service.Image)
	}
	readme, err := os.ReadFile(repoFile("deploy", "controller", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CERTISTACK_CONTROLLER_IMAGE=certistack-controller:dev", "--pull always", "pull_policy: missing"} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("the guide does not say %q", want)
		}
	}
}

// Compose's env_file has its own parser: it interpolates $VAR and ${VAR},
// processes escapes in quoted values and strips an inline comment, so a
// credential the CLI's literal loader accepts intact could reach the container
// as a different string. The service has no env_file; the controller reads
// controller.env itself, with --env-file.
func TestControllerComposeDoesNotParseTheEnvironmentFile(t *testing.T) {
	data, err := os.ReadFile(repoFile("deploy", "controller", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for name, service := range doc.Services {
		if _, has := service["env_file"]; has {
			t.Errorf("the %s service has env_file, which Compose parses with its own rules instead of the controller's literal loader", name)
		}
	}
	// The secrets directory stays mounted read-only: that is where the
	// controller opens the file.
	service := composeFile(t).Services["controller"]
	mounted := false
	for _, volume := range service.Volumes {
		mounted = mounted || volume == "./secrets:/run/certistack-secrets:ro"
	}
	if !mounted {
		t.Errorf("the controller service does not mount ./secrets read-only at /run/certistack-secrets: %v", service.Volumes)
	}
}

// Every container command of the guides that loads the controller
// environment passes the mounted file to the controller's own loader; only
// `version`, which reads no environment, is exempt.
func TestControllerContainerCommandsPassTheLiteralEnvironmentFile(t *testing.T) {
	const flag = "--env-file /run/certistack-secrets/controller.env"
	loaders := map[string]bool{"run": true, "plan": true, "validate": true, "doctor": true, "init": true, "check": true}
	files := map[string][]string{
		"deploy/controller/README.md": {"deploy", "controller", "README.md"},
	}
	sawRun := map[string]bool{}
	for name, parts := range files {
		for _, block := range codeBlocks(t, repoFile(parts...)) {
			for _, command := range block.commands() {
				_, after, found := strings.Cut(command, "docker compose ")
				if !found {
					continue
				}
				// The words after the service name are the controller's own.
				_, controller, found := strings.Cut(after, " controller ")
				if !found {
					continue
				}
				subcommand := strings.Fields(controller)[0]
				switch {
				case subcommand == "version":
				case loaders[subcommand]:
					if !strings.Contains(command, flag) {
						t.Errorf("%s: %q does not pass %s, so Compose would be the only reader of controller.env", name, command, flag)
					}
					sawRun[name] = sawRun[name] || subcommand == "run"
				default:
					t.Errorf("%s: %q runs a controller command (%s) this test does not know to read an environment file or not", name, command, subcommand)
				}
			}
		}
	}
	for name := range files {
		if !sawRun[name] {
			t.Errorf("%s has no container run command to check", name)
		}
	}
	// The guide says why the file is not left to Compose.
	readme := readRepoText(t, "deploy", "controller", "README.md")
	for _, want := range []string{"literal", "interpolat"} {
		if !strings.Contains(readme, want) {
			t.Errorf("the controller guide does not explain that controller.env is read literally by the controller, not by Compose (no %q)", want)
		}
	}
}

// docs/telemetry.md says where a container opts in: in the container's own
// environment, which is the Compose file's environment: block (the service has
// no env_file), and never in controller.env, whose literal loader refuses a name
// that is not one of its settings.
func TestTelemetryDocsSayHowAContainerOptsIn(t *testing.T) {
	doc := section(t, readRepoText(t, "docs", "telemetry.md"), "Under a service account")
	for _, want := range []string{"CERTISTACK_TELEMETRY=1", "`environment:`", "`deploy/controller/compose.yaml`", "`/usr/local/bin/certistack-controller`"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the telemetry section for containers lacks %q:\n%s", want, doc)
		}
	}
	if strings.Contains(doc, "env_file") {
		t.Errorf("the telemetry section points at env_file:\n%s", doc)
	}
	if !regexp.MustCompile(`(?m)^    environment:$`).MatchString(readRepoText(t, "deploy", "controller", "compose.yaml")) {
		t.Error("the controller service of deploy/controller/compose.yaml has no environment: block for the page to send the reader to")
	}
	if !strings.Contains(readRepoText(t, "deploy", "appliance", "files", "certistack-controller"), "podman run") {
		t.Error("the appliance wrapper has no podman run for the page to send the reader to")
	}
	if !strings.Contains(readRepoText(t, "docs", "telemetry.md"), "never read from `controller.env`") {
		t.Error("docs/telemetry.md does not say the usage statistics variables are never read from controller.env")
	}
}

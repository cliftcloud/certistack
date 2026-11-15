// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Hosted Ubuntu runners no longer ship Terraform, so every job that
// runs terraform first installs a pinned CLI. Every action is pinned by
// commit, and no step interpolates an expression into its shell (values
// reach the shell through env).
func TestWorkflowsInstallTerraformBeforeUsingIt(t *testing.T) {
	files, err := filepath.Glob(repoFile(".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	terraformCommand := regexp.MustCompile(`(?m)(^|[\s;&|(])terraform\s`)
	pinned := regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)
	exactVersion := regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	terraformSteps := 0
	for _, file := range files {
		for jobName, job := range readWorkflowFile(t, file).Jobs {
			where := filepath.Base(file) + " " + jobName
			installed := false
			for _, step := range job.Steps {
				if step.Uses != "" && !pinned.MatchString(step.Uses) {
					t.Errorf("%s: step %q uses %s, not pinned by commit", where, step.Name, step.Uses)
				}
				if strings.HasPrefix(step.Uses, "hashicorp/setup-terraform@") {
					installed = true
					if version, _ := step.With["terraform_version"].(string); !exactVersion.MatchString(version) {
						t.Errorf("%s: setup-terraform installs %q, not an exact version", where, version)
					}
				}
				if terraformCommand.MatchString(step.Run) {
					terraformSteps++
					if !installed {
						t.Errorf("%s: step %q runs terraform before installing it", where, step.Name)
					}
				}
				if strings.Contains(step.Run, "${{") {
					t.Errorf("%s: step %q interpolates an expression into its shell; pass it through env", where, step.Name)
				}
			}
		}
	}
	if terraformSteps < 2 {
		t.Fatalf("expected the CI and release jobs to run terraform, found %d steps", terraformSteps)
	}
}

// Both workflows take their Go version from go.mod, the one place it
// is set (see TestOneGoToolchainEverywhere), not from a literal of their own.
func TestWorkflowsTakeGoFromGoMod(t *testing.T) {
	for _, name := range []string{"ci.yml", "release.yml"} {
		workflow, err := os.ReadFile(repoFile(".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`go-version:`).Match(workflow) || !strings.Contains(string(workflow), "go-version-file: go.mod") {
			t.Errorf("%s must take its Go version from go.mod (go-version-file), not a second literal", name)
		}
	}
}

// The release gate accepts only a stable SemVer tag without leading
// zeros, and a dated changelog heading for exactly that version.
func TestReleaseMetadataGate(t *testing.T) {
	needTools(t, "git", "sed", "grep")
	_, gate := readWorkflow(t, "release.yml").Jobs["verify"].step(t, "Validate release metadata")
	for _, c := range []struct {
		tag, heading string
		pass         bool
	}{
		{"v1.2.3", "## [1.2.3] - 2026-09-29", true},
		{"v0.1.0", "## [0.1.0] - 2026-09-29", true},
		{"v10.20.30", "## [10.20.30] - 2026-09-29", true},
		{"v1.2.3", "## [1x2x3] - 2026-09-29", false},
		{"v1.2.3", "## [1.2.4] - 2026-09-29", false},
		{"v1.2.3", "## [1.2.3]", false},
		{"v1.2.3", "## [1.2.3] - 2026-09-29 (draft)", false},
		{"v1.2.3", "## [11.2.3] - 2026-09-29", false},
		{"v01.2.3", "## [01.2.3] - 2026-09-29", false},
		{"v1.02.3", "## [1.02.3] - 2026-09-29", false},
		{"v1.2.03", "## [1.2.03] - 2026-09-29", false},
		{"v1.2.3-rc.1", "## [1.2.3-rc.1] - 2026-09-29", false},
		{"v1.2", "## [1.2] - 2026-09-29", false},
	} {
		dir := t.TempDir()
		changelog := "# Changelog\n\n## [Unreleased]\n\n" + c.heading + "\n\n- A change.\n"
		if err := os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), []byte(changelog), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"init", "-q"}, {"add", "CHANGELOG.md"}} {
			cmd := exec.Command("git", args...)
			cmd.Dir = dir
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
		out, err := runStep(t, dir, shellEnv(t, dir, dir, map[string]string{"RELEASE_TAG": c.tag}), gate.Run)
		if (err == nil) != c.pass {
			t.Errorf("tag %s, heading %q: passed=%v, want %v\n%s", c.tag, c.heading, err == nil, c.pass, out)
		}
	}
}

// The publish job's steps that touch signing, the release notes or the
// registry, in workflow order.
var releasePublicationSteps = []string{
	"Check release signing configuration",
	"Refuse to replace a published release",
	"Write release notes",
	"Stage controller image under its candidate tag",
	"Generate Checksums",
	"Sign release checksums",
	"Verify release artifacts before publication",
	"Promote the signed image to its version tag",
}

const releaseDockerStub = `#!/usr/bin/env bash
printf 'docker %s\n' "$*" >> "$STUB_LOG"
case "$1" in
login) cat >/dev/null ;;
logout|push) ;;
inspect) printf '%s@%s\n' "$IMAGE_REPOSITORY" "$STUB_PUSHED_DIGEST" ;;
buildx)
	case "$2 $3" in
	"imagetools create") ;;
	"imagetools inspect") printf '%s' "$STUB_REGISTRY_MANIFEST" ;;
	*) echo "docker stub: unexpected $*" >&2; exit 64 ;;
	esac ;;
*) echo "docker stub: unexpected $*" >&2; exit 64 ;;
esac
`

const releaseGHStub = `#!/usr/bin/env bash
printf 'gh %s\n' "$*" >> "$STUB_LOG"
case "$STUB_RELEASE" in
missing) echo 'release not found' >&2; exit 1 ;;
draft) echo true ;;
published) echo false ;;
*) echo 'HTTP 502: Bad Gateway' >&2; exit 1 ;;
esac
`

type releaseKey struct {
	private, public, fingerprint string
}

const releasePassphrase = "release-test-passphrase"

// newReleaseKey generates a throwaway passphrase-protected signing key.
func newReleaseKey(t *testing.T) releaseKey {
	t.Helper()
	home := t.TempDir()
	t.Cleanup(func() {
		kill := exec.Command("gpgconf", "--kill", "gpg-agent")
		kill.Env = append(os.Environ(), "GNUPGHOME="+home)
		_ = kill.Run()
	})
	gpg := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("gpg", append([]string{"--batch", "--pinentry-mode", "loopback", "--passphrase", releasePassphrase}, args...)...)
		cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("gpg %v: %v", args, err)
		}
		return string(out)
	}
	gpg("--quick-gen-key", "CertiStack release test <release-test@example.invalid>", "ed25519", "sign", "never")
	key := releaseKey{}
	for _, line := range strings.Split(gpg("--with-colons", "--list-secret-keys"), "\n") {
		if fields := strings.Split(line, ":"); len(fields) > 9 && fields[0] == "fpr" {
			key.fingerprint = fields[9]
			break
		}
	}
	if key.fingerprint == "" {
		t.Fatal("no fingerprint for the generated key")
	}
	key.private = gpg("--armor", "--export-secret-keys", key.fingerprint)
	key.public = gpg("--armor", "--export", key.fingerprint)
	return key
}

type releaseOutcome struct {
	failedStep string
	output     string
	log        []string
	workspace  string
	outputs    string
}

const releaseChangelog = "# Changelog\n\n## [Unreleased]\n\n## [1.2.3] - 2026-09-29\n\nFirst release.\n\n### Added\n- A thing.\n\n## [1.2.2] - 2026-09-01\n\nOlder.\n"

// runReleasePublication runs the publish job's signing, notes and registry
// steps in order against stub docker and gh programs, stopping at the first
// failure as Actions does. The release-creating action records
// "github-release". Each step sees only the secrets its env declares.
func runReleasePublication(t *testing.T, secrets map[string]string, release string, registryManifest string, changelog string) releaseOutcome {
	t.Helper()
	job := readWorkflow(t, "release.yml").Jobs["publish"]
	publication := map[string]bool{}
	previous := -1
	for _, name := range releasePublicationSteps {
		index, _ := job.step(t, name)
		if index < previous {
			t.Fatalf("step %q is out of the expected order", name)
		}
		previous = index
		publication[name] = true
	}

	root := t.TempDir()
	stubs, workspace, home := filepath.Join(root, "stubs"), filepath.Join(root, "workspace"), filepath.Join(root, "home")
	for _, dir := range []string{stubs, filepath.Join(workspace, "bin"), home, filepath.Join(root, "runner")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(workspace, "bin", "certistack-linux-amd64"), []byte("test binary\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "CHANGELOG.md"), []byte(changelog), 0o600); err != nil {
		t.Fatal(err)
	}
	// The key the tagged tree commits for users to import. It is not a secret
	// of any step (no step's env names it); "-" means the file is absent.
	if committed, ok := secrets["COMMITTED_RELEASE_PUBLIC_KEY"]; ok && committed != "-" {
		if err := os.MkdirAll(filepath.Join(workspace, "release"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workspace, "release", "release-public-key.asc"), []byte(committed), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable(t, filepath.Join(stubs, "docker"), releaseDockerStub)
	writeExecutable(t, filepath.Join(stubs, "gh"), releaseGHStub)

	const pushedManifest = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`
	sum := sha256.Sum256([]byte(pushedManifest))
	if registryManifest == "" {
		registryManifest = pushedManifest
	}
	logPath := filepath.Join(root, "calls.log")
	githubOutput := filepath.Join(root, "github-output")
	outcome := releaseOutcome{workspace: workspace}
	for _, step := range job.Steps {
		if strings.HasPrefix(step.Uses, "softprops/action-gh-release@") {
			f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.WriteString("github-release\n")
			_ = f.Close()
			continue
		}
		if !publication[step.Name] {
			if regexp.MustCompile(`docker (login|push)|imagetools create|gh release`).MatchString(step.Run) {
				t.Errorf("step %q writes to the registry or releases but is not in the tested publication path", step.Name)
			}
			continue
		}
		extra := map[string]string{
			"STUB_LOG":               logPath,
			"STUB_RELEASE":           release,
			"STUB_PUSHED_DIGEST":     "sha256:" + hex.EncodeToString(sum[:]),
			"STUB_REGISTRY_MANIFEST": registryManifest,
			"IMAGE_REPOSITORY":       "ghcr.io/test-owner/certistack-controller",
			"RELEASE_TAG":            "v1.2.3",
			"RUNNER_TEMP":            filepath.Join(root, "runner"),
			"GITHUB_OUTPUT":          githubOutput,
		}
		for name := range step.Env {
			extra[name] = secrets[name]
		}
		out, err := runStep(t, workspace, shellEnv(t, stubs, home, extra), step.Run)
		if err != nil {
			outcome.failedStep, outcome.output = step.Name, out
			break
		}
	}
	outcome.log = readLog(t, logPath)
	if data, err := os.ReadFile(githubOutput); err == nil {
		outcome.outputs = string(data)
	}
	return outcome
}

// Nothing reaches the registry before the release set can be signed
// and verified, and the version tag is written last, to the signed digest.
// The reported case was a missing signing fingerprint or public key after
// the final tag had already been pushed. The notes are checked
// before any registry write too.
func TestReleaseSignsBeforeAnyRegistryWrite(t *testing.T) {
	needTools(t, "gpg", "gpgv", "gpgconf", "sha256sum", "awk", "mktemp")
	key := newReleaseKey(t)
	other := newReleaseKey(t)
	good := map[string]string{
		"GPG_PRIVATE_KEY":         key.private,
		"GPG_RELEASE_PUBLIC_KEY":  key.public,
		"GPG_PASSPHRASE":          releasePassphrase,
		"GPG_SIGNING_FINGERPRINT": key.fingerprint,
		// What release/release-public-key.asc holds at the tag (see runReleasePublication).
		"COMMITTED_RELEASE_PUBLIC_KEY": key.public,
		"GHCR_TOKEN":                   "test-token",
		"GHCR_USER":                    "test-actor",
		"GH_TOKEN":                     "test-token",
		"GH_REPO":                      "test-owner/certistack",
	}
	with := func(name, value string) map[string]string {
		secrets := map[string]string{}
		for k, v := range good {
			secrets[k] = v
		}
		secrets[name] = value
		return secrets
	}

	for _, c := range []struct {
		name, release, changelog, failedStep string
		secrets                              map[string]string
	}{
		{"missing fingerprint", "missing", releaseChangelog, "Check release signing configuration", with("GPG_SIGNING_FINGERPRINT", "")},
		{"missing public key", "missing", releaseChangelog, "Check release signing configuration", with("GPG_RELEASE_PUBLIC_KEY", "")},
		{"missing private key", "missing", releaseChangelog, "Check release signing configuration", with("GPG_PRIVATE_KEY", "")},
		{"wrong passphrase", "missing", releaseChangelog, "Check release signing configuration", with("GPG_PASSPHRASE", "not-the-passphrase")},
		{"public key of another key", "missing", releaseChangelog, "Check release signing configuration", with("GPG_RELEASE_PUBLIC_KEY", other.public)},
		// The key users are told to trust, committed in the tagged tree, must be the key that signs:
		// a release that verifies only against the secret would verify for nobody else.
		{"committed key of another key", "missing", releaseChangelog, "Check release signing configuration", with("COMMITTED_RELEASE_PUBLIC_KEY", other.public)},
		{"committed file is not a key", "missing", releaseChangelog, "Check release signing configuration", with("COMMITTED_RELEASE_PUBLIC_KEY", "not an OpenPGP key\n")},
		{"committed file missing", "missing", releaseChangelog, "Check release signing configuration", with("COMMITTED_RELEASE_PUBLIC_KEY", "-")},
		{"committed file holds two keys", "missing", releaseChangelog, "Check release signing configuration", with("COMMITTED_RELEASE_PUBLIC_KEY", key.public+"\n"+other.public)},
		{"release already published", "published", releaseChangelog, "Refuse to replace a published release", good},
		{"release state unknown", "error", releaseChangelog, "Refuse to replace a published release", good},
		{"no changelog notes for the version", "missing", "# Changelog\n\n## [1.2.2] - 2026-09-01\n\nOlder.\n", "Write release notes", good},
		{"an empty changelog section", "missing", "# Changelog\n\n## [1.2.3] - 2026-09-29\n\n\n## [1.2.2] - 2026-09-01\n\nOlder.\n", "Write release notes", good},
	} {
		outcome := runReleasePublication(t, c.secrets, c.release, "", c.changelog)
		if outcome.failedStep != c.failedStep {
			t.Errorf("%s: failed at %q, want %q\n%s", c.name, outcome.failedStep, c.failedStep, outcome.output)
		}
		for _, call := range outcome.log {
			if strings.HasPrefix(call, "docker ") || call == "github-release" {
				t.Errorf("%s: %q ran although the release could not be signed, may not be replaced, or has no notes", c.name, call)
			}
		}
	}

	for _, release := range []string{"missing", "draft"} {
		outcome := runReleasePublication(t, good, release, "", releaseChangelog)
		if outcome.failedStep != "" {
			t.Fatalf("release %s: failed at %q\n%s", release, outcome.failedStep, outcome.output)
		}
		signed, err := os.ReadFile(filepath.Join(outcome.workspace, "bin", "CONTAINER-IMAGE.txt"))
		if err != nil {
			t.Fatal(err)
		}
		digestRef := strings.TrimSpace(string(signed))
		if want := "digest=sha256:" + digestRef[strings.LastIndex(digestRef, "@sha256:")+len("@sha256:"):]; !strings.Contains(outcome.outputs, want) {
			t.Errorf("release %s: the job's image digest output is %q, want %q for the attestation job", release, outcome.outputs, want)
		}
		position := map[string]int{}
		for i, call := range outcome.log {
			if strings.HasPrefix(call, "docker push ") && !strings.HasSuffix(call, ":candidate-1.2.3") {
				t.Errorf("release %s: pushed %q; only the candidate tag is pushed", release, call)
			}
			for _, want := range []string{
				"docker push ghcr.io/test-owner/certistack-controller:candidate-1.2.3",
				"github-release",
				"docker buildx imagetools create --prefer-index=false --tag ghcr.io/test-owner/certistack-controller:1.2.3 " + digestRef,
			} {
				if call == want {
					position[want] = i + 1
				}
			}
		}
		push := position["docker push ghcr.io/test-owner/certistack-controller:candidate-1.2.3"]
		published := position["github-release"]
		promoted := position["docker buildx imagetools create --prefer-index=false --tag ghcr.io/test-owner/certistack-controller:1.2.3 "+digestRef]
		if push == 0 || published == 0 || promoted == 0 || !(push < published && published < promoted) {
			t.Errorf("release %s: want candidate push, then release, then version tag; calls:\n%s", release, strings.Join(outcome.log, "\n"))
		}
		if _, err := os.Stat(filepath.Join(outcome.workspace, "bin", "SHA256SUMS-bin.txt.asc")); err != nil {
			t.Errorf("release %s: no signature: %v", release, err)
		}
	}

	// The registry answering with another manifest for the version tag
	// fails the promotion rather than passing it.
	outcome := runReleasePublication(t, good, "missing", `{"schemaVersion":2,"note":"another manifest"}`, releaseChangelog)
	if outcome.failedStep != "Promote the signed image to its version tag" || !strings.Contains(outcome.output, "not the signed sha256:") {
		t.Errorf("mismatched version tag: failed at %q\n%s", outcome.failedStep, outcome.output)
	}
}

// The release notes are the changelog section of the version, read
// literally (a heading with the version's digits and other separators is not
// it), followed by where to verify the release; and the release is created as
// a draft, so a maintainer publishes it after reading the notes.
func TestReleaseNotesComeFromTheChangelogAndTheReleaseIsADraft(t *testing.T) {
	needTools(t, "awk", "grep")
	job := readWorkflow(t, "release.yml").Jobs["publish"]
	_, notes := job.step(t, "Write release notes")
	dir := t.TempDir()
	changelog := "# Changelog\n\n## [Unreleased]\n\n- Unreleased.\n\n## [1x2x3] - 2026-09-30\n\nDecoy.\n\n## [1.2.3] - 2026-09-29\n\nFirst release.\n\n### Added\n- A thing.\n\n## [1.2.2] - 2026-09-01\n\nOlder.\n"
	if err := os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), []byte(changelog), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := t.TempDir()
	out, err := runStep(t, dir, shellEnv(t, dir, dir, map[string]string{"RELEASE_TAG": "v1.2.3", "RUNNER_TEMP": runner, "GH_REPO": "test-owner/certistack"}), notes.Run)
	if err != nil {
		t.Fatalf("notes: %v\n%s", err, out)
	}
	body, err := os.ReadFile(filepath.Join(runner, "release-notes.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"First release.", "### Added", "- A thing.", "github.com/test-owner/certistack/blob/v1.2.3/SECURITY.md#verifying-release-integrity", "CONTAINER-IMAGE.txt"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("release notes lack %q:\n%s", want, body)
		}
	}
	for _, unwanted := range []string{"Decoy.", "Unreleased.", "Older."} {
		if strings.Contains(string(body), unwanted) {
			t.Errorf("release notes include %q from another section:\n%s", unwanted, body)
		}
	}

	_, release := job.step(t, "Create draft GitHub release")
	if release.With["draft"] != true {
		t.Errorf("the release is created with draft=%v; a maintainer publishes it", release.With["draft"])
	}
	if release.With["generate_release_notes"] == true || release.With["body_path"] == nil || release.With["fail_on_unmatched_files"] != true {
		t.Errorf("the release must use the changelog notes and fail on a missing asset: %v", release.With)
	}
}

// Publication is gated and least-privilege. Anyone who can push a
// tag can start the workflow, so the tag alone must never reach signing or a
// write: the read-only verify job holds no secret and no write permission
// (third-party code runs in it), one job behind the protected `release`
// environment holds the signing secrets and write access, and only the two
// attestation jobs may ask for an identity token.
func TestReleaseWorkflowGatesPublicationAndSplitsPrivileges(t *testing.T) {
	raw := rawWorkflow(t, "release.yml")
	workflow := readWorkflow(t, "release.yml")

	// Trigger: stable tags only, and nothing that lets another ref start it.
	on, _ := raw["on"].(map[string]any)
	if len(on) != 1 {
		t.Errorf("the workflow has triggers %v; only a tag push may start a release", on)
	}
	push, _ := on["push"].(map[string]any)
	tags, _ := push["tags"].([]any)
	if len(push) != 1 || len(tags) != 1 || tags[0] != "v[0-9]+.[0-9]+.[0-9]+" {
		t.Errorf("push trigger %v; want tags: ['v[0-9]+.[0-9]+.[0-9]+'] only", push)
	}
	if _, present := raw["permissions"]; !present || len(workflow.Permissions) != 0 {
		t.Errorf("workflow-level permissions %v (present: %v); no job may inherit any", workflow.Permissions, present)
	}
	if workflow.Defaults.Run.Shell != "bash" {
		t.Errorf("default shell %q; steps must run `bash -eo pipefail`, which a runner only does when bash is named", workflow.Defaults.Run.Shell)
	}

	wantPermissions := map[string]map[string]string{
		"verify":        {"contents": "read"},
		"publish":       {"actions": "read", "contents": "write", "packages": "write"},
		"attest-binary": {"id-token": "write", "attestations": "write"},
		"attest-image":  {"id-token": "write", "attestations": "write", "packages": "write"},
	}
	if len(workflow.Jobs) != len(wantPermissions) {
		t.Errorf("jobs %v; the tested privilege split covers verify, publish, attest-binary and attest-image", jobNames(workflow))
	}
	for name, want := range wantPermissions {
		job, ok := workflow.Jobs[name]
		if !ok {
			t.Errorf("no %s job", name)
			continue
		}
		if fmt.Sprint(job.Permissions) != fmt.Sprint(want) {
			t.Errorf("%s permissions %v, want %v", name, job.Permissions, want)
		}
	}

	// Only publish sits behind the environment, and only publish sees the
	// signing secrets; verify sees no secret of any kind.
	for name, job := range workflow.Jobs {
		body, err := yaml.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		if (job.environmentName() == "release") != (name == "publish") {
			t.Errorf("job %s has environment %q; only publish is gated", name, job.environmentName())
		}
		if strings.Contains(string(body), "GPG_") && name != "publish" {
			t.Errorf("job %s references the signing secrets", name)
		}
		if name == "verify" && strings.Contains(string(body), "secrets.") {
			t.Errorf("the read-only verify job references a secret")
		}
	}
	if got := workflow.Jobs["publish"].needs(); fmt.Sprint(got) != "[verify]" {
		t.Errorf("publish needs %v, want [verify]", got)
	}
	if got := workflow.Jobs["attest-binary"].needs(); fmt.Sprint(got) != "[verify publish]" {
		t.Errorf("attest-binary needs %v; it may run only after publish", got)
	}
	if got := workflow.Jobs["attest-image"].needs(); fmt.Sprint(got) != "[publish]" {
		t.Errorf("attest-image needs %v; it may run only after publish", got)
	}

	// Checkouts leave no credential in .git, the release build restores no
	// cache another workflow could have written, and code fetched from
	// elsewhere runs only in the read-only job.
	third := regexp.MustCompile(`go install|terraform |pip |npm |curl |wget `)
	for name, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/checkout@") && step.With["persist-credentials"] != false {
				t.Errorf("%s: checkout %q leaves the token in .git/config", name, step.Name)
			}
			if strings.HasPrefix(step.Uses, "actions/setup-go@") && step.With["cache"] != false {
				t.Errorf("%s: setup-go %q restores a build cache", name, step.Name)
			}
			if name != "verify" && third.MatchString(step.Run) {
				t.Errorf("%s: step %q runs third-party tooling in a job with write access or secrets", name, step.Name)
			}
		}
	}
	if _, checkout := workflow.Jobs["verify"].step(t, "Checkout Code"); checkout.With["fetch-depth"] != 0 {
		t.Error("the verify job's checkout must fetch the full history, or the default branch cannot be checked")
	}

	// In the publish job the environment's protection is verified before any
	// step uses a secret or writes anywhere, and the version tag comes last.
	publish := workflow.Jobs["publish"]
	order := []string{
		"Require the release environment's protection",
		"Download the verified executable",
		"Check the executable is the verified one",
		"Check release signing configuration",
		"Refuse to replace a published release",
		"Write release notes",
		"Build controller image",
		"Stage controller image under its candidate tag",
		"Sign release checksums",
		"Verify release artifacts before publication",
		"Create draft GitHub release",
		"Promote the signed image to its version tag",
	}
	previous := -1
	for _, name := range order {
		index, _ := publish.step(t, name)
		if index <= previous {
			t.Errorf("publish step %q is out of order", name)
		}
		previous = index
	}
	guard, _ := publish.step(t, "Require the release environment's protection")
	for i, step := range publish.Steps[:guard] {
		body, _ := yaml.Marshal(step)
		if strings.Contains(string(body), "secrets.") {
			t.Errorf("step %d %q uses a secret before the environment's protection is verified", i, step.Name)
		}
	}
	// The image is built around the verified executable, never compiled again.
	_, build := publish.step(t, "Build controller image")
	if !strings.Contains(build.Run, "make container-release") || regexp.MustCompile(`make container( |$)`).MatchString(build.Run) {
		t.Errorf("the release image must be built with make container-release:\n%s", build.Run)
	}
	if check := strings.Index(build.Run, "check-image-binary.sh"); check < 0 || check > strings.Index(build.Run, "docker run") {
		t.Error("the image's executable must be checked against the verified one before the image is run")
	}
	if strings.Contains(build.Run, "docker push") || strings.Contains(build.Run, "docker login") {
		t.Error("the build step must not write to the registry")
	}
}

func jobNames(workflow workflowFile) []string {
	var names []string
	for name := range workflow.Jobs {
		names = append(names, name)
	}
	return names
}

const environmentGHStub = `#!/usr/bin/env bash
printf 'gh %s\n' "$*" >> "$STUB_LOG"
if [ -z "$STUB_ENVIRONMENT" ]; then echo 'HTTP 403: Resource not accessible by integration' >&2; exit 1; fi
printf '%s\n' "$STUB_ENVIRONMENT"
`

// An environment GitHub creates on first use has no protection, so
// the publish job reads the environment's rules first and refuses unless a
// reviewer is required and the refs that may deploy are restricted.
func TestPublishRefusesAnUnprotectedReleaseEnvironment(t *testing.T) {
	needTools(t, "jq")
	_, step := readWorkflow(t, "release.yml").Jobs["publish"].step(t, "Require the release environment's protection")
	stubs := t.TempDir()
	writeExecutable(t, filepath.Join(stubs, "gh"), environmentGHStub)
	const reviewers = `{"type":"required_reviewers","reviewers":[{"type":"User","reviewer":{"login":"maintainer"}}]}`
	for _, c := range []struct {
		name, environment, want string
		pass                    bool
	}{
		{"reviewers and restricted refs", `{"protection_rules":[` + reviewers + `],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}`, "", true},
		{"a wait timer among the rules", `{"protection_rules":[{"type":"wait_timer","wait_timer":30},` + reviewers + `],"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}`, "", true},
		{"no protection rules", `{"protection_rules":[],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}`, "requires no reviewer", false},
		{"protection_rules absent", `{"name":"release"}`, "requires no reviewer", false},
		{"only a wait timer", `{"protection_rules":[{"type":"wait_timer","wait_timer":5}],"deployment_branch_policy":{"custom_branch_policies":true}}`, "requires no reviewer", false},
		{"reviewers but any ref may deploy", `{"protection_rules":[` + reviewers + `],"deployment_branch_policy":null}`, "any ref", false},
		{"reviewers and no branch policy field", `{"protection_rules":[` + reviewers + `]}`, "any ref", false},
		{"the API refuses the token", "", "Could not read", false},
	} {
		out, err := runStep(t, t.TempDir(), shellEnv(t, stubs, t.TempDir(), map[string]string{
			"STUB_LOG": filepath.Join(stubs, "gh.log"), "STUB_ENVIRONMENT": c.environment,
			"GH_TOKEN": "test-token", "GH_REPO": "test-owner/certistack",
		}), step.Run)
		if (err == nil) != c.pass || (c.want != "" && !strings.Contains(out, c.want)) {
			t.Errorf("%s: passed=%v (%v), want pass=%v containing %q\n%s", c.name, err == nil, err, c.pass, c.want, out)
		}
	}
	if calls := readLog(t, filepath.Join(stubs, "gh.log")); len(calls) == 0 || calls[0] != "gh api repos/test-owner/certistack/environments/release" {
		t.Errorf("gh calls %q, want a read of the release environment", calls)
	}
}

// candidateFixture is a repository shaped like a checkout of a tag push: a
// release commit R on the default branch, the commit M that registered R's
// candidate, and a side commit X that is on no reviewed branch.
type candidateFixture struct {
	dir, release, main, side string
}

const fixtureDate = "2026-01-02T03:04:05+0000"

// newCandidateFixture builds it. staleCopy is the registry in R's own tree;
// registry gives the content M commits (M is skipped when it is empty).
func newCandidateFixture(t *testing.T, staleCopy string, registry func(release, side string) string) candidateFixture {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, dir, fixtureDate, "init", "-q", "-b", "main")
	write("release/candidates.txt", staleCopy)
	write("code", "release\n")
	gitIn(t, dir, fixtureDate, "add", ".")
	gitIn(t, dir, fixtureDate, "commit", "-q", "-m", "release commit")
	fixture := candidateFixture{dir: dir, release: gitIn(t, dir, fixtureDate, "rev-parse", "HEAD")}
	gitIn(t, dir, fixtureDate, "checkout", "-q", "-b", "elsewhere")
	write("code", "side\n")
	gitIn(t, dir, fixtureDate, "commit", "-q", "-am", "side commit")
	fixture.side = gitIn(t, dir, fixtureDate, "rev-parse", "HEAD")
	gitIn(t, dir, fixtureDate, "checkout", "-q", "main")
	if content := registry(fixture.release, fixture.side); content != "" {
		write("release/candidates.txt", content)
		gitIn(t, dir, fixtureDate, "commit", "-q", "-am", "register the candidate")
	}
	fixture.main = gitIn(t, dir, fixtureDate, "rev-parse", "HEAD")
	return fixture
}

const candidateHeader = "# Release candidates.\n\n"

func candidateLine(tag, commit string) string {
	return tag + " " + commit + " " + strings.Repeat("ab", 32) + "\n"
}

// A tag proves nothing by itself. The workflow publishes only a
// commit that is on the default branch and that the default branch's registry
// names for this tag, and reads the registry from the default branch, never
// from the tagged tree.
func TestReleaseTagMustNameARegisteredCandidate(t *testing.T) {
	needTools(t, "git", "awk")
	_, step := readWorkflow(t, "release.yml").Jobs["verify"].step(t, "Check the tag names a registered candidate")
	// run points the tag at tagAt, tells the step the run started at sha, and
	// runs it with the default branch fetched (or not).
	run := func(f candidateFixture, tag, tagAt, sha string, fetchMain bool) (out, outputs string, err error) {
		gitIn(t, f.dir, fixtureDate, "tag", "-f", tag, tagAt)
		// A tag push checks out the tagged commit, detached; the default
		// branch is only a remote-tracking ref there.
		gitIn(t, f.dir, fixtureDate, "checkout", "-q", "--detach", sha)
		if fetchMain {
			gitIn(t, f.dir, fixtureDate, "update-ref", "refs/remotes/origin/main", f.main)
		}
		output := filepath.Join(t.TempDir(), "output")
		out, err = runStep(t, f.dir, shellEnv(t, f.dir, t.TempDir(), map[string]string{
			"GITHUB_SHA": sha, "RELEASE_TAG": tag, "DEFAULT_BRANCH": "main", "GITHUB_OUTPUT": output,
		}), step.Run)
		data, _ := os.ReadFile(output)
		return out, string(data), err
	}

	// A commented-out line, a line for another tag and the real one.
	registered := newCandidateFixture(t, candidateHeader, func(release, _ string) string {
		return candidateHeader + "# v1.2.3 " + strings.Repeat("0", 40) + " " + strings.Repeat("0", 64) + "\n" +
			candidateLine("v1.2.3", release) + candidateLine("v1.2.4", strings.Repeat("c", 40))
	})
	out, outputs, err := run(registered, "v1.2.3", registered.release, registered.release, true)
	if err != nil {
		t.Fatalf("a registered candidate on the default branch: %v\n%s", err, out)
	}
	if want := "line=" + strings.TrimSpace(candidateLine("v1.2.3", registered.release)); !strings.Contains(outputs, want) {
		t.Errorf("step output %q, want %q", outputs, want)
	}

	// The tagged tree holds a line of its own, naming another commit; only
	// the default branch's copy counts.
	stale := newCandidateFixture(t, candidateHeader+candidateLine("v1.2.3", strings.Repeat("a", 40)), func(release, _ string) string {
		return candidateHeader + candidateLine("v1.2.3", release)
	})
	if out, outputs, err := run(stale, "v1.2.3", stale.release, stale.release, true); err != nil || !strings.Contains(outputs, stale.release) || strings.Contains(outputs, strings.Repeat("a", 40)) {
		t.Errorf("the registry must be read from the default branch, not the tagged tree: %v %q\n%s", err, outputs, out)
	}

	atRelease := func(f candidateFixture) (tagAt, sha string) { return f.release, f.release }
	for _, c := range []struct {
		name     string
		registry func(release, side string) string
		at       func(f candidateFixture) (tagAt, sha string)
		fetch    bool
		want     string
	}{
		{"no line for the tag", func(release, _ string) string { return candidateHeader + candidateLine("v1.2.9", release) },
			atRelease, true, "no line for v1.2.3"},
		{"only a commented-out line", func(release, _ string) string { return candidateHeader + "# " + candidateLine("v1.2.3", release) },
			atRelease, true, "no line for v1.2.3"},
		{"a registry with no lines at all", func(_, _ string) string { return "" },
			atRelease, true, "no line for v1.2.3"},
		{"the registry names another commit", func(_, side string) string { return candidateHeader + candidateLine("v1.2.3", side) },
			atRelease, true, "names commit"},
		{"two lines for the tag", func(release, _ string) string {
			return candidateHeader + candidateLine("v1.2.3", release) + candidateLine("v1.2.3", release)
		}, atRelease, true, "more than one line"},
		{"a short digest", func(release, _ string) string { return candidateHeader + "v1.2.3 " + release + " abc\n" },
			atRelease, true, "not '<tag>"},
		{"a tag on a commit that is not on the default branch", func(_, side string) string { return candidateHeader + candidateLine("v1.2.3", side) },
			func(f candidateFixture) (string, string) { return f.side, f.side }, true, "is not on main"},
		{"a tag moved after the run started", func(release, _ string) string { return candidateHeader + candidateLine("v1.2.3", release) },
			func(f candidateFixture) (string, string) { return f.main, f.release }, true, "it was moved"},
		{"the default branch was not fetched", func(release, _ string) string { return candidateHeader + candidateLine("v1.2.3", release) },
			atRelease, false, "was not fetched"},
	} {
		f := newCandidateFixture(t, candidateHeader, c.registry)
		tagAt, sha := c.at(f)
		out, outputs, err := run(f, "v1.2.3", tagAt, sha, c.fetch)
		if err == nil || !strings.Contains(out, c.want) || outputs != "" {
			t.Errorf("%s: err=%v, output %q, step output %q, want a refusal saying %q with no output", c.name, err, out, outputs, c.want)
		}
	}
}

// The release job rebuilds the candidate with the script a
// maintainer ran and publishes only if the rebuilt registry line is the
// registered one: the released bytes are the tested bytes.
func TestReleaseRebuildMustMatchTheRegisteredCandidate(t *testing.T) {
	needTools(t)
	_, step := readWorkflow(t, "release.yml").Jobs["verify"].step(t, "Rebuild the release candidate")
	registered := strings.TrimSpace(candidateLine("v1.2.3", strings.Repeat("d", 40)))
	for _, c := range []struct {
		name, printed, registered, want string
		pass                            bool
	}{
		{"the same candidate", registered, registered, "", true},
		{"another digest", "v1.2.3 " + strings.Repeat("d", 40) + " " + strings.Repeat("e", 64), registered, "not the executable that was tested", false},
		{"another commit", "v1.2.3 " + strings.Repeat("e", 40) + " " + strings.Repeat("ab", 32), registered, "not the executable that was tested", false},
		{"no registered line reached the step", registered, "", "No registered candidate line", false},
		{"a registered line for another tag", registered, strings.Replace(registered, "v1.2.3", "v1.2.4", 1), "No registered candidate line", false},
		{"the script fails", "FAIL", registered, "", false},
	} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeExecutable(t, filepath.Join(dir, "scripts", "release-candidate.sh"), "#!/bin/sh\n[ \"$STUB_LINE\" != FAIL ] || exit 1\nprintf '%s\\n' \"$STUB_LINE\"\n")
		output := filepath.Join(dir, "output")
		out, err := runStep(t, dir, shellEnv(t, dir, dir, map[string]string{
			"RELEASE_TAG": "v1.2.3", "REGISTERED_LINE": c.registered, "STUB_LINE": c.printed, "GITHUB_OUTPUT": output,
		}), step.Run)
		data, _ := os.ReadFile(output)
		if (err == nil) != c.pass || (c.want != "" && !strings.Contains(out, c.want)) {
			t.Errorf("%s: passed=%v (%v), want pass=%v containing %q\n%s", c.name, err == nil, err, c.pass, c.want, out)
		}
		if c.pass && string(data) != "sha256="+registeredDigest(registered)+"\n" {
			t.Errorf("%s: step output %q, want the registered digest", c.name, data)
		}
		if !c.pass && len(data) != 0 {
			t.Errorf("%s: a refused rebuild still published the output %q", c.name, data)
		}
	}
}

func registeredDigest(line string) string {
	return line[strings.LastIndex(line, " ")+1:]
}

// The executable that crosses from the verify job to the publish and
// attestation jobs is checked against the digest the verify job matched to
// the registry before anything uses it.
func TestArtifactsAreCheckedAgainstTheVerifiedDigest(t *testing.T) {
	needTools(t, "sha256sum")
	workflow := readWorkflow(t, "release.yml")
	content := []byte("verified executable\n")
	sum := sha256.Sum256(content)
	good := hex.EncodeToString(sum[:])
	for _, jobName := range []string{"publish", "attest-binary"} {
		_, step := workflow.Jobs[jobName].step(t, "Check the executable is the verified one")
		for _, c := range []struct {
			name, expected string
			pass           bool
		}{
			{"the verified digest", good, true},
			{"another digest", strings.Repeat("0", 64), false},
			{"no digest from the verify job", "", false},
			{"a digest with junk", good + "\n", false},
		} {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "bin", "certistack-linux-amd64"), content, 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := runStep(t, dir, shellEnv(t, dir, dir, map[string]string{"EXPECTED_SHA256": c.expected}), step.Run)
			if (err == nil) != c.pass {
				t.Errorf("%s, %s: passed=%v, want %v\n%s", jobName, c.name, err == nil, c.pass, out)
			}
		}
	}
}

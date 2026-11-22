// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// upgradePodman is a Podman with a store: pull adds an image to it, image
// exists and image inspect read it, and run (the wrapper's job) records the
// arguments of the container it would start.
const upgradePodman = `#!/bin/sh
store=$UP_STORE/images
case "$1" in
  run)
    for arg in "$@"; do printf '%s\n' "$arg"; done > "$UP_STORE/run.args"
    ;;
  pull)
    [ -z "$UP_PULL_FAILS" ] || { echo 'podman: registry unreachable' >&2; exit 125; }
    printf '%s\n' "$2" >> "$store"
    ;;
  image)
    case "$2" in
      exists) grep -Fxq -- "$3" "$store" ;;
      inspect)
        [ "$3" = --format ] && [ "$4" = '{{.Digest}}' ] || exit 64
        grep -Fxq -- "$5" "$store" || { echo "podman: no such image $5" >&2; exit 125; }
        printf '%s\n' "${5#*@}"
        ;;
      *) exit 64 ;;
    esac
    ;;
  *) echo "podman stub: unexpected $*" >&2; exit 64 ;;
esac
`

const (
	upgradeOldImage = "registry.example.invalid/certistack-controller@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	upgradeNewImage = "registry.example.invalid/certistack-controller@sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

// upgradeAppliance is an appliance with its reference file and image store,
// and the guide's upgrade and rollback commands run against them.
type upgradeAppliance struct {
	t     *testing.T
	root  string
	stubs string
	work  string
	store string
}

func newUpgradeAppliance(t *testing.T) *upgradeAppliance {
	t.Helper()
	needTools(t, "sh", "grep", "tee", "cp", "mv", "chmod")
	wrapper, stubs, root, _ := applianceWrapperSetup(t)
	a := &upgradeAppliance{t: t, root: root, stubs: stubs, work: filepath.Join(root, "release"), store: filepath.Join(root, "store")}
	for _, d := range []string{a.work, a.store} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable(t, filepath.Join(stubs, "podman"), upgradePodman)
	writeExecutable(t, filepath.Join(stubs, "sudo"), "#!/bin/sh\nexec \"$@\"\n")
	// The wrapper is what `sudo certistack-controller` runs; its reference
	// file is the test's copy of /etc/certistack/controller-image.
	data, err := os.ReadFile(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(stubs, "certistack-controller"), string(data))
	a.write(filepath.Join(root, "controller-image"), upgradeOldImage+"\n")
	a.write(filepath.Join(a.store, "images"), upgradeOldImage+"\n")
	a.write(filepath.Join(a.work, "CONTAINER-IMAGE.txt"), upgradeNewImage+"\n")
	return a
}

func (a *upgradeAppliance) write(path, content string) {
	a.t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		a.t.Fatal(err)
	}
}

func (a *upgradeAppliance) read(path string) string {
	a.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// reference is the image reference the wrapper would start.
func (a *upgradeAppliance) reference() string {
	return a.read(filepath.Join(a.root, "controller-image"))
}

// ranImage is the image of the last container the wrapper started.
func (a *upgradeAppliance) ranImage() string {
	a.t.Helper()
	for _, arg := range strings.Split(a.read(filepath.Join(a.store, "run.args")), "\n") {
		if strings.HasPrefix(arg, "registry.example.invalid/") {
			return arg
		}
	}
	return ""
}

// block runs the guide's n'th code block under "Upgrade and roll back" as
// written, with /etc/certistack standing in the test's directory.
func (a *upgradeAppliance) block(n int, env ...string) (string, error) {
	a.t.Helper()
	var bodies []string
	for _, b := range codeBlocks(a.t, repoFile("deploy", "appliance", "README.md")) {
		if b.heading == "Upgrade and roll back" && b.lang == "bash" {
			bodies = append(bodies, b.body)
		}
	}
	if len(bodies) != 3 {
		a.t.Fatalf("the guide's Upgrade and roll back section has %d bash blocks, want the pull, the switch and the rollback", len(bodies))
	}
	body := strings.ReplaceAll(bodies[n], "/etc/certistack/", a.root+"/")
	extra := map[string]string{"UP_STORE": a.store}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		extra[k] = v
	}
	return runStep(a.t, a.work, shellEnv(a.t, a.stubs, a.root, extra), body)
}

// The guide's appliance upgrade really updates the image the wrapper runs, and
// its rollback really restores it. Replacing a host binary would change nothing
// appliance jobs run, and changing only the reference file, for an image the
// store does not hold, leaves the wrapper (which never pulls) unable to start a
// job.
func TestApplianceUpgradeAndRollbackChangeTheImageTheWrapperRuns(t *testing.T) {
	a := newUpgradeAppliance(t)

	// A reference switched before the image is pulled is refused, and nothing
	// changes.
	if out, err := a.block(1); err == nil {
		t.Fatalf("the switch succeeded for an image the store does not hold:\n%s", out)
	}
	if a.reference() != upgradeOldImage || a.read(filepath.Join(a.root, "controller-image.previous")) != "" {
		t.Errorf("a refused switch changed the reference to %q", a.reference())
	}

	// A pull that fails changes nothing either, and the switch still refuses.
	if out, err := a.block(0, "UP_PULL_FAILS=1"); err == nil {
		t.Fatalf("the pull block succeeded with the registry unreachable:\n%s", out)
	}
	if out, err := a.block(1); err == nil {
		t.Fatalf("the switch succeeded after a failed pull:\n%s", out)
	}

	// The upgrade.
	if out, err := a.block(0); err != nil {
		t.Fatalf("the pull block failed: %v\n%s", err, out)
	}
	if out, err := a.block(1); err != nil {
		t.Fatalf("the switch block failed: %v\n%s", err, out)
	}
	if got := a.reference(); got != upgradeNewImage {
		t.Errorf("after the upgrade the reference is %q, want %q", got, upgradeNewImage)
	}
	if got := a.read(filepath.Join(a.root, "controller-image.previous")); got != upgradeOldImage {
		t.Errorf("the previous reference was not kept: %q", got)
	}
	if got := a.ranImage(); got != upgradeNewImage {
		t.Errorf("after the upgrade the wrapper starts %q, want %q", got, upgradeNewImage)
	}
	if _, err := os.Stat(filepath.Join(a.root, "controller-image.next")); err == nil {
		t.Error("the switch left controller-image.next behind")
	}

	// The rollback.
	if out, err := a.block(2); err != nil {
		t.Fatalf("the rollback block failed: %v\n%s", err, out)
	}
	if got := a.reference(); got != upgradeOldImage {
		t.Errorf("after the rollback the reference is %q, want %q", got, upgradeOldImage)
	}
	if got := a.ranImage(); got != upgradeOldImage {
		t.Errorf("after the rollback the wrapper starts %q, want %q", got, upgradeOldImage)
	}
}

// The upgrade installs a digest, not whatever CONTAINER-IMAGE.txt says: a tag
// or a malformed reference stops at the check and leaves the reference alone.
func TestApplianceUpgradeRefusesAReferenceThatIsNotADigest(t *testing.T) {
	for name, reference := range map[string]string{
		"a tag":             "registry.example.invalid/certistack-controller:latest",
		"a short digest":    "registry.example.invalid/certistack-controller@sha256:1111",
		"an uppercase name": "Registry.example.invalid/certistack-controller@sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"a scheme":          "https://registry.example.invalid/certistack-controller@sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"a command":         "x;id@sha256:1111111111111111111111111111111111111111111111111111111111111111",
	} {
		t.Run(name, func(t *testing.T) {
			a := newUpgradeAppliance(t)
			a.write(filepath.Join(a.work, "CONTAINER-IMAGE.txt"), reference+"\n")
			// Even if the store happens to hold it (a tag was pulled by hand).
			a.write(filepath.Join(a.store, "images"), upgradeOldImage+"\n"+reference+"\n")
			if out, err := a.block(1); err == nil {
				t.Fatalf("the switch accepted %q:\n%s", reference, out)
			}
			if a.reference() != upgradeOldImage {
				t.Errorf("the reference became %q", a.reference())
			}
		})
	}
}

// The manual setup page's install, upgrade and rollback steps are a host-binary
// procedure, and the page says an appliance runs its image instead and sends
// the reader to the appliance guide, which owns its upgrade, rollback and OS
// patching.
func TestApplianceLifecycleIsDocumentedWhereItApplies(t *testing.T) {
	manualSetup := section(t, readRepoText(t, "docs", "manual-setup.md"), "Install, upgrade and roll back a release")
	flat := strings.Join(strings.Fields(manualSetup), " ")
	for _, want := range []string{"An appliance runs the image named in `/etc/certistack/controller-image` instead", "`deploy/appliance/README.md`"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the install, upgrade and roll back section of docs/manual-setup.md does not say %q", want)
		}
	}
	if !strings.Contains(readRepoText(t, "deploy", "appliance", "files", "certistack-controller"), "image_file=/etc/certistack/controller-image") {
		t.Error("the appliance wrapper does not run the image named in /etc/certistack/controller-image, which docs/manual-setup.md says it does")
	}

	readme := applianceReadme(t)
	for _, heading := range []string{"\n## Upgrade and roll back\n", "\n## Patch the appliance's operating system\n"} {
		if !strings.Contains(readme, heading) {
			t.Errorf("the appliance guide has no %q section", strings.TrimSpace(heading))
		}
	}
	start := strings.Index(readme, "\n## Patch the appliance's operating system\n")
	if start < 0 {
		return
	}
	patch := readme[start:]
	for _, want := range []string{"replacement, not in-place patching", "rebuild", "build-manifest", "/etc/certistack/secrets", "Keep the old VM", "Do not run `apt upgrade`", "Automatic-Reboot"} {
		if !strings.Contains(patch, want) {
			t.Errorf("the OS patching section does not say %q", want)
		}
	}
}

// The patch copies controller.env and the controller's key, which is root on
// the node, through the workstation. The archive is created under umask 077
// (the redirection inside the subshell, so the umask covers it) and shredded,
// not merely unlinked.
func TestAppliancePatchKeepsTheStateArchivePrivate(t *testing.T) {
	readme := applianceReadme(t)
	start := strings.Index(readme, "\n## Patch the appliance's operating system\n")
	if start < 0 {
		t.Fatal("the appliance guide has no Patch the appliance's operating system section")
	}
	patch := readme[start:]
	if end := strings.Index(patch[1:], "\n## "); end >= 0 {
		patch = patch[:end+1]
	}
	if !regexp.MustCompile(`\(umask 077; ssh [^\n]*'sudo tar -C / -cpf - [^\n]*' > appliance-state\.tar\)`).MatchString(patch) {
		t.Error("the state archive is not written under umask 077")
	}
	if !strings.Contains(patch, "shred -u appliance-state.tar") || strings.Contains(patch, "rm -f appliance-state.tar") {
		t.Error("the state archive is not shredded after the copy")
	}
}

// Removing the appliance also takes back what the build left on the build
// machine: the node's CA copy, Packer's plugin, and the tools it installed.
func TestApplianceRemovalCoversTheBuildMachine(t *testing.T) {
	readme := applianceReadme(t)
	start := strings.Index(readme, "\n## Remove the appliance\n")
	if start < 0 {
		t.Fatal("the appliance guide has no Remove the appliance section")
	}
	removal := flat(readme[start:])
	for _, want := range []string{
		"On the build machine",
		"`rm -f /secure/certistack/pve-root-ca.pem`",
		"the release checkout",
		"`rm -rf ~/.config/packer`",
		"uninstall Packer and skopeo",
	} {
		if !strings.Contains(removal, want) {
			t.Errorf("the removal section does not say %q", want)
		}
	}
}

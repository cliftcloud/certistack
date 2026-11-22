// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// packerRecipe is the appliance Packer recipe's text.
func packerRecipe(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(repoFile("deploy", "appliance", "packer", "proxmox-clone.pkr.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// packerVariable returns the body of the recipe's variable block, and
// whether the recipe declares it.
func packerVariable(recipe, name string) (string, bool) {
	match := regexp.MustCompile(`(?ms)^variable "` + regexp.QuoteMeta(name) + `" \{\n(.*?)^\}`).FindStringSubmatch(recipe)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// packerVariableNames lists every variable the recipe declares.
func packerVariableNames(recipe string) []string {
	var names []string
	for _, match := range regexp.MustCompile(`(?m)^variable "([a-z0-9_]+)" \{`).FindAllStringSubmatch(recipe, -1) {
		names = append(names, match[1])
	}
	return names
}

// packerDefault is a variable's default as written, without quotes.
func packerDefault(t *testing.T, recipe, name string) string {
	t.Helper()
	body, ok := packerVariable(recipe, name)
	if !ok {
		t.Fatalf("the recipe declares no variable %q", name)
	}
	match := regexp.MustCompile(`(?m)^\s*default\s*=\s*"?([^"\n]*)"?\s*$`).FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("variable %q has no default:\n%s", name, body)
	}
	return match[1]
}

// hclRegex returns the pattern of the first regex(...) call in an HCL
// variable's validation, with the string literal's escapes undone. HCL and Go
// both use RE2, so the pattern means the same in either.
func hclRegex(t *testing.T, body string) *regexp.Regexp {
	t.Helper()
	match := regexp.MustCompile(`regex\("((?:[^"\\]|\\.)*)", var\.[a-z_]+\)`).FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("no regex(...) validation in:\n%s", body)
	}
	pattern := strings.NewReplacer(`\\`, `\`, `\"`, `"`).Replace(match[1])
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("the recipe's pattern %q does not compile: %v", pattern, err)
	}
	return compiled
}

// controller_image admits only registry-host/repository@sha256:<64 lowercase
// hex>. A looser check would let an uppercase repository, an https:// prefix, a
// doubled slash or a dir: transport path pass "packer validate" and fail only
// at the late podman pull (or, for dir:, pull something that is not a registry
// manifest at all).
func TestApplianceControllerImageIsAStrictRegistryReference(t *testing.T) {
	body, ok := packerVariable(packerRecipe(t), "controller_image")
	if !ok {
		t.Fatal("the recipe declares no controller_image")
	}
	pattern := hclRegex(t, body)
	digest := strings.Repeat("0123456789abcdef", 4)

	for _, reference := range []string{
		"ghcr.io/cliftcloud/certistack-controller@sha256:" + digest,
		"registry.example.internal/team/controller@sha256:" + digest,
		"registry.example.internal:5000/team/controller@sha256:" + digest,
		"registry.example:5000/controller@sha256:" + digest,
		"localhost:5000/controller@sha256:" + digest,
		"localhost/controller@sha256:" + digest,
		"10.0.0.5:5000/controller@sha256:" + digest,
		"registry.example/a/b/c/d@sha256:" + digest,
		"registry.example/team_a/my.controller-2@sha256:" + digest,
		"registry.example/team/con__troller@sha256:" + digest,
	} {
		if !pattern.MatchString(reference) {
			t.Errorf("a canonical reference is refused: %s", reference)
		}
	}

	for name, reference := range map[string]string{
		"uppercase repository":        "registry.example/Team/controller@sha256:" + digest,
		"uppercase registry":          "Registry.example/team/controller@sha256:" + digest,
		"https scheme":                "https://registry.example/team/controller@sha256:" + digest,
		"docker scheme":               "docker://registry.example/team/controller@sha256:" + digest,
		"doubled slash":               "registry.example//team/controller@sha256:" + digest,
		"doubled slash in the path":   "registry.example/team//controller@sha256:" + digest,
		"leading slash":               "/registry.example/team/controller@sha256:" + digest,
		"dir transport":               "dir:/tmp/controller-layout@sha256:" + digest,
		"oci transport":               "oci:/tmp/layout@sha256:" + digest,
		"containers-storage":          "containers-storage:registry.example/team/controller@sha256:" + digest,
		"no digest, a tag":            "registry.example/team/controller:latest",
		"a tag and a digest":          "registry.example/team/controller:1.0@sha256:" + digest,
		"no registry host":            "controller@sha256:" + digest,
		"an ambiguous short name":     "team/controller@sha256:" + digest,
		"a host with no dot or port":  "registry/team/controller@sha256:" + digest,
		"a single quote":              "registry.example/te'am/controller@sha256:" + digest,
		"a shell substitution":        "registry.example/$(id)/controller@sha256:" + digest,
		"a semicolon":                 "registry.example/team/controller;id@sha256:" + digest,
		"a space":                     "registry.example/team /controller@sha256:" + digest,
		"a trailing newline":          "registry.example/team/controller@sha256:" + digest + "\n",
		"an embedded newline":         "registry.example/team/controller\n@sha256:" + digest,
		"uppercase digest":            "registry.example/team/controller@sha256:" + strings.ToUpper(digest),
		"a 63-digit digest":           "registry.example/team/controller@sha256:" + digest[1:],
		"a 65-digit digest":           "registry.example/team/controller@sha256:" + digest + "0",
		"another algorithm":           "registry.example/team/controller@sha512:" + digest,
		"credentials":                 "user:pass@registry.example/team/controller@sha256:" + digest,
		"a path starting with a dash": "registry.example/-team/controller@sha256:" + digest,
		"a path ending in a dot":      "registry.example/team/controller.@sha256:" + digest,
		"a port too long":             "registry.example:123456/team/controller@sha256:" + digest,
		"an underscore in the host":   "reg_istry.example/team/controller@sha256:" + digest,
		"empty":                       "",
	} {
		if pattern.MatchString(reference) {
			t.Errorf("%s is accepted: %q", name, reference)
		}
	}
}

// The recipe names the Packer range and the exact plugin it was checked with,
// sets the clone timeout and the template's size itself instead of inheriting
// the plugin's (one minute; 512 MiB, one core, kvm64, OS "other"), and the
// guide documents every input the recipe has.
func TestApplianceRecipePinsAndSizesTheBuild(t *testing.T) {
	recipe := packerRecipe(t)

	if !regexp.MustCompile(`(?m)^\s*required_version\s*=\s*">=\s*\d+\.\d+\.\d+,\s*<\s*\d+\.\d+\.\d+"`).MatchString(recipe) {
		t.Error("the packer block has no bounded required_version")
	}
	plugin := regexp.MustCompile(`(?m)^\s*version\s*=\s*"([^"]+)"`).FindStringSubmatch(recipe)
	if plugin == nil || !regexp.MustCompile(`^= \d+\.\d+\.\d+$`).MatchString(plugin[1]) {
		t.Errorf("the plugin constraint is %v, not an exact version (= x.y.z): packer init would install whatever is newest", plugin)
	}

	// Each setting reaches the source block from a variable, so the operator
	// can change it, and its default is what the guide promises.
	source := regexp.MustCompile(`(?ms)^source "proxmox-clone" "controller" \{\n(.*?)^\}`).FindStringSubmatch(recipe)
	if source == nil {
		t.Fatal("no proxmox-clone source block")
	}
	for setting, variable := range map[string]string{
		"task_timeout": "task_timeout", "memory": "memory", "cores": "cores",
		"sockets": "sockets", "cpu_type": "cpu_type", "os": "os", "pool": "pool",
	} {
		if !regexp.MustCompile(`(?m)^\s*` + setting + `\s*=\s*var\.` + variable + `\s*$`).MatchString(source[1]) {
			t.Errorf("the source block does not take %s from var.%s", setting, variable)
		}
	}
	timeout, err := time.ParseDuration(packerDefault(t, recipe, "task_timeout"))
	if err != nil || timeout <= time.Minute {
		t.Errorf("task_timeout defaults to %v (%v); the plugin's own one minute is what a full clone outgrows", timeout, err)
	}
	if memory, _ := strconv.Atoi(packerDefault(t, recipe, "memory")); memory < 2048 {
		t.Errorf("memory defaults to %d MiB, below the documented 2048 minimum", memory)
	}
	if cores, _ := strconv.Atoi(packerDefault(t, recipe, "cores")); cores < 2 {
		t.Errorf("cores defaults to %d, below the documented 2 vCPU minimum", cores)
	}
	if cpu := packerDefault(t, recipe, "cpu_type"); cpu == "" || cpu == "kvm64" {
		t.Errorf("cpu_type defaults to %q, the plugin's own or none", cpu)
	}
	if os := packerDefault(t, recipe, "os"); os != "l26" {
		t.Errorf("os defaults to %q; the plugin's own \"other\" is what the recipe replaces, and the appliance is Linux", os)
	}
	memory, _ := packerVariable(recipe, "memory")
	cores, _ := packerVariable(recipe, "cores")
	if !strings.Contains(memory, "validation") || !strings.Contains(cores, "validation") {
		t.Error("memory and cores have no validation, so the documented minimum is advice only")
	}
}

// sourceBlock is the body of the recipe's proxmox-clone source block.
func sourceBlock(t *testing.T, recipe string) string {
	t.Helper()
	source := regexp.MustCompile(`(?ms)^source "proxmox-clone" "controller" \{\n(.*?)^\}`).FindStringSubmatch(recipe)
	if source == nil {
		t.Fatal("no proxmox-clone source block")
	}
	return source[1]
}

// The settings a stock Debian or Ubuntu cloud source needs for the build VM to
// boot, be reached and leave a template its clones can use:
//
//   - a VirtIO SCSI controller: the plugin's own default, lsi, has no driver
//     in Debian's cloud kernel, and the build VM finds no disk;
//   - a network adapter on a bridge the operator names, and a static address
//     through cloud-init for a bridge without DHCP (the plugin attaches an
//     ipconfig only to a declared adapter);
//   - an empty cloud-init drive on the template, since the plugin removes the
//     build's drive and settings before the conversion;
//   - a wait for the source's first-boot cloud-init before apt, which it may
//     still hold.
func TestApplianceRecipeGivesTheBuildVMADiskANetworkAndCloudInit(t *testing.T) {
	recipe := packerRecipe(t)
	source := sourceBlock(t, recipe)
	for setting, variable := range map[string]string{
		"scsi_controller": "scsi_controller", "cloud_init_storage_pool": "cloud_init_storage_pool",
	} {
		if !regexp.MustCompile(`(?m)^\s*` + setting + `\s*=\s*var\.` + variable + `\s*$`).MatchString(source) {
			t.Errorf("the source block does not take %s from var.%s", setting, variable)
		}
	}
	if got := packerDefault(t, recipe, "scsi_controller"); got != "virtio-scsi-single" {
		t.Errorf("scsi_controller defaults to %q, want virtio-scsi-single", got)
	}
	if !regexp.MustCompile(`(?m)^\s*cloud_init\s*=\s*true\s*$`).MatchString(source) {
		t.Error("the source block does not set cloud_init = true, so the template has no cloud-init drive for its clones")
	}
	if !regexp.MustCompile(`(?s)network_adapters \{\s*model\s*=\s*"virtio"\s*bridge\s*=\s*var\.bridge\s*\}`).MatchString(source) {
		t.Error("the source block declares no virtio network adapter on var.bridge")
	}
	if !regexp.MustCompile(`(?s)dynamic "ipconfig" \{\s*for_each\s*=\s*var\.build_ip == "" \? \[\] : \[var\.build_ip\]\s*content \{\s*ip\s*=\s*ipconfig\.value\s*gateway\s*=\s*var\.build_gateway\s*\}`).MatchString(source) {
		t.Error("the source block does not pass build_ip and build_gateway as an ipconfig only when build_ip is set")
	}
	if !regexp.MustCompile(`(?m)^\s*template_description\s*=\s*".*\$\{var\.controller_image\}`).MatchString(source) {
		t.Error("the template's description does not name the controller image")
	}

	provisioner := recipe[strings.Index(recipe, `provisioner "shell"`):]
	inline := regexp.MustCompile(`"([^"\n]*)"`).FindAllStringSubmatch(provisioner[strings.Index(provisioner, "inline"):], -1)
	if len(inline) == 0 || !strings.HasPrefix(inline[0][1], "cloud-init status --wait") {
		t.Fatalf("the first shell provisioner does not start by waiting for cloud-init: %q", inline)
	}
	if !strings.Contains(inline[0][1], "test $? -eq 2") {
		t.Errorf("the wait %q does not accept cloud-init's exit 2 (finished, with recoverable errors)", inline[0][1])
	}
}

// proxmox_url needs the API path (the plugin appends paths to it, so
// https://host:8006 fails at the first call) and source_template is a name
// (clone_vm takes no ID). packer validate refuses either mistake before a
// build starts.
func TestApplianceRecipeRefusesAnEndpointWithoutItsPathAndATemplateID(t *testing.T) {
	recipe := packerRecipe(t)
	body, _ := packerVariable(recipe, "proxmox_url")
	endpoint := hclRegex(t, body)
	for _, url := range []string{"https://pve-01.example.internal:8006/api2/json", "https://10.0.0.5:8006/api2/json"} {
		if !endpoint.MatchString(url) {
			t.Errorf("the endpoint %q is refused", url)
		}
	}
	for _, url := range []string{"https://pve-01.example.internal:8006", "https://pve-01.example.internal:8006/", "http://pve-01.example.internal:8006/api2/json", "https://pve-01.example.internal:8006/api2/json/nodes", ""} {
		if endpoint.MatchString(url) {
			t.Errorf("the endpoint %q is accepted", url)
		}
	}

	body, _ = packerVariable(recipe, "source_template")
	if !strings.Contains(body, "!can(regex(") {
		t.Fatalf("source_template's validation does not refuse what its pattern matches:\n%s", body)
	}
	id := hclRegex(t, body)
	for value, refused := range map[string]bool{"9000": true, "100": true, "debian12-cloudinit": false, "ubuntu-2404": false} {
		if id.MatchString(value) != refused {
			t.Errorf("source_template %q: refused = %v, want %v", value, id.MatchString(value), refused)
		}
	}
}

// The recipe has no fallback that turns a failed cleanup into a
// built template, and the cleanup it does is the script the tests below run.
func TestApplianceRecipeHasNoSwallowedFailure(t *testing.T) {
	recipe := packerRecipe(t)
	for _, inline := range regexp.MustCompile(`"([^"\n]*)"`).FindAllStringSubmatch(recipe, -1) {
		for _, masked := range []string{"|| true", "||true", "|| :", "; true", "|| exit 0"} {
			if strings.Contains(inline[1], masked) {
				t.Errorf("the recipe masks a failure with %q: %q", masked, inline[1])
			}
		}
	}
	if strings.Contains(recipe, "cloud-init clean") {
		t.Error("the recipe runs cloud-init clean itself; the finalize script owns it and its postconditions")
	}
	script := finalizeScript(t)
	for _, masked := range []string{"|| true", "||true", "|| :"} {
		if strings.Contains(script, masked) {
			t.Errorf("the finalize script masks a failure with %q", masked)
		}
	}

	// The finalize script is uploaded and is the last provisioner.
	if !regexp.MustCompile(`(?s)provisioner "file" \{\s*source\s*=\s*"\.\./files/finalize-template\.sh"\s*destination\s*=\s*"/tmp/certistack-finalize-template\.sh"`).MatchString(recipe) {
		t.Error("the recipe does not upload files/finalize-template.sh")
	}
	provisioners := regexp.MustCompile(`provisioner "([a-z-]+)" \{`).FindAllStringSubmatch(recipe, -1)
	if len(provisioners) == 0 || provisioners[len(provisioners)-1][1] != "shell" {
		t.Fatal("the recipe's last provisioner is not a shell provisioner")
	}
	last := recipe[strings.LastIndex(recipe, `provisioner "shell"`):]
	for _, want := range []string{
		`"sh /tmp/certistack-finalize-template.sh"`,
		"CERTISTACK_CONTROLLER_IMAGE=${var.controller_image}",
		"CERTISTACK_BUILD_KEY_BLOB=",
		"var.ssh_build_public_key_file",
	} {
		if !strings.Contains(last, want) {
			t.Errorf("the last provisioner does not contain %q:\n%s", want, last)
		}
	}
	// Nothing after the key is removed can need the build connection.
	if strings.Count(recipe, `provisioner "shell"`) < 2 {
		t.Error("the recipe has no separate finalize provisioner")
	}

	// Packer's own cleanup option stays on, beside the real control.
	if !regexp.MustCompile(`(?m)^\s*ssh_clear_authorized_keys\s*=\s*true\s*$`).MatchString(recipe) {
		t.Error("the source block does not set ssh_clear_authorized_keys")
	}
	if !regexp.MustCompile(`variable "ssh_build_public_key_file" \{\n\s*type\s*=\s*string\n`).MatchString(recipe) {
		t.Error("ssh_build_public_key_file is missing or has a default; the build key must be named on every build")
	}
	if body, _ := packerVariable(recipe, "ssh_build_public_key_file"); strings.Contains(body, "default") {
		t.Error("ssh_build_public_key_file has a default")
	}
}

func finalizeScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(repoFile("deploy", "appliance", "files", "finalize-template.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// ---------------------------------------------------------------------------
// files/finalize-template.sh, run against a scratch tree
// ---------------------------------------------------------------------------

const (
	finalizeImageDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	finalizeImage       = "registry.example.invalid/certistack-controller@sha256:" + finalizeImageDigest
	// Two distinct public keys' base64 fields.
	buildKeyBlob = "AAAAC3NzaC1lZDI1NTE5AAAAIBuildKeyBuildKeyBuildKeyBuildKeyBuildKey0"
	otherKeyBlob = "AAAAC3NzaC1lZDI1NTE5AAAAIOperatorKeyOperatorKeyOperatorKeyOper0"
	machineID    = "3f6c1a2b9d7e4c58a0b1d2e3f4a5b6c7"
)

// cloud-init as the golden-image procedure meets it. STUB_CLOUDINIT chooses:
//
//	current     knows --machine-id, sets "uninitialized"
//	deletesID   knows --machine-id and deletes the file (Debian 12's 22.4)
//	old         predates --machine-id and rejects it
//	fail        clean itself fails (status 73)
//	ignoresID   accepts --machine-id and leaves the ID alone
//	leavesState accepts every option and leaves the instance state behind
const cloudInitStub = `#!/bin/sh
root=$CERTISTACK_FINALIZE_ROOT
printf 'cloud-init %s\n' "$*" >> "$STUB_LOG"
mode=${STUB_CLOUDINIT:-current}
[ "$1" = clean ] || exit 64
shift
if [ "$1" = --help ]; then
  echo 'usage: cloud-init clean [-h] [-l] [-s] [-r] [-c CONFIGS]'
  [ "$mode" = old ] || echo '  -M, --machine-id  Set /etc/machine-id to uninitialized'
  exit 0
fi
[ "$mode" != fail ] || { echo 'cloud-init: clean failed' >&2; exit 73; }
logs=no seed=no id=no
for arg; do
  case $arg in
    --logs) logs=yes ;;
    --seed) seed=yes ;;
    --machine-id) id=yes ;;
  esac
done
if [ "$mode" = old ] && [ $id = yes ]; then echo 'cloud-init: unrecognized arguments: --machine-id' >&2; exit 2; fi
if [ "$mode" != leavesState ]; then
  rm -rf "$root/var/lib/cloud/instance" "$root/var/lib/cloud/instances" "$root/var/lib/cloud/data" "$root/var/lib/cloud/sem"
  if [ $seed = yes ]; then rm -rf "$root/var/lib/cloud/seed"/*; fi
fi
if [ $logs = yes ]; then rm -f "$root/var/log/cloud-init.log" "$root/var/log/cloud-init-output.log"; fi
if [ $id = yes ] && [ "$mode" = deletesID ]; then rm -f "$root/etc/machine-id"
elif [ $id = yes ] && [ "$mode" != ignoresID ]; then printf 'uninitialized\n' > "$root/etc/machine-id"; fi
exit 0
`

// podman answers only the two inspect queries the script makes.
const finalizePodmanStub = `#!/bin/sh
[ "$1 $2 $3" = "image inspect --format" ] || { echo "podman stub: unexpected $*" >&2; exit 64; }
[ "$STUB_PODMAN" != fail ] || exit 125
case "$4" in
  '{{.Digest}}') printf '%s\n' "$STUB_DIGEST" ;;
  *RepoDigests*) printf '%s' "$STUB_REFS" ;;
  *) exit 64 ;;
esac
`

const dpkgQueryStub = `#!/bin/sh
printf 'podman 4.3.1+ds1-8\nca-certificates 20230311\ntini 0.19.0-1\n'
`

// journalctl logs each call with the number of journal files there were at
// the time, so a test sees journald moved off /var before they are deleted.
// STUB_JOURNALCTL=fail makes it fail as on a journald that does not answer.
const journalctlStub = `#!/bin/sh
files=$(find "$CERTISTACK_FINALIZE_ROOT/var/log/journal" -type f 2>/dev/null | grep -c .)
printf 'journalctl %s (journal files: %s)\n' "$*" "$files" >> "$STUB_LOG"
[ "$STUB_JOURNALCTL" != fail ] || { echo 'Failed to relinquish /var/log/journal' >&2; exit 1; }
[ "$*" = --relinquish-var ] || exit 64
`

// finalizeTree is a guest filesystem as the build leaves it before the last
// step: an initialised machine ID, a used cloud-init instance, cloud-init
// logs, and the build key authorized for root and for a login user.
type finalizeTree struct {
	t     *testing.T
	root  string
	stubs string
	log   string
}

func newFinalizeTree(t *testing.T) *finalizeTree {
	t.Helper()
	needTools(t, "sh", "find", "awk", "mktemp", "sort", "grep")
	tree := &finalizeTree{t: t, root: filepath.Join(t.TempDir(), "guest"), stubs: t.TempDir()}
	tree.log = filepath.Join(tree.stubs, "calls.log")
	writeExecutable(t, filepath.Join(tree.stubs, "cloud-init"), cloudInitStub)
	writeExecutable(t, filepath.Join(tree.stubs, "podman"), finalizePodmanStub)
	writeExecutable(t, filepath.Join(tree.stubs, "dpkg-query"), dpkgQueryStub)
	writeExecutable(t, filepath.Join(tree.stubs, "journalctl"), journalctlStub)

	tree.write("etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n", 0o644)
	// A real /etc/machine-id is 0444 and root writes it anyway; the tests run
	// unprivileged, so the scratch copy is writable.
	tree.write("etc/machine-id", machineID+"\n", 0o644)
	tree.symlink("../../../etc/machine-id", "var/lib/dbus/machine-id")
	tree.write("var/lib/cloud/instances/iid-build/obj.pkl", "state", 0o600)
	tree.symlink("instances/iid-build", "var/lib/cloud/instance")
	tree.write("var/lib/cloud/data/result.json", "{}", 0o644)
	tree.write("var/lib/cloud/sem/config_ssh", "done", 0o644)
	tree.write("var/lib/cloud/seed/nocloud/user-data", "#cloud-config\n", 0o644)
	tree.write("var/log/cloud-init.log", "log\n", 0o640)
	tree.write("var/log/cloud-init-output.log", "log\n", 0o640)
	build := "ssh-ed25519 " + buildKeyBlob + " packer-build\n"
	operator := "ssh-ed25519 " + otherKeyBlob + " operator@laptop\n"
	tree.write("root/.ssh/authorized_keys", "# build access\n"+build+operator, 0o600)
	tree.write("home/ubuntu/.ssh/authorized_keys", `command="/bin/true",no-pty ssh-ed25519 `+buildKeyBlob+" restricted\n"+operator, 0o600)
	tree.write("etc/ssh/authorized_keys/ubuntu", build, 0o644)
	tree.write("etc/ssh/sshd_config", "PermitRootLogin prohibit-password\n", 0o644)
	for _, key := range []string{"ssh_host_ed25519_key", "ssh_host_ecdsa_key", "ssh_host_rsa_key", "ssh_host_dsa_key"} {
		tree.write("etc/ssh/"+key, "private host key\n", 0o600)
		tree.write("etc/ssh/"+key+".pub", "public host key\n", 0o644)
	}
	tree.write("var/log/journal/"+machineID+"/system.journal", "journal\n", 0o640)
	return tree
}

func (f *finalizeTree) path(rel string) string { return filepath.Join(f.root, rel) }

func (f *finalizeTree) write(rel, content string, mode os.FileMode) {
	f.t.Helper()
	path := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		f.t.Fatal(err)
	}
}

func (f *finalizeTree) symlink(target, rel string) {
	f.t.Helper()
	path := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		f.t.Fatal(err)
	}
}

func (f *finalizeTree) read(rel string) string {
	f.t.Helper()
	data, err := os.ReadFile(f.path(rel))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(data)
}

func (f *finalizeTree) exists(rel string) bool {
	_, err := os.Lstat(f.path(rel))
	return err == nil
}

// run executes the script as Packer would (sh, from a copy it may delete),
// with the stubs first on PATH, and returns its combined output and error.
func (f *finalizeTree) run(env map[string]string) (string, error) {
	f.t.Helper()
	script := filepath.Join(f.t.TempDir(), "certistack-finalize-template.sh")
	if err := os.WriteFile(script, []byte(finalizeScript(f.t)), 0o600); err != nil {
		f.t.Fatal(err)
	}
	merged := map[string]string{
		"CERTISTACK_FINALIZE_ROOT":    f.root,
		"CERTISTACK_CONTROLLER_IMAGE": finalizeImage,
		"CERTISTACK_BUILD_KEY_BLOB":   buildKeyBlob,
		"CERTISTACK_PACKER_VERSION":   "1.14.2",
		"STUB_LOG":                    f.log,
		"STUB_DIGEST":                 "sha256:" + finalizeImageDigest,
		"STUB_REFS":                   finalizeImage + " ",
	}
	for name, value := range env {
		merged[name] = value
	}
	cmd := exec.Command("sh", script)
	cmd.Env = shellEnv(f.t, f.stubs, f.t.TempDir(), merged)
	out, err := cmd.CombinedOutput()
	if _, statErr := os.Lstat(script); err == nil && statErr == nil {
		f.t.Errorf("a successful run left its script behind")
	}
	return string(out), err
}

// keyStillAuthorized lists every file under the guest that still holds the
// build key's base64 field anywhere.
func (f *finalizeTree) keyStillAuthorized() []string {
	f.t.Helper()
	var found []string
	for _, rel := range []string{"root/.ssh/authorized_keys", "home/ubuntu/.ssh/authorized_keys", "etc/ssh/authorized_keys/ubuntu"} {
		if data, err := os.ReadFile(f.path(rel)); err == nil && strings.Contains(string(data), buildKeyBlob) {
			found = append(found, rel)
		}
	}
	return found
}

// The last provisioner resets the machine ID, clears cloud-init's instance,
// seed and logs, removes the build key from every authorized_keys file and
// keeps the other keys, records the image and a build manifest, and succeeds.
func TestFinalizeTemplateLeavesACleanTemplate(t *testing.T) {
	for _, mode := range []string{"current", "deletesID", "old"} {
		t.Run(mode, func(t *testing.T) {
			tree := newFinalizeTree(t)
			out, err := tree.run(map[string]string{"STUB_CLOUDINIT": mode})
			if err != nil {
				t.Fatalf("finalization failed: %v\n%s", err, out)
			}
			// systemd will make a new ID on each clone's first boot. It needs
			// the file: a clone without one boots with no network.
			if !tree.exists("etc/machine-id") {
				t.Fatal("/etc/machine-id is missing after finalization")
			}
			if id := strings.TrimSpace(tree.read("etc/machine-id")); id != "" && id != "uninitialized" {
				t.Errorf("the machine ID is %q after finalization", id)
			}
			// The build VM's host keys and journals go; cloud-init makes new
			// host keys on each clone. The SSH configuration stays.
			for _, rel := range []string{"etc/ssh/ssh_host_ed25519_key", "etc/ssh/ssh_host_ed25519_key.pub", "etc/ssh/ssh_host_dsa_key", "var/log/journal/" + machineID} {
				if tree.exists(rel) {
					t.Errorf("%s remains", rel)
				}
			}
			if !tree.exists("etc/ssh/sshd_config") || !tree.exists("var/log/journal") {
				t.Error("finalization removed the SSH configuration or the journal directory itself")
			}
			// The build key is gone from every file; the operator's stays.
			if left := tree.keyStillAuthorized(); len(left) > 0 {
				t.Errorf("the build key is still authorized in %v", left)
			}
			for _, rel := range []string{"root/.ssh/authorized_keys", "home/ubuntu/.ssh/authorized_keys"} {
				if !strings.Contains(tree.read(rel), otherKeyBlob) {
					t.Errorf("%s lost the operator's own key", rel)
				}
			}
			if strings.Contains(tree.read("root/.ssh/authorized_keys"), "# build access") == false {
				t.Error("an unrelated comment line was removed from root's authorized_keys")
			}
			if info, err := os.Stat(tree.path("root/.ssh/authorized_keys")); err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("root's authorized_keys mode changed: %v %v", info, err)
			}
			// Cloud-init state is gone.
			for _, rel := range []string{"var/lib/cloud/instance", "var/lib/cloud/instances", "var/log/cloud-init.log", "var/log/cloud-init-output.log", "var/lib/cloud/seed/nocloud/user-data"} {
				if tree.exists(rel) {
					t.Errorf("%s remains", rel)
				}
			}
			// The image reference and the manifest.
			if got := tree.read("etc/certistack/controller-image"); got != finalizeImage+"\n" {
				t.Errorf("controller-image = %q", got)
			}
			manifest := tree.read("etc/certistack/build-manifest")
			for _, want := range []string{"controller_image=" + finalizeImage, "packer_version=1.14.2", "[os-release]", "ID=debian", "[packages]", "podman 4.3.1+ds1-8"} {
				if !strings.Contains(manifest, want) {
					t.Errorf("the build manifest lacks %q:\n%s", want, manifest)
				}
			}
			if strings.Contains(manifest, buildKeyBlob) {
				t.Error("the build manifest carries the build key")
			}
			calls := strings.Join(readLog(t, tree.log), "\n")
			wantClean := "cloud-init clean --logs --seed --machine-id"
			if mode == "old" {
				wantClean = "cloud-init clean --logs --seed"
			}
			if !strings.Contains(calls, wantClean) {
				t.Errorf("cloud-init calls:\n%s\nwant %q", calls, wantClean)
			}
			if mode == "old" && strings.Contains(calls, "--machine-id\n") {
				t.Errorf("an old cloud-init was given --machine-id:\n%s", calls)
			}
			// journald leaves /var/log/journal while the build's journal is
			// still there, so the shutdown after it writes nothing to the template.
			if !strings.Contains(calls, "journalctl --relinquish-var (journal files: 1)") {
				t.Errorf("journald was not moved off /var/log/journal before its files were deleted:\n%s", calls)
			}
		})
	}
}

// A journald that does not leave /var/log/journal would write the build VM's
// shutdown into the template, so the failure fails the build.
func TestFinalizeTemplateFailsWhenJournaldKeepsWritingToVar(t *testing.T) {
	tree := newFinalizeTree(t)
	out, err := tree.run(map[string]string{"STUB_JOURNALCTL": "fail"})
	if err == nil || !strings.Contains(out, "journalctl --relinquish-var failed") {
		t.Errorf("a failed journalctl --relinquish-var did not fail the build: err=%v\n%s", err, out)
	}
}

// cloud-init clean --logs --seed without --machine-id leaves the build VM's
// machine ID in the template. A cloud-init
// that accepts the option but does not reset the ID is caught by the
// postcondition, not believed.
func TestFinalizeTemplateRefusesAMachineIDThatSurvives(t *testing.T) {
	tree := newFinalizeTree(t)
	out, err := tree.run(map[string]string{"STUB_CLOUDINIT": "ignoresID"})
	if err == nil || !strings.Contains(out, "still holds a machine ID") {
		t.Fatalf("a template that kept the build machine ID passed: err=%v\n%s", err, out)
	}
	// The D-Bus copy is the same instruction: a regular file with an ID in it
	// is removed, and a link to the first is left alone.
	tree = newFinalizeTree(t)
	if err := os.Remove(tree.path("var/lib/dbus/machine-id")); err != nil {
		t.Fatal(err)
	}
	tree.write("var/lib/dbus/machine-id", machineID+"\n", 0o644)
	if out, err := tree.run(nil); err != nil || tree.exists("var/lib/dbus/machine-id") {
		t.Errorf("a stale D-Bus machine-id copy survived: err=%v\n%s", err, out)
	}
}

// A cloud-init clean that fails (status 73) fails the build rather than being
// ignored, and so does a cloud-init that is not installed, and cloud state that
// a "successful" clean left behind.
func TestFinalizeTemplateFailsWhenCloudInitCleanupFails(t *testing.T) {
	tree := newFinalizeTree(t)
	out, err := tree.run(map[string]string{"STUB_CLOUDINIT": "fail"})
	if err == nil || !strings.Contains(out, "cloud-init clean failed") {
		t.Errorf("a failed cloud-init clean did not fail the build: err=%v\n%s", err, out)
	}

	// cloud-init missing: the stub directory holds no cloud-init.
	tree = newFinalizeTree(t)
	if err := os.Remove(filepath.Join(tree.stubs, "cloud-init")); err != nil {
		t.Fatal(err)
	}
	if out, err := tree.run(nil); err == nil {
		t.Errorf("a missing cloud-init did not fail the build\n%s", out)
	}

	tree = newFinalizeTree(t)
	out, err = tree.run(map[string]string{"STUB_CLOUDINIT": "leavesState"})
	if err == nil || !strings.Contains(out, "cloud-init state remains") {
		t.Errorf("leftover cloud-init state passed: err=%v\n%s", err, out)
	}

	// A log the clean did not remove.
	tree = newFinalizeTree(t)
	tree.write("var/log/cloud-init.log", "x", 0o640)
	tree.write("var/lib/cloud/seed/nocloud/user-data", "#cloud-config\n", 0o644)
	cmd := filepath.Join(tree.stubs, "cloud-init")
	stub, err := os.ReadFile(cmd)
	if err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, cmd, strings.Replace(string(stub), `if [ $logs = yes ]; then rm -f`, `if false; then rm -f`, 1))
	if out, err := tree.run(nil); err == nil || !strings.Contains(out, "cloud-init.log remains") {
		t.Errorf("a remaining cloud-init log passed: err=%v\n%s", err, out)
	}
}

// The build key is removed wherever it is, and a copy the removal
// cannot reach (here a file whose name has a newline in it) still fails the
// build, because the postcondition searches independently of the removal.
func TestFinalizeTemplateRemovesOrRefusesTheBuildKey(t *testing.T) {
	tree := newFinalizeTree(t)
	tree.write("home/ubuntu/.ssh/authorized_keys2", "ssh-rsa "+buildKeyBlob+"\n", 0o600)
	tree.write("home/deploy/.ssh/authorized_keys", "ssh-ed25519 "+buildKeyBlob+" second-account\n", 0o600)
	out, err := tree.run(nil)
	if err != nil {
		t.Fatalf("finalization failed: %v\n%s", err, out)
	}
	for _, rel := range []string{"home/ubuntu/.ssh/authorized_keys2", "home/deploy/.ssh/authorized_keys", "etc/ssh/authorized_keys/ubuntu"} {
		if strings.Contains(tree.read(rel), buildKeyBlob) {
			t.Errorf("%s still authorizes the build key", rel)
		}
	}

	tree = newFinalizeTree(t)
	tree.write("home/ubuntu/.ssh/authorized_keys2\nodd", "ssh-ed25519 "+buildKeyBlob+" odd-name\n", 0o600)
	out, err = tree.run(nil)
	if err == nil || !strings.Contains(out, "the build key is still authorized") {
		t.Errorf("a build key the removal could not reach passed: err=%v\n%s", err, out)
	}
}

// find does not follow links, and sshd does: a linked SSH directory, or a link
// under one, can authorize the build key through a file neither the removal
// nor the residual check lists, so the build would end with an empty search
// result and the key still in the template. A link as or under any of the
// directories the script searches therefore fails the build.
func TestFinalizeTemplateRefusesLinkedSSHPaths(t *testing.T) {
	for name, layout := range map[string]func(tree *finalizeTree){
		"a linked root .ssh": func(tree *finalizeTree) {
			if err := os.RemoveAll(tree.path("root/.ssh")); err != nil {
				tree.t.Fatal(err)
			}
			tree.write("root/ssh-real/authorized_keys", "ssh-ed25519 "+buildKeyBlob+" build\n", 0o600)
			tree.symlink("ssh-real", "root/.ssh")
		},
		"a linked .ssh in a home": func(tree *finalizeTree) {
			if err := os.RemoveAll(tree.path("home/ubuntu/.ssh")); err != nil {
				tree.t.Fatal(err)
			}
			tree.write("srv/keys/authorized_keys", "ssh-ed25519 "+buildKeyBlob+" build\n", 0o600)
			tree.symlink("../../srv/keys", "home/ubuntu/.ssh")
		},
		"a linked home directory": func(tree *finalizeTree) {
			tree.write("srv/deploy/.ssh/authorized_keys", "ssh-ed25519 "+buildKeyBlob+" build\n", 0o600)
			tree.symlink("../srv/deploy", "home/deploy")
		},
		"a linked authorized_keys directory under /etc/ssh": func(tree *finalizeTree) {
			if err := os.RemoveAll(tree.path("etc/ssh/authorized_keys")); err != nil {
				tree.t.Fatal(err)
			}
			tree.write("srv/keydir/ubuntu", "ssh-ed25519 "+buildKeyBlob+" build\n", 0o644)
			tree.symlink("../../srv/keydir", "etc/ssh/authorized_keys")
		},
		"a linked key file": func(tree *finalizeTree) {
			tree.write("srv/real_keys", "ssh-ed25519 "+buildKeyBlob+" build\n", 0o600)
			tree.symlink("../../../srv/real_keys", "home/ubuntu/.ssh/authorized_keys2")
		},
		"a dangling linked .ssh": func(tree *finalizeTree) {
			if err := os.RemoveAll(tree.path("root/.ssh")); err != nil {
				tree.t.Fatal(err)
			}
			tree.symlink("nowhere", "root/.ssh")
		},
	} {
		t.Run(name, func(t *testing.T) {
			tree := newFinalizeTree(t)
			layout(tree)
			out, err := tree.run(nil)
			if err == nil || !strings.Contains(out, "symbolic link") {
				t.Fatalf("a template with a linked SSH path passed: err=%v\n%s", err, out)
			}
		})
	}

	// The removal pass refuses before it rewrites anything: a template with a
	// link is not half-cleaned and then failed.
	tree := newFinalizeTree(t)
	tree.write("srv/real_keys", "ssh-ed25519 "+buildKeyBlob+" build\n", 0o600)
	tree.symlink("../../../srv/real_keys", "home/ubuntu/.ssh/authorized_keys2")
	if out, err := tree.run(nil); err == nil || !strings.Contains(out, "symbolic link") {
		t.Fatalf("a linked key file passed: err=%v\n%s", err, out)
	}
	if !strings.Contains(tree.read("home/ubuntu/.ssh/authorized_keys"), buildKeyBlob) {
		t.Error("the removal pass rewrote a key file before it refused the linked path")
	}

	// The residual check looks for itself: a link that appears after the
	// removal pass (here, when the removal first runs awk) is still refused.
	tree = newFinalizeTree(t)
	realAwk, err := exec.LookPath("awk")
	if err != nil {
		t.Fatal(err)
	}
	flag := filepath.Join(tree.stubs, "linked")
	writeExecutable(t, filepath.Join(tree.stubs, "awk"), "#!/bin/sh\nif [ ! -e '"+flag+"' ]; then : > '"+flag+"'; ln -s ../../../srv/late '"+tree.path("home/ubuntu/.ssh/late")+"'; fi\nexec '"+realAwk+"' \"$@\"\n")
	out, err := tree.run(nil)
	if err == nil || !strings.Contains(out, "symbolic link") {
		t.Errorf("a link that appeared after the removal pass was not refused: err=%v\n%s", err, out)
	}

	// A tree with no links still passes (the link of machine-id and the
	// cloud-init instance are outside the SSH directories).
	if out, err := newFinalizeTree(t).run(nil); err != nil {
		t.Errorf("a template without linked SSH paths was refused: %v\n%s", err, out)
	}
}

// The script refuses input that would make "nothing removed" look like
// success, and an image the store does not hold, before it records anything.
func TestFinalizeTemplateChecksItsInputsAndTheImage(t *testing.T) {
	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"an empty build key":    {map[string]string{"CERTISTACK_BUILD_KEY_BLOB": ""}, "CERTISTACK_BUILD_KEY_BLOB"},
		"a short build key":     {map[string]string{"CERTISTACK_BUILD_KEY_BLOB": "AAAA"}, "too short"},
		"a build key with text": {map[string]string{"CERTISTACK_BUILD_KEY_BLOB": "ssh-ed25519-not-a-blob-ssh-ed25519-not-a-blob"}, "CERTISTACK_BUILD_KEY_BLOB"},
		"no image":              {map[string]string{"CERTISTACK_CONTROLLER_IMAGE": ""}, "CERTISTACK_CONTROLLER_IMAGE"},
		"a tag, not a digest":   {map[string]string{"CERTISTACK_CONTROLLER_IMAGE": "registry.example.invalid/x:latest"}, "not pinned"},
		"a store without the digest": {map[string]string{
			"STUB_DIGEST": "sha256:" + strings.Repeat("f", 64), "STUB_REFS": "registry.example.invalid/other@sha256:" + strings.Repeat("f", 64) + " "}, "image store holds"},
		"a podman that cannot inspect": {map[string]string{"STUB_PODMAN": "fail"}, "cannot inspect"},
	} {
		t.Run(name, func(t *testing.T) {
			tree := newFinalizeTree(t)
			out, err := tree.run(c.env)
			if err == nil || !strings.Contains(out, c.want) {
				t.Fatalf("err=%v, want a refusal saying %q\n%s", err, c.want, out)
			}
			if tree.exists("etc/certistack/controller-image") {
				t.Error("an image reference was recorded before the image was confirmed")
			}
			if len(tree.keyStillAuthorized()) == 0 {
				t.Error("the build key was removed by a run that failed its input checks")
			}
		})
	}

	// The store may list the pinned reference without reporting the same
	// top-level digest (an image index pulled by its digest).
	tree := newFinalizeTree(t)
	if out, err := tree.run(map[string]string{"STUB_DIGEST": "sha256:" + strings.Repeat("e", 64)}); err != nil {
		t.Errorf("the store lists the pinned reference, which is enough: %v\n%s", err, out)
	}
}

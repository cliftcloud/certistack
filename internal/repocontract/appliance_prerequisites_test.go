// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"regexp"
	"strings"
	"testing"
)

// flat is text with its whitespace collapsed, so a sentence can be found
// wherever the guide wraps it.
func flat(text string) string { return strings.Join(strings.Fields(text), " ") }

// The build finds its VM's address through the guest agent and
// connects before any provisioner has run, so a source template without a
// running agent hangs the build for as long as Packer waits. The guide says so
// before the build, and gives the check that finds it out in a minute.
func TestApplianceReadmeRequiresAndChecksTheGuestAgent(t *testing.T) {
	readme := flat(applianceReadme(t))
	for _, want := range []string{
		"with `cloud-init` and `qemu-guest-agent` installed, enabled at boot and answering",
		"The recipe sets `qemu_agent = true`",
		"the recipe cannot install the agent for you",
		"`qm agent <vmid> ping`",
		"prints nothing and exits 0 when the agent answers",
		"set `qemu_agent = false` and give it an `ssh_host`",
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("the appliance guide does not say %q", want)
		}
	}
	// The prerequisite comes before the build's inputs, where a reader still
	// has the template in hand.
	prerequisite, inputs := strings.Index(readme, "`qm agent <vmid> ping`"), strings.Index(readme, "### Inputs")
	if prerequisite < 0 || inputs < 0 || prerequisite > inputs {
		t.Errorf("the guest-agent check (at %d) is not stated before the inputs (at %d)", prerequisite, inputs)
	}
	// The recipe is what the sentences describe: it asks the agent for the
	// address, and its source_template variable says the agent must run.
	recipe := packerRecipe(t)
	if !regexp.MustCompile(`(?m)^\s*qemu_agent\s*=\s*true\b`).MatchString(recipe) {
		t.Error("the recipe does not set qemu_agent = true, which the guide's prerequisite describes")
	}
	body, ok := packerVariable(recipe, "source_template")
	if !ok || !strings.Contains(body, "qemu-guest-agent") {
		t.Errorf("the recipe's source_template description does not say the guest agent must be running: %q", body)
	}
}

// The reference file an upgrade switches selects the controller image and
// nothing else. The wrapper and the example environment file are installed from
// the template (the recipe puts them there), so a release that changes either
// reaches an appliance only through a rebuilt template, and the guide says so
// beside the upgrade: an image-only upgrade of an older appliance keeps its
// older wrapper.
func TestApplianceUpgradeSaysTheWrapperBelongsToTheTemplate(t *testing.T) {
	readme := flat(applianceReadme(t))
	upgrade := readme[strings.Index(readme, "## Upgrade and roll back"):]
	if end := strings.Index(upgrade, "## Patch the appliance's operating system"); end > 0 {
		upgrade = upgrade[:end]
	}
	for _, want := range []string{
		"The reference selects the controller image and nothing else.",
		"`certistack-controller` wrapper",
		"the example environment file are installed from the template, not from the image",
		"a new image does not carry a change to either",
		"says so in its release notes",
		"only from a rebuilt template",
		"an image-only upgrade of an appliance built from an older template keeps its older wrapper",
	} {
		if !strings.Contains(upgrade, want) {
			t.Errorf("the upgrade section does not say %q", want)
		}
	}
	// The claim is true of the recipe: both files are installed into the
	// template by its provisioners.
	recipe := packerRecipe(t)
	for _, install := range []string{
		"install -m 0755 /tmp/certistack-controller /usr/local/bin/certistack-controller",
		"install -m 0600 /tmp/controller.env.example /etc/certistack/secrets/controller.env.example",
	} {
		if !strings.Contains(recipe, install) {
			t.Errorf("the recipe does not install the template's file with %q, which the guide says it does", install)
		}
	}
}

// buildSection is the guide's "Build a PVE VM template" up to its inputs.
func buildSection(t *testing.T) string {
	t.Helper()
	readme := applianceReadme(t)
	start, end := strings.Index(readme, "## Build a PVE VM template"), strings.Index(readme, "### Inputs")
	if start < 0 || end < start {
		t.Fatal("the guide has no Build a PVE VM template section before its inputs")
	}
	return readme[start:end]
}

// A build machine needs Packer, a private directory, the node's CA (the API
// certificate is signed by it, and insecure_skip_tls_verify stays off), a key
// without a passphrase (Packer cannot use one) and an address for the build
// VM, which Packer learns from the guest agent. The guide says each before the
// build, and checks the registry tag without Docker.
func TestApplianceReadmeStatesWhatABuildMachineNeeds(t *testing.T) {
	section := flat(buildSection(t))
	for _, want := range []string{
		"https://developer.hashicorp.com/packer/install",
		`sudo install -d -m 0700 -o "$USER" /secure/certistack`,
		"/etc/pve/pve-root-ca.pem",
		"openssl x509 -noout -fingerprint -sha256 -in /secure/certistack/pve-root-ca.pem",
		"SSL_CERT_FILE=/secure/certistack/pve-root-ca.pem packer build -var-file=/secure/certistack/packer.pkrvars.hcl .",
		"ssh-keygen -t ed25519 -N '' -C packer-build -f /secure/certistack/packer-build",
		"without a passphrase",
		"DHCP on the bridge",
		"`build_ip`",
		"a cloud-init drive",
		"skopeo inspect --format '{{.Digest}}' docker://ghcr.io/cliftcloud/certistack-controller:<version>",
		"`sudo apt install skopeo`",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the build section does not say %q", want)
		}
	}
	if strings.Contains(section, "docker buildx") {
		t.Error("the build section needs Docker for a registry check")
	}
}

// The guide's variable file is one the recipe takes: every name is a recipe
// variable, every required variable is there, the endpoint has its API path,
// the source template is a name, and the files are where the build command and
// the cleanup look for them.
func TestApplianceReadmeVariableFileMatchesTheRecipe(t *testing.T) {
	recipe := packerRecipe(t)
	var example string
	for _, block := range codeBlocks(t, repoFile("deploy", "appliance", "README.md")) {
		if block.heading == "Build a PVE VM template" && block.lang == "hcl" {
			example = block.body
		}
	}
	if example == "" {
		t.Fatal("the build section has no hcl variable file")
	}
	values := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^([a-z0-9_]+)\s*=\s*"([^"]*)"\s*$`).FindAllStringSubmatch(example, -1) {
		values[m[1]] = m[2]
	}
	for name := range values {
		if _, ok := packerVariable(recipe, name); !ok {
			t.Errorf("the variable file sets %s, which the recipe does not declare", name)
		}
	}
	for _, name := range packerVariableNames(recipe) {
		body, _ := packerVariable(recipe, name)
		if _, set := values[name]; !set && !regexp.MustCompile(`(?m)^\s*default\s*=`).MatchString(body) {
			t.Errorf("the variable file leaves out the required %s", name)
		}
	}
	body, _ := packerVariable(recipe, "proxmox_url")
	if !hclRegex(t, body).MatchString(values["proxmox_url"]) {
		t.Errorf("the example endpoint %q fails the recipe's validation", values["proxmox_url"])
	}
	body, _ = packerVariable(recipe, "source_template")
	if hclRegex(t, body).MatchString(values["source_template"]) {
		t.Errorf("the example source_template %q is a VM ID", values["source_template"])
	}
	section := flat(buildSection(t))
	for _, name := range []string{"ssh_private_key_file", "ssh_build_public_key_file"} {
		if !strings.Contains(section, values[name]) || !strings.HasPrefix(values[name], "/secure/certistack/") {
			t.Errorf("%s = %q is not the key pair the guide makes in /secure/certistack", name, values[name])
		}
	}
	if !strings.Contains(section, "Write the inputs to `/secure/certistack/packer.pkrvars.hcl`") {
		t.Error("the guide does not say where the variable file goes")
	}
}

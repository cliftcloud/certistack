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
// before the build, and gives the check that finds it out in a minute. A
// mutation of the README that replaced the agent's name and the preflight command
// left every other repocontract test green, because nothing read the text.
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

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func applianceReadme(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(repoFile("deploy", "appliance", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The guide describes the recipe it ships. Every variable the recipe declares
// is in the guide's input table with the same required flag and default, and
// the guide states the Packer range and the plugin version the recipe pins.
func TestApplianceReadmeDocumentsTheRecipe(t *testing.T) {
	recipe := packerRecipe(t)
	readme := applianceReadme(t)

	documented := map[string][2]string{}
	for _, row := range regexp.MustCompile("(?m)^\\| `([a-z0-9_]+)` \\| (Yes|No) \\| ([^|]*)\\|").FindAllStringSubmatch(readme, -1) {
		documented[row[1]] = [2]string{row[2], strings.Trim(strings.TrimSpace(row[3]), "`")}
	}
	for _, name := range packerVariableNames(recipe) {
		row, ok := documented[name]
		if !ok {
			t.Errorf("the appliance guide's input table does not list the recipe variable %s", name)
			continue
		}
		body, _ := packerVariable(recipe, name)
		hasDefault := regexp.MustCompile(`(?m)^\s*default\s*=`).MatchString(body)
		if required := row[0] == "Yes"; required == hasDefault {
			t.Errorf("%s: the guide says required=%v, the recipe says it has a default: %v", name, required, hasDefault)
		}
		if hasDefault && row[1] != "" && row[1] != "none" {
			if want := packerDefault(t, recipe, name); row[1] != want {
				t.Errorf("%s: the guide says the default is %q, the recipe says %q", name, row[1], want)
			}
		}
	}
	for name := range documented {
		if _, ok := packerVariable(recipe, name); !ok {
			t.Errorf("the guide's input table lists %s, which the recipe does not declare", name)
		}
	}

	if plugin := regexp.MustCompile(`version\s*=\s*"= (\d+\.\d+\.\d+)"`).FindStringSubmatch(recipe); plugin == nil ||
		!strings.Contains(readme, "exactly `= "+plugin[1]+"`") {
		t.Errorf("the guide does not state the pinned plugin version %v", plugin)
	}
	if packer := regexp.MustCompile(`required_version\s*=\s*"([^"]+)"`).FindStringSubmatch(recipe); packer == nil ||
		!strings.Contains(readme, "`required_version = \""+packer[1]+"\"`") {
		t.Errorf("the guide does not state the required Packer range %v", packer)
	}
	// The sizing table and the recipe's validation state the same minimum.
	for _, want := range []string{"| Memory | 2048 MiB |", "| vCPU | 2 |"} {
		if !strings.Contains(readme, want) {
			t.Errorf("the guide's sizing table lacks %q", want)
		}
	}
}

// secretInArguments reports whether a shell command puts a Packer secret
// variable's value on its command line: -var or -var=, in any quoting.
func secretInArguments(command string) bool {
	return regexp.MustCompile(`(?i)(^|\s)-var(\s+|=)['"]?[a-z_]*(secret|password|passphrase|token(_value)?)=`).MatchString(command)
}

// The build example passed the PVE token secret with -var, which puts
// it in the process's argument list for every local user and every process
// accounting tool to read. The guide's examples supply it from a variable
// file, and the detector is checked against the forms that leak.
func TestApplianceReadmeKeepsTheTokenOutOfArguments(t *testing.T) {
	for _, leaking := range []string{
		`packer build -var 'proxmox_token_secret=REDACTED' .`,
		`packer build -var proxmox_token_secret=abc .`,
		`packer build -var "proxmox_token_secret=$SECRET" .`,
		`packer build -var=proxmox_token_secret=abc .`,
		`packer build -var 'registry_password=x' .`,
		`  -var 'proxmox_token_secret=REDACTED' \`,
	} {
		if !secretInArguments(leaking) {
			t.Errorf("the detector misses %q", leaking)
		}
	}
	for _, fine := range []string{
		`packer build -var-file=/secure/certistack/packer.pkrvars.hcl .`,
		`packer build -var 'proxmox_node=pve-01' .`,
		`packer build -var 'ssh_private_key_file=/secure/packer-build-key' .`,
		`packer build -var 'proxmox_token_id=packer@pve!template' .`,
	} {
		if secretInArguments(fine) {
			t.Errorf("the detector flags %q", fine)
		}
	}

	sawBuild := false
	for _, block := range codeBlocks(t, repoFile("deploy", "appliance", "README.md")) {
		for _, command := range block.commands() {
			if secretInArguments(command) {
				t.Errorf("the guide puts a secret on a command line: %q", command)
			}
			if strings.HasPrefix(command, "packer build") {
				sawBuild = true
				if !strings.Contains(command, "-var-file=") {
					t.Errorf("the guide's build command takes no -var-file: %q", command)
				}
			}
		}
	}
	if !sawBuild {
		t.Error("the guide has no packer build command")
	}
}

// The Packer token's permission contract is written down: a named
// role with its privileges, granted to the user and to the separated token on
// the same explicit, non-propagating paths (never on /), expiring, removed
// after the build, and checked with pveum before it is used.
func TestApplianceReadmeStatesThePackerTokenContract(t *testing.T) {
	readme := applianceReadme(t)
	start := strings.Index(readme, "\n## Packer token permissions\n")
	if start < 0 {
		t.Fatal("the guide has no Packer token permissions section")
	}
	section := readme[start+1:]
	if end := strings.Index(section[3:], "\n## "); end >= 0 {
		section = section[:end+3]
	}

	var roleCommand string
	var aclPaths []string
	for _, block := range codeBlocks(t, repoFile("deploy", "appliance", "README.md")) {
		if block.heading != "Packer token permissions" {
			continue
		}
		for _, command := range block.commands() {
			switch {
			case strings.HasPrefix(command, "pveum role add "):
				roleCommand = command
			case strings.HasPrefix(command, "pveum acl modify "):
				fields := strings.Fields(command)
				aclPaths = append(aclPaths, fields[3])
				for _, want := range []string{"--roles PackerTemplateBuilder", "--users ", "--tokens ", "--propagate 0"} {
					if !strings.Contains(command, want) {
						t.Errorf("%q lacks %q: a privilege-separated token needs the role on the user and on the token", command, want)
					}
				}
			case strings.HasPrefix(command, "pveum user token add "):
				if !strings.Contains(command, "--privsep 1") || !strings.Contains(command, "--expire") {
					t.Errorf("%q must create a privilege-separated token that expires", command)
				}
			}
		}
	}
	for _, privilege := range []string{"VM.Clone", "VM.Allocate", "VM.Audit", "VM.PowerMgmt", "VM.GuestAgent.Audit", "VM.Config.CPU", "VM.Config.Memory", "Datastore.AllocateSpace", "SDN.Use"} {
		if !strings.Contains(roleCommand, privilege) {
			t.Errorf("the role omits %s", privilege)
		}
	}
	if strings.Contains(roleCommand, "Administrator") || strings.Contains(roleCommand, "Sys.Modify") || strings.Contains(roleCommand, "Permissions.Modify") {
		t.Errorf("the role carries an administrative privilege: %s", roleCommand)
	}
	if len(aclPaths) < 3 {
		t.Errorf("the guide grants the role on %v; the source, the build VM and its storage are each a path", aclPaths)
	}
	for _, path := range aclPaths {
		if path == "/" || path == "/vms" || path == "/storage" {
			t.Errorf("the role is granted on %s, which is wider than the build needs", path)
		}
	}
	for _, want := range []string{"pveum user token permissions packer@pve template --path", "pveum user token remove packer@pve template"} {
		if !strings.Contains(section, want) {
			t.Errorf("the section does not show %q", want)
		}
	}
}

// Two behaviour changes that an operator meets before anything else, and the
// guides say them: on the appliance, validate now needs controller.env, and a
// remote init always sends its scratch directory. The first quotes the
// controller's own error, so a change to the message fails here (cmd/certistack
// TestValidateWithoutItsEnvironmentFileSaysSo holds the command to it).
func TestGuidesSayWhatTheAppliancesValidateAndRemoteInitNeed(t *testing.T) {
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	readme := flat(applianceReadme(t))
	for _, want := range []string{
		"Because `validate` loads the file too, `sudo certistack-controller validate plan.yaml` needs `/etc/certistack/secrets/controller.env` to exist",
		`it fails with "open controller environment file: open /run/certistack-secrets/controller.env: no such file or directory"`,
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("deploy/appliance/README.md no longer says %q", want)
		}
	}
	data, err := os.ReadFile(repoFile("docs", "cli-reference.md"))
	if err != nil {
		t.Fatal(err)
	}
	guide := flat(string(data))
	for _, want := range []string{
		"With `--ssh-host`, `init` always sends the scratch directory it chose",
		`otherwise ` + "`init`" + ` stops at "prepare scratch directory"`,
	} {
		if !strings.Contains(guide, want) {
			t.Errorf("docs/cli-reference.md no longer says %q", want)
		}
	}
}

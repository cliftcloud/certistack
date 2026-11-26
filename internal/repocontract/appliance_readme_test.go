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

// -var on the command line puts a value in the process's argument list, where
// every local user and every process accounting tool can read it. The guide's
// examples supply the PVE token secret from a variable file instead, and the
// detector is checked against the forms that leak.
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
			if isPackerBuild(command) {
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

// isPackerBuild reports whether a shell command runs packer build, after any
// VAR=value environment assignments.
func isPackerBuild(command string) bool {
	fields := strings.Fields(command)
	for len(fields) > 0 && regexp.MustCompile(`^[A-Z_][A-Z0-9_]*=`).MatchString(fields[0]) {
		fields = fields[1:]
	}
	return len(fields) > 1 && fields[0] == "packer" && fields[1] == "build"
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
	// VM.Config.Cloudinit and VM.Config.CDROM: the plugin removes the build's
	// cloud-init drive and settings before the conversion and adds an empty
	// drive to the template, after the whole build has run.
	privileges := map[string]bool{}
	for _, privilege := range strings.Fields(strings.Trim(strings.TrimPrefix(roleCommand, "pveum role add PackerTemplateBuilder --privs "), `"`)) {
		privileges[privilege] = true
	}
	for _, privilege := range []string{"VM.Clone", "VM.Allocate", "VM.Audit", "VM.PowerMgmt", "VM.GuestAgent.Audit", "VM.Config.CPU", "VM.Config.Memory", "VM.Config.Cloudinit", "VM.Config.CDROM", "Datastore.AllocateSpace", "SDN.Use"} {
		if !privileges[privilege] {
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
	// PVE deletes a VM's grants with the VM, so a failed build takes the build
	// VM's grant with it, and the guide says to grant it again before a retry.
	if !strings.Contains(flat(readme), "PVE deletes the VM's grant with it: run the `/vms/<template_vmid>` line") {
		t.Error("the guide does not say a failed build takes the /vms/<template_vmid> grant with it")
	}
}

// A token removed before its grants leaves them in PVE's user.cfg, and every
// pveum and qm command then warns about an invalid ACL token. The guide removes
// the grants on each path it granted, then the token.
func TestApplianceReadmeRemovesTheTokensGrantsBeforeTheToken(t *testing.T) {
	var granted []string
	var removal []string
	for _, block := range codeBlocks(t, repoFile("deploy", "appliance", "README.md")) {
		if block.heading != "Packer token permissions" {
			continue
		}
		commands := block.commands()
		for _, command := range commands {
			if strings.HasPrefix(command, "pveum acl modify ") {
				granted = append(granted, strings.Fields(command)[3])
			}
			if command == "pveum user token remove packer@pve template" {
				removal = commands
			}
		}
	}
	if removal == nil {
		t.Fatal("the Packer token section has no block that runs pveum user token remove packer@pve template")
	}
	loop := regexp.MustCompile(`^for path in ([^;]+); do$`)
	var deleted []string
	deleteAt, removeAt := -1, -1
	for i, command := range removal {
		if m := loop.FindStringSubmatch(command); m != nil {
			deleted = strings.Fields(m[1])
		}
		switch command {
		case `pveum acl delete "$path" --roles PackerTemplateBuilder --tokens 'packer@pve!template'`:
			deleteAt = i
		case "pveum user token remove packer@pve template":
			removeAt = i
		}
	}
	if deleteAt < 0 || deleteAt > removeAt {
		t.Errorf("the token's grants are not removed before the token:\n%s", strings.Join(removal, "\n"))
	}
	if strings.Join(deleted, " ") != strings.Join(granted, " ") {
		t.Errorf("the grants are removed on %v and were granted on %v", deleted, granted)
	}
}

// On the appliance, validate loads controller.env too, and the appliance guide
// says so, quoting the controller's own error, so a change to the message fails
// here (cmd/certistack TestValidateWithoutItsEnvironmentFileSaysSo holds the
// command to it).
func TestApplianceGuideSaysValidateNeedsTheEnvironmentFile(t *testing.T) {
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	readme := flat(applianceReadme(t))
	for _, want := range []string{
		"Because `validate` loads the file too, `sudo certistack-controller validate plan.yaml` needs `/etc/certistack/secrets/controller.env` to exist",
		`it fails with "open controller environment file: open /run/certistack-secrets/controller.env: no such file or directory"`,
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("deploy/appliance/README.md does not say %q", want)
		}
	}
}

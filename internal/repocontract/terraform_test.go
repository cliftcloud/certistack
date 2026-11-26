// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// resourceBody returns the body of a top-level Terraform resource block.
func resourceBody(source, kind, name string) (string, bool) {
	match := regexp.MustCompile(`(?ms)^resource "` + regexp.QuoteMeta(kind) + `" "` + regexp.QuoteMeta(name) + `" \{\n(.*?)^\}`).FindStringSubmatch(source)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// bodyLinesExcept is a block body's trimmed, non-blank lines, dropping those
// that start with any of the prefixes.
func bodyLinesExcept(body string, prefixes ...string) []string {
	var lines []string
next:
	for _, line := range strings.Split(body, "\n") {
		line = strings.Join(strings.Fields(line), " ")
		if line == "" {
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(line, prefix) {
				continue next
			}
		}
		lines = append(lines, line)
	}
	return lines
}

// A privilege-separated token holds only what both it and its user hold on a
// path, so the module must grant CertiStackRole to the token as well as to the
// user on the very same paths. pkg/pve checks the paths against the privilege
// check a run makes, but it reads the expectation tables of
// tests/module.tftest.hcl and never main.tf; `terraform test` is what binds the
// tables to main.tf, and it needs Terraform. This test pins main.tf itself: the
// token's ACL resource exists, it is the user's resource with only the subject
// changed, both range over one path map, and none of them is the root path.
func TestTerraformModuleGrantsTheTokenWhatItGrantsTheUser(t *testing.T) {
	data, err := os.ReadFile(repoFile("terraform", "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)

	user, haveUser := resourceBody(source, "proxmox_acl", "certistack_user")
	token, haveToken := resourceBody(source, "proxmox_acl", "certistack_token")
	if !haveUser || !haveToken {
		t.Fatalf("main.tf must grant the role to the user (found: %v) and to the token (found: %v)", haveUser, haveToken)
	}
	if !strings.Contains(user, "user_id") || strings.Contains(user, "token_id") {
		t.Errorf("the user's ACL must name a user_id and no token:\n%s", user)
	}
	if !strings.Contains(token, "token_id") || strings.Contains(token, "user_id") {
		t.Errorf("the token's ACL must name a token_id and no user:\n%s", token)
	}
	// Everything but the subject is the same: the role, the paths and their
	// propagation.
	userRest := bodyLinesExcept(user, "user_id")
	tokenRest := bodyLinesExcept(token, "token_id")
	if !reflect.DeepEqual(userRest, tokenRest) {
		t.Errorf("the token's ACL differs from the user's in more than its subject:\nuser:  %q\ntoken: %q", userRest, tokenRest)
	}
	for _, want := range []string{"for_each = local.acl_paths", "path = each.key", "propagate = each.value", "role_id = proxmox_virtual_environment_role.certistack_role.role_id"} {
		if !strings.Contains(strings.Join(tokenRest, "\n"), want) {
			t.Errorf("the token's ACL lacks %q", want)
		}
	}
	if !regexp.MustCompile(`(?m)^\s*certistack_token_id\s*=\s*"\$\{proxmox_virtual_environment_user\.certistack_user\.user_id\}!\$\{proxmox_user_token\.certistack_token\.token_name\}"`).MatchString(source) ||
		!strings.Contains(token, "token_id  = local.certistack_token_id") {
		t.Error("the token ACL's subject is not the created token's own ID")
	}
	if tokenResource, _ := resourceBody(source, "proxmox_user_token", "certistack_token"); !regexp.MustCompile(`(?m)^\s*privileges_separation\s*=\s*true\s*$`).MatchString(tokenResource) {
		t.Error("the token is not privilege-separated, which is what makes its own ACLs necessary and meaningful")
	}

	// The path map: every path a run's privilege check reads, and never "/".
	locals := regexp.MustCompile(`(?ms)^locals \{\n(.*?)^\}`).FindStringSubmatch(source)
	if locals == nil {
		t.Fatal("main.tf has no locals block")
	}
	for _, want := range []string{
		`"/sdn"       = false`,
		`"/sdn/zones" = true`,
		`"/sdn/zones/${zone}" => true`,
		`"/vms"                            = true`,
		`"/storage/${var.overlay_storage}" = true`,
		`"/nodes/${var.pve_node_name}"     = false`,
	} {
		if !strings.Contains(locals[1], want) {
			t.Errorf("the ACL path map lacks %s", want)
		}
	}
	if regexp.MustCompile(`"/"\s*(=|=>)`).MatchString(source) || regexp.MustCompile(`(?m)^\s*path\s*=\s*"/"\s*$`).MatchString(source) {
		t.Error("main.tf grants the root path")
	}
}

// `terraform test` is what binds the module to the grants the Go tests check,
// so both the CI job and the release gate run it, after the module is
// initialized and unconditionally.
func TestWorkflowsRunTheModulesOfflineTests(t *testing.T) {
	for _, c := range []struct{ workflow, job string }{{"ci.yml", "test"}, {"release.yml", "verify"}} {
		job, ok := readWorkflow(t, c.workflow).Jobs[c.job]
		if !ok {
			t.Fatalf("%s has no job %q", c.workflow, c.job)
		}
		if job.ContinueOnError != nil {
			t.Errorf("%s %s may fail without failing the workflow", c.workflow, c.job)
		}
		found := false
		for _, step := range job.Steps {
			initialized := false
			for _, line := range strings.Split(step.Run, "\n") {
				switch strings.TrimSpace(line) {
				case "terraform -chdir=terraform init -backend=false":
					initialized = true
				case "terraform -chdir=terraform test":
					found = true
					if !initialized {
						t.Errorf("%s %s: terraform test runs before the module is initialized in its step %q", c.workflow, c.job, step.Name)
					}
					if step.If != "" || step.ContinueOnError != nil {
						t.Errorf("%s %s: the step %q running terraform test is conditional or may fail silently", c.workflow, c.job, step.Name)
					}
				}
			}
		}
		if !found {
			t.Errorf("%s %s never runs `terraform -chdir=terraform test`, so nothing binds main.tf to the grants pkg/pve checks", c.workflow, c.job)
		}
	}
}

// The provider deprecates its proxmox_virtual_environment_* names for the ACL
// and token resources. State that holds them under those names must move to
// the current ones without a destroy and create, which would issue a new token
// secret: each such resource needs a moved block from its deprecated address,
// and the module must require a Terraform that can move across types (1.8).
func TestTerraformModuleMovesTheDeprecatedResourceNames(t *testing.T) {
	data, err := os.ReadFile(repoFile("terraform", "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	moved, err := os.ReadFile(repoFile("terraform", "moved.tf"))
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile(`(?m)^moved \{\n\s*from\s*=\s*(\S+)\n\s*to\s*=\s*(\S+)\n\}`).FindAllStringSubmatch(string(moved), -1)
	have := map[string]string{}
	for _, b := range blocks {
		have[b[2]] = b[1]
	}
	for _, r := range []struct{ kind, name string }{
		{"proxmox_user_token", "certistack_token"},
		{"proxmox_acl", "certistack_user"},
		{"proxmox_acl", "certistack_token"},
	} {
		if _, ok := resourceBody(source, r.kind, r.name); !ok {
			t.Errorf("main.tf has no resource %s.%s", r.kind, r.name)
		}
		to := r.kind + "." + r.name
		if from, want := have[to], "proxmox_virtual_environment_"+strings.TrimPrefix(r.kind, "proxmox_")+"."+r.name; from != want {
			t.Errorf("moved.tf moves %q to %s, want %s", from, to, want)
		}
	}
	if len(blocks) != 3 {
		t.Errorf("moved.tf has %d moved blocks, want 3", len(blocks))
	}
	for _, deprecated := range []string{"proxmox_virtual_environment_acl", "proxmox_virtual_environment_user_token"} {
		if strings.Contains(source, deprecated) {
			t.Errorf("main.tf still uses the deprecated %s", deprecated)
		}
	}
	if !regexp.MustCompile(`(?m)^\s*required_version\s*=\s*">= 1\.8\.0"`).MatchString(source) {
		t.Error(`main.tf must require Terraform ">= 1.8.0", the first release whose moved blocks can change a resource's type`)
	}
}

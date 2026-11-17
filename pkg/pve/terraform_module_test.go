// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// terraformGrants reads the "grants:" tables of terraform/tests/module.tftest.hcl:
// the exact ACL paths (path => propagate) `terraform test` proves the module
// gives the CertiStack token, and its user, for each sandbox lifecycle.
func terraformGrants(t *testing.T) map[string]map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "terraform", "tests", "module.tftest.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	start := regexp.MustCompile(`^\s*# grants: (\S+)\s*$`)
	entry := regexp.MustCompile(`^\s*"([^"]+)"\s*=\s*(true|false)\s*$`)
	tables := map[string]map[string]bool{}
	var current map[string]bool
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if m := start.FindStringSubmatch(line); m != nil {
			current = map[string]bool{}
			tables[m[1]] = current
			continue
		}
		if current == nil {
			continue
		}
		if m := entry.FindStringSubmatch(line); m != nil {
			current[m[1]] = m[2] == "true"
			continue
		}
		current = nil
	}
	for _, lifecycle := range []string{"ephemeral", "preprovisioned"} {
		if len(tables[lifecycle]) == 0 {
			t.Fatalf("no %q grants table in terraform/tests/module.tftest.hcl", lifecycle)
		}
	}
	return tables
}

// grantCovers reports whether an ACL on grant, with this propagation, applies
// to path, as PVE resolves ACL paths.
func grantCovers(grant string, propagate bool, path string) bool {
	return path == grant || (propagate && strings.HasPrefix(path, strings.TrimSuffix(grant, "/")+"/"))
}

// aclServer answers access/permissions like PVE does for a privilege-separated
// token: the role's privileges where both the user's and the token's ACLs
// cover the path, none elsewhere.
func aclServer(t *testing.T, user, token map[string]bool) *httptest.Server {
	t.Helper()
	role := map[string]int{}
	for _, req := range RunPrivileges("pve1", []int{9001}, "csSb01", "csVn01", true, "certistack-scratch") {
		for _, priv := range append(append([]string(nil), req.Required...), req.Advisory...) {
			role[priv] = 1
		}
	}
	covered := func(grants map[string]bool, path string) bool {
		for grant, propagate := range grants {
			if grantCovers(grant, propagate, path) {
				return true
			}
		}
		return false
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		held := map[string]int{}
		if covered(user, path) && covered(token, path) {
			held = role
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{path: held}})
	}))
}

// The Terraform module's ACLs give the separated token every privilege a run's
// check asks for, on both sandbox lifecycles, and nothing on a path no run
// reads. Grants to the user alone, or on one resource path, leave gaps.
func TestTerraformGrantsCoverRunPrivileges(t *testing.T) {
	tables := terraformGrants(t)
	vmids := []int{9001, 9002}
	for _, lifecycle := range []string{"ephemeral", "preprovisioned"} {
		grants := tables[lifecycle]
		reqs := RunPrivileges("pve1", vmids, "csSb01", "csVn01", lifecycle == "ephemeral", "certistack-scratch")

		server := aclServer(t, grants, grants)
		missing, err := NewClient(Config{BaseURL: server.URL}).MissingPrivileges(context.Background(), reqs)
		server.Close()
		if err != nil {
			t.Fatal(err)
		}
		if required, advisory := DescribeMissingPrivileges(missing); required != "" || advisory != "" {
			t.Errorf("%s: the module's grants leave gaps: required %q, advisory %q", lifecycle, required, advisory)
		}

		for grant, propagate := range grants {
			if grant == "/" {
				t.Errorf("%s: the module grants the root path", lifecycle)
			}
			used := false
			for _, req := range reqs {
				used = used || grantCovers(grant, propagate, req.Path)
			}
			if !used {
				t.Errorf("%s: the module grants %s, which no run reads", lifecycle, grant)
			}
		}

		// Grants that fall short: the user alone holds the role, or it is held on
		// one pool path.
		for name, scopes := range map[string][2]map[string]bool{
			"token without its own ACLs": {grants, {}},
			"one pool path":              {{"/pool/certistack-recovery": true}, {"/pool/certistack-recovery": true}},
		} {
			server := aclServer(t, scopes[0], scopes[1])
			missing, err := NewClient(Config{BaseURL: server.URL}).MissingPrivileges(context.Background(), reqs)
			server.Close()
			if err != nil {
				t.Fatal(err)
			}
			if required, _ := DescribeMissingPrivileges(missing); !strings.Contains(required, "/vms/9001") || !strings.Contains(required, "/sdn/zones") {
				t.Errorf("%s, %s: expected VM and SDN gaps, got %q", lifecycle, name, required)
			}
		}
	}
}

// terraformVariables returns the module's declared inputs and whether each
// is required (declared without a default).
func terraformVariables(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "terraform", "variables.tf"))
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	blocks := regexp.MustCompile(`(?ms)^variable "([^"]+)" \{\n(.*?)^\}`).FindAllSubmatch(data, -1)
	for _, block := range blocks {
		declared[string(block[1])] = !regexp.MustCompile(`(?m)^\s*default\s*=`).Match(block[2])
	}
	if len(declared) == 0 {
		t.Fatal("no variables in terraform/variables.tf")
	}
	return declared
}

// rootACLAdvice lists the lines of a guide that put the root path in a
// statement about ACLs, grants or roles, in any wording: the path `/` itself,
// or the root or the cluster root, as the place to grant. The guide's own
// statement that the module never grants on it is not advice.
func rootACLAdvice(guide string) []string {
	root := regexp.MustCompile("(?i)`/`|" + `\b(at|on|to|from) the (cluster )?root\b|\broot (path|acl)\b`)
	topic := regexp.MustCompile(`(?i)\b(acls?|grants?|granted|granting|role|propagat\w*|path)\b`)
	var lines []string
	for _, line := range strings.Split(guide, "\n") {
		if strings.Contains(line, "never on `/`") || !root.MatchString(line) {
			continue
		}
		if topic.MatchString(line) || strings.HasPrefix(strings.TrimSpace(line), "| `/` |") {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	return lines
}

// rootACLAdvice finds root-path advice however it is worded. (The first guard
// matched only two literal phrases.)
func TestRootACLAdviceIsFoundInAnyWording(t *testing.T) {
	for _, advice := range []string{
		"* **ACL Path**: `/` (Propagate: yes)",
		"Grant the role at the root path `/` with propagation.",
		"| `/` | yes | everything a run touches |",
		"Give the user the role on `/` and let it propagate.",
		"Set the ACL on the cluster root so the role propagates to every VM.",
		"Assign CertiStackRole at the root ACL.",
	} {
		if len(rootACLAdvice(advice)) == 0 {
			t.Errorf("root ACL advice not found: %q", advice)
		}
	}
	for _, fine := range []string{
		"token, and never on `/`:",
		"| `/vms` | yes | the sandbox VMs (`/vms/<vmid>`) |",
		"Grant the role on `/storage/<overlay_storage>` and `/nodes/<node>`.",
		"a backing file that shows as `/` in losetup",
		"Privilege separation applies to the token.",
	} {
		if lines := rootACLAdvice(fine); len(lines) != 0 {
			t.Errorf("%q is not root ACL advice: %q", fine, lines)
		}
	}
}

// The guide sends the reader to the shipped tfvars example for the module's
// inputs, and gives no root-ACL advice; the example names every input the
// module declares (set, or commented out), only declared ones, and sets every
// required one.
func TestTerraformInputsAreDocumented(t *testing.T) {
	declared := terraformVariables(t)

	guide, err := os.ReadFile(filepath.Join("..", "..", "docs", "manual-setup.md"))
	if err != nil {
		t.Fatal(err)
	}
	const heading = "## Create the PVE access with Terraform"
	start := bytes.Index(guide, []byte("\n"+heading))
	if start < 0 {
		t.Fatalf("docs/manual-setup.md has no %q section", heading)
	}
	section := guide[start+1+len(heading):]
	if next := bytes.Index(section, []byte("\n## ")); next >= 0 {
		section = section[:next]
	}
	if !strings.Contains(strings.Join(strings.Fields(string(section)), " "), "`terraform/terraform.tfvars.example` lists its inputs") {
		t.Errorf("the Terraform section of docs/manual-setup.md does not send the reader to terraform/terraform.tfvars.example for the inputs:\n%s", section)
	}
	for _, line := range rootACLAdvice(string(guide)) {
		t.Errorf("the guide advises a root ACL, which the module does not grant: %s", line)
	}

	example, err := os.ReadFile(filepath.Join("..", "..", "terraform", "terraform.tfvars.example"))
	if err != nil {
		t.Fatal(err)
	}
	set, named := map[string]bool{}, map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^#?\s*([a-z0-9_]+)\s*=`).FindAllSubmatch(example, -1) {
		name := string(m[1])
		if _, ok := declared[name]; !ok {
			t.Errorf("terraform.tfvars.example sets %s, which the module does not declare", name)
		}
		named[name] = true
		if !strings.HasPrefix(string(m[0]), "#") {
			set[name] = true
		}
	}
	for name := range declared {
		if !named[name] {
			t.Errorf("terraform.tfvars.example does not name the input %s, and the guide says it lists the inputs", name)
		}
	}
	if len(declared) < 10 {
		t.Fatalf("read only %d inputs from the module; the layout this test reads has changed", len(declared))
	}
	var unset []string
	for name, required := range declared {
		if required && !set[name] {
			unset = append(unset, name)
		}
	}
	sort.Strings(unset)
	if len(unset) > 0 {
		t.Errorf("terraform.tfvars.example leaves required inputs unset: %v", unset)
	}
}

// The provider reads a user's ACL entries back into the user resource's `acl`
// blocks, so a module that manages them with proxmox_virtual_environment_acl
// must tell the user resource to leave them alone. Without that, every apply
// after the first removes the entries from PVE (PVE 9.2 with bpg/proxmox
// 0.66.3) and the privilege-separated token, which holds only what
// its user also holds, is left with nothing. The mocked provider of
// `terraform test` cannot see this, so the module's text is checked here.
func TestTerraformUserResourceLeavesItsACLToTheACLResources(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "terraform", "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `resource "proxmox_virtual_environment_acl" "certistack_user"`) {
		t.Skip("the module does not manage the service user's ACL with separate ACL resources")
	}
	start := strings.Index(text, `resource "proxmox_virtual_environment_user" "certistack_user"`)
	if start < 0 {
		t.Fatal("main.tf has no proxmox_virtual_environment_user.certistack_user resource")
	}
	block := text[start:]
	if end := strings.Index(block, "\nresource "); end >= 0 {
		block = block[:end]
	}
	if !regexp.MustCompile(`ignore_changes\s*=\s*\[[^\]]*\bacl\b[^\]]*\]`).MatchString(block) {
		t.Fatal("the service user resource must set lifecycle { ignore_changes = [acl] }: the provider reads the user's ACLs back, and without it every apply after the first removes the ACLs the separate ACL resources created")
	}
	// Deleting the user removes the ACL entries it holds, which name the role:
	// destroyed in parallel with the role, the delete fails with "the requested
	// resource does not exist" and leaves the user behind.
	if !regexp.MustCompile(`depends_on\s*=\s*\[[^\]]*proxmox_virtual_environment_role\.certistack_role[^\]]*\]`).MatchString(block) {
		t.Fatal("the service user resource must depend on the role (depends_on = [proxmox_virtual_environment_role.certistack_role]) so terraform destroy removes the user before the role")
	}
}

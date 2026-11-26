// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pve"
)

func repoText(t *testing.T, parts ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func sorted(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func sameSet(a, b []string) bool {
	return strings.Join(sorted(a), " ") == strings.Join(sorted(b), " ")
}

// terraformRolePrivileges reads the privileges of CertiStackRole out of
// terraform/main.tf.
func terraformRolePrivileges(t *testing.T) []string {
	t.Helper()
	main := repoText(t, "terraform", "main.tf")
	block := regexp.MustCompile(`(?s)resource "proxmox_virtual_environment_role" "certistack_role" \{.*?privileges\s*=\s*\[(.*?)\]`).FindStringSubmatch(main)
	if block == nil {
		t.Fatal("terraform/main.tf has no CertiStackRole privileges list")
	}
	var privileges []string
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(block[1], -1) {
		privileges = append(privileges, m[1])
	}
	if len(privileges) == 0 {
		t.Fatal("terraform/main.tf lists no privileges")
	}
	return privileges
}

// The script's role is the Terraform module's role: this test reads the module,
// so changing one without the other fails here.
func TestRolePrivilegesAreTheTerraformModulesRole(t *testing.T) {
	tf := terraformRolePrivileges(t)
	if !sameSet(RolePrivileges, tf) || len(RolePrivileges) != len(tf) {
		t.Errorf("the script's privileges differ from terraform/main.tf's:\n script:    %v\n terraform: %v", sorted(RolePrivileges), sorted(tf))
	}
	seen := map[string]bool{}
	for _, privilege := range RolePrivileges {
		if seen[privilege] {
			t.Errorf("%s is listed twice", privilege)
		}
		seen[privilege] = true
	}
}

// ... and the by-hand recipe in the guide, which the script replaces.
func TestRolePrivilegesAreTheGuidesRecipe(t *testing.T) {
	guide := repoText(t, "docs", "manual-setup.md")
	recipe := regexp.MustCompile(`pveum role add CertiStackRole --privs "([^"]+)"`).FindStringSubmatch(guide)
	if recipe == nil {
		t.Fatal("docs/manual-setup.md has no `pveum role add CertiStackRole --privs` recipe")
	}
	if got := strings.Fields(recipe[1]); !sameSet(RolePrivileges, got) || len(got) != len(RolePrivileges) {
		t.Errorf("the guide's recipe differs from the script's privileges:\n guide:  %v\n script: %v", sorted(got), sorted(RolePrivileges))
	}
}

// The role holds every privilege a run's check reads, required or advisory.
func TestRolePrivilegesCoverWhatARunChecks(t *testing.T) {
	have := map[string]bool{}
	for _, privilege := range RolePrivileges {
		have[privilege] = true
	}
	for _, zones := range []bool{true, false} {
		for _, requirement := range pve.RunPrivileges("pve1", []int{9100}, "csSb01", "csVn01", zones, "certistack-scratch") {
			for _, privilege := range append(append([]string(nil), requirement.Required...), requirement.Advisory...) {
				if !have[privilege] {
					t.Errorf("a run checks %s on %s, which the role lacks", privilege, requirement.Path)
				}
			}
		}
	}
}

// terraformGrants reads the "grants:" tables of the module's offline tests:
// the ACL paths (path => propagate) `terraform test` proves the module grants.
func terraformGrants(t *testing.T) map[string]map[string]bool {
	t.Helper()
	tests := repoText(t, "terraform", "tests", "module.tftest.hcl")
	start := regexp.MustCompile(`^\s*# grants: (\S+)\s*$`)
	entry := regexp.MustCompile(`^\s*"([^"]+)"\s*=\s*(true|false)\s*$`)
	tables := map[string]map[string]bool{}
	var current map[string]bool
	for _, line := range strings.Split(tests, "\n") {
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
	return tables
}

// The ACL paths and their propagation are the ones the module's tests prove,
// for the node, storage and zone of those tests.
func TestACLsAreTheTerraformModulesGrants(t *testing.T) {
	grants := terraformGrants(t)
	for lifecycle, zones := range map[string][]string{"ephemeral": nil, "preprovisioned": {"csSb01"}} {
		want := grants[lifecycle]
		if len(want) == 0 {
			t.Fatalf("no %q grants table in terraform/tests/module.tftest.hcl", lifecycle)
		}
		got := map[string]bool{}
		for _, acl := range PVEACLs("pve1", "certistack-scratch", zones) {
			got[acl.Path] = acl.Propagate
		}
		if len(got) != len(want) {
			t.Errorf("%s: the script grants %v, the module grants %v", lifecycle, got, want)
			continue
		}
		for path, propagate := range want {
			if value, ok := got[path]; !ok || value != propagate {
				t.Errorf("%s: %s propagate = %v (granted %v); the module has %v", lifecycle, path, value, ok, propagate)
			}
		}
	}
}

func scriptFor(t *testing.T, p RBACParams) string {
	t.Helper()
	script, err := RBACScript(p)
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func commandsOf(script string) []string {
	var commands []string
	for _, line := range strings.Split(script, "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			commands = append(commands, line)
		}
	}
	return commands
}

func TestRBACScriptGrantsUserAndTokenOnEveryPathAndNeverOnRoot(t *testing.T) {
	for _, zones := range [][]string{nil, {"csSb01", "csSb02"}} {
		script := scriptFor(t, RBACParams{Node: "pve-node-01", OverlayStorage: "certistack-scratch", Zones: zones})
		var paths []string
		for _, command := range commandsOf(script) {
			if !strings.HasPrefix(command, "pveum acl modify ") {
				continue
			}
			fields := strings.Fields(command)
			path := fields[3]
			paths = append(paths, path)
			if path == "/" {
				t.Errorf("the role is granted on the root: %s", command)
			}
			for _, want := range []string{"--roles CertiStackRole", "--users certistack-svc@pve", "--tokens 'certistack-svc@pve!automation'"} {
				if !strings.Contains(command, want) {
					t.Errorf("%q lacks %s", command, want)
				}
			}
		}
		want := []string{"/vms"}
		if len(zones) == 0 {
			want = append(want, "/sdn", "/sdn/zones")
		}
		for _, zone := range zones {
			want = append(want, "/sdn/zones/"+zone)
		}
		want = append(want, "/storage/certistack-scratch", "/nodes/pve-node-01")
		if strings.Join(paths, " ") != strings.Join(want, " ") {
			t.Errorf("zones %v: paths = %v, want %v", zones, paths, want)
		}
	}
}

func TestRBACScriptPropagationFollowsTheGuidesTable(t *testing.T) {
	script := scriptFor(t, RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch"})
	for path, propagate := range map[string]string{"/vms": "1", "/sdn": "0", "/sdn/zones": "1", "/storage/certistack-scratch": "1", "/nodes/pve1": "0"} {
		want := "pveum acl modify " + path + " --roles CertiStackRole --users certistack-svc@pve --tokens 'certistack-svc@pve!automation' --propagate " + propagate
		if !strings.Contains(script, want+"\n") {
			t.Errorf("the script lacks %q", want)
		}
	}
}

func TestRBACScriptPBSPartOnlyWithADatastoreAndReadOnly(t *testing.T) {
	without := scriptFor(t, RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch"})
	if strings.Contains(without, "proxmox-backup-manager user") || strings.Contains(without, "PART 2 of 2") {
		t.Error("the PBS part is there without a datastore")
	}
	with := scriptFor(t, RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch", PBSDatastore: "datastore1"})
	for _, want := range []string{
		"proxmox-backup-manager user create certistack-ro@pbs\n",
		"proxmox-backup-manager user generate-token certistack-ro@pbs ro\n",
		"proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id certistack-ro@pbs\n",
		"proxmox-backup-manager acl update /datastore/datastore1 DatastoreReader --auth-id 'certistack-ro@pbs!ro'\n",
	} {
		if !strings.Contains(with, want) {
			t.Errorf("the script lacks %q", want)
		}
	}
	for _, command := range commandsOf(with) {
		if strings.HasPrefix(command, "proxmox-backup-manager acl") && !strings.Contains(command, "DatastoreReader") {
			t.Errorf("a PBS grant is not DatastoreReader: %s", command)
		}
		for _, writer := range []string{"DatastoreBackup", "DatastoreAdmin", "DatastorePowerUser", "Admin"} {
			if strings.Contains(command, " "+writer+" ") {
				t.Errorf("a PBS grant gives a role that can write: %s", command)
			}
		}
	}
	scoped := scriptFor(t, RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch", PBSDatastore: "datastore1", PBSNamespace: "prod/dc1"})
	for _, want := range []string{
		"acl update /datastore/datastore1/prod/dc1 DatastoreReader --auth-id certistack-ro@pbs\n",
		"acl update /datastore/datastore1/prod/dc1 DatastoreReader --auth-id 'certistack-ro@pbs!ro'\n",
		"#   PBS_NAMESPACE=prod/dc1",
	} {
		if !strings.Contains(scoped, want) {
			t.Errorf("the namespace-scoped script lacks %q", want)
		}
	}
}

// The script never carries a secret, and says where the tool's own secrets
// appear: once, from the command that creates the token.
func TestRBACScriptSaysWhereTheSecretsAppear(t *testing.T) {
	script := scriptFor(t, RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch", PBSDatastore: "datastore1"})
	for _, want := range []string{
		"Run as root on a PVE node",
		"Run as root on the PBS server",
		"ONCE, here. It is PVE_TOKEN_SECRET",
		"prints the token's secret ONCE. It is PBS_PASSWORD",
		"certistack never\n# sees the secrets",
		"printed this script and ran nothing",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the script lacks %q", want)
		}
	}
}

// When certistack setup holds the secret of an existing token, the script says
// the token was found and its secret is kept, and gives none of the advice for
// a lost secret. Without SecretKept, the script setup runs (capture) says that
// setup holds no secret and stops before any grant; a printed script stops
// unless CERTISTACK_KEEP_TOKEN=yes, and says how to replace a lost secret.
func TestRBACScriptKeptSecretGivesNoLostSecretAdvice(t *testing.T) {
	for _, part := range []string{PartPVE, PartPBS} {
		for _, capture := range []bool{true, false} {
			p := RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch", PBSDatastore: "datastore1", Part: part, Capture: capture, Command: "certistack setup"}
			unheld := scriptFor(t, p)
			p.SecretKept = true
			kept := scriptFor(t, p)
			wantUnheld := []string{"cannot be shown again", "certistack setup does not hold its secret, so nothing was granted to it.", "exit 0"}
			if !capture {
				wantUnheld = []string{"cannot be shown again", "Nothing was granted to it", "CERTISTACK_KEEP_TOKEN=yes", "If you lost it", "exit 3"}
			}
			for _, want := range wantUnheld {
				if !strings.Contains(unheld, want) {
					t.Errorf("%s part (capture %v) without SecretKept lacks %q", part, capture, want)
				}
			}
			for _, lost := range []string{"If you lost it", "cannot be shown again", "CERTISTACK_KEEP_TOKEN=yes:", "Nothing was granted", "nothing was granted"} {
				if strings.Contains(kept, lost) {
					t.Errorf("%s part (capture %v) with SecretKept still says %q", part, capture, lost)
				}
			}
			for _, want := range []string{"it exists already, so it was not created again", "certistack setup holds the secret of this token and keeps using it."} {
				if !strings.Contains(kept, want) {
					t.Errorf("%s part (capture %v) with SecretKept lacks %q", part, capture, want)
				}
			}
		}
	}
}

// A script a shell cannot parse would only be found out on the node.
func TestRBACScriptIsValidShell(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, p := range []RBACParams{
		{Node: "pve1", OverlayStorage: "certistack-scratch"},
		{Node: "pve1", OverlayStorage: "certistack-scratch", Zones: []string{"csSb01"}, PBSDatastore: "datastore1", PBSNamespace: "a/b"},
		{Node: "pve1", OverlayStorage: "certistack-scratch", Part: PartPVE, Capture: true, SecretKept: true},
		{Node: "pve1", OverlayStorage: "certistack-scratch", PBSDatastore: "datastore1", Part: PartPBS, Capture: true, SecretKept: true},
	} {
		command := exec.Command(shell, "-n")
		command.Stdin = strings.NewReader(scriptFor(t, p))
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("sh -n: %v\n%s", err, output)
		}
	}
}

func TestRBACParamsRefuseWhatCouldChangeTheCommands(t *testing.T) {
	good := RBACParams{Node: "pve1", OverlayStorage: "certistack-scratch"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RBACParams){
		"node with a semicolon": func(p *RBACParams) { p.Node = "pve1; rm -rf /" },
		"empty node":            func(p *RBACParams) { p.Node = "" },
		"storage with a space":  func(p *RBACParams) { p.OverlayStorage = "scratch disk" },
		"storage in capitals":   func(p *RBACParams) { p.OverlayStorage = "Scratch" },
		"no storage":            func(p *RBACParams) { p.OverlayStorage = "" },
		"zone with a dash":      func(p *RBACParams) { p.Zones = []string{"cs-zone"} },
		"zone with a slash":     func(p *RBACParams) { p.Zones = []string{"cs/zone"} },
		"zone twice":            func(p *RBACParams) { p.Zones = []string{"csSb01", "csSb01"} },
		"datastore too short":   func(p *RBACParams) { p.PBSDatastore = "ab" },
		"datastore with quote":  func(p *RBACParams) { p.PBSDatastore = "data'store" },
		"namespace dotdot":      func(p *RBACParams) { p.PBSDatastore, p.PBSNamespace = "datastore1", "a/../b" },
		"namespace with space":  func(p *RBACParams) { p.PBSDatastore, p.PBSNamespace = "datastore1", "a b" },
		"namespace alone":       func(p *RBACParams) { p.PBSNamespace = "prod" },
	} {
		p := good
		mutate(&p)
		if _, err := RBACScript(p); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

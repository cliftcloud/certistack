// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
)

// The names the access setup uses. They are the ones terraform/main.tf and the
// quickstart use, so a controller configured by any of the three looks the same.
const (
	RoleName     = "CertiStackRole"
	PVEUser      = "certistack-svc@pve"
	PVETokenName = "automation"
	PVETokenID   = PVEUser + "!" + PVETokenName
	PBSUser      = "certistack-ro@pbs"
	PBSTokenName = "ro"
	PBSTokenID   = PBSUser + "!" + PBSTokenName
)

// RolePrivileges are CertiStackRole's privileges, in the order
// terraform/main.tf lists them. A test reads the module and the by-hand recipe
// in docs/manual-setup.md and fails when either differs from this list,
// so the script, the module and the guide cannot drift apart.
var RolePrivileges = []string{
	"VM.Allocate",
	"VM.Audit",
	"VM.PowerMgmt",
	"VM.Console",
	"VM.Config.Disk",
	"VM.Config.CPU",
	"VM.Config.Memory",
	"VM.Config.Network",
	"VM.Config.Options",
	"VM.Config.HWType",
	"VM.Config.CDROM",
	"SDN.Allocate",
	"SDN.Audit",
	"SDN.Use",
	"Sys.Audit",
	"Datastore.AllocateSpace",
	"Datastore.Audit",
}

// ACL is one path the role is granted on, to the user and to the token.
type ACL struct {
	Path      string
	Propagate bool
	// Why is what the grant covers, for the script's comment.
	Why string
}

// PVEACLs are the paths the role is granted on, as docs/manual-setup.md
// tabulates them and terraform/main.tf grants them: never on "/". Without zones
// the sandbox is ephemeral and the SDN paths cover creating its zone; with zones
// (pre-provisioned sandboxes) each zone is granted instead.
func PVEACLs(node, overlayStorage string, zones []string) []ACL {
	acls := []ACL{{"/vms", true, "the sandbox VMs (/vms/<vmid>); not narrower, because PVE deletes a VM's own ACL when the VM is destroyed"}}
	if len(zones) == 0 {
		acls = append(acls,
			ACL{"/sdn", false, "taking PVE's SDN lock (PVE 9) and applying the sandbox network"},
			ACL{"/sdn/zones", true, "creating and removing the ephemeral sandbox zone and its VNet"},
		)
	}
	for _, zone := range zones {
		acls = append(acls, ACL{"/sdn/zones/" + zone, true, "reading and using the pre-provisioned sandbox zone " + zone + " and its VNet"})
	}
	return append(acls,
		ACL{"/storage/" + overlayStorage, true, "the overlays and firmware copies"},
		ACL{"/nodes/" + node, false, "reading the node's status and QEMU machine versions"},
	)
}

// RBACParams are what the script is written for.
type RBACParams struct {
	// Node is the PVE node that hosts the sandbox, as PVE names it.
	Node string
	// OverlayStorage is the PVE storage that holds the overlays.
	OverlayStorage string
	// Zones are pre-provisioned sandbox zones; none means an ephemeral sandbox.
	Zones []string
	// PBSDatastore, when set, adds the PBS part for a read-only identity on
	// that datastore; PBSNamespace limits it to one namespace of it.
	PBSDatastore string
	PBSNamespace string
	// Part limits the script to one of its parts: PartPVE or PartPBS. Empty is
	// both parts (the PBS part only with a datastore). A single part is a
	// complete script of its own, so that
	// `certistack setup rbac ... --part pve | ssh root@NODE sh -s` works.
	Part    string
	Command string // the command line that was run, quoted in the header
	// Capture writes the script `certistack setup` runs itself, one part at a
	// time: everything the script says goes to standard error, where the
	// operator sees it, and standard output carries only the JSON of the token
	// the part creates (nothing when the token exists already), which the setup
	// reads into the 0600 environment file. The secret is never shown.
	Capture bool
	// SecretKept says that certistack setup holds the secret of the part's
	// token, which exists already: the script then reports the token as found
	// and kept, without the advice for a lost secret, which would tell the
	// operator to replace a token whose secret setup has in hand.
	SecretKept bool
}

// The values of RBACParams.Part, and of the command's --part flag.
const (
	PartPVE = "pve"
	PartPBS = "pbs"
)

// validDatastore reports whether name looks like a PBS datastore ID: 3 to 32
// letters, digits, "-", "_" and ".", not starting with "-" or ".", as PBS and
// the shape check of PBS_REPOSITORY allow.
func validDatastore(name string) bool {
	if len(name) < 3 || len(name) > 32 {
		return false
	}
	for i, r := range name {
		word := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_'
		if !word && (i == 0 || (r != '-' && r != '.')) {
			return false
		}
	}
	return true
}

// Validate refuses a value that is not what it names, so the script holds only
// words that cannot change what its commands mean.
func (p RBACParams) Validate() error {
	if err := initplan.ValidateRequest(initplan.Request{Node: p.Node, Namespace: p.PBSNamespace, AvoidSDNIDs: p.Zones}); err != nil {
		return err
	}
	if p.OverlayStorage == "" || !config.ValidPVEStorageID(p.OverlayStorage) {
		return fmt.Errorf("invalid overlay storage ID %q: use a PVE storage ID such as certistack-scratch", p.OverlayStorage)
	}
	seen := map[string]bool{}
	for _, zone := range p.Zones {
		if seen[zone] {
			return fmt.Errorf("zone %q is named twice", zone)
		}
		seen[zone] = true
	}
	if p.PBSDatastore != "" && !validDatastore(p.PBSDatastore) {
		return fmt.Errorf("invalid PBS datastore %q: use the datastore's ID as PBS shows it", p.PBSDatastore)
	}
	if p.PBSNamespace != "" && p.PBSDatastore == "" {
		return errors.New("--pbs-namespace needs --pbs-datastore")
	}
	if p.Capture && p.Part == "" {
		return errors.New("a script whose token secret certistack setup reads holds one part: name pve or pbs")
	}
	switch p.Part {
	case "", PartPVE:
	case PartPBS:
		if p.PBSDatastore == "" {
			return errors.New("--part pbs needs --pbs-datastore: the Proxmox Backup Server part is only written for a datastore")
		}
	default:
		return fmt.Errorf("invalid --part %q: use pve (the Proxmox VE part) or pbs (the Proxmox Backup Server part), or leave --part out to print both", p.Part)
	}
	return nil
}

// RBACScript is the shell script that creates what a controller needs: on the
// PVE node, CertiStackRole, the service user, a privilege-separated token and
// the ACLs for the user and the token; and, when a datastore is named, on the
// PBS server, a read-only user and token with DatastoreReader. Nothing runs it
// here: it is printed for an operator to read and run. Every command in it is
// the one docs/manual-setup.md gives for the same step.
func RBACScript(p RBACParams) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	// stopTrap makes a failing step say which step it was: set -e alone would
	// stop on the tool's own error with nothing to tell a newcomer what to do.
	stopTrap := func() {
		line("STEP='starting'")
		line(`trap 'status=$?; [ "$status" -eq 0 ] || echo "certistack access setup stopped while $STEP (exit status $status). Nothing after this step ran. Fix the cause shown above, then run the script again: every step can be repeated." >&2' EXIT`)
	}
	// existingToken is the branch for a token that exists already: its secret
	// was shown once and cannot be shown again. The grants that follow it are
	// given only to a token whose secret is held: by certistack setup
	// (SecretKept), or by the person running a printed script, who says so with
	// CERTISTACK_KEEP_TOKEN=yes. Otherwise the script stops before any grant: a
	// token made for another controller (another customer's, on a PBS or a
	// cluster they share) must gain no access from this run.
	existingToken := func(system, tokenID, secretName, removal string) {
		kind := "API token"
		if system == "PBS" {
			kind = "PBS API token"
		}
		line("  echo 'Found the existing %s %s: it exists already, so it was not created again.' >&2", kind, tokenID)
		line("  echo 'It was not examined or changed: its expiry, its privilege separation and its comment stay as they are.' >&2")
		if p.SecretKept {
			if system == "PVE" {
				line("  echo 'A token made by hand without --privsep 1 holds all the privileges of its user, not only the role; if it was, remove it (%s) and run certistack setup again.' >&2", removal)
			}
			line("  echo 'certistack setup holds the secret of this token and keeps using it.' >&2")
			return
		}
		if system == "PVE" {
			line("  echo 'A token made by hand without --privsep 1 holds all the privileges of its user, not only the role; if it was, replace it as below.' >&2")
		}
		line("  echo '%s shows the secret of a token only once, when it is created; it cannot be shown again.' >&2", system)
		if p.Capture {
			// certistack setup holds no secret for it: it asks next whether to
			// replace the token. No token JSON on standard output is how it
			// learns that the token exists.
			line("  echo 'certistack setup does not hold its secret, so nothing was granted to it.' >&2")
			line("  exit 0")
			return
		}
		line(`  if [ "${CERTISTACK_KEEP_TOKEN:-}" != yes ]; then`)
		line("    echo 'Nothing was granted to it: a token whose secret is held elsewhere gains no access from this script.' >&2")
		line("    echo 'If you hold its secret (your %s), run this script again with CERTISTACK_KEEP_TOKEN=yes in front, for example: CERTISTACK_KEEP_TOKEN=yes sh -s < this-script.sh' >&2", secretName)
		line("    echo 'If you lost it, replace the token: run  %s' >&2", removal)
		line("    echo 'and then run this script again; it creates a new token and prints its new secret.' >&2")
		line("    exit 3")
		line("  fi")
		line("  echo 'CERTISTACK_KEEP_TOKEN=yes: you hold its secret, so the grants below are given to it.' >&2")
	}

	line("#!/bin/sh")
	line("# CertiStack access setup. Review it, then run each part where it says.")
	if p.Command != "" {
		line("# Generated by: %s", p.Command)
	}
	line("#")
	if p.Capture {
		line("# `certistack setup` runs this script and reads the secret of the token it creates")
		line("# from the script's standard output into your 0600 controller.env; it is not")
		line("# shown. Everything else the script says goes to standard error.")
	} else {
		line("# `certistack setup rbac` printed this script and ran nothing. certistack never")
		line("# sees the secrets the script creates: each token secret is printed once, by the")
		line("# command that creates it, on the terminal where you run it. Put it in your 0600")
		line("# controller.env at once; neither PVE nor PBS can show it again.")
	}
	line("#")
	line("# The script is safe to run again, after an error or when a newer CertiStack")
	line("# prints it: a role that exists is set to the current privilege list, a user or")
	line("# token that exists is left as it is (a token's secret cannot be shown a second")
	line("# time, so the script says how to replace it instead), and the ACLs are set again.")
	line("# A token that exists gets the ACLs only if you hold its secret: then run the")
	line("# script with CERTISTACK_KEEP_TOKEN=yes in front. Without it the script stops")
	line("# before any grant, so a token made for another controller gains no access.")
	line("# If a step fails the script stops and says which one; run it again once the")
	line("# cause is fixed.")
	line("#")
	parts := 1
	if p.PBSDatastore != "" {
		parts = 2
	}
	withPVE := p.Part != PartPBS
	withPBS := p.PBSDatastore != "" && p.Part != PartPVE
	// partCommand is the command that prints one part on its own; its output is
	// a complete script, so it can be sent to the host that runs it.
	partCommand := func(part string) string {
		command := p.Command
		if command == "" {
			command = "certistack setup rbac ..."
		}
		return strings.TrimSuffix(strings.TrimSuffix(command, " --part pve"), " --part pbs") + " --part " + part
	}
	switch {
	case p.PBSDatastore == "":
		line("# This file is for a Proxmox VE node: run it as root there. The PBS part (a")
		line("# read-only user) is not included; run `certistack setup rbac` again with")
		line("# --pbs-datastore NAME to add it.")
	case p.Part == PartPVE:
		line("# This file holds PART 1 only, for a Proxmox VE node: run it as root there. PART 2,")
		line("# for the Proxmox Backup Server, is printed by the same command with --part pbs:")
		line("#   %s | ssh root@PBS-HOST sh -s", partCommand(PartPBS))
	case p.Part == PartPBS:
		line("# This file holds PART 2 only, for the Proxmox Backup Server: run it as root there.")
		line("# PART 1, for a Proxmox VE node, is printed by the same command with --part pve:")
		line("#   %s | ssh root@NODE sh -s", partCommand(PartPVE))
	default:
		line("# This file holds two parts for two hosts. Copy PART 1 to a Proxmox VE node and")
		line("# PART 2 to the Proxmox Backup Server, and run each as root on its own host.")
		line("# To send one part to its host without copying this file, print it alone:")
		line("#   %s | ssh root@NODE sh -s", partCommand(PartPVE))
		line("#   %s | ssh root@PBS-HOST sh -s", partCommand(PartPBS))
	}
	line("")
	if withPVE {
		line("# ======================================================================")
		line("# PART 1 of %d: Proxmox VE. Run as root on a PVE node. pveum configures the", parts)
		line("# whole cluster, so any one node will do.")
		line("# ======================================================================")
		line("set -eu")
		if p.Capture {
			// Standard output is kept as descriptor 3 for the token's JSON alone;
			// everything else the part prints goes to standard error.
			line("exec 3>&1 1>&2")
		}
		line(`command -v pveum >/dev/null 2>&1 || { echo "pveum not found: run PART 1 as root on a Proxmox VE node" >&2; exit 1; }`)
		stopTrap()
		line("")
		line("# 1. The role: the privileges a run needs and nothing else. It is the list in")
		line("#    terraform/main.tf and at https://certistack.dev/docs/manual-setup/. A role that")
		line("#    exists is set to this list; a missing one is created.")
		privileges := strings.Join(RolePrivileges, " ")
		line("STEP='creating or updating the role %s'", RoleName)
		line(`if pveum role list --output-format json | grep -Fq '"%s"'; then`, RoleName)
		line(`  pveum role modify %s --privs "%s"`, RoleName, privileges)
		line("  echo 'Role %s existed: its privileges are now the current list.'", RoleName)
		line("else")
		line(`  pveum role add %s --privs "%s"`, RoleName, privileges)
		line("  echo 'Role %s created.'", RoleName)
		line("fi")
		line("")
		line("# 2. The service user. It has no password, so nobody can sign in as it. A user")
		line("#    that exists is left as it is.")
		line("STEP='creating the user %s'", PVEUser)
		line(`if pveum user list --output-format json | grep -Fq '"%s"'; then`, PVEUser)
		line("  echo 'Found the existing user %s. It was not examined or changed: it is left as it is, whatever its state (a disabled user stays disabled).'", PVEUser)
		line("else")
		line(`  pveum user add %s --comment "CertiStack restore tests"`, PVEUser)
		line("  echo 'User %s created.'", PVEUser)
		line("fi")
		line("")
		line("# 3. The API token, privilege-separated: PVE gives it only the privileges that")
		line("#    both it and its user hold on a path, which is why item 4 grants both.")
		line("#    PVE prints the token's secret (\"value\") ONCE, here. It is PVE_TOKEN_SECRET.")
		line("#    PVE_TOKEN_ID is %s.", PVETokenID)
		line("#    A token that exists is not created again (PVE cannot show its secret a second")
		line("#    time); the ACLs below are given to it only if its secret is held.")
		line("STEP='creating the API token %s'", PVETokenID)
		line(`if pveum user token list %s --output-format json | grep -Eq '"(%s!)?%s"'; then`, PVEUser, PVEUser, PVETokenName)
		existingToken("PVE", PVETokenID, "PVE_TOKEN_SECRET", "pveum user token remove "+PVEUser+" "+PVETokenName)
		line("else")
		if p.Capture {
			line("  echo 'Creating the API token %s. certistack setup reads its secret into controller.env.'", PVETokenID)
			line("  pveum user token add %s %s --privsep 1 --output-format json >&3", PVEUser, PVETokenName)
		} else {
			line("  echo 'Creating the API token %s. Its secret is printed once, below: copy it now.'", PVETokenID)
			line("  pveum user token add %s %s --privsep 1", PVEUser, PVETokenName)
		}
		line("fi")
		line("")
		line("# 4. Grant the role to the user AND to the token on each path below, and on no")
		line("#    other: never on \"/\".")
		if len(p.Zones) > 0 {
			line("#    This is for pre-provisioned sandbox zone(s) %s, so /sdn and /sdn/zones are", strings.Join(p.Zones, ", "))
			line("#    not granted. A plan with the default ephemeral sandbox would fail its")
			line("#    privilege check; leave --zone and --sandbox-zones out for that.")
		}
		line("STEP='granting %s on the paths of item 4'", RoleName)
		for _, acl := range PVEACLs(p.Node, p.OverlayStorage, p.Zones) {
			line("# %s: %s.", acl.Path, acl.Why)
			line("pveum acl modify %s --roles %s --users %s --tokens '%s' --propagate %d", acl.Path, RoleName, PVEUser, PVETokenID, boolToInt(acl.Propagate))
		}
		line("")
		line("# 5. Check what the token holds on a path (certistack plan lists any privilege")
		line("#    still missing for the paths a plan uses):")
		line("STEP='reading the token permissions'")
		line("pveum user token permissions %s %s --path /vms", PVEUser, PVETokenName)
		line("")
		line("# Then, on the controller, in controller.env:")
		line("#   PVE_TOKEN_ID=%s", PVETokenID)
		line("#   PVE_TOKEN_SECRET=<the value item 3 printed>")
	}

	if withPBS {
		path := "/datastore/" + p.PBSDatastore
		scope := "the datastore " + p.PBSDatastore
		if p.PBSNamespace != "" {
			path += "/" + p.PBSNamespace
			scope = "the namespace " + p.PBSNamespace + " of the datastore " + p.PBSDatastore + " only"
		}
		if withPVE {
			line("")
		}
		line("# ======================================================================")
		line("# PART 2 of 2: Proxmox Backup Server. Run as root on the PBS server.")
		line("# ======================================================================")
		line("set -eu")
		if p.Capture {
			line("exec 3>&1 1>&2")
		}
		// The step is named before the check, so that a failing check does not
		// blame the last step of part 1 when the whole file is run.
		line("STEP='checking that this host is the Proxmox Backup Server'")
		line("if ! command -v proxmox-backup-manager >/dev/null 2>&1; then")
		if withPVE {
			// The whole file run on a Proxmox VE node: part 1 has just been done
			// and part 2 belongs elsewhere. That is not an error.
			line("  if command -v pveum >/dev/null 2>&1; then")
			line("    echo 'Part 1 is done on this Proxmox VE node. Part 2 is for the Proxmox Backup Server and is not run here:'")
			line("    echo 'run part 2 on the Proxmox Backup Server, as root there, with this file or with the same certistack setup rbac command plus --part pbs.'")
			line("    exit 0")
			line("  fi")
			line(`  echo "proxmox-backup-manager not found: run PART 2 as root on the Proxmox Backup Server" >&2`)
		} else {
			line(`  echo "proxmox-backup-manager not found: run this script as root on the Proxmox Backup Server" >&2`)
		}
		line("  exit 1")
		line("fi")
		stopTrap()
		line("")
		line("# A read-only identity: DatastoreReader (Datastore.Audit and Datastore.Read) on")
		line("# %s and no write privilege. A user that exists is left as it is.", scope)
		line("# This script adds that grant and removes none: a wider grant the user already")
		line("# holds stays. Check what it holds with: proxmox-backup-manager acl list")
		line("STEP='creating the PBS user %s'", PBSUser)
		line(`if proxmox-backup-manager user list --output-format json | grep -Fq '"%s"'; then`, PBSUser)
		line("  echo 'Found the existing PBS user %s. It was not examined or changed: it is left as it is, whatever its state (a disabled user stays disabled).'", PBSUser)
		line("else")
		line("  proxmox-backup-manager user create %s", PBSUser)
		line("  echo 'PBS user %s created.'", PBSUser)
		line("fi")
		line("")
		line("# generate-token prints the token's secret ONCE. It is PBS_PASSWORD. A token that")
		line("# exists is not created again (PBS cannot show its secret a second time); the")
		line("# ACLs below are given to it only if its secret is held.")
		line("STEP='creating the PBS API token %s'", PBSTokenID)
		line(`if proxmox-backup-manager user list-tokens %s --output-format json | grep -Eq '"(%s!)?%s"'; then`, PBSUser, PBSUser, PBSTokenName)
		existingToken("PBS", PBSTokenID, "PBS_PASSWORD", "proxmox-backup-manager user delete-token "+PBSUser+" "+PBSTokenName+" (or in the PBS web UI: Configuration, Access Control, API Token)")
		line("else")
		if p.Capture {
			line("  echo 'Creating the PBS API token %s. certistack setup reads its secret into controller.env.'", PBSTokenID)
			// generate-token has no --output-format (PBS 4.2 refuses it: "schema does
			// not allow additional properties"); it prints "Result: " and the JSON
			// object, which ParseTokenSecret reads.
			line("  proxmox-backup-manager user generate-token %s %s >&3", PBSUser, PBSTokenName)
		} else {
			line("  echo 'Creating the PBS API token %s. Its secret is printed once, below: copy it now.'", PBSTokenID)
			line("  proxmox-backup-manager user generate-token %s %s", PBSUser, PBSTokenName)
		}
		line("fi")
		line("")
		line("# The role is set for the user and for the token, so the token is covered")
		line("# whichever of the two PBS consults.")
		line("STEP='granting DatastoreReader on %s'", path)
		line("proxmox-backup-manager acl update %s DatastoreReader --auth-id %s", path, PBSUser)
		line("proxmox-backup-manager acl update %s DatastoreReader --auth-id '%s'", path, PBSTokenID)
		if p.PBSNamespace != "" {
			widerGrantCheck(line, p.PBSDatastore, p.Capture)
		}
		line("")
		line("# Then, on the controller, in controller.env:")
		line("#   PBS_REPOSITORY=%s@<PBS host>:8007:%s", PBSTokenID, p.PBSDatastore)
		line("#   PBS_PASSWORD=<the secret generate-token printed>")
		line("#   PBS_FINGERPRINT=<the PBS certificate's fingerprint: proxmox-backup-manager cert info>")
		if p.PBSNamespace != "" {
			line("#   PBS_NAMESPACE=%s", p.PBSNamespace)
		}
	}
	return b.String(), nil
}

// widerGrantCheck writes the lines that look, after a namespace was granted,
// for the grant on the whole datastore that an earlier setup (or this script
// without a namespace) gave the PBS user or its token: DatastoreReader,
// propagated, on /datastore/<datastore>. The namespace grant does not take it
// back, so the user would still read every namespace. The lines change
// nothing. The script setup runs (capture) reports which of the two hold it as
// one JSON line, {"wider_grant":"<auth-id> ..."}, and setup offers to remove
// it; a printed script says so and prints the commands that remove it. Only
// the user's and the token's own names are matched: the token's "!" stays
// inside single quotes, out of reach of an interactive shell's history
// expansion.
func widerGrantCheck(line func(format string, args ...any), datastore string, capture bool) {
	path := "/datastore/" + datastore
	line("")
	line("# An earlier grant on the whole datastore (%s, from a setup or a script", path)
	line("# without a namespace) is not taken back by the namespace grant above, and")
	line("# lets the user read every namespace. Look for it; this changes nothing.")
	line("STEP='looking for an earlier grant on %s'", path)
	line(`wider=$(proxmox-backup-manager acl list --output-format json 2>/dev/null | tr -d '\n' | grep -o '{[^}]*}' | grep -F '"path":"%s"' | grep -F '"roleid":"DatastoreReader"' | grep -F '"propagate":true' || true)`, path)
	line("held=")
	line(`case "$wider" in *'"ugid":"%s"'*) held='%s' ;; esac`, PBSUser, PBSUser)
	line(`case "$wider" in *'"ugid":"%s"'*) held="$held "'%s' ;; esac`, PBSTokenID, PBSTokenID)
	if capture {
		line(`[ -z "$held" ] || printf '{"wider_grant":"%%s"}\n' "$held" >&3`)
		return
	}
	line(`if [ -n "$held" ]; then`)
	line("  echo 'The PBS user can still read every namespace of the datastore %s: an earlier grant on %s stays, and this script removes none. To remove it, run:'", datastore, path)
	line("  for id in $held; do")
	line(`    echo "  proxmox-backup-manager acl update %s DatastoreReader --auth-id '$id' --delete true"`, path)
	line("  done")
	line("fi")
}

// WiderGrantHolders reads the {"wider_grant": ...} value the PBS part setup
// runs reports: the names, of the PBS user and its token, that still hold the
// grant on the whole datastore. Any other word is dropped.
func WiderGrantHolders(value string) []string {
	var held []string
	for _, id := range strings.Fields(value) {
		if (id == PBSUser || id == PBSTokenID) && !contains(held, id) {
			held = append(held, id)
		}
	}
	return held
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// PBSGrantRemovalCommands are the commands that remove the grant on the whole
// datastore from the PBS user or its token (held, as WiderGrantHolders reads
// it): the ones docs/manual-setup.md gives. Each removes DatastoreReader for
// one name on /datastore/<datastore> and nothing else.
func PBSGrantRemovalCommands(datastore string, held []string) ([]string, error) {
	if !validDatastore(datastore) {
		return nil, fmt.Errorf("invalid PBS datastore %q: use the datastore's ID as PBS shows it", datastore)
	}
	var commands []string
	for _, id := range WiderGrantHolders(strings.Join(held, " ")) {
		authID := id
		if strings.Contains(id, "!") {
			authID = "'" + id + "'"
		}
		commands = append(commands, fmt.Sprintf("proxmox-backup-manager acl update /datastore/%s DatastoreReader --auth-id %s --delete true", datastore, authID))
	}
	if len(commands) == 0 {
		return nil, errors.New("no grant of the PBS user or its token to remove")
	}
	return commands, nil
}

// PBSGrantRemovalScript is PBSGrantRemovalCommands as a script that setup runs
// on the PBS as root: it stops at its first error, and what the tool says goes
// to standard error.
func PBSGrantRemovalScript(datastore string, held []string) (string, error) {
	commands, err := PBSGrantRemovalCommands(datastore, held)
	if err != nil {
		return "", err
	}
	return "set -eu\n" + strings.Join(commands, " >&2\n") + " >&2\n", nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

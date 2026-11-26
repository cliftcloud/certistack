// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/nodecheck"
	"github.com/cliftcloud/certistack/internal/nodeidentity"
	"github.com/cliftcloud/certistack/internal/nodesetup"
	"github.com/cliftcloud/certistack/internal/support"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/sdn"
)

// The two things check asks of a node. They are variables so that a test gives
// the command a node without SSH.
var (
	// checkNodeMachine is the node's `uname -m`, asked once over the strict SSH
	// access a run uses.
	checkNodeMachine = func(ctx context.Context, cfg controller.SSHConfig) (string, error) {
		return controller.NewExecutor().NodeMachine(ctx, cfg)
	}
	// checkNodeName is the PVE name of the node the SSH access reaches, asked over
	// the same connection.
	checkNodeName = func(ctx context.Context, cfg controller.SSHConfig) (string, error) {
		return controller.NewExecutor().NodeName(ctx, cfg)
	}
	// checkOnNode has a temporary worker try the node's own layers and returns
	// its JSON report.
	// through, when set, has the worker stop after that layer.
	checkOnNode = func(ctx context.Context, opts controller.RunOptions, through string) ([]byte, error) {
		return controller.NewExecutor().Check(ctx, opts, through)
	}
)

// checkRequiredVariables are the variables layers 2 to 4 and 6 need, which a
// controller has before anything on the node exists: where the node is, and the
// PVE and PBS addresses and the PBS credential. Their names are checked and
// never their values. The PVE token is not among them: it can only be created
// after SSH works and the access script has run on the node, so layer 5 checks
// it, and a controller without one still learns about layers 1 to 4.
var checkRequiredVariables = []string{
	"PVE_URL", "PBS_REPOSITORY", "PBS_PASSWORD", "CERTISTACK_NODE", "CERTISTACK_SSH_HOST",
}

// checkTokenVariables are the PVE token's variables, checked by layer 5.
var checkTokenVariables = []string{"PVE_TOKEN_ID", "PVE_TOKEN_SECRET"}

// The numbered steps of docs/quickstart.md that check sends the reader to: "##
// 2. Run the setup" (certistack setup connects the controller to the node and
// writes the environment file) and "## 3. Write your first plan". A test reads
// the page's headings and compares what check says with them.
const (
	quickstartStepSetup     = 2
	quickstartStepFirstPlan = 3
)

// environmentFileMissingFix is what every command says to a reader whose
// environment file is not there: the first run has not happened, and
// certistack setup writes the file (check says the same at layer 1).
func environmentFileMissingFix() string {
	return "Run certistack setup (quickstart step " + strconv.Itoa(quickstartStepSetup) + "): it asks for a directory and writes controller.env there. Or write the file by hand " + setupByHandGuide + ": NAME=value lines, mode 0600. Every variable is listed at https://certistack.dev/docs/configuration/#variables."
}

// setupByHandGuide is where the fix for a missing environment file or SSH key
// sends the reader who does not run certistack setup: the section of
// docs/manual-setup.md that gives the same steps one command at a time. A
// test reads every section a message names (the heading must exist on the
// page).
const setupByHandGuide = "(https://certistack.dev/docs/manual-setup/#set-up-by-hand)"

// sudoersRuleGuide is where the fix for a non-root SSH account sends the
// reader: the subsection of docs/manual-setup.md that lists the commands the
// controller runs under sudo and gives the rule that allows them. A test reads
// every section a message names (the heading must exist on the page).
const sudoersRuleGuide = "(https://certistack.dev/docs/manual-setup/#the-sudoers-rule-for-a-non-root-account)"

// The layers, in the order they are tried.
const (
	layerEnvironment = "Environment file"
	layerSSHFiles    = "SSH files"
	layerSSH         = "SSH connection"
	layerTools       = "Node tools"
	layerPVE         = "PVE API"
	layerPBS         = "PBS"
	layerPlan        = "Plan"
	layerSandbox     = "Sandbox network"
)

// checkCmdWithCleanupContext is check; cleanupContext, when set, is canceled by
// the operator's second interrupt and abandons the removal of the temporary
// worker's workspace on the node.
func checkCmdWithCleanupContext(cleanupContext context.Context) *cobra.Command {
	var envFile string
	cmd := &cobra.Command{
		Use:   "check [--env-file FILE] [plan.yaml]",
		Short: "Check, layer by layer, that this controller is ready for certistack plan",
		Long: `Walks the layers between a fresh controller and "certistack plan", stops at
the first that fails and prints the command that fixes it:

  1. the environment file exists, is mode 0600, has the shape each value needs
     (every wrong one is listed at once, with its line and its fix) and sets
     the variables the first layers need (their names only, never their
     values): PVE_URL, PBS_REPOSITORY, PBS_PASSWORD, CERTISTACK_NODE and
     CERTISTACK_SSH_HOST;
  2. the SSH identity and known_hosts files exist, and known_hosts has an entry
     for the node (certistack setup trust-node);
  3. ssh connects non-interactively with strict host-key checking, the node
     reports a supported architecture, and it is the PVE node CERTISTACK_NODE
     names;
  4. the node has the tools a run needs: qemu-img, proxmox-backup-client,
     guestfish (libguestfs-tools), ip and nft (nftables; not asked of a plan
     that has no network probe), and proxmox-backup-client is a version this
     release supports. certistack setup installs what is missing
     after it shows what apt-get would install, upgrade and remove. By hand,
     on the node as root: apt update; apt install --no-upgrade libguestfs-tools
     nftables. Without a Proxmox subscription apt update prints 401
     Unauthorized for enterprise.proxmox.com and ends with an error; that is
     expected, and the package lists it could fetch are still updated;
  5. PVE_TOKEN_ID and PVE_TOKEN_SECRET are set (if not, the fix is the access
     script from certistack setup rbac), the node can reach the PVE API and
     PVE accepts the token (a certificate the node does not trust is fixed by
     certistack setup pve-ca), the Proxmox VE release is one this release
     supports, and PVE has the SDN API a run builds its sandbox network with;
  6. the PBS credential can list the repository (and PBS_NAMESPACE, if set);
  7. with a plan file, that the file exists;
  8. with a plan file, the node judges the plan's sandbox network: the range
     must hold neither the PVE API nor the PBS server and must overlap none of
     the node's own routes or addresses (a plan that does not validate fails
     here, and certistack validate says why); routes the node cannot read are
     reported as not checked, never as passed.

It ends with the next command: certistack plan when you gave a plan; without
one, certistack init to write a first plan, or certistack check with a plan you
have.

Layers 4 to 6 and 8 run on the node, as plan does: a temporary worker is staged
and removed again, and nothing else is changed. They use the credentials in the
environment file and the CA file a run would use.

Without --env-file it checks the file certistack setup recorded, unless PVE_URL
is set in the environment.

It exits 0 only when every layer passes.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Context() == nil {
				cmd.SetContext(context.Background())
			}
			planPath := ""
			if len(args) > 0 {
				planPath = args[0]
			}
			out := newCheckedOutput(cmd.OutOrStdout())
			return out.deliver(runCheck(cmd, out, envFile, planPath, cleanupContext))
		},
	}
	cmd.Flags().StringVar(&envFile, "env-file", "", "allowlisted controller environment file (mode 0600); values are parsed literally, never shell-sourced (default: the file certistack setup recorded)")
	return cmd
}

// checkReport prints the layers as they are decided and, after the first
// failure, lists the rest as not checked.
type checkReport struct {
	w      io.Writer
	titles []string
	done   int
	failed int // 1-based number of the failed layer; 0 while all pass
}

func (r *checkReport) line(icon, title, detail string) {
	r.done++
	lines := strings.Split(strings.TrimRight(detail, "\n"), "\n")
	fmt.Fprintf(r.w, "  %s %d. %-17s %s\n", icon, r.done, title, lines[0])
	for _, extra := range lines[1:] {
		fmt.Fprintf(r.w, "       %s\n", extra)
	}
}

func (r *checkReport) pass(title, detail string) { r.line("✓", title, detail) }

// warn reports a layer that could not be made: neither passed nor failed.
func (r *checkReport) warn(title, detail string) { r.line("!", title, detail) }

// fail reports the layer that failed with the fix for it, and the layers after
// it as not checked. It returns the command's error.
func (r *checkReport) fail(title, detail, fix string) error {
	r.line("✗", title, detail)
	r.failed = r.done
	if fix != "" {
		fixLines := strings.Split(strings.TrimRight(fix, "\n"), "\n")
		fmt.Fprintf(r.w, "       Fix: %s\n", fixLines[0])
		for _, extra := range fixLines[1:] {
			fmt.Fprintf(r.w, "            %s\n", extra)
		}
	}
	for _, later := range r.titles[r.done:] {
		r.done++
		fmt.Fprintf(r.w, "  - %d. %-17s not checked: an earlier layer failed\n", r.done, later)
	}
	fmt.Fprintf(r.w, "\n✗ Not ready: fix layer %d (%s) above, then run certistack check again.\n", r.failed, title)
	return withExitCode(fmt.Errorf("check failed at layer %d (%s)", r.failed, title), exitCodeInfrastructure)
}

// runCheck is check. envFile is its --env-file, "" for none: then it checks
// the file certistack setup recorded (resolveControllerEnvFile).
func runCheck(cmd *cobra.Command, w io.Writer, envFile, planPath string, cleanupContext context.Context) error {
	ctx := cmd.Context()
	chosenEnv, err := resolveControllerEnvFile(envFile)
	if err != nil {
		return err
	}
	if chosenEnv.path == "" {
		return errEnvFileRequired
	}
	envFile = chosenEnv.path
	envPath, err := filepath.Abs(envFile)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", envFile, err)
	}
	// How the commands check prints name the file: not at all when it is the
	// default. Decided now, before the file sets PVE_URL.
	withEnv := chosenEnv.flag(envPath)
	titles := []string{layerEnvironment, layerSSHFiles, layerSSH, layerTools, layerPVE, layerPBS}
	workerLayers := "Layers 4 to 6"
	if planPath != "" {
		titles = append(titles, layerPlan, layerSandbox)
		workerLayers = "Layers 4 to 6 and 8"
	}
	report := &checkReport{w: w, titles: titles}
	unchecked := "" // the layer that could not be made, if one could not
	fmt.Fprintf(w, "CertiStack check: is this controller ready for certistack plan?\nThe layers run in order and it stops at the first that fails. %s use a temporary worker on the node, removed afterwards.\n\n", workerLayers)

	// 1. The environment file.
	detail, fix, restore := checkEnvironmentFile(envPath)
	if restore != nil {
		defer restore()
	}
	if fix != "" {
		return report.fail(layerEnvironment, detail, fix)
	}
	report.pass(layerEnvironment, detail)

	cfg, err := controllerSSHFromEnvironment(cmd)
	if err != nil {
		return report.fail(layerSSHFiles, err.Error(), "Fix the SSH variables in "+envPath+".")
	}

	// 2. The SSH files.
	detail, fix = checkSSHFiles(cfg)
	if fix != "" {
		return report.fail(layerSSHFiles, detail, fix)
	}
	report.pass(layerSSHFiles, detail)

	// 3. The SSH connection.
	machine, err := checkNodeMachine(ctx, cfg)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return report.fail(layerSSH, "ssh to "+sshTarget(cfg)+" did not work:\n"+clip(err.Error()), sshFix(err, cfg))
	}
	if err := controller.CheckArchitecture(cfg, machine); err != nil {
		return report.fail(layerSSH, err.Error(), "Run the controller build that matches the node's architecture: certistack-linux-amd64, or the controller container image, for an x86_64 Proxmox VE node.")
	}
	// The node ssh reaches must be the node CERTISTACK_NODE names: the worker
	// runs on the one and addresses PVE as the other.
	nodeName, err := checkNodeName(ctx, cfg)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return report.fail(layerSSH, "ssh to "+sshTarget(cfg)+" works, but it could not check which PVE node this is:\n"+clip(err.Error()),
			"The node's name is the target of /etc/pve/local, which exists once the PVE cluster file system runs (systemctl status pve-cluster on the node), or else the host name. Check that /usr/bin/readlink and /usr/bin/hostname exist on the node and that the SSH account can run them.")
	}
	if err := nodeidentity.Compare(nodeName, os.Getenv("CERTISTACK_NODE")); err != nil {
		var mismatch *nodeidentity.MismatchError
		if errors.As(err, &mismatch) {
			return report.fail(layerSSH, "ssh to "+sshTarget(cfg)+" works and reaches "+mismatch.Reached(), mismatch.Fix(envPath))
		}
		return report.fail(layerSSH, err.Error(), "")
	}
	report.pass(layerSSH, fmt.Sprintf("ssh to %s works without a prompt, with strict host-key checking; the node reports %s", sshTarget(cfg), machine))

	// The plan's sandbox network, for the node to judge as the last layer. A plan
	// that does not validate has none to judge: layer 8 says why. A plan file
	// that cannot be read at all is layer 7's.
	var sandbox *config.Network
	var planProblem error
	noWireProbes := false // only a plan that validates and has none says so
	if planPath != "" {
		if info, statErr := os.Stat(planPath); statErr == nil && !info.IsDir() {
			if plan, loadErr := config.LoadFromFileForWorker(planPath); loadErr != nil {
				planProblem = loadErr
			} else {
				network := plan.Network
				sandbox = &network
				noWireProbes = !plan.HasWireProbes()
			}
		}
	}

	// 4 to 6. The node's own layers. Without a PVE token the worker is still
	// staged, so the tools are checked, but it stops after them and PVE is never
	// asked: staging needs the two variables set, so they hold a marker that is
	// not a credential, and the environment is restored when the command ends.
	missingToken := missingVariables(checkTokenVariables)
	through := ""
	if len(missingToken) > 0 {
		through = nodecheck.LayerTools
		for _, name := range missingToken {
			_ = os.Setenv(name, "not-set-"+strings.ToLower(name))
		}
	}
	noteWorkerStaged()
	raw, err := checkOnNode(ctx, controller.RunOptions{
		NodeName:   os.Getenv("CERTISTACK_NODE"),
		StateDir:   os.Getenv("CERTISTACK_STATE_DIR"),
		ScratchDir: os.Getenv("CERTISTACK_SCRATCH_DIR"),
		SSH:        cfg,
		Writer:     io.Discard,
		Sandbox:    sandbox,
		// nft is required unless the plan has no wire probe.
		NoWireProbes: noWireProbes,
		// The operator's second interrupt abandons the removal of the
		// workspace.
		CleanupContext: cleanupContext,
	}, through)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		detail, fix := stagingFailure(err, envPath, withEnv)
		return report.fail(layerTools, detail, fix)
	}
	var nodeReport nodecheck.Report
	if err := json.Unmarshal(raw, &nodeReport); err != nil {
		return report.fail(layerTools, "the node's worker returned a report this controller cannot read: "+err.Error(), "Use the same certistack build on the controller and the node; this build stages itself as the worker, so a mismatch means the staged copy is not this one.")
	}
	rows := map[string]string{nodecheck.LayerTools: layerTools, nodecheck.LayerPVE: layerPVE, nodecheck.LayerPBS: layerPBS}
	for _, name := range []string{nodecheck.LayerTools, nodecheck.LayerPVE, nodecheck.LayerPBS} {
		if name == nodecheck.LayerPVE && len(missingToken) > 0 {
			return report.fail(layerPVE, strings.Join(missingToken, " and ")+" "+verbAre(missingToken)+" not set in "+envPath+", so there is no token to offer PVE", missingTokenFix(envPath))
		}
		layer, ok := findLayer(nodeReport, name)
		if !ok {
			return report.fail(rows[name], "the node's worker did not report this layer", "Run certistack check again; if it persists, run with --debug and report it.")
		}
		if layer.Status != nodecheck.StatusPassed {
			return report.fail(rows[name], layer.Detail, nodeLayerFix(layer, envPath, withEnv))
		}
		report.pass(rows[name], layer.Detail)
	}

	// 7. The plan.
	if planPath != "" {
		if info, err := os.Stat(planPath); err != nil || info.IsDir() {
			return report.fail(layerPlan, "the plan file "+planPath+" cannot be read", "Give the path of the plan YAML, or write one with certistack init"+withEnv+" (quickstart step "+strconv.Itoa(quickstartStepFirstPlan)+").")
		}
		report.pass(layerPlan, "the plan file exists")

		// 8. The plan's sandbox network, judged by the node.
		if planProblem != nil {
			return report.fail(layerSandbox, "the plan does not validate, so its sandbox network cannot be checked:\n"+clip(planProblem.Error()), "Run certistack validate "+planPath+", which lists every problem in the plan, and fix them.")
		}
		layer, ok := findLayer(nodeReport, nodecheck.LayerSandbox)
		switch {
		case !ok:
			return report.fail(layerSandbox, "the node's worker did not report this layer", "Run certistack check again; if it persists, run with --debug and report it.")
		case layer.Status == nodecheck.StatusFailed:
			return report.fail(layerSandbox, layer.Detail, sandboxLayerFix(layer, planPath))
		case layer.Status == nodecheck.StatusUnchecked:
			report.warn(layerSandbox, layer.Detail)
			unchecked = layerSandbox
		default:
			report.pass(layerSandbox, layer.Detail)
		}
	}

	if unchecked != "" {
		fmt.Fprintf(w, "\n✓ Every layer passed, but layer %d (%s) could not be checked: read its message above and do by hand what it says.\n", report.done, unchecked)
	} else {
		fmt.Fprintf(w, "\n✓ Every layer passed.\n")
	}
	if planPath != "" {
		fmt.Fprintf(w, "Now run: certistack plan %s%s\n", planPath, withEnv)
	} else {
		// With no plan to judge, the next step is a first plan, or checking one
		// that exists.
		fmt.Fprintf(w, "Next: write a first plan with certistack init%s (quickstart step %d), or check one you have: certistack check%s <plan.yaml>\n", withEnv, quickstartStepFirstPlan, withEnv)
	}
	return nil
}

// checkEnvironmentFile is layer 1. It returns the detail to print and, when the
// layer failed, the fix; and the function that undoes the environment it applied.
func checkEnvironmentFile(envPath string) (detail, fix string, restore func()) {
	info, err := os.Stat(envPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return envPath + " does not exist" + missingDirectoryNote(envPath, err), environmentFileMissingFix(), nil
	case err != nil:
		return err.Error(), "Make the file readable by the user running certistack.", nil
	case !info.Mode().IsRegular():
		return envPath + " is not a regular file", "Point --env-file at the environment file itself.", nil
	case runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0:
		return fmt.Sprintf("%s has mode %04o, so other users can read the secrets in it", envPath, info.Mode().Perm()), "chmod 600 " + envPath, nil
	}
	restore, file, err := useCommandEnvironmentFile(envPath, false)
	if err != nil {
		// Every value that has the wrong shape, each with its line and its fix.
		var shapes *environmentShapeError
		if errors.As(err, &shapes) {
			detail, fix := shapes.layerDetail(envPath)
			return detail, fix, nil
		}
		return err.Error(), "Correct the line the message names. The variables an environment file may hold are listed at https://certistack.dev/docs/configuration/#variables.", nil
	}
	missing := missingVariables(checkRequiredVariables)
	if len(missing) > 0 {
		// A variable that is in the file with nothing after the "=" is said so:
		// adding it again would make a duplicate.
		named := make([]string, len(missing))
		emptyOnes := false
		for i, name := range missing {
			named[i] = name
			if line, present := file.lines[name]; present {
				named[i] = fmt.Sprintf("%s (line %d has no value)", name, line)
				emptyOnes = true
			}
		}
		fix = "Add " + strings.Join(missing, ", ") + " to " + envPath + " as NAME=value lines " + setupByHandGuide + ", or run certistack setup (quickstart step " + strconv.Itoa(quickstartStepSetup) + ") to write the file."
		if emptyOnes {
			fix += " A variable that is already in the file with nothing after the = needs its value written there, not a second line."
		}
		return "required variable(s) not set: " + strings.Join(named, ", "), fix + " Values are never printed here.", restore
	}
	mode := ""
	if runtime.GOOS != "windows" {
		mode = fmt.Sprintf(", mode %04o", info.Mode().Perm())
	}
	detail = fmt.Sprintf("%s%s, the %d required variables are set", envPath, mode, len(checkRequiredVariables))
	for _, note := range file.notes {
		detail += "\n" + note
	}
	return detail, "", restore
}

// checkSSHFiles is layer 2: the identity and the known_hosts file are there and
// the node's host key is recorded.
func checkSSHFiles(cfg controller.SSHConfig) (detail, fix string) {
	notes := ""
	if cfg.IdentityFile == "" {
		notes = "\nCERTISTACK_SSH_IDENTITY is not set: ssh offers only the keys your ssh configuration names for this host."
	} else {
		info, err := os.Stat(cfg.IdentityFile)
		switch {
		case err != nil:
			return "the SSH identity " + cfg.IdentityFile + " cannot be read: " + errorReason(err), "Run certistack setup (quickstart step " + strconv.Itoa(quickstartStepSetup) + "): it creates the key and has the node authorize it. By hand, create the key pair: ssh-keygen -t ed25519 -N '' -C certistack-controller -f " + cfg.IdentityFile + "\nThen authorize " + cfg.IdentityFile + ".pub on the node " + setupByHandGuide + "."
		case info.IsDir():
			return "the SSH identity " + cfg.IdentityFile + " is a directory", "Point CERTISTACK_SSH_IDENTITY at the private key file."
		case !info.Mode().IsRegular():
			return "the SSH identity " + cfg.IdentityFile + " is not a regular file but " + sysutil.FileKind(info.Mode()) + ", which ssh would wait on", "Point CERTISTACK_SSH_IDENTITY at the private key file."
		case runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0:
			return fmt.Sprintf("the SSH identity %s has mode %04o, so ssh will refuse it", cfg.IdentityFile, info.Mode().Perm()), "chmod 600 " + cfg.IdentityFile
		}
		if detail, fix := untrustedSSHFile(cfg.IdentityFile, info, sysutil.IdentityWhat, sysutil.IdentityRisk); detail != "" {
			return detail, fix
		}
	}
	info, err := os.Stat(cfg.KnownHostsFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "there is no known_hosts file at " + cfg.KnownHostsFile + ", so the node's host key is not recorded", "Record it after comparing the fingerprint with the node's: " + trustNodeCommand(cfg)
	case err != nil:
		return "the known_hosts file " + cfg.KnownHostsFile + " cannot be read: " + errorReason(err), "Make it readable by the user running certistack."
	case info.IsDir():
		return "the known_hosts path " + cfg.KnownHostsFile + " is a directory", "Point CERTISTACK_SSH_KNOWN_HOSTS at a file."
	case !info.Mode().IsRegular():
		return "the known_hosts path " + cfg.KnownHostsFile + " is not a regular file but " + sysutil.FileKind(info.Mode()) + ", which reading would wait on", "Point CERTISTACK_SSH_KNOWN_HOSTS at a file."
	}
	if detail, fix := untrustedSSHFile(cfg.KnownHostsFile, info, sysutil.KnownHostsWhat, sysutil.KnownHostsRisk); detail != "" {
		return detail, fix
	}
	if err := controller.ValidateSSH(cfg); err != nil {
		return err.Error(), "Correct the SSH settings in the environment file."
	}
	known, err := nodesetup.HasHostEntry(cfg.KnownHostsFile, cfg.Host, cfg.Port)
	if err != nil {
		return err.Error(), "Fix the file, or point CERTISTACK_SSH_KNOWN_HOSTS at another."
	}
	if !known {
		return cfg.KnownHostsFile + " has no entry for " + nodesetup.KnownHostsName(strings.ToLower(strings.Trim(cfg.Host, "[]")), cfg.Port) + ", and strict host-key checking is always on", "Record the node's host key after you have compared its fingerprint with the node's: " + trustNodeCommand(cfg)
	}
	return fmt.Sprintf("identity %s; %s has an entry for %s%s", valueOr(cfg.IdentityFile, "(none set)"), cfg.KnownHostsFile, nodesetup.KnownHostsName(strings.ToLower(strings.Trim(cfg.Host, "[]")), cfg.Port), notes), ""
}

// untrustedSSHFile is layer 2's detail and fix for an SSH file someone other
// than the user, or root, could change (sysutil.UnsafeToTrust), or "".
func untrustedSSHFile(path string, info os.FileInfo, what, risk string) (detail, fix string) {
	err := sysutil.UnsafeToTrust(path, info, what, risk)
	var untrusted *sysutil.UntrustedFileError
	if !errors.As(err, &untrusted) {
		return "", ""
	}
	return untrusted.Problem, strings.ToUpper(untrusted.Fix[:1]) + untrusted.Fix[1:] + "."
}

func sshTarget(cfg controller.SSHConfig) string {
	port := cfg.Port
	if port == 0 {
		port = 22
	}
	target := cfg.User + "@" + cfg.Host
	if port != 22 {
		target += ":" + fmt.Sprint(port)
	}
	return target
}

// sshFix is the fix for a failed SSH connection: the hint for what OpenSSH said,
// or the command to run by hand to read its message.
func sshFix(err error, cfg controller.SSHConfig) string {
	if hint := sshFailureHint(err, cfg); hint != "" {
		return hint
	}
	args := []string{"ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + cfg.KnownHostsFile, "-o", "IdentitiesOnly=yes"}
	if cfg.Port != 0 && cfg.Port != 22 {
		args = append(args, "-p", fmt.Sprint(cfg.Port))
	}
	if cfg.IdentityFile != "" {
		args = append(args, "-i", cfg.IdentityFile)
	}
	args = append(args, cfg.User+"@"+cfg.Host, "uname", "-m")
	return "Run the connection by hand to read ssh's own message: " + strings.Join(args, " ")
}

// stagingFailure explains a check worker that could not be staged on the node:
// nothing of the node's own layers was reached. withEnv is how a command it
// prints names the environment file (controllerEnvFile.flag).
func stagingFailure(err error, envPath, withEnv string) (detail, fix string) {
	text := err.Error()
	detail = "the controller could not put its temporary worker on the node, which layers 4 to 6 need:\n" + clip(text)
	switch {
	case strings.Contains(text, "stage PVE CA file"):
		lead := "CERTISTACK_PVE_CA_SOURCE names a file this controller cannot read as a CA. "
		if dir := filepath.Dir(envPath); !directoryWritable(dir) {
			return detail, lead + fetchPVECAOnTheHost(dir)
		}
		return detail, lead + "Fetch it again: certistack setup pve-ca" + withEnv
	case strings.Contains(text, "stage PBS encryption key"):
		return detail, "Fix CERTISTACK_PBS_KEYFILE (and PBS_ENCRYPTION_PASSWORD, if the key has a passphrase) in " + envPath + "."
	case strings.Contains(text, "Permission denied"), strings.Contains(text, "a password is required"):
		return detail, "The SSH account is not root and cannot use passwordless sudo on the node. Use root (CERTISTACK_SSH_USER=root), or an account with passwordless sudo and CERTISTACK_SSH_SUDO=true " + sudoersRuleGuide + "."
	case strings.Contains(text, "architecture"):
		return detail, "Run the controller build that matches the node's architecture."
	}
	return detail, "Run certistack check --debug" + withEnv + " to see every step, and read the message above."
}

func findLayer(report nodecheck.Report, name string) (nodecheck.Layer, bool) {
	for _, layer := range report.Layers {
		if layer.Name == name {
			return layer, true
		}
	}
	return nodecheck.Layer{}, false
}

// directoryWritable reports whether this process can create a file in dir. It
// creates one and removes it again, the only test that agrees with what
// certistack setup pve-ca finds when it writes the CA there: a read-only mount,
// a directory owned by another user and a full disk all answer no.
func directoryWritable(dir string) bool {
	probe, err := os.CreateTemp(dir, ".certistack-write-check.*")
	if err != nil {
		return false
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return true
}

// fetchPVECAOnTheHost is the fix for a PVE CA that has to be fetched when
// certistack setup pve-ca cannot write it where it writes it, dir. That is the
// case in the controller container, whose secrets directory is mounted
// read-only (deploy/controller/README.md): the CA is fetched or copied on the
// host and installed into the directory the container mounts.
func fetchPVECAOnTheHost(dir string) string {
	return "This process cannot write to " + dir + ", so certistack setup pve-ca cannot put the CA there (in the controller container it is the read-only secrets mount). " +
		"Get the CA on the host instead: run certistack setup pve-ca on a host where the SSH paths of the environment file exist, or copy /etc/pve/pve-root-ca.pem from the node. " +
		"Then install it as the file CERTISTACK_PVE_CA_SOURCE names in controller.env (uncomment that line if it is commented out):\n" +
		"sudo install -m 0600 -o 65532 -g 65532 pve-root-ca.pem deploy/controller/secrets/pve-ca.pem\n" +
		pveCAContainerGuide
}

// pveCAContainerGuide names where the container's secrets are installed, as the
// README of the controller container gives it. The appliance mounts its own
// directory at the same path in the container.
const pveCAContainerGuide = "(https://github.com/cliftcloud/certistack/blob/main/deploy/controller/README.md#prepare-controller-secrets; the appliance keeps those files in /etc/certistack/secrets.)"

// aptUpdateNote is what a fix that starts with apt update adds: on a node
// without a subscription it ends with an error that does no harm.
const aptUpdateNote = "Without a Proxmox subscription apt update prints 401 Unauthorized for enterprise.proxmox.com and ends with an error; that is expected, and the package lists it could fetch are still updated."

// nodeLayerFix is the fix for a layer the node reported as failed. withEnv is
// how a command it prints names the environment file (controllerEnvFile.flag).
func nodeLayerFix(layer nodecheck.Layer, envPath, withEnv string) string {
	switch layer.Code {
	case nodecheck.CodeToolsMissing:
		return toolsFix(layer.Missing, envPath)
	case nodecheck.CodeClientUnsupported:
		return fmt.Sprintf("Update proxmox-backup-client on the node to version %d or later. On the node as root: apt update; apt install proxmox-backup-client (apt lists what it would do and asks). PVE 8.1 and later ship a client this release supports.\n%s", support.MinPBSMajor, aptUpdateNote)
	case nodecheck.CodePVEUnsupported:
		return fmt.Sprintf("Update the node to Proxmox VE %d.%d or later; the versions this release supports are listed at https://certistack.dev/docs/compatibility/#supported-versions", support.MinPVEMajor, support.MinPVEMinor)
	case nodecheck.CodePVESDNMissing:
		return "A run builds its sandbox network with PVE's SDN, which this node lacks: " + sdn.MissingFix + ". On the node as root: apt update; apt install libpve-network-perl ifupdown2 (apt lists what it would do and asks).\n" + aptUpdateNote
	case nodecheck.CodePVECAUntrusted:
		if source := os.Getenv("CERTISTACK_PVE_CA_SOURCE"); source != "" {
			lead := "CERTISTACK_PVE_CA_SOURCE is set (" + source + "), but the PVE certificate was not signed by a CA in that file. "
			// --out writes the file itself, so its directory is the one that must be writable.
			if dir := filepath.Dir(source); !directoryWritable(dir) {
				return lead + fetchPVECAOnTheHost(dir)
			}
			return lead + "Fetch the node's current CA into it:\ncertistack setup pve-ca" + withEnv + " --out " + source
		}
		lead := "A stock Proxmox VE node signs its API certificate with the cluster's own CA, which no trust store holds. "
		if dir := filepath.Dir(envPath); !directoryWritable(dir) {
			return lead + fetchPVECAOnTheHost(dir)
		}
		return lead + "Fetch it over your pinned SSH access:\ncertistack setup pve-ca" + withEnv + "\nand add the CERTISTACK_PVE_CA_SOURCE line it prints to " + envPath + "."
	case nodecheck.CodePVECertName:
		return "Put in PVE_URL the host name or address the PVE certificate is issued for (the node's own name or IP), not an alias or a load balancer's name."
	case nodecheck.CodePVECertInvalid:
		return "On the node run pvecm updatecerts --force, and check that the node's clock and this controller's are right."
	case nodecheck.CodePVEAuth:
		return "Check PVE_TOKEN_ID (user@realm!tokenname) and PVE_TOKEN_SECRET in " + envPath + ". The token secret is shown only once, when the token is created; certistack setup rbac --node <node> --overlay-storage <storage> prints the commands that create the user and token."
	case nodecheck.CodePVEForbidden:
		return "Check that the token's user exists and is enabled and that the token has not expired (Datacenter, Permissions, API Tokens)."
	case nodecheck.CodePVEUnreachable:
		return "The node, not this controller, calls the PVE API: PVE_URL must resolve and answer from the node. Check the host name and port 8006 from the node itself (curl -k " + "https://<host>:8006/)."
	case nodecheck.CodePVEConfig:
		return "Correct what the message names: PVE_URL (https, with no path), CERTISTACK_PVE_CA_SOURCE (a PEM file) or PVE_TLS_INSECURE."
	case nodecheck.CodePBSFailed:
		fix := "The PBS client's own output is withheld, because it can carry credentials. The usual causes: a wrong PBS_PASSWORD or PBS_REPOSITORY, or a self-signed PBS certificate without PBS_FINGERPRINT (PBS dashboard, Show Fingerprint). To read the client's message, run on the node with the same password:\nproxmox-backup-client snapshot list --repository '<your PBS_REPOSITORY>'"
		if os.Getenv("PBS_NAMESPACE") != "" {
			fix += "\nPBS_NAMESPACE is set: the PBS identity must be allowed to read that namespace (certistack setup rbac --pbs-datastore <datastore> --pbs-namespace <namespace> prints the grant)."
		}
		return fix
	}
	return ""
}

// sandboxLayerFix is the fix for a sandbox network the node refused.
func sandboxLayerFix(layer nodecheck.Layer, planPath string) string {
	fix := "Change network.ip_range (and network.probe_ip, which must lie inside it) in " + planPath + ". Use a range your node does not use: the examples use 192.0.2.0/24, and `ip -4 route` on the node lists the networks it does use."
	if layer.Code == nodecheck.CodeSandboxRange {
		fix += "\nThe PVE API (PVE_URL) and the PBS server (PBS_REPOSITORY) must not be inside the range."
	}
	return fix
}

// toolsFix is the fix for the tools the node lacks: certistack setup, which
// previews what apt-get would install, upgrade and remove and asks, and the
// apt command by hand, which asks too (no -y). The packages are the
// controller's own, found by the tool's name in nodecheck.Tools: the node's
// report is parsed JSON from a machine, and a package name it sent would
// otherwise be put in a root command for an operator to paste. A tool the
// controller does not know is not named in the command.
func toolsFix(missing []nodecheck.Tool, envPath string) string {
	known := map[string]string{}
	for _, tool := range nodecheck.Tools {
		known[tool.Name] = tool.Package
	}
	seen := map[string]bool{}
	var packages []string
	proxmoxClient, nft := false, false
	for _, tool := range missing {
		pkg, ok := known[tool.Name]
		if !ok {
			continue
		}
		if tool.Name == "proxmox-backup-client" {
			proxmoxClient = true
		}
		if tool.Name == "nft" {
			nft = true
		}
		if !seen[pkg] {
			seen[pkg] = true
			packages = append(packages, pkg)
		}
	}
	if len(packages) == 0 {
		return "The node reported a missing tool that this version of certistack does not know, so it cannot name the package. certistack doctor on the node lists every tool a run needs."
	}
	sort.Strings(packages)
	// setup run again reads the earlier controller.env for its defaults: --dir
	// names the directory when the file is the one setup writes.
	setup := "certistack setup"
	if filepath.Base(envPath) == "controller.env" {
		setup += " --dir " + quoteForShell(filepath.Dir(envPath))
	}
	// apt update first: a stock node has no package lists. It ends with an error
	// on a node without a subscription (401 from the enterprise repositories), which
	// is why the two commands are joined by a semicolon, not by &&.
	fix := "Run " + setup + ": it shows what apt-get would install, upgrade and remove on the node, and asks before it installs." +
		"\nBy hand, on the node as root: apt update; apt install --no-upgrade " + strings.Join(packages, " ") + " (apt lists what it would do and asks)." +
		"\n" + aptUpdateNote
	if proxmoxClient {
		fix += "\nproxmox-backup-client comes from the Proxmox repositories (a Proxmox VE node has them configured)."
	}
	if nft {
		fix += "\nnft contains the sandbox probe address of a plan with network probes. certistack doctor on the node lists every tool a run needs."
	}
	return fix
}

// errorReason is err without the operation and path os added.
func errorReason(err error) string {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}

// clip bounds a multi-line message to what fits a terminal screen.
func clip(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > 8 {
		lines = append(lines[:8], "...")
	}
	return strings.Join(lines, "\n")
}

// missingVariables are the names, of those given, that are not set.
func missingVariables(names []string) []string {
	var missing []string
	for _, name := range names {
		if os.Getenv(name) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

func verbAre(names []string) string {
	if len(names) == 1 {
		return "is"
	}
	return "are"
}

// safeWord is a value that may be put into a command line shown to the
// operator as it is: no space, quote or shell character in it.
var safeWord = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

func wordOr(value, placeholder string) string {
	if safeWord.MatchString(value) {
		return value
	}
	return placeholder
}

// repositoryDatastore is the datastore at the end of a PBS repository
// ([user@realm!token@]host[:port]:datastore), or "" when it has none.
func repositoryDatastore(repository string) string {
	if i := strings.LastIndex(repository, ":"); i >= 0 {
		return repository[i+1:]
	}
	return ""
}

// missingTokenFix is the fix for a PVE token that is not in the environment
// file: the access script that creates it, filled in with what the file knows.
func missingTokenFix(envPath string) string {
	return "The PVE token does not exist yet, or is not in the environment file. Create it with the access script:\n" +
		"certistack setup rbac --node " + wordOr(os.Getenv("CERTISTACK_NODE"), "<node>") +
		" --overlay-storage " + wordOr(os.Getenv("CERTISTACK_OVERLAY_STORAGE"), "<storage>") +
		" --pbs-datastore " + wordOr(repositoryDatastore(os.Getenv("PBS_REPOSITORY")), "<ds>") + " > certistack-access.sh\n" +
		"Read the script, run PART 1 as root on the PVE node (it prints the token secret once), then put PVE_TOKEN_ID and PVE_TOKEN_SECRET in " + envPath + "."
}

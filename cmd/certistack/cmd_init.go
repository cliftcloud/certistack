// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/runner"
	"github.com/cliftcloud/certistack/pkg/runphase"
)

const defaultInitOutput = "certistack-plan.yaml"

// runnerDiscover reads what init needs on this node. It is a variable so that
// a test can tell what init and node-discover hand to it and give
// the listing and the plan a node to read without PBS and PVE.
var runnerDiscover = runner.Discover

// initClock is when init writes a plan, for its header; a variable so that a
// test's plan is the same on every run.
var initClock = time.Now

// remoteDiscover reads the same from a node through a temporary worker the
// controller stages there; a variable for the same reason.
var remoteDiscover = func(ctx context.Context, opts controller.RunOptions, req initplan.Request) ([]byte, error) {
	return controller.NewExecutor().Discover(ctx, opts, req)
}

func initCmd() *cobra.Command {
	return initCmdWithCleanupContext(nil)
}

// initCmdWithCleanupContext is init; cleanupContext, when set, is cancelled
// by a second interrupt, which abandons the cleanup of an inspection on a
// node as it abandons a run's.
func initCmdWithCleanupContext(cleanupContext context.Context) *cobra.Command {
	var (
		inspect        bool
		vmids          []int
		all            bool
		output         string
		force          bool
		planID         string
		planName       string
		overlayStorage string
		namespace      string
		firstVMID      int
		envFile        string
		nodeName       string
		scratchDir     string
		stateDir       string
		sshHost        string
		sshUser        string
		sshPort        int
		sshIdentity    string
		sshKnownHosts  string
		sshSudo        bool
		unusedOutput   string
		yes            bool
	)
	cmd := &cobra.Command{
		Use:   "init [--vm ID]... | --all",
		Short: "Write a first plan from the VMs that have PBS backups",
		Long: `Reads, without changing anything, what a first plan needs: the VMs with
complete PBS backups, what each VM's newest backup says about its guest
(OS, firmware, guest agent, NIC, disks), the node's storages for overlays,
and sandbox VM IDs and SDN IDs that are free. It writes a commented plan
with a first probe for each VM chosen from its backup:
  - a Linux VM with a NIC: SSH on the address the sandbox gives it;
  - a Windows VM with the guest agent: its Event Log service, through the
    agent;
  - another guest with the agent: the agent answering.
A guest without the agent, and without a Linux NIC the sandbox can give an
address, is left out with the reason: the only check left would be that
QEMU runs the VM, which says nothing about the guest.
The plan is valid as written: compliance.frameworks is [NONE], the label for no
standard, which you replace only to name one. Change the probes to the service
each VM exists for (the plan marks them CHANGE), then "certistack plan" the file
before the first run.

With --inspect, init also looks inside the newest backup of each Linux VM
it gives a sandbox address, one VM at a time: it maps the backup read-only
on the node, as a run does, reads the guest's os-release, the systemd units
it enables and the listen settings of nginx, Apache, PostgreSQL,
MariaDB/MySQL, Redis and sshd, releases the map, and writes a probe for each
service found (at most six per VM), with the evidence in a comment. A VM it
finds nothing to probe on, or cannot inspect, keeps the SSH probe, and the
plan says why.

With --vm or --all it prints, before it writes the plan, what a run of it
reads and holds: the disks it reads in full, about how long that takes and the
RAM it reserves. At a terminal it asks first when you gave --all or the disks
come to more than 500 GiB (--yes skips the question; without a terminal it
asks nothing).

Without --vm or --all, it lists the VMs that have backups.

With an SSH host (--ssh-host or CERTISTACK_SSH_HOST), it reads from the
controller as "run" does, through a temporary worker on the node. Without
one, it reads on the node itself, as root.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if envFile != "" {
				restoreEnvironment, err := useCommandEnvironment(envFile, false)
				if err != nil {
					return err
				}
				defer restoreEnvironment()
			}
			if err := applyControllerEnvironmentDefaults(cmd, &nodeName, &scratchDir, &unusedOutput, &stateDir, &sshHost, &sshUser, &sshPort, &sshIdentity, &sshKnownHosts, &sshSudo); err != nil {
				return err
			}
			if !cmd.Flags().Changed("overlay-storage") {
				overlayStorage = os.Getenv("CERTISTACK_OVERLAY_STORAGE")
			}
			if !cmd.Flags().Changed("namespace") {
				namespace = os.Getenv("PBS_NAMESPACE")
			}
			// Without an SSH host init works on the node itself: on any other
			// host it stops here, before it reads anything.
			if sshHost == "" {
				if err := requirePVENodeWithoutSSHHost(envFile); err != nil {
					return err
				}
			}
			if nodeName == "" && sshHost == "" {
				nodeName = localNodeName()
			}
			if nodeName == "" {
				return errors.New("--node is required")
			}
			// On the node itself, the name must be the node's own. Through an SSH
			// host the temporary worker checks it on the node, first thing.
			if sshHost == "" {
				if err := verifyNodeIdentity(nodeName); err != nil {
					return err
				}
			}
			listing := len(vmids) == 0 && !all
			if !listing {
				// The operator's own value, refused before the node is read,
				// not as a plan that does not validate once it is composed.
				if planID != "" && !config.ValidPlanID(planID) {
					return fmt.Errorf("--plan-id %q is not a plan_id: use letters, digits, _ and -, at most 128 characters", planID)
				}
				if err := checkPlanOutput(output, force); err != nil {
					return err
				}
				if err := checkPlanOutputDirectory(output); err != nil {
					return err
				}
			}
			req := initplan.Request{Node: nodeName, Namespace: namespace, VMIDs: vmids, All: all, FirstVMID: firstVMID}
			if !listing {
				var (
					err    error
					unread []string
				)
				if req.AvoidVMIDs, req.AvoidSDNIDs, unread, err = siblingPlanIDs(cmd.Context(), output); err != nil {
					return err
				}
				// A file that may be a plan and could not be read: its sandbox
				// IDs are not avoided, which the operator should know before
				// the plan is used, not find out as a refused run.
				for _, file := range unread {
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not read %s, so the sandbox VM IDs and SDN IDs it may use are not avoided; if it is a plan, check the new plan's IDs against it\n", file)
				}
			}
			if err := initplan.ValidateRequest(req); err != nil {
				return err
			}

			var d *initplan.Discovery
			var remote *controller.RunOptions
			if sshHost != "" {
				if sshKnownHosts == "" {
					sshKnownHosts = defaultKnownHostsPath()
				}
				remote = &controller.RunOptions{
					NodeName:   nodeName,
					ScratchDir: scratchDir,
					StateDir:   stateDir,
					SSH: controller.SSHConfig{
						Host: sshHost, User: sshUser, Port: sshPort, IdentityFile: sshIdentity,
						KnownHostsFile: sshKnownHosts, UseSudo: sshSudo,
					},
					Writer: cmd.ErrOrStderr(),
				}
				noteWorkerStaged()
				// The discovery's read-only workspace is removed under the
				// cleanup context: the operator's second interrupt abandons it.
				remote.CleanupContext = cleanupContext
				out, err := remoteDiscover(cmd.Context(), *remote, req)
				if len(out) == 0 {
					return withExitCode(err, exitCodeInfrastructure)
				}
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %v\n", err)
				}
				d = &initplan.Discovery{}
				if err := json.Unmarshal(out, d); err != nil {
					return withExitCode(fmt.Errorf("read the node's discovery: %w", err), exitCodeInfrastructure)
				}
			} else {
				var err error
				if d, err = runnerDiscover(cmd.Context(), req, scratchDir); err != nil {
					return withExitCode(err, exitCodeInfrastructure)
				}
			}

			if listing {
				out := newCheckedOutput(cmd.OutOrStdout())
				writeBackupList(out, d)
				return out.deliver(nil)
			}
			// What a run of this plan reads and holds, before the inspection
			// spends a node's time and before the plan is written.
			if sizes, err := d.PlanSizes(overlayStorage); err == nil && sizes.VMs > 0 {
				// A write that fails here fails again in the account init ends with,
				// which reports it with the plan's path.
				fmt.Fprintf(cmd.OutOrStdout(), "The plan restores %d VM(s). A run of it:\n", sizes.VMs)
				for _, line := range sizes.Lines() {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", line)
				}
				if err := confirmPlanSize(cmd, sizes, all, yes); err != nil {
					return err
				}
			}
			var found inspection
			if inspect {
				found.result = &initplan.Inspection{}
				if targets := initplan.InspectionTargets(d, overlayStorage); len(targets) > 0 {
					inspectReq := initplan.InspectRequest{Node: nodeName, Namespace: namespace, Targets: targets}
					if remote != nil {
						remote.CleanupContext = cleanupContext
					}
					var err error
					if found, err = inspectForInit(cmd.Context(), cmd.ErrOrStderr(), inspectReq, remote, runner.InspectOptions{NodeName: nodeName, ScratchDir: scratchDir, StateDir: stateDir}); err != nil {
						return err
					}
				}
			}
			res, err := initplan.Compose(d, initplan.Options{
				PlanID:         planID,
				Name:           planName,
				OverlayStorage: overlayStorage,
				Written:        initClock(),
				Inspect:        inspect,
				Inspection:     found.result,
			})
			if err != nil {
				return err
			}
			if err := writePlanFile(output, res.YAML, force); err != nil {
				return err
			}
			if err := finishInit(cmd.OutOrStdout(), output, res, d.Node, inspect, envFile); err != nil {
				return err
			}
			if found.cleanupError != nil {
				return withExitCode(fmt.Errorf("the plan was written to %s, but %w", output, found.cleanupError), exitCodeInfrastructure)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&inspect, "inspect", false, "look inside each Linux VM's newest backup, read-only, for the services it runs, and write a probe for each (maps one backup at a time on the node)")
	cmd.Flags().IntSliceVar(&vmids, "vm", nil, "source VM ID to put in the plan (repeat, or comma-separate)")
	cmd.Flags().BoolVar(&all, "all", false, "put every VM that has a backup in the plan")
	cmd.Flags().StringVarP(&output, "output", "o", defaultInitOutput, "plan file to write")
	cmd.Flags().BoolVar(&force, "force", false, "replace the plan file if it exists")
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask before writing a plan of every VM (--all) or of more than 500 GiB of disks; init asks only at a terminal")
	cmd.Flags().StringVar(&planID, "plan-id", "", "plan_id (default: recovery-<node>)")
	cmd.Flags().StringVar(&planName, "name", "", "plan name")
	cmd.Flags().StringVar(&overlayStorage, "overlay-storage", "", "PVE storage for overlays (default: CERTISTACK_OVERLAY_STORAGE, else the node's roomiest usable storage)")
	cmd.Flags().StringVar(&namespace, "namespace", "", "PBS namespace to read (default: PBS_NAMESPACE)")
	cmd.Flags().IntVar(&firstVMID, "first-vmid", initplan.DefaultFirstVMID, "first VM ID to consider for sandbox VMs")
	cmd.Flags().StringVar(&envFile, "env-file", "", "allowlisted controller environment file; values are parsed literally, never shell-sourced")
	cmd.Flags().StringVar(&nodeName, "node", "", "PVE node name (default on the node: this host's short name)")
	cmd.Flags().StringVar(&scratchDir, "scratch", "", "node scratch directory the backups' configurations are read into (default: CERTISTACK_SCRATCH_DIR; else /var/lib/certistack/scratch through --ssh-host, or the node's temporary directory on the node); created private if missing")
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/certistack", "node state directory")
	cmd.Flags().StringVar(&sshHost, "ssh-host", "", "PVE node SSH host: read from the controller, as run does")
	cmd.Flags().StringVar(&sshUser, "ssh-user", "certistack", "SSH service account")
	cmd.Flags().IntVar(&sshPort, "ssh-port", 22, "SSH port")
	cmd.Flags().StringVar(&sshIdentity, "ssh-identity", "", "absolute SSH private-key path")
	cmd.Flags().StringVar(&sshKnownHosts, "ssh-known-hosts", "", "absolute known_hosts path; strict verification is always enabled")
	cmd.Flags().BoolVar(&sshSudo, "ssh-sudo", false, "explicitly permit passwordless sudo for the temporary node worker")
	return cmd
}

// initIsTerminal says whether init can ask a question; a variable so that a test
// can stand a terminal in.
var initIsTerminal = stdinIsTerminal

// confirmPlanSize asks, at a terminal, before init writes a plan of every VM
// that has a backup (--all) or of more disk than a run reads in about an hour and
// a half (initplan.ConfirmAboveBytes). It asks nothing without a terminal, so that
// a script is not held up, and nothing with --yes. The default is no.
func confirmPlanSize(cmd *cobra.Command, sizes initplan.Sizes, all, yes bool) error {
	if yes || !initIsTerminal() {
		return nil
	}
	var why string
	switch {
	case all:
		why = fmt.Sprintf("--all puts every VM that has a backup in the plan, %d here.", sizes.VMs)
	case sizes.Large():
		why = fmt.Sprintf("A run of this plan reads more than %d GiB.", initplan.ConfirmAboveBytes>>30)
	default:
		return nil
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s Write the plan? [y/N] ", why)
	type answer struct {
		text string
		err  error
	}
	read := make(chan answer, 1)
	go func() {
		text, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		read <- answer{text, err}
	}()
	select {
	case <-cmd.Context().Done():
		fmt.Fprintln(cmd.ErrOrStderr())
		return withExitCode(cmd.Context().Err(), exitCodeInterrupted)
	case a := <-read:
		switch strings.ToLower(strings.TrimSpace(a.text)) {
		case "y", "yes":
			return nil
		}
		if a.err != nil && a.text == "" {
			fmt.Fprintln(cmd.ErrOrStderr())
		}
	}
	return errors.New("nothing was written: the plan was not confirmed. Name fewer VMs with --vm, or pass --yes to write it without being asked")
}

// nodeDiscoverCmd is the temporary worker's side of init: it prints what it
// discovered as JSON.
func nodeDiscoverCmd() *cobra.Command {
	var (
		req      initplan.Request
		envFile  string
		scratch  string
		vmids    []int
		avoidIDs []int
		avoidSDN []string
	)
	cmd := &cobra.Command{
		Use:    "node-discover",
		Short:  "Read what init needs on this node for a controller",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := verifyNodeIdentity(req.Node); err != nil {
				return err
			}
			restoreEnvironment, err := useCommandEnvironment(envFile, true)
			if err != nil {
				return err
			}
			defer restoreEnvironment()
			req.VMIDs, req.AvoidVMIDs, req.AvoidSDNIDs = vmids, avoidIDs, avoidSDN
			d, err := runnerDiscover(cmd.Context(), req, scratch)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(d)
		},
	}
	cmd.Flags().StringVar(&req.Node, "node", "", "PVE node name")
	cmd.Flags().StringVar(&req.Namespace, "namespace", "", "PBS namespace")
	cmd.Flags().BoolVar(&req.All, "all", false, "every VM with a backup")
	cmd.Flags().IntSliceVar(&vmids, "vm", nil, "source VM IDs")
	cmd.Flags().IntVar(&req.FirstVMID, "first-vmid", 0, "first sandbox VM ID")
	cmd.Flags().IntSliceVar(&avoidIDs, "avoid-vmid", nil, "VM IDs other plans use")
	cmd.Flags().StringSliceVar(&avoidSDN, "avoid-sdn", nil, "SDN IDs other plans use")
	cmd.Flags().StringVar(&scratch, "scratch", "", "private node directory the backups' configurations are read into, created if missing (default: the node's temporary directory)")
	cmd.Flags().StringVar(&envFile, "env-file", "", "protected node-local controller environment file")
	for _, name := range []string{"node", "env-file"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

// writeBackupList prints the VMs that have backups, and how to go on.
func writeBackupList(w io.Writer, d *initplan.Discovery) {
	where := "the PBS repository"
	if d.Namespace != "" {
		where = fmt.Sprintf("PBS namespace %q", d.Namespace)
	}
	if len(d.Backups) == 0 {
		if d.Namespace == "" {
			// Backups in a namespace are invisible from the root: say so, or the
			// newcomer whose backups are in one sees an empty list and no reason.
			fmt.Fprint(w, "No VM has a complete backup in the root namespace of the PBS repository. If your backups are in a namespace, set PBS_NAMESPACE (or pass --namespace).\n")
			return
		}
		fmt.Fprintf(w, "No VM has a complete backup in %s.\n", where)
		return
	}
	fmt.Fprintf(w, "VMs with a complete backup in %s:\n\n", where)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VMID\tNOTES\tNEWEST BACKUP\tBACKUPS\tDISKS")
	for _, b := range d.Backups {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%s\n", b.VMID, b.Comment, b.Time.UTC().Format("2006-01-02 15:04 UTC"), b.Count, listedDiskSize(b.DiskBytes))
	}
	_ = tw.Flush()
	fmt.Fprintf(w, "\nWrite a plan for some of them with --vm <id> (repeat it), or for all with --all.\n")
}

// listedDiskSize is the size of a VM's disk images for the backup list: whole
// GiB without a fraction ("32 GiB"), else one decimal ("10.5 GiB"), MiB below
// 1 GiB (never rounded up: 1 MiB and 123 bytes is "1.0 MiB"), and "unknown"
// when the snapshot list does not say.
func listedDiskSize(n int64) string {
	const gib = int64(1) << 30
	switch {
	case n <= 0:
		return "unknown"
	case n < gib:
		return runphase.FormatSize(n)
	case n%gib == 0:
		return fmt.Sprintf("%d GiB", n/gib)
	default:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(gib))
	}
}

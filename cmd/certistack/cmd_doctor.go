// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cliftcloud/certistack/internal/nodeidentity"
	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/runner"
	"github.com/spf13/cobra"
)

// doctorInterrupted is the command's answer when its context has ended: no
// verdict, and the interrupted exit status.
func doctorInterrupted(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("doctor was interrupted before it reached a verdict, so none is reported: %w", err)
	}
	return nil
}

// runPreflight is the host's preflight checks. It is a variable so that a
// test can give doctor a host that is ready: the verdict a ready host gets is
// written through the same checked output as every other.
var runPreflight = preflight.Check

// hasBackupClient and checkPlanSources are what doctor asks of the host to read
// each plan VM's backup; variables so that a test gives doctor a PVE node
// without one.
var (
	hasBackupClient = func() bool {
		_, err := exec.LookPath("proxmox-backup-client")
		return err == nil
	}
	checkPlanSources = runner.CheckSources
)

func doctorCmd() *cobra.Command {
	var (
		planPath       string
		scratchDir     string
		stateDir       string
		envFile        string
		overlayStorage string
		jsonOutput     bool
	)

	cmd := &cobra.Command{
		Use:   "doctor [plan.yaml]",
		Short: "Run preflight diagnostics on host, dependencies, and plan",
		Long: `Performs read-only preflight diagnostic checks against KVM virtualization,
host memory availability, scratch storage write/exec flags and free space,
QEMU/PBS/PVE tooling prerequisites, and optional plan constraints.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Cobra supplies a context to a command it executes. A caller that
			// runs this function itself (a test, an embedder) may have none, and
			// every check below asks the context whether it has ended: a nil one
			// panicked in the first of them.
			if cmd.Context() == nil {
				cmd.SetContext(context.Background())
			}
			if err := onePlanPath(args, planPath); err != nil {
				return err
			}
			if envFile != "" {
				restoreEnvironment, err := useCommandEnvironment(envFile, false)
				if err != nil {
					return err
				}
				defer restoreEnvironment()
			}
			// Doctor runs on the node. A node name the environment gives
			// (CERTISTACK_NODE) must be the node's own, before anything else is
			// read; without one the node's own name is the default.
			if err := verifyNodeIdentity(os.Getenv("CERTISTACK_NODE")); err != nil {
				return err
			}
			if len(args) > 0 {
				planPath = args[0]
			}

			if !jsonOutput {
				quietStructuredLogs(cmd)
			}

			var plan *config.Plan
			if planPath != "" {
				var err error
				plan, err = config.LoadFromFile(planPath)
				if err != nil {
					return fmt.Errorf("failed to load plan for doctor check: %w", err)
				}
			}

			// The scratch directory a run would use: the flag, or
			// CERTISTACK_SCRATCH_DIR as for run and plan, else the plan's own
			// storage.scratch_dir, else the default.
			if !cmd.Flags().Changed("scratch") {
				if value := os.Getenv("CERTISTACK_SCRATCH_DIR"); value != "" {
					scratchDir = value
				}
			}
			scratchDir = config.EffectiveScratchDir(scratchDir, plan, sysutil.DefaultScratchDir)
			if stateDir == "" {
				stateDir = "/var/lib/certistack"
			}

			// The PVE client refuses PVE_TLS_INSECURE without the lab opt-in
			// before sending any request, so doctor reports the policy
			// violation rather than sending the token unverified.
			opts := preflight.Options{
				ScratchDir:            scratchDir,
				StateDir:              stateDir,
				PVEURL:                os.Getenv("PVE_URL"),
				PVETLSInsecure:        envBool("PVE_TLS_INSECURE"),
				PVETLSCAFile:          os.Getenv("CERTISTACK_PVE_CA_SOURCE"),
				PVETokenID:            os.Getenv("PVE_TOKEN_ID"),
				PVETokenSecret:        os.Getenv("PVE_TOKEN_SECRET"),
				PBSKeyfile:            os.Getenv("CERTISTACK_PBS_KEYFILE"),
				PBSEncryptionPassword: os.Getenv("PBS_ENCRYPTION_PASSWORD"),
				NodeName:              localNodeName(),
				OverlayStorage:        overlayStorage,
			}

			res := runPreflight(cmd.Context(), plan, opts)
			if plan != nil {
				res = withSourceChecks(cmd.Context(), res, plan, overlayStorage)
				var err error
				if res, err = withOverlayDiskCheck(cmd.Context(), res, plan, overlayStorage, scratchDir); err != nil {
					// Only an ended context stops that check, and it
					// gets the same answer as every other interrupted step: no verdict, the
					// interrupted status, one message.
					if interrupted := doctorInterrupted(cmd.Context()); interrupted != nil {
						return interrupted
					}
					return err
				}
			}
			// An interrupted doctor has no verdict: the checks that were
			// stopped hold the interruption as their result. It ends with the
			// interrupted status instead of printing them as findings.
			if err := doctorInterrupted(cmd.Context()); err != nil {
				return err
			}

			out := newCheckedOutput(cmd.OutOrStdout())
			if jsonOutput {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(res); err != nil {
					return err
				}
				if !res.Ready {
					return withExitCode(errors.New("preflight diagnostics failed"), exitCodeInfrastructure)
				}
				return nil
			}

			// A verdict that could not be written is not one that was given.
			fmt.Fprintln(out, "CertiStack Preflight Diagnostics")
			fmt.Fprintln(out, "================================")
			for _, item := range res.Checks {
				icon := "✓"
				if item.Status == "failed" {
					icon = "✗"
				} else if item.Status == "warning" {
					icon = "!"
				} else if item.Status == "skipped" {
					icon = "-"
				}
				fmt.Fprintf(out, "  [%s] %-25s : %s\n", icon, item.Name, item.Detail)
			}
			fmt.Fprintln(out, "--------------------------------")
			if !res.Ready {
				fmt.Fprintln(out, "✗ Preflight checks FAILED. System is not ready for DR validation.")
				return out.deliver(withExitCode(errors.New("preflight diagnostics failed"), exitCodeInfrastructure))
			}
			if plan == nil {
				// The host's tools are all doctor saw: what the plan needs
				// (its backups, its storage, its network) it checks only when
				// it is given the plan, so it does not call the system ready.
				fmt.Fprintln(out, "✓ Preflight checks PASSED. Host tools present. Run doctor with your plan (or certistack check) before a run: some checks need the plan.")
				return out.deliver(nil)
			}
			fmt.Fprintln(out, "✓ Preflight checks PASSED. System is ready for DR validation.")
			return out.deliver(nil)
		},
	}

	cmd.Flags().StringVarP(&planPath, "plan", "p", "", "path to disaster recovery plan YAML")
	cmd.Flags().StringVar(&envFile, "env-file", "", "allowlisted controller environment file; values are parsed literally, never shell-sourced")
	cmd.Flags().StringVar(&scratchDir, "scratch", "", "private ephemeral scratch directory to check (default: CERTISTACK_SCRATCH_DIR, else the plan's storage.scratch_dir, else /var/lib/certistack/scratch)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/certistack", "runner state directory to check: it must be private and usable, as the worker requires")
	cmd.Flags().StringVar(&overlayStorage, "overlay-storage", "", "PVE storage for COW overlays, as for run (default: plan storage.overlay_storage)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output diagnostics in JSON format")

	return cmd
}

// quietStructuredLogs keeps the structured log's info lines out of doctor's
// human report: a PBS lookup writes "time=... level=INFO msg=resolved latest PBS
// snapshot ..." to standard error in the middle of the table, in a format none of
// the report's other lines has. Warnings and errors still show, and --debug
// restores everything.
func quietStructuredLogs(cmd *cobra.Command) {
	if flag := cmd.Flag("debug"); flag != nil && flag.Value.String() == "true" {
		return
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
}

// noPBSCredentialsHint explains a failed backup check on a host that was given
// no PBS credential: the PBS client cannot log in, and its own message is
// withheld because it can carry credentials, so all doctor would show is the
// exit status. "" when a credential is in the environment, where the failure is
// something else.
func noPBSCredentialsHint() string {
	if os.Getenv("PBS_PASSWORD") != "" {
		return ""
	}
	return "; no PBS credentials were passed to doctor (PBS_PASSWORD is not set): run it with --env-file FILE holding the PBS variables, or use certistack check <plan> --env-file FILE from the controller, which needs no file on the node"
}

// withOverlayDiskCheck warns when the sandbox overlays would share a
// physical disk with the cluster file system's database: a sandbox's first
// writes can saturate it and delay corosync. Overlays go to the
// overlay storage, or to the scratch directory without one. The check is
// stopped when ctx ends, and the error is ctx's: an interrupted doctor does
// not report the topology as unknown.
func withOverlayDiskCheck(ctx context.Context, res preflight.Result, plan *config.Plan, overlayStorage, scratchDir string) (preflight.Result, error) {
	if overlayStorage == "" {
		overlayStorage = strings.TrimSpace(plan.Storage.OverlayStorage)
	}
	dir := scratchDir
	if overlayStorage != "" {
		// Minimal environment: doctor runs with the controller environment, which holds the PVE token.
		out, err := process.CommandContext(ctx, "pvesm", []string{"path", overlayStorage + ":1/certistack-doctor.qcow2"}, false).Output()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return res, ctxErr
			}
			res.Checks = append(res.Checks, preflight.CheckItem{Name: "overlay_disk", Status: "skipped", Detail: "cannot resolve overlay storage " + overlayStorage + " here (pvesm)"})
			return res, nil
		}
		dir = filepath.Dir(filepath.Dir(strings.TrimSpace(string(out))))
	}
	shared, err := sysutil.SharedDisks(ctx, dir, sysutil.ClusterStateDir)
	if err != nil && ctx.Err() != nil {
		return res, ctx.Err()
	}
	switch {
	case err != nil:
		// Unknown is not safe: a run treats it as possibly shared.
		res.Checks = append(res.Checks, preflight.CheckItem{Name: "overlay_disk", Status: "warning",
			Detail: fmt.Sprintf("could not determine whether sandbox overlays in %s share a disk with the cluster database (%s): %v; a run treats them as possibly shared, and copy-before-boot's auto mode does not copy there", dir, sysutil.ClusterStateDir, err)})
	case len(shared) > 0:
		res.Checks = append(res.Checks, preflight.CheckItem{Name: "overlay_disk", Status: "warning",
			Detail: fmt.Sprintf("sandbox overlays in %s share disk %s with the cluster database (%s); their writes can delay corosync", dir, strings.Join(shared, ", "), sysutil.ClusterStateDir)})
	default:
		res.Checks = append(res.Checks, preflight.CheckItem{Name: "overlay_disk", Status: "passed", Detail: "sandbox overlays in " + dir + " do not share a disk with the cluster database"})
	}
	return res, nil
}

// withSourceChecks adds each plan VM's backup as a run would find it, when
// this host can read PBS: a controller usually cannot, a PVE node can.
func withSourceChecks(ctx context.Context, res preflight.Result, plan *config.Plan, overlayStorage string) preflight.Result {
	if !hasBackupClient() {
		res.Checks = append(res.Checks, preflight.CheckItem{Name: "backup_sources", Status: "skipped",
			Detail: "proxmox-backup-client is not installed here; run doctor with the plan on a PVE node to check each VM's backup"})
		return res
	}
	checks, err := checkPlanSources(ctx, plan, runner.Options{OverlayStorage: overlayStorage})
	if err != nil {
		res.Checks = append(res.Checks, preflight.CheckItem{Name: "backup_sources", Status: "failed", Detail: runner.SafeFailureReason(err) + noPBSCredentialsHint()})
		res.Ready = false
		return res
	}
	for _, check := range checks {
		detail := check.Detail
		if check.Status == runner.SourceFailed {
			detail += noPBSCredentialsHint()
		}
		res.Checks = append(res.Checks, preflight.CheckItem{Name: fmt.Sprintf("backup_vm_%d", check.VMID), Status: check.Status, Detail: detail})
		if check.Status == runner.SourceFailed {
			res.Ready = false
		}
	}
	return res
}

// localNodeName is this host's PVE node name: the node PVE's own link names
// (/etc/pve/local), else the short host name. "" when neither can be read. A
// variable so that a test can name the host.
var localNodeName = readLocalNodeName

func readLocalNodeName() string {
	if name, err := nodeidentity.Local(); err == nil {
		return name
	}
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	name, _, _ := strings.Cut(host, ".")
	return name
}

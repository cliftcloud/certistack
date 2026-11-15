// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/spf13/cobra"
)

// runController runs the controller; a variable so a test can hand run a result
// without a node.
var runController = func(ctx context.Context, opts controller.RunOptions) (*controller.Result, error) {
	return controller.NewExecutor().Run(ctx, opts)
}

func runCmd() *cobra.Command {
	return runCmdWithCleanupContext(nil)
}

func runCmdWithCleanupContext(cleanupContext context.Context) *cobra.Command {
	var (
		planPath       string
		nodeName       string
		scratchDir     string
		overlayStorage string
		outputDir      string
		envFile        string
		stateDir       string
		sshHost        string
		sshUser        string
		sshPort        int
		sshIdentity    string
		sshKnownHosts  string
		sshSudo        bool
		skipIntegrity  bool
	)

	cmd := &cobra.Command{
		Use:   "run [plan.yaml]",
		Short: "Run a disaster recovery validation from a remote controller",
		Long: `Runs CertiStack from a management host. The controller authenticates
to the selected PVE node with strict SSH host-key verification, uploads a
temporary worker beneath its node state directory, and keeps the run's
report locally, as JSON. The Community Edition writes the report unsigned;
read it with "certistack report show". It never installs the controller,
dashboard or database on PVE.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			if err := applyControllerEnvironmentDefaults(cmd, &nodeName, &scratchDir, &outputDir, &stateDir, &sshHost, &sshUser, &sshPort, &sshIdentity, &sshKnownHosts, &sshSudo); err != nil {
				return err
			}
			if !cmd.Flags().Changed("overlay-storage") {
				if value := os.Getenv("CERTISTACK_OVERLAY_STORAGE"); value != "" {
					overlayStorage = value
				}
			}
			if skipIntegrity && !testModeOptedIn() {
				return errors.New("--skip-integrity is test-only; set CERTISTACK_ALLOW_TEST_MODE=1 for an explicit lab opt-in")
			}
			if len(args) > 0 {
				planPath = args[0]
			}
			if planPath == "" {
				return errors.New("plan path is required (pass as argument or via --plan)")
			}
			if sshKnownHosts == "" {
				sshKnownHosts = defaultKnownHostsPath()
			}

			result, err := runController(cmd.Context(), controller.RunOptions{
				PlanPath:       planPath,
				NodeName:       nodeName,
				ScratchDir:     scratchDir,
				OverlayStorage: overlayStorage,
				StateDir:       stateDir,
				OutputDir:      outputDir,
				SkipIntegrity:  skipIntegrity,
				CleanupContext: cleanupContext,
				SSH: controller.SSHConfig{
					Host:           sshHost,
					User:           sshUser,
					Port:           sshPort,
					IdentityFile:   sshIdentity,
					KnownHostsFile: sshKnownHosts,
					UseSudo:        sshSudo,
				},
				Build: controller.BuildInfo{
					Version:   version,
					Commit:    commit,
					BuildDate: buildDate,
				},
				Writer: cmd.ErrOrStderr(),
			})
			delivered := deliverRun(cmd.OutOrStdout(), result, err)
			// What to read next goes to standard error with the progress:
			// standard output keeps only the saved-report line.
			writeRunNextSteps(cmd.ErrOrStderr(), result, err)
			// The opt-in usage report (off by default; docs/telemetry.md) goes
			// after the verdict is out, waits at most two seconds, and cannot
			// change the exit status.
			telemetryAfterRun(cmd.Context(), cmd.ErrOrStderr(), result)
			return delivered
		},
	}

	cmd.Flags().StringVarP(&planPath, "plan", "p", "", "path to disaster recovery plan YAML")
	cmd.Flags().StringVar(&envFile, "env-file", "", "allowlisted controller environment file; values are parsed literally, never shell-sourced")
	cmd.Flags().StringVar(&nodeName, "node", "", "Proxmox VE node name that will host the temporary worker")
	cmd.Flags().StringVar(&scratchDir, "scratch", "", "remote private work directory (default: plan storage.scratch_dir, else /var/lib/certistack/scratch)")
	cmd.Flags().StringVar(&overlayStorage, "overlay-storage", "", "PVE storage (file-based, images content) for COW overlays; required on stock Proxmox VE (default: plan storage.overlay_storage)")
	cmd.Flags().StringVar(&outputDir, "output", "/var/lib/certistack/reports", "controller directory for the reports a run writes (unsigned, in the Community Edition)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/certistack", "remote node recovery journal directory")
	cmd.Flags().StringVar(&sshHost, "ssh-host", "", "PVE node SSH host or address")
	cmd.Flags().StringVar(&sshUser, "ssh-user", "certistack", "SSH service account")
	cmd.Flags().IntVar(&sshPort, "ssh-port", 22, "SSH port")
	cmd.Flags().StringVar(&sshIdentity, "ssh-identity", "", "absolute SSH private-key path")
	cmd.Flags().StringVar(&sshKnownHosts, "ssh-known-hosts", "", "absolute known_hosts path; strict verification is always enabled")
	cmd.Flags().BoolVar(&sshSudo, "ssh-sudo", false, "explicitly permit passwordless sudo for the temporary node worker")
	cmd.Flags().BoolVar(&skipIntegrity, "skip-integrity", false, "TEST ONLY: skip full mapped-PBS image verification; evidence is marked non-comprehensive")
	_ = cmd.Flags().MarkHidden("skip-integrity")
	return cmd
}

// deliverRun prints where the report was saved and returns the run's own
// error. The notice is the only place the report's path is printed, and a
// run's verdict is not delivered by an exit status alone: a notice that could
// not be written fails the command, and says the report was saved.
func deliverRun(w io.Writer, result *controller.Result, err error) error {
	out := newCheckedOutput(w)
	var saved []string
	if result != nil && result.ReportPath != "" {
		fmt.Fprintf(out, "✓ Controller report saved to: %s\n", result.ReportPath)
		saved = append(saved, "the report was saved to "+result.ReportPath)
	}
	// The report goes to standard output between markers when it could
	// be saved nowhere else; it is written through the checked
	// output, so a failure to deliver it is reported too.
	return out.deliver(runOutcomeError(result, unsavedReportFallback(out, result, err)), saved...)
}

// controllerCleanupUnverified is the controller's wording when it could not
// verify the removal of the run's credential-bearing node workspace or SSH
// staging directory. runOutcomeError recognizes the condition by
// controller.ErrControllerMaterialCleanupUnverified, not by this text; a test
// keeps the wording an operator reads in step with the sentinel's.
const controllerCleanupUnverified = "temporary controller material cleanup was not verified"

// unsavedReportFallback is the second way out of a report that could be
// neither saved nor written between markers to the operator's progress output:
// it writes the report between the same markers on standard output, and says
// so, or says that standard output failed as well. It changes nothing when the
// run's error does not say the first copy failed.
func unsavedReportFallback(stdout io.Writer, result *controller.Result, err error) error {
	if result == nil || result.Report == nil || result.ReportPath != "" || !errors.Is(err, controller.ErrEmergencyReportNotWritten) {
		return err
	}
	if writeErr := controller.WriteUnsavedReport(stdout, result.Report); writeErr != nil {
		return errors.Join(err, fmt.Errorf("the emergency copy on standard output failed as well: %w; the report was lost with this process", writeErr))
	}
	return errors.Join(err, errors.New("the report was written to standard output instead, between the same BEGIN and END CERTISTACK REPORT markers"))
}

// runOutcomeError is the command's error, and so its exit status, for a
// controller run. A validation that failed with verified cleanup, and whose
// report was saved, exits 1. A run whose credential-bearing controller
// material was not verified removed, or whose report could not be
// saved, exits 2 in every outcome, including a failed validation: a campaign
// credits a failed-validation drill (a fault or a capacity guard) only on
// status 1, so it never credits a run that left its credentials on the node or
// whose evidence was not archived. The one exception is an interruption, which
// exits 130 whatever else went wrong: exitCodeForError reads a cancellation
// before any status an error carries.
func runOutcomeError(result *controller.Result, err error) error {
	formattedErr := formatRunError(err)
	if errors.Is(formattedErr, controller.ErrControllerMaterialCleanupUnverified) {
		return withExitCode(formattedErr, exitCodeInfrastructure)
	}
	if result != nil && result.Report != nil && result.ReportPath == "" {
		// The controller returns the report of a run without a path only when
		// it could not save it.
		if formattedErr == nil {
			formattedErr = errors.New("the report could not be saved")
		}
		return withExitCode(formattedErr, exitCodeInfrastructure)
	}
	if result != nil && result.Report != nil && !result.Report.AllPassed {
		if formattedErr == nil {
			formattedErr = errors.New("validation report does not record a pass")
		}
		if result.Report.TeardownEvidence != nil && result.Report.TeardownEvidence.AllCleaned {
			return withExitCode(formattedErr, exitCodeValidationFailed)
		}
	}
	return formattedErr
}

func formatRunError(err error) error {
	if err == context.Canceled {
		return interruptedRunError{"validation interrupted after CertiStack verified cleanup of its temporary node resources"}
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("validation interrupted: %w", err)
	}
	return err
}

// interruptedRunError reads as its message alone, without a trailing
// "context canceled", and is still a cancellation for the exit code.
type interruptedRunError struct{ message string }

func (e interruptedRunError) Error() string { return e.message }
func (e interruptedRunError) Unwrap() error { return context.Canceled }

// applyControllerEnvironmentDefaults lets a controller environment file supply
// operational defaults while preserving explicit command-line flags as the
// highest-precedence configuration source. A value that is set but is not a
// port or a yes or no is an error, not a default.
func applyControllerEnvironmentDefaults(cmd *cobra.Command, nodeName, scratchDir, outputDir, stateDir, sshHost, sshUser *string, sshPort *int, sshIdentity, sshKnownHosts *string, sshSudo *bool) error {
	setString := func(flagName, environmentName string, target *string) {
		if !cmd.Flags().Changed(flagName) {
			if value := os.Getenv(environmentName); value != "" {
				*target = value
			}
		}
	}

	setString("node", "CERTISTACK_NODE", nodeName)
	setString("scratch", "CERTISTACK_SCRATCH_DIR", scratchDir)
	setString("output", "CERTISTACK_OUTPUT_DIR", outputDir)
	setString("state-dir", "CERTISTACK_STATE_DIR", stateDir)
	setString("ssh-host", "CERTISTACK_SSH_HOST", sshHost)
	setString("ssh-user", "CERTISTACK_SSH_USER", sshUser)
	if !cmd.Flags().Changed("ssh-port") {
		port, err := envPortOrDefault("CERTISTACK_SSH_PORT", *sshPort)
		if err != nil {
			return err
		}
		*sshPort = port
	}
	setString("ssh-identity", "CERTISTACK_SSH_IDENTITY", sshIdentity)
	setString("ssh-known-hosts", "CERTISTACK_SSH_KNOWN_HOSTS", sshKnownHosts)
	if !cmd.Flags().Changed("ssh-sudo") {
		sudo, err := envBoolDefault("CERTISTACK_SSH_SUDO", *sshSudo)
		if err != nil {
			return err
		}
		*sshSudo = sudo
	}
	return nil
}

func defaultKnownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

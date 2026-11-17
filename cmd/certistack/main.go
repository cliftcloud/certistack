// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package main provides the certistack CLI binary—an administrative
// interface for CertiStack disaster recovery validation plans.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/pkg/controller"
)

// Build-time variables injected via -ldflags; applyBuildInfo fills them from
// the embedded module/VCS metadata when a binary was built without them.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

const (
	exitCodeValidationFailed = 1
	exitCodeInfrastructure   = 2
	exitCodeInterrupted      = 130
)

type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string {
	return e.err.Error()
}

func (e *exitCodeError) Unwrap() error {
	return e.err
}

func withExitCode(err error, code int) error {
	if err == nil {
		return nil
	}
	return &exitCodeError{code: code, err: err}
}

func exitCodeForError(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return exitCodeInterrupted
	}
	var coded *exitCodeError
	if errors.As(err, &coded) {
		return coded.code
	}
	return exitCodeInfrastructure
}

// activeCommand is the name of the command this process runs, set before the
// command does, so that the signal handler can word what it says about an
// interruption for that command; remoteWorkerStaged is set by plan and init
// when they stage a temporary worker on a node, which they clean up.
var (
	activeCommand      atomic.Value // string
	remoteWorkerStaged atomic.Bool
	// localInspection is set when init --inspect, run on the node itself,
	// is about to map backups there, which it releases when interrupted.
	localInspection atomic.Bool
	// remoteInspectionStaged is set when init --ssh-host --inspect stages the
	// worker that maps backups on the node: unlike the read-only workspace of
	// plan, check and init's discovery, it keeps a recovery journal.
	remoteInspectionStaged atomic.Bool
)

// noteWorkerStaged records that the command is about to stage a temporary
// worker on a node, so an interruption has a cleanup to wait for.
func noteWorkerStaged() { remoteWorkerStaged.Store(true) }

// interruptHasCleanup reports whether interrupting the running command leaves
// anything to clean up, and so whether the first signal's message should say
// that CertiStack is waiting for cleanup and offer to abandon it.
// Most commands only read: they end at once and have no worker workspace, so
// that message is untrue of them and sends an operator looking for a
// workspace there is not. plan and init clean up only when they stage a
// worker on a node, and init when --inspect maps backups on this node. A
// command not named here, or none yet, is assumed to have cleanup: the claim
// that is safe to make is the longer one.
func interruptHasCleanup() bool {
	name, _ := activeCommand.Load().(string)
	switch name {
	case "version", "validate", "doctor", "verify-report", "inspect", "node-plan", "node-discover", "telemetry", "report", "show", "schema", "setup", "trust-node", "pve-ca", "rbac", "node-check":
		return false
	case "init":
		return remoteWorkerStaged.Load() || localInspection.Load()
	case "plan", "check":
		return remoteWorkerStaged.Load()
	}
	return true
}

// readOnlyWorkerCleanup reports whether the cleanup an interrupt waits for is
// that of a read-only worker: plan, check and init's discovery stage a
// workspace on the node that holds the read's credentials and nothing a
// recovery could need (it keeps no journal), and the node removes it itself
// once the controller stops renewing its lease. The workspace of init
// --inspect's inspection, here or on the node, is a journaled worker's.
func readOnlyWorkerCleanup() bool {
	if localInspection.Load() || remoteInspectionStaged.Load() || !remoteWorkerStaged.Load() {
		return false
	}
	name, _ := activeCommand.Load().(string)
	return name == "plan" || name == "check" || name == "init"
}

// recovering reports whether the running command is recover. It is itself the
// cleanup: there is no worker workspace for an interrupt to retain, and the
// interrupts reach recovery through recovery.RecoverContext, which says what
// each of them ends. The notices below say exactly that, and no more.
func recovering() bool {
	name, _ := activeCommand.Load().(string)
	return name == "recover"
}

const (
	// recoverStops is what the first interrupt of recover does: no further
	// step starts, and the waits that can end (PVE, a loop detach) end. What
	// has begun and cannot be cut short runs to its own bound.
	recoverStops = "stopping recovery. It starts no further step and stops waiting on PVE and on a loop detach; a step that has begun and cannot be cut short (the kill of a recorded process, the stop of a map's daemon, the removal of a probe address) runs to its own end. If recovery had not finished, its journal stays unresolved: " + recoverhint.Again + "."
	// recoverCutsShort is what the second interrupt does, and only that.
	recoverCutsShort = "cut short the kernel commands of a probe address's removal that are running; the kill of a process, the stop of a map's daemon and a loop detach already issued go on."
)

// noticeWait bounds how long a signal notice may hold up what the signal asks
// for. The operator's terminal or a supervisor's pipe can block a write (a full
// pipe nobody reads, a stopped pager): cancelling the run, and abandoning its
// cleanup on a second interrupt, must not wait on it.
var noticeWait = 2 * time.Second

// signalNotice writes the notice before the cancellation it announces, and gives up
// waiting for the write after noticeWait.
func signalNotice(output io.Writer, format string, args ...any) {
	written := make(chan struct{})
	go func() {
		defer close(written)
		fmt.Fprintf(output, format, args...)
	}()
	select {
	case <-written:
	case <-time.After(noticeWait):
	}
}

func newSignalContexts(signals <-chan os.Signal, output io.Writer) (context.Context, context.Context, func()) {
	if output == nil {
		output = io.Discard
	}
	ctx, cancel := context.WithCancel(context.Background())
	cleanupCtx, cancelCleanup := context.WithCancel(context.Background())
	done := make(chan struct{})
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			cancelCleanup()
			close(done)
		})
	}

	go func() {
		select {
		case sig, ok := <-signals:
			if !ok {
				return
			}
			switch {
			case !interruptHasCleanup() && sig == os.Interrupt:
				signalNotice(output, "Interrupt received; stopping. This command changes nothing, so there is nothing to clean up.\n")
			case !interruptHasCleanup():
				signalNotice(output, "Stop signal received (%s); stopping. This command changes nothing, so there is nothing to clean up.\n", sig)
			case recovering() && sig == os.Interrupt:
				signalNotice(output, "Interrupt received; "+recoverStops+" Press Ctrl-C again to "+recoverCutsShort+"\n")
			case recovering():
				signalNotice(output, "Stop signal received (%s); "+recoverStops+" A second signal will "+recoverCutsShort+"\n", sig)
			case sig == os.Interrupt && readOnlyWorkerCleanup():
				signalNotice(output, "Interrupt received; waiting for CertiStack cleanup. Press Ctrl-C again to abandon cleanup; the node then removes the temporary worker workspace itself, about %d seconds after this controller stops renewing its lease, so there is nothing to recover manually.\n", controller.ReadWorkspaceLeaseSeconds)
			case sig == os.Interrupt:
				signalNotice(output, "Interrupt received; waiting for CertiStack cleanup. Press Ctrl-C again to abandon cleanup and retain the protected worker workspace for manual recovery.\n")
			default:
				// SIGTERM or SIGHUP: a supervisor (the node worker's, once the
				// controller's lease expires), systemd or a lost session, with
				// nobody at a terminal to press Ctrl-C.
				signalNotice(output, "Stop signal received (%s); cleaning up CertiStack's temporary resources before exit.\n", sig)
			}
			cancel()
		case <-done:
			return
		}

		select {
		case _, ok := <-signals:
			if !ok {
				return
			}
			if recovering() {
				signalNotice(output, "Second interrupt received; cutting short the kernel commands of a probe address's removal that are running. The kill of a process, the stop of a map's daemon and a loop detach already issued go on and are not undone. The journal stays unresolved: "+recoverhint.Again+".\n")
			} else if interruptHasCleanup() && readOnlyWorkerCleanup() {
				signalNotice(output, "Second interrupt received; abandoning automatic cleanup. The node removes the temporary worker workspace itself about %d seconds after this controller stops renewing its lease; there is nothing to recover manually.\n", controller.ReadWorkspaceLeaseSeconds)
			} else if interruptHasCleanup() {
				signalNotice(output, "Second interrupt received; abandoning automatic cleanup. Retain the protected worker workspace, and "+recoverhint.Recover+".\n")
			} else {
				signalNotice(output, "Second interrupt received.\n")
			}
			cancelCleanup()
		case <-done:
		}
	}()

	return ctx, cleanupCtx, stop
}

func main() {
	applyBuildInfo(readBuildInfo())
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer signal.Stop(signals)
	ctx, cleanupCtx, stop := newSignalContexts(signals, os.Stderr)
	defer stop()
	if err := newRootCmd(cleanupCtx).ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitCodeForError(err))
	}
}

func rootCmd() *cobra.Command {
	return newRootCmd(nil)
}

func newRootCmd(cleanupContext context.Context) *cobra.Command {
	var (
		debug bool
	)

	root := &cobra.Command{
		Use:   "certistack",
		Short: "CertiStack — Autonomous Disaster Recovery Validation for Proxmox VE",
		Long: `CertiStack validates disaster recovery plans by booting ephemeral VMs
from Proxmox Backup Server snapshots inside isolated SDN sandboxes,
executing deterministic multi-stage probes, and writing a JSON report of what
the run found. The Community Edition writes the report unsigned ("certistack
report show" reads it); the Enterprise Edition signs it, and "certistack
verify-report" checks a signed one.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// --env-file "" is a script's unset variable, not "no file": the
			// command would read the process environment instead of the file
			// the operator meant. Refused before anything is read.
			if flag := cmd.Flags().Lookup("env-file"); flag != nil && flag.Changed && strings.TrimSpace(flag.Value.String()) == "" {
				return errors.New("--env-file is empty: give the path of the environment file, or leave the flag out")
			}
			activeCommand.Store(cmd.Name())
			level := slog.LevelInfo
			if debug {
				level = slog.LevelDebug
			}
			handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
			slog.SetDefault(slog.New(handler))
			telemetryPreRun(cmd.Context(), cmd.Name())
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug-level logging")

	root.AddCommand(versionCmd())
	root.AddCommand(initCmdWithCleanupContext(cleanupContext))
	root.AddCommand(nodeDiscoverCmd())
	root.AddCommand(nodeInspectCmd())
	root.AddCommand(validateCmd())
	root.AddCommand(doctorCmd())
	root.AddCommand(planCmdWithCleanupContext(cleanupContext))
	root.AddCommand(nodePlanCmd())
	root.AddCommand(verifyReportCmd())
	root.AddCommand(reportCmd())
	root.AddCommand(schemaCmd())
	root.AddCommand(inspectCmd())
	root.AddCommand(recoverCmdWithCleanupContext(cleanupContext))
	root.AddCommand(runCmdWithCleanupContext(cleanupContext))
	root.AddCommand(nodeRunCmd())
	root.AddCommand(telemetryCmd())
	root.AddCommand(setupCmd())
	root.AddCommand(checkCmdWithCleanupContext(cleanupContext))
	root.AddCommand(nodeCheckCmd())

	return root
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print CertiStack version information",
		// Arguments it would discard are an error, as for the other commands
		// that take none.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := newCheckedOutput(cmd.OutOrStdout())
			fmt.Fprintf(out, "certistack %s\n", version)
			fmt.Fprintf(out, "  commit:    %s\n", commit)
			fmt.Fprintf(out, "  built:     %s\n", buildDate)
			fmt.Fprintf(out, "  go:        %s\n", runtime.Version())
			fmt.Fprintf(out, "  os/arch:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
			return out.deliver(nil)
		},
	}
}

func readBuildInfo() *debug.BuildInfo {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return info
}

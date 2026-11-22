// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/telemetry"
)

// telemetryTerminals is what the first-run question reads and writes. It is a
// variable so a test can stand in a terminal; the process's own streams are
// the only ones the product uses.
type telemetryTerminals struct {
	Stdin          io.Reader
	Stderr         io.Writer
	StdinTerminal  bool
	StderrTerminal bool
}

func realTelemetryTerminals() telemetryTerminals {
	return telemetryTerminals{
		Stdin:          os.Stdin,
		Stderr:         os.Stderr,
		StdinTerminal:  telemetry.IsTerminal(os.Stdin),
		StderrTerminal: telemetry.IsTerminal(os.Stderr),
	}
}

// productionTelemetryManager is the opt-in report as this process sees it: the
// process environment, the per-user state file and this build's version.
func productionTelemetryManager() *telemetry.Manager {
	return &telemetry.Manager{Version: version}
}

// The two seams a test replaces: the streams the question uses, and the
// manager (a temporary state file, a map for an environment, a local server).
var (
	processTelemetryTerminals = realTelemetryTerminals
	newTelemetryManager       = productionTelemetryManager
)

// userConfigDir is the per-user CertiStack directory the usage statistics keep
// their answer in ($XDG_CONFIG_HOME/certistack, else ~/.config/certistack).
// certistack setup records its environment file there too
// (envFilePointerPath); this file alone imports pkg/telemetry.
func userConfigDir() (string, error) {
	return telemetry.ConfigDir()
}

// telemetryExitBudget is the longest a finished run waits for the report; a
// variable only so a test need not wait it out.
var telemetryExitBudget = telemetry.ExitBudget

// telemetryPreRun asks the first-run question, once, and only when a person is
// there to answer: stdin and stderr are both terminals, CI is unset, the
// command really runs something, nothing in the environment has decided, and
// the answer is not already stored. Everywhere else it does nothing and
// touches nothing. It never fails the command.
func telemetryPreRun(ctx context.Context, command string) {
	defer recoverTelemetry()
	terminals := processTelemetryTerminals()
	manager := newTelemetryManager()
	if !manager.ShouldPrompt(command, terminals.StdinTerminal, terminals.StderrTerminal) {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	answer, ok := telemetry.Ask(ctx, terminals.Stdin, terminals.Stderr)
	if !ok {
		return
	}
	if err := manager.Record(answer); err != nil {
		slog.Debug("telemetry: the answer could not be stored", "error", err)
	}
}

// telemetryAfterRun is the only place the report is sent, and only `run`
// calls it (a test holds that): after a run that tested at least one VM, pass
// or fail. It waits at most telemetry.ExitBudget and never changes the exit
// status. Every failure is a debug line, except one: a report that is on but
// could not write its state file sent nothing, and says so in one warning on
// w, with the file and the fix.
func telemetryAfterRun(ctx context.Context, w io.Writer, result *controller.Result) {
	defer recoverTelemetry()
	if ctx == nil {
		ctx = context.Background()
	}
	if result == nil || result.Report == nil || len(result.Report.VMRecords) == 0 || ctx.Err() != nil {
		return
	}
	tested, err := time.Parse(time.RFC3339, result.Report.Timestamp)
	if err != nil {
		tested = time.Now()
	}
	ctx, cancel := context.WithTimeout(ctx, telemetryExitBudget)
	defer cancel()
	outcome := newTelemetryManager().AfterRun(ctx, telemetry.Completed{Cluster: telemetryClusterIdentity(result.Report.NodeFQDN), TestedAt: tested})
	if !outcome.Sent {
		slog.Debug("telemetry: nothing sent", "why", outcome.Why, "error", outcome.Err)
	}
	if warning := outcome.UnwritableWarning(); warning != "" && w != nil {
		_, _ = fmt.Fprintln(w, warning)
	}
}

// recoverTelemetry keeps a defect in the optional report from ever becoming a
// crash of the command it rides on.
func recoverTelemetry() {
	if r := recover(); r != nil {
		slog.Debug("telemetry: recovered", "panic", r)
	}
}

func telemetryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "telemetry",
		Short: "Show or change the opt-in usage statistics (off by default)",
		Long: `CertiStack sends nothing unless you opt in. If you do, it sends five fields,
at most once a day, after a completed run: a random install id, the version,
how many Proxmox VE clusters you have tested on, the date of the last restore
test, and whether you use it for business. "certistack telemetry show" prints
exactly that.

CERTISTACK_TELEMETRY=1 opts in without storing an answer, for CI and
containers. It keeps the install id and the time of the last report in
telemetry.json, so it too reports at most once a day and counts the install
once; where that file cannot be written it sends nothing, and a run says
so in one warning. See https://certistack.dev/docs/telemetry/.`,
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(telemetryStatusCmd(), telemetryShowCmd(), telemetryEnableCmd(), telemetryDisableCmd(), telemetryResetCmd())
	return cmd
}

func telemetryStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Say whether the report is on or off, and why",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := newCheckedOutput(cmd.OutOrStdout())
			manager := newTelemetryManager()
			snap := manager.Resolve()
			switch {
			case snap.Decision.Enabled:
				fmt.Fprintln(out, "telemetry: on")
			case snap.Decision.KeptByEnvironment:
				fmt.Fprintln(out, "telemetry: off in this shell")
			default:
				fmt.Fprintln(out, "telemetry: off")
			}
			fmt.Fprintf(out, "reason: %s\n", snap.Decision.Reason)
			switch {
			case snap.PathErr != nil:
				fmt.Fprintf(out, "state file: none (%v)\n", snap.PathErr)
			default:
				fmt.Fprintf(out, "state file: %s (%s)\n", snap.Path, snap.Status)
			}
			if snap.Decision.Enabled {
				endpoint, err := manager.Endpoint()
				if err != nil {
					fmt.Fprintf(out, "sent to: nowhere, %v\n", err)
				} else {
					fmt.Fprintf(out, "sent to: %s\n", endpoint)
				}
				switch {
				case snap.State.InstallID != "":
					fmt.Fprintf(out, "install id: %s\n", snap.State.InstallID)
				case snap.Decision.Environment:
					fmt.Fprintln(out, "install id: none yet; the first report makes it and keeps it in the state file")
				}
			}
			if snap.Decision.KeptByEnvironment {
				fmt.Fprintf(out, "install id: %s (kept by %s=1)\n", snap.State.InstallID, telemetry.VarTelemetry)
			}
			fmt.Fprintln(out, "what is sent: certistack telemetry show; details: https://certistack.dev/docs/telemetry/")
			return out.deliver(nil)
		},
	}
}

func telemetryShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the exact JSON that would be sent now",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := newCheckedOutput(cmd.OutOrStdout())
			snap, body, err := newTelemetryManager().Show()
			if err != nil {
				return err
			}
			if body == nil && snap.Decision.KeptByEnvironment {
				fmt.Fprintf(out, "this shell sends nothing: %s\n", snap.Decision.Reason)
				return out.deliver(nil)
			}
			if body == nil {
				fmt.Fprintf(out, "nothing is sent: disabled (%s)\n", snap.Decision.Reason)
				return out.deliver(nil)
			}
			out.Write(body)
			if snap.Decision.Environment && !snap.State.HasInstall() {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: CERTISTACK_TELEMETRY is on and no install is kept yet, so this install_id is a sample. The first report makes the real one and keeps it in %s.\n", snap.Path)
			}
			return out.deliver(nil)
		},
	}
}

func telemetryEnableCmd() *cobra.Command {
	var business bool
	cmd := &cobra.Command{
		Use:   "enable [--business]",
		Short: "Opt in to the usage statistics",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := newCheckedOutput(cmd.OutOrStdout())
			manager := newTelemetryManager()
			st, err := manager.Enable(business)
			if err != nil {
				return err
			}
			answer := "no"
			if st.BusinessUse {
				answer = "yes"
			}
			fmt.Fprintf(out, "Telemetry is on. Install id: %s. Business or commercial use: %s.\n", st.InstallID, answer)
			fmt.Fprintln(out, "`certistack telemetry show` prints exactly what is sent; `certistack telemetry disable` turns it off.")
			if decision := manager.Resolve().Decision; !decision.Enabled {
				fmt.Fprintf(out, "Note: nothing is sent in this environment: %s.\n", decision.Reason)
			}
			return out.deliver(nil)
		},
	}
	cmd.Flags().BoolVar(&business, "business", false, "answer yes to \"Do you use CertiStack for a business or commercial purpose?\"")
	return cmd
}

func telemetryDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Opt out; forgets the install id on this machine",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := newCheckedOutput(cmd.OutOrStdout())
			manager := newTelemetryManager()
			forgotten, err := manager.Disable()
			if err != nil {
				return err
			}
			if decision := manager.Resolve().Decision; decision.Environment {
				fmt.Fprintln(out, "The stored answer is now no.")
				writeForgotten(out, forgotten)
				writeEnvironmentStillOn(out, decision)
				return out.deliver(nil)
			}
			fmt.Fprintln(out, "Telemetry is off. Nothing is sent.")
			writeForgotten(out, forgotten)
			return out.deliver(nil)
		},
	}
}

func telemetryResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Delete the state file, if there is one: forget the install id and your answers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := newCheckedOutput(cmd.OutOrStdout())
			manager := newTelemetryManager()
			reset, err := manager.Reset()
			if err != nil {
				return err
			}
			decision := manager.Resolve().Decision
			switch {
			case !reset.Deleted:
				fmt.Fprintf(out, "Nothing to reset: there is no telemetry state file at %s.\n", reset.Path)
			case decision.Environment:
				fmt.Fprintln(out, "The telemetry state file is deleted.")
			default:
				fmt.Fprintln(out, "The telemetry state file is deleted. Telemetry is off until you opt in again, and the first-run question will be asked again.")
			}
			writeForgotten(out, reset.InstallID)
			if decision.Environment {
				writeEnvironmentStillOn(out, decision)
			}
			return out.deliver(nil)
		},
	}
}

// writeEnvironmentStillOn says that a command which turns the report off did
// not, because CERTISTACK_TELEMETRY still turns it on.
func writeEnvironmentStillOn(w io.Writer, decision telemetry.Decision) {
	fmt.Fprintf(w, "Reports are still on: %s. Unset CERTISTACK_TELEMETRY (or set it to 0) to stop them; until then the next report comes from a new install.\n", decision.Reason)
}

func writeForgotten(w io.Writer, installID string) {
	if installID == "" {
		return
	}
	fmt.Fprintf(w, "Forgotten here: install id %s. To have a record the server already holds deleted, send that id to privacy@certistack.dev (see https://certistack.dev/docs/telemetry/).\n", installID)
}

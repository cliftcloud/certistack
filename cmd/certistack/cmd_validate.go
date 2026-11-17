// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/spf13/cobra"
)

func validateCmd() *cobra.Command {
	var (
		planFlag string
		envFile  string
	)

	cmd := &cobra.Command{
		Use:   "validate [plan.yaml | plan-directory]",
		Short: "Parse and validate one or more disaster recovery test plans",
		Args:  cobra.MaximumNArgs(1),
		Long: `Validates one YAML test plan, or every immediate .yaml/.yml file in a directory,
against the CertiStack v1 schema.
Checks all field constraints, CIDR validity, probe requirements,
VMID uniqueness, and framework compliance references.

compliance.sign_key_path is optional: the Community Edition writes its reports
unsigned and does not read it. A plan that sets it is valid, and validate says
in one line that the field is used by the Enterprise Edition.

A valid plan can also get notes, printed with "!" under the summary. A note is
advice, not an error, and the exit status stays 0: a network.ip_range outside
the documentation ranges (plan checks it against the node), a zone_id or
vnet_id that a host bridge also has (vmbr0), an overlay_storage of local or
local-lvm, and a max_host_ram_percent above 95.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			planPath := planFlag
			if len(args) > 0 {
				if planPath != "" {
					return errors.New("pass the plan path either as an argument or via --plan, not both")
				}
				planPath = args[0]
			}
			if planPath == "" {
				return errors.New("plan file or directory is required (pass as argument or via --plan)")
			}

			// Without --env-file, the file certistack setup recorded, unless
			// PVE_URL is set in the process environment.
			chosenEnv, err := resolveControllerEnvFile(envFile)
			if err != nil {
				return err
			}
			envFile = chosenEnv.path
			if envFile != "" {
				restoreEnvironment, err := useCommandEnvironment(envFile, false)
				if err != nil {
					return err
				}
				defer restoreEnvironment()
			}

			planPaths, skipped, err := collectPlanPaths(planPath)
			if err != nil {
				return err
			}
			// A summary that could not be written is not a validation that
			// was reported.
			out := newCheckedOutput(cmd.OutOrStdout())
			for _, entry := range skipped {
				fmt.Fprintf(out, "! not read: %s\n", entry)
			}
			if len(planPaths) > 1 {
				fmt.Fprintf(out, "Validating %d plan files in %s\n", len(planPaths), planPath)
			}

			failed := 0
			var firstError error
			for _, path := range planPaths {
				slog.Debug("validating plan", "path", path)
				plan, loadErr := config.LoadFromFile(path)
				if loadErr != nil {
					failed++
					if firstError == nil {
						firstError = loadErr
					}
					slog.Debug("validation failed", "path", path, "error", loadErr)
					fmt.Fprintf(cmd.ErrOrStderr(), "✗ %s: %v\n", path, loadErr)
					continue
				}
				writePlanSummary(out, path, plan, len(planPaths) > 1)
			}

			if failed > 0 {
				if len(planPaths) == 1 {
					return out.deliver(withExitCode(&planInvalidError{cause: firstError}, exitCodeValidationFailed))
				}
				return out.deliver(withExitCode(fmt.Errorf("plan validation failed: %d of %d plans are invalid", failed, len(planPaths)), exitCodeValidationFailed))
			}
			if len(planPaths) > 1 {
				fmt.Fprintf(out, "✓ Validation complete: %d/%d plans are valid\n", len(planPaths), len(planPaths))
			}
			return out.deliver(nil)
		},
	}

	cmd.Flags().StringVarP(&planFlag, "plan", "p", "", "path to disaster recovery plan YAML or directory")
	cmd.Flags().StringVar(&envFile, "env-file", "", "allowlisted controller environment file to read and check (none of its values changes the plan's validation); values are parsed literally, never shell-sourced (default: the file certistack setup recorded)")
	return cmd
}

// planInvalidError is the error of validate for the one plan it was given that
// does not validate. Its problems were written, with the plan's path, on the
// "✗" line just above the "Error:" line main prints, so the message does not
// say them a second time; the problems stay reachable as the wrapped cause.
type planInvalidError struct{ cause error }

func (e *planInvalidError) Error() string { return "plan validation failed" }
func (e *planInvalidError) Unwrap() error { return e.cause }

// collectPlanPaths returns one plan file, or the immediate YAML files in an
// operator-selected directory, and the YAML entries of the directory it does
// not read, each with the reason. A path named on the command line is read as
// run reads it: a symbolic link to a plan is that plan. In a directory it does
// not recurse or follow links, so validation stays bounded and does not wander
// outside the directory because of an unexpected link; it says which entries
// it left out, so that a directory of plans is never reported valid over
// plans it did not read.
func collectPlanPaths(path string) (paths, skipped []string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect plan path: %w", err)
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("plan path is not a regular file or directory: %s", path)
		}
		return []string{path}, nil, nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read plan directory: %w", err)
	}
	for _, entry := range entries {
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if extension != ".yaml" && extension != ".yml" {
			continue
		}
		entryPath := filepath.Join(path, entry.Name())
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			return nil, nil, fmt.Errorf("inspect plan file %s: %w", entry.Name(), infoErr)
		}
		mode := entryInfo.Mode()
		switch {
		case mode.IsRegular():
			paths = append(paths, entryPath)
		case mode&os.ModeSymlink != 0:
			skipped = append(skipped, entryPath+": a symbolic link, not followed in a directory; validate it by its own path")
		case mode.IsDir():
			skipped = append(skipped, entryPath+": a directory; validate looks only at the files directly in the directory it is given")
		case mode&os.ModeNamedPipe != 0:
			skipped = append(skipped, entryPath+": a FIFO, not a plan file")
		default:
			skipped = append(skipped, entryPath+": not a regular file (a device or socket)")
		}
	}
	sort.Strings(paths)
	sort.Strings(skipped)
	if len(paths) == 0 {
		message := fmt.Sprintf("plan directory contains no immediate .yaml or .yml files: %s", path)
		if len(skipped) > 0 {
			message = fmt.Sprintf("plan directory contains no .yaml or .yml file that validate reads: %s; not read:\n  %s", path, strings.Join(skipped, "\n  "))
		}
		return nil, nil, errors.New(message)
	}
	return paths, skipped, nil
}

func writePlanSummary(writer interface{ Write([]byte) (int, error) }, path string, plan *config.Plan, includePath bool) {
	var totalVMs, totalProbes int
	for _, tier := range plan.Tiers {
		totalVMs += len(tier.VMs)
		for _, vm := range tier.VMs {
			totalProbes += len(vm.Probes)
		}
	}
	if includePath {
		fmt.Fprintf(writer, "✓ %s\n", path)
	} else {
		fmt.Fprintln(writer, "✓ Plan is valid")
	}
	fmt.Fprintf(writer, "  Plan ID:        %s\n", plan.PlanID)
	fmt.Fprintf(writer, "  Name:           %s\n", plan.Name)
	if plan.Environment != "" {
		fmt.Fprintf(writer, "  Environment:    %s\n", plan.Environment)
	}
	fmt.Fprintf(writer, "  Tiers:          %d\n", len(plan.Tiers))
	fmt.Fprintf(writer, "  Ephemeral VMs:  %d\n", totalVMs)
	fmt.Fprintf(writer, "  Probes:         %d\n", totalProbes)
	fmt.Fprintf(writer, "  Network:        %s (zone=%s, vnet=%s)\n", plan.Network.Mode, plan.Network.ZoneID, plan.Network.VNetID)
	fmt.Fprintf(writer, "  Frameworks:     %v\n", plan.Compliance.Frameworks)
	fmt.Fprintf(writer, "  Retention:      %d days\n", plan.Compliance.RetentionDays)
	// Notes are advice about a valid plan, never a reason to refuse it.
	for _, note := range config.PlanNotes(plan) {
		fmt.Fprintf(writer, "  ! %s\n", note)
	}
}

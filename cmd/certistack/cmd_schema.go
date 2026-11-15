// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/spf13/cobra"
)

func schemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Print the JSON Schema of a plan, for editor completion and checks",
		Long: `Prints a JSON Schema (draft 2020-12) for the YAML a plan is written in. An
editor with a YAML language server (VS Code with the Red Hat YAML extension,
Neovim, JetBrains IDEs) then completes a plan's keys, offers the values a key
accepts (probe types, network.mode, network_recovery.mode, compliance
frameworks and so on), shows what each key means, and marks a mistake as it is
typed.

Save it next to a plan and name it on the plan's first line:

    certistack schema > certistack-plan.schema.json

    # yaml-language-server: $schema=./certistack-plan.schema.json

The schema is generated from the same types the plan loader reads, so it always
matches this binary. It describes the file's keys, values and ranges; it does not
replace validate, which also checks what spans keys (an address inside
network.ip_range, a MAC used once, a snapshot of the VM's own backup group). It
reads nothing and sends nothing.`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := newCheckedOutput(cmd.OutOrStdout())
			_, _ = out.Write(config.PlanSchemaJSON())
			return out.deliver(nil)
		},
	}
}

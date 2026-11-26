// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import "github.com/spf13/cobra"

// The commands as the tests build them: with no cleanup context, which only
// the interrupt handler in main supplies.

func rootCmd() *cobra.Command { return newRootCmd(nil) }

func runCmd() *cobra.Command { return runCmdWithCleanupContext(nil) }

func initCmd() *cobra.Command { return initCmdWithCleanupContext(nil) }

func recoverCmd() *cobra.Command { return recoverCmdWithCleanupContext(nil) }

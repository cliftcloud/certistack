// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package recoverhint is the one wording of what an operator does about what an
// interrupted run left on a node, for every message that says it.
//
// A node set up by the documentation has no certistack binary on its PATH. A run
// uploads its worker as <state-dir>/workers/<run>/certistack-node and keeps it
// when cleanup fails; recovery happens when the node's next run starts (it
// recovers before it does anything else), or when the operator runs the kept
// worker's recover subcommand with the arguments the controller prints, as
// docs/troubleshooting.md Issue 26 shows. "certistack recover" is a real
// subcommand of the controller binary, which an operator may install on a node
// by hand, and its own help names it; a message that sends the operator to it
// sends them to a command most nodes do not have.
//
// The package has no imports, so that every package that prints such a message
// can use it without an import cycle. The text holds no % so that it can be
// concatenated into a format string.
package recoverhint

// Guide names the page and entry of docs/troubleshooting.md that give the
// recovery command and when the node recovers by itself.
const Guide = "Troubleshooting, Issue 26"

// Worker is the command an operator runs by hand: the recover subcommand of the
// worker a run kept in its workspace on the node.
const Worker = "the kept worker's certistack-node recover"

// Recover is the instruction for a message about something no recovery has
// settled yet: "...; stop it first, then " + Recover. The node's next run
// recovers before it starts; the kept worker's recover does it at once.
const Recover = "let the node's next run recover, or run " + Worker + " (" + Guide + ")"

// Again is the instruction for a message printed by a recovery that left
// something: what the operator can do about it, and finish with. It is for the
// recovery that ran, whether the node's next run started it or the operator ran
// the printed command.
const Again = "run the same recovery command again, or let the node's next run finish it (" + Guide + ")"

// Recovery names the recovery as the subject of a sentence: "..., and " +
// Recovery + " removes them".
const Recovery = "a recovery on the node (" + Guide + ")"

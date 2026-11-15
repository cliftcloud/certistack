// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"time"

	"github.com/cliftcloud/certistack/internal/support"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// versionReadTimeout bounds the two reads of the node's versions together.
// They are one request to PVE and one to PBS; a node that does not answer in
// this time has versions that are unknown, and the run finds out what is
// wrong with it at its first real call.
const versionReadTimeout = 20 * time.Second

// versionRecord is what a run or a plan learned about the Proxmox versions of
// its node, kept for the report (stamp), the operator (warn) and the plan
// (addToPlan). prepareRun fills it through Options.versions; a prepareRun
// that is replaced in a test leaves it unread, and the report then says
// nothing of the versions.
type versionRecord struct {
	read   bool
	status support.Status
}

// detectVersions reads the node's Proxmox VE version and the PBS client's and
// server's. It is a variable so that a test can give a run a node.
var detectVersions = func(ctx context.Context, pveClient *pve.Client, pbsClient *pbs.Client) support.Status {
	ctx, cancel := context.WithTimeout(ctx, versionReadTimeout)
	defer cancel()
	var sources support.Sources
	if pveClient != nil {
		sources.PVE = pveClient.Version
	}
	if pbsClient != nil {
		sources.PBS = pbsClient.Versions
	}
	return support.Detect(ctx, sources)
}

// gateVersions is what a run and a plan do before they read a backup or
// create anything: read the versions, keep them in opts.versions, and refuse
// a pair the release does not support, in the words doctor fails with. An
// untested pair, or a version that could not be read, is not a refusal; the
// caller says so once.
func gateVersions(ctx context.Context, opts Options, pveClient *pve.Client, pbsClient *pbs.Client) error {
	status := detectVersions(ctx, pveClient, pbsClient)
	if opts.versions != nil {
		*opts.versions = versionRecord{read: true, status: status}
	}
	return status.Refusal()
}

// warn tells the operator, once, that the run goes on with a pair the release
// evidence does not cover. A tested pair needs no word.
func (r *versionRecord) warn() {
	if r == nil || !r.read || r.status.Level == support.Tested {
		return
	}
	progress.Warn("Versions", "%s", r.status.Describe())
}

// stamp records the versions the run read, and what the release makes of
// them, in its report. A run that read none leaves the report without the
// members.
func (r *versionRecord) stamp(report *attest.Report) {
	if r == nil || !r.read {
		return
	}
	report.PVEVersion = r.status.PVE.Raw
	report.PBSVersion = r.status.PBS.Raw
	report.PBSClientVersion = r.status.Client.Raw
	report.VersionSupport = r.status.Verdict()
}

// addToPlan shows the version check first among a plan's checks, and says in
// the plan's warnings what a run would warn about when the pair is not
// tested.
func (r *versionRecord) addToPlan(plan *orchestrator.RunPlan) {
	if r == nil || !r.read || plan == nil {
		return
	}
	status := r.status
	step := orchestrator.PlanStep{
		Phase:  "checks",
		Action: orchestrator.PlanCheck,
		Kind:   "versions",
		Target: "PVE " + status.PVE.String() + ", PBS " + status.PBS.String() + ", proxmox-backup-client " + status.Client.String(),
		Detail: status.Verdict() + " (" + status.Reason + ")",
		Status: orchestrator.StatusOK,
	}
	if status.Level != support.Tested {
		step.Status = orchestrator.StatusWarning
		plan.Warnings = append(plan.Warnings, status.Describe())
	}
	plan.Steps = append([]orchestrator.PlanStep{step}, plan.Steps...)
}

//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"context"

	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/config"
)

// CheckItem represents an individual preflight check outcome.
type CheckItem struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "passed", "failed", "warning", "skipped"
	Detail string `json:"detail"`
}

// Result encapsulates all preflight check outcomes.
type Result struct {
	Ready            bool                  `json:"ready"`
	Checks           []CheckItem           `json:"checks"`
	MemoryEvaluation *admission.Evaluation `json:"memory_evaluation,omitempty"`
	Versions         *VersionReport        `json:"versions,omitempty"`
}

// Options configures optional preflight checks.
type Options struct {
	ScratchDir             string
	StateDir               string
	RequiredRAMMB          int
	MinimumFreeGiB         int
	PVEURL                 string
	PVETLSInsecure         bool
	PVETLSCAFile           string
	PVETokenID             string
	PVETokenSecret         string
	RequirePVEConnectivity bool
	WorkerMode             bool
	PBSKeyfile             string
	PBSEncryptionPassword  string
	NodeName               string
	OverlayStorage         string
}

func Check(ctx context.Context, plan *config.Plan, opts Options) Result {
	return Result{
		Ready: true,
		Checks: []CheckItem{
			{Name: "Platform", Status: "passed", Detail: "Non-Linux platform (development mode)"},
		},
	}
}

func SafePath(path string) error {
	return sysutil.ValidatePrivateDirectory(path)
}

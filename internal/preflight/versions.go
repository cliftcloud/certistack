// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import "github.com/cliftcloud/certistack/internal/support"

// VersionCheckName names the check that reports the Proxmox versions and
// whether this release has been tested with them.
const VersionCheckName = "version_support"

// VersionReport is the Proxmox versions a preflight found, in doctor's JSON
// (the "versions" member of the result). A version it could not read is
// "unknown". Support is the status's verdict: "tested", "untested",
// "unsupported", or "unknown" when a version could not be read.
type VersionReport struct {
	PVE       string `json:"pve"`
	PBS       string `json:"pbs"`
	PBSClient string `json:"pbs_client"`
	Support   string `json:"support"`
	Reason    string `json:"reason"`
}

// versionCheck is the check line and the JSON member for status: passed when
// the pair is tested, a warning when it is untested or a version could not be
// read, failed when it is unsupported. The failure's detail is the text run
// and plan refuse with.
func versionCheck(status support.Status) (CheckItem, *VersionReport) {
	item := CheckItem{Name: VersionCheckName, Status: "passed", Detail: status.Describe()}
	switch status.Level {
	case support.Unsupported:
		item.Status = "failed"
	case support.Untested:
		item.Status = "warning"
	}
	return item, &VersionReport{
		PVE:       status.PVE.String(),
		PBS:       status.PBS.String(),
		PBSClient: status.Client.String(),
		Support:   status.Verdict(),
		Reason:    status.Reason,
	}
}

// applyVersionStatus adds the version check to r. Only an unsupported pair
// makes the host not ready; an untested one, and a version that could not be
// read, are warnings.
func applyVersionStatus(r *Result, status support.Status) {
	item, report := versionCheck(status)
	r.Checks = append(r.Checks, item)
	r.Versions = report
	if status.Level == support.Unsupported {
		r.Ready = false
	}
}

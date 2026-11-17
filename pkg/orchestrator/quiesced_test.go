// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// A VM that requires a quiesced backup fails before anything is
// restored, and its record still says how consistent the backup was.
func TestBootRefusesAnUnquiescedBackupTheVMRequires(t *testing.T) {
	o := &Orchestrator{} // any step past the refusal would need a PVE client
	vm := config.VM{VMID: 9001, Name: "db", RequireQuiescedBackup: true,
		SourceConsistency: pbs.ConsistencyCrash, SourceConsistencyDetail: "fsfreeze failed"}
	record, err := o.bootAndVerifyVM(context.Background(), vm, 60, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "the plan requires a quiesced backup") {
		t.Fatalf("err = %v, want the quiesced-backup refusal", err)
	}
	if record == nil || record.SourceConsistency != pbs.ConsistencyCrash || record.SourceConsistencyDetail != "fsfreeze failed" {
		t.Fatalf("record = %+v, want the backup's consistency", record)
	}
}

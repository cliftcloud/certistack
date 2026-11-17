// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

func TestAutoCopyRefusesUnknownDiskSafety(t *testing.T) {
	o := &Orchestrator{
		deviceBytesFn: func(string) (int64, error) { return 48 << 30, nil },
		freeBytesFn:   func(string) (int64, error) { return 500 << 30, nil },
		sharedDisksFn: func(context.Context, string, string) ([]string, error) {
			return nil, errors.New("cannot resolve cluster disk")
		},
		tierCache: tierCache{budgetKnown: true, budgetBytes: 35 << 30},
	}
	vm := config.VM{VMID: 9001}
	copied, err := o.chooseCopyBeforeBoot(context.Background(), vm, []string{"/dev/loop0"}, "/scratch")
	if err != nil || copied || o.copiedBytes != 0 {
		t.Fatalf("unknown topology: copied %v, bytes %d, error %v", copied, o.copiedBytes, err)
	}
	if warning, err := o.overlayClusterDiskWarning(context.Background(), "/scratch"); err != nil || !strings.Contains(warning, "cannot resolve cluster disk") {
		t.Fatalf("topology error was not explained: %q", warning)
	}
	vm.CopyBeforeBoot = config.CopyBeforeBootAlways
	if copied, err := o.chooseCopyBeforeBoot(context.Background(), vm, []string{"/dev/loop0"}, "/scratch"); err != nil || !copied {
		t.Fatalf("explicit always policy: copied %v, error %v", copied, err)
	}
}

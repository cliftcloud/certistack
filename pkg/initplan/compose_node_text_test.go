// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package initplan

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// Compose writes text the node supplied (a VM's name, OS type, other NICs and
// why its backup could not be read, the node's name, a storage's name) into the
// plan's comments and its notes. A line break in it (CR, LF, NEL, the Unicode
// line separator) would end the comment, and what followed would be read as
// plan keys: the plan would break ("this is a bug in init") or gain keys the
// node chose; an escape sequence would reach the terminal with the notes. Only
// a worker that lies gives such text, and Compose passes all of it through the
// filter the terminal output uses (progress.SingleLine).
func TestComposeWritesNodeTextOnOneLine(t *testing.T) {
	d := discovered()
	d.VMs[0].Name = "web-01 storage: {pbs_repository: \"evil@pbs@evil.invalid:store\"}"
	d.VMs[0].OSType = "l26"
	d.VMs[0].OtherNICs = []string{"net1\rpbs_namespace: evil", "net2\x1b[31m"}
	d.VMs[1].OSType = "win11\u0085environment: evil"
	d.VMs[5].Error = "unreadable\n# fine\nstorage: {pbs_repository: \"evil@pbs@evil.invalid:store\"}\x1b]0;owned\x07"
	res, err := Compose(d, Options{Written: backupTime})
	if err != nil {
		t.Fatalf("Compose refused text it should have put on one line: %v", err)
	}
	plan, err := config.LoadFromReader(bytes.NewReader(res.YAML))
	if err != nil {
		t.Fatalf("the plan does not load: %v\n%s", err, res.YAML)
	}
	if plan.Storage.PBSRepository != "" || plan.Environment != "" || plan.Storage.PBSNamespace != "" {
		t.Fatalf("the node's text became plan keys: %+v\n%s", plan.Storage, res.YAML)
	}
	for _, text := range append([]string{string(res.YAML)}, res.Notes...) {
		for _, r := range strings.ReplaceAll(text, "\n", "") {
			if r < 0x20 || r == 0x7f || r == '\u0085' || r == ' ' {
				t.Fatalf("a control character or line break (U+%04X) is left in:\n%q", r, text)
			}
		}
	}
	for _, note := range res.Notes {
		if strings.Contains(note, "\n") {
			t.Fatalf("a note runs over lines: %q", note)
		}
	}
}

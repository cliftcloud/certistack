// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package envtypes

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// The names here are the ones the rest of the product reads.
func TestNamesMatchTheirReaders(t *testing.T) {
	if InsecureTLSLabOpt != pve.InsecureTLSLabOptInEnv || ProgressEvents != progress.EnvironmentEvents {
		t.Fatalf("names drifted: %s %s", InsecureTLSLabOpt, ProgressEvents)
	}
}

// Each typed variable is checked with the rule its reader applies, and
// the message names what is accepted.
func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string // want "" means accepted
	}{
		{SSHPort, "22", ""}, {SSHPort, "65535", ""}, {SSHPort, "0", "not a port"}, {SSHPort, "65536", "not a port"}, {SSHPort, "22abc", "not a port"}, {SSHPort, "-1", "not a port"}, {SSHPort, "+22", "not a port"},
		{SSHSudo, "true", ""}, {SSHSudo, "No", ""}, {SSHSudo, "treu", "not a yes or no value"},
		{InsecureTLS, "true", ""}, {InsecureTLS, "0", ""}, {InsecureTLS, "no", "use true or false"}, {InsecureTLS, "yes", "use true or false"}, {InsecureTLS, "on", "use true or false"},
		{InsecureTLSLabOpt, "TRUE", ""}, {InsecureTLSLabOpt, "on", "use true or false"},
		{AllowTestMode, "1", ""}, {AllowTestMode, "true", "only 1 turns it on"},
		{ProgressEvents, "0", ""}, {ProgressEvents, "yes", "only 1 turns it on"},
		{"PVE_URL", "anything", ""}, {SSHPort, "", ""},
	} {
		err := Check(tc.name, tc.value)
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("Check(%s, %q) = %v, want %q", tc.name, tc.value, err, tc.want)
		}
	}
}

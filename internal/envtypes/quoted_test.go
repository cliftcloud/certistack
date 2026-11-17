// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package envtypes

import (
	"strings"
	"testing"
)

// A secret pasted into the wrong line (the mistake layer 1 exists for) must not
// be printed with the message. A message shows a value only when it is short
// and made of what a host name, an address, a port or a yes or no is made of,
// and cannot be a credential; otherwise it says how long the value is.
func TestQuotedShowsOnlyValuesThatCannotBeACredential(t *testing.T) {
	for _, tc := range []struct {
		value string
		shown bool
	}{
		{"yes", true},
		{"22 # my port", true},
		{"abc", true},
		{"pve1.example.com", true},
		{"root@10.42.20.36", true},
		{"[fd00::1]", true},
		{"a/b", true},
		{"proxmox-node-01.corp.example.net", true}, // 32 characters, dotted: a host name
		{"u@r!CANARYsecret9Zx=CANARYsecret9Zx", false},
		{"PVEAPIToken=CANARYsecret9Zx", false},
		{"3f2b6c1e-8a44-4b0e-9d1f-0c5a7e2d9b11", false}, // a PVE token secret
		{"CANARYsecret9Zx4Ab7Cd8Ef", false},             // one unbroken run of letters and digits
		{"hunter2!", false},
		{"pass word=1", false},
		{strings.Repeat("a", 41), false},
		{"", true},
	} {
		got := Quoted(tc.value)
		if tc.shown && got != `"`+tc.value+`"` {
			t.Errorf("Quoted(%q) = %s, want the value shown", tc.value, got)
		}
		if !tc.shown {
			if strings.Contains(got, tc.value) || strings.Contains(got, "CANARY") || strings.Contains(got, "hunter2") {
				t.Errorf("Quoted(%q) = %s, which shows the value", tc.value, got)
			}
			if !strings.Contains(got, "characters") || !strings.Contains(got, "not shown") {
				t.Errorf("Quoted(%q) = %s, want its length and that it is not shown", tc.value, got)
			}
		}
	}
}

// The typed variables' messages never show the value, however plain: a short
// password pasted into the wrong line can look like a word. They say what is
// wrong with it, and keep the guidance.
func TestCheckMessagesNeverShowTheValue(t *testing.T) {
	for value, want := range map[string]string{
		"abc":    "it holds 3 characters other than a digit",
		"220000": "it has 6 digits",
		"0":      "it is outside 1 to 65535",
		"70000":  "it is outside 1 to 65535",
	} {
		err := Check(SSHPort, value)
		if err == nil || strings.Contains(err.Error(), `"`+value+`"`) || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), portGuidance) {
			t.Errorf("port %q: %v, want %q and the guidance, without the value", value, err, want)
		}
	}
	for _, name := range []string{SSHPort, SSHSudo, InsecureTLS, InsecureTLSLabOpt, ProgressEvents, AllowTestMode} {
		if err := Check(name, "Zq7Secret"); err == nil || strings.Contains(err.Error(), "Zq7Secret") {
			t.Errorf("%s showed a short pasted password: %v", name, err)
		}
		err := Check(name, "u@r!CANARYsecret9Zx=CANARYsecret9Zx")
		if err == nil {
			t.Fatalf("%s accepted a token", name)
		}
		if strings.Contains(err.Error(), "CANARY") {
			t.Errorf("%s printed the pasted secret: %v", name, err)
		}
	}
	for _, parse := range []func(string) error{
		func(v string) error { _, err := ParsePort(v); return err },
		func(v string) error { _, err := ParseBoolean(v); return err },
	} {
		if err := parse("CANARYsecret9Zx4Ab7Cd8Ef"); err == nil || strings.Contains(err.Error(), "CANARY") {
			t.Errorf("a parser printed or accepted a pasted secret: %v", err)
		}
	}
}

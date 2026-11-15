// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"
)

// Review R2-07. The documentation said that values are never printed; the typed
// variables (a port, a yes or no) and the SSH host and user named the whole
// value in their messages, so a secret pasted into the wrong line was printed
// with it. The claim that holds now is: the value of a line is never printed
// in a refusal (IN-08). This test pastes a secret into every line a newcomer
// could, in the forms a secret takes, and finds it in no message.

// pastedSecrets are credentials in the shapes people paste them in. Each holds a
// canary that must not appear in any output.
var pastedSecrets = []string{
	"3f2b6c1e-8a44-4b0e-9d1f-0c5a7e2d9b11",                // a PVE token secret
	"u@r!CANARYsecret9ZxQ7vLm2Rk=CANARYsecret9ZxQ7vLm2Rk", // token id with the secret appended
	"PVEAPIToken=CANARYsecret9ZxQ7vLm2Rk",                 // the header form
	"https://root:CANARYsecret9ZxQ7vLm2Rk@pve.example.invalid:8006",
	"CANARYsecret9ZxQ7vLm2Rk@pbs.example.invalid:8007:store",
	"CANARYsecret9ZxQ7vLm2Rk",       // a bare token of letters and digits
	"CANARY secret 9ZxQ7vLm2Rk!",    // a passphrase
	`"CANARYsecret9ZxQ7vLm2Rk`,      // an unterminated quote
	"CANARYsecret9ZxQ7vLm2Rk # old", // with a comment
}

func TestNoPastedSecretIsEchoedByAnyLineOfTheControllerFile(t *testing.T) {
	variables := []string{
		"PVE_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET", "PBS_REPOSITORY", "PBS_PASSWORD", "PBS_FINGERPRINT", "PBS_NAMESPACE",
		"PBS_ENCRYPTION_PASSWORD", "CERTISTACK_API_TOKEN", "CERTISTACK_NODE", "CERTISTACK_SSH_HOST", "CERTISTACK_SSH_USER",
		"CERTISTACK_SSH_PORT", "CERTISTACK_SSH_SUDO", "PVE_TLS_INSECURE", "CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB",
		"CERTISTACK_PROGRESS_EVENTS", "CERTISTACK_ALLOW_TEST_MODE",
	}
	// The node's name, the SSH host and the account are settings, not secrets: when
	// what is pasted in them is a valid name, it is used and shown (the fix of layer
	// 2 is a command with the host in it, to be copied). A secret that is not shaped
	// like a name is refused at layer 1, and never shown.
	shownWhenValid := map[string]bool{"CERTISTACK_NODE": true, "CERTISTACK_SSH_HOST": true, "CERTISTACK_SSH_USER": true}
	for _, variable := range variables {
		for _, secret := range pastedSecrets {
			text := environmentWith(variable + "=" + secret)
			out, _ := runLayer1(t, text, 0o600)
			if shownWhenValid[variable] && strings.Contains(out, "✓ 1. Environment file") {
				continue
			}
			for _, canary := range []string{"CANARY", "3f2b6c1e", secret} {
				if strings.Contains(out, canary) {
					t.Errorf("%s=%s: layer 1 printed %q:\n%s", variable, secret, canary, out)
				}
			}
		}
	}
}

// What a person mistypes in a plain line is described, never shown: a short
// password pasted into the wrong line looks like a mistyped word (IN-08 of the
// 2026-11-15 chaos audit, which replaced R2-07's rule of showing a plain value).
func TestAPlainMistakeInATypedOrSSHLineIsDescribedNotShown(t *testing.T) {
	for _, tc := range []struct{ line, value, want string }{
		{"CERTISTACK_SSH_PORT=22a", "22a", "is not a port: it holds a character other than a digit"},
		{"CERTISTACK_SSH_SUDO=maybe", "maybe", "is not a yes or no value (5 characters long)"},
		{"PVE_TLS_INSECURE=yes", "yes", "is not true or false (3 characters long)"},
		{"CERTISTACK_ALLOW_TEST_MODE=true", "true", "is not 0 or 1 (4 characters long)"},
		{"CERTISTACK_SSH_PORT=Zq7SecretValueKx9", "Zq7SecretValueKx9", "is not a port"},
		{"CERTISTACK_NODE=Zq7Secret.example", "Zq7Secret", "contains a dot"},
		{"CERTISTACK_SSH_HOST=Zq7Secret:2222", "2222", "put the port in CERTISTACK_SSH_PORT"},
		{"PBS_REPOSITORY=u@pbs!t@Zq7Secret:8007", "Zq7Secret", "has no datastore"},
		{"PVE_URL=Zq7secret://pve1:8006", "Zq7secret", "scheme"},
	} {
		out, _ := runLayer1(t, environmentWith(tc.line), 0o600)
		if !strings.Contains(out, tc.want) || strings.Contains(out, tc.value) {
			t.Errorf("%s: output lacks %q, or shows %q:\n%s", tc.line, tc.want, tc.value, out)
		}
	}
}

// The SSH host and user are judged at layer 1 by the rule that layer 2 applies,
// so a value that cannot be one is not found only after the SSH steps.
func TestLayer1JudgesTheSSHHostAndUserAsLayer2Does(t *testing.T) {
	for _, tc := range []struct {
		line string
		pass bool
		want string
	}{
		{"CERTISTACK_SSH_HOST=pve1/etc", false, "line 7, CERTISTACK_SSH_HOST:"},
		{"CERTISTACK_SSH_HOST=-oProxyCommand=x", false, "line 7, CERTISTACK_SSH_HOST:"},
		{"CERTISTACK_SSH_HOST=pve_1", false, "line 7, CERTISTACK_SSH_HOST:"},
		{"CERTISTACK_SSH_HOST=[fd00::36]", false, "line 7, CERTISTACK_SSH_HOST:"},
		{"CERTISTACK_SSH_HOST=a[b", false, "line 7, CERTISTACK_SSH_HOST:"},
		{"CERTISTACK_SSH_HOST=a]b", false, "line 7, CERTISTACK_SSH_HOST:"},
		{"CERTISTACK_SSH_HOST=pve1.example.com", true, ""},
		{"CERTISTACK_SSH_HOST=fe80::1", true, ""},
		{"CERTISTACK_SSH_HOST=fd00::36", true, ""},
		{"CERTISTACK_SSH_HOST=10.42.20.36", true, ""},
		{"CERTISTACK_SSH_USER=root user", false, "line 8, CERTISTACK_SSH_USER:"},
		{"CERTISTACK_SSH_USER=1root", false, "line 8, CERTISTACK_SSH_USER:"},
		{"CERTISTACK_SSH_USER=ro!ot", false, "line 8, CERTISTACK_SSH_USER:"},
		{"CERTISTACK_SSH_USER=" + strings.Repeat("a", 33), false, "line 8, CERTISTACK_SSH_USER:"},
		{"CERTISTACK_SSH_USER=root@pve1", false, "line 8, CERTISTACK_SSH_USER:"},
		{"CERTISTACK_SSH_USER=certistack-svc", true, ""},
		{"CERTISTACK_SSH_USER=_svc", true, ""},
	} {
		out, err := runLayer1(t, environmentWith(tc.line), 0o600)
		passed := strings.Contains(out, "✓ 1. Environment file")
		switch {
		case tc.pass && !passed:
			t.Errorf("%s: layer 1 failed (%v):\n%s", tc.line, err, out)
		case !tc.pass && passed:
			t.Errorf("%s: layer 1 passed:\n%s", tc.line, out)
		case !tc.pass && !strings.Contains(out, tc.want):
			t.Errorf("%s: output lacks %q:\n%s", tc.line, tc.want, out)
		}
	}
}

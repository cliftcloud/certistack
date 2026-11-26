// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/controller"
)

// The commands a hint prints are copied and pasted, and a path the user
// supplied can hold a space, so each path is one shell word (the
// bracketed [host]:port of ssh-keygen -R is a pattern to zsh, which refuses it
// unquoted).
func TestSSHFailureHintQuotesEveryPathItPrints(t *testing.T) {
	cfg := controller.SSHConfig{Host: "pve.example.com", User: "root", Port: 2222, IdentityFile: "/my keys/id_ed25519", KnownHostsFile: "/my keys/known_hosts"}
	for _, tc := range []struct {
		name, text string
		want       []string
	}{
		{"not recorded", "Host key verification failed.", []string{"--known-hosts '/my keys/known_hosts'"}},
		{"changed", "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", []string{"ssh-keygen -R '[pve.example.com]:2222' -f '/my keys/known_hosts'", "--known-hosts '/my keys/known_hosts'"}},
		{"permissions", "Permissions 0644 for '/my keys/id_ed25519' are too open.", []string{"chmod 600 '/my keys/id_ed25519'"}},
		{"key refused", "Permission denied (publickey).", []string{"-o UserKnownHostsFile='/my keys/known_hosts'", "-i '/my keys/id_ed25519.pub'"}},
	} {
		hint := sshFailureHint(errors.New(tc.text), cfg)
		for _, want := range tc.want {
			if !strings.Contains(hint, want) {
				t.Errorf("%s: the hint lacks %q:\n%s", tc.name, want, hint)
			}
		}
	}
}

// Each case is OpenSSH's own wording for a failure a first-time user meets,
// and what the operator is told to do about it.
func TestSSHFailureHintReadsOpenSSHsWords(t *testing.T) {
	cfg := controller.SSHConfig{Host: "pve.example.com", User: "certistack", Port: 22, IdentityFile: "/secure/certistack/id_ed25519", KnownHostsFile: "/secure/certistack/known_hosts"}
	for _, c := range []struct {
		name string
		text string
		cfg  controller.SSHConfig
		want []string
		not  []string
	}{
		{
			"host key not recorded",
			"ssh failed: exit status 255: No ED25519 host key is known for pve.example.com and you have requested strict checking.\nHost key verification failed.",
			cfg,
			[]string{"is not in /secure/certistack/known_hosts", "certistack setup trust-node --host pve.example.com --known-hosts /secure/certistack/known_hosts"},
			[]string{"impersonated"},
		},
		{
			"host key changed",
			"ssh failed: exit status 255: @@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.",
			controller.SSHConfig{Host: "pve.example.com", User: "root", Port: 2222, KnownHostsFile: "/k/known_hosts"},
			[]string{"impersonated", "ssh-keygen -R '[pve.example.com]:2222' -f /k/known_hosts", "setup trust-node --host pve.example.com --port 2222"},
			[]string{"is not in /k/known_hosts"},
		},
		{
			"key refused",
			"ssh failed: exit status 255: certistack@pve.example.com: Permission denied (publickey,password).",
			cfg,
			[]string{`account "certistack"`, "root exists", "ssh-copy-id", "/secure/certistack/id_ed25519.pub certistack@pve.example.com"},
			nil,
		},
		{
			"key permissions",
			"ssh failed: exit status 255: Permissions 0644 for '/secure/certistack/id_ed25519' are too open.\nLoad key \"/secure/certistack/id_ed25519\": bad permissions\ncertistack@pve: Permission denied (publickey).",
			cfg,
			[]string{"chmod 600 /secure/certistack/id_ed25519"},
			[]string{"ssh-copy-id"},
		},
		{
			"refused",
			"ssh failed: exit status 255: ssh: connect to host pve.example.com port 2222: Connection refused",
			controller.SSHConfig{Host: "pve.example.com", Port: 2222},
			[]string{"pve.example.com port 2222", "sshd"},
			nil,
		},
		{
			"unknown name",
			"ssh failed: exit status 255: ssh: Could not resolve hostname pve.example.com: Name or service not known",
			cfg,
			[]string{`cannot resolve "pve.example.com"`},
			nil,
		},
		{
			"timeout",
			"ssh failed: exit status 255: ssh: connect to host pve.example.com port 22: Connection timed out",
			cfg,
			[]string{"does not answer", "firewall"},
			nil,
		},
		{
			"no ssh client",
			`exec: "ssh": executable file not found in $PATH`,
			cfg,
			[]string{"apt install openssh-client"},
			nil,
		},
		{
			"sudo needs a password",
			"ssh failed: exit status 1: sudo: a password is required",
			cfg,
			[]string{"passwordless sudo"},
			nil,
		},
		// known_hosts is looked up by exactly the spelling in CERTISTACK_SSH_HOST:
		// the node recorded under its name is not found by its address, and the
		// reverse, and the line that is found for the other spelling may be an old
		// one for another machine.
		{
			"host key changed, the host given as an address",
			"ssh failed: exit status 255: @@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.",
			controller.SSHConfig{Host: "192.0.2.7", User: "root", Port: 22, KnownHostsFile: "/k/known_hosts"},
			[]string{
				"exactly the spelling in CERTISTACK_SSH_HOST",
				"an IP address (192.0.2.7)",
				"under its host name",
				"set CERTISTACK_SSH_HOST to the host name you recorded",
				"certistack setup trust-node --host 192.0.2.7 --known-hosts /k/known_hosts",
			},
			nil,
		},
		{
			"host key changed, the host given as a name",
			"ssh failed: exit status 255: @@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.",
			controller.SSHConfig{Host: "pve.example.com", User: "root", Port: 22, KnownHostsFile: "/k/known_hosts"},
			[]string{
				"exactly the spelling in CERTISTACK_SSH_HOST",
				"a host name (pve.example.com)",
				"under its IP address",
				"set CERTISTACK_SSH_HOST to the IP address you recorded",
				"certistack setup trust-node --host pve.example.com --known-hosts /k/known_hosts",
			},
			nil,
		},
		{
			"host key changed, the host given as a bracketed IPv6 address",
			"ssh failed: exit status 255: @@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.",
			controller.SSHConfig{Host: "[fd00::7]", User: "root", Port: 2222, KnownHostsFile: "/k/known_hosts"},
			[]string{"an IP address ([fd00::7])", "certistack setup trust-node --host [fd00::7] --port 2222 --known-hosts /k/known_hosts"},
			nil,
		},
		{
			"host key not recorded, the host given as an address",
			"ssh failed: exit status 255: No ED25519 host key is known for 192.0.2.7 and you have requested strict checking.\nHost key verification failed.",
			controller.SSHConfig{Host: "192.0.2.7", User: "root", Port: 22, KnownHostsFile: "/k/known_hosts"},
			[]string{
				"exactly the spelling in CERTISTACK_SSH_HOST",
				"an IP address (192.0.2.7)",
				"under its host name",
				"certistack setup trust-node --host 192.0.2.7 --known-hosts /k/known_hosts",
			},
			[]string{"impersonated"},
		},
		{
			"host key not recorded, the host given as a name",
			"ssh failed: exit status 255: No ED25519 host key is known for pve.example.com and you have requested strict checking.\nHost key verification failed.",
			controller.SSHConfig{Host: "pve.example.com", User: "root", Port: 22, KnownHostsFile: "/k/known_hosts"},
			[]string{"a host name (pve.example.com)", "under its IP address", "certistack setup trust-node --host pve.example.com --known-hosts /k/known_hosts"},
			[]string{"impersonated"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			hint := sshFailureHint(errors.New(c.text), c.cfg)
			for _, want := range c.want {
				if !strings.Contains(hint, want) {
					t.Errorf("hint lacks %q:\n%s", want, hint)
				}
			}
			for _, not := range c.not {
				if strings.Contains(hint, not) {
					t.Errorf("hint contains %q:\n%s", not, hint)
				}
			}
		})
	}
	if hint := sshFailureHint(errors.New("something nobody foresaw"), cfg); hint != "" {
		t.Errorf("an unrecognized failure got the hint %q", hint)
	}
	if hint := sshFailureHint(nil, cfg); hint != "" {
		t.Errorf("no error got the hint %q", hint)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/pkg/controller"
)

// trustNodeCommand is the command that records cfg's host key, with the port
// only when it is not 22.
func trustNodeCommand(cfg controller.SSHConfig) string {
	command := "certistack setup trust-node --host " + cfg.Host
	if cfg.Port != 0 && cfg.Port != 22 {
		command += " --port " + strconv.Itoa(cfg.Port)
	}
	if cfg.KnownHostsFile != "" {
		command += " --known-hosts " + quotedPath(cfg.KnownHostsFile)
	}
	return command
}

// sshFailureHint says what to do about a failed SSH connection, read from
// OpenSSH's own words in err. It returns "" for a failure it does not
// recognise, which the caller then shows as it is.
func sshFailureHint(err error, cfg controller.SSHConfig) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	port := cfg.Port
	if port == 0 {
		port = 22
	}
	account := cfg.User
	if account == "" {
		account = "certistack"
	}
	switch {
	case strings.Contains(text, "REMOTE HOST IDENTIFICATION HAS CHANGED"), strings.Contains(text, "host key for") && strings.Contains(text, "has changed"):
		name := cfg.Host
		if port != 22 {
			name = "[" + cfg.Host + "]:" + strconv.Itoa(port)
		}
		return fmt.Sprintf("The host key the node presents is not the one recorded in %s. A reinstalled node looks like this, and so does an impersonated one. If you know the node was rebuilt, read its new fingerprint on the node (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub), remove the old line (ssh-keygen -R %s -f %s) and run: %s",
			cfg.KnownHostsFile, quotedPath(name), quotedPath(cfg.KnownHostsFile), trustNodeCommand(cfg)) + otherSpellingNote(cfg)
	case strings.Contains(text, "host key is known for"), strings.Contains(text, "Host key verification failed"):
		return fmt.Sprintf("The node's host key is not in %s, and strict host-key checking is always on. Record it after you have compared its fingerprint with the node's: %s", cfg.KnownHostsFile, trustNodeCommand(cfg)) + otherSpellingNote(cfg)
	case strings.Contains(text, "UNPROTECTED PRIVATE KEY"), strings.Contains(text, "bad permissions"), strings.Contains(text, "are too open"):
		return fmt.Sprintf("ssh refuses a private key other users can read. Run: chmod 600 %s", quotedPath(cfg.IdentityFile))
	case strings.Contains(text, "Permission denied (publickey"), strings.Contains(text, "Permission denied (password"):
		return fmt.Sprintf("The node does not accept the key for the account %q (CERTISTACK_SSH_USER, default certistack, which a stock Proxmox VE node does not have: root exists). The account must exist on the node and hold the public key of the identity %s in its authorized_keys: ssh-copy-id -o UserKnownHostsFile=%s -o StrictHostKeyChecking=yes -i %s %s@%s",
			account, valueOr(cfg.IdentityFile, "(CERTISTACK_SSH_IDENTITY is not set)"), quotedPath(cfg.KnownHostsFile), publicKeyArgument(cfg.IdentityFile), account, cfg.Host)
	case strings.Contains(text, "Connection refused"):
		return fmt.Sprintf("Nothing accepts connections on %s port %d. Check that sshd runs on the node and that CERTISTACK_SSH_HOST and CERTISTACK_SSH_PORT are right.", cfg.Host, port)
	case strings.Contains(text, "Could not resolve hostname"), strings.Contains(text, "Name or service not known"), strings.Contains(text, "Temporary failure in name resolution"):
		return fmt.Sprintf("This controller cannot resolve %q. Fix CERTISTACK_SSH_HOST, or the controller's DNS.", cfg.Host)
	case strings.Contains(text, "Connection timed out"), strings.Contains(text, "No route to host"), strings.Contains(text, "Network is unreachable"), strings.Contains(text, "Operation timed out"):
		return fmt.Sprintf("%s port %d does not answer from this controller. Check the address, the network path and any firewall between them.", cfg.Host, port)
	case strings.Contains(text, "executable file not found"):
		return "The OpenSSH client (ssh and scp) is not installed on this controller. On Debian or Ubuntu: sudo apt install openssh-client"
	case strings.Contains(text, "a password is required"), strings.Contains(text, "sudo: not found"), strings.Contains(text, "sudo: command not found"):
		return fmt.Sprintf("CERTISTACK_SSH_SUDO is on, but %q cannot run sudo without a password on the node (or the node has no /usr/bin/sudo). Use root, or give the account passwordless sudo as in the SSH setup guide.", account)
	}
	return ""
}

// otherSpellingNote is the sentence that follows a host key failure: ssh finds
// a node in known_hosts by exactly the spelling in CERTISTACK_SSH_HOST, so a node
// recorded under its host name is not found by its address, nor one recorded
// under its address by its name, and the line that is found for this spelling
// may be an old one for another machine. The command that records this
// spelling, exactly as CERTISTACK_SSH_HOST says it, is in the sentence before.
func otherSpellingNote(cfg controller.SSHConfig) string {
	if cfg.Host == "" {
		return ""
	}
	if net.ParseIP(strings.Trim(cfg.Host, "[]")) != nil {
		return fmt.Sprintf(" known_hosts is looked up by exactly the spelling in CERTISTACK_SSH_HOST, an IP address (%s) here: if the node is recorded under its host name, that line is not used for the address, and a line found for the address may be an old one for another machine. Either set CERTISTACK_SSH_HOST to the host name you recorded, or record this spelling with the command above.", cfg.Host)
	}
	return fmt.Sprintf(" known_hosts is looked up by exactly the spelling in CERTISTACK_SSH_HOST, a host name (%s) here: if the node is recorded under its IP address, that line is not used for the name, and a line found for the name may be an old one for another machine. Either set CERTISTACK_SSH_HOST to the IP address you recorded, or record this spelling with the command above.", cfg.Host)
}

// publicKeyArgument is the public key beside the identity, as one shell word.
func publicKeyArgument(identity string) string {
	if identity == "" {
		return "<identity>.pub"
	}
	return quotedPath(identity + ".pub")
}

// quotedPath is path as one shell word, and an empty path as nothing.
func quotedPath(path string) string {
	if path == "" {
		return ""
	}
	return quoteForShell(path)
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

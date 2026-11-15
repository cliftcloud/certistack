// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/nodesetup"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// fetchPVECA reads the node's PVE cluster CA file over the controller's SSH
// access. It is a variable so that a test gives the command a node without SSH.
var fetchPVECA = func(ctx context.Context, cfg controller.SSHConfig) ([]byte, error) {
	return controller.NewExecutor().ReadNodeFile(ctx, cfg, nodesetup.PVERootCAPath, pve.MaxCAFileBytes)
}

// defaultCAFileName is the CA file's name next to the environment file.
const defaultCAFileName = "pve-root-ca.pem"

func setupPVECACmd() *cobra.Command {
	var envFile, out string
	cmd := &cobra.Command{
		Use:   "pve-ca --env-file FILE [--out FILE]",
		Short: "Fetch the PVE cluster CA from the node and print the line that makes the controller trust it",
		Long: `A stock Proxmox VE node serves its API with a certificate signed by the
cluster's own CA, which no system trust store holds, so init, plan and run stop
with "x509: certificate signed by unknown authority" until
CERTISTACK_PVE_CA_SOURCE names that CA. This command fetches
` + nodesetup.PVERootCAPath + ` from the node over the same SSH access run uses
(the identity, known_hosts file, account and sudo setting in the environment file,
with strict host-key checking), checks that it is PEM with at least one CA
certificate, and writes it atomically with mode 0644: next to the environment file
as ` + defaultCAFileName + `, or at --out. It then prints the line to add to the
environment file. It does not edit the environment file.

A file that holds a private key, no CA certificate or an expired CA is not
written, and neither is a destination that exists and is not a certificate
file.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Context() == nil {
				cmd.SetContext(context.Background())
			}
			result := newCheckedOutput(cmd.OutOrStdout())
			return result.deliver(runSetupPVECA(cmd, result, envFile, out))
		},
	}
	cmd.Flags().StringVar(&envFile, "env-file", "", "allowlisted controller environment file: the SSH settings run uses are read from it, and the CA is written next to it")
	cmd.Flags().StringVar(&out, "out", "", "where to write the CA (default: "+defaultCAFileName+" next to the environment file)")
	_ = cmd.MarkFlagRequired("env-file")
	return cmd
}

// controllerSSHFromEnvironment is the SSH access the environment gives a
// command, as run resolves it: the same variables, the same defaults. It
// returns what is missing before anything is attempted.
func controllerSSHFromEnvironment(cmd *cobra.Command) (controller.SSHConfig, error) {
	var (
		nodeName, scratchDir, outputDir, stateDir string
		host, user, identity, knownHosts          string
		port                                      = 22
		sudo                                      bool
	)
	user = "certistack"
	if err := applyControllerEnvironmentDefaults(cmd, &nodeName, &scratchDir, &outputDir, &stateDir, &host, &user, &port, &identity, &knownHosts, &sudo); err != nil {
		return controller.SSHConfig{}, err
	}
	if host == "" {
		return controller.SSHConfig{}, errors.New("CERTISTACK_SSH_HOST is not set in the environment file: name the node's SSH host there")
	}
	if knownHosts == "" {
		knownHosts = defaultKnownHostsPath()
	}
	return controller.SSHConfig{Host: host, User: user, Port: port, IdentityFile: identity, KnownHostsFile: knownHosts, UseSudo: sudo}, nil
}

func runSetupPVECA(cmd *cobra.Command, w io.Writer, envFile, out string) error {
	restoreEnvironment, err := useCommandEnvironment(envFile, false)
	if err != nil {
		return err
	}
	defer restoreEnvironment()
	cfg, err := controllerSSHFromEnvironment(cmd)
	if err != nil {
		return err
	}
	envPath, err := filepath.Abs(envFile)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", envFile, err)
	}
	if out == "" {
		out = filepath.Join(filepath.Dir(envPath), defaultCAFileName)
	}
	outPath, err := filepath.Abs(out)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", out, err)
	}
	if outPath == envPath {
		return errors.New("--out names the environment file itself; give the CA a file of its own")
	}

	if _, err := os.Stat(cfg.KnownHostsFile); err != nil {
		return fmt.Errorf("the known_hosts file %s does not exist, so the node's host key cannot be checked. Record it after you have compared its fingerprint with the node's: %s", cfg.KnownHostsFile, trustNodeCommand(cfg))
	}
	if err := controller.ValidateSSH(cfg); err != nil {
		return err
	}

	raw, err := fetchPVECA(cmd.Context(), cfg)
	if err != nil {
		return describeFetchFailure(err, cfg)
	}
	bundle, err := nodesetup.ParseCABundle(raw, time.Now())
	if err != nil {
		return fmt.Errorf("%s on %s was not written: %w", nodesetup.PVERootCAPath, cfg.Host, err)
	}
	changed, err := nodesetup.WriteCAFile(outPath, bundle.PEM)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "Fetched %s from %s over the pinned SSH connection.\n\nCertificate authority to trust:\n", nodesetup.PVERootCAPath, cfg.Host)
	for _, cert := range bundle.Certificates {
		fmt.Fprintf(w, "  Subject:      %s\n  SHA-256:      %s\n  Valid until:  %s\n", cert.Subject, cert.SHA256, cert.NotAfter.Format("2006-01-02"))
	}
	if bundle.IgnoredLeaves > 0 {
		fmt.Fprintf(w, "  (%d certificate(s) in the file are not CA certificates and were left out.)\n", bundle.IgnoredLeaves)
	}
	if changed {
		fmt.Fprintf(w, "\nWrote %s (mode 0644).\n", outPath)
	} else {
		fmt.Fprintf(w, "\n%s already holds this CA: nothing to write.\n", outPath)
	}
	if current := os.Getenv("CERTISTACK_PVE_CA_SOURCE"); current == outPath {
		fmt.Fprintf(w, "\n%s already sets CERTISTACK_PVE_CA_SOURCE to this file. Next: certistack check --env-file %s\n", envPath, envPath)
		return nil
	} else if current != "" {
		fmt.Fprintf(w, "\nNote: %s sets CERTISTACK_PVE_CA_SOURCE to %s, not to this file. Change that line to:\n", envPath, current)
	} else {
		fmt.Fprintf(w, "\nAdd this line to %s:\n", envPath)
	}
	fmt.Fprintf(w, "  CERTISTACK_PVE_CA_SOURCE=%s\n\nThen run: certistack check --env-file %s\n", outPath, envPath)
	return nil
}

// describeFetchFailure is the error for a CA that could not be fetched: what
// OpenSSH or the node said, and what to do about it.
func describeFetchFailure(err error, cfg controller.SSHConfig) error {
	if hint := sshFailureHint(err, cfg); hint != "" {
		return fmt.Errorf("fetch %s from %s: %w\n%s", nodesetup.PVERootCAPath, cfg.Host, err, hint)
	}
	text := err.Error()
	switch {
	case strings.Contains(text, "No such file or directory"):
		return fmt.Errorf("fetch %s from %s: %w\nThe node has no cluster CA file there: is %s a Proxmox VE node (not a PBS host or another machine)?", nodesetup.PVERootCAPath, cfg.Host, err, cfg.Host)
	case strings.Contains(text, "Permission denied"):
		return fmt.Errorf("fetch %s from %s: %w\nThe account %q cannot read the cluster file system. Use root (CERTISTACK_SSH_USER=root), or an account with passwordless sudo and CERTISTACK_SSH_SUDO=true.", nodesetup.PVERootCAPath, cfg.Host, err, cfg.User)
	}
	return fmt.Errorf("fetch %s from %s: %w", nodesetup.PVERootCAPath, cfg.Host, err)
}

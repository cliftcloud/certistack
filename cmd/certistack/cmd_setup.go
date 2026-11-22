// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/nodesetup"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

// defaultSetupKnownHosts is where the quickstart keeps the node's approved host
// key, and where `setup trust-node` writes it when nothing else says.
const defaultSetupKnownHosts = "/secure/certistack/known_hosts"

func setupCmd() *cobra.Command {
	var opts setupWizardOptions
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Connect this controller to a Proxmox VE node and its PBS: asks, then does the first-run steps",
		Long: `certistack setup connects this controller to one Proxmox VE node and its
Proxmox Backup Server, and ends with certistack check. It asks for the node's
address, shows the node's SSH host key for you to confirm, reads the node
(and stops there, before the steps below, on a node a run cannot use: PVE 8.0,
a proxmox-backup-client older than 3, or no SDN API), and then, after your yes
to each, does the first-run steps:

  - installs libguestfs-tools and nftables on the node when they are missing,
    after showing what apt-get would install, upgrade and remove;
  - adds the overlay storage (certistack-scratch);
  - creates the PVE role, the user with no password, its privilege-separated
    token and the ACLs (never on /);
  - creates the read-only PBS user and token, over your own ssh to the PBS
    (or by a script you paste into the PBS web shell);
  - fetches the node's cluster CA, and writes the environment file, mode 0600.

The two token secrets go from the commands that create them into the file;
they are never shown. A node that backs up to a PBS already offers that PBS's
server, datastore, namespace and fingerprint. Running it again reuses what
exists, replaces a token only after you agree, keeps a copy of an existing
environment file and carries over the variables of it that setup does not set.
Strict SSH host-key checking stays on throughout.

Every answer has a flag; with --yes the defaults are taken (--fingerprint is
required then, and so is a PBS namespace: --pbs-namespace NAME, or / for the
root namespace, which lets the PBS user read every namespace of the datastore). The manual steps are subcommands:

  setup trust-node   read the node's SSH host key, show its fingerprint and
                     record it in known_hosts after you confirm it
  setup pve-ca       fetch the PVE cluster CA over the pinned SSH access
  setup rbac         print the script that creates the PVE role, user, token
                     and ACLs and the read-only PBS user (it runs nothing)`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Context() == nil {
				cmd.SetContext(context.Background())
			}
			deps := setupWizardRuntime
			deps.check = func(ctx context.Context, envPath string, w io.Writer) error {
				return runCheck(cmd, w, envPath, "", ctx)
			}
			return runSetupWizard(cmd.Context(), cmd.OutOrStdout(), cmd.InOrStdin(), opts, deps)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Dir, "dir", "", "directory for the key, known_hosts and controller.env (default /secure/certistack, or ~/certistack/secure when that is not a directory you can write to)")
	f.StringVar(&opts.NodeHost, "node-host", "", "the node's DNS name or IP address, as this controller reaches it over SSH")
	f.IntVar(&opts.Port, "port", 0, "the node's SSH port (default 22, or the earlier controller.env's for the same host)")
	f.StringVar(&opts.Fingerprint, "fingerprint", "", "the node's ED25519 host key fingerprint you verified (SHA256:...); trusts a matching key without a prompt")
	f.BoolVar(&opts.Yes, "yes", false, "take the default of every question the flags leave (needs --fingerprint and, unless the PBS storage or the earlier controller.env names one, --pbs-namespace)")
	f.StringVar(&opts.OverlayStorage, "overlay-storage", "", "the overlay storage's ID (default: the CERTISTACK_OVERLAY_STORAGE of an existing controller.env, else certistack-scratch)")
	f.StringVar(&opts.OverlayPath, "overlay-path", "", "the directory for a new overlay storage (default /var/lib/vz/<ID> on a standalone node)")
	f.StringVar(&opts.PBSStorage, "pbs-storage", "", "use this PBS storage of the node (its server, datastore, namespace and fingerprint)")
	f.StringVar(&opts.PBSHost, "pbs-host", "", "the PBS's DNS name or IP address, when no PBS storage of the node is used")
	f.IntVar(&opts.PBSPort, "pbs-port", 0, "the PBS API port, with --pbs-host (default 8007, or the earlier controller.env's)")
	f.StringVar(&opts.PBSDatastore, "pbs-datastore", "", "the PBS datastore, with --pbs-host")
	f.StringVar(&opts.PBSNamespace, "pbs-namespace", "", "the PBS namespace the PBS user is granted (default: the PBS storage's, else the earlier controller.env's for the same PBS and datastore, else setup asks); / is the root namespace, which lets it read every namespace of the datastore")
	f.StringVar(&opts.PBSFingerprint, "pbs-fingerprint", "", "the PBS certificate's SHA-256 fingerprint (PBS dashboard, Show Fingerprint); refused if the node's PBS storage or the PBS reports another. Without it, setup asks you to confirm the one it reads")
	f.StringVar(&opts.PBSSSH, "pbs-ssh", "", "how to reach the PBS as root over your own ssh (default root@<PBS host>)")
	f.BoolVar(&opts.PBSManual, "pbs-manual", false, "do not ssh to the PBS: print its part to paste into the PBS web shell, then paste the secret")
	cmd.AddCommand(setupTrustNodeCmd(), setupPVECACmd(), setupRBACCmd())
	return cmd
}

// fetchNodeHostKey reads a node's ED25519 host key. It is a variable so that a
// test gives the command a node without a network.
var fetchNodeHostKey = func(ctx context.Context, host string, port int) (nodesetup.HostKey, error) {
	return nodesetup.FetchHostKey(ctx, nodesetup.NetDial, host, port)
}

// fingerprintForm is what an SHA-256 host key fingerprint looks like as
// `ssh-keygen -l` prints it: SHA256: and 43 unpadded base64 characters.
var fingerprintForm = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// malformedFingerprint is the refusal of a host key fingerprint that is not
// in the form ssh-keygen -l prints.
func malformedFingerprint(flag, value string) error {
	return fmt.Errorf("%s %q is not an SHA-256 fingerprint as ssh-keygen -l prints it (SHA256: and 43 characters of unpadded base64): give the fingerprint that ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub prints on the node", flag, value)
}

func setupTrustNodeCmd() *cobra.Command {
	var (
		host        string
		port        int
		knownHosts  string
		fingerprint string
		yes         bool
	)
	cmd := &cobra.Command{
		Use:   "trust-node --host HOST [--port N] [--known-hosts FILE] [--fingerprint SHA256:...] [--yes]",
		Short: "Read the node's SSH host key and record it in known_hosts after you confirm it",
		Long: `Reads the ED25519 host key the node offers on its SSH port, prints its
SHA-256 fingerprint and the exact known_hosts line, and writes that line only
after you confirm it:

  - at a terminal, by typing yes after comparing the fingerprint with the one
    the node reports about itself (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
    on the node); or
  - unattended, with --fingerprint set to the fingerprint you already verified.
    A key that does not match it is refused and nothing is written.

--yes never trusts a key by itself: it is accepted only together with
--fingerprint. Nothing is written for a key the node offers that you have not
confirmed, and a host that already has a different key in the file is refused,
not overwritten.

The line is written as ssh looks it up: the bare host for port 22 and [host]:PORT
for any other port. The file is created with mode 0600 and its directory with 0700.
The default file is CERTISTACK_SSH_KNOWN_HOSTS, else ` + defaultSetupKnownHosts + `.
Strict host-key checking stays on for every command; this one only adds the
line you approve.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Context() == nil {
				cmd.SetContext(context.Background())
			}
			if !cmd.Flags().Changed("known-hosts") {
				knownHosts = os.Getenv("CERTISTACK_SSH_KNOWN_HOSTS")
				if knownHosts == "" {
					knownHosts = defaultSetupKnownHosts
				}
			}
			out := newCheckedOutput(cmd.OutOrStdout())
			err := runTrustNode(cmd.Context(), out, cmd.InOrStdin(), trustNodeRequest{
				Host: host, Port: port, KnownHosts: knownHosts, Fingerprint: fingerprint, Yes: yes,
			})
			return out.deliver(err)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "the node's SSH host name or address, exactly as CERTISTACK_SSH_HOST names it")
	cmd.Flags().IntVar(&port, "port", 22, "the node's SSH port")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", "", "known_hosts file to add the line to (default: CERTISTACK_SSH_KNOWN_HOSTS, else "+defaultSetupKnownHosts+")")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "the host key's SHA256:... fingerprint you verified; a key that differs is refused, one that matches is trusted without a prompt")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the prompt; only valid together with --fingerprint")
	_ = cmd.MarkFlagRequired("host")
	return cmd
}

// trustNodeRequest is what `setup trust-node` was asked to do.
type trustNodeRequest struct {
	Host        string
	Port        int
	KnownHosts  string
	Fingerprint string
	Yes         bool
	// InWizard leaves out the next steps, which certistack setup takes itself.
	InWizard bool
}

// runTrustNode is `setup trust-node`: it reads the host key, shows it, and
// writes the known_hosts line only for a key the operator confirmed, by typing
// yes or by naming its fingerprint.
func runTrustNode(ctx context.Context, out io.Writer, in io.Reader, req trustNodeRequest) error {
	host, err := nodesetup.NormalizeHost(req.Host)
	if err != nil {
		return err
	}
	if err := nodesetup.CheckPort(req.Port); err != nil {
		return err
	}
	expected := strings.TrimSpace(req.Fingerprint)
	if req.Yes && expected == "" {
		return errors.New("--yes does not trust a key by itself: it only skips the prompt when --fingerprint names the key's fingerprint. Run the command without --yes at a terminal and compare the fingerprint, or give --fingerprint the fingerprint that ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub prints on the node")
	}
	if expected != "" && !fingerprintForm.MatchString(expected) {
		return malformedFingerprint("--fingerprint", req.Fingerprint)
	}
	if strings.TrimSpace(req.KnownHosts) == "" {
		return errors.New("--known-hosts needs a file path")
	}
	knownHosts, err := filepath.Abs(req.KnownHosts)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", req.KnownHosts, err)
	}
	// A file that someone else could change is refused before the node is
	// asked: a line written there would not be trusted.
	if info, err := os.Stat(knownHosts); err == nil && info.Mode().IsRegular() {
		if err := sysutil.UnsafeToTrust(knownHosts, info, sysutil.KnownHostsWhat, sysutil.KnownHostsRisk); err != nil {
			return err
		}
	}

	key, err := fetchNodeHostKey(ctx, host, req.Port)
	if err != nil {
		return err
	}
	line := nodesetup.KnownHostsLine(host, req.Port, key.Key)

	fmt.Fprintf(out, "Host key offered by %s on port %d (%s):\n  %s\n\n", host, req.Port, key.Key.Type(), key.Fingerprint)
	fmt.Fprintf(out, "Compare it with the key the node reports about itself. On the node, run:\n  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub\n\n")

	if expected != "" && expected != key.Fingerprint {
		return fmt.Errorf("the node offered %s, not the %s you expected: nothing was written. This command reads and compares only the ED25519 host key, so the fingerprint of the node's ECDSA or RSA key never matches; the one to pass is printed on the node by: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub. If the node's host key was replaced on purpose, read the new fingerprint on the node and pass that one; otherwise something other than the node is answering at %s:%d", key.Fingerprint, expected, host, req.Port)
	}

	held, err := nodesetup.InspectKnownHosts(knownHosts, host, req.Port, key.Key)
	if err != nil {
		return err
	}
	switch held.State {
	case nodesetup.HostTrusted:
		fmt.Fprintf(out, "%s already holds exactly this key for %s: nothing to write.\n", knownHosts, nodesetup.KnownHostsName(host, req.Port))
		return nil
	case nodesetup.HostKeyChanged:
		return fmt.Errorf("%s already holds a different ED25519 key for %s (%s), so nothing was written. A host key that changes is what an impersonated node looks like. If the node was reinstalled on purpose and you have verified the new fingerprint on it, remove the old line yourself (ssh-keygen -R %s -f %s) and run this again",
			knownHosts, nodesetup.KnownHostsName(host, req.Port), strings.Join(held.Held, ", "), nodesetup.KnownHostsName(host, req.Port), knownHosts)
	case nodesetup.HostOtherKeyTypes:
		fmt.Fprintf(out, "Note: %s holds other key types for this host (%s); the ED25519 line is added next to them.\n\n", knownHosts, strings.Join(held.Held, ", "))
	}

	fmt.Fprintf(out, "This line will be written to %s:\n  %s\n\n", knownHosts, line)
	if expected == "" {
		confirmed, err := confirmTyped(ctx, out, in, `Type "yes" to trust this key and write the line: `)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("not confirmed, so nothing was written. Run the command again at a terminal and type yes once the fingerprint matches the node's, or give --fingerprint the fingerprint that ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub prints on the node, to confirm it without a prompt")
		}
	} else {
		fmt.Fprintln(out, "The fingerprint matches the one you gave: trusting this key without a prompt.")
	}

	if err := nodesetup.AppendKnownHost(knownHosts, line); err != nil {
		return err
	}
	if req.InWizard {
		fmt.Fprintf(out, "Wrote 1 line to %s.\nWith this file ssh accepts only this key for %s.\n", knownHosts, nodesetup.KnownHostsName(host, req.Port))
		return nil
	}
	fmt.Fprintf(out, "Wrote 1 line to %s.\nWith this file ssh accepts only this key for %s. Next: set CERTISTACK_SSH_KNOWN_HOSTS to it, authorize your public key on the node, and run certistack check.\n", knownHosts, nodesetup.KnownHostsName(host, req.Port))
	return nil
}

// confirmTyped asks a question and is satisfied only by the answer yes. End of
// input, a cancelled context and every other answer decline. The prompt is
// written to out and the answer read from in; the read stops waiting when ctx
// ends, so Ctrl-C does not leave the command stuck on the terminal.
func confirmTyped(ctx context.Context, out io.Writer, in io.Reader, prompt string) (bool, error) {
	fmt.Fprint(out, prompt)
	type answer struct {
		text string
		err  error
	}
	read := make(chan answer, 1)
	go func() {
		text, err := bufio.NewReader(in).ReadString('\n')
		read <- answer{text, err}
	}()
	select {
	case <-ctx.Done():
		fmt.Fprintln(out)
		return false, ctx.Err()
	case a := <-read:
		if a.err != nil && a.text == "" {
			fmt.Fprintln(out)
			return false, nil
		}
		return strings.TrimSpace(a.text) == "yes", nil
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cliftcloud/certistack/internal/nodesetup"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// `certistack setup` with no subcommand is the first-run wizard: it asks for
// what it needs, reads the node, and does what the manual steps do
// (docs/manual-setup.md, "Set up by hand") with the operator's yes to each
// change. The rules it keeps: nothing changes on
// a host before a yes for that change; no secret is shown or typed (the token
// secrets go from the creating command's JSON into the 0600 environment file);
// no admin credential is kept; strict host-key checking throughout.

// setupWizardOptions are the wizard's flags: every answer can be given in
// advance, and --yes takes the default of every question the flags leave.
type setupWizardOptions struct {
	Dir            string
	NodeHost       string
	Port           int
	Fingerprint    string
	Yes            bool
	OverlayStorage string
	OverlayPath    string
	PBSStorage     string
	PBSHost        string
	PBSPort        int
	PBSDatastore   string
	PBSNamespace   string
	PBSFingerprint string
	PBSSSH         string
	PBSManual      bool
}

// setupWizardDeps is how the wizard reaches the world; tests replace it.
type setupWizardDeps struct {
	sshKeygen   func(ctx context.Context, path string) error
	sshCopyID   func(ctx context.Context, cfg controller.SSHConfig) error
	nodeScript  func(ctx context.Context, cfg controller.SSHConfig, script string, stderr io.Writer) ([]byte, error)
	nodeFile    func(ctx context.Context, cfg controller.SSHConfig, path string, limit int) ([]byte, error)
	pbsScript   func(ctx context.Context, target string, port int, script string, stderr io.Writer) ([]byte, error)
	check       func(ctx context.Context, envPath string, w io.Writer) error
	envPointer  func() (string, error) // where setup records the file it wrote, for the commands' default (envFilePointerPath)
	readSecret  func(ctx context.Context, prompt string, out io.Writer) (string, error)
	isTerminal  func() bool
	now         func() time.Time
	reportsDir  string // the default report directory, which the wizard leaves unset when it is writable
	defaultDirs []string
}

func defaultSetupWizardDeps() setupWizardDeps {
	executor := controller.NewExecutor()
	return setupWizardDeps{
		sshKeygen: func(ctx context.Context, path string) error {
			cmd := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "certistack-controller", "-f", path)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("ssh-keygen: %w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		sshCopyID: func(ctx context.Context, cfg controller.SSHConfig) error {
			// ssh-copy-id keeps a temporary directory in ~/.ssh and stops
			// ("failed to create required temporary directory under ~/.ssh")
			// on an account that has none yet.
			if home, err := os.UserHomeDir(); err == nil {
				if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
					return fmt.Errorf("create %s for ssh-copy-id: %w", filepath.Join(home, ".ssh"), err)
				}
			}
			cmd := exec.CommandContext(ctx, "ssh-copy-id",
				"-o", "UserKnownHostsFile="+cfg.KnownHostsFile, "-o", "StrictHostKeyChecking=yes",
				"-i", cfg.IdentityFile+".pub", "-p", strconv.Itoa(cfg.Port), cfg.User+"@"+cfg.Host)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
			return cmd.Run()
		},
		nodeScript: executor.RunNodeScript,
		nodeFile:   executor.ReadNodeFile,
		pbsScript: func(ctx context.Context, target string, port int, script string, stderr io.Writer) ([]byte, error) {
			// The operator's own ssh, but never one that trusts a host key
			// unasked: StrictHostKeyChecking=ask on the command line wins over
			// an ssh_config that says no or accept-new.
			args := []string{"-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=ask"}
			if port != 0 && port != 22 {
				args = append(args, "-p", strconv.Itoa(port))
			}
			args = append(args, target, "/bin/sh -c "+singleQuote(script))
			cmd := exec.CommandContext(ctx, "ssh", args...)
			var stdout strings.Builder
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, &stdout, stderr
			err := cmd.Run()
			return []byte(stdout.String()), err
		},
		envPointer:  envFilePointerPath,
		readSecret:  readHiddenLine,
		isTerminal:  stdinIsTerminal,
		now:         time.Now,
		reportsDir:  "/var/lib/certistack/reports",
		defaultDirs: []string{"/secure/certistack"},
	}
}

// setupWizardRuntime is the wizard's world; tests replace it.
var setupWizardRuntime = defaultSetupWizardDeps()

func singleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// lineReader hands out one line per Read, so that each prompt, including the
// one runTrustNode reads with a reader of its own, takes exactly its answer
// and leaves the next one for the next prompt.
type lineReader struct {
	r       *bufio.Reader
	pending []byte
}

func newLineReader(in io.Reader) *lineReader { return &lineReader{r: bufio.NewReader(in)} }

func (l *lineReader) Read(p []byte) (int, error) {
	if len(l.pending) == 0 {
		line, err := l.r.ReadBytes('\n')
		if len(line) == 0 {
			return 0, err
		}
		l.pending = line
	}
	n := copy(p, l.pending)
	l.pending = l.pending[n:]
	return n, nil
}

// wizardUI asks the questions.
type wizardUI struct {
	ctx  context.Context
	out  io.Writer
	in   *lineReader
	yes  bool
	deps setupWizardDeps
	step int
}

const wizardSteps = 9

func (u *wizardUI) say(format string, args ...any) { fmt.Fprintf(u.out, format+"\n", args...) }

func (u *wizardUI) heading(title string) {
	u.step++
	fmt.Fprintf(u.out, "\n%d/%d  %s\n", u.step, wizardSteps, title)
}

func (u *wizardUI) readLine() (string, error) {
	type answer struct {
		text string
		err  error
	}
	read := make(chan answer, 1)
	go func() {
		text, err := bufio.NewReader(u.in).ReadString('\n')
		read <- answer{text, err}
	}()
	select {
	case <-u.ctx.Done():
		fmt.Fprintln(u.out)
		return "", u.ctx.Err()
	case a := <-read:
		if a.err != nil && a.text == "" {
			fmt.Fprintln(u.out)
			return "", errors.New("the input ended before the setup was done; nothing more was changed")
		}
		return strings.TrimSpace(a.text), nil
	}
}

// ask returns the answer, or def for an empty one. With --yes it returns def
// without asking, and a question that has no default is an error naming the
// flag that answers it.
func (u *wizardUI) ask(question, def, flag string) (string, error) {
	if u.yes {
		if def == "" {
			return "", fmt.Errorf("%s has no default: give it with %s", strings.TrimSuffix(question, "?"), flag)
		}
		u.say("%s: %s", question, def)
		return def, nil
	}
	prompt := question
	if def != "" {
		prompt += " [" + def + "]"
	}
	fmt.Fprint(u.out, prompt+": ")
	answer, err := u.readLine()
	if err != nil {
		return "", err
	}
	if answer == "" {
		answer = def
	}
	return answer, nil
}

// confirm asks a yes/no question. --yes takes its default: yes for the
// steps of the setup, no for what destroys something (replacing a token).
func (u *wizardUI) confirm(question string, def bool) (bool, error) {
	if u.yes {
		answer := "no"
		if def {
			answer = "yes"
		}
		u.say("%s %s (--yes takes the default)", question, answer)
		return def, nil
	}
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	for {
		fmt.Fprintf(u.out, "%s %s: ", question, hint)
		answer, err := u.readLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		u.say("Answer yes or no.")
	}
}

// setupWizardContext is what the wizard has learned so far.
type setupWizardContext struct {
	dir        string
	knownHosts string
	identity   string
	envPath    string
	ssh        controller.SSHConfig
	facts      nodesetup.NodeFacts
	overlayID  string
	pbs        nodesetup.PBSStorage
	pbsSSH     string
	pbsSSHPort int
	// existing is the earlier controller.env, with the values of
	// controller.env.partial over it (fromPartial names those).
	existing    map[string]string
	fromPartial map[string]bool
	partialPath string
	partial     []nodesetup.EnvVar // what controller.env.partial holds now
	env         nodesetup.EnvFile
	// pointer is the file envPath was recorded in as the commands' default
	// environment file, once it was; "" until then.
	pointer string
}

// partialEnvName is where setup keeps the secret of a token it created the
// moment it has it, until controller.env is written: a setup that stops after
// that (a failed step, Ctrl-C) leaves the secret there, and the next run
// offers to use it, so a token is never left without its secret.
const partialEnvName = "controller.env.partial"

// keepPartial adds vars to controller.env.partial (mode 0600, written whole).
func (w *setupWizardContext) keepPartial(vars ...nodesetup.EnvVar) error {
	for _, v := range vars {
		replaced := false
		for i := range w.partial {
			if w.partial[i].Name == v.Name {
				w.partial[i].Value, replaced = v.Value, true
			}
		}
		if !replaced {
			w.partial = append(w.partial, v)
		}
	}
	var b strings.Builder
	b.WriteString("# Kept by certistack setup until it writes controller.env: the secrets of the tokens it created.\n")
	b.WriteString("# Mode 0600. certistack setup run again offers to use them; remove the file only together with the tokens.\n")
	for _, v := range w.partial {
		if !nodesetup.LiteralValue(v.Value) {
			return fmt.Errorf("%s has a value an environment file cannot hold literally", v.Name)
		}
		fmt.Fprintf(&b, "%s=%s\n", v.Name, v.Value)
	}
	return nodesetup.WriteSecretFile(w.partialPath, []byte(b.String()))
}

// partialHas reports whether controller.env.partial holds the variable.
func (w *setupWizardContext) partialHas(name string) bool {
	for _, v := range w.partial {
		if v.Name == name && v.Value != "" {
			return true
		}
	}
	return false
}

// sourceOf names the file an existing value comes from.
func (w *setupWizardContext) sourceOf(name string) string {
	if w.fromPartial[name] {
		return w.partialPath + " (left by a setup that did not finish)"
	}
	return w.envPath
}

// runSetupWizard is `certistack setup`.
func runSetupWizard(ctx context.Context, out io.Writer, in io.Reader, opts setupWizardOptions, deps setupWizardDeps) error {
	if !opts.Yes && !deps.isTerminal() {
		return errors.New("certistack setup asks questions and needs a terminal. To run it unattended, give the answers as flags with --yes (at least --node-host and --fingerprint); or use the manual steps: certistack setup trust-node, setup rbac, setup pve-ca")
	}
	if opts.Yes && strings.TrimSpace(opts.Fingerprint) == "" {
		return errors.New("--yes does not trust the node's host key by itself: give --fingerprint the fingerprint that ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub prints on the node")
	}
	if err := checkWizardFlags(opts); err != nil {
		return err
	}
	if err := checkUnattendedPBSFlags(opts, deps); err != nil {
		return err
	}
	u := &wizardUI{ctx: ctx, out: out, in: newLineReader(in), yes: opts.Yes, deps: deps}
	w := &setupWizardContext{}

	u.say("CertiStack setup connects this controller to one Proxmox VE node and its Proxmox Backup Server,")
	u.say("and ends with certistack check. It changes nothing on a host before you say yes to that change;")
	u.say("the two token secrets go into the environment file and are never shown.")

	steps := []func(*wizardUI, *setupWizardContext, setupWizardOptions) error{
		wizardDirectory, wizardNode, wizardNodeFacts, wizardPackages, wizardOverlay, wizardPVEAccess, wizardPBS, wizardEnvironment, wizardCheck,
	}
	for _, step := range steps {
		if err := step(u, w, opts); err != nil {
			return err
		}
	}
	return nil
}

// checkWizardFlags refuses, before anything is asked or changed, a flag value
// a later step would refuse.
func checkWizardFlags(opts setupWizardOptions) error {
	host := func(flag, value string) error {
		if value == "" {
			return nil
		}
		normalized, err := nodesetup.NormalizeHost(value)
		if err != nil || !controller.ValidSSHHost(normalized) {
			return fmt.Errorf("%s %q is not a host name or address (no scheme, user or port)", flag, value)
		}
		return nil
	}
	checks := []func() error{
		func() error {
			if opts.Dir != "" && (!filepath.IsAbs(opts.Dir) || strings.ContainsAny(opts.Dir, " \t\r\n\"'\\")) {
				return fmt.Errorf("--dir %q must be an absolute path without spaces, quotes or backslashes (ssh cannot use one for its known_hosts file)", opts.Dir)
			}
			return nil
		},
		func() error { return host("--node-host", opts.NodeHost) },
		func() error {
			// Refused here, before anything is asked or connected to: the
			// same check trust-node makes, for the same form.
			if fp := strings.TrimSpace(opts.Fingerprint); fp != "" && !fingerprintForm.MatchString(fp) {
				return malformedFingerprint("--fingerprint", opts.Fingerprint)
			}
			return nil
		},
		func() error { return host("--pbs-host", opts.PBSHost) },
		func() error {
			// The destination ssh is given: one that starts with "-" is read
			// as an option, and white space is in no destination.
			if strings.HasPrefix(opts.PBSSSH, "-") || strings.IndexFunc(opts.PBSSSH, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
				return fmt.Errorf("--pbs-ssh %q is not an ssh destination: give user@host, a host or a Host alias of your ssh configuration, with no option and no space (ssh options belong in ~/.ssh/config)", opts.PBSSSH)
			}
			return nil
		},
		func() error {
			if opts.Port < 0 || opts.Port > 65535 || opts.PBSPort < 0 || opts.PBSPort > 65535 {
				return errors.New("--port and --pbs-port are from 1 to 65535")
			}
			return nil
		},
		func() error {
			if opts.PBSStorage != "" && opts.PBSHost != "" {
				return errors.New("give --pbs-storage (a PBS storage of the node) or --pbs-host, not both")
			}
			if opts.PBSManual && opts.Yes {
				return errors.New("--pbs-manual has you paste the PBS token's secret at a terminal; it cannot be used with --yes (give --pbs-ssh instead)")
			}
			return nil
		},
		func() error {
			if opts.PBSDatastore == "" {
				return nil
			}
			return flagError("--pbs-datastore", nodesetup.CheckDatastore(opts.PBSDatastore))
		},
		func() error {
			_, err := checkNamespaceAnswer(opts.PBSNamespace)
			return flagError("--pbs-namespace", err)
		},
		func() error {
			if opts.PBSFingerprint == "" {
				return nil
			}
			_, err := nodesetup.NormalizeFingerprint(opts.PBSFingerprint)
			return flagError("--pbs-fingerprint", err)
		},
		func() error {
			if opts.OverlayStorage == "" {
				return nil
			}
			return flagError("--overlay-storage", nodesetup.CheckStorageID(opts.OverlayStorage))
		},
		func() error {
			if opts.OverlayPath == "" {
				return nil
			}
			return flagError("--overlay-path", nodesetup.CheckOverlayPath(opts.OverlayPath))
		},
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func flagError(flag string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", flag, err)
}

// unattendedPBSChoice refuses, under --yes and before any change, a PBS that
// step 7 could not settle without a question: as choosePBS chooses it. That
// includes a PBS namespace nobody named, which would let the PBS user read
// every namespace of the datastore.
func unattendedPBSChoice(w *setupWizardContext, opts setupWizardOptions) error {
	storages := nodesetup.PBSStorages(w.facts.Storage)
	if opts.PBSStorage != "" {
		for _, s := range storages {
			if s.ID == opts.PBSStorage {
				if _, named := storageNamespace(s, opts, w.existing); !named {
					return errNamespaceNotNamed(s.Datastore)
				}
				return nil
			}
		}
		return fmt.Errorf("the node has no PBS storage %s (--pbs-storage)", opts.PBSStorage)
	}
	if opts.PBSHost == "" && len(storages) > 0 {
		// The first storage is the default, and --yes takes it.
		if _, named := storageNamespace(storages[0], opts, w.existing); !named {
			return errNamespaceNotNamed(storages[0].Datastore)
		}
		return nil
	}
	d := manualPBSDefaults(w.existing, opts)
	if d.host == "" {
		return errors.New("the node has no PBS storage and no earlier controller.env names a PBS: give --pbs-host and --pbs-datastore")
	}
	if d.datastore == "" {
		return errors.New("give the PBS datastore with --pbs-datastore")
	}
	if namespace := d.namespaceFor(opts, w.existing, d.host, d.datastore); namespace == "" && opts.PBSNamespace == "" {
		return errNamespaceNotNamed(d.datastore)
	}
	return nil
}

// checkUnattendedPBSFlags refuses, under --yes and before step 1 creates the
// directory, known_hosts or a key, what unattendedPBSChoice would refuse at
// step 3 from the flags and the earlier controller.env alone: a PBS named by
// --pbs-host with no datastore, or with no namespace that the flag or the
// earlier file names. Without --pbs-host the PBS comes from the node's own
// storages, which only step 3 reads.
func checkUnattendedPBSFlags(opts setupWizardOptions, deps setupWizardDeps) error {
	if !opts.Yes || opts.PBSHost == "" {
		return nil
	}
	existing := earlierSetupValues(wizardDefaultDir(opts, deps))
	d := manualPBSDefaults(existing, opts)
	if d.datastore == "" {
		return errors.New("give the PBS datastore with --pbs-datastore")
	}
	host, err := nodesetup.NormalizeHost(opts.PBSHost)
	if err != nil {
		return nil // checkWizardFlags refuses it
	}
	if d.namespaceFor(opts, existing, host, d.datastore) == "" && opts.PBSNamespace == "" {
		return errNamespaceNotNamed(d.datastore)
	}
	return nil
}

// earlierSetupValues is, read and changing nothing, what an earlier setup left
// in dir: controller.env, with the values controller.env.partial keeps over
// it, as wizardDirectory reads them. A file that cannot be read counts as
// absent here; wizardDirectory says why.
func earlierSetupValues(dir string) map[string]string {
	if dir == "" {
		return map[string]string{}
	}
	existing, err := loadControllerEnvironment(filepath.Join(dir, "controller.env"))
	if err != nil || existing == nil {
		existing = map[string]string{}
	}
	if partial, err := loadControllerEnvironment(filepath.Join(dir, partialEnvName)); err == nil {
		for _, name := range partialEnvNames {
			if value := partial[name]; value != "" {
				existing[name] = value
			}
		}
	}
	return existing
}

// partialEnvNames are the variables controller.env.partial keeps.
var partialEnvNames = []string{"PVE_TOKEN_ID", "PVE_TOKEN_SECRET", "CERTISTACK_NODE", "PBS_REPOSITORY", "PBS_PASSWORD"}

// errNamespaceNotNamed is what --yes says when the PBS namespace was not
// given: a root namespace the operator did not ask for is every namespace of
// the datastore.
func errNamespaceNotNamed(datastore string) error {
	return fmt.Errorf("no PBS namespace was given, and --yes does not let the PBS user read every namespace of the datastore %s by itself: give --pbs-namespace NAMESPACE for the namespace that holds the backups, or --pbs-namespace / to grant the whole datastore", datastore)
}

// storageNamespace is the namespace the PBS user gets for a PBS storage of the
// node, and whether anyone named it: --pbs-namespace (/ is the root), else the
// storage's own, else the earlier controller.env's for the same PBS server and
// datastore. A storage without a namespace backs up to the root namespace.
func storageNamespace(s nodesetup.PBSStorage, opts setupWizardOptions, existing map[string]string) (string, bool) {
	if opts.PBSNamespace != "" {
		ns, _ := checkNamespaceAnswer(opts.PBSNamespace)
		return ns, true
	}
	if s.Namespace != "" {
		return s.Namespace, true
	}
	if prev := previousPBS(existing); prev.Namespace != "" && prev.Server != "" && strings.EqualFold(prev.Server, s.Server) && prev.Datastore == s.Datastore {
		return prev.Namespace, true
	}
	return "", false
}

// manualPBS is what the flags and the earlier controller.env give for a PBS
// the node has no storage for.
type manualPBS struct {
	host, datastore, namespace string
	port                       int
}

func manualPBSDefaults(existing map[string]string, opts setupWizardOptions) manualPBS {
	prev := previousPBS(existing)
	d := manualPBS{host: opts.PBSHost, datastore: opts.PBSDatastore, namespace: opts.PBSNamespace, port: opts.PBSPort}
	if d.host == "" && prev.Server != "" {
		d.host = prev.Server
		if d.port == 0 {
			d.port = prev.Port
		}
		if d.datastore == "" {
			d.datastore = prev.Datastore
		}
		if d.namespace == "" {
			d.namespace = prev.Namespace
		}
	}
	if d.port == 0 {
		d.port = 8007
	}
	return d
}

// namespaceFor is the namespace for the host and datastore finally chosen: the
// default, else the earlier file's for the same PBS server and datastore (a
// rerun must not move the controller to the root namespace, which widens the
// PBS user's grant to the whole datastore, unasked). "" is the root namespace,
// or none given.
func (d manualPBS) namespaceFor(opts setupWizardOptions, existing map[string]string, host, datastore string) string {
	namespace := d.namespace
	if prev := previousPBS(existing); namespace == "" && opts.PBSNamespace == "" && prev.Server != "" && prev.Server == host && prev.Datastore == datastore {
		namespace = prev.Namespace
	}
	return namespace
}

// wizardDirectory: where the keys, the known_hosts file and the environment
// file go.
func wizardDirectory(u *wizardUI, w *setupWizardContext, opts setupWizardOptions) error {
	u.heading("Where this controller keeps its keys and the environment file")
	def := wizardDefaultDir(opts, u.deps)
	for {
		dir, err := u.ask("Directory", def, "--dir")
		if err != nil {
			return err
		}
		if !filepath.IsAbs(dir) {
			u.say("Give an absolute path.")
			if u.yes {
				return fmt.Errorf("--dir %q is not an absolute path", dir)
			}
			continue
		}
		// ssh splits an -o UserKnownHostsFile= value at white space and reads
		// quotes in it: such a path would break every connection.
		if strings.ContainsAny(dir, " \t\r\n\"'\\") {
			u.say("Give a path without spaces, quotes or backslashes: ssh cannot use one for its known_hosts file.")
			if u.yes {
				return fmt.Errorf("--dir %q has a space, quote or backslash, which ssh cannot use in a file path", dir)
			}
			continue
		}
		dir = filepath.Clean(dir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			u.say("Cannot create %s: %v. Create it first (sudo install -d -m 0700 -o \"$USER\" %s) or name a directory you own.", dir, err, dir)
			if u.yes {
				return err
			}
			continue
		}
		if info, err := os.Stat(dir); err == nil && info.Mode().Perm()&0o077 != 0 {
			// Only setup's own directory is made private: a shared one given
			// by mistake (/tmp, a home, /etc, /) keeps its mode.
			if others := filesNotSetups(dir); len(others) > 0 {
				problem := fmt.Sprintf("%s is open to other users (mode %04o) and holds files that are not setup's (%s), so setup does not change its mode. Name a directory for setup alone (setup creates it private), or make this one private yourself (chmod 700 %s) and run setup again", dir, info.Mode().Perm(), strings.Join(others, ", "), dir)
				if u.yes {
					return errors.New(problem)
				}
				u.say("%s.", problem)
				continue
			}
			if err := os.Chmod(dir, 0o700); err != nil {
				return fmt.Errorf("%s is open to other users (mode %04o) and could not be made 0700: %w", dir, info.Mode().Perm(), err)
			}
			u.say("Made %s private (mode 0700): it will hold a private key and two secrets.", dir)
		}
		if !dirWritable(dir) {
			u.say("%s is not writable by you; name a directory you own.", dir)
			if u.yes {
				return fmt.Errorf("%s is not writable", dir)
			}
			continue
		}
		w.dir = dir
		break
	}
	w.knownHosts = filepath.Join(w.dir, "known_hosts")
	w.identity = filepath.Join(w.dir, "id_ed25519")
	w.envPath = filepath.Join(w.dir, "controller.env")
	// What setup writes at the end must be writable then: a link or a
	// directory there is refused here, before anything is changed.
	for _, name := range []string{"controller.env", defaultCAFileName, partialEnvName} {
		if info, err := os.Lstat(filepath.Join(w.dir, name)); err == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("%s exists and is not a regular file (a link or a directory); move it away, then run certistack setup again", filepath.Join(w.dir, name))
		}
	}
	if _, err := os.Stat(w.envPath); err == nil {
		existing, err := loadControllerEnvironment(w.envPath)
		if err != nil {
			u.say("Note: %s exists and cannot be read as an environment file (%v); a copy of it is kept before it is rewritten.", w.envPath, err)
		} else {
			w.existing = existing
			u.say("Note: %s exists. Setup reuses what it can and keeps a copy before it writes the new one.", w.envPath)
		}
	}
	if w.existing == nil {
		w.existing = map[string]string{}
	}
	w.fromPartial = map[string]bool{}
	w.partialPath = filepath.Join(w.dir, partialEnvName)
	if _, err := os.Lstat(w.partialPath); err == nil {
		partial, err := loadControllerEnvironment(w.partialPath)
		if err != nil {
			return fmt.Errorf("%s exists and cannot be read (%v): it holds the secrets of tokens an unfinished setup created; fix or remove it (and those tokens), then run certistack setup again", w.partialPath, err)
		}
		var names []string
		for _, name := range partialEnvNames {
			if value := partial[name]; value != "" {
				w.existing[name] = value
				w.fromPartial[name] = true
				w.partial = append(w.partial, nodesetup.EnvVar{Name: name, Value: value})
				names = append(names, name)
			}
		}
		u.say("Note: %s holds what an unfinished setup kept (%s); setup offers to use it.", w.partialPath, strings.Join(names, ", "))
	}
	return nil
}

// wizardDefaultDir is the directory step 1 offers: --dir, else the first
// writable default directory, else ~/certistack/secure.
func wizardDefaultDir(opts setupWizardOptions, deps setupWizardDeps) string {
	if opts.Dir != "" {
		return opts.Dir
	}
	for _, d := range deps.defaultDirs {
		if dirWritable(d) {
			return d
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "certistack", "secure")
	}
	return ""
}

// sshPenaltyHint explains a connection the node's sshd reset or closed before
// any sign-in: after failed sign-ins from this controller, OpenSSH 10 (PVE 9's)
// refuses its connections for a while (PerSourcePenalties, up to 10 minutes).
func sshPenaltyHint(err error) string {
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "connection reset") || strings.Contains(text, "connection closed by") {
		return " (if this follows failed sign-ins from this controller, the node's sshd refuses its connections for a while, up to 10 minutes: OpenSSH's PerSourcePenalties; wait, then run setup again)"
	}
	return ""
}

// filesNotSetups names, at most three, the entries of dir that setup does not
// write: anything but its key, known_hosts, CA, environment file and their
// copies. A directory it cannot list counts as holding other files.
func filesNotSetups(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{"its entries cannot be listed"}
	}
	var others []string
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case name == "controller.env", name == partialEnvName, strings.HasPrefix(name, "controller.env.bak-"),
			name == "known_hosts", name == "known_hosts.old", name == "id_ed25519", name == "id_ed25519.pub",
			name == defaultCAFileName, name == "pbs-access.sh", strings.HasPrefix(name, ".secret."),
			strings.HasSuffix(name, ".enc"): // a copy of a PBS storage's encryption key
			if entry.Type().IsRegular() {
				continue
			}
		}
		if len(others) == 3 {
			others = append(others, "...")
			break
		}
		others = append(others, name)
	}
	return others
}

// dirWritable reports whether a file can be created in dir.
func dirWritable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	return directoryWritable(dir)
}

// wizardNode: the node's address, its host key, and the controller's key.
func wizardNode(u *wizardUI, w *setupWizardContext, opts setupWizardOptions) error {
	u.heading("The Proxmox VE node")
	def := opts.NodeHost
	if def == "" && w.existing != nil {
		def = w.existing["CERTISTACK_SSH_HOST"]
	}
	var host string
	for {
		answer, err := u.ask("The node's DNS name or IP address, as this controller reaches it over SSH", def, "--node-host")
		if err != nil {
			return err
		}
		normalized, err := nodesetup.NormalizeHost(answer)
		if err == nil && controller.ValidSSHHost(normalized) {
			host = normalized
			break
		}
		u.say("%q is not a host name or address (letters, digits, '.', '-', ':').", answer)
		if u.yes {
			return fmt.Errorf("--node-host %q is not a host name or address", answer)
		}
	}
	// The port: --port, else the earlier file's for this host, else 22.
	port := opts.Port
	if port == 0 && w.existing["CERTISTACK_SSH_HOST"] == host {
		if p, err := strconv.Atoi(w.existing["CERTISTACK_SSH_PORT"]); err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}
	if port == 0 {
		port = 22
	}
	if err := runTrustNode(u.ctx, u.out, u.in, trustNodeRequest{Host: host, Port: port, KnownHosts: w.knownHosts, Fingerprint: opts.Fingerprint, Yes: opts.Yes, InWizard: true}); err != nil {
		if hint := sshPenaltyHint(err); hint != "" {
			return fmt.Errorf("%w%s", err, hint)
		}
		return err
	}
	w.ssh = controller.SSHConfig{Host: host, User: "root", Port: port, IdentityFile: w.identity, KnownHostsFile: w.knownHosts}

	if info, err := os.Stat(w.identity); errors.Is(err, os.ErrNotExist) {
		if err := u.deps.sshKeygen(u.ctx, w.identity); err != nil {
			return fmt.Errorf("create the controller's SSH key %s: %w", w.identity, err)
		}
		u.say("Created the controller's SSH key %s (used for nothing else).", w.identity)
	} else if err != nil {
		return fmt.Errorf("look at %s: %w", w.identity, err)
	} else if err := sysutil.UnsafeToTrust(w.identity, info, sysutil.IdentityWhat, sysutil.IdentityRisk); err != nil {
		// A key someone else could have replaced is not authorized on the node.
		return err
	} else {
		u.say("Using the controller's SSH key %s.", w.identity)
	}
	for attempt := 0; ; attempt++ {
		_, err := u.deps.nodeScript(u.ctx, w.ssh, "true", io.Discard)
		if err == nil {
			u.say("The key signs in to root@%s with strict host-key checking.", host)
			return nil
		}
		// Only a refused key is fixed by authorizing it; a changed host key,
		// a host that does not answer or a wrong port is not.
		if !strings.Contains(err.Error(), "Permission denied") {
			return fmt.Errorf("ssh to root@%s:%d failed, and not because the key is not authorized: %w%s", host, port, err, sshPenaltyHint(err))
		}
		if attempt >= 3 {
			return fmt.Errorf("the key still does not sign in to root@%s: %w", host, err)
		}
		pub, err := os.ReadFile(w.identity + ".pub")
		if err != nil {
			return fmt.Errorf("read %s.pub: %w", w.identity, err)
		}
		u.say("The key is not authorized on the node yet.")
		// Unattended, there is no terminal for root's password, and every
		// failed sign-in counts against this controller: OpenSSH 10 (PVE 9)
		// drops a source's connections for minutes after a few
		// (PerSourcePenalties). One test, then stop with the line to add.
		if u.yes {
			return fmt.Errorf("the controller's key is not authorized on the node, and --yes cannot ask for root's password: append this line to /root/.ssh/authorized_keys on %s, then run setup again:\n  %s", host, strings.TrimSpace(string(pub)))
		}
		// The node cannot be read before the key works, so the question says
		// both cases: root on this node, and, where root's authorized_keys is
		// shared (a cluster), root on every node.
		useCopy, err := u.confirm("Authorize it for root with ssh-copy-id?\n"+
			"  The key then signs in as root on this node. If the node is in a cluster, root's authorized_keys is shared by all its nodes, so the key signs in as root on every node of the cluster.\n"+
			"  ssh-copy-id asks for root's password on the node once.", true)
		if err != nil {
			return err
		}
		if useCopy {
			if err := u.deps.sshCopyID(u.ctx, w.ssh); err != nil {
				u.say("ssh-copy-id did not succeed (%v).", err)
			}
			continue
		}
		u.say("Append this line to /root/.ssh/authorized_keys on the node (its web interface: the node, then Shell):")
		u.say("  %s", strings.TrimSpace(string(pub)))
		if _, err := u.ask("Press Enter when it is there", "", ""); err != nil {
			return err
		}
	}
}

// wizardNodeFacts reads the node, changing nothing.
func wizardNodeFacts(u *wizardUI, w *setupWizardContext, opts setupWizardOptions) error {
	u.heading("Reading the node (nothing is changed)")
	output, err := u.deps.nodeScript(u.ctx, w.ssh, nodesetup.NodeFactsScript, u.out)
	if err != nil {
		return fmt.Errorf("read the node: %w", err)
	}
	facts, err := nodesetup.ParseNodeFacts(output)
	if err != nil {
		return err
	}
	if missing := facts.MissingTools(); len(missing) > 0 {
		return fmt.Errorf("%s has no %s: it is not a Proxmox VE node with PBS support", w.ssh.Host, strings.Join(missing, ", "))
	}
	w.facts = facts
	kind, every := "standalone", "every node of the cluster"
	if facts.Cluster {
		kind = "in a cluster"
		if facts.ClusterNodes > 0 {
			kind = fmt.Sprintf("in a cluster of %d nodes", facts.ClusterNodes)
			every = fmt.Sprintf("all %d nodes", facts.ClusterNodes)
		}
	}
	u.say("Node %s: %s, %s.", facts.Name, facts.PVEVersion, kind)
	if facts.Cluster {
		// Said once, here: what a run costs the cluster is not a choice setup
		// asks about, but it is what a newcomer on a cluster node meets first.
		u.say("Every run applies SDN twice, and PVE reloads the network on %s each time. network.lifecycle: preprovisioned in the plan avoids it (docs/plan-reference.md#use-a-pre-provisioned-sandbox).", every)
	}
	if !facts.KVM {
		u.say("Warning: the node has no /dev/kvm. A run refuses such a node; on a nested node, turn on nested virtualization first.")
	}
	if u.yes {
		return unattendedPBSChoice(w, opts)
	}
	return nil
}

// wizardPackages installs libguestfs-tools and nftables when they are missing.
// It refreshes the node's package lists first (after a yes: it changes apt's
// lists), so that the preview it shows, what would be installed, upgraded and
// removed, is what the install then does; the install does not refresh again.
func wizardPackages(u *wizardUI, w *setupWizardContext, opts setupWizardOptions) error {
	u.heading("Packages on the node")
	missing := w.facts.MissingPackages()
	if len(missing) == 0 {
		u.say("The node has every tool a run needs (qemu-img, proxmox-backup-client, ip, guestfish, nft).")
		return nil
	}
	if !w.facts.Tools["apt-get"] {
		return fmt.Errorf("the node lacks %s and has no apt-get to install them", strings.Join(missing, ", "))
	}
	script, err := nodesetup.PackagesPreviewScript(missing)
	if err != nil {
		return err
	}
	byHand := "a run needs guestfish and nft on the node; install libguestfs-tools and nftables there (apt update; apt install --no-upgrade libguestfs-tools nftables), then run certistack setup again"
	u.say("The node lacks %s.", strings.Join(missing, " and "))
	// The refresh comes before the preview: from lists that were never
	// refreshed apt-get does not know the packages, and from old ones it can
	// show an install other than the one that follows.
	ok, err := u.confirm("Refresh the package lists on "+w.facts.Name+" (apt-get update, which changes only apt's lists), so that what is shown next is what installing does?", true)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New(byHand)
	}
	u.say("On a node without a subscription, apt-get update reports 401 for the enterprise repositories; that is expected.")
	if _, err := u.deps.nodeScript(u.ctx, w.ssh, nodesetup.PackagesUpdateScript, u.out); err != nil {
		return fmt.Errorf("apt-get update on the node: %w", err)
	}
	output, err := u.deps.nodeScript(u.ctx, w.ssh, script, io.Discard)
	if err != nil {
		return fmt.Errorf("ask apt-get what it would install: %w", err)
	}
	preview, err := nodesetup.ParsePackagesPreview(output)
	if err != nil {
		return err
	}
	if preview.Error != "" {
		return fmt.Errorf("apt-get cannot install %s on %s (%s): check the node's package repositories, then run certistack setup again", strings.Join(missing, " and "), w.facts.Name, preview.Error)
	}
	u.say("apt-get would install %d package(s): %s.", len(preview.Install), shortList(preview.Install))
	if len(preview.Upgrade) > 0 {
		u.say("It would also upgrade %d installed package(s) they need: %s.", len(preview.Upgrade), shortList(preview.Upgrade))
	} else {
		u.say("It would upgrade no installed package.")
	}
	removing := len(preview.Remove) > 0
	if removing {
		u.say("It would REMOVE: %s.", strings.Join(preview.Remove, ", "))
	} else {
		u.say("It would remove no installed package.")
	}
	question := "Install them on " + w.facts.Name + " now?"
	if removing {
		question = "Install them on " + w.facts.Name + " now, and remove those packages?"
	}
	ok, err = u.confirm(question, !removing)
	if err != nil {
		return err
	}
	if !ok {
		if removing {
			return fmt.Errorf("nothing was installed, because apt-get would remove %s, and setup removes nothing without your yes (--yes does not give it). A run needs guestfish and nft on the node: find out why apt-get removes those, install libguestfs-tools and nftables there yourself, then run certistack setup again", strings.Join(preview.Remove, ", "))
		}
		return errors.New(byHand)
	}
	install, err := nodesetup.PackagesInstallScript(missing)
	if err != nil {
		return err
	}
	if _, err := u.deps.nodeScript(u.ctx, w.ssh, "exec 1>&2\n"+install, u.out); err != nil {
		return fmt.Errorf("install %s on the node: %w", strings.Join(missing, ", "), err)
	}
	u.say("Installed %s.", strings.Join(missing, " and "))
	return nil
}

// shortList is names, the first 12 and how many more.
func shortList(names []string) string {
	if len(names) <= 12 {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:12], ", ") + fmt.Sprintf(" and %d more", len(names)-12)
}

const minOverlayFreeBytes = 25 << 30

// wizardOverlay reuses or adds the overlay storage.
func wizardOverlay(u *wizardUI, w *setupWizardContext, opts setupWizardOptions) error {
	u.heading("Storage for the sandbox overlays")
	id := opts.OverlayStorage
	if id == "" && w.existing != nil {
		// The storage an earlier setup (or the operator) named.
		id = w.existing["CERTISTACK_OVERLAY_STORAGE"]
	}
	if id == "" {
		id = "certistack-scratch"
	}
	for _, storage := range nodesetup.DirStorages(w.facts.Storage) {
		if storage.ID != id {
			continue
		}
		if !storage.HasContent("images") {
			return fmt.Errorf("the node has a storage %s without images content; name another with --overlay-storage", id)
		}
		if storage.Disabled {
			return fmt.Errorf("the node's storage %s is disabled; enable it (pvesm set %s --disable 0) or name another with --overlay-storage", id, id)
		}
		if !storage.OnNode(w.facts.Name) {
			return fmt.Errorf("the storage %s is limited to node(s) %s, not %s: add %s to its nodes (pvesm set %s --nodes %s,%s) or name another with --overlay-storage",
				id, strings.Join(storage.Nodes, ", "), w.facts.Name, w.facts.Name, id, strings.Join(storage.Nodes, ","), w.facts.Name)
		}
		u.say("Using the existing storage %s (%s).", id, storage.Path)
		w.overlayID = id
		return nil
	}
	if nodesetup.StorageIDTaken(w.facts.Storage, id) {
		return fmt.Errorf("the node has a storage %s that is not a directory storage; name another with --overlay-storage", id)
	}
	path := opts.OverlayPath
	def := ""
	if !w.facts.Cluster {
		def = "/var/lib/vz/" + id
	}
	if path == "" {
		if w.facts.Cluster {
			u.say("The node is in a cluster: put the overlays on a disk of their own, never the root disk, where heavy I/O can delay corosync.")
		} else if w.facts.VZOnRootDisk() {
			u.say("/var/lib/vz is on the node's root disk; runs warn that the overlays share it with the cluster database.")
		}
		if w.facts.VZAvail >= 0 {
			u.say("/var/lib/vz has %s free; a run needs the VM's disk size plus 5 GiB.", humanBytes(w.facts.VZAvail))
		}
	}
	for {
		if path == "" {
			answer, err := u.ask("Directory for the storage "+id, def, "--overlay-path")
			if err != nil {
				return err
			}
			path = answer
		}
		problem, err := overlayPathProblem(u, w, path)
		if err != nil {
			return err
		}
		if problem == "" {
			break
		}
		if u.yes || opts.OverlayPath != "" {
			return errors.New(problem)
		}
		u.say("%s", problem)
		path = ""
	}
	script, err := nodesetup.StorageScript(id, path, w.facts.Name, w.facts.Cluster)
	if err != nil {
		return err
	}
	where := ""
	if w.facts.Cluster {
		where = " on node " + w.facts.Name + " only"
	}
	ok, err := u.confirm(fmt.Sprintf("Add the directory storage %s at %s (images, not shared)%s?", id, path, where), true)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("a run needs a file-based storage with images content for its overlays; add one, then run certistack setup again with --overlay-storage ID")
	}
	if _, err := u.deps.nodeScript(u.ctx, w.ssh, script, u.out); err != nil {
		return fmt.Errorf("add the storage %s: %w", id, err)
	}
	u.say("Added the storage %s.", id)
	w.overlayID = id
	return nil
}

// overlayPathProblem looks, changing nothing, at where path would be on the
// node, and says why it cannot hold the overlays ("" when it can). What is only
// advice (the root disk of a standalone node, little free space) is said here.
func overlayPathProblem(u *wizardUI, w *setupWizardContext, path string) (string, error) {
	if err := nodesetup.CheckOverlayPath(path); err != nil {
		return err.Error(), nil
	}
	script, err := nodesetup.PathProbeScript(path)
	if err != nil {
		return "", err
	}
	output, err := u.deps.nodeScript(u.ctx, w.ssh, script, io.Discard)
	if err != nil {
		return "", fmt.Errorf("look at %s on the node: %w", path, err)
	}
	source, avail, err := nodesetup.ParsePathProbe(output)
	if err != nil {
		return "", err
	}
	onRoot := nodesetup.SameDisk(source, w.facts.RootSource)
	if w.facts.Cluster && onRoot {
		return fmt.Sprintf("%s is on the root disk of a cluster node (%s); give a directory on another disk with --overlay-path", path, source), nil
	}
	if onRoot && !strings.HasPrefix(path, "/var/lib/vz/") {
		u.say("%s is on the node's root disk; runs warn that the overlays share it with the cluster database.", path)
	}
	if avail >= 0 && avail < minOverlayFreeBytes {
		u.say("Warning: only %s free at %s, less than the 25 GiB a VM with a 20 GiB disk needs.", humanBytes(avail), path)
	}
	return "", nil
}

func humanBytes(n int64) string {
	const gib = 1 << 30
	return fmt.Sprintf("%.1f GiB", float64(n)/gib)
}

// tokenListed reports whether a token list (pveum or proxmox-backup-manager,
// --output-format json) names the token.
func tokenListed(output []byte, user, name string) (bool, error) {
	var tokens []map[string]any
	if len(strings.TrimSpace(string(output))) == 0 {
		return false, nil // no tokens: some versions print nothing for an empty list
	}
	if err := json.Unmarshal(output, &tokens); err != nil {
		return false, fmt.Errorf("read the token list: %w", err)
	}
	for _, t := range tokens {
		id, _ := t["tokenid"].(string)
		if id == name || id == user+"!"+name {
			return true, nil
		}
	}
	return false, nil
}

// wizardPVEAccess creates the role, user, token and ACLs and keeps the token's
// secret for the environment file.
func wizardPVEAccess(u *wizardUI, w *setupWizardContext, opts setupWizardOptions) error {
	u.heading("Access to the PVE API")
	acls := nodesetup.PVEACLs(w.facts.Name, w.overlayID, nil)
	paths := make([]string, len(acls))
	for i, acl := range acls {
		paths[i] = acl.Path
	}
	u.say("Setup creates the role %s (the privileges a run needs), the user %s with no password,", nodesetup.RoleName, nodesetup.PVEUser)
	u.say("its privilege-separated token %s, and grants the role on %s (never on /).", nodesetup.PVETokenID, strings.Join(paths, ", "))
	list, err := u.deps.nodeScript(u.ctx, w.ssh, "pveum user token list "+nodesetup.PVEUser+" --output-format json 2>/dev/null || echo '[]'", io.Discard)
	if err != nil {
		return fmt.Errorf("list the tokens of %s: %w", nodesetup.PVEUser, err)
	}
	exists, err := tokenListed(list, nodesetup.PVEUser, nodesetup.PVETokenName)
	if err != nil {
		return err
	}
	secret := ""
	replace := false
	if exists {
		if w.existing["PVE_TOKEN_ID"] == nodesetup.PVETokenID && w.existing["PVE_TOKEN_SECRET"] != "" {
			// A secret kept for another node is this token's only when that
			// node is in the same cluster, which setup cannot tell: then the
			// default is no.
			prevNode := w.existing["CERTISTACK_NODE"]
			sameNode := prevNode == w.facts.Name
			if !sameNode {
				u.say("%s keeps that secret for node %q, not %s: it is this token's secret only if both are in one cluster.", w.sourceOf("PVE_TOKEN_SECRET"), prevNode, w.facts.Name)
			}
			keep, err := u.confirm("The token "+nodesetup.PVETokenID+" exists and "+w.sourceOf("PVE_TOKEN_SECRET")+" holds a secret for it. Keep that secret?", sameNode)
			if err != nil {
				return err
			}
			if keep {
				secret = w.existing["PVE_TOKEN_SECRET"]
			}
		}
		if secret == "" {
			replace, err = u.confirm("The token "+nodesetup.PVETokenID+" exists, and PVE cannot show its secret again. Replace it with a new one? The old secret stops working: anything still using it (a scheduled job, another controller) fails until it gets the new one", false)
			if err != nil {
				return err
			}
			if !replace {
				return errors.New("the token's secret is needed: put it in PVE_TOKEN_SECRET yourself, or run certistack setup again and let it replace the token")
			}
		}
	}
	ok, err := u.confirm("Create or update them on the node now?", true)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("a run needs the PVE token: run certistack setup again, or create it by hand with certistack setup rbac")
	}
	// The old token goes only now, after the yes to the whole change: a no
	// above leaves it working.
	if replace {
		if _, err := u.deps.nodeScript(u.ctx, w.ssh, "pveum user token remove "+nodesetup.PVEUser+" "+nodesetup.PVETokenName+" >&2", u.out); err != nil {
			return fmt.Errorf("remove the old token: %w", err)
		}
	}
	script, err := nodesetup.RBACScript(nodesetup.RBACParams{Node: w.facts.Name, OverlayStorage: w.overlayID, Part: nodesetup.PartPVE, Capture: true, Command: "certistack setup"})
	if err != nil {
		return err
	}
	// The script's output comes back even when a step after the token failed:
	// a new token's secret is kept before anything else can go wrong.
	output, runErr := u.deps.nodeScript(u.ctx, w.ssh, script, u.out)
	if secret == "" {
		created, err := nodesetup.ParseTokenSecret(output)
		switch {
		case err == nil:
			secret = created
			if err := w.keepPartial(nodesetup.EnvVar{Name: "PVE_TOKEN_ID", Value: nodesetup.PVETokenID}, nodesetup.EnvVar{Name: "PVE_TOKEN_SECRET", Value: created},
				nodesetup.EnvVar{Name: "CERTISTACK_NODE", Value: w.facts.Name}); err != nil {
				return fmt.Errorf("the token %s was created, but its secret could not be kept in %s: %w; remove the token (pveum user token remove %s %s) and run certistack setup again",
					nodesetup.PVETokenID, w.partialPath, err, nodesetup.PVEUser, nodesetup.PVETokenName)
			}
		case runErr == nil:
			return fmt.Errorf("read the new token's secret: %w", err)
		}
	}
	if runErr != nil {
		if secret != "" && w.partialHas("PVE_TOKEN_SECRET") {
			u.say("The token's secret is kept in %s; run certistack setup again to finish.", w.partialPath)
		}
		return fmt.Errorf("set up the PVE access: %w", runErr)
	}
	w.env.PVETokenID = nodesetup.PVETokenID
	w.env.PVETokenSecret = secret
	u.say("The PVE token is ready; its secret goes into the environment file.")
	return nil
}

// wizardPBS chooses the PBS, creates the read-only user and token there, and
// learns the certificate's fingerprint.
func wizardPBS(u *wizardUI, w *setupWizardContext, opts setupWizardOptions) error {
	u.heading("The Proxmox Backup Server")
	if err := choosePBS(u, w, opts); err != nil {
		return err
	}
	scope := "the datastore " + w.pbs.Datastore
	if w.pbs.Namespace != "" {
		scope = "the namespace " + w.pbs.Namespace + " of the datastore " + w.pbs.Datastore
	}
	u.say("On the PBS, setup creates the user %s and its token %s with DatastoreReader on %s: read-only.", nodesetup.PBSUser, nodesetup.PBSTokenID, scope)
	script, err := nodesetup.RBACScript(nodesetup.RBACParams{Node: w.facts.Name, OverlayStorage: w.overlayID, PBSDatastore: w.pbs.Datastore, PBSNamespace: w.pbs.Namespace, Part: nodesetup.PartPBS, Capture: true, Command: "certistack setup"})
	if err != nil {
		return err
	}
	repository := w.pbs.Repository(nodesetup.PBSTokenID)
	// A kept secret is offered only for the same PBS server, where the token
	// is the same. The PBS is left as it is only when nothing about the grant
	// changed and the secret comes from a finished setup; otherwise the PBS
	// part runs again, for the grant, and keeps the secret.
	secret, leave := "", false
	prevRepo, prevSecret := w.existing["PBS_REPOSITORY"], w.existing["PBS_PASSWORD"]
	if prevSecret != "" && strings.HasPrefix(prevRepo, nodesetup.PBSTokenID+"@") && pbsServer(prevRepo) == pbsServer(repository) {
		same := prevRepo == repository && w.existing["PBS_NAMESPACE"] == w.pbs.Namespace && !w.fromPartial["PBS_PASSWORD"]
		question := w.sourceOf("PBS_PASSWORD") + " holds a secret for " + nodesetup.PBSTokenID + " on this PBS. Keep it, and leave the PBS as it is?"
		if !same {
			question = w.sourceOf("PBS_PASSWORD") + " holds a secret for " + nodesetup.PBSTokenID + " on this PBS. Keep it? (The PBS part still runs, to grant " + scope + ".)"
		}
		keep, err := u.confirm(question, true)
		if err != nil {
			return err
		}
		if keep {
			secret, leave = prevSecret, same
		}
	}
	if !leave {
		done := false
		if !opts.PBSManual {
			if secret, done, err = pbsOverSSH(u, w, opts, script, secret); err != nil {
				return err
			}
		}
		if !done {
			if secret, err = pbsByHand(u, w, secret); err != nil {
				return err
			}
		}
	}
	if opts.PBSFingerprint != "" {
		given, err := nodesetup.NormalizeFingerprint(opts.PBSFingerprint)
		if err != nil {
			return fmt.Errorf("--pbs-fingerprint: %w", err)
		}
		// One that the node's PBS storage or the PBS itself reports must match.
		if w.pbs.Fingerprint != "" {
			if known, err := nodesetup.NormalizeFingerprint(w.pbs.Fingerprint); err == nil && known != given {
				return fmt.Errorf("--pbs-fingerprint %s is not the fingerprint the PBS storage or the PBS reports (%s)", given, known)
			}
		}
		w.pbs.Fingerprint = given
	}
	for w.pbs.Fingerprint == "" {
		answer, err := u.ask("The PBS certificate's SHA-256 fingerprint (PBS dashboard, Show Fingerprint; or proxmox-backup-manager cert info)", "", "--pbs-fingerprint")
		if err != nil {
			return err
		}
		if _, err := nodesetup.NormalizeFingerprint(answer); err != nil {
			u.say("%v", err)
			continue
		}
		w.pbs.Fingerprint = answer
	}
	fingerprint, err := nodesetup.NormalizeFingerprint(w.pbs.Fingerprint)
	if err != nil {
		return err
	}
	w.env.PBSRepository = repository
	w.env.PBSPassword = secret
	w.env.PBSFingerprint = fingerprint
	w.env.PBSNamespace = w.pbs.Namespace
	if w.pbs.Encrypted {
		if err := copyPBSKey(u, w); err != nil {
			return err
		}
	}
	return nil
}

// choosePBS offers the PBS storages the node is configured with, or asks.
func choosePBS(u *wizardUI, w *setupWizardContext, opts setupWizardOptions) error {
	storages := nodesetup.PBSStorages(w.facts.Storage)
	if opts.PBSStorage != "" {
		for _, s := range storages {
			if s.ID == opts.PBSStorage {
				chosen, ok, err := acceptStorageNamespace(u, w, opts, s)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("setup lets the PBS user read every namespace of the datastore %s only after your yes: name the namespace that holds the backups with --pbs-namespace, or answer yes", s.Datastore)
				}
				w.pbs = chosen
				u.say("Using the node's PBS storage %s: %s:%d, datastore %s%s.", chosen.ID, chosen.Server, chosen.Port, chosen.Datastore, namespaceNote(chosen.Namespace))
				return nil
			}
		}
		return fmt.Errorf("the node has no PBS storage %s", opts.PBSStorage)
	}
	if opts.PBSHost == "" && len(storages) > 0 {
		u.say("The node backs up to these Proxmox Backup Server storages:")
		for i, s := range storages {
			note := ""
			if s.Encrypted {
				note = ", encrypted"
			}
			if i == 0 {
				note += " (default)"
			}
			u.say("  %d. %s: %s:%d, datastore %s%s%s", i+1, s.ID, s.Server, s.Port, s.Datastore, namespaceNote(s.Namespace), note)
		}
		u.say("  %d. another PBS", len(storages)+1)
		for {
			answer, err := u.ask("Which one holds the backups to test", "1", "--pbs-storage")
			if err != nil {
				return err
			}
			n, err := strconv.Atoi(answer)
			if err == nil && n >= 1 && n <= len(storages) {
				chosen, ok, err := acceptStorageNamespace(u, w, opts, storages[n-1])
				if err != nil {
					return err
				}
				if ok {
					w.pbs = chosen
					return nil
				}
				continue // not accepted: choose again
			}
			if err == nil && n == len(storages)+1 {
				break
			}
			u.say("Give a number from 1 to %d.", len(storages)+1)
		}
	}
	// An environment file from an earlier setup names the PBS: offer it.
	prev := previousPBS(w.existing)
	d := manualPBSDefaults(w.existing, opts)
	host, err := askValid(u, "The PBS's DNS name or IP address, as the node reaches it", d.host, "--pbs-host", func(answer string) (string, error) {
		normalized, err := nodesetup.NormalizeHost(answer)
		if err != nil || !controller.ValidSSHHost(normalized) {
			return "", fmt.Errorf("%q is not a host name or address (letters, digits, '.', '-', ':'; no scheme or port: the port is --pbs-port)", answer)
		}
		return normalized, nil
	})
	if err != nil {
		return err
	}
	datastore, err := askValid(u, "The PBS datastore that holds the backups", d.datastore, "--pbs-datastore", func(answer string) (string, error) {
		return answer, nodesetup.CheckDatastore(answer)
	})
	if err != nil {
		return err
	}
	// The flags may name the PBS and datastore the earlier file names: keep its
	// namespace then, unless --pbs-namespace says otherwise. Else a rerun such
	// as the unattended one would move the controller to the root namespace and
	// widen the PBS user's grant to the whole datastore without being asked.
	namespace := d.namespaceFor(opts, w.existing, host, datastore)
	if !u.yes && opts.PBSNamespace == "" {
		for {
			question := "The PBS namespace of the backups (empty for the root namespace)"
			if namespace != "" {
				question = "The PBS namespace of the backups (/ for the root namespace)"
			}
			if namespace, err = askValid(u, question, namespace, "--pbs-namespace", checkNamespaceAnswer); err != nil {
				return err
			}
			// An empty answer is the root namespace, which is every namespace of
			// the datastore: that is a yes of its own.
			ok, err := confirmWholeDatastore(u, datastore, namespace)
			if err != nil {
				return err
			}
			if ok {
				break
			}
		}
	} else if namespace, err = checkNamespaceAnswer(namespace); err != nil {
		return err
	}
	w.pbs = nodesetup.PBSStorage{Server: host, Port: d.port, Datastore: datastore, Namespace: namespace}
	// The earlier file's fingerprint, unless --pbs-fingerprint gives one (a
	// renewed certificate has a new one).
	if prev.Server == host && prev.Datastore == datastore && opts.PBSFingerprint == "" {
		w.pbs.Fingerprint = prev.Fingerprint
	}
	return nil
}

// acceptStorageNamespace is a PBS storage of the node with the namespace the
// PBS user will get (storageNamespace), after the yes that a storage with no
// namespace needs: it backs up to the root namespace, and the grant for it is
// every namespace of the datastore.
func acceptStorageNamespace(u *wizardUI, w *setupWizardContext, opts setupWizardOptions, s nodesetup.PBSStorage) (nodesetup.PBSStorage, bool, error) {
	namespace, named := storageNamespace(s, opts, w.existing)
	s.Namespace = namespace
	if named {
		return s, true, nil
	}
	ok, err := confirmWholeDatastore(u, s.Datastore, "")
	return s, ok, err
}

// confirmWholeDatastore asks before the PBS user is granted the whole datastore:
// an empty namespace is every namespace of it. Under --yes there is no such
// yes: the namespace is named by flag (unattendedPBSChoice stops it earlier).
func confirmWholeDatastore(u *wizardUI, datastore, namespace string) (bool, error) {
	if namespace != "" {
		return true, nil
	}
	if u.yes {
		return false, errNamespaceNotNamed(datastore)
	}
	return u.confirm("The PBS user can then read every namespace of datastore "+datastore+". Continue?", false)
}

// askValid asks until check accepts the answer (once with --yes, where a
// refused answer is an error naming the flag). check returns the value to use.
func askValid(u *wizardUI, question, def, flag string, check func(string) (string, error)) (string, error) {
	for {
		answer, err := u.ask(question, def, flag)
		if err != nil {
			return "", err
		}
		value, err := check(answer)
		if err == nil {
			return value, nil
		}
		if u.yes {
			return "", fmt.Errorf("%s: %w", flag, err)
		}
		u.say("%v", err)
	}
}

// checkNamespaceAnswer is a namespace answer: "/" (or empty) is the root one.
func checkNamespaceAnswer(answer string) (string, error) {
	if answer == "/" {
		answer = ""
	}
	return answer, nodesetup.CheckNamespace(answer)
}

// pbsServer is the "host:port" of a PBS repository, in lower case ("" when it
// is not one): the token is the same for every datastore of one server.
func pbsServer(repository string) string {
	p := previousPBS(map[string]string{"PBS_REPOSITORY": repository})
	if p.Server == "" {
		return ""
	}
	return strings.ToLower(p.Server) + ":" + strconv.Itoa(p.Port)
}

// previousPBS is the PBS an earlier environment file names: the server, port
// and datastore of its PBS_REPOSITORY, its namespace and its fingerprint.
func previousPBS(existing map[string]string) nodesetup.PBSStorage {
	repo := existing["PBS_REPOSITORY"]
	at := strings.LastIndex(repo, "@")
	if at < 0 {
		return nodesetup.PBSStorage{}
	}
	rest := repo[at+1:]
	parts := strings.Split(rest, ":")
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 {
			return nodesetup.PBSStorage{}
		}
		parts = append([]string{rest[1:end]}, strings.Split(strings.TrimPrefix(rest[end+1:], ":"), ":")...)
	}
	if len(parts) != 3 {
		return nodesetup.PBSStorage{}
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return nodesetup.PBSStorage{}
	}
	return nodesetup.PBSStorage{Server: parts[0], Port: port, Datastore: parts[2], Namespace: existing["PBS_NAMESPACE"], Fingerprint: existing["PBS_FINGERPRINT"]}
}

func namespaceNote(ns string) string {
	if ns == "" {
		return ""
	}
	return ", namespace " + ns
}

// pbsFingerprintScript prints the PBS certificate's fingerprint as one JSON
// object on the capture descriptor, after the access part.
const pbsFingerprintScript = `
fp=$(proxmox-backup-manager cert info 2>/dev/null | sed -n 's/^Fingerprint (sha256): *//p' | head -n 1)
printf '{"fingerprint":"%s"}\n' "$fp" >&3
`

// pbsOverSSH runs the PBS part over the operator's own ssh to the PBS. have is
// a secret setup holds for the token already ("" when none). It returns the
// secret and done; done is false when the operator chose the manual way or the
// ssh failed, and then the secret is the one to give pbsByHand (have, or the
// secret of a token this run created before the part failed).
func pbsOverSSH(u *wizardUI, w *setupWizardContext, opts setupWizardOptions, script, have string) (string, bool, error) {
	target := opts.PBSSSH
	if target == "" {
		target = "root@" + w.pbs.Server
	}
	u.say("Setup runs this on the PBS as root over your own SSH (%s), with your keys and known_hosts;", target)
	u.say("ssh may ask for root's password there and to confirm the PBS host key. The controller's key is not used there.")
	ok, err := u.confirm("Run it over ssh now? (No: paste it into the PBS web shell instead)", true)
	if err != nil || !ok {
		return have, false, err
	}
	repository := w.pbs.Repository(nodesetup.PBSTokenID)
	for attempt := 0; attempt < 2; attempt++ {
		// The output comes back even when the part failed after it made the
		// token: the secret is kept first.
		output, runErr := u.deps.pbsScript(u.ctx, target, w.pbsSSHPort, script+pbsFingerprintScript, u.out)
		if fp := captureField(output, "fingerprint"); fp != "" && w.pbs.Fingerprint == "" {
			w.pbs.Fingerprint = fp
		}
		created, err := nodesetup.ParseTokenSecret(tokenObjects(output))
		if err == nil {
			if kerr := w.keepPartial(nodesetup.EnvVar{Name: "PBS_REPOSITORY", Value: repository}, nodesetup.EnvVar{Name: "PBS_PASSWORD", Value: created}); kerr != nil {
				return "", false, fmt.Errorf("the PBS token %s was created, but its secret could not be kept in %s: %w; delete it on the PBS (proxmox-backup-manager user delete-token %s %s) and run certistack setup again",
					nodesetup.PBSTokenID, w.partialPath, kerr, nodesetup.PBSUser, nodesetup.PBSTokenName)
			}
			have = created
		}
		if runErr != nil {
			u.say("The PBS part did not finish over ssh (%v).", runErr)
			return have, false, nil
		}
		if err == nil {
			u.say("The PBS token is ready; its secret goes into the environment file.")
			if err := narrowPBSGrant(u, w, target, output); err != nil {
				return "", false, err
			}
			return created, true, nil
		}
		if !errors.Is(err, nodesetup.ErrTokenExists) {
			return "", false, fmt.Errorf("read the PBS token's secret: %w", err)
		}
		if have != "" {
			u.say("The PBS user, token and grant are in place; setup keeps the token's secret it holds.")
			if err := narrowPBSGrant(u, w, target, output); err != nil {
				return "", false, err
			}
			return have, true, nil
		}
		replace, err := u.confirm("The PBS token "+nodesetup.PBSTokenID+" exists, and PBS cannot show its secret again. Replace it with a new one? The old secret stops working: anything still using it (a scheduled job, another controller) fails until it gets the new one", false)
		if err != nil {
			return "", false, err
		}
		if !replace {
			return "", false, errors.New("the PBS token's secret is needed: put it in PBS_PASSWORD yourself, or run certistack setup again and let it replace the token")
		}
		// Its output goes to stderr: stdout carries only the JSON lines.
		removal := "proxmox-backup-manager user delete-token " + nodesetup.PBSUser + " " + nodesetup.PBSTokenName + " >&2\n"
		script = removal + script
	}
	return "", false, errors.New("the PBS token could not be replaced")
}

// narrowPBSGrant offers to take back the grant on the whole datastore that an
// earlier setup gave the PBS user or its token, now that the PBS part has
// granted one namespace: the namespace grant does not take the wider one back,
// and the user would still read every namespace. The PBS part reports which of
// the two still hold DatastoreReader, propagated, on /datastore/<datastore>
// (the grant setup itself makes for a datastore without a namespace); only
// that grant is removed, over the same ssh. Removing narrows access, so yes is
// the default, and --yes takes it. A removal that fails is said, with the
// commands to run by hand; the setup goes on, since the namespace is granted.
func narrowPBSGrant(u *wizardUI, w *setupWizardContext, target string, output []byte) error {
	if w.pbs.Namespace == "" {
		return nil
	}
	held := nodesetup.WiderGrantHolders(captureField(output, "wider_grant"))
	if len(held) == 0 {
		return nil
	}
	commands, err := nodesetup.PBSGrantRemovalCommands(w.pbs.Datastore, held)
	if err != nil {
		return err
	}
	path := "/datastore/" + w.pbs.Datastore
	byHand := "  " + strings.Join(commands, "\n  ")
	remove, err := u.confirm("The PBS user can still read every namespace of datastore "+w.pbs.Datastore+" (granted by an earlier setup). Remove that grant?", true)
	if err != nil {
		return err
	}
	if !remove {
		u.say("Kept the grant on %s: the PBS user can read every namespace of datastore %s. To remove it later, run as root on the PBS:\n%s", path, w.pbs.Datastore, byHand)
		return nil
	}
	script, err := nodesetup.PBSGrantRemovalScript(w.pbs.Datastore, held)
	if err != nil {
		return err
	}
	if _, err := u.deps.pbsScript(u.ctx, target, w.pbsSSHPort, script, u.out); err != nil {
		if u.ctx.Err() != nil {
			return u.ctx.Err()
		}
		u.say("The grant on %s was not removed (%v): the PBS user can still read every namespace of datastore %s. Remove it as root on the PBS:\n%s", path, err, w.pbs.Datastore, byHand)
		return nil
	}
	u.say("Removed the earlier grant on %s: the PBS user reads the namespace %s, not every namespace of the datastore.", path, w.pbs.Namespace)
	return nil
}

// pbsByHand writes the PBS part to paste into a root shell on the PBS. When
// setup holds no secret for the token, it reads the one the part prints at a
// hidden prompt.
func pbsByHand(u *wizardUI, w *setupWizardContext, have string) (string, error) {
	if u.yes {
		return "", errors.New("the PBS part needs ssh to the PBS when setup runs unattended (--pbs-ssh root@HOST)")
	}
	script, err := nodesetup.RBACScript(nodesetup.RBACParams{Node: w.facts.Name, OverlayStorage: w.overlayID, PBSDatastore: w.pbs.Datastore, PBSNamespace: w.pbs.Namespace, Part: nodesetup.PartPBS, Command: "certistack setup"})
	if err != nil {
		return "", err
	}
	path := filepath.Join(w.dir, "pbs-access.sh")
	if err := nodesetup.WriteSecretFile(path, []byte(script)); err != nil {
		return "", err
	}
	// Typed into sh, not the web shell's own bash: the script's set -eu would
	// otherwise stay in that shell, and its first error would close it.
	u.say("Wrote the PBS part to %s. Run it as root on the PBS: in its web shell (Administration, Shell), type sh, paste the script, then type exit.", path)
	if have != "" {
		u.say("The token exists, so it prints no secret: setup keeps the one it holds.")
		_, err := u.ask("Press Enter when it has run", "", "")
		return have, err
	}
	u.say("It prints the token's secret once: copy only the string after \"value\":, without the quotes.")
	for attempt := 0; attempt < 3; attempt++ {
		pasted, err := u.deps.readSecret(u.ctx, "Paste that secret here (it is not shown): ", u.out)
		if err != nil {
			return "", err
		}
		secret := strings.Trim(strings.TrimSpace(pasted), `"`)
		if _, err := nodesetup.ParseTokenSecret([]byte(`{"value":` + strconv.Quote(secret) + `}`)); err == nil {
			if err := w.keepPartial(nodesetup.EnvVar{Name: "PBS_REPOSITORY", Value: w.pbs.Repository(nodesetup.PBSTokenID)}, nodesetup.EnvVar{Name: "PBS_PASSWORD", Value: secret}); err != nil {
				return "", fmt.Errorf("keep the PBS token's secret in %s: %w", w.partialPath, err)
			}
			return secret, nil
		}
		u.say("That does not look like a PBS token secret (a UUID such as 01234567-89ab-cdef-0123-456789abcdef). Paste only the value.")
		u.say("If the part said the token exists, it printed none: delete it there (proxmox-backup-manager user delete-token %s %s) and run the part again.", nodesetup.PBSUser, nodesetup.PBSTokenName)
	}
	return "", errors.New("no PBS token secret was pasted; run certistack setup again")
}

// tokenObjects keeps the JSON objects of a capture output that are not the
// fingerprint or the wider-grant line, for ParseTokenSecret.
func tokenObjects(output []byte) []byte {
	var kept []string
	for _, line := range strings.Split(string(output), "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, `{"fingerprint":`) || strings.HasPrefix(trimmed, `{"wider_grant":`) {
			continue
		}
		kept = append(kept, line)
	}
	return []byte(strings.Join(kept, "\n"))
}

// captureField is a string field of a JSON object line of a capture output.
func captureField(output []byte, field string) string {
	for _, line := range strings.Split(string(output), "\n") {
		var object map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &object) != nil {
			continue
		}
		if v, ok := object[field].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// copyPBSKey copies an encrypted PBS storage's key from the node.
func copyPBSKey(u *wizardUI, w *setupWizardContext) error {
	u.say("The storage %s encrypts its backups: reading them needs its key, which PVE keeps on the node in %s.", w.pbs.ID, w.pbs.EncryptionKeyPath())
	dest := filepath.Join(w.dir, w.pbs.ID+".enc")
	// The key decrypts every backup in the storage, whatever namespace the PBS
	// user is limited to: copying it is a grant of its own, and the answer is
	// no unless the operator gives it (--yes does not).
	ok, err := u.confirm("The key decrypts every backup in the storage "+w.pbs.ID+". Copy it to "+dest+" (mode 0600)?", false)
	if err != nil {
		return err
	}
	if !ok {
		u.say("Not copied: set CERTISTACK_PBS_KEYFILE to a copy of the key yourself before running a plan.")
		return nil
	}
	data, err := u.deps.nodeFile(u.ctx, w.ssh, w.pbs.EncryptionKeyPath(), 64<<10)
	if err != nil {
		return fmt.Errorf("read %s on the node: %w", w.pbs.EncryptionKeyPath(), err)
	}
	if err := nodesetup.WriteSecretFile(dest, data); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	w.env.PBSKeyFile = dest
	u.say("Copied the key to %s.", dest)
	return nil
}

// wizardEnvironment fetches the PVE CA and writes the environment file.
func wizardEnvironment(u *wizardUI, w *setupWizardContext, opts setupWizardOptions) error {
	u.heading("The environment file")
	if w.facts.CertByClusterCA {
		raw, err := u.deps.nodeFile(u.ctx, w.ssh, nodesetup.PVERootCAPath, pve.MaxCAFileBytes)
		if err != nil {
			return fmt.Errorf("fetch the PVE cluster CA: %w", err)
		}
		bundle, err := nodesetup.ParseCABundle(raw, u.deps.now())
		if err != nil {
			return fmt.Errorf("%s on %s: %w", nodesetup.PVERootCAPath, w.ssh.Host, err)
		}
		caPath := filepath.Join(w.dir, defaultCAFileName)
		if _, err := nodesetup.WriteCAFile(caPath, bundle.PEM); err != nil {
			return err
		}
		u.say("Fetched the node's cluster CA (%s) into %s.", bundle.Certificates[0].Subject, caPath)
		w.env.PVECASource = caPath
	} else {
		// An administrator installed the API certificate (ACME, a company
		// CA): the cluster CA does not sign it, and trusting only that CA
		// would refuse it.
		u.say("The node's API certificate is not signed by its cluster CA (one an administrator installed, such as an ACME one):")
		u.say("setup does not set CERTISTACK_PVE_CA_SOURCE, so the node's own trust store checks it. For a company CA, set it to that CA's file.")
	}

	w.env.PVEURL = "https://" + pveURLHost(w.facts.CertNames, w.ssh.Host, w.facts.Name) + ":8006"
	w.env.Node = w.facts.Name
	w.env.SSHHost = w.ssh.Host
	w.env.SSHPort = w.ssh.Port
	w.env.SSHUser = w.ssh.User
	w.env.SSHIdentity = w.identity
	w.env.SSHKnownHosts = w.knownHosts
	w.env.OverlayStorage = w.overlayID
	// An earlier file's report directory is the operator's choice: it is
	// carried over below.
	if w.existing["CERTISTACK_OUTPUT_DIR"] == "" && !dirWritable(u.deps.reportsDir) {
		reports := filepath.Join(filepath.Dir(w.dir), "reports")
		if err := os.MkdirAll(reports, 0o700); err != nil {
			return fmt.Errorf("%s is not writable and %s could not be created: %w", u.deps.reportsDir, reports, err)
		}
		w.env.OutputDir = reports
		u.say("Reports go to %s (%s is not writable by you).", reports, u.deps.reportsDir)
	}
	kept, notes := keptVariables(w.existing, w.env)
	w.env.Kept = kept
	for _, note := range notes {
		u.say("%s", note)
	}
	data, err := w.env.Render(u.deps.now())
	if err != nil {
		return err
	}
	backup, err := nodesetup.WriteEnvFile(w.envPath, data, u.deps.now())
	if err != nil {
		return err
	}
	if backup != "" {
		u.say("Kept the previous file as %s.", backup)
	}
	u.say("Wrote %s (mode 0600). It holds the two secrets; they were not shown.", w.envPath)
	// The secrets are in controller.env now.
	if err := os.Remove(w.partialPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		u.say("Note: %s could not be removed (%v); it holds the same secrets as %s: remove it.", w.partialPath, err, w.envPath)
	}
	// The commands use this file from now on when they are given no
	// --env-file. Recorded before the check, so that the next steps check
	// prints leave the flag out.
	pointer, err := u.deps.envPointer()
	if err == nil {
		err = recordEnvFile(pointer, w.envPath)
	}
	if err != nil {
		u.say("Note: %s could not be recorded as the default environment file (%v): pass --env-file %s to each command.", w.envPath, err, w.envPath)
		return nil
	}
	w.pointer = pointer
	return nil
}

// setupOwnedVariables are the ones setup decides on every run: it writes them,
// or leaves them out to mean their default (the root namespace, port 22). An
// earlier file's value of one is never carried over.
var setupOwnedVariables = map[string]bool{
	"PVE_URL": true, "PVE_TOKEN_ID": true, "PVE_TOKEN_SECRET": true,
	"PBS_REPOSITORY": true, "PBS_PASSWORD": true, "PBS_FINGERPRINT": true, "PBS_NAMESPACE": true,
	"CERTISTACK_NODE": true, "CERTISTACK_SSH_HOST": true, "CERTISTACK_SSH_PORT": true, "CERTISTACK_SSH_USER": true,
	"CERTISTACK_SSH_IDENTITY": true, "CERTISTACK_SSH_KNOWN_HOSTS": true, "CERTISTACK_OVERLAY_STORAGE": true,
}

// setupDroppedVariables contradict how setup connects: as root, trusting the
// node's own CA. An earlier value is left out, and setup says so.
var setupDroppedVariables = map[string]string{
	"CERTISTACK_SSH_SUDO":      "setup connects as root",
	"PVE_TLS_INSECURE":         "setup fetched the node's cluster CA",
	pve.InsecureTLSLabOptInEnv: "setup fetched the node's cluster CA",
}

// keptVariables are the variables of the earlier environment file that the new
// one carries over, by name, and what setup says about them (names only, never
// a value: some are secrets). The key file and its passphrase are carried over
// only for the same PBS repository.
func keptVariables(existing map[string]string, env nodesetup.EnvFile) ([]nodesetup.EnvVar, []string) {
	names := make([]string, 0, len(existing))
	for name := range existing {
		names = append(names, name)
	}
	sort.Strings(names)
	var kept []nodesetup.EnvVar
	var keptNames, notes []string
	for _, name := range names {
		value := existing[name]
		if value == "" || setupOwnedVariables[name] {
			continue
		}
		if why, ok := setupDroppedVariables[name]; ok {
			notes = append(notes, fmt.Sprintf("Not carried over from the earlier file: %s (%s).", name, why))
			continue
		}
		switch name {
		case "CERTISTACK_PBS_KEYFILE", "PBS_ENCRYPTION_PASSWORD":
			if name == "CERTISTACK_PBS_KEYFILE" && env.PBSKeyFile != "" {
				continue
			}
			if existing["PBS_REPOSITORY"] != env.PBSRepository {
				notes = append(notes, fmt.Sprintf("Not carried over from the earlier file: %s (it was for another PBS repository).", name))
				continue
			}
		case "CERTISTACK_OUTPUT_DIR":
			if env.OutputDir != "" {
				continue
			}
		case "CERTISTACK_PVE_CA_SOURCE":
			// Kept only when setup sets none: a node whose API certificate
			// the cluster CA does not sign, where an earlier value is the
			// operator's CA.
			if env.PVECASource != "" {
				continue
			}
		}
		if !nodesetup.LiteralValue(value) {
			notes = append(notes, fmt.Sprintf("Not carried over from the earlier file: %s (its value cannot be written on one line as it is); the copy keeps it.", name))
			continue
		}
		kept = append(kept, nodesetup.EnvVar{Name: name, Value: value})
		keptNames = append(keptNames, name)
	}
	if len(keptNames) > 0 {
		notes = append(notes, "Carried over from the earlier file: "+strings.Join(keptNames, ", ")+".")
	}
	return kept, notes
}

// pveURLHost is the host for PVE_URL: the SSH host when the node's certificate
// names it (a wildcard name counts), else the node's name, else 127.0.0.1,
// which the worker on the node always reaches, else the certificate's first
// DNS name (one an administrator installed names neither); else the SSH host.
// Without names to compare it is the SSH host, as the manual steps write it.
func pveURLHost(certNames []string, sshHost, nodeName string) string {
	if len(certNames) == 0 {
		return sshHost
	}
	has := func(name string) bool {
		if addr, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil {
			name = addr.String()
		}
		for _, n := range certNames {
			if strings.EqualFold(n, name) {
				return true
			}
			// A wildcard name covers one label: *.example.com covers
			// pve1.example.com.
			if suffix, ok := strings.CutPrefix(n, "*"); ok && strings.HasPrefix(suffix, ".") {
				if label, rest, found := strings.Cut(name, "."); found && label != "" && strings.EqualFold("."+rest, suffix) {
					return true
				}
			}
		}
		return false
	}
	// A certificate an administrator installed may name neither the SSH host,
	// the node nor 127.0.0.1: its own first DNS name (not a wildcard, not
	// localhost) is then the one it is valid for.
	certName := ""
	for _, n := range certNames {
		if _, err := netip.ParseAddr(n); err != nil && !strings.HasPrefix(n, "*") && !strings.EqualFold(n, "localhost") {
			certName = n
			break
		}
	}
	for _, candidate := range []string{sshHost, nodeName, "127.0.0.1", certName} {
		if candidate != "" && has(candidate) {
			if strings.Contains(candidate, ":") {
				return "[" + candidate + "]"
			}
			return candidate
		}
	}
	return sshHost
}

// wizardCheck runs certistack check with the new file.
func wizardCheck(u *wizardUI, w *setupWizardContext, opts setupWizardOptions) error {
	u.heading("Checking the controller")
	if err := u.deps.check(u.ctx, w.envPath, u.out); err != nil {
		return fmt.Errorf("setup wrote %s, but certistack check did not pass: %w", w.envPath, err)
	}
	// check has printed the next step (certistack init ...).
	u.say("Setup is done.")
	if w.pointer != "" {
		u.say("Commands now use %s when not given --env-file (recorded in %s); --env-file chooses another file.%s", w.envPath, w.pointer, pveURLOverridesNote())
	}
	return nil
}

// pveURLOverridesNote is what setup's last line adds when PVE_URL is set in
// its environment: the commands then use the environment, not the file.
func pveURLOverridesNote() string {
	if os.Getenv("PVE_URL") == "" {
		return ""
	}
	return " While PVE_URL is set in the environment, as it is now, they use the environment instead."
}

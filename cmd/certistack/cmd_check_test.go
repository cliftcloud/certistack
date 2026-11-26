// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/nodecheck"
	"github.com/cliftcloud/certistack/internal/nodesetup"
	"github.com/cliftcloud/certistack/pkg/controller"
)

// readyController is a controller directory that passes layers 1 and 2: an
// environment file, an identity, and a known_hosts file that holds the node's
// key.
func readyController(t *testing.T, extraEnv ...string) controllerDir {
	t.Helper()
	c := newControllerDir(t, extraEnv...)
	key := fixedHostKey(t, 5)
	line := nodesetup.KnownHostsLine("pve-node-01.example.com", 2222, key.Key) + "\n"
	if err := os.WriteFile(c.knownHosts, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// nodeStub is a node for check: what its layers answer, and what was asked.
type nodeStub struct {
	machine      string
	sshError     error
	staged       []controller.RunOptions
	stagingError error
	report       nodecheck.Report
	machineCalls int
	// nodeName is the PVE name the node gives; empty answers with the name the
	// environment file gives, which is the node being the one named.
	// nodeNameError is its failure.
	nodeName      string
	nodeNameError error
	nameCalls     int
	cleanupAsked  bool
	environmentAt map[string]string
	// through is what each staged check asked the worker to stop after.
	through []string
	// sandbox is the layer a worker given the plan's network reports last; nil
	// is a layer that passes.
	sandbox *nodecheck.Layer
}

func passingReport() nodecheck.Report {
	return nodecheck.Report{Layers: []nodecheck.Layer{
		{Name: nodecheck.LayerTools, Status: nodecheck.StatusPassed, Detail: "found on the node: qemu-img, proxmox-backup-client, guestfish, ip, nft"},
		{Name: nodecheck.LayerPVE, Status: nodecheck.StatusPassed, Detail: "the node reaches the PVE API and PVE accepts the token (Proxmox VE 9.0.3)"},
		{Name: nodecheck.LayerPBS, Status: nodecheck.StatusPassed, Detail: "the PBS credential lists the repository: 2 VMs have a complete backup"},
	}}
}

func withNode(t *testing.T, stub *nodeStub) {
	t.Helper()
	if stub.machine == "" {
		stub.machine = map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	}
	if len(stub.report.Layers) == 0 {
		stub.report = passingReport()
	}
	previousMachine, previousName, previousOnNode := checkNodeMachine, checkNodeName, checkOnNode
	t.Cleanup(func() {
		checkNodeMachine, checkNodeName, checkOnNode = previousMachine, previousName, previousOnNode
		remoteWorkerStaged.Store(false)
		activeCommand.Store("")
	})
	checkNodeMachine = func(_ context.Context, cfg controller.SSHConfig) (string, error) {
		stub.machineCalls++
		return stub.machine, stub.sshError
	}
	checkNodeName = func(context.Context, controller.SSHConfig) (string, error) {
		stub.nameCalls++
		if stub.nodeNameError != nil {
			return "", stub.nodeNameError
		}
		if stub.nodeName != "" {
			return stub.nodeName, nil
		}
		return os.Getenv("CERTISTACK_NODE"), nil
	}
	checkOnNode = func(_ context.Context, opts controller.RunOptions, through string) ([]byte, error) {
		stub.staged = append(stub.staged, opts)
		stub.through = append(stub.through, through)
		stub.cleanupAsked = interruptHasCleanup()
		stub.environmentAt = map[string]string{
			"PVE_URL": os.Getenv("PVE_URL"), "CERTISTACK_PVE_CA_SOURCE": os.Getenv("CERTISTACK_PVE_CA_SOURCE"),
			"PVE_TOKEN_ID": os.Getenv("PVE_TOKEN_ID"), "PVE_TOKEN_SECRET": os.Getenv("PVE_TOKEN_SECRET"),
		}
		if stub.stagingError != nil {
			return nil, stub.stagingError
		}
		// The worker stops after the layer it is asked to.
		report := stub.report
		for i, layer := range report.Layers {
			if through != "" && layer.Name == through {
				report.Layers = report.Layers[:i+1]
				break
			}
		}
		// A worker given the plan's network judges it last, as the real one does,
		// when every layer before it was tried and none failed.
		if opts.Sandbox != nil && through == "" && report.Failed() == nil {
			layer := nodecheck.Layer{Name: nodecheck.LayerSandbox, Status: nodecheck.StatusPassed, Detail: "network.ip_range " + opts.Sandbox.IPRange + " holds neither the PVE API nor the PBS server, and overlaps none of the node's routes or addresses"}
			if stub.sandbox != nil {
				layer = *stub.sandbox
			}
			report.Layers = append(append([]nodecheck.Layer(nil), report.Layers...), layer)
		}
		return json.Marshal(report)
	}
	remoteWorkerStaged.Store(false)
}

// With a plan the closing line is the plan command and says nothing of writing
// a first plan, the plan being there.
func TestCheckWithAPlanClosesWithThePlanCommand(t *testing.T) {
	c := readyController(t)
	withNode(t, &nodeStub{})
	plan := writeCheckedPlan(t, c)
	out, err := runRootWithInput(t, "", "check", "--env-file", c.env, plan)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	last := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if got, want := last[len(last)-1], "Now run: certistack plan "+plan+" --env-file "+c.env; got != want {
		t.Errorf("the closing line is %q, want %q", got, want)
	}
	if strings.Contains(out, "write a first plan") || strings.Contains(out, "certistack init") {
		t.Errorf("a check with a plan sends the reader to write one:\n%s", out)
	}
}

func TestCheckPassesEveryLayerAndSaysWhatToRunNext(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the golden output is for an x86_64 controller")
	}
	c := readyController(t)
	stub := &nodeStub{}
	withNode(t, stub)
	plan := writeCheckedPlan(t, c)
	before := os.Environ()

	out, err := runRootWithInput(t, "", "check", "--env-file", c.env, plan)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	assertGolden(t, "check_all_pass.golden", maskDir(out, c.dir))

	// The node's layers got what a run would use: the node name, the SSH access
	// and the environment file's values.
	if len(stub.staged) != 1 {
		t.Fatalf("the node's layers were run %d times", len(stub.staged))
	}
	got := stub.staged[0]
	want := controller.SSHConfig{Host: "pve-node-01.example.com", User: "root", Port: 2222, IdentityFile: c.identity, KnownHostsFile: c.knownHosts}
	if got.NodeName != "pve-node-01" || got.SSH != want {
		t.Errorf("worker options = %+v", got)
	}
	if stub.environmentAt["PVE_URL"] != "https://pve-node-01.example.com:8006" {
		t.Errorf("the environment file was not applied while the worker was staged: %v", stub.environmentAt)
	}
	if !stub.cleanupAsked {
		t.Error("check did not say it stages a worker before it did, so an interrupt would call it a command with nothing to clean up")
	}
	for _, secret := range []string{"super-secret-token-value", "super-secret-pbs-value"} {
		if strings.Contains(out, secret) {
			t.Errorf("a secret was printed: %q", secret)
		}
	}
	after := os.Environ()
	if len(before) != len(after) {
		t.Errorf("check left the process environment changed (%d variables before, %d after)", len(before), len(after))
	}
}

func TestCheckWithoutAPlanSaysToWriteOne(t *testing.T) {
	c := readyController(t)
	withNode(t, &nodeStub{})
	out, err := runRootWithInput(t, "", "check", "--env-file", c.env)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	// The next command names the plan as the positional argument it is: with no
	// plan, a first one is written, or one that exists is checked.
	if !strings.Contains(out, "✓ Every layer passed.") || !strings.Contains(out, "certistack init --env-file "+c.env) || !strings.Contains(out, ", or check one you have: certistack check --env-file "+c.env+" <plan.yaml>\n") || strings.Contains(out, "--plan") || strings.Contains(out, "Now run: certistack plan") {
		t.Errorf("output:\n%s", out)
	}
	if strings.Contains(out, "7. Plan") {
		t.Errorf("a plan layer was listed without a plan:\n%s", out)
	}
}

// failsAt runs check against a controller and returns the output and the error;
// it fails the test unless check stops with the infrastructure exit status.
func failsAt(t *testing.T, c controllerDir, args ...string) (string, error) {
	t.Helper()
	out, err := runRootWithInput(t, "", append([]string{"check", "--env-file", c.env}, args...)...)
	if err == nil {
		t.Fatalf("check passed:\n%s", out)
	}
	if exitCodeForError(err) != exitCodeInfrastructure {
		t.Errorf("exit status %d, want %d (%v)", exitCodeForError(err), exitCodeInfrastructure, err)
	}
	return out, err
}

func TestCheckLayer1StopsOnTheEnvironmentFile(t *testing.T) {
	stub := &nodeStub{}
	withNode(t, stub)

	// Missing.
	missing := controllerDir{dir: t.TempDir()}
	missing.env = filepath.Join(missing.dir, "controller.env")
	out, _ := failsAt(t, missing)
	if !strings.Contains(out, "✗ 1. Environment file") || !strings.Contains(out, "does not exist") || !strings.Contains(out, "quickstart step 2") {
		t.Errorf("missing file:\n%s", out)
	}
	for _, later := range []string{"2. SSH files", "3. SSH connection", "4. Node tools", "5. PVE API", "6. PBS"} {
		if !strings.Contains(out, "- "+later) && !strings.Contains(out, "- "+strings.Replace(later, ". ", ". ", 1)) {
			t.Errorf("%q is not listed as not checked:\n%s", later, out)
		}
	}
	if !strings.Contains(out, "not checked: an earlier layer failed") {
		t.Errorf("later layers are not marked:\n%s", out)
	}

	// Others can read it.
	if runtime.GOOS != "windows" {
		wide := readyController(t)
		if err := os.Chmod(wide.env, 0o644); err != nil {
			t.Fatal(err)
		}
		out, _ := failsAt(t, wide)
		if !strings.Contains(out, "has mode 0644, so other users can read the secrets in it") || !strings.Contains(out, "Fix: chmod 600 "+wide.env) {
			t.Errorf("wide mode:\n%s", out)
		}
	}

	// Required variables missing: named, never valued.
	partial := t.TempDir()
	env := filepath.Join(partial, "controller.env")
	body := "PVE_URL=https://pve.example:8006\nPVE_TOKEN_SECRET=do-not-print-this-secret\nCERTISTACK_NODE=pve1\n"
	if err := os.WriteFile(env, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ = failsAt(t, controllerDir{dir: partial, env: env})
	for _, want := range []string{"required variable(s) not set: PBS_REPOSITORY, PBS_PASSWORD, CERTISTACK_SSH_HOST", "Add PBS_REPOSITORY, PBS_PASSWORD, CERTISTACK_SSH_HOST to " + env} {
		if !strings.Contains(out, want) {
			t.Errorf("missing variables: output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "do-not-print-this-secret") {
		t.Errorf("a value was printed:\n%s", out)
	}

	// A line the file may not have.
	if err := os.WriteFile(env, []byte("NOT_A_CERTISTACK_VARIABLE=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ = failsAt(t, controllerDir{dir: partial, env: env})
	if !strings.Contains(out, `unsupported controller environment variable "NOT_A_CERTISTACK_VARIABLE"`) {
		t.Errorf("unsupported variable:\n%s", out)
	}

	if stub.machineCalls != 0 || len(stub.staged) != 0 {
		t.Errorf("a later layer was tried after layer 1 failed (ssh %d, node %d)", stub.machineCalls, len(stub.staged))
	}
}

func TestCheckLayer2StopsOnTheSSHFiles(t *testing.T) {
	stub := &nodeStub{}
	withNode(t, stub)

	// known_hosts missing: the fix is trust-node, with this node's host and port.
	noKnownHosts := readyController(t)
	if err := os.Remove(noKnownHosts.knownHosts); err != nil {
		t.Fatal(err)
	}
	out, _ := failsAt(t, noKnownHosts)
	for _, want := range []string{"✗ 2. SSH files", "there is no known_hosts file at " + noKnownHosts.knownHosts, "Fix: Record it after comparing the fingerprint with the node's: certistack setup trust-node --host pve-node-01.example.com --port 2222 --known-hosts " + quotedPath(noKnownHosts.knownHosts)} {
		if !strings.Contains(out, want) {
			t.Errorf("no known_hosts: output lacks %q:\n%s", want, out)
		}
	}

	// known_hosts without this node.
	otherHost := readyController(t)
	if err := os.WriteFile(otherHost.knownHosts, []byte(nodesetup.KnownHostsLine("another.example", 22, fixedHostKey(t, 6).Key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ = failsAt(t, otherHost)
	if !strings.Contains(out, "has no entry for [pve-node-01.example.com]:2222") || !strings.Contains(out, "certistack setup trust-node --host pve-node-01.example.com --port 2222") {
		t.Errorf("no entry:\n%s", out)
	}

	// A known_hosts file this tool cannot read.
	garbled := readyController(t)
	if err := os.WriteFile(garbled.knownHosts, []byte("pve ssh-ed25519 not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ = failsAt(t, garbled)
	if !strings.Contains(out, "is not a known_hosts file this tool can read") {
		t.Errorf("garbled known_hosts:\n%s", out)
	}

	// The identity is missing.
	noIdentity := readyController(t)
	if err := os.Remove(noIdentity.identity); err != nil {
		t.Fatal(err)
	}
	out, _ = failsAt(t, noIdentity)
	if !strings.Contains(out, "the SSH identity "+noIdentity.identity+" cannot be read") || !strings.Contains(out, "ssh-keygen -t ed25519 -N '' -C certistack-controller -f "+noIdentity.identity) {
		t.Errorf("no identity:\n%s", out)
	}

	// The identity is readable by others: ssh would refuse it.
	if runtime.GOOS != "windows" {
		open := readyController(t)
		if err := os.Chmod(open.identity, 0o644); err != nil {
			t.Fatal(err)
		}
		out, _ = failsAt(t, open)
		if !strings.Contains(out, "will refuse it") || !strings.Contains(out, "chmod 600 "+open.identity) {
			t.Errorf("identity mode:\n%s", out)
		}
	}
	if stub.machineCalls != 0 || len(stub.staged) != 0 {
		t.Errorf("SSH was tried after layer 2 failed (ssh %d, node %d)", stub.machineCalls, len(stub.staged))
	}
}

func TestCheckLayer2NotesAnIdentityThatIsNotSet(t *testing.T) {
	c := readyController(t)
	env, _ := os.ReadFile(c.env)
	if err := os.WriteFile(c.env, []byte(strings.Replace(string(env), "CERTISTACK_SSH_IDENTITY="+c.identity+"\n", "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	withNode(t, &nodeStub{})
	out, err := runRootWithInput(t, "", "check", "--env-file", c.env)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "CERTISTACK_SSH_IDENTITY is not set") {
		t.Errorf("the missing identity was not noted:\n%s", out)
	}
}

func TestCheckLayer3ExplainsWhySSHFailed(t *testing.T) {
	for name, c := range map[string]struct {
		err  string
		want []string
	}{
		"host key changed": {
			"SSH command on pve-node-01.example.com: ssh failed: exit status 255: @@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.",
			[]string{"✗ 3. SSH connection", "ssh to root@pve-node-01.example.com:2222 did not work", "impersonated", "ssh-keygen -R '[pve-node-01.example.com]:2222'"},
		},
		"account has no key": {
			"ssh failed: exit status 255: root@pve-node-01.example.com: Permission denied (publickey,password).",
			[]string{"Permission denied (publickey", "ssh-copy-id"},
		},
		"unrecognized": {
			"ssh failed: exit status 255: something new",
			[]string{"Run the connection by hand to read ssh's own message: ssh -o BatchMode=yes -o StrictHostKeyChecking=yes", "-p 2222", "root@pve-node-01.example.com uname -m"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctl := readyController(t)
			stub := &nodeStub{sshError: errors.New(c.err)}
			withNode(t, stub)
			out, _ := failsAt(t, ctl)
			for _, want := range c.want {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			if len(stub.staged) != 0 {
				t.Error("the node's layers were tried after SSH failed")
			}
		})
	}
}

func TestCheckLayer3RefusesANodeOfAnotherArchitecture(t *testing.T) {
	c := readyController(t)
	stub := &nodeStub{machine: "riscv64"}
	withNode(t, stub)
	out, _ := failsAt(t, c)
	if !strings.Contains(out, "✗ 3. SSH connection") || !strings.Contains(out, `reports architecture "riscv64"`) || len(stub.staged) != 0 {
		t.Errorf("output:\n%s", out)
	}
}

func TestCheckLayer4ToolsSaysAptInstall(t *testing.T) {
	c := readyController(t)
	stub := &nodeStub{report: nodecheck.Report{Layers: []nodecheck.Layer{{
		Name: nodecheck.LayerTools, Status: nodecheck.StatusFailed, Code: nodecheck.CodeToolsMissing,
		Detail:  "not installed on the node (or not on its PATH): guestfish",
		Missing: []nodecheck.Tool{{Name: "guestfish", Package: "libguestfs-tools"}},
	}}}}
	withNode(t, stub)
	out, _ := failsAt(t, c)
	// The fix sends the reader to certistack setup, which previews what apt
	// would do and asks; the command by hand has no -y, so apt asks there too.
	for _, want := range []string{"✗ 4. Node tools", "not installed on the node (or not on its PATH): guestfish", "Fix: Run certistack setup --dir " + c.dir + ": it shows what apt-get would install, upgrade and remove", "asks before it installs", "By hand, on the node as root: apt update; apt install --no-upgrade libguestfs-tools", "apt update prints 401 Unauthorized for enterprise.proxmox.com", "- 5. PVE API", "- 6. PBS"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "install -y") {
		t.Errorf("the fix prints an apt install that does not ask:\n%s", out)
	}
	if !strings.Contains(out, "3. SSH connection") || !strings.Contains(out, "✓ 3.") {
		t.Errorf("the layers before were not shown as passed:\n%s", out)
	}
}

func TestCheckLayer5NamesSetupPVECAForAnUntrustedCertificate(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the golden output is for an x86_64 controller")
	}
	pveFailure := nodecheck.Report{Layers: []nodecheck.Layer{
		{Name: nodecheck.LayerTools, Status: nodecheck.StatusPassed, Detail: "found on the node: qemu-img, proxmox-backup-client, guestfish, ip, nft"},
		{Name: nodecheck.LayerPVE, Status: nodecheck.StatusFailed, Code: nodecheck.CodePVECAUntrusted,
			Detail: "the node does not trust the certificate authority that signed the PVE API certificate (x509: certificate signed by unknown authority)"},
	}}
	c := readyController(t)
	stub := &nodeStub{report: pveFailure}
	withNode(t, stub)
	out, _ := failsAt(t, c)
	assertGolden(t, "check_pve_ca.golden", maskDir(out, c.dir))
	if len(stub.staged) != 1 {
		t.Errorf("the node was asked %d times", len(stub.staged))
	}

	// When a CA is already named, the fix refreshes that file.
	named := filepath.Join(t.TempDir(), "ca.pem")
	c2 := readyController(t, "CERTISTACK_PVE_CA_SOURCE="+named)
	if err := os.WriteFile(named, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	withNode(t, &nodeStub{report: pveFailure})
	out, _ = failsAt(t, c2)
	if !strings.Contains(out, "CERTISTACK_PVE_CA_SOURCE is set ("+named+")") || !strings.Contains(out, "certistack setup pve-ca --env-file "+c2.env+" --out "+named) {
		t.Errorf("a named CA:\n%s", out)
	}
}

func TestCheckLayerFixesForEveryNodeFailure(t *testing.T) {
	for _, c := range []struct {
		layer nodecheck.Layer
		title string
		want  []string
	}{
		{nodecheck.Layer{Name: nodecheck.LayerPVE, Code: nodecheck.CodePVEAuth, Detail: "PVE answered but rejected the token (HTTP 401)"}, "5. PVE API", []string{"PVE_TOKEN_ID", "certistack setup rbac --node"}},
		{nodecheck.Layer{Name: nodecheck.LayerPVE, Code: nodecheck.CodePVEUnreachable, Detail: "the node cannot reach the PVE API: connection refused"}, "5. PVE API", []string{"The node, not this controller, calls the PVE API", "from the node itself"}},
		{nodecheck.Layer{Name: nodecheck.LayerPVE, Code: nodecheck.CodePVECertName, Detail: "the PVE API certificate does not name the host in PVE_URL (pve)"}, "5. PVE API", []string{"host name or address the PVE certificate is issued for"}},
		{nodecheck.Layer{Name: nodecheck.LayerPVE, Code: nodecheck.CodePVECertInvalid, Detail: "expired"}, "5. PVE API", []string{"pvecm updatecerts --force"}},
		{nodecheck.Layer{Name: nodecheck.LayerPVE, Code: nodecheck.CodePVEConfig, Detail: "configure PVE API client: PVE base URL must be an absolute HTTP(S) URL"}, "5. PVE API", []string{"PVE_URL (https, with no path)"}},
		{nodecheck.Layer{Name: nodecheck.LayerPBS, Code: nodecheck.CodePBSFailed, Detail: "list PBS snapshots: exit status 255 (client output withheld; 38 bytes)"}, "6. PBS", []string{"exit status 255 (client output withheld; 38 bytes)", "PBS_FINGERPRINT", "proxmox-backup-client snapshot list --repository '<your PBS_REPOSITORY>'"}},
	} {
		layer := c.layer
		layer.Status = nodecheck.StatusFailed
		report := passingReport()
		for i := range report.Layers {
			if report.Layers[i].Name == layer.Name {
				report.Layers[i] = layer
				report.Layers = report.Layers[:i+1]
				break
			}
		}
		ctl := readyController(t)
		withNode(t, &nodeStub{report: report})
		out, _ := failsAt(t, ctl)
		if !strings.Contains(out, "✗ "+c.title) {
			t.Errorf("%s: the layer was not marked failed:\n%s", layer.Code, out)
		}
		for _, want := range c.want {
			if !strings.Contains(out, want) {
				t.Errorf("%s: output lacks %q:\n%s", layer.Code, want, out)
			}
		}
		if strings.Contains(out, "super-secret") {
			t.Errorf("%s: a secret was printed", layer.Code)
		}
	}
}

func TestCheckPBSFixMentionsTheNamespaceWhenOneIsSet(t *testing.T) {
	c := readyController(t, "PBS_NAMESPACE=prod")
	report := passingReport()
	report.Layers[2] = nodecheck.Layer{Name: nodecheck.LayerPBS, Status: nodecheck.StatusFailed, Code: nodecheck.CodePBSFailed, Detail: "list PBS snapshots: exit status 255"}
	withNode(t, &nodeStub{report: report})
	out, _ := failsAt(t, c)
	if !strings.Contains(out, "--pbs-datastore <datastore> --pbs-namespace <namespace>") {
		t.Errorf("output:\n%s", out)
	}
}

func TestCheckExplainsAWorkerThatCouldNotBeStaged(t *testing.T) {
	for name, c := range map[string]struct {
		err  string
		want string
	}{
		"not root": {"create protected node workspace: SSH command on pve: ssh failed: exit status 1: install: cannot create directory '/var/lib/certistack': Permission denied", "CERTISTACK_SSH_SUDO=true"},
		"CA file":  {"stage PVE CA file: read PVE TLS CA file: no such file", "certistack setup pve-ca --env-file"},
		"PBS key":  {"stage PBS encryption key: the key file is group readable", "CERTISTACK_PBS_KEYFILE"},
		"other":    {"something else broke", "certistack check --debug --env-file"},
	} {
		t.Run(name, func(t *testing.T) {
			ctl := readyController(t)
			withNode(t, &nodeStub{stagingError: errors.New(c.err)})
			out, _ := failsAt(t, ctl)
			if !strings.Contains(out, "✗ 4. Node tools") || !strings.Contains(out, "could not put its temporary worker on the node") || !strings.Contains(out, c.want) {
				t.Errorf("output lacks %q:\n%s", c.want, out)
			}
		})
	}
}

func TestCheckLayer7RefusesAPlanThatIsNotThere(t *testing.T) {
	c := readyController(t)
	withNode(t, &nodeStub{})
	out, _ := failsAt(t, c, filepath.Join(c.dir, "no-such-plan.yaml"))
	if !strings.Contains(out, "✗ 7. Plan") || !strings.Contains(out, "cannot be read") {
		t.Errorf("output:\n%s", out)
	}
}

// An interrupt ends the command with the interrupted status, not a failed layer.
func TestCheckEndsWithTheInterruptedStatusWhenCanceled(t *testing.T) {
	c := readyController(t)
	withNode(t, &nodeStub{})
	checkNodeMachine = func(ctx context.Context, cfg controller.SSHConfig) (string, error) { return "", context.Canceled }
	root := newRootCmd(nil)
	root.SetOut(&strings.Builder{})
	root.SetErr(&strings.Builder{})
	root.SetArgs([]string{"check", "--env-file", c.env})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := root.ExecuteContext(ctx)
	if exitCodeForError(err) != exitCodeInterrupted {
		t.Errorf("exit status %d (%v), want %d", exitCodeForError(err), err, exitCodeInterrupted)
	}
}

func TestCheckRequiresAnEnvironmentFileAndTakesOnePlan(t *testing.T) {
	withNode(t, &nodeStub{})
	if _, err := runRootWithInput(t, "", "check"); err == nil || !strings.Contains(err.Error(), "env-file") {
		t.Errorf("no --env-file: %v", err)
	}
	if _, err := runRootWithInput(t, "", "check", "--env-file", "x", "a.yaml", "b.yaml"); err == nil {
		t.Error("two plans were accepted")
	}
}

func TestCheckHelpListsTheLayers(t *testing.T) {
	help, err := runRootWithInput(t, "", "check", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--env-file", "[plan.yaml]", "mode 0600", "setup trust-node", "qemu-img", "guestfish", "certistack setup", "apt update; apt install --no-upgrade libguestfs-tools", "401", "setup pve-ca", "PBS credential", "exits 0 only when every layer passes"} {
		if !strings.Contains(help, want) {
			t.Errorf("check --help does not mention %q", want)
		}
	}
}

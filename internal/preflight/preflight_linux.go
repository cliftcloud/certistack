// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package preflight performs read-only environment, hardware, and dependency
// checks before a run.
package preflight

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cliftcloud/certistack/internal/support"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// CheckItem represents an individual preflight check outcome.
type CheckItem struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "passed", "failed", "warning", "skipped"
	Detail string `json:"detail"`
}

// Result encapsulates all preflight check outcomes.
type Result struct {
	Ready            bool                  `json:"ready"`
	Checks           []CheckItem           `json:"checks"`
	MemoryEvaluation *admission.Evaluation `json:"memory_evaluation,omitempty"`
	// Versions are the Proxmox versions the preflight read, and whether this
	// release has been tested with them (the version_support check).
	Versions *VersionReport `json:"versions,omitempty"`
}

// Options configures optional preflight checks.
type Options struct {
	ScratchDir     string
	StateDir       string
	RequiredRAMMB  int
	MinimumFreeGiB int
	PVEURL         string
	PVETLSInsecure bool
	PVETLSCAFile   string
	PVETokenID     string
	PVETokenSecret string
	// RequirePVEConnectivity turns PVE endpoint and token validation into a
	// hard gate. The remote node worker sets this because it cannot perform a
	// safe recovery run without authenticated PVE access; controller-side
	// doctor remains diagnostic-only.
	RequirePVEConnectivity bool
	// WorkerMode validates the plan the node worker was sent, which lacks the
	// controller's own settings (MarshalWorkerPlan).
	WorkerMode bool
	// PBSKeyfile is CERTISTACK_PBS_KEYFILE, checked when set, and
	// PBSEncryptionPassword the PBS_ENCRYPTION_PASSWORD that unlocks it.
	PBSKeyfile            string
	PBSEncryptionPassword string
	// NodeName and OverlayStorage place the plan's privilege check: the
	// token's privileges are read on the paths a run on this node touches.
	// OverlayStorage defaults to the plan's storage.overlay_storage.
	NodeName       string
	OverlayStorage string
}

// readNodeNetworksForCheck reads the node's routes and addresses for the
// sandbox_network check; a variable so that a test can give Check a node.
var readNodeNetworksForCheck = ReadNodeNetworks

// Check runs all read-only preflight diagnostic checks. ctx stops the ones
// that wait on the PVE API, the connectivity request and each privilege
// request: an interrupted command ends them at once instead of after their
// own time limits. A Result from a Check whose ctx ended is not a
// verdict: the checks it stopped are reported as failed or warned for what
// stopped them, and the caller, which owns ctx, should say it was interrupted
// instead of showing it.
func Check(ctx context.Context, plan *config.Plan, opts Options) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	r := Result{Ready: true}

	add := func(name string, err error, success string) {
		item := CheckItem{Name: name, Status: "passed", Detail: success}
		if err != nil {
			r.Ready = false
			item.Status = "failed"
			item.Detail = err.Error()
		}
		r.Checks = append(r.Checks, item)
	}

	addWarn := func(name string, warnErr error, success string) {
		item := CheckItem{Name: name, Status: "passed", Detail: success}
		if warnErr != nil {
			item.Status = "warning"
			item.Detail = warnErr.Error()
		}
		r.Checks = append(r.Checks, item)
	}

	// 1. Plan validation
	if plan != nil {
		var errs []config.ValidationError
		if opts.WorkerMode {
			errs = config.ValidateForWorker(plan)
		} else {
			errs = config.Validate(plan)
		}
		var planErr error
		if len(errs) > 0 {
			planErr = fmt.Errorf("plan schema errors: %v", errs[0].Message)
		}
		add("plan", planErr, fmt.Sprintf("plan %s is valid", plan.PlanID))
		repository := os.Getenv("PBS_REPOSITORY")
		if repository == "" {
			repository = plan.Storage.PBSRepository
		}
		add(SandboxRangeCheckName, CheckSandboxRange(ctx, plan, opts.PVEURL, repository, nil), "the sandbox network contains neither the PVE API nor the PBS server")
		// The range against the node's own networks. A node whose routes
		// cannot be read is a warning that says the range was not compared,
		// never a pass.
		if _, present, rangeErr := sandboxPrefix(plan.Network); present || rangeErr != nil {
			warning, networkErr := VerifySandboxNetwork(plan.Network, OwnVNetInterface(plan.Network), readNodeNetworksForCheck)
			switch {
			case networkErr != nil:
				add(SandboxNetworkCheckName, networkErr, "")
			case warning != "":
				addWarn(SandboxNetworkCheckName, errors.New(warning), "")
			default:
				add(SandboxNetworkCheckName, nil, "the sandbox network overlaps none of the node's real networks, and holds neither a gateway of its routes nor an address of the node")
			}
		}
	}

	// 2. Privileges (root required for PBS loop device mapping)
	var privErr error
	if os.Geteuid() != 0 {
		privErr = errors.New("CertiStack requires root privileges for node-local PBS mapping, QEMU, and cleanup operations")
	}
	add("privileges", privErr, "running as root")

	// 3. KVM Virtualization
	f, kvmErr := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if f != nil {
		f.Close()
	}
	add("kvm", kvmErr, "/dev/kvm is accessible for hardware acceleration")

	// 4. Executable Lookups
	for _, bin := range []string{"qemu-img", "proxmox-backup-client", "ip"} {
		_, err := exec.LookPath(bin)
		add(bin, err, fmt.Sprintf("%s executable found", bin))
	}

	// 4b. Sandbox tools, each only when the plan needs it: nft contains the
	// host-side probe address, guestfish writes COW-only network recovery.
	if plan == nil || planHasWireProbes(plan) {
		_, err := exec.LookPath("nft")
		if err != nil {
			err = fmt.Errorf("nft (nftables) is required to contain the sandbox probe address: %w", err)
		}
		add("nft", err, "nft executable found for sandbox containment")
	}
	if plan != nil && planUsesNetworkRecovery(plan) {
		_, err := exec.LookPath("guestfish")
		if err != nil {
			err = fmt.Errorf("guestfish (package libguestfs-tools) is required for network recovery; install it or set network_recovery.mode: preserve: %w", err)
		}
		add("guestfish", err, "guestfish executable found for network recovery")
	}

	// 4c. The PBS encryption key, before any restore needs it.
	if opts.PBSKeyfile != "" {
		add("pbs_keyfile", pbs.ValidateKeyfile(opts.PBSKeyfile), "PBS encryption key is a private PBS key file")
		add("pbs_key_passphrase", pbs.CheckKeyPassphrase(opts.PBSKeyfile, opts.PBSEncryptionPassword), "PBS encryption key's passphrase is set when it needs one")
	}

	// 5. Host Memory Availability
	reqRAM := opts.RequiredRAMMB
	reservationDetail := ""
	if reqRAM <= 0 && plan != nil {
		reservation, vmCount, tierLevel, reservationErr := admission.RecoveryMemoryReservation(plan)
		if reservationErr != nil {
			add("memory", reservationErr, "")
		} else {
			reqRAM = reservation
			if vmCount > 0 {
				reservationDetail = fmt.Sprintf(" for %d concurrent sandbox VM(s) through tier %d", vmCount, tierLevel)
			}
		}
	}
	if reqRAM > 0 {
		maxPercent := 0.0
		if plan != nil && reservationDetail != "" {
			maxPercent = plan.AdmissionControl.MaxHostRAMPercent
		}
		evaluation, memErr := admission.PreflightMemory(reqRAM, maxPercent)
		if memErr != nil {
			r.MemoryEvaluation = &evaluation
		}
		add("memory", memErr, fmt.Sprintf("host has sufficient available RAM for concurrent recovery reservation (%d MiB%s)", reqRAM, reservationDetail))
	}

	// 6. Scratch Directory Safety & Free Space
	scratch := opts.ScratchDir
	if scratch == "" {
		scratch = sysutil.DefaultScratchDir
	}
	// A failure names the directory it checked, since which one that is
	// follows from the flag, the environment and the plan.
	scratchPathErr := SafePath(scratch)
	if scratchPathErr != nil {
		scratchPathErr = fmt.Errorf("scratch directory %s: %w", scratch, scratchPathErr)
	}
	add("scratch_path", scratchPathErr, fmt.Sprintf("scratch directory path %s is safe", scratch))

	minFreeGiB := opts.MinimumFreeGiB
	if minFreeGiB <= 0 {
		minFreeGiB = 5 // default 5 GiB minimum
	}
	free, freeErr := FreeBytes(scratch)
	if freeErr == nil && free < uint64(minFreeGiB)*(1<<30) {
		freeErr = fmt.Errorf("scratch directory %s has %.1f GiB free, but %d GiB is required", scratch, float64(free)/(1<<30), minFreeGiB)
	}
	add("scratch_space", freeErr, fmt.Sprintf("scratch storage has %.1f GiB free space", float64(free)/(1<<30)))

	// 6a. The node state directory holds the recovery journal and the worker
	// workspaces. A run creates it private if it is missing and refuses one
	// that is not private, shared or owned by someone else, so the flag
	// doctor was given is checked the way the worker checks it.
	if opts.StateDir != "" {
		existed, stateErr := sysutil.CheckPrivateDirectory(opts.StateDir)
		detail := fmt.Sprintf("state directory %s is private and usable", opts.StateDir)
		if stateErr == nil && !existed {
			detail = fmt.Sprintf("state directory %s does not exist yet; a run creates it private (mode 0700)", opts.StateDir)
		}
		add("state_path", stateErr, detail)
	}

	// 6b. Loop devices left by a PBS map whose daemon and FUSE mount are
	// gone. Nothing ties them to a run, so they are named, not released.
	addWarn("stale_loops", staleLoopsWarning(sysutil.StaleFUSELoops(), sysutil.OrphanedFUSEConnections()), "no loop device is attached to a FUSE file that is no longer mounted")

	// 7. PVE API connectivity is diagnostic for a controller-side doctor, but
	// mandatory for the temporary node worker before it can create or recover
	// an exact sandbox VM.
	var pveVersion string
	if opts.RequirePVEConnectivity {
		var pveErr error
		switch {
		case strings.TrimSpace(opts.PVEURL) == "":
			pveErr = errors.New("PVE_URL is required for a node worker")
		case strings.TrimSpace(opts.PVETokenID) == "" || strings.TrimSpace(opts.PVETokenSecret) == "":
			pveErr = errors.New("PVE_TOKEN_ID and PVE_TOKEN_SECRET are required for a node worker")
		default:
			pveVersion, pveErr = checkPVEConnectivity(ctx, opts.PVEURL, opts.PVETLSInsecure, opts.PVETLSCAFile, opts.PVETokenID, opts.PVETokenSecret)
		}
		add("pve_connectivity", pveErr, fmt.Sprintf("Proxmox VE API authenticated and reachable at %s", opts.PVEURL))
		if pveErr == nil {
			checkPVEPrivileges(ctx, plan, opts, add, addWarn)
		}
	} else if opts.PVEURL != "" {
		var pveErr error
		pveVersion, pveErr = checkPVEConnectivity(ctx, opts.PVEURL, opts.PVETLSInsecure, opts.PVETLSCAFile, opts.PVETokenID, opts.PVETokenSecret)
		addWarn("pve_connectivity", pveErr, fmt.Sprintf("Proxmox VE API reachable at %s", opts.PVEURL))
		if pveErr == nil && opts.PVETokenID != "" {
			checkPVEPrivileges(ctx, plan, opts, add, addWarn)
		}
	}

	// 8. The Proxmox versions, and whether this release has been tested with
	// the pair: the PVE version from the request above (no second one), the
	// PBS server's and the client's from `proxmox-backup-client version`. A
	// version that cannot be read is unknown, a warning; only a pair the
	// release does not support makes the host not ready, with the text run
	// and plan refuse with (internal/support).
	applyVersionStatus(&r, support.Detect(ctx, support.Sources{
		PVE: func(context.Context) (string, error) { return pveVersion, nil },
		PBS: pbsVersionSource(plan),
	}))

	return r
}

// pbsVersionSource reads the PBS client's and server's versions with the
// repository and credentials a run would use: the environment, else the plan.
func pbsVersionSource(plan *config.Plan) func(context.Context) (string, string, error) {
	cfg := pbs.Config{
		Repository:  os.Getenv("PBS_REPOSITORY"),
		Password:    os.Getenv("PBS_PASSWORD"),
		Fingerprint: os.Getenv("PBS_FINGERPRINT"),
	}
	if plan != nil {
		if cfg.Repository == "" {
			cfg.Repository = plan.Storage.PBSRepository
		}
		if cfg.Fingerprint == "" {
			cfg.Fingerprint = plan.Storage.PBSFingerprint
		}
	}
	return pbs.New(cfg).Versions
}

// staleLoopsWarning describes stale FUSE loops, and FUSE connections with
// requests nothing will answer, and how to release them; or is nil for
// none. A connection must be aborted before its loop is detached: while
// reads wait on it, losetup -d, udev and PVE's vgs hang on the loop, which
// freezes the node's status.
func staleLoopsWarning(loops []sysutil.StaleFUSELoop, conns []sysutil.OrphanedFUSEConnection) error {
	if len(loops) == 0 && len(conns) == 0 {
		return nil
	}
	var parts, steps []string
	if len(conns) > 0 {
		var names, aborts []string
		for _, c := range conns {
			names = append(names, fmt.Sprintf("%s (%d waiting)", c.Minor, c.Waiting))
			aborts = append(aborts, fmt.Sprintf("echo 1 > /sys/fs/fuse/connections/%s/abort", c.Minor))
		}
		parts = append(parts, fmt.Sprintf("FUSE connection(s) %s have requests waiting and no mount, most likely a PBS map whose process died; nothing will answer them, and anything that opens their loop device hangs, PVE's vgs included", strings.Join(names, ", ")))
		steps = append(steps, "abort them first: "+strings.Join(aborts, "; "))
	}
	if len(loops) > 0 {
		var devices, sizes, held []string
		var holders []sysutil.LoopHolder
		seen := map[string]bool{}
		for _, loop := range loops {
			devices = append(devices, loop.Device)
			state := ""
			if loop.Stuck {
				state = ", reads stuck"
			}
			sizes = append(sizes, fmt.Sprintf("%s (%.1f GiB%s)", loop.Device, float64(loop.Bytes)/(1<<30), state))
			if len(loop.Holders) > 0 {
				held = append(held, fmt.Sprintf("%s: %s", loop.Device, sysutil.HolderLabels(loop.Holders)))
			}
			// A device that holds several loops (a RAID across two disks) is named once.
			for _, holder := range loop.Holders {
				if !seen[holder.Name] {
					seen[holder.Name] = true
					holders = append(holders, holder)
				}
			}
		}
		parts = append(parts, fmt.Sprintf("%s: read-only loop device(s) attached to a FUSE file that is no longer mounted; nothing can read them", strings.Join(sizes, ", ")))
		// A loop that software RAID, LVM or dm-crypt devices hold stays after
		// losetup -d (the detach only marks it for removal): they are stopped first.
		if len(holders) > 0 {
			parts = append(parts, fmt.Sprintf("the host assembled devices from their partitions (%s), and losetup -d cannot release a loop device they hold until they are stopped", strings.Join(held, "; ")))
			if commands := sysutil.StopCommands(holders); len(commands) > 0 {
				steps = append(steps, "stop what holds them: "+strings.Join(commands, "; "))
			}
		}
		steps = append(steps, "release them: losetup -d "+strings.Join(devices, " "))
	}
	return fmt.Errorf("%s. To fix, %s", strings.Join(parts, ". "), strings.Join(steps, ", then "))
}

func planHasWireProbes(plan *config.Plan) bool { return plan.HasWireProbes() }

func planUsesNetworkRecovery(plan *config.Plan) bool {
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			if _, configured, err := vm.SandboxAddress(plan.Network); err == nil && configured {
				return true
			}
		}
	}
	return false
}

// CheckMemory reads /proc/meminfo to verify MemAvailable meets requiredMiB.
func CheckMemory(requiredMiB int) error {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil // Non-Linux or container, skip
	}
	defer f.Close()

	available, err := parseAvailableMemory(f)
	if err != nil {
		return err
	}

	if available < uint64(requiredMiB)*(1<<20) {
		return fmt.Errorf("available RAM %.0f MiB is below required %d MiB", float64(available)/(1<<20), requiredMiB)
	}
	return nil
}

func parseAvailableMemory(r io.Reader) (uint64, error) {
	s := bufio.NewScanner(r)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 0 && fields[0] == "MemAvailable:" {
			if len(fields) != 3 || fields[2] != "kB" {
				return 0, errors.New("invalid MemAvailable units")
			}
			v, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil || v > ^uint64(0)/1024 {
				return 0, errors.New("invalid MemAvailable value")
			}
			return v * 1024, nil
		}
	}
	return 0, errors.New("MemAvailable not found in /proc/meminfo")
}

// FreeBytes returns available bytes on the filesystem hosting path using Statfs.
func FreeBytes(path string) (uint64, error) {
	for {
		var stat syscall.Statfs_t
		err := syscall.Statfs(path, &stat)
		if err == nil {
			return stat.Bavail * uint64(stat.Bsize), nil
		}
		if !errors.Is(err, os.ErrNotExist) || path == "/" {
			return 0, err
		}
		path = filepath.Dir(path)
	}
}

// SafePath checks that the scratch directory is private, clean, owned by the
// current process user, and contains no symlinked path component.
func SafePath(path string) error {
	return sysutil.ValidatePrivateDirectory(path)
}

// checkPVEPrivileges reads the token's privileges on every path a run of
// plan touches and fails, listing all of them at once, when it lacks one the
// run needs. A privilege the run works around is a warning, and so is a
// failure to read them: the run itself still finds out at the first call.
func checkPVEPrivileges(ctx context.Context, plan *config.Plan, opts Options, add, addWarn func(string, error, string)) {
	if plan == nil || strings.TrimSpace(opts.NodeName) == "" {
		return
	}
	var vmids []int
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			vmids = append(vmids, vm.VMID)
		}
	}
	storage := opts.OverlayStorage
	if storage == "" {
		storage = plan.Storage.OverlayStorage
	}
	client := pve.NewClient(pve.Config{
		BaseURL: opts.PVEURL, TLSInsecure: opts.PVETLSInsecure, TLSCAFile: opts.PVETLSCAFile,
		TokenID: opts.PVETokenID, TokenSecret: opts.PVETokenSecret, Timeout: 10 * time.Second,
	})
	reqs := pve.RunPrivileges(opts.NodeName, vmids, plan.Network.ZoneID, plan.Network.VNetID, plan.Network.EffectiveLifecycle() != "preprovisioned", storage)
	missing, err := client.MissingPrivileges(ctx, reqs)
	if err != nil {
		addWarn("pve_privileges", fmt.Errorf("could not read the PVE token's privileges: %w", err), "")
		return
	}
	required, advisory := pve.DescribeMissingPrivileges(missing)
	if required != "" {
		add("pve_privileges", fmt.Errorf("the PVE token lacks %s", required), "")
		return
	}
	if advisory != "" {
		addWarn("pve_privileges", fmt.Errorf("the PVE token lacks %s; the run works around these", advisory), "")
		return
	}
	add("pve_privileges", nil, "The PVE token holds the documented CertiStackRole on every path the plan uses")
}

// checkPVEConnectivity asks PVE for its version, which proves the endpoint
// answers and the token authenticates, and returns the version as PVE wrote
// it (empty when the answer held none).
func checkPVEConnectivity(ctx context.Context, urlStr string, insecure bool, caFile, tokenID, tokenSecret string) (string, error) {
	client := pve.NewClient(pve.Config{
		BaseURL:     urlStr,
		TLSInsecure: insecure,
		TLSCAFile:   caFile,
		TokenID:     tokenID,
		TokenSecret: tokenSecret,
		Timeout:     5 * time.Second,
	})
	version, err := client.Version(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to reach PVE API: %w", err)
	}
	return version, nil
}

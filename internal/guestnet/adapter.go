// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package guestnet writes isolated recovery network settings into a disposable
// COW overlay. It deliberately never mounts or changes the protected PBS map.
package guestnet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/internal/ifname"
	"github.com/cliftcloud/certistack/internal/macaddr"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
)

const (
	modeAuto              = "auto"
	modeIfcfg             = "ifcfg"
	modeNetworkManager    = "networkmanager"
	modeNetplan           = "netplan"
	modeSystemdNetworkd   = "systemd-networkd"
	modeIfupdown          = "ifupdown"
	guestfishTimeout      = 2 * time.Minute
	networkManagerDir     = "/etc/NetworkManager/system-connections"
	ifcfgDir              = "/etc/sysconfig/network-scripts"
	netplanDir            = "/etc/netplan"
	systemdNetworkdDir    = "/etc/systemd/network"
	networkManagerProfile = networkManagerDir + "/90-certistack-recovery.nmconnection"
	ifcfgProfile          = ifcfgDir + "/ifcfg-certistack-recovery"
	netplanProfile        = netplanDir + "/90-certistack-recovery.yaml"
	networkdProfile       = systemdNetworkdDir + "/00-certistack-recovery.network"
	interfaceLinkProfile  = systemdNetworkdDir + "/00-certistack-recovery.link"
	ifupdownDir           = "/etc/network"
	ifupdownConfig        = ifupdownDir + "/interfaces"
	ifupdownOriginal      = ifupdownDir + "/interfaces.certistack-original"
	enabledUnitsDir       = "/etc/systemd/system/multi-user.target.wants"
	osReleaseFile         = "/etc/os-release"
	osReleaseFallback     = "/usr/lib/os-release"
	networkManagerConf    = "/etc/NetworkManager/NetworkManager.conf"
	cloudConfigDir        = "/etc/cloud/cloud.cfg.d"
	cloudNetworkDropIn    = cloudConfigDir + "/99-certistack-recovery-network.cfg"
	waitOnlineDropInDir   = "/etc/systemd/system/systemd-networkd-wait-online.service.d"
	waitOnlineDropIn      = waitOnlineDropInDir + "/90-certistack-recovery.conf"
	diagnosticScript      = "/usr/local/lib/certistack/capture-network-recovery"
	diagnosticUnit        = "/etc/systemd/system/certistack-network-recovery.service"
	diagnosticLink        = "/etc/systemd/system/multi-user.target.wants/certistack-network-recovery.service"
	diagnosticLateUnit    = "/etc/systemd/system/certistack-network-recovery-late.service"
	diagnosticLateLink    = "/etc/systemd/system/multi-user.target.wants/certistack-network-recovery-late.service"
	diagnosticDispatcher  = "/etc/NetworkManager/dispatcher.d/90-certistack-network-recovery"
	diagnosticDir         = "/var/lib/certistack"
	diagnosticOutput      = diagnosticDir + "/network-recovery.txt"
	firewalldDir          = "/etc/firewalld"
	firewalldConfig       = firewalldDir + "/firewalld.conf"
	firewalldZoneDir      = firewalldDir + "/zones"
	firewalldSystemZones  = "/usr/lib/firewalld/zones"
)

// maxSeedCandidates bounds how many of a directory's profiles are looked at
// when choosing the one to copy.
const maxSeedCandidates = 32

// maxOverlays bounds Config.Overlays at a little over the most disks a PVE VM
// has (ide 4, sata 6, scsi 31, virtio 16).
const maxOverlays = 64

// Config identifies the disposable overlays and the temporary isolated address
// to make available inside the sandbox VM.
type Config struct {
	VMID int
	// Overlays are the COW overlays of every disk the sandbox VM restores, in
	// the order the guest sees its disks. guestfish opens all of them
	// in every call, so inspection sees the same block-device graph as the
	// guest: a root filesystem on a second disk, a /boot or EFI disk beside it,
	// an LVM volume group across several. Writes still land only in these
	// disposable overlays, in whichever one holds the file.
	Overlays      []string
	MAC           string
	Address       string
	CIDR          string
	Mode          string
	InterfaceName string
	// OnlyNIC reports that the recovered NIC is the sandbox VM's only one, so
	// every interface the guest's own configuration names can only be that
	// NIC under another name (a stale stanza from the image, or another
	// naming scheme).
	OnlyNIC            bool
	CaptureDiagnostics bool
	ProbeIP            string
	FirewallPorts      []FirewallPort
	// Progress receives bounded, operator-facing phase updates. It is not
	// persisted in the guest or plan; it exists so slow offline image work is
	// visible to the controller without exposing guest contents.
	Progress func(string)
}

// FirewallPort is a port a network probe uses, named in the plan, that may be
// admitted from the temporary host-side probe address in a COW guest.
type FirewallPort struct {
	Protocol string
	Port     int
}

// Result is included in the VM record so an operator can see exactly
// what was adapted during the recovery test.
type Result struct {
	Strategy string
	Address  string
	Files    []string
}

type stagedFile struct {
	localPath   string
	destination string
	mode        os.FileMode
}

type commandRunner func(context.Context, ...string) (string, error)

// Adapter applies guest network profiles through libguestfs/guestfish. The
// worker must have guestfish available locally because the COW overlay exists
// on the PVE node; it is a documented appliance/worker dependency.
type Adapter struct {
	scratchDir string
	run        commandRunner
}

func New(scratchDir string) *Adapter {
	if scratchDir == "" {
		scratchDir = sysutil.DefaultScratchDir
	}
	return &Adapter{scratchDir: scratchDir, run: runGuestfish}
}

// CheckDependency verifies that a worker can perform COW-only recovery before
// it maps a PBS image or provisions sandbox resources.
func CheckDependency(ctx context.Context) error {
	if _, err := runGuestfish(ctx, "--version"); err != nil {
		return dependencyError("start", err)
	}
	return nil
}

// Apply detects the supported Linux network manager and writes exactly one
// root-owned recovery profile to the overlay. It never adds a gateway, DNS
// server, or default route, retaining the sandbox's air-gap.
func (a *Adapter) Apply(ctx context.Context, cfg Config) (Result, error) {
	if a == nil || a.run == nil {
		return Result{}, fmt.Errorf("guest network adapter is not initialized")
	}
	parsed, mode, err := validate(cfg)
	if err != nil {
		return Result{}, err
	}
	status(cfg, "Detecting the guest network manager from the disposable overlay")
	guest := newDetection(a, cfg.Overlays, cfg.MAC)
	guest.iface = cfg.InterfaceName
	// ifcfgFile is the existing profile the recovery rewrites in place, when a
	// MAC-bound one was found; its name need not be that of its interface.
	ifcfgFile := ""
	strategy, err := a.strategy(ctx, guest, cfg, mode)
	if err != nil {
		return Result{}, err
	}
	// NetworkManager on RHEL can actively manage a legacy ifcfg connection.
	// When that existing profile is bound to the restored NIC's MAC, update the
	// exact file (and therefore its SELinux label) instead of adding a competing
	// nmconnection that NetworkManager may never activate.
	if mode == modeAuto && strategy == modeNetworkManager && cfg.InterfaceName == "" {
		status(cfg, "Checking for a MAC-bound legacy connection profile")
		if profile, found, findErr := a.ifcfgProfileForMAC(ctx, cfg.Overlays, cfg.MAC); findErr != nil {
			return Result{}, findErr
		} else if found {
			strategy = modeIfcfg
			cfg.InterfaceName = profile.iface
			ifcfgFile = profile.file
		}
	}
	// With or without an interface name: auto must never write a profile
	// the guest's NetworkManager does not read.
	if mode == modeAuto && strategy == modeNetworkManager {
		if ignores, checkErr := a.networkManagerIgnoresKeyfiles(ctx, guest); checkErr != nil {
			return Result{}, checkErr
		} else if ignores {
			// EL7's NetworkManager 1.18 loads only the ifcfg-rh plugin unless
			// keyfile is listed, so a keyfile profile is silently ignored and
			// the guest keeps its own address. A MAC-bound ifcfg profile with
			// a higher autoconnect priority is what it activates.
			strategy = modeIfcfg
		}
	}

	contents, destination := render(strategy, cfg, parsed)
	if ifcfgFile != "" {
		destination = ifcfgFile
	}
	if strategy == modeNetworkManager {
		// The profile goes where this guest's NetworkManager reads keyfiles, which
		// its configuration can move.
		settings, settingsErr := guest.networkManagerSettings(ctx)
		if settingsErr != nil {
			return Result{}, settingsErr
		}
		destination = path.Join(settings.keyfileDir, path.Base(networkManagerProfile))
	}
	if strategy == modeIfcfg && ifcfgIgnored(path.Base(destination)) {
		// An explicit interface name such as "eth0.bak" would name a file
		// NetworkManager never loads.
		return Result{}, fmt.Errorf("VM %d recovery interface name %q would make the ifcfg profile %s, a name NetworkManager's ifcfg plugin ignores (it skips files ending in %s); choose another network_recovery.interface_name", cfg.VMID, cfg.InterfaceName, path.Base(destination), strings.Join(ifcfgIgnoredSuffixes, ", "))
	}
	netplanGuest := strategy == modeNetplan
	if netplanGuest {
		// A definition with a later file name does not take precedence: netplan
		// writes one networkd file per definition ID and networkd applies the
		// first matching file in name order.
		status(cfg, "Checking the guest's Netplan definitions so that the recovery definition is the one systemd-networkd applies")
		if contents, err = guest.netplanRecovery(ctx, cfg, parsed); err != nil {
			return Result{}, err
		}
	}
	if strategy == modeSystemdNetworkd {
		if destination, err = guest.firstMatchFile(ctx, ".network"); err != nil {
			return Result{}, err
		}
	}
	var ifupdownCommands [][]string
	if strategy == modeIfupdown {
		status(cfg, "Reading the guest's ifupdown interface configuration")
		names := []string{cfg.InterfaceName}
		// The guest's files are read to choose the interface name, and, when the
		// sandbox VM has the source's other NICs too, to keep their stanzas.
		var graph *ifupdownGraph
		if cfg.InterfaceName == "" || !cfg.OnlyNIC {
			graph = newIfupdownGraph(a, cfg.Overlays)
			if err = graph.read(ctx, ifupdownConfig, 0, true); err != nil {
				return Result{}, err
			}
		}
		if cfg.InterfaceName == "" {
			if names, err = graph.recoveryNames(cfg.OnlyNIC); err != nil {
				return Result{}, err
			}
			if len(names) > 1 {
				status(cfg, fmt.Sprintf("The guest configures its only NIC as %s; each gets a hotplug recovery stanza, and only the one that exists comes up", strings.Join(names, ", ")))
			}
		}
		contents, destination = renderIfupdown(names, cfg, parsed), ifupdownConfig
		if !cfg.OnlyNIC {
			retained, retainErr := graph.retainedIfupdown(names)
			if retainErr != nil {
				return Result{}, retainErr
			}
			if retained != "" {
				status(cfg, "Keeping the guest's own stanzas for its other NICs beside the recovery address")
			}
			contents += retained
		}
		// Keep the guest's own file beside the recovery one (both only in the
		// disposable overlay) so the evidence shows what was replaced.
		ifupdownCommands = [][]string{{"cp-a", ifupdownConfig, ifupdownOriginal}}
	}
	stageDir, err := os.MkdirTemp(a.scratchDir, "certistack-guestnet-")
	if err != nil {
		return Result{}, fmt.Errorf("create temporary network profile: %w", err)
	}
	defer os.RemoveAll(stageDir)

	status(cfg, "Preparing the isolated no-gateway network profile")
	profileSeed := ""
	if strategy != modeIfupdown {
		if profileSeed, err = a.profileSeedSource(ctx, guest, strategy, destination); err != nil {
			return Result{}, err
		}
	}
	profileMode := os.FileMode(0600)
	switch strategy {
	case modeIfupdown:
		profileMode = 0644 // /etc/network/interfaces is world-readable by convention
	case modeSystemdNetworkd:
		// systemd-networkd reads its .network files as its own user on some
		// distributions (Amazon Linux 2023): a root-only profile is "Permission
		// denied", the guest comes up on its cloud-init profile with no address. It
		// holds an address and a prefix, nothing secret.
		profileMode = 0644
	}
	profileFile, err := stageFile(stageDir, destination, contents, profileMode)
	if err != nil {
		return Result{}, err
	}
	files := []string{destination}
	commands := make([][]string, 0, 16)
	if profileSeed != "" {
		commands = append(commands, []string{"cp-a", profileSeed, destination})
	}
	if len(ifupdownCommands) > 0 {
		commands = append(commands, ifupdownCommands...)
		files = append(files, ifupdownOriginal)
	}
	commands = append(commands, uploadCommands(profileFile)...)
	if strategy == modeIfupdown {
		// cloud-init renders /etc/network/interfaces at every boot on some images (Alpine): with no datasource it falls back to DHCP and
		// overwrites the recovery stanza. Telling it to leave the network alone only affects the disposable overlay.
		cloudInit, err := guest.directoryExists(ctx, cloudConfigDir)
		if err != nil {
			return Result{}, err
		}
		if cloudInit {
			cloudFile, err := stageFile(stageDir, cloudNetworkDropIn, renderCloudNetworkDropIn(), 0644)
			if err != nil {
				return Result{}, err
			}
			status(cfg, "Telling the guest's cloud-init to leave the network alone, so it does not replace the recovery profile at boot")
			commands = append(commands, uploadCommands(cloudFile)...)
			files = append(files, cloudNetworkDropIn)
		}
	}
	if netplanGuest {
		dropInFile, err := stageFile(stageDir, waitOnlineDropIn, renderWaitOnlineDropIn(), 0644)
		if err != nil {
			return Result{}, err
		}
		commands = append(commands, []string{"mkdir-p", waitOnlineDropInDir})
		commands = append(commands, uploadCommands(dropInFile)...)
		files = append(files, waitOnlineDropIn)
	}
	if cfg.InterfaceName != "" {
		linkProfile, err := guest.firstMatchFile(ctx, ".link")
		if err != nil {
			return Result{}, err
		}
		linkFile, err := stageFile(stageDir, linkProfile, renderInterfaceLink(cfg), 0600)
		if err != nil {
			return Result{}, err
		}
		commands = append(commands, []string{"mkdir-p", systemdNetworkdDir})
		commands = append(commands, uploadCommands(linkFile)...)
		files = append(files, linkProfile)
	}
	if cfg.CaptureDiagnostics {
		install, err := diagnosticMutations(stageDir)
		if err != nil {
			return Result{}, err
		}
		commands = append(commands, install.commands...)
		files = append(files, install.files...)
	}
	if len(cfg.FirewallPorts) > 0 {
		status(cfg, "Checking the disposable guest firewall for declared probe ports")
		firewallFiles, firewallCommands, err := a.firewallMutations(ctx, cfg.Overlays, stageDir, cfg.ProbeIP, cfg.FirewallPorts)
		if err != nil {
			return Result{}, err
		}
		commands = append(commands, firewallCommands...)
		files = append(files, firewallFiles...)
	}
	status(cfg, "Writing COW-only network changes in one guestfs transaction")
	if err := a.runBatch(ctx, cfg.Overlays, commands); err != nil {
		return Result{}, err
	}
	status(cfg, "COW-only network recovery profile is ready")

	return Result{Strategy: strategy, Address: cfg.Address, Files: files}, nil
}

func status(cfg Config, message string) {
	if cfg.Progress != nil {
		cfg.Progress(message)
	}
}

func (a *Adapter) writeFirewallProbeRule(ctx context.Context, overlays []string, stageDir, probeIP string, ports []FirewallPort) ([]string, error) {
	files, commands, err := a.firewallMutations(ctx, overlays, stageDir, probeIP, ports)
	if err != nil {
		return nil, err
	}
	if err := a.runBatch(ctx, overlays, commands); err != nil {
		return nil, err
	}
	return files, nil
}

func (a *Adapter) firewallMutations(ctx context.Context, overlays []string, stageDir, probeIP string, ports []FirewallPort) ([]string, [][]string, error) {
	probe := net.ParseIP(probeIP).To4()
	if probe == nil {
		return nil, nil, fmt.Errorf("guest firewall recovery requires a valid IPv4 probe address")
	}
	exists, err := a.directoryExists(ctx, overlays, firewalldDir)
	if err != nil {
		return nil, nil, dependencyError("inspect guest firewall", err)
	}
	if !exists {
		return nil, nil, nil
	}
	configured, err := a.firewalldDefaultZone(ctx, overlays)
	if err != nil {
		return nil, nil, err
	}
	zones, err := a.readGuestZones(ctx, overlays)
	if err != nil {
		return nil, nil, err
	}
	defaultZone, err := effectiveDefaultZone(configured, zones)
	if err != nil {
		return nil, nil, err
	}
	// Keep what each guest zone allows (services, ports, rich rules,
	// target) and only add the probe rules: replacing a zone would cut the
	// traffic between the members of a multi-tier application inside the
	// sandbox.
	var files []string
	commands := [][]string{{"mkdir-p", firewalldZoneDir}}
	for _, zone := range probeZones(defaultZone, zones, probe) {
		destination := path.Join(firewalldZoneDir, zone+".xml")
		source, seed := destination, ""
		base, administrator := zones.etc[zone]
		if !administrator {
			// A vendor zone is copied under /etc first, so the result keeps
			// the vendor file's SELinux label and ownership.
			source, seed = path.Join(firewalldSystemZones, zone+".xml"), path.Join(firewalldSystemZones, zone+".xml")
			if base, err = a.run(ctx, guestfishReadArgs(overlays, "cat", seed)...); err != nil {
				return nil, nil, dependencyError("read guest firewall zone", err)
			}
		}
		merged, err := mergeFirewallProbeRules(base, probeIP, ports)
		if err != nil {
			return nil, nil, fmt.Errorf("guest firewalld zone %s cannot take the probe rules (%v); fix the zone or use network_recovery.mode: preserve", source, err)
		}
		file, err := stageFile(stageDir, destination, merged, 0600)
		if err != nil {
			return nil, nil, err
		}
		if seed != "" {
			commands = append(commands, []string{"cp-a", seed, destination})
		}
		commands = append(commands, uploadCommands(file)...)
		files = append(files, destination)
	}
	return files, commands, nil
}

// firewalldDefaultZone reads the DefaultZone firewalld.conf configures.
// public is firewalld's documented default when the configuration file is
// absent or does not set DefaultZone; effectiveDefaultZone then applies
// firewalld's own fallback when that zone is not defined.
func (a *Adapter) firewalldDefaultZone(ctx context.Context, overlays []string) (string, error) {
	exists, err := a.fileExists(ctx, overlays, firewalldConfig)
	if err != nil {
		return "", dependencyError("inspect guest firewall configuration", err)
	}
	if !exists {
		return "public", nil
	}
	contents, err := a.run(ctx, guestfishReadArgs(overlays, "cat", firewalldConfig)...)
	if err != nil {
		return "", dependencyError("read guest firewall configuration", err)
	}
	// Read as firewalld reads it: "Key=Value" with exactly one "=", the key
	// exact, the value as written (quotes stay part of it), and the first
	// definition of a key counts.
	zone := "public"
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		pair := strings.Split(line, "=")
		if len(pair) != 2 || strings.TrimSpace(pair[0]) != "DefaultZone" || strings.TrimSpace(pair[1]) == "" {
			continue
		}
		zone = strings.TrimSpace(pair[1])
		break
	}
	if !validFirewalldZone(zone) {
		return "", fmt.Errorf("guest firewalld DefaultZone %q is not a safe zone name", zone)
	}
	return zone, nil
}

func validFirewalldZone(zone string) bool {
	if zone == "" || len(zone) > 64 {
		return false
	}
	for _, char := range zone {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func firewallProbeRules(probeIP string, ports []FirewallPort) string {
	var b strings.Builder
	for _, port := range ports {
		if port.Port <= 0 || port.Port > 65535 || (port.Protocol != "tcp" && port.Protocol != "udp") {
			continue
		}
		fmt.Fprintf(&b, "  <rule family=\"ipv4\"><source address=\"%s\"/><port port=\"%d\" protocol=\"%s\"/><accept/></rule>\n", probeIP, port.Port, port.Protocol)
	}
	return b.String()
}

// profileSeedSource selects a same-backend profile to clone in the final
// guestfish transaction. cp -a preserves ownership, mode, and SELinux extended
// attributes, which is essential for enforcing RHEL guests: a newly-created
// NetworkManager profile can otherwise be ignored due to an unlabeled inode.
// Guests without SELinux simply receive an equivalent ordinary copy.
func (a *Adapter) profileSeedSource(ctx context.Context, guest *detection, strategy, destination string) (string, error) {
	if _, ok := strategyDirectory(strategy); !ok {
		return "", fmt.Errorf("unsupported recovery network strategy %q", strategy)
	}
	// The profile is written beside the guest's own: the directory its backend
	// reads, which for NetworkManager is the configured one.
	directory := path.Dir(destination)
	entries, err := guest.list(ctx, directory)
	if err != nil {
		return "", err
	}
	destinationName := path.Base(destination)
	var candidates []string
	for _, entry := range entries {
		if entry == destinationName || !isProfileSeed(strategy, entry) {
			continue
		}
		if candidates = append(candidates, path.Join(directory, entry)); len(candidates) == maxSeedCandidates {
			break
		}
	}
	if len(candidates) == 0 {
		return "", nil
	}
	// Only a regular file can be a seed: "cp -a" keeps a symbolic link a link,
	// and the upload that follows would then replace whatever it points at. The
	// owner of the seed does not matter: the profile's owner is set after the
	// copy.
	kinds, err := a.guestFileKinds(ctx, guest.overlays, candidates)
	if err != nil {
		return "", err
	}
	for i, kind := range kinds {
		if kind == kindRegular {
			return candidates[i], nil
		}
	}
	return "", nil
}

// ifcfgMatchesMAC reports an ifcfg file whose HWADDR is mac.
func ifcfgMatchesMAC(contents, mac string) bool {
	return strings.EqualFold(ifcfgAssignments(contents)["HWADDR"], strings.TrimSpace(mac))
}

func isProfileSeed(strategy, name string) bool {
	if !safeEntryName(name) {
		return false
	}
	switch strategy {
	case modeNetworkManager:
		return strings.HasSuffix(name, ".nmconnection")
	case modeIfcfg:
		// A profile NetworkManager ignores is neither a profile to rewrite nor a
		// seed to copy.
		return !ifcfgIgnored(name)
	case modeNetplan:
		return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
	case modeSystemdNetworkd:
		return strings.HasSuffix(name, ".network")
	default:
		return false
	}
}

func (a *Adapter) writeDiagnostics(ctx context.Context, overlays []string, stageDir string) error {
	install, err := diagnosticMutations(stageDir)
	if err != nil {
		return err
	}
	return a.runBatch(ctx, overlays, install.commands)
}

// diagnosticInstall is what installing the diagnostics adds to the guest: the
// guestfish commands that do it and, made in the same step so the two cannot
// drift apart, every destination those commands write, in order. A regular
// file is listed by its path, a symbolic link as "path -> target".
type diagnosticInstall struct {
	commands [][]string
	files    []string
}

func (i *diagnosticInstall) upload(file stagedFile) {
	i.commands = append(i.commands, uploadCommands(file)...)
	i.files = append(i.files, file.destination)
}

func (i *diagnosticInstall) symlink(target, link string) {
	i.commands = append(i.commands, []string{"ln-s", target, link})
	i.files = append(i.files, link+" -> "+target)
}

func diagnosticMutations(stageDir string) (diagnosticInstall, error) {
	install := diagnosticInstall{commands: make([][]string, 0, 16)}
	for _, dir := range []string{"/usr/local/lib/certistack", "/etc/systemd/system/multi-user.target.wants", "/etc/NetworkManager/dispatcher.d", "/var/lib/certistack"} {
		install.commands = append(install.commands, []string{"mkdir-p", dir})
	}
	script := bootDiagnosticScript(diagnosticOutput)
	// Ordered after network-online.target, never pulling it in: a Wants= on it
	// would make a guest that does not normally wait for the network wait for
	// it (up to its wait-online timeout) on this failed-VM run alone, which is
	// a boot the guest never had in production.
	unit := "[Unit]\nAfter=NetworkManager.service network-online.target\n\n[Service]\nType=oneshot\nExecStart=" + diagnosticScript + "\n\n[Install]\nWantedBy=multi-user.target\n"
	scriptFile, err := stageFile(stageDir, diagnosticScript, script, 0700)
	if err != nil {
		return diagnosticInstall{}, err
	}
	unitFile, err := stageFile(stageDir, diagnosticUnit, unit, 0600)
	if err != nil {
		return diagnosticInstall{}, err
	}
	// Once more after boot has settled: a listener list taken while
	// multi-user.target is still starting cannot tell a service that never
	// started from one that starts late. Wanted by multi-user.target and
	// ordered after it, it starts once the target is reached (systemd does not
	// order the target after a unit that is already ordered after it, so there
	// is no cycle: systemd-analyze verify finds none), and then the script waits for the rest of boot to
	// finish. It is Type=simple on purpose: a oneshot service's start job lasts
	// as long as the script runs, and a manager with a job pending reports
	// "starting", so a oneshot would wait for itself to settle until the wait
	// ran out. Type=simple is understood by every systemd, EL7's included
	// (which has no Type=exec).
	lateUnit := "[Unit]\nDescription=CertiStack failed-VM diagnostic after boot\nAfter=multi-user.target\n\n[Service]\nType=simple\nExecStart=" + diagnosticScript + " after-boot\n\n[Install]\nWantedBy=multi-user.target\n"
	lateUnitFile, err := stageFile(stageDir, diagnosticLateUnit, lateUnit, 0600)
	if err != nil {
		return diagnosticInstall{}, err
	}
	// NetworkManager dispatches this on every device-state transition. Unlike
	// an after-boot service, it also runs when an attempted recovery profile
	// never reaches an online state.
	dispatcherFile, err := stageFile(stageDir, diagnosticDispatcher, script, 0700)
	if err != nil {
		return diagnosticInstall{}, err
	}
	install.upload(scriptFile)
	install.upload(unitFile)
	install.upload(lateUnitFile)
	install.upload(dispatcherFile)
	install.symlink("../certistack-network-recovery.service", diagnosticLink)
	install.symlink("../certistack-network-recovery-late.service", diagnosticLateLink)
	return install, nil
}

// ReadDiagnostics retrieves the intentionally narrow in-guest network state
// after QEMU has stopped but before the COW overlays are deleted. It opens
// every overlay the recovery profile was written against: the guest's
// root filesystem, and so the file, can be on any of its disks.
func ReadDiagnostics(ctx context.Context, overlays []string) (string, error) {
	return readDiagnostics(ctx, runGuestfish, overlays)
}

// diagnosticReadTimeout bounds the whole read: the listing and the read of the
// newest capture each start a guestfish appliance with its own timeout, and the
// failed VM's teardown waits for both.
const diagnosticReadTimeout = 3 * time.Minute

// readDiagnostics reads the newest capture the guest's diagnostic script left:
// at most diagnosticReadLimit bytes of it, whatever size the file is, so a
// capture that is too large is cut and marked instead of failing the read. The
// captures are told apart by the names they were published under (see
// bootDiagnosticScript), and the one that began last wins.
func readDiagnostics(ctx context.Context, run commandRunner, overlays []string) (string, error) {
	if err := validateOverlays(overlays); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, diagnosticReadTimeout)
	defer cancel()
	listing, err := run(ctx, guestfishReadArgs(overlays, "ls", diagnosticDir)...)
	if err != nil {
		// Only the diagnostic directory not being there is "the guest wrote none".
		// The same words about anything else, a missing overlay above all, are a
		// failure to read.
		if namesMissingPath(err, diagnosticDir) {
			return "", nil
		}
		return "", err
	}
	name := newestDiagnostic(listingEntries(listing))
	if name == "" {
		return "", nil
	}
	// One byte more than is reported says whether the capture was cut.
	data, err := run(ctx, guestfishReadArgs(overlays, "pread", path.Join(diagnosticDir, name), strconv.Itoa(diagnosticReadLimit+1), "0")...)
	if err != nil {
		return "", err
	}
	return boundedDiagnostic(data), nil
}

// namesMissingPath reports a guestfish error that says this very path is not
// there ("<path>: No such file or directory"), not one that says it of a path
// below it, such as an overlay in the same directory.
func namesMissingPath(err error, p string) bool {
	return strings.Contains(strings.ToLower(err.Error()), strings.ToLower(p)+": no such file or directory")
}

var diagnosticName = regexp.MustCompile(`^network-recovery\.txt\.([0-9]{10})\.([0-9]+)$`)

// newestDiagnostic is the capture, among the entries of the diagnostic
// directory, that began last: the greatest hundredth-of-a-second stamp, the
// greatest process ID among captures that began in the same one. "" when there
// is none.
func newestDiagnostic(entries []string) string {
	best, bestStamp, bestPID := "", "", ""
	for _, entry := range entries {
		match := diagnosticName.FindStringSubmatch(entry)
		if match == nil {
			continue
		}
		stamp, pid := match[1], match[2]
		newer := stamp > bestStamp || (stamp == bestStamp && (len(pid) > len(bestPID) || (len(pid) == len(bestPID) && pid > bestPID)))
		if best == "" || newer {
			best, bestStamp, bestPID = entry, stamp, pid
		}
	}
	return best
}

// boundedDiagnostic is what the report keeps of a capture read with one byte
// over the limit: the limit's worth, cut at a whole character, with a marker
// when there was more.
func boundedDiagnostic(data string) string {
	truncated := len(data) > diagnosticReadLimit
	if truncated {
		data = data[:diagnosticReadLimit]
		for len(data) > 0 {
			r, size := utf8.DecodeLastRuneInString(data)
			if r != utf8.RuneError || size > 1 {
				break
			}
			data = data[:len(data)-1]
		}
	}
	output := strings.TrimSpace(data)
	if truncated {
		output += "\n[truncated]"
	}
	return output
}

func stageFile(stageDir, destination, contents string, mode os.FileMode) (stagedFile, error) {
	stage, err := os.CreateTemp(stageDir, "certistack-guestnet-")
	if err != nil {
		return stagedFile{}, fmt.Errorf("create temporary network profile: %w", err)
	}
	stagePath := stage.Name()
	if _, err := stage.Write([]byte(contents)); err != nil {
		_ = stage.Close()
		return stagedFile{}, fmt.Errorf("write temporary network profile: %w", err)
	}
	if err := stage.Close(); err != nil {
		return stagedFile{}, fmt.Errorf("close temporary network profile: %w", err)
	}
	if err := os.Chmod(stagePath, 0600); err != nil {
		return stagedFile{}, fmt.Errorf("secure temporary network profile: %w", err)
	}
	return stagedFile{localPath: stagePath, destination: destination, mode: mode}, nil
}

func uploadCommands(file stagedFile) [][]string {
	// guestfish accepts decimal modes. NetworkManager profiles must remain
	// root-only (0600); the two diagnostic executables are explicitly 0700.
	// The upload reuses the inode of a file that is already there (a copy of
	// the guest's own profile, which keeps its SELinux label), and with it that
	// file's owner; NetworkManager ignores a keyfile owned by anyone but root, so
	// the owner is always set.
	return [][]string{
		{"upload", file.localPath, file.destination},
		{"chmod", strconv.FormatUint(uint64(file.mode.Perm()), 10), file.destination},
		{"chown", "0", "0", file.destination},
	}
}

// runBatch performs all mutations for one recovered guest with one libguestfs
// appliance boot. Detection remains separate and read-only; batching only
// combines ordered writes to the disposable COW overlay. Every path the batch
// writes is checked before the write and read back after it:
// what is there must be a regular file, not a link that would send the write
// elsewhere, and what was written must be a root-owned regular file of the
// mode the batch set.
func (a *Adapter) runBatch(ctx context.Context, overlays []string, commands [][]string) error {
	if len(commands) == 0 {
		return nil
	}
	targets := collectWriteTargets(commands)
	satisfied, err := a.checkWriteTargets(ctx, overlays, targets)
	if err != nil {
		return err
	}
	if len(satisfied) > 0 {
		// A link that is there already, pointing where it should, is left as it is.
		pending := make([][]string, 0, len(commands))
		for _, command := range commands {
			if command[0] == "ln-s" && len(command) == 3 && satisfied[command[2]] {
				continue
			}
			pending = append(pending, command)
		}
		commands = pending
	}
	if _, err := a.run(ctx, guestfishBatchArgs(overlays, commands)...); err != nil {
		return dependencyError("write COW-only guest network recovery profile", err)
	}
	return a.verifyWritten(ctx, overlays, targets)
}

// strategy chooses the backend that configures the guest's network. An
// explicit mode is used when the guest can run it; auto follows what is in
// charge, not which configuration directory exists: a guest can keep
// /etc/NetworkManager while NetworkManager is masked and networkd runs.
func (a *Adapter) strategy(ctx context.Context, guest *detection, cfg Config, requested string) (string, error) {
	if requested != modeAuto {
		if _, ok := strategyDirectory(requested); !ok {
			return "", fmt.Errorf("unsupported recovery network mode %q", requested)
		}
		dir, exists, err := guest.backendDirectory(ctx, requested)
		if err != nil {
			return "", err
		}
		if !exists {
			if requested == modeNetworkManager && dir != networkManagerDir {
				return "", fmt.Errorf("requested %s recovery adapter is not present in the guest overlay: NetworkManager is configured to keep its profiles in %s, which does not exist", requested, dir)
			}
			return "", fmt.Errorf("requested %s recovery adapter is not present in the guest overlay", requested)
		}
		// A profile for a service that never starts is never read.
		if unit := strategyUnit(requested); unit != "" {
			if masked, err := guest.masked(ctx, unit); err != nil {
				return "", err
			} else if masked {
				return "", maskedError(unit, requested)
			}
		}
		if requested == modeNetworkManager {
			// NetworkManager leaves a device that netplan hands to networkd, and
			// an ifupdown or networkd guest with NetworkManager disabled never
			// reads its profile.
			owner, err := guest.networkManagerOwner(ctx)
			if err != nil {
				return "", err
			}
			if owner != modeNetworkManager {
				return "", fmt.Errorf("the guest's network is configured by %s, not NetworkManager, so a NetworkManager recovery profile would not be applied; use network_recovery.mode: auto or %s", owner, owner)
			}
		}
		return requested, nil
	}

	// Modern RHEL-family guests commonly retain the legacy ifcfg directory while
	// NetworkManager is the active controller. Prefer the active-generation
	// backends before that compatibility directory; callers can still select
	// mode: ifcfg explicitly for an older network-scripts guest.
	var masked []string
	// nmConfigErr is why the guest's NetworkManager configuration could not be
	// evaluated. It stops recovery only if NetworkManager configures the guest:
	// a leftover malformed file beside a netplan or networkd guest is not a
	// reason to refuse it.
	var nmConfigErr error
	for _, candidate := range []string{modeNetworkManager, modeNetplan, modeSystemdNetworkd, modeIfcfg} {
		_, exists, err := guest.backendDirectory(ctx, candidate)
		// A guest guestfish cannot open fails the same way on any other call
		// (an encrypted root, no system, several): the second appliance boot
		// that asks "does the directory exist" would only repeat the refusal
		// after another wait.
		if err != nil && candidate == modeNetworkManager && !isGuestRefusal(err) {
			nmConfigErr = err
			exists, err = guest.directoryExists(ctx, networkManagerDir)
		}
		if err != nil {
			return "", err
		}
		if !exists {
			continue
		}
		switch candidate {
		case modeNetworkManager:
			owner, err := guest.networkManagerOwner(ctx)
			if err != nil {
				return "", err
			}
			if owner == "" {
				status(cfg, "NetworkManager.service is masked in the guest, so its configuration files are not what configures the network")
				masked = append(masked, networkManagerUnit)
				continue
			}
			if owner != modeNetworkManager {
				status(cfg, fmt.Sprintf("The guest keeps NetworkManager files, but %s is what configures its network", owner))
			} else if nmConfigErr != nil {
				return "", nmConfigErr
			}
			return owner, nil
		case modeNetplan, modeSystemdNetworkd:
			// netplan renders for systemd-networkd.
			if isMasked, err := guest.masked(ctx, networkdUnit); err != nil {
				return "", err
			} else if isMasked {
				status(cfg, "systemd-networkd.service is masked in the guest, so netplan and networkd files are not what configures the network")
				masked = append(masked, networkdUnit)
				continue
			}
			if candidate == modeSystemdNetworkd {
				// Debian ships an empty /etc/systemd/network even when ifupdown
				// (networking.service) owns the network and networkd is disabled;
				// a networkd profile there is never read.
				if ifupdown, err := guest.ifupdownOwnsNetwork(ctx); err != nil {
					return "", err
				} else if ifupdown {
					return modeIfupdown, nil
				}
			}
		}
		return candidate, nil
	}
	if ifupdown, err := guest.ifupdownOwnsNetwork(ctx); err != nil {
		return "", err
	} else if ifupdown {
		return modeIfupdown, nil
	}
	// Nothing systemd-based configures the guest: an OpenRC guest (Alpine) may still run ifupdown.
	if len(masked) == 0 {
		if openrc, err := guest.openrcIfupdownOwnsNetwork(ctx); err != nil {
			return "", err
		} else if openrc {
			return modeIfupdown, nil
		}
	}
	if len(masked) > 0 {
		return "", fmt.Errorf("the guest's network configuration belongs to masked services (%s), which never start, and no other supported backend is configured in the COW overlay; use network_recovery.mode: preserve (the guest keeps its own network on the isolated VNet) or restore the guest with its network manager enabled", strings.Join(masked, ", "))
	}
	return "", fmt.Errorf("unsupported guest network layout: no NetworkManager, netplan, systemd-networkd, or ifupdown configuration found in the COW overlay; for Windows or other non-Linux guests, use network_recovery.mode: preserve (the guest keeps its own network on the isolated VNet)")
}

func (a *Adapter) enabledUnits(ctx context.Context, overlays []string) (map[string]bool, error) {
	exists, err := a.directoryExists(ctx, overlays, enabledUnitsDir)
	if err != nil {
		return nil, dependencyError("inspect enabled services", err)
	}
	units := map[string]bool{}
	if !exists {
		return units, nil
	}
	output, err := a.run(ctx, guestfishReadArgs(overlays, "ls", enabledUnitsDir)...)
	if err != nil {
		return nil, dependencyError("list enabled services", err)
	}
	for _, name := range listingEntries(output) {
		units[name] = true
	}
	return units, nil
}

// ifupdownRecoveryNames chooses the interface names the recovery stanza is
// written for, from /etc/network/interfaces and the files its source and
// source-directory directives include. Virtual interfaces (bridges, bonds, VLANs, tunnels) are set
// aside while a physical-looking one remains: the recovery stanza cannot
// recreate them, and it must not give a device that appears later the same
// address. One candidate is used as is. Several are acceptable only when the
// recovered NIC is the sandbox VM's only one, so they can only be that NIC
// under different names (cloud-init's enp6s18 beside the image's stale
// eth0); otherwise the operator must name the recovered NIC
// (network_recovery.interface_name) rather than have CertiStack guess.
func (a *Adapter) ifupdownRecoveryNames(ctx context.Context, overlays []string, onlyNIC bool) ([]string, error) {
	graph := newIfupdownGraph(a, overlays)
	if err := graph.read(ctx, ifupdownConfig, 0, true); err != nil {
		return nil, err
	}
	return graph.recoveryNames(onlyNIC)
}

// recoveryNames is ifupdownRecoveryNames for a graph already read.
func (g *ifupdownGraph) recoveryNames(onlyNIC bool) ([]string, error) {
	var physical, all []string
	for _, iface := range g.interfaces {
		all = append(all, iface.name)
		if !iface.virtual {
			physical = append(physical, iface.name)
		}
	}
	names := physical
	if len(names) == 0 {
		names = all
	}
	switch {
	case len(names) == 0:
		return nil, fmt.Errorf("guest ifupdown configuration defines no network interface; set network_recovery.interface_name or use network_recovery.mode: preserve")
	case len(names) == 1 || onlyNIC:
		return names, nil
	default:
		return nil, fmt.Errorf("guest ifupdown configuration defines several interfaces (%s) and the sandbox VM has several NICs; set network_recovery.interface_name to the recovered NIC's name", strings.Join(names, ", "))
	}
}

// ifupdownInterface is a non-loopback interface with an iface stanza.
type ifupdownInterface struct {
	name    string
	virtual bool
}

// ifupdownInterfaces lists the non-loopback interfaces with an iface stanza,
// in file order, marking those the name, method or options show to be
// virtual.
func ifupdownInterfaces(contents string) []ifupdownInterface {
	var interfaces []ifupdownInterface
	current := -1
	for _, fields := range ifupdownLogicalLines(contents) {
		switch {
		case fields[0] == "iface":
			current = -1
			if len(fields) < 2 || fields[1] == "lo" || !ifname.Valid(fields[1]) {
				continue
			}
			iface := ifupdownInterface{name: fields[1], virtual: virtualInterfaceName(fields[1])}
			if len(fields) >= 4 && virtualIfupdownMethods[fields[3]] {
				iface.virtual = true
			}
			interfaces = mergeIfupdownInterfaces(interfaces, []ifupdownInterface{iface})
			for i := range interfaces {
				if interfaces[i].name == iface.name {
					current = i
				}
			}
		case ifupdownStanzaKeyword(fields[0]):
			current = -1
		case current >= 0 && virtualIfupdownOptions[fields[0]]:
			interfaces[current].virtual = true
		}
	}
	return interfaces
}

// mergeIfupdownInterfaces adds more to interfaces in order. An interface
// with several stanzas (inet and inet6, or one per file) is listed once and
// is virtual if any of its stanzas says so.
func mergeIfupdownInterfaces(interfaces, more []ifupdownInterface) []ifupdownInterface {
	for _, iface := range more {
		found := false
		for i := range interfaces {
			if interfaces[i].name == iface.name {
				interfaces[i].virtual = interfaces[i].virtual || iface.virtual
				found = true
			}
		}
		if !found {
			interfaces = append(interfaces, iface)
		}
	}
	return interfaces
}

// ifupdownStanzaKeyword reports a line that starts a stanza other than
// iface, ending the options of the one before it.
func ifupdownStanzaKeyword(word string) bool {
	switch word {
	case "auto", "mapping", "source", "source-directory", "no-auto-down", "no-scripts", "rename", "template":
		return true
	}
	return strings.HasPrefix(word, "allow-")
}

// virtualIfupdownMethods are iface methods that create their own device.
var virtualIfupdownMethods = map[string]bool{"tunnel": true, "v4tunnel": true, "6to4": true, "ppp": true, "wvdial": true}

// virtualIfupdownOptions are stanza options only a bridge, bond, VLAN, VXLAN
// or Open vSwitch device has. A bond's member carries bond-master and stays
// physical.
var virtualIfupdownOptions = map[string]bool{
	"bridge_ports": true, "bridge-ports": true,
	"bond-slaves": true, "bond_slaves": true, "bond-mode": true, "bond_mode": true,
	"vlan-raw-device": true, "vlan_raw_device": true, "vlan-id": true,
	"vxlan-id": true, "vxlan_id": true,
	"ovs_type": true, "ovs-type": true,
}

// virtualInterfaceName reports a name the kernel never gives a physical NIC:
// a VLAN (eth0.100) or a conventional bridge, bond, tunnel or container
// device name.
func virtualInterfaceName(name string) bool {
	if strings.Contains(name, ".") {
		return true
	}
	for _, prefix := range []string{"br", "vmbr", "virbr", "lxcbr", "bond", "team", "vlan", "vxlan", "docker", "veth", "tap", "tun", "wg", "ppp"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// networkManagerIgnoresKeyfiles reports an EL7 guest whose NetworkManager
// (1.18) has not been configured to load the keyfile plugin. The plugin list is
// the guest's effective one: its main file, the snippets that override it, and
// the list-extending forms of the key. NetworkManager's manual says
// the keyfile plugin is always active, but an EL7 template kept its own address
// with a keyfile profile and no keyfile plugin listed, so the observed
// behavior is what decides.
func (a *Adapter) networkManagerIgnoresKeyfiles(ctx context.Context, guest *detection) (bool, error) {
	release, err := a.readOptionalFile(ctx, guest.overlays, osReleaseFile)
	if err == nil && release == "" {
		release, err = a.readOptionalFile(ctx, guest.overlays, osReleaseFallback)
	}
	if err != nil {
		return false, err
	}
	if !enterpriseLinux7(release) {
		return false, nil
	}
	settings, err := guest.networkManagerSettings(ctx)
	if err != nil {
		return false, err
	}
	return !settings.loadsKeyfile(), nil
}

// readOptionalFile reads a guest file, "" when it is absent. It follows
// symlinks inside the guest (CentOS 7's /etc/os-release links to
// ../usr/lib/os-release).
func (a *Adapter) readOptionalFile(ctx context.Context, overlays []string, file string) (string, error) {
	output, err := a.run(ctx, guestfishReadArgs(overlays, "is-file", file, "followsymlinks:true")...)
	exists := strings.EqualFold(strings.TrimSpace(output), "true")
	if err != nil {
		return "", dependencyError("inspect "+file, err)
	}
	if !exists {
		return "", nil
	}
	contents, err := a.run(ctx, guestfishReadArgs(overlays, "cat", file)...)
	if err != nil {
		return "", dependencyError("read "+file, err)
	}
	return contents, nil
}

// enterpriseLinux7 recognizes RHEL 7 and its rebuilds (CentOS, Oracle Linux,
// Scientific Linux) from /etc/os-release.
func enterpriseLinux7(osRelease string) bool {
	values := map[string]string{}
	for _, line := range strings.Split(osRelease, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found {
			values[key] = strings.ToLower(strings.Trim(value, "\"'"))
		}
	}
	family := " " + values["ID"] + " " + values["ID_LIKE"] + " "
	if !strings.Contains(family, " rhel ") && !strings.Contains(family, " centos ") && !strings.Contains(family, " fedora ") {
		return false
	}
	major, _, _ := strings.Cut(values["VERSION_ID"], ".")
	return major == "7"
}

func (a *Adapter) directoryExists(ctx context.Context, overlays []string, path string) (bool, error) {
	output, err := a.run(ctx, guestfishReadArgs(overlays, "is-dir", path)...)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(output), "true"), nil
}

func (a *Adapter) fileExists(ctx context.Context, overlays []string, path string) (bool, error) {
	output, err := a.run(ctx, guestfishReadArgs(overlays, "is-file", path)...)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(output), "true"), nil
}

func validate(cfg Config) (*net.IPNet, string, error) {
	if cfg.VMID <= 0 {
		return nil, "", fmt.Errorf("guest network adapter requires a positive VMID")
	}
	if err := validateOverlays(cfg.Overlays); err != nil {
		return nil, "", fmt.Errorf("VM %d: %w", cfg.VMID, err)
	}
	// The address goes into the guest's profile as the adapter to match: the
	// same rule as the plan and the PVE request (internal/macaddr), so a zero,
	// broadcast or multicast address is never written.
	if _, err := macaddr.Parse(cfg.MAC); err != nil {
		return nil, "", fmt.Errorf("VM %d needs a valid source MAC for overlay network recovery: %v", cfg.VMID, err)
	}
	ip := net.ParseIP(cfg.Address).To4()
	if ip == nil {
		return nil, "", fmt.Errorf("VM %d recovery address must be IPv4", cfg.VMID)
	}
	// The one reader of the sandbox range, shared with plan validation, the
	// node's overlap check and the engine (config.ParseSandboxRange).
	sandbox, err := config.ParseSandboxRange(cfg.CIDR)
	if err != nil {
		return nil, "", fmt.Errorf("VM %d: the sandbox range %w", cfg.VMID, err)
	}
	subnet := &net.IPNet{IP: net.IP(sandbox.Addr().AsSlice()), Mask: net.CIDRMask(sandbox.Bits(), 32)}
	if !subnet.Contains(ip) {
		return nil, "", fmt.Errorf("VM %d recovery address must be within the isolated IPv4 CIDR", cfg.VMID)
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = modeAuto
	}
	if _, ok := strategyDirectory(mode); !ok && mode != modeAuto {
		return nil, "", fmt.Errorf("unsupported recovery network mode %q", cfg.Mode)
	}
	if cfg.InterfaceName != "" && !ifname.Valid(cfg.InterfaceName) {
		return nil, "", fmt.Errorf("VM %d recovery interface name %q is invalid: %s", cfg.VMID, cfg.InterfaceName, ifname.Describe)
	}
	return subnet, mode, nil
}

// validateOverlays refuses an overlay list guestfish could not safely open:
// none at all, a relative or unsafe path, a duplicate. Every restored disk's
// overlay must be listed, so an empty entry (a disk whose overlay was never
// created) is an error here rather than a disk the guest has but guestfish
// silently never sees.
func validateOverlays(overlays []string) error {
	if len(overlays) == 0 {
		return fmt.Errorf("guest network adapter requires the overlay of every restored disk, and none was given")
	}
	if len(overlays) > maxOverlays {
		return fmt.Errorf("guest network adapter takes at most %d overlays, got %d", maxOverlays, len(overlays))
	}
	seen := make(map[string]bool, len(overlays))
	for _, overlay := range overlays {
		if (!path.IsAbs(overlay) && !filepath.IsAbs(overlay)) || strings.ContainsAny(overlay, "\r\n\x00") {
			return fmt.Errorf("guest network adapter requires an absolute safe overlay path for every restored disk, got %q", overlay)
		}
		if seen[filepath.Clean(overlay)] {
			return fmt.Errorf("guest network adapter was given the overlay %s twice", overlay)
		}
		seen[filepath.Clean(overlay)] = true
	}
	return nil
}

func renderInterfaceLink(cfg Config) string {
	return fmt.Sprintf(`[Match]
MACAddress=%s

[Link]
NamePolicy=
Name=%s
`, strings.ToUpper(cfg.MAC), cfg.InterfaceName)
}

func strategyDirectory(strategy string) (string, bool) {
	switch strategy {
	case modeIfcfg:
		return ifcfgDir, true
	case modeNetworkManager:
		return networkManagerDir, true
	case modeNetplan:
		return netplanDir, true
	case modeSystemdNetworkd:
		return systemdNetworkdDir, true
	case modeIfupdown:
		return ifupdownDir, true
	default:
		return "", false
	}
}

func render(strategy string, cfg Config, subnet *net.IPNet) (string, string) {
	ones, _ := subnet.Mask.Size()
	address := fmt.Sprintf("%s/%d", net.ParseIP(cfg.Address).To4().String(), ones)
	mac := strings.ToLower(cfg.MAC)

	switch strategy {
	case modeIfcfg:
		destination := ifcfgProfile
		if cfg.InterfaceName != "" {
			destination = ifcfgDir + "/ifcfg-" + cfg.InterfaceName
		}
		return renderIfcfg(cfg, subnet), destination
	case modeNetworkManager:
		return fmt.Sprintf(`[connection]
id=CertiStack isolated recovery
uuid=%s
type=ethernet
autoconnect=true
autoconnect-priority=999

[ethernet]
mac-address=%s

[ipv4]
method=manual
address1=%s
never-default=true
may-fail=false

[ipv6]
method=disabled
`, profileUUID(cfg), mac, address), networkManagerProfile
	case modeNetplan:
		return renderNetplan(recoveryIDs[0], false, cfg, subnet), netplanProfile
	default:
		return fmt.Sprintf(`[Match]
MACAddress=%s

[Network]
Address=%s
LinkLocalAddressing=no
IPv6AcceptRA=no
`, strings.ToUpper(cfg.MAC), address), networkdProfile
	}
}

// renderNetplan renders the recovery definition under the given ID. The ID
// decides where its generated networkd file sorts among the guest's own (see
// recoveryID). The sandbox is IPv4-only with no router. Like the networkd and
// NetworkManager profiles, turn off IPv6 link-local and router
// advertisements: otherwise networkd keeps the link "configuring"
// while it waits for an RA, and systemd-networkd-wait-online holds
// network-online.target (and nginx, PostgreSQL, ...) until its
// timeout. For the same reason the link is not "optional".
// networkd names the renderer for a guest whose global renderer is another
// one: netplan would otherwise give the definition to that renderer.
func renderNetplan(id string, networkd bool, cfg Config, subnet *net.IPNet) string {
	ones, _ := subnet.Mask.Size()
	address := fmt.Sprintf("%s/%d", net.ParseIP(cfg.Address).To4().String(), ones)
	renderer := ""
	if networkd {
		renderer = "      renderer: networkd\n"
	}
	return fmt.Sprintf(`network:
  version: 2
  ethernets:
    %s:
%s      match:
        macaddress: %s
      addresses:
        - %s
      dhcp4: false
      dhcp6: false
      accept-ra: false
      link-local: []
`, id, renderer, strings.ToLower(cfg.MAC), address)
}

// renderWaitOnlineDropIn replaces the interface list that netplan's generator
// passes to systemd-networkd-wait-online. netplan resolves a MAC-matched
// definition to the NIC's name at generator time; when an initrd rename
// (dracut: eth0 -> ens18) is followed by the guest's own set-name (ens18 ->
// eth0), wait-online waits for a name that no longer exists until its timeout,
// holding network-online.target and every service ordered after it. The
// sandbox has one recovery link, so any online link is the right condition.
// The file sorts after netplan's 10-netplan.conf, so this ExecStart wins; the
// /lib path is the one netplan itself writes.
func renderWaitOnlineDropIn() string {
	return "[Service]\nExecStart=\nExecStart=/lib/systemd/systemd-networkd-wait-online --any\n"
}

// renderCloudNetworkDropIn is cloud-init's documented switch for leaving the
// network configuration to the guest.
func renderCloudNetworkDropIn() string {
	return "# Written by CertiStack into a disposable copy-on-write overlay only.\nnetwork: {config: disabled}\n"
}

// renderIfupdown replaces the guest's /etc/network/interfaces in the overlay.
// It deliberately does not source interfaces.d: the guest's own stanza for the
// NIC (with its gateway and DNS) may live there and must not come back.
//
// One name is raised at boot ("auto"). Several names for the only NIC are
// each "allow-hotplug": udev raises the one that exists, the rest never
// appear, and ifupdown-wait-online waits for any hotplug interface, where an
// "auto" stanza for a missing name would fail networking.service and hold
// network-online.target for five minutes.
func renderIfupdown(names []string, cfg Config, subnet *net.IPNet) string {
	ones, _ := subnet.Mask.Size()
	var b strings.Builder
	b.WriteString(`# CertiStack isolated recovery profile (disposable COW overlay only).
# The guest's original file is interfaces.certistack-original.
# No gateway and no DNS: the sandbox is air-gapped.
auto lo
iface lo inet loopback
`)
	start := "auto"
	if len(names) > 1 {
		start = "allow-hotplug"
		b.WriteString("\n# The guest's configuration names its only NIC several ways; the one\n# that exists comes up when udev adds it.\n")
	}
	for _, name := range names {
		fmt.Fprintf(&b, "\n%[1]s %[2]s\niface %[2]s inet static\n    address %[3]s/%[4]d\n", start, name, net.ParseIP(cfg.Address).To4().String(), ones)
	}
	return b.String()
}

func renderIfcfg(cfg Config, subnet *net.IPNet) string {
	ones, _ := subnet.Mask.Size()
	lines := []string{
		"TYPE=Ethernet",
		"BOOTPROTO=none",
		"DEFROUTE=no",
		"HWADDR=" + strings.ToLower(cfg.MAC),
		"IPADDR=" + net.ParseIP(cfg.Address).To4().String(),
		"PREFIX=" + strconv.Itoa(ones),
		"ONBOOT=yes",
		"NM_CONTROLLED=yes",
		"AUTOCONNECT_PRIORITY=999",
	}
	if cfg.InterfaceName != "" {
		lines = append(lines, "DEVICE="+cfg.InterfaceName)
	}
	return strings.Join(lines, "\n") + "\n"
}

func profileUUID(cfg Config) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("certistack:%d:%s:%s", cfg.VMID, strings.ToUpper(cfg.MAC), cfg.Address)))
	value := digest[:16]
	// RFC 4122 variant and version 5 layout; this is deterministic evidence,
	// not an identity or secret.
	value[6] = (value[6] & 0x0f) | 0x50
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

// guestfishDrives adds every overlay as a drive, in order, each with its own
// explicit format. The upstream manuals say a multi-device guest must have each
// block device passed as a separate -a for inspection to see it whole; the
// order is the guest's disk order, which decides how /dev/sdX names in its
// fstab and LVM metadata resolve.
//
// Every call reads keys only from standard input (keysFromStdin): a guest with
// an encrypted volume fails at once with "could not read key from user" and
// never makes guestfish wait on a terminal for a passphrase.
func guestfishDrives(access string, overlays []string) []string {
	return guestfishDrivesOf(access, "qcow2", overlays)
}

// guestfishReadArgs opens the overlays read-only for all detection and evidence
// collection. Mutation is intentionally limited to guestfishBatchArgs, which
// executes one reviewed COW-only transaction after the strategy is known.
func guestfishReadArgs(overlays []string, command ...string) []string {
	return append(guestfishDrives("--ro", overlays), command...)
}

func guestfishBatchArgs(overlays []string, commands [][]string) []string {
	return guestfishScript(guestfishDrives("--rw", overlays), commands)
}

// guestfishQueryArgs runs several read-only commands in one appliance boot;
// their results are printed one after the other.
func guestfishQueryArgs(overlays []string, commands [][]string) []string {
	return guestfishScript(guestfishDrives("--ro", overlays), commands)
}

func guestfishScript(args []string, commands [][]string) []string {
	args = append(args, "--")
	for index, command := range commands {
		args = append(args, command...)
		if index+1 < len(commands) {
			args = append(args, ":")
		}
	}
	return args
}

// dependencyError adds the install hint only when guestfish itself is
// missing; an installed guestfish that cannot inspect a disk needs a
// different remedy.
func dependencyError(action string, err error) error {
	message := err.Error()
	switch {
	case errors.Is(err, exec.ErrNotFound) || strings.Contains(message, "executable file not found"):
		return fmt.Errorf("%s isolated guest network profile with guestfish: %w (install libguestfs-tools on the node worker or use the CertiStack appliance image)", action, err)
	case encryptedVolume(message) != "":
		// An encrypted root cannot be read without its passphrase.
		return guestRefusal{encryptedGuestError(action, err, encryptedVolume(message))}
	case strings.Contains(message, "no operating system was found"):
		return guestRefusal{fmt.Errorf("%s isolated guest network profile with guestfish: %w (the restored disks have no inspectable Linux installation, or the installation needs a disk that was not restored; use network_recovery.mode: preserve for non-Linux guests)", action, err)}
	case strings.Contains(message, "multi-boot"):
		// guestfish opens every restored disk together, and -i takes
		// one operating system: a data disk that holds another one defeats it.
		return guestRefusal{fmt.Errorf("%s isolated guest network profile with guestfish: %w (more than one restored disk holds an operating system, and guestfish -i cannot choose between them; use network_recovery.mode: preserve, or leave the extra system disk out of the plan's restored disks)", action, err)}
	case strings.Contains(message, "Read-only file system"):
		// An appliance image mounts its root read-only (Home Assistant OS keeps the writable state on separate partitions), so the
		// profile cannot be placed in it.
		return guestRefusal{fmt.Errorf("%s isolated guest network profile with guestfish: %w (unsupported guest network layout: the guest's file system is read-only in the image, as on an appliance such as Home Assistant OS, so the profile cannot be written; use network_recovery.mode: preserve)", action, err)}
	case strings.Contains(message, "inspect_os") && strings.Contains(message, "Invalid partition table"):
		// libguestfs cannot read the partition layout of FreeBSD-based systems such as OPNsense (a partition table inside a partition).
		return guestRefusal{fmt.Errorf("%s isolated guest network profile with guestfish: %w (unsupported guest network layout: libguestfs cannot read this guest's partition layout, as with FreeBSD-based systems such as OPNsense, and there is no inspectable Linux installation; use network_recovery.mode: preserve for non-Linux guests)", action, err)}
	default:
		return fmt.Errorf("%s isolated guest network profile with guestfish: %w", action, err)
	}
}

func runGuestfish(ctx context.Context, args ...string) (string, error) {
	result, err := sysutil.Run(ctx, guestfishTimeout, "guestfish", args...)
	if result == nil {
		return "", err
	}
	if err != nil {
		if reason := guestfishReason(result.Stderr); reason != "" {
			err = fmt.Errorf("%w: %s", err, reason)
		}
		err = withEncryptedVolume(ctx, args, err)
	}
	return string(result.Stdout), err
}

// guestfishReason condenses guestfish stderr to its first error line so a
// failure says why ("no operating system was found on this disk") instead of
// only "exit status 1". It is bounded and single-line for the report.
func guestfishReason(stderr []byte) string {
	const maximum = 240
	var fallback string
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimSpace(strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, line))
		if line == "" {
			continue
		}
		if fallback == "" {
			fallback = line
		}
		if strings.HasPrefix(line, "guestfish:") || strings.Contains(line, "libguestfs: error:") {
			fallback = line
			break
		}
	}
	if len(fallback) > maximum {
		fallback = fallback[:maximum] + "..."
	}
	return fallback
}

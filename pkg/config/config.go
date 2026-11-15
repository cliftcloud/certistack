// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package config parses, normalises, and validates CertiStack test plans.
//
// A plan is a single literal YAML document (no environment interpolation).
// LoadFromFile and LoadFromReader apply the controller rules; the *ForWorker
// variants load the plan the temporary node worker is sent, which lacks the
// controller's own settings and is judged by the same rules. No plan needs a
// report signing key: the Community Edition writes its reports unsigned, and
// accepts compliance.sign_key_path only so that plans stay portable between the
// editions. Every accepted, aliased, and rejected key is documented in
// the keys section of docs/plan-reference.md.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cliftcloud/certistack/internal/diskslot"
	"github.com/cliftcloud/certistack/internal/httptarget"
	"github.com/cliftcloud/certistack/internal/ifname"
	"github.com/cliftcloud/certistack/internal/ldapdn"
	"github.com/cliftcloud/certistack/internal/macaddr"
	"github.com/cliftcloud/certistack/internal/qgacommand"
)

const maxPlanBytes = 10 << 20

// MaxPlanBytes is the largest plan file the loaders accept. Anything that
// reads other plans to learn what they hold (init, for the IDs of the plans
// beside its output) reads up to this and no less, so it never skips a plan a
// run would accept.
const MaxPlanBytes = maxPlanBytes

// maxRetentionDays bounds compliance.retention_days at 100 years.
const maxRetentionDays = 36500

// MaxVXLANVNI is the largest value representable by the VXLAN 24-bit VNI.
const MaxVXLANVNI = 1<<24 - 1

// maxPVESDNIDLength is the Proxmox VE limit for SDN zone and VNet IDs.
const maxPVESDNIDLength = 8

// DefaultBootSettleSec is how long a started sandbox VM counts as booting
// for admission_control.max_concurrent_boots when boot_settle_sec is unset:
// the first minutes, when a guest's writes to its fresh overlays are
// heaviest.
const DefaultBootSettleSec = 180

// BootSettle is how long a started sandbox VM counts as booting.
func (a AdmissionControl) BootSettle() time.Duration {
	if a.BootSettleSec > 0 {
		return time.Duration(a.BootSettleSec) * time.Second
	}
	return DefaultBootSettleSec * time.Second
}

// Plan represents a complete CertiStack disaster recovery test plan.
type Plan struct {
	Version          string           `yaml:"version" json:"version"`
	PlanID           string           `yaml:"plan_id" json:"plan_id"`
	Name             string           `yaml:"name" json:"name"`
	Environment      string           `yaml:"environment,omitempty" json:"environment,omitempty"`
	UseBackupConfig  bool             `yaml:"use_backup_config,omitempty" json:"use_backup_config,omitempty"`
	Compliance       Compliance       `yaml:"compliance" json:"compliance"`
	AdmissionControl AdmissionControl `yaml:"admission_control" json:"admission_control"`
	Admission        AdmissionControl `yaml:"admission,omitempty" json:"admission,omitempty"`
	Network          Network          `yaml:"network" json:"network"`
	Storage          Storage          `yaml:"storage,omitempty" json:"storage,omitempty"`
	Tiers            []Tier           `yaml:"tiers" json:"tiers"`

	// keys are the paths of the keys the plan's YAML gave, for a plan loaded
	// from YAML (see planKeys); nil for a plan built in code.
	keys map[string]bool
}

type Compliance struct {
	Frameworks    []string `yaml:"frameworks" json:"frameworks"`
	RetentionDays int      `yaml:"retention_days,omitempty" json:"retention_days,omitempty"`
	// SignKeyPath names the controller-local private key the Enterprise Edition
	// signs its reports with. It is accepted so that a plan stays portable between
	// the editions. The Community Edition writes its reports unsigned and ignores
	// the field: it never reads, checks or requires the file (SignKeyPathNote).
	SignKeyPath      string  `yaml:"sign_key_path,omitempty" json:"sign_key_path,omitempty"`
	RTOTargetSeconds float64 `yaml:"rto_target_seconds,omitempty" json:"rto_target_seconds,omitempty"`
}

type AdmissionControl struct {
	MaxHostRAMPercent       float64 `yaml:"max_host_ram_percent" json:"max_host_ram_percent"`
	MaxHostIOWaitPercent    float64 `yaml:"max_host_iowait_percent,omitempty" json:"max_host_iowait_percent,omitempty"`
	MaxHostIOWaitPercentAlt float64 `yaml:"max_host_io_wait_percent,omitempty" json:"max_host_io_wait_percent,omitempty"`
	DeferRetryIntervalSec   int     `yaml:"defer_retry_interval_sec" json:"defer_retry_interval_sec"`
	MaxDeferRetries         int     `yaml:"max_defer_retries" json:"max_defer_retries"`
	// MaxConcurrentBoots limits how many sandbox VMs boot at once on the
	// node: a VM counts as booting for BootSettleSec after it is started
	// (DefaultBootSettleSec when zero). Zero is unlimited.
	MaxConcurrentBoots int `yaml:"max_concurrent_boots,omitempty" json:"max_concurrent_boots,omitempty"`
	BootSettleSec      int `yaml:"boot_settle_sec,omitempty" json:"boot_settle_sec,omitempty"`
}

type Network struct {
	Mode       string `yaml:"mode" json:"mode"`
	Lifecycle  string `yaml:"lifecycle,omitempty" json:"lifecycle,omitempty"`
	ZoneID     string `yaml:"zone_id" json:"zone_id"`
	VNetID     string `yaml:"vnet_id" json:"vnet_id"`
	Tag        int    `yaml:"tag,omitempty" json:"tag,omitempty"`
	Peers      string `yaml:"peers,omitempty" json:"peers,omitempty"`
	IPRange    string `yaml:"ip_range,omitempty" json:"ip_range,omitempty"`
	ProbeIP    string `yaml:"probe_ip,omitempty" json:"probe_ip,omitempty"`
	SubnetCIDR string `yaml:"subnet_cidr,omitempty" json:"subnet_cidr,omitempty"`
	Gateway    string `yaml:"gateway,omitempty" json:"gateway,omitempty"`
	IPAM       string `yaml:"ipam,omitempty" json:"ipam,omitempty"`
	MTU        int    `yaml:"mtu,omitempty" json:"mtu,omitempty"`
}

// EffectiveLifecycle returns the ownership model for the PVE SDN sandbox.
// Ephemeral is the compatibility-safe default: CertiStack creates, records,
// and removes the zone and VNet. Preprovisioned is explicit opt-in for a
// platform-owned, already-isolated sandbox that CertiStack validates and uses
// without modifying its SDN configuration.
func (n Network) EffectiveLifecycle() string {
	lifecycle := strings.ToLower(strings.TrimSpace(n.Lifecycle))
	if lifecycle == "" {
		return "ephemeral"
	}
	return lifecycle
}

// VXLANPeerAddresses returns the canonical, sorted peer IP list for a VXLAN
// zone. Proxmox represents this field as a comma-separated string.
func (n Network) VXLANPeerAddresses() ([]string, error) {
	if strings.TrimSpace(n.Peers) == "" {
		return nil, fmt.Errorf("must specify at least one VXLAN peer")
	}

	seen := make(map[string]struct{})
	peers := make([]string, 0)
	for _, rawPeer := range strings.Split(n.Peers, ",") {
		peer := net.ParseIP(strings.TrimSpace(rawPeer))
		if peer == nil {
			return nil, fmt.Errorf("VXLAN peers must be comma-separated IP addresses")
		}
		canonical := peer.String()
		if _, duplicate := seen[canonical]; duplicate {
			return nil, fmt.Errorf("VXLAN peers must not contain duplicates")
		}
		seen[canonical] = struct{}{}
		peers = append(peers, canonical)
	}
	sort.Strings(peers)
	return peers, nil
}

// ProbeAddressCIDR returns the host-side sandbox address in CIDR notation.
// The address is attached only to the transient VNet while CertiStack is
// running, giving Stage 2 probes an explicit local route into the air-gapped
// subnet without creating a gateway or a route outside it.
func (n Network) ProbeAddressCIDR() (string, error) {
	ip := net.ParseIP(strings.TrimSpace(n.ProbeIP))
	if ip == nil {
		return "", fmt.Errorf("network.probe_ip must be a valid IP address")
	}
	if problem := ipv4OnlyProblem(strings.TrimSpace(n.ProbeIP)); problem != "" {
		return "", fmt.Errorf("network.probe_ip %s", problem)
	}
	sandboxRange, err := ParseSandboxRange(n.IPRange)
	if err != nil {
		return "", fmt.Errorf("network.ip_range %w", err)
	}
	subnet := ipNet(sandboxRange)
	if !subnet.Contains(ip) {
		return "", fmt.Errorf("network.probe_ip must be within network.ip_range")
	}
	ones, bits := subnet.Mask.Size()
	if ones < 0 || bits == 0 {
		return "", fmt.Errorf("network.ip_range has an invalid mask")
	}
	if ip4 := ip.To4(); ip4 != nil && bits == net.IPv4len*8 {
		ip = ip4
	}
	return fmt.Sprintf("%s/%d", ip.String(), ones), nil
}

type Storage struct {
	PBSRepository  string `yaml:"pbs_repository,omitempty" json:"pbs_repository,omitempty"`
	PBSFingerprint string `yaml:"pbs_fingerprint,omitempty" json:"pbs_fingerprint,omitempty"`
	PBSNamespace   string `yaml:"pbs_namespace,omitempty" json:"pbs_namespace,omitempty"`
	ScratchDir     string `yaml:"scratch_dir,omitempty" json:"scratch_dir,omitempty"`
	// OverlayStorage is the PVE storage ID (file-based, with "images" content)
	// that holds the disposable qcow2 overlays. Stock Proxmox VE only attaches
	// disks that belong to a storage, so overlays are created as volumes of
	// this storage and attached by volume ID.
	OverlayStorage string `yaml:"overlay_storage,omitempty" json:"overlay_storage,omitempty"`
	// MaxCopyGiB caps what copy-before-boot writes in one run, all VMs
	// together, beside the overlays. Zero is no cap beyond the free space.
	MaxCopyGiB int `yaml:"max_copy_gib,omitempty" json:"max_copy_gib,omitempty"`
}

type Tier struct {
	Level                 int    `yaml:"level,omitempty" json:"level,omitempty"`
	Tier                  int    `yaml:"tier,omitempty" json:"tier,omitempty"`
	Name                  string `yaml:"name" json:"name"`
	StartupGracePeriodSec int    `yaml:"startup_grace_period_sec,omitempty" json:"startup_grace_period_sec,omitempty"`
	BootTimeoutSec        int    `yaml:"boot_timeout_sec,omitempty" json:"boot_timeout_sec,omitempty"`
	SoakTimeSec           int    `yaml:"soak_time_sec,omitempty" json:"soak_time_sec,omitempty"`
	VMs                   []VM   `yaml:"vms" json:"vms"`
}

type VM struct {
	VMID            int             `yaml:"vmid,omitempty" json:"vmid,omitempty"`
	TargetVMID      int             `yaml:"target_vmid,omitempty" json:"target_vmid,omitempty"`
	SourceVMID      int             `yaml:"source_vmid,omitempty" json:"source_vmid,omitempty"`
	Name            string          `yaml:"name" json:"name"`
	MAC             string          `yaml:"mac,omitempty" json:"mac,omitempty"`
	NICModel        string          `yaml:"nic_model,omitempty" json:"nic_model,omitempty"`
	NetworkRecovery NetworkRecovery `yaml:"network_recovery,omitempty" json:"network_recovery,omitempty"`
	Machine         string          `yaml:"machine,omitempty" json:"machine,omitempty"`
	OSType          string          `yaml:"ostype,omitempty" json:"ostype,omitempty"`
	BIOS            string          `yaml:"bios,omitempty" json:"bios,omitempty"`
	SCSIHW          string          `yaml:"scsihw,omitempty" json:"scsihw,omitempty"`
	SourceTags      []string        `yaml:"-" json:"source_tags,omitempty"`
	// BootDisk, BootOrder and OmittedDisks are set by the worker from the
	// backup: the slot the sandbox VM boots (the source boot order's first
	// restored disk), the source boot order restricted to the restored disks
	// (the sandbox VM's whole boot order: a guest whose /boot is on a second
	// disk needs that disk in it), and the backed-up disks this plan does not
	// restore.
	BootDisk     string   `yaml:"-" json:"-"`
	BootOrder    []string `yaml:"-" json:"-"`
	OmittedDisks []string `yaml:"-" json:"-"`
	// SourceDiskBytes are the restored disks' sizes from the backup's
	// configuration, where it gives them; set by the worker. It is what PVE
	// recorded (the size a resize asked for), not necessarily the image's size.
	SourceDiskBytes map[string]int64 `yaml:"-" json:"-"`
	// SourceImageBytes are the restored disks' image sizes from the snapshot's
	// manifest, where it lists them: the length a mapped image must have. Set
	// by the worker.
	SourceImageBytes map[string]int64 `yaml:"-" json:"-"`
	// SourceCryptMode is the weakest PBS crypt mode of the backup's disks,
	// SourceSignatureVerified whether a key verified its manifest, and
	// ExcludedDisks the source disks left out of backups (backup=0); all set
	// by the worker.
	SourceCryptMode         string   `yaml:"-" json:"-"`
	SourceSignatureVerified bool     `yaml:"-" json:"-"`
	ExcludedDisks           []string `yaml:"-" json:"-"`
	// AdditionalNICs are the source NICs after net0 that the sandbox VM
	// gets (attach_all_nics); OmittedNICs are the ones it does not.
	AdditionalNICs []SourceNIC `yaml:"-" json:"-"`
	OmittedNICs    []string    `yaml:"-" json:"-"`
	// NoBalloon is set by the worker when the source VM has no memory
	// balloon device (balloon: 0).
	NoBalloon bool `yaml:"-" json:"-"`
	// SourceConsistency and SourceConsistencyDetail are how consistent the
	// backup's disks were, from its log; set by the worker.
	SourceConsistency       string `yaml:"-" json:"-"`
	SourceConsistencyDetail string `yaml:"-" json:"-"`
	// SMBIOS1 is the source's SMBIOS identity and SourceMeta its meta
	// information (creation-qemu), set by the worker.
	SMBIOS1    string `yaml:"-" json:"-"`
	SourceMeta string `yaml:"-" json:"-"`
	// SourceCDROMs are the source's CD-ROM slots, set by the worker.
	SourceCDROMs      []string          `yaml:"-" json:"-"`
	SourcePBS         SourcePBS         `yaml:"source_pbs,omitempty" json:"source_pbs,omitempty"`
	HardwareOverrides HardwareOverrides `yaml:"hardware_overrides,omitempty" json:"hardware_overrides,omitempty"`
	// RequireQuiescedBackup fails the VM unless its backup was quiesced or
	// taken powered off, for applications that must not start from
	// crash-consistent disks.
	RequireQuiescedBackup bool `yaml:"require_quiesced_backup,omitempty" json:"require_quiesced_backup,omitempty"`
	// RequireSignedBackup fails the VM before anything is created unless its
	// backup's manifest is signed (sign-only or encrypted) and the key in
	// CERTISTACK_PBS_KEYFILE verified it. Without it, a run with a key still
	// restores an unsigned backup as unsigned, and reports it as such.
	RequireSignedBackup bool `yaml:"require_signed_backup,omitempty" json:"require_signed_backup,omitempty"`
	// CopyBeforeBoot chooses whether the scan also copies the VM's disks to
	// local storage for the sandbox to boot from: "auto" (the default) when
	// they would not fit in the node's page cache, "always", or "never".
	CopyBeforeBoot string  `yaml:"copy_before_boot,omitempty" json:"copy_before_boot,omitempty"`
	Probes         []Probe `yaml:"probes" json:"probes"`
	// FirmwareDisks are the firmware state images of a UEFI source VM. The
	// worker discovers them from the PBS snapshot; a plan cannot set them.
	FirmwareDisks []FirmwareDisk `yaml:"-" json:"-"`
}

// Copy-before-boot modes (VM.CopyBeforeBoot).
const (
	CopyBeforeBootAuto   = "auto"
	CopyBeforeBootAlways = "always"
	CopyBeforeBootNever  = "never"
)

// SourceNIC is a source NIC after net0: its slot (net1..net31), model and
// MAC. Its bridge, VLAN and firewall settings are never replayed.
type SourceNIC struct {
	Slot  string
	Model string
	MAC   string
}

// FirmwareDisk is one backed-up firmware state image: the UEFI variable
// store (efidisk0) or the TPM state (tpmstate0). Options holds only the
// allowlisted PVE options that describe it, such as "efitype=4m".
type FirmwareDisk struct {
	Slot    string
	Archive string
	Options string
}

// NetworkRecovery controls the temporary, isolated network profile written
// only to a VM's disposable COW overlay. It never changes the source VM,
// backup snapshot, or production network configuration.
//
// Mode defaults to "auto" for isolated wire-probe plans. CertiStack detects
// the supported Linux network manager and writes only the disposable COW
// overlay; set mode to "preserve" to opt out. The explicit backend modes are
// useful when a guest family is already known.
type NetworkRecovery struct {
	Mode               string `yaml:"mode,omitempty" json:"mode,omitempty"`
	SandboxIP          string `yaml:"sandbox_ip,omitempty" json:"sandbox_ip,omitempty"`
	InterfaceName      string `yaml:"interface_name,omitempty" json:"interface_name,omitempty"`
	CaptureDiagnostics bool   `yaml:"capture_diagnostics,omitempty" json:"capture_diagnostics,omitempty"`
	// AttachAllNICs attaches the source's other NICs (net1 and up) to the
	// isolated VNet too, each with its own MAC and model, so services bound
	// to their addresses start. Only net0 gets a recovery address.
	AttachAllNICs bool `yaml:"attach_all_nics,omitempty" json:"attach_all_nics,omitempty"`
}

// EffectiveMode returns the safe-by-construction default. Adaptation never
// modifies the protected guest or its backup; it writes only the disposable
// COW overlay used by the isolated recovery VM.
func (n NetworkRecovery) EffectiveMode() string {
	mode := strings.ToLower(strings.TrimSpace(n.Mode))
	if mode == "" {
		return "auto"
	}
	return mode
}

// SandboxAddress resolves the single address that an overlay network adapter
// must configure for this VM. Existing plans need no rewrite when every wire
// probe already targets the same isolated address; plans with several guest
// addresses must declare sandbox_ip explicitly. With attach_all_nics, a
// declared sandbox_ip is net0's address and other wire probe targets are the
// guest's own addresses on its other NICs (AdditionalProbeAddresses).
func (v VM) SandboxAddress(network Network) (string, bool, error) {
	if v.NetworkRecovery.EffectiveMode() == "preserve" {
		return "", false, nil
	}
	sandboxRange, err := ParseSandboxRange(network.IPRange)
	if err != nil {
		return "", false, fmt.Errorf("network.ip_range must be a valid IPv4 CIDR: %w", err)
	}
	subnet := ipNet(sandboxRange)
	probeIP := net.ParseIP(network.ProbeIP).To4()
	if probeIP == nil {
		return "", false, fmt.Errorf("network.probe_ip must be a valid IPv4 address")
	}

	configured := strings.TrimSpace(v.NetworkRecovery.SandboxIP)
	if configured != "" {
		if problem := ipv4OnlyProblem(configured); problem != "" {
			return "", false, fmt.Errorf("network_recovery.sandbox_ip %s", problem)
		}
		address := net.ParseIP(configured).To4()
		if address == nil || !subnet.Contains(address) || address.Equal(probeIP) || isSubnetReservedAddress(address, subnet) {
			return "", false, fmt.Errorf("network_recovery.sandbox_ip must be a usable IPv4 address in network.ip_range")
		}
		for _, probe := range v.Probes {
			if v.NetworkRecovery.AttachAllNICs || !isWireProbe(probe.Type) || strings.TrimSpace(probe.TargetIP) == "" {
				continue
			}
			target := net.ParseIP(probe.TargetIP).To4()
			if target != nil && !target.Equal(address) {
				return "", false, fmt.Errorf("network_recovery.sandbox_ip supports one guest address unless attach_all_nics is on; wire probe %q targets %s", probe.Description, probe.TargetIP)
			}
		}
		return address.String(), true, nil
	}

	var address net.IP
	for _, probe := range v.Probes {
		if !isWireProbe(probe.Type) || strings.TrimSpace(probe.TargetIP) == "" {
			continue
		}
		target := net.ParseIP(probe.TargetIP).To4()
		if target == nil || !subnet.Contains(target) || target.Equal(probeIP) {
			continue // Validate reports malformed or out-of-sandbox targets separately.
		}
		if address == nil {
			address = target
			continue
		}
		if !address.Equal(target) {
			return "", false, fmt.Errorf("wire probes target multiple guest addresses; declare network_recovery.sandbox_ip (net0's address)")
		}
	}
	if address == nil {
		return "", false, nil
	}
	return address.String(), true, nil
}

// AdditionalProbeAddresses returns the wire probe targets other than the
// sandbox address, which with attach_all_nics belong to the guest's other
// NICs. They are the guest's own addresses: network recovery configures only
// net0, so a probe reaches them only if the guest's configuration puts them
// inside network.ip_range.
func (v VM) AdditionalProbeAddresses(network Network) []string {
	address, configured, err := v.SandboxAddress(network)
	if err != nil || !configured || !v.NetworkRecovery.AttachAllNICs {
		return nil
	}
	seen := map[string]bool{address: true}
	var extra []string
	for _, probe := range v.Probes {
		target := net.ParseIP(strings.TrimSpace(probe.TargetIP)).To4()
		if !isWireProbe(probe.Type) || target == nil || seen[target.String()] {
			continue
		}
		seen[target.String()] = true
		extra = append(extra, target.String())
	}
	return extra
}

// IsWireProbe reports whether a probe type connects to the guest over the
// sandbox network from the worker host (tcp, http, dns, ldap, mssql, smb).
func IsWireProbe(probeType string) bool {
	return isWireProbe(probeType)
}

// HasWireProbes reports whether any probe of the plan is a wire probe. Only
// such a plan puts the host's probe address on the sandbox bridge, which is
// what nft contains. A nil plan has none.
func (p *Plan) HasWireProbes() bool {
	if p == nil {
		return false
	}
	for _, tier := range p.Tiers {
		for _, vm := range tier.VMs {
			for _, probe := range vm.Probes {
				if isWireProbe(probe.Type) {
					return true
				}
			}
		}
	}
	return false
}

func isWireProbe(probeType string) bool {
	switch strings.ToLower(strings.TrimSpace(probeType)) {
	case "tcp", "tcp_handshake", "http", "http_get", "dns", "ldap", "mssql", "smb":
		return true
	default:
		return false
	}
}

type SourcePBS struct {
	StorageID string `yaml:"storage_id" json:"storage_id"`
	Snapshot  string `yaml:"snapshot" json:"snapshot"`
	// Drive is the legacy single-disk selector. New plans should use Drives so
	// the restore layout records the PVE bus slot for every backed-up disk.
	Drive     string        `yaml:"drive,omitempty" json:"drive,omitempty"`
	Drives    []SourceDrive `yaml:"drives,omitempty" json:"drives,omitempty"`
	Namespace string        `yaml:"namespace,omitempty" json:"namespace,omitempty"`
}

// SourceDrive maps one PBS archive to the SCSI slot it occupied on the source
// VM. Cloud-init and other non-backed-up media are deliberately not modelled.
type SourceDrive struct {
	Slot    string `yaml:"slot" json:"slot"`
	Archive string `yaml:"archive" json:"archive"`
}

// RestoreDrives returns the complete backed-up disk layout. It preserves the
// legacy drive field for existing single-disk plans.
func (s SourcePBS) RestoreDrives() []SourceDrive {
	if len(s.Drives) > 0 {
		return append([]SourceDrive(nil), s.Drives...)
	}
	if s.Drive == "" {
		return nil
	}
	return []SourceDrive{{Slot: legacyDriveSlot(s.Drive), Archive: s.Drive}}
}

// legacyDriveSlot is the slot of the single-disk drive shorthand: the slot
// its archive names ("drive-virtio0" is virtio0), else scsi0.
func legacyDriveSlot(archive string) string {
	if slot, ok := diskslot.ArchiveSlot(archive); ok {
		return slot
	}
	return "scsi0"
}

type HardwareOverrides struct {
	Cores     int `yaml:"cores,omitempty" json:"cores,omitempty"`
	Sockets   int `yaml:"sockets,omitempty" json:"sockets,omitempty"`
	MemoryMB  int `yaml:"memory_mb,omitempty" json:"memory_mb,omitempty"`
	BalloonMB int `yaml:"balloon_mb,omitempty" json:"balloon_mb,omitempty"`
	CPUWeight int `yaml:"cpu_weight,omitempty" json:"cpu_weight,omitempty"`
}

type Probe struct {
	Type               string `yaml:"type" json:"type"`
	TargetIP           string `yaml:"target_ip,omitempty" json:"target_ip,omitempty"`
	URL                string `yaml:"url,omitempty" json:"url,omitempty"`
	Port               int    `yaml:"port,omitempty" json:"port,omitempty"`
	Path               string `yaml:"path,omitempty" json:"path,omitempty"`
	TLS                bool   `yaml:"tls,omitempty" json:"tls,omitempty"`
	ServerName         string `yaml:"server_name,omitempty" json:"server_name,omitempty"`
	TLSSkipVerify      bool   `yaml:"tls_skip_verify,omitempty" json:"tls_skip_verify,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty" json:"insecure_skip_verify,omitempty"`
	ExpectedStatus     int    `yaml:"expected_status,omitempty" json:"expected_status,omitempty"`
	Command            string `yaml:"command,omitempty" json:"command,omitempty"`
	ExpectedOutput     string `yaml:"expected_output,omitempty" json:"expected_output,omitempty"`
	RequireQGA         bool   `yaml:"require_qga,omitempty" json:"require_qga,omitempty"`
	TimeoutSec         int    `yaml:"timeout_sec" json:"timeout_sec"`
	// Retries caps additional probe executions within TimeoutSec. Zero retains
	// automatic readiness polling until the timeout budget expires.
	Retries     int    `yaml:"retries,omitempty" json:"retries,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Domain      string `yaml:"domain,omitempty" json:"domain,omitempty"`
	Transport   string `yaml:"transport,omitempty" json:"transport,omitempty"`
	// RecordType selects the DNS record a dns probe asserts: "a" (the
	// default, an A or AAAA answer) or "srv".
	RecordType string `yaml:"record_type,omitempty" json:"record_type,omitempty"`
	BaseDN     string `yaml:"base_dn,omitempty" json:"base_dn,omitempty"`
	// NamingContext makes an ldap probe read the Root DSE and require the
	// directory to advertise this naming context, without a directory search.
	NamingContext string `yaml:"naming_context,omitempty" json:"naming_context,omitempty"`
}

// ValidationError describes a single schema violation.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}
	if len(e) == 1 {
		return e[0].Error()
	}
	return fmt.Sprintf("%d validation errors occurred, first is %s", len(e), e[0].Error())
}

var (
	planIDRegex         = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
	pveSDNIDRegex       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*[A-Za-z0-9]$`)
	pveStorageIDRegex   = regexp.MustCompile(`^[a-z][a-z0-9_.-]*[a-z0-9]$`)
	archiveNameRegex    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	serverNameLabelExpr = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	// pveVMNameRegex is a PVE VM name, which PVE requires to be a DNS name
	// (pkg/pbs reads a backup's name by the same rule).
	pveVMNameRegex = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$`)
)

func validServerName(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.HasSuffix(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !serverNameLabelExpr.MatchString(label) {
			return false
		}
	}
	return true
}

// maxProbePort is the highest TCP or UDP port a wire probe can name.
const maxProbePort = 65535

// ldapDNProblem says why dn is not a distinguished name (RFC 4514, at most
// ldapdn.MaxLength bytes), or returns "". The prober parses with the same code.
func ldapDNProblem(dn string) string {
	if err := ldapdn.Valid(dn); err != nil {
		return ": it " + err.Error()
	}
	return ""
}

// Normalize populates alias fields and default values across the Plan. It
// fills a canonical field from its alias, or a default, only where the plan
// left the canonical field out; a value the plan gives is never replaced, so
// validation sees what the author wrote.
func (p *Plan) Normalize() {
	p.normalizeAdmission()
	if !p.given("network.ip_range", p.Network.IPRange != "") && p.given("network.subnet_cidr", p.Network.SubnetCIDR != "") {
		p.Network.IPRange = p.Network.SubnetCIDR
	}

	for i := range p.Tiers {
		tier := &p.Tiers[i]
		tierPath := fmt.Sprintf("tiers[%d]", i)
		if !p.given(tierPath+".level", tier.Level != 0) && p.given(tierPath+".tier", tier.Tier != 0) {
			tier.Level = tier.Tier
		}
		if tier.Name == "" {
			tier.Name = fmt.Sprintf("Tier %d", tier.Level)
		}

		for j := range tier.VMs {
			vm := &tier.VMs[j]
			vmPath := fmt.Sprintf("%s.vms[%d]", tierPath, j)
			if !p.given(vmPath+".vmid", vm.VMID != 0) && p.given(vmPath+".target_vmid", vm.TargetVMID != 0) {
				vm.VMID = vm.TargetVMID
			}
			// A usable MAC is carried in PVE's spelling (upper-case, colons),
			// the one the request, the report and the guest profile all take.
			// One that is not usable stays as written, for validation to name.
			if canonical, err := macaddr.Canonical(vm.MAC); err == nil {
				vm.MAC = canonical
			}
			// A VM that names no PBS storage restores from this run's one
			// endpoint, and each part of its source it leaves out gets its
			// default on its own. A snapshot pin or disk the plan does give is
			// never replaced: testing another snapshot than the one the plan
			// pins would be a false pass.
			if vm.SourcePBS.StorageID == "" && (vm.SourceVMID > 0 || (p.Storage.PBSRepository != "" && vm.VMID > 0)) {
				vm.SourcePBS.StorageID = "pbs"
				if vm.SourcePBS.Snapshot == "" {
					group := vm.SourceVMID
					if group <= 0 {
						group = vm.VMID
					}
					vm.SourcePBS.Snapshot = fmt.Sprintf("vm/%d/latest", group)
				}
				if !p.UseBackupConfig && vm.SourcePBS.Drive == "" && len(vm.SourcePBS.Drives) == 0 {
					vm.SourcePBS.Drive = "drive-scsi0"
				}
			}
			if vm.SourcePBS.Namespace == "" && p.Storage.PBSNamespace != "" {
				vm.SourcePBS.Namespace = p.Storage.PBSNamespace
			}
			if len(vm.SourcePBS.Drives) == 0 && vm.SourcePBS.Drive != "" {
				vm.SourcePBS.Drives = []SourceDrive{{Slot: legacyDriveSlot(vm.SourcePBS.Drive), Archive: vm.SourcePBS.Drive}}
			}
			if vm.SourcePBS.Drive == "" {
				for _, drive := range vm.SourcePBS.Drives {
					if drive.Slot == "scsi0" {
						vm.SourcePBS.Drive = drive.Archive
						break
					}
				}
			}

			for k := range vm.Probes {
				pr := &vm.Probes[k]
				timeoutPath := fmt.Sprintf("%s.probes[%d].timeout_sec", vmPath, k)
				*pr = canonicalProbe(*pr)

				if pr.TLSSkipVerify {
					pr.InsecureSkipVerify = true
				}
				if pr.Type == "dns" && pr.Transport == "" {
					pr.Transport = "udp"
				}
				if pr.Description == "" {
					pr.Description = fmt.Sprintf("%s verification probe", pr.Type)
				}
				// Only a timeout the plan leaves out gets the default; one it
				// gives as zero or negative is refused by validation, not
				// quietly turned into ten seconds.
				if !p.given(timeoutPath, pr.TimeoutSec != 0) {
					pr.TimeoutSec = 10
				}
				if pr.Type == "http" && pr.URL != "" {
					// A url that does not stand for exactly one request, or that
					// disagrees with a target_ip, port, path or tls the probe also
					// gives, stays unexpanded, and validation reports why.
					if expanded, err := expandHTTPProbeURL(*pr); err == nil {
						*pr = expanded
					}
				}
			}
		}
	}
}

// SignKeyPathNote is the one line validate and plan print for a plan that sets
// compliance.sign_key_path, and "" for a plan that leaves it out or blank. The
// field is accepted so that a plan stays portable between the editions, and the
// Community Edition does not read it: it writes its reports unsigned. The note
// does not repeat the path, which is not looked at.
func SignKeyPathNote(p *Plan) string {
	if p == nil || strings.TrimSpace(p.Compliance.SignKeyPath) == "" {
		return ""
	}
	return "compliance.sign_key_path is set, but the Community Edition writes its reports unsigned and does not read it; the Enterprise Edition uses it to sign."
}

// Validate checks all schema constraints on a parsed Plan. compliance.sign_key_path
// is not among them: the Community Edition writes its reports unsigned, so the
// field is optional, accepted as written and never read (see SignKeyPathNote).
func Validate(p *Plan) []ValidationError {
	return validate(p)
}

// ValidateForWorker checks the constraints that apply on a node worker. They
// are the controller's: the worker's plan only lacks the controller's own
// settings (MarshalWorkerPlan leaves compliance.sign_key_path out of it).
func ValidateForWorker(p *Plan) []ValidationError {
	return validate(p)
}

func validate(p *Plan) []ValidationError {
	var errors []ValidationError

	// 1. version must equal "v1" or "certistack/v1"
	if p.Version != "v1" && p.Version != "certistack/v1" {
		errors = append(errors, ValidationError{Field: "version", Message: "must equal 'v1' or 'certistack/v1'"})
	}
	// 2. plan_id must match regex ^[a-zA-Z0-9_-]{1,128}$ and not be empty (the evidence hub keeps no report with a longer one)
	if p.PlanID == "" {
		errors = append(errors, ValidationError{Field: "plan_id", Message: "must not be empty"})
	} else if !planIDRegex.MatchString(p.PlanID) {
		errors = append(errors, ValidationError{Field: "plan_id", Message: "must match regex ^[a-zA-Z0-9_-]{1,128}$ (letters, digits, _ and -, at most 128 characters)"})
	}
	// 3. name must not be empty
	if p.Name == "" {
		errors = append(errors, ValidationError{Field: "name", Message: "must not be empty"})
	}
	// 4-5. compliance.frameworks and compliance.retention_days: both are
	// signed into every report, and both are required.
	errors = append(errors, ComplianceErrors(p)...)
	// 6-9. The admission limits, the RTO target and every duration.
	errors = append(errors, NumericBoundsErrors(p)...)
	errors = append(errors, aliasConflictErrors(p)...)
	errors = append(errors, textControlErrors(p)...)
	errors = append(errors, sandboxIsSourceErrors(p)...)
	if n := p.AdmissionControl.MaxConcurrentBoots; n < 0 || n > 64 {
		errors = append(errors, ValidationError{Field: "admission_control.max_concurrent_boots", Message: "must be between 0 (unlimited) and 64"})
	}
	if s := p.AdmissionControl.BootSettleSec; s < 0 || s > 3600 {
		errors = append(errors, ValidationError{Field: "admission_control.boot_settle_sec", Message: "must be between 0 (the default, 180) and 3600"})
	} else if s > 0 && p.AdmissionControl.MaxConcurrentBoots == 0 {
		errors = append(errors, ValidationError{Field: "admission_control.boot_settle_sec", Message: "has no effect without admission_control.max_concurrent_boots"})
	}
	// 10. network.mode
	if p.Network.Mode != "simple" && p.Network.Mode != "vxlan" {
		errors = append(errors, ValidationError{Field: "network.mode", Message: "must be 'simple' or 'vxlan'"})
	}
	if lifecycle := p.Network.EffectiveLifecycle(); lifecycle != "ephemeral" && lifecycle != "preprovisioned" {
		errors = append(errors, ValidationError{Field: "network.lifecycle", Message: "must be 'ephemeral' or 'preprovisioned'"})
	}
	// 11. network.zone_id
	if p.Network.ZoneID == "" {
		errors = append(errors, ValidationError{Field: "network.zone_id", Message: "must not be empty"})
	} else if !pveSDNIDRegex.MatchString(p.Network.ZoneID) {
		errors = append(errors, ValidationError{Field: "network.zone_id", Message: "must be a Proxmox SDN identifier: start with a letter and use only letters and digits"})
	} else if len(p.Network.ZoneID) > maxPVESDNIDLength {
		errors = append(errors, ValidationError{Field: "network.zone_id", Message: fmt.Sprintf("must be at most %d characters (Proxmox SDN limit)", maxPVESDNIDLength)})
	}
	if dir := strings.TrimSpace(p.Storage.ScratchDir); dir != "" {
		if problem := ScratchDirProblem(dir); problem != "" {
			errors = append(errors, ValidationError{Field: "storage.scratch_dir", Message: problem})
		}
	}
	if id := p.Storage.OverlayStorage; id != "" && !ValidPVEStorageID(id) {
		errors = append(errors, ValidationError{Field: "storage.overlay_storage", Message: "must be a Proxmox storage ID (lowercase letters, digits, '-', '_', '.'; starting with a letter)"})
	}
	if n := p.Storage.MaxCopyGiB; n < 0 || n > 1<<20 {
		errors = append(errors, ValidationError{Field: "storage.max_copy_gib", Message: "must be between 0 (no cap) and 1048576"})
	}
	// 12. network.vnet_id
	if p.Network.VNetID == "" {
		errors = append(errors, ValidationError{Field: "network.vnet_id", Message: "must not be empty"})
	} else if !pveSDNIDRegex.MatchString(p.Network.VNetID) {
		errors = append(errors, ValidationError{Field: "network.vnet_id", Message: "must be a Proxmox SDN identifier: start with a letter and use only letters and digits"})
	} else if len(p.Network.VNetID) > maxPVESDNIDLength {
		errors = append(errors, ValidationError{Field: "network.vnet_id", Message: fmt.Sprintf("must be at most %d characters (Proxmox SDN limit)", maxPVESDNIDLength)})
	} else if p.Network.EffectiveLifecycle() == "ephemeral" && strings.EqualFold(p.Network.VNetID, p.Network.ZoneID) {
		// PVE accepts a zone and a VNet with one id, but CertiStack keeps the
		// ids it has seen in a single set, so it could not tell its own zone
		// from the VNet and would read one as a clash with the other. That is the
		// zone and VNet a run creates: a pre-provisioned sandbox names a zone and
		// VNet that already exist, whose ids the plan has to carry as they are, and
		// the run only validates them (review R2-02).
		errors = append(errors, ValidationError{Field: "network.vnet_id", Message: "must differ from network.zone_id (Proxmox allows the same id for both, but CertiStack tracks zone and VNet ids in one set); for example zone_id csZone01 and vnet_id csVnet01"})
	}
	// 13. network.tag
	if p.Network.Tag < 0 {
		errors = append(errors, ValidationError{Field: "network.tag", Message: "must be >= 0"})
	}
	if p.Network.Mode == "vxlan" {
		if p.Network.Tag <= 0 {
			errors = append(errors, ValidationError{Field: "network.tag", Message: "must be explicitly set to a positive VXLAN VNI"})
		} else if p.Network.Tag > MaxVXLANVNI {
			errors = append(errors, ValidationError{Field: "network.tag", Message: fmt.Sprintf("must be <= %d for vxlan mode", MaxVXLANVNI)})
		}
		if _, err := p.Network.VXLANPeerAddresses(); err != nil {
			errors = append(errors, ValidationError{Field: "network.peers", Message: err.Error()})
		}
	} else {
		if strings.TrimSpace(p.Network.Peers) != "" {
			errors = append(errors, ValidationError{Field: "network.peers", Message: "is only valid for vxlan mode"})
		}
		// A simple zone's VNet has no tag: CertiStack sends none, and a plan
		// that set one would read as a VLAN or VNI the network never had.
		if p.Network.Mode == "simple" && p.Network.Tag > 0 {
			errors = append(errors, ValidationError{Field: "network.tag", Message: "is only valid for vxlan mode (a simple network's VNet carries no tag, so a tag set here would never reach PVE)"})
		}
	}
	// 14. network.ip_range
	// ParseSandboxRange is the one reader of the range (the node-side overlap
	// check and the engine call it too): a spelling it refuses never reaches PVE
	// or `ip addr add`, and a range it accepts is the one network all of them see.
	var isolatedNetwork *net.IPNet
	// rangeRefused is set when the range was refused: nothing else the plan says
	// about addresses can be judged against it, and the range is the cause.
	rangeRefused := false
	if sandboxRange, err := ParseSandboxRange(p.Network.IPRange); err != nil {
		errors = append(errors, ValidationError{Field: "network.ip_range", Message: err.Error()})
		rangeRefused = true
	} else {
		isolatedNetwork = ipNet(sandboxRange)
		if hostLocal := overlappingHostLocalNetwork(isolatedNetwork); hostLocal != "" {
			// The worker host itself answers loopback and similar addresses, so a
			// wire probe to one would pass with no restored guest present.
			errors = append(errors, ValidationError{Field: "network.ip_range", Message: "must not overlap host-local or non-unicast address space " + hostLocal})
			isolatedNetwork = nil
		}
	}
	if p.Network.Mode == "vxlan" && isolatedNetwork != nil {
		// A peer is a real address of another cluster node. With the probe
		// address on the sandbox bridge the node routes the whole range into the
		// sandbox, so the zone's tunnel to a peer inside it would run into the
		// sandbox instead of the cluster network.
		if peers, err := p.Network.VXLANPeerAddresses(); err == nil {
			for _, peer := range peers {
				if ip := net.ParseIP(peer); ip != nil && isolatedNetwork.Contains(ip) {
					message := fmt.Sprintf("%s lies inside network.ip_range %s: once the probe address is on the sandbox bridge, the tunnel to that peer would run into the sandbox instead of the cluster network; choose a range that holds no peer", peer, isolatedNetwork)
					if suggestion := SuggestedDocumentationRange(p.Network.IPRange, peers); suggestion != "" {
						message += ", for example " + suggestion
					}
					errors = append(errors, ValidationError{Field: "network.peers", Message: message})
				}
			}
		}
	}
	probeIP := net.ParseIP(p.Network.ProbeIP)
	if probeIP == nil {
		errors = append(errors, ValidationError{Field: "network.probe_ip", Message: "must be a valid IP address within network.ip_range"})
	} else if problem := ipv4OnlyProblem(p.Network.ProbeIP); problem != "" && !rangeRefused {
		errors = append(errors, ValidationError{Field: "network.probe_ip", Message: problem})
	} else if isolatedNetwork != nil && !isolatedNetwork.Contains(probeIP) {
		errors = append(errors, ValidationError{Field: "network.probe_ip", Message: "must be within network.ip_range"})
	} else if isolatedNetwork != nil && isSubnetReservedAddress(probeIP, isolatedNetwork) {
		errors = append(errors, ValidationError{Field: "network.probe_ip", Message: "must not be the subnet network or broadcast address"})
	}
	if p.Network.Gateway != "" && net.ParseIP(p.Network.Gateway) == nil {
		errors = append(errors, ValidationError{Field: "network.gateway", Message: "must be a valid IP address"})
	}
	// CertiStack sandboxes are intentionally air-gapped.  A gateway would turn
	// an otherwise isolated VNet into a routed network, so it is never a valid
	// plan setting (even when the address itself is syntactically valid).
	if p.Network.Gateway != "" {
		errors = append(errors, ValidationError{Field: "network.gateway", Message: "must be empty; sandbox networks cannot define a gateway"})
	}
	// network.ipam and network.mtu are accepted by the plan schema but have no
	// implementation anywhere in the engine: the SDN VNet is always created
	// with the platform default MTU and no IPAM plugin. Silently ignoring
	// them would let an operator believe a jumbo-frame or IPAM requirement
	// was honored when it was not, so reject them explicitly instead.
	if p.Network.IPAM != "" {
		errors = append(errors, ValidationError{Field: "network.ipam", Message: "is not implemented; must be empty"})
	}
	if p.Network.MTU != 0 {
		errors = append(errors, ValidationError{Field: "network.mtu", Message: "is not implemented; must be unset"})
	}
	// 15. tiers must contain at least 1 tier
	if len(p.Tiers) == 0 {
		errors = append(errors, ValidationError{Field: "tiers", Message: "must contain at least 1 tier"})
	}

	seenVMIDs := make(map[int]bool)
	var planNamespace string
	seenTierLevels := make(map[int]bool)
	seenSandboxIPs := make(map[string]int)

	for i, tier := range p.Tiers {
		prefix := fmt.Sprintf("tiers[%d]", i)
		// 16. Each tier level must be >= 1
		if tier.Level < 1 {
			errors = append(errors, ValidationError{Field: prefix + ".level", Message: "must be >= 1"})
		}
		if seenTierLevels[tier.Level] {
			errors = append(errors, ValidationError{Field: prefix + ".level", Message: "must be unique across the plan"})
		}
		seenTierLevels[tier.Level] = true
		// 17. Each tier must have at least 1 VM
		if len(tier.VMs) == 0 {
			errors = append(errors, ValidationError{Field: prefix + ".vms", Message: "must contain at least 1 VM"})
		}
		// 18. Each tier name must not be empty
		if tier.Name == "" {
			errors = append(errors, ValidationError{Field: prefix + ".name", Message: "must not be empty"})
		}

		for j, vm := range tier.VMs {
			vmPrefix := fmt.Sprintf("%s.vms[%d]", prefix, j)
			// 19. VMIDs must be unique across the ENTIRE plan
			if seenVMIDs[vm.VMID] {
				errors = append(errors, ValidationError{Field: vmPrefix + ".vmid", Message: "must be unique across the entire plan"})
			}
			seenVMIDs[vm.VMID] = true

			// 20. Each VM name must not be empty, and must be a name PVE
			// accepts, so a bad one is refused here and not when the run
			// creates the VM.
			if vm.Name == "" {
				errors = append(errors, ValidationError{Field: vmPrefix + ".name", Message: "must not be empty"})
			} else if !pveVMNameRegex.MatchString(vm.Name) {
				errors = append(errors, ValidationError{Field: vmPrefix + ".name", Message: "must be a DNS name of at most 63 characters (letters, digits, '-' and '.', starting and ending with a letter or digit), which Proxmox VE requires"})
			}
			// 21. Each VM's IDs and hardware overrides are checked by
			// NumericBoundsErrors: vmid must be a Proxmox VM ID, the range
			// init allocates sandbox IDs from.
			// The disposable restore must never be registered under the ID of
			// the VM it was backed up from; the runtime occupancy guard would
			// refuse it anyway, but only after contacting PVE and PBS.
			if vm.SourceVMID > 0 && vm.VMID == vm.SourceVMID {
				errors = append(errors, ValidationError{Field: vmPrefix + ".vmid", Message: "must differ from source_vmid"})
			}
			// A run maps every disk through one configured PBS endpoint and
			// namespace (runner.validatePBSRouting); reject other selectors
			// here instead of after the worker has started.
			if id := strings.TrimSpace(vm.SourcePBS.StorageID); id != "" && id != "pbs" {
				errors = append(errors, ValidationError{Field: vmPrefix + ".source_pbs.storage_id", Message: "must be pbs; a run restores from its one configured PBS endpoint"})
			}
			if ns := strings.TrimSpace(vm.SourcePBS.Namespace); ns != "" {
				if planNamespace == "" {
					planNamespace = ns
				} else if ns != planNamespace {
					errors = append(errors, ValidationError{Field: vmPrefix + ".source_pbs.namespace", Message: fmt.Sprintf("must match the plan's other PBS namespace %q; one run reads one namespace", planNamespace)})
				}
			}
			// 22. source_pbs must be defined unless global storage is configured
			if vm.SourcePBS.StorageID == "" && p.Storage.PBSRepository == "" {
				errors = append(errors, ValidationError{Field: vmPrefix + ".source_pbs.storage_id", Message: "must not be empty"})
			}
			if vm.SourcePBS.Snapshot == "" && p.Storage.PBSRepository == "" {
				errors = append(errors, ValidationError{Field: vmPrefix + ".source_pbs.snapshot", Message: "must not be empty"})
			}
			drives := vm.SourcePBS.RestoreDrives()
			if len(drives) == 0 && !p.UseBackupConfig && p.Storage.PBSRepository == "" {
				errors = append(errors, ValidationError{Field: vmPrefix + ".source_pbs.drives", Message: "must define at least one backed-up disk"})
			}
			seenSlots := make(map[string]bool)
			seenArchives := make(map[string]bool)
			for driveIndex, drive := range drives {
				drivePrefix := fmt.Sprintf("%s.source_pbs.drives[%d]", vmPrefix, driveIndex)
				if !diskslot.Valid(drive.Slot) {
					errors = append(errors, ValidationError{Field: drivePrefix + ".slot", Message: "must be a PVE disk slot: " + diskslot.Describe})
				}
				if seenSlots[drive.Slot] {
					errors = append(errors, ValidationError{Field: drivePrefix + ".slot", Message: "must be unique within the VM"})
				}
				seenSlots[drive.Slot] = true
				if !archiveNameRegex.MatchString(drive.Archive) {
					errors = append(errors, ValidationError{Field: drivePrefix + ".archive", Message: "must be a PBS archive filename without path separators"})
				}
				// The report's disk evidence is per slot, so each archive must
				// go to the slot it was backed up from, and only once.
				archiveKey := drive.Archive
				if archiveSlot, ok := diskslot.ArchiveSlot(drive.Archive); ok {
					archiveKey = archiveSlot
					if archiveSlot != drive.Slot {
						errors = append(errors, ValidationError{Field: drivePrefix + ".archive", Message: fmt.Sprintf("holds the %s disk; it must be restored to slot %s", archiveSlot, archiveSlot)})
					}
				}
				if seenArchives[archiveKey] {
					errors = append(errors, ValidationError{Field: drivePrefix + ".archive", Message: "restores an archive another drive already restores"})
				}
				seenArchives[archiveKey] = true
			}
			if vm.SourcePBS.Snapshot == "latest" && vm.SourceVMID <= 0 {
				errors = append(errors, ValidationError{Field: vmPrefix + ".source_vmid", Message: "must be set when source_pbs.snapshot is latest"})
			}
			if vm.SourcePBS.Snapshot != "" && !validPBSSnapshotSelector(vm.SourcePBS.Snapshot) {
				message := "must be latest, vm/<positive VMID>/latest, or vm/<positive VMID>/<RFC3339 timestamp>"
				if strings.HasPrefix(vm.SourcePBS.Snapshot, "ct/") {
					group := strings.Join(strings.SplitN(vm.SourcePBS.Snapshot, "/", 3)[:2], "/")
					message = fmt.Sprintf("is a container backup (%s): containers are not supported, CertiStack restore-tests VMs only; it %s", group, message)
				}
				errors = append(errors, ValidationError{Field: vmPrefix + ".source_pbs.snapshot", Message: message})
			}
			// The report names the protected VM by source_vmid. A snapshot of
			// another VM's backup group would credit that VM's recovery to it.
			if group, ok := snapshotGroupVMID(vm.SourcePBS.Snapshot); ok && vm.SourceVMID > 0 && group != vm.SourceVMID {
				errors = append(errors, ValidationError{Field: vmPrefix + ".source_pbs.snapshot", Message: fmt.Sprintf("is a backup of VM %d, but source_vmid is %d; both must name the protected VM", group, vm.SourceVMID)})
			}
			// The legacy drive restores nothing beside drives: a disk it names
			// that drives does not list would be silently left out.
			if drive := vm.SourcePBS.Drive; drive != "" && len(vm.SourcePBS.Drives) > 0 && !drivesInclude(vm.SourcePBS.Drives, drive) {
				errors = append(errors, ValidationError{Field: vmPrefix + ".source_pbs.drive", Message: "names an archive that source_pbs.drives does not restore; list every disk in drives and leave drive out"})
			}
			switch vm.CopyBeforeBoot {
			case "", CopyBeforeBootAuto, CopyBeforeBootAlways, CopyBeforeBootNever:
			default:
				errors = append(errors, ValidationError{Field: vmPrefix + ".copy_before_boot", Message: "must be auto, always or never"})
			}
			if vm.NICModel != "" && !validNICModel(vm.NICModel) {
				errors = append(errors, ValidationError{Field: vmPrefix + ".nic_model", Message: "must be a supported PVE network model"})
			}
			// machine, ostype, bios and scsihw go to PVE as written: hold them to
			// PVE's values here, not when the run creates the VM.
			errors = append(errors, vmHardwareValueErrors(vmPrefix, vm)...)
			// The MAC is checked with the plan's other NICs after the loops
			// (nicIdentityErrors): each must be usable, and none may repeat.
			mode := vm.NetworkRecovery.EffectiveMode()
			switch mode {
			case "auto", "preserve", "ifcfg", "networkmanager", "netplan", "systemd-networkd", "ifupdown":
			default:
				errors = append(errors, ValidationError{Field: vmPrefix + ".network_recovery.mode", Message: "must be auto, preserve, ifcfg, networkmanager, netplan, systemd-networkd, or ifupdown"})
			}
			if mode == "preserve" && vm.NetworkRecovery.SandboxIP != "" {
				errors = append(errors, ValidationError{Field: vmPrefix + ".network_recovery.sandbox_ip", Message: "must be omitted when network_recovery.mode is preserve"})
			}
			// One rule with the guest-network adapter, which writes the name.
			if vm.NetworkRecovery.InterfaceName != "" && !ifname.Valid(vm.NetworkRecovery.InterfaceName) {
				errors = append(errors, ValidationError{Field: vmPrefix + ".network_recovery.interface_name", Message: "must be a valid Linux interface name: " + ifname.Describe})
			}
			if mode != "preserve" {
				address, configured, addressErr := vm.SandboxAddress(p.Network)
				if addressErr != nil {
					// The IPv6 range is already named, once, as the cause.
					if !rangeRefused {
						errors = append(errors, ValidationError{Field: vmPrefix + ".network_recovery", Message: addressErr.Error()})
					}
				} else if configured {
					if prior, exists := seenSandboxIPs[address]; exists {
						errors = append(errors, ValidationError{Field: vmPrefix + ".network_recovery.sandbox_ip", Message: fmt.Sprintf("must be unique; VM %d also uses %s", prior, address)})
					} else {
						seenSandboxIPs[address] = vm.VMID
					}
					// The other NICs' addresses must not answer for another VM.
					for _, extra := range vm.AdditionalProbeAddresses(p.Network) {
						if prior, exists := seenSandboxIPs[extra]; exists {
							errors = append(errors, ValidationError{Field: vmPrefix + ".probes", Message: fmt.Sprintf("target %s is also VM %d's address; every guest address in the sandbox must be unique", extra, prior)})
						} else {
							seenSandboxIPs[extra] = vm.VMID
						}
					}
				}
			}

			// Every wire-probe target belongs to exactly one VM, whatever its
			// network recovery mode. A preserve-mode VM keeps its guest's own
			// addresses, so no sandbox_ip claims them above; without this a
			// probe of one VM could name another VM's address, and the other
			// VM's service would answer it and credit the pass to the wrong
			// VM. Earlier tiers stay up until teardown, so
			// this holds across tiers as well as within one.
			for k, probe := range vm.Probes {
				if !isWireProbe(probe.Type) {
					continue
				}
				target, ok := wireTargetKey(probe.TargetIP)
				if !ok {
					continue // reported below as a malformed target
				}
				if prior, exists := seenSandboxIPs[target]; exists && prior != vm.VMID {
					errors = append(errors, ValidationError{Field: fmt.Sprintf("%s.probes[%d].target_ip", vmPrefix, k), Message: fmt.Sprintf("%s is also VM %d's address; every wire-probe target must belong to exactly one VM, or a pass could be credited to the wrong VM", target, prior)})
				} else if !exists {
					seenSandboxIPs[target] = vm.VMID
				}
			}

			// 23. Fail-closed: Each VM MUST define at least one probe, and one
			// that is sure to assert something in the guest.
			if len(vm.Probes) == 0 {
				errors = append(errors, ValidationError{Field: vmPrefix + ".probes", Message: "must define at least 1 probe"})
			} else if problem := guestAssertionProblem(vm.Probes); problem != "" {
				errors = append(errors, ValidationError{Field: vmPrefix + ".probes", Message: problem})
			}

			for k, given := range vm.Probes {
				probePrefix := fmt.Sprintf("%s.probes[%d]", vmPrefix, k)
				// Every check below is the canonical type's, whether or not the
				// caller ran Normalize: a direct Validate must not hold qga_ping
				// to less than qga.
				probe := canonicalProbe(given)
				// 24. Probe type
				if !validProbeType(given.Type) {
					errors = append(errors, ValidationError{Field: probePrefix + ".type", Message: "must be one of: tcp, http, qga, qmp, screendump, dns, ldap, mssql, smb"})
				}
				if probe.Retries < 0 || probe.Retries > 10 {
					errors = append(errors, ValidationError{Field: probePrefix + ".retries", Message: "must be between 0 and 10 (zero uses automatic retry until timeout)"})
				}
				if probe.Description == "" {
					errors = append(errors, ValidationError{Field: probePrefix + ".description", Message: "must not be empty"})
				}
				// A field the type does not read is refused, not ignored: the plan
				// would look stricter than the check the run makes.
				errors = append(errors, unusedProbeFieldErrors(probePrefix, probe)...)
				// Normalize leaves an http url it cannot expand exactly in place,
				// or one that disagrees with the probe's own target_ip, port, path
				// or tls. Report why, instead of the fields the url would have
				// supplied.
				var urlProblem error
				if probe.Type == "http" && probe.URL != "" {
					_, urlProblem = expandHTTPProbeURL(probe)
				}
				if urlProblem != nil {
					errors = append(errors, ValidationError{Field: probePrefix + ".url", Message: urlProblem.Error()})
				}
				if probe.Type == "tcp" || probe.Type == "http" {
					if probe.TargetIP == "" && urlProblem == nil {
						errors = append(errors, ValidationError{Field: probePrefix + ".target_ip", Message: "must be set for tcp and http probes"})
					}
				}
				// Wire probes must target an address on the isolated VNet. This
				// prevents a plan from accidentally testing a PVE management or
				// production service from the host network namespace.
				if isolatedNetwork != nil && isWireProbe(probe.Type) && probe.TargetIP != "" {
					target := net.ParseIP(probe.TargetIP)
					if target == nil {
						errors = append(errors, ValidationError{Field: probePrefix + ".target_ip", Message: "must be a literal IP address in network.ip_range for isolated probes"})
					} else if problem := ipv4OnlyProblem(probe.TargetIP); problem != "" {
						errors = append(errors, ValidationError{Field: probePrefix + ".target_ip", Message: problem})
					} else if !isolatedNetwork.Contains(target) {
						errors = append(errors, ValidationError{Field: probePrefix + ".target_ip", Message: "must be within network.ip_range for isolated probes"})
					} else if probeIP != nil && target.Equal(probeIP) {
						errors = append(errors, ValidationError{Field: probePrefix + ".target_ip", Message: "must not equal network.probe_ip"})
					} else if isSubnetReservedAddress(target, isolatedNetwork) {
						errors = append(errors, ValidationError{Field: probePrefix + ".target_ip", Message: "must not be the subnet network or broadcast address"})
					}
				}
				// Every wire probe names a TCP or UDP port, which is 1 to 65535.
				// A port outside that range only fails once the run is under way.
				portError := func(unset string) {
					switch {
					case probe.Port == 0:
						errors = append(errors, ValidationError{Field: probePrefix + ".port", Message: unset})
					case probe.Port < 0 || probe.Port > maxProbePort:
						errors = append(errors, ValidationError{Field: probePrefix + ".port", Message: fmt.Sprintf("must be between 1 and %d, the range of TCP and UDP ports", maxProbePort)})
					}
				}
				if probe.Type == "tcp" {
					portError("must be set for tcp probes")
				}
				if probe.Type == "http" {
					if probe.Port != 0 || urlProblem == nil {
						portError("must be set for http probes (or use url)")
					}
					// HTTP status codes are 100 to 599 (RFC 9110 section 15). The
					// probe sends one GET, and Go's client consumes 1xx interim
					// answers and waits for the final one, so a 1xx status is
					// never what the probe sees and cannot be asserted.
					switch status := probe.ExpectedStatus; {
					case status == 0:
						errors = append(errors, ValidationError{Field: probePrefix + ".expected_status", Message: "must be set for http probes to an HTTP status code from 200 to 599, for example 200"})
					case status < 200 || status > 599:
						errors = append(errors, ValidationError{Field: probePrefix + ".expected_status", Message: fmt.Sprintf("must be an HTTP status code from 200 to 599, not %d: HTTP has no status above 599, and a 1xx status is never the final answer to the GET this probe sends", status)})
					}
					if problem := httptarget.Problem(httpProbePath(probe.Path)); problem != "" {
						errors = append(errors, ValidationError{Field: probePrefix + ".path", Message: problem})
					}
				}
				// A certificate-check bypass is refused on every probe type, not only
				// on the one that would read it: no probe may carry one.
				if probe.InsecureSkipVerify || probe.TLSSkipVerify {
					errors = append(errors, ValidationError{Field: probePrefix + ".insecure_skip_verify", Message: "TLS certificate verification bypass is not permitted"})
				}
				if probe.Type == "dns" {
					if probe.TargetIP == "" {
						errors = append(errors, ValidationError{Field: probePrefix + ".target_ip", Message: "must be set for dns probes"})
					}
					portError("must be set for dns probes")
					if probe.Transport != "" && probe.Transport != "udp" && probe.Transport != "tcp" {
						errors = append(errors, ValidationError{Field: probePrefix + ".transport", Message: "must be udp or tcp"})
					}
					// The name the probe asks for: domain, else path (as the
					// run reads them). One a DNS query cannot carry would fail
					// the probe only after the VM had booted.
					nameField, name := "domain", probe.Domain
					if name == "" {
						nameField, name = "path", probe.Path
					}
					if problem := DNSQueryNameProblem(name); problem != "" {
						errors = append(errors, ValidationError{Field: probePrefix + "." + nameField, Message: problem})
					}
					switch strings.ToLower(probe.RecordType) {
					case "", "a":
					case "srv":
						if strings.TrimSpace(probe.Domain) == "" && strings.TrimSpace(probe.Path) == "" {
							errors = append(errors, ValidationError{Field: probePrefix + ".domain", Message: "must be set for an srv record check"})
						}
					default:
						errors = append(errors, ValidationError{Field: probePrefix + ".record_type", Message: "must be a or srv"})
					}
				}
				if probe.Type == "ldap" {
					if probe.TargetIP == "" {
						errors = append(errors, ValidationError{Field: probePrefix + ".target_ip", Message: "must be set for ldap probes"})
					}
					portError("must be set for ldap probes")
					// base_dn is "auto" (discover a naming context from the Root DSE)
					// or a distinguished name. Both DNs are sent to the server, so a
					// string that is not a DN fails here rather than mid-run.
					if baseDN := strings.TrimSpace(probe.BaseDN); baseDN != "" && !strings.EqualFold(baseDN, "auto") {
						if problem := ldapDNProblem(baseDN); problem != "" {
							errors = append(errors, ValidationError{Field: probePrefix + ".base_dn", Message: `must be "auto" or a distinguished name such as DC=example,DC=com` + problem})
						}
					} else if probe.BaseDN != "" && baseDN == "" {
						errors = append(errors, ValidationError{Field: probePrefix + ".base_dn", Message: `must be "auto" or a distinguished name such as DC=example,DC=com, not only spaces`})
					}
					if probe.NamingContext != "" {
						if probe.BaseDN != "" {
							errors = append(errors, ValidationError{Field: probePrefix + ".naming_context", Message: "cannot be combined with base_dn; choose a Root DSE assertion or a base-object search"})
						}
						if problem := ldapDNProblem(probe.NamingContext); problem != "" {
							errors = append(errors, ValidationError{Field: probePrefix + ".naming_context", Message: "must be a distinguished name such as DC=example,DC=com" + problem})
						}
					}
				}
				// An http probe asserts the virtual host it names, and an mssql probe
				// verifies the certificate for it: both use it as the TLS SNI.
				if (probe.Type == "http" || probe.Type == "mssql") && probe.ServerName != "" && !validServerName(probe.ServerName) {
					errors = append(errors, ValidationError{Field: probePrefix + ".server_name", Message: "must be a valid DNS hostname for TLS SNI"})
				}
				if probe.Type == "mssql" || probe.Type == "smb" {
					if probe.TargetIP == "" {
						errors = append(errors, ValidationError{Field: probePrefix + ".target_ip", Message: "must be set for " + probe.Type + " probes"})
					}
					portError("must be set for " + probe.Type + " probes")
				}
				if problem := qgaCommandProblem(probe); problem != "" {
					errors = append(errors, ValidationError{Field: probePrefix + ".command", Message: problem})
				}
				// A ping answers with an empty object, so there is no
				// output for expected_output to match. Accepting one would
				// pass a plan that asks for evidence the probe cannot give.
				if isQGAPing(probe) && probe.ExpectedOutput != "" {
					errors = append(errors, ValidationError{Field: probePrefix + ".expected_output", Message: "a QGA ping has no output to match: it passes when the guest agent answers, so this could never be checked; remove expected_output, or check the guest with hostname, 'systemctl is-active <service>', or 'sc query <service>'"})
				}
			}
		}
	}

	// Every VM sits on the one isolated VNet, so a MAC may name only one NIC of
	// the whole plan, and must be one a NIC can hold.
	errors = append(errors, nicIdentityErrors(p)...)

	if len(errors) > 0 {
		return errors
	}
	return nil
}

// IsGuestLevelProbe reports whether a probe of this type, when it runs and
// passes, asserts something about the guest: a wire probe from the worker to
// a service in it, or a guest-agent probe inside it. A qmp probe (QEMU says
// the VM is running) and a screendump (a framebuffer was captured) say
// nothing about what the guest did: a guest in a boot loop, at a "No
// bootable device" screen or at a kernel panic passes both. They are
// supporting evidence, and a VM is verified only by a guest-level assertion.
// The evidence verdict (cmd/certistack) applies the same rule to a signed
// report.
func IsGuestLevelProbe(probeType string) bool {
	switch strings.ToLower(strings.TrimSpace(probeType)) {
	case "qga", "qga_ping":
		return true
	}
	return isWireProbe(probeType)
}

// isHypervisorProbe is a probe type that observes only the hypervisor's view.
func isHypervisorProbe(probeType string) bool {
	switch strings.ToLower(strings.TrimSpace(probeType)) {
	case "qmp", "qmp_status", "screendump":
		return true
	}
	return false
}

// isQGAPing reports whether a probe is the guest agent's ping: a qga probe
// with the ping command, or the qga_ping alias, which defaults to it.
func isQGAPing(p Probe) bool {
	command := strings.TrimSpace(p.Command)
	switch strings.ToLower(strings.TrimSpace(p.Type)) {
	case "qga":
		return command == "ping" || command == "guest-ping"
	case "qga_ping":
		return command == "" || command == "ping" || command == "guest-ping"
	}
	return false
}

// guestAssertionProblem is why none of a VM's probes is sure to assert
// something in the guest, or "" when one is: a wire probe, or a guest-agent
// probe with require_qga. An optional guest-agent probe is skipped when the
// agent does not answer, and qmp and screendump probes never assert
// anything in the guest, so a VM whose probes are only those could
// be marked verified with nothing checked in the guest. A probe of an
// unknown type is reported on its own, not here.
func guestAssertionProblem(probes []Probe) string {
	hypervisorOnly, optionalQGA := true, true
	for _, probe := range probes {
		kind := strings.ToLower(strings.TrimSpace(probe.Type))
		switch {
		case isWireProbe(kind):
			return ""
		case kind == "qga" || kind == "qga_ping":
			if probe.RequireQGA {
				return ""
			}
			hypervisorOnly = false
		case isHypervisorProbe(kind):
			optionalQGA = false
		default:
			return ""
		}
	}
	switch {
	case hypervisorOnly:
		return "every probe is a hypervisor-level probe (qmp or screendump), which shows only that QEMU runs the VM: a guest that never booted, or that stopped at a boot failure, passes them, so a run could not verify the VM; add a probe that asserts something in the guest (a tcp, http, dns, ldap, mssql or smb probe on its address, or a qga probe with require_qga: true)"
	case optionalQGA:
		return "every probe is an optional QGA probe, which is skipped when the guest agent does not answer, so the VM could pass with nothing checked; set require_qga: true on one, or add a probe that asserts something in the guest without the agent (tcp, http, dns, ldap, mssql, or smb)"
	default:
		return "no probe is sure to assert something in the guest: an optional QGA probe is skipped when the guest agent does not answer, and qmp and screendump probes show only that QEMU runs the VM, so the VM could pass with nothing checked in the guest; set require_qga: true on a QGA probe, or add a tcp, http, dns, ldap, mssql, or smb probe"
	}
}

// FrameworkPlaceholder is the value an earlier `certistack init` wrote where
// the operator had to choose the compliance frameworks (init now writes
// FrameworkNone, which is valid as it stands). A plan that still holds it is
// not valid.
const FrameworkPlaceholder = "CHANGE"

// FrameworkNone is the label for a report that is mapped to no compliance
// standard, for an operator who has none to name. It stands alone: a list that
// holds it and a standard says two things at once.
const FrameworkNone = "NONE"

var validFrameworks = map[string]bool{
	FrameworkNone:      true,
	"DORA":             true,
	"DORA-Article-12":  true,
	"SOC2":             true,
	"SOC2-Type2-CC7.4": true,
	"HIPAA":            true,
	"HIPAA-164.308-A7": true,
	"ISO27001":         true,
	"ISO27001-A8.13":   true,
	"ISO27001-A.12.3":  true,
	"ISO27001-A12.3":   true,
	"CIS_V8":           true,
}

// ComplianceErrors checks the compliance metadata every signed report carries.
// frameworks must name at least one standard, and retention_days must be a
// positive number of days up to a century: the report records both, and a
// report with no framework or a zero retention would leave the reader unable
// to tell an intentional choice from an omission. validate applies it, and a
// run applies it again to a plan it is handed directly, before anything is
// signed.
func ComplianceErrors(p *Plan) []ValidationError {
	var errors []ValidationError
	const frameworkList = "NONE (no standard), DORA, SOC2, HIPAA, ISO27001, CIS_V8 (or an article code such as DORA-Article-12)"
	if len(p.Compliance.Frameworks) == 0 {
		errors = append(errors, ValidationError{Field: "compliance.frameworks", Message: "must list at least one framework, one of: " + frameworkList + "; the report records which standards its evidence is mapped to (a label is not a certification), and an empty list cannot be told from an omission"})
	}
	for i, f := range p.Compliance.Frameworks {
		field := fmt.Sprintf("compliance.frameworks[%d]", i)
		switch {
		case f == FrameworkPlaceholder:
			errors = append(errors, ValidationError{Field: field, Message: FrameworkPlaceholder + " is the placeholder an earlier certistack init wrote: replace it with the frameworks this report maps to, one of: " + frameworkList})
		case f == FrameworkNone && len(p.Compliance.Frameworks) > 1:
			errors = append(errors, ValidationError{Field: field, Message: FrameworkNone + " means the report is mapped to no standard, so it cannot be listed together with others: use [" + FrameworkNone + "] alone, or name the standards"})
		case !validFrameworks[f]:
			errors = append(errors, ValidationError{Field: field, Message: "must be one of: " + frameworkList})
		}
	}
	// It is signed into every report, and evidence stores turn it into a
	// duration.
	switch days := p.Compliance.RetentionDays; {
	case days == 0:
		errors = append(errors, ValidationError{Field: "compliance.retention_days", Message: fmt.Sprintf("must be set to the number of days the report is kept, from 1 to %d (2555 is seven years); a missing key or 0 is not accepted, because the report would record no retention", maxRetentionDays)})
	case days < 0 || days > maxRetentionDays:
		errors = append(errors, ValidationError{Field: "compliance.retention_days", Message: fmt.Sprintf("must be between 1 and %d (100 years)", maxRetentionDays)})
	}
	return errors
}

// MaxDurationSec bounds every duration a plan gives in seconds (admission
// retry interval, tier grace, boot timeout and soak, probe timeout) at seven
// days. A larger count of seconds, converted to a time.Duration, would
// overflow past about 292 years into a negative wait that ends at once.
const MaxDurationSec = 7 * 24 * 60 * 60

// MaxDeferRetries bounds admission_control.max_defer_retries.
const MaxDeferRetries = 10000

// NumericBoundsErrors checks the plan's numbers that become admission
// limits, the RTO target and durations: every float must be finite, since
// NaN compares false both ways and would pass any range check (a NaN I/O
// wait limit admits every load), and every duration must fit in a
// time.Duration. It also holds each VM's IDs and hardware to the
// ranges the rest of the product uses. validate
// applies it, and a run applies it again to a plan it is handed directly.
func NumericBoundsErrors(p *Plan) []ValidationError {
	var errors []ValidationError
	finite := func(field string, value float64) bool {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			errors = append(errors, ValidationError{Field: field, Message: "must be a finite number"})
			return false
		}
		return true
	}
	seconds := func(field string, value int, minimum int) {
		if value < minimum || value > MaxDurationSec {
			errors = append(errors, ValidationError{Field: field, Message: fmt.Sprintf("must be between %d and %d (7 days)", minimum, MaxDurationSec)})
		}
	}
	// compliance.rto_target_seconds, when set, is enforced as a real pass/fail
	// criterion after the run (pkg/runner) and recorded in the signed report;
	// omitting it is the only way to set no objective. A zero the plan gave or a
	// negative number would be read as "not set" (zero is the field's unset
	// value), so each is refused instead of silently passing every run; a key with
	// no value at all counts as left out, as everywhere in a plan. A plan built in
	// code has no record of which keys it gave, and there zero is the field left
	// alone.
	if target := p.Compliance.RTOTargetSeconds; finite("compliance.rto_target_seconds", target) {
		switch {
		case target < 0:
			errors = append(errors, ValidationError{Field: "compliance.rto_target_seconds", Message: "must be a number of seconds above 0 (a negative objective can never be met); leave the key out to set no objective"})
		case target == 0 && p.given("compliance.rto_target_seconds", false):
			errors = append(errors, ValidationError{Field: "compliance.rto_target_seconds", Message: "must be a number of seconds above 0: a value of 0 would be read as no objective and every run would pass it; leave the key out to set no objective"})
		}
	}
	// The admission alias block and the I/O wait alias key are normalised
	// into admission_control only when positive; a non-finite value there
	// must not be dropped silently.
	for _, alias := range []struct {
		field string
		value float64
	}{
		{"admission.max_host_ram_percent", p.Admission.MaxHostRAMPercent},
		{"admission.max_host_iowait_percent", p.Admission.MaxHostIOWaitPercent},
		{"admission.max_host_io_wait_percent", p.Admission.MaxHostIOWaitPercentAlt},
		{"admission_control.max_host_io_wait_percent", p.AdmissionControl.MaxHostIOWaitPercentAlt},
	} {
		finite(alias.field, alias.value)
	}
	// 6. admission_control.max_host_ram_percent
	if value := p.AdmissionControl.MaxHostRAMPercent; finite("admission_control.max_host_ram_percent", value) && (value <= 0 || value > 100) {
		errors = append(errors, ValidationError{Field: "admission_control.max_host_ram_percent", Message: "must be > 0 and <= 100"})
	}
	// 7. admission_control.max_host_iowait_percent
	if value := p.AdmissionControl.MaxHostIOWaitPercent; finite("admission_control.max_host_iowait_percent", value) && (value <= 0 || value > 100) {
		errors = append(errors, ValidationError{Field: "admission_control.max_host_iowait_percent", Message: "must be > 0 and <= 100"})
	}
	// 8. admission_control.defer_retry_interval_sec
	seconds("admission_control.defer_retry_interval_sec", p.AdmissionControl.DeferRetryIntervalSec, 1)
	// 9. admission_control.max_defer_retries
	if n := p.AdmissionControl.MaxDeferRetries; n <= 0 || n > MaxDeferRetries {
		errors = append(errors, ValidationError{Field: "admission_control.max_defer_retries", Message: fmt.Sprintf("must be between 1 and %d", MaxDeferRetries)})
	}
	for i, tier := range p.Tiers {
		prefix := fmt.Sprintf("tiers[%d]", i)
		seconds(prefix+".soak_time_sec", tier.SoakTimeSec, 0)
		seconds(prefix+".startup_grace_period_sec", tier.StartupGracePeriodSec, 0)
		seconds(prefix+".boot_timeout_sec", tier.BootTimeoutSec, 0)
		for j, vm := range tier.VMs {
			errors = append(errors, vmNumberErrors(fmt.Sprintf("%s.vms[%d]", prefix, j), vm)...)
			for k, probe := range vm.Probes {
				field := fmt.Sprintf("%s.vms[%d].probes[%d].timeout_sec", prefix, j, k)
				if probe.TimeoutSec < 1 {
					// Only a timeout left out gets the default of 10.
					errors = append(errors, ValidationError{Field: field, Message: fmt.Sprintf("must be at least 1 second, not %d; leave timeout_sec out for the default of 10", probe.TimeoutSec)})
					continue
				}
				seconds(field, probe.TimeoutSec, 1)
			}
		}
	}
	return errors
}

// qgaCommandProblem is why a qga probe's command may not run in a guest, or
// "" when it may (or the probe is not a qga probe). The agent runs a command
// outside its fast paths as "/bin/sh -c <command>", so only the commands of
// internal/qgacommand are allowed; probe must already be canonical.
func qgaCommandProblem(probe Probe) string {
	if probe.Type != "qga" {
		return ""
	}
	if probe.Command == "" {
		return "must not be empty for qga probes"
	}
	if !qgacommand.Allowed(probe.Command) {
		return "must be " + qgacommand.Description + "; arbitrary guest shell commands are not permitted"
	}
	return ""
}

// ProbeCommandErrors checks the guest commands of a plan's probes against the
// allowlist, for either spelling of the guest-agent probe. validate applies
// it, and a run applies it again to a plan it is handed directly, which may
// not have been loaded through the validating loader: the command reaches a
// shell in the recovered guest.
func ProbeCommandErrors(p *Plan) []ValidationError {
	var errors []ValidationError
	for i, tier := range p.Tiers {
		for j, vm := range tier.VMs {
			for k, probe := range vm.Probes {
				if problem := qgaCommandProblem(canonicalProbe(probe)); problem != "" {
					errors = append(errors, ValidationError{Field: fmt.Sprintf("tiers[%d].vms[%d].probes[%d].command", i, j, k), Message: problem})
				}
			}
		}
	}
	return errors
}

func validPBSSnapshotSelector(snapshot string) bool {
	if snapshot == "latest" {
		return true
	}
	parts := strings.Split(snapshot, "/")
	if len(parts) != 3 || parts[0] != "vm" {
		return false
	}
	if _, ok := canonicalVMID(parts[1]); !ok {
		return false
	}
	if parts[2] == "latest" {
		return true
	}
	_, err := time.Parse(time.RFC3339, parts[2])
	return err == nil
}

// snapshotGroupVMID is the VM ID of the backup group a vm/<id>/... snapshot
// selector names; the bare "latest" names none.
func snapshotGroupVMID(snapshot string) (int, bool) {
	parts := strings.Split(snapshot, "/")
	if len(parts) != 3 || parts[0] != "vm" {
		return 0, false
	}
	return canonicalVMID(parts[1])
}

// canonicalVMID reads a VM ID written as a canonical positive decimal. Atoi
// also reads "+7001" and "07001" as 7001, which the report-side rules
// (attest.snapshotGroup) refuse, so a plan that validated with such a spelling
// could not be bound to its source VM by verify-report --expect-plan.
func canonicalVMID(text string) (int, bool) {
	id, err := strconv.Atoi(text)
	if err != nil || id <= 0 || strconv.Itoa(id) != text {
		return 0, false
	}
	return id, true
}

// drivesInclude reports whether drives restores archive, however its name is
// suffixed ("drive-scsi0", "drive-scsi0.img", "drive-scsi0.img.fidx").
func drivesInclude(drives []SourceDrive, archive string) bool {
	base := func(name string) string {
		return strings.TrimSuffix(strings.TrimSuffix(name, ".fidx"), ".img")
	}
	for _, drive := range drives {
		if base(drive.Archive) == base(archive) {
			return true
		}
	}
	return false
}

func validNICModel(model string) bool {
	switch model {
	case "virtio", "e1000", "e1000e", "igb", "ne2k_pci", "ne2k_isa", "pcnet", "rtl8139", "vmxnet3":
		return true
	default:
		return false
	}
}

// hostLocalNetworks are ranges a worker host answers itself or that are not
// link unicast: unspecified, loopback, link-local, multicast, and reserved.
var hostLocalNetworks = func() []*net.IPNet {
	var networks []*net.IPNet
	for _, cidr := range []string{
		"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fe80::/10", "ff00::/8",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		networks = append(networks, network)
	}
	return networks
}()

// overlappingHostLocalNetwork returns the host-local range that subnet
// overlaps, or "" when it overlaps none.
func overlappingHostLocalNetwork(subnet *net.IPNet) string {
	for _, hostLocal := range hostLocalNetworks {
		if hostLocal.Contains(subnet.IP) || subnet.Contains(hostLocal.IP) {
			return hostLocal.String()
		}
	}
	return ""
}

func isSubnetReservedAddress(ip net.IP, subnet *net.IPNet) bool {
	if ip.Equal(subnet.IP) {
		return true
	}
	ip4, network4 := ip.To4(), subnet.IP.To4()
	if ip4 == nil || network4 == nil || len(subnet.Mask) != net.IPv4len {
		return false
	}
	broadcast := make(net.IP, net.IPv4len)
	for i := range broadcast {
		broadcast[i] = network4[i] | ^subnet.Mask[i]
	}
	return ip4.Equal(broadcast)
}

// LoadFromReader reads and validates a controller plan from an io.Reader.
func LoadFromReader(r io.Reader) (*Plan, error) {
	return loadFromReader(r)
}

// LoadFromReaderForWorker reads and validates a plan staged for the node
// worker. Controller-only configuration (compliance.sign_key_path) is
// intentionally absent from it, and no longer needed in any plan.
func LoadFromReaderForWorker(r io.Reader) (*Plan, error) {
	return loadFromReader(r)
}

func loadFromReader(r io.Reader) (*Plan, error) {
	data, err := readPlanBytes(r)
	if err != nil {
		return nil, err
	}
	return loadFromBytes(data)
}

// readPlanBytes reads a plan through the loader's size limit.
func readPlanBytes(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxPlanBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read plan: %w", err)
	}
	if len(data) > maxPlanBytes {
		return nil, fmt.Errorf("plan exceeds maximum size of %d bytes", maxPlanBytes)
	}
	return data, nil
}

func loadFromBytes(data []byte) (*Plan, error) {
	var p Plan
	// Plans can be submitted through the Enterprise API. Expanding the daemon's
	// environment here would make credentials available to QGA command text and
	// subsequently to signed report evidence. Runtime configuration belongs in
	// protected environment files, never in an untrusted plan.
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&p); err != nil {
		return nil, planDecodeError(err, data)
	}
	// A plan is one security boundary. Never silently ignore a second YAML
	// document, which could make an edited automation artifact look valid while
	// part of the operator's intended configuration was not evaluated.
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("plan must contain exactly one YAML document")
		}
		return nil, fmt.Errorf("failed to parse trailing YAML document: %w", err)
	}

	// Which keys the plan gives, before normalisation fills any: a value
	// written as zero is not a key left out.
	document, err := parsePlanDocument(data)
	if err != nil {
		return nil, err
	}
	keys, err := planKeysOf(document)
	if err != nil {
		return nil, err
	}
	// The decoder cuts a decimal to fit an int key (2555.9 would be 2555):
	// refuse it before anything judges the value it left.
	if err := wholeNumberError(document); err != nil {
		return nil, err
	}
	p.keys = keys
	p.Normalize()

	if errs := validate(&p); len(errs) > 0 {
		return nil, ValidationErrors(errs)
	}

	return &p, nil
}

// LoadFromFile reads a YAML test plan from the given file path.
func LoadFromFile(path string) (*Plan, error) {
	return loadFromFile(path)
}

// LoadFromFileWithDigest is LoadFromFile that also returns the SHA-256, in
// lower-case hex, of the file's bytes exactly as read. The plan is parsed from
// those same bytes, so the digest identifies the plan that was loaded even if
// the file changes afterwards. It is the digest a report records as
// plan_sha256, and the one sha256sum prints for the file.
func LoadFromFileWithDigest(path string) (*Plan, string, error) {
	data, err := readPlanFile(path)
	if err != nil {
		return nil, "", err
	}
	plan, err := loadFromBytes(data)
	if err != nil {
		return nil, "", err
	}
	return plan, PlanDigest(data), nil
}

// PlanDigest is the SHA-256, in lower-case hex, of a plan file's bytes: the
// value a report records as plan_sha256 and verify-report compares with the
// file it is given.
func PlanDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// LoadFromFileForWorker reads a controller-redacted plan staged on a node.
func LoadFromFileForWorker(path string) (*Plan, error) {
	return loadFromFile(path)
}

// loadFromFile reads the file through the loader's size limit, so a file
// larger than a plan is refused after reading no more than the limit, not
// after reading all of it. The file is opened without waiting and
// read only if the open descriptor is a regular file: a FIFO named like a
// plan made a plain open wait for a writer, and validate, run, plan and the
// node worker with it, ahead of any size limit.
func loadFromFile(path string) (*Plan, error) {
	data, err := readPlanFile(path)
	if err != nil {
		return nil, err
	}
	return loadFromBytes(data)
}

// readPlanFile is the bytes of the plan file at path, read as loadFromFile
// reads them: through the open descriptor, which must be a regular file, and
// no further than the size limit.
func readPlanFile(path string) ([]byte, error) {
	file, err := openPlanFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("plan path %s is not a regular file", path)
	}
	return readPlanBytes(file)
}

// MarshalWorkerPlan removes controller-only signing configuration before a
// plan is transferred to the node worker.
func MarshalWorkerPlan(plan *Plan) ([]byte, error) {
	if plan == nil {
		return nil, fmt.Errorf("plan is required")
	}
	// The worker reads each setting under its canonical key only, so the two
	// spellings of one setting cannot disagree there.
	workerPlan := plan.canonicalCopy()
	workerPlan.Compliance.SignKeyPath = ""
	data, err := yaml.Marshal(&workerPlan)
	if err != nil {
		return nil, fmt.Errorf("marshal worker plan: %w", err)
	}
	if readsBackAs(data, &workerPlan) {
		return data, nil
	}
	// The encoder writes some texts in a form it does not read back as the
	// same text ("\n" as "", "\t\n" as YAML it cannot read). Only such a
	// plan is written again, with each of those texts double-quoted (a JSON
	// string is a YAML double-quoted scalar), which spells every character:
	// the bytes of every other plan, which its canonical digest is of, stay as
	// they were.
	texts := map[string]string{}
	stand := copyPlanTexts(reflect.ValueOf(workerPlan), func(text string) string {
		var back string
		if encoded, err := yaml.Marshal(text); err == nil && yaml.Unmarshal(encoded, &back) == nil && back == text {
			return text
		}
		token := fmt.Sprintf("certistack-worker-plan-text-%d", len(texts))
		texts[token] = text
		return token
	}).Interface().(Plan)
	if data, err = yaml.Marshal(&stand); err != nil {
		return nil, fmt.Errorf("marshal worker plan: %w", err)
	}
	for token, text := range texts {
		quoted, err := json.Marshal(text)
		if err != nil || bytes.Count(data, []byte(token)) != 1 {
			return nil, errors.New("marshal worker plan: a text of the plan cannot be written so that the node worker reads it unchanged")
		}
		data = bytes.Replace(data, []byte(token), quoted, 1)
	}
	if !readsBackAs(data, &workerPlan) {
		return nil, errors.New("marshal worker plan: a text of the plan cannot be written so that the node worker reads it unchanged")
	}
	return data, nil
}

// readsBackAs reports whether a marshalled plan, decoded, holds every value
// of want that a plan's YAML gives.
func readsBackAs(data []byte, want *Plan) bool {
	var again Plan
	if err := yaml.Unmarshal(data, &again); err != nil {
		return false
	}
	return sameYAMLValues(reflect.ValueOf(again), reflect.ValueOf(*want))
}

// sameYAMLValues compares the values two plans' YAML would give: the
// exported fields a yaml tag does not leave out, a nil list the same as an
// empty one.
func sameYAMLValues(a, b reflect.Value) bool {
	switch a.Kind() {
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			field := a.Type().Field(i)
			if !field.IsExported() || field.Tag.Get("yaml") == "-" {
				continue
			}
			if !sameYAMLValues(a.Field(i), b.Field(i)) {
				return false
			}
		}
		return true
	case reflect.Slice:
		if a.Len() != b.Len() {
			return false
		}
		for i := 0; i < a.Len(); i++ {
			if !sameYAMLValues(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.String:
		return a.String() == b.String()
	case reflect.Bool:
		return a.Bool() == b.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return a.Int() == b.Int()
	case reflect.Float32, reflect.Float64:
		return a.Float() == b.Float()
	}
	return reflect.DeepEqual(a.Interface(), b.Interface())
}

// copyPlanTexts is a copy of v, a plan or a part of one, with each text
// replaced by what replace makes of it. Lists are copied, so the copy shares
// no text with v.
func copyPlanTexts(v reflect.Value, replace func(string) string) reflect.Value {
	switch v.Kind() {
	case reflect.String:
		out := reflect.New(v.Type()).Elem()
		out.SetString(replace(v.String()))
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				out.Field(i).Set(copyPlanTexts(v.Field(i), replace))
			}
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(copyPlanTexts(v.Index(i), replace))
		}
		return out
	}
	return v
}

// CopyWorkerPlan is an independent copy of a worker plan, as the worker loaded
// it: the plan is marshalled as it is sent to a node and loaded again, so the
// copy shares nothing with plan and has the same canonical digest. A caller
// that hands plan to code which writes into it (the runner pins snapshots and
// inherits hardware as it goes) keeps the copy to describe the plan it was
// given, whichever way that code ends.
func CopyWorkerPlan(plan *Plan) (*Plan, error) {
	data, err := MarshalWorkerPlan(plan)
	if err != nil {
		return nil, err
	}
	return LoadFromReaderForWorker(bytes.NewReader(data))
}

// CanonicalWorkerPlanSHA256 identifies the complete effective worker plan.
// Version 1 hashes MarshalWorkerPlan's deterministic canonical YAML: aliases
// are removed and the controller-only signing-key path is redacted. Loaders
// have applied defaults before this is called; the runner calls it again after
// backup configuration resolution. The digest contains no credential bytes.
const WorkerPlanDigestFormat = "worker-plan-yaml-v1"

func CanonicalWorkerPlanSHA256(plan *Plan) (string, error) {
	data, err := MarshalWorkerPlan(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

// DNSQueryNameProblem says why a dns probe could not send name (its domain,
// or its path when the domain is left out) in a DNS query, or "" when it
// can: at most 253 octets without the root's trailing dot, in labels of 1 to
// 63 octets. White space around the name is ignored, and no name at all is a
// listener check (a query for the root).
func DNSQueryNameProblem(name string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(name), ".")
	if trimmed == "" {
		return ""
	}
	if len(trimmed) > 253 {
		return fmt.Sprintf("is %d octets long, and a DNS name holds at most 253", len(trimmed))
	}
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" {
			return "has an empty label (a dot at the start, or two dots in a row), which a DNS query cannot carry"
		}
		if len(label) > 63 {
			return fmt.Sprintf("has a label of %d octets, and a DNS label holds at most 63", len(label))
		}
	}
	return ""
}

// sharedTemporaryDirectories are the node's directories every user writes in,
// which a run refuses as its scratch directory.
var sharedTemporaryDirectories = []string{"/tmp", "/var/tmp", "/dev/shm"}

// ScratchDirProblem says why a run refuses dir as the node's scratch
// directory, or "" when it takes it: the run's rule (white space around dir
// is ignored, as the run ignores it). A plan's storage.scratch_dir is held to
// it by validate.
func ScratchDirProblem(dir string) string {
	dir = strings.TrimSpace(dir)
	if !strings.HasPrefix(dir, "/") || dir == "/" || path.Clean(dir) != dir || strings.Contains(dir, "..") || strings.ContainsAny(dir, "\x00\r\n\\") {
		return "must be a clean absolute path on the node, other than /, without .. or a trailing /, such as /var/lib/certistack/scratch"
	}
	for _, shared := range sharedTemporaryDirectories {
		if dir == shared {
			return fmt.Sprintf("%s is a shared temporary directory; choose a private path, such as the default /var/lib/certistack/scratch", dir)
		}
	}
	return ""
}

// sandboxIsSourceErrors refuses a sandbox vmid that another VM of the plan
// restores the backups of (its source_vmid, or the group of its snapshot).
// While that VM exists, a run refuses the plan on the node; once it is
// deleted, the sandbox VM would take the ID that names the backups the plan
// tests, and a backup job meanwhile would write the sandbox into their group.
// A VM's own source_vmid is refused with its own message.
func sandboxIsSourceErrors(p *Plan) []ValidationError {
	sources := map[int]string{}
	for i, tier := range p.Tiers {
		for j, vm := range tier.VMs {
			path := fmt.Sprintf("tiers[%d].vms[%d]", i, j)
			if vm.SourceVMID > 0 {
				sources[vm.SourceVMID] = path
			}
			if group, ok := snapshotGroupVMID(vm.SourcePBS.Snapshot); ok && group > 0 {
				if _, known := sources[group]; !known {
					sources[group] = path
				}
			}
		}
	}
	var errors []ValidationError
	for i, tier := range p.Tiers {
		for j, vm := range tier.VMs {
			path := fmt.Sprintf("tiers[%d].vms[%d]", i, j)
			if restorer, ok := sources[vm.VMID]; ok && vm.VMID > 0 && restorer != path {
				errors = append(errors, ValidationError{Field: path + ".vmid", Message: fmt.Sprintf("must differ from every source_vmid of the plan: %s restores the backups of VM %d", restorer, vm.VMID)})
			}
		}
	}
	return errors
}

// ValidPlanID reports whether id may be a plan's plan_id: letters, digits, _
// and -, at most 128 characters.
func ValidPlanID(id string) bool {
	return planIDRegex.MatchString(id)
}

// ValidPVEStorageID reports whether id is a Proxmox VE storage identifier
// (the pve-storage-id format).
func ValidPVEStorageID(id string) bool {
	return pveStorageIDRegex.MatchString(id)
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cliftcloud/certistack/internal/diskslot"
	"github.com/cliftcloud/certistack/internal/macaddr"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/internal/vmlimits"
)

const localQMTaskPrefix = "certistack-local-qm:"

// Hardware is the virtual hardware CreateVM requests for a sandbox VM after
// defaults are applied. Machine and BIOS stay empty when PVE's own default
// (i440fx, SeaBIOS) is used.
type Hardware struct {
	Cores     int
	Sockets   int
	MemoryMB  int
	BalloonMB int
	// NoBalloon is true when the VM has no memory balloon device.
	NoBalloon bool
	CPU       string
	Machine   string
	BIOS      string
	SCSIHW    string
	OSType    string
	NICModel  string
	MAC       string
	// CPUWeight is the PVE cpuunits value CreateVM sends; zero when none is
	// sent and PVE applies its own default. Relative CPU shares change how
	// fast a guest boots and answers under contention, so the evidence names
	// it.
	CPUWeight int
	// BootOrder is the disks the sandbox VM's boot order lists, in order: the
	// "boot" setting CreateVM sends. The first is the boot disk.
	BootOrder []string
}

// EffectiveHardware applies CreateVM's defaults so signed evidence records
// exactly the hardware that was requested, not the plan's partial view.
func (cfg VMConfig) EffectiveHardware() Hardware {
	hw := Hardware{
		Cores: cfg.Cores, Sockets: cfg.Sockets, MemoryMB: cfg.MemoryMB, BalloonMB: cfg.BalloonMB,
		CPU: "host", Machine: cfg.Machine, BIOS: cfg.BIOS, SCSIHW: cfg.SCSIHW, OSType: cfg.OSType,
		NICModel: cfg.NICModel, MAC: cfg.MAC, NoBalloon: cfg.NoBalloon && cfg.BalloonMB <= 0,
	}
	// The report records the address as the request writes it (createRequest
	// refuses one that is not an interface address).
	if canonical, err := macaddr.Canonical(cfg.MAC); err == nil {
		hw.MAC = canonical
	}
	// createRequest sends cpuunits only for a positive weight, so that is the
	// only weight the sandbox VM was created with.
	if cfg.CPUWeight > 0 {
		hw.CPUWeight = cfg.CPUWeight
	}
	if hw.Cores <= 0 {
		hw.Cores = 2
	}
	if hw.Sockets <= 0 {
		hw.Sockets = 1
	}
	if hw.MemoryMB <= 0 {
		hw.MemoryMB = 2048
	}
	if hw.SCSIHW == "" {
		hw.SCSIHW = "virtio-scsi-single"
	}
	if hw.OSType == "" {
		hw.OSType = "l26"
	}
	if hw.NICModel == "" {
		hw.NICModel = "virtio"
	}
	// createRequest refuses a boot disk the VM does not have, so an order that
	// cannot be built is one no VM is created with.
	if order, err := cfg.bootOrder(cfg.overlays()); err == nil {
		hw.BootOrder = order
	}
	return hw
}

// VMConfig defines the ephemeral virtual machine parameters for DR validation.
type VMConfig struct {
	VMID        int    // Unique ephemeral VM identifier
	Name        string // Ephemeral VM name label
	RunID       string // Unique DR validation run UUID for ownership tagging
	Tags        string // Comma-separated PVE resource tags
	Description string // Durable VM description
	Cores       int    // Number of vCPUs
	Sockets     int    // Number of CPU sockets
	MemoryMB    int    // Allocated RAM in MB
	BalloonMB   int    // Dynamic ballooning floor in MB
	// NoBalloon leaves out the memory balloon device PVE adds by default, as
	// the source VM did (balloon: 0). A BalloonMB floor takes precedence.
	NoBalloon bool
	// SMBIOS1 is the source's SMBIOS identity (a normalized PVE smbios1
	// string); empty lets PVE generate a new one.
	SMBIOS1 string
	// EmptyCDROMs are the source's CD-ROM slots, attached without media, as
	// a restore keeps the drives. A slot a restored disk uses is left out.
	EmptyCDROMs []string
	CPUWeight   int // PVE relative CPU weight via cpuunits (default 50)
	// DeltaPath is retained for legacy single-disk callers. New callers use
	// DiskOverlays to preserve every backed-up disk slot.
	DeltaPath    string        // Absolute path to ephemeral COW .qcow2 delta file
	DiskOverlays []DiskOverlay // Ephemeral COW overlays keyed by PVE disk slot
	// BootDisk is the slot to boot; empty means PVE's first disk.
	BootDisk string
	// BootOrder is the source VM's boot order restricted to the disks this VM
	// has, in the source's order. The sandbox VM boots exactly these disks, in
	// this order, after BootDisk: SeaBIOS exposes to the guest only the disks
	// in the boot order, so a guest whose /boot is on a second disk needs that
	// disk in it. Entries that are not one of the VM's disks (a
	// CD-ROM, net0, a disk the plan left out) are dropped. Empty boots BootDisk
	// alone.
	BootOrder []string
	// FirmwareVolumes are disposable copies of a UEFI source VM's variable
	// store (efidisk0) and TPM state (tpmstate0).
	FirmwareVolumes []FirmwareVolume
	// AdditionalNICs are attached, like net0, only to Bridge.
	AdditionalNICs []NIC
	Bridge         string // Isolated SDN VNet interface name
	MAC            string // Optional MAC address for net0 (preserves guest network binding)
	NICModel       string // Optional source net0 model (defaults to virtio)
	Machine        string // Optional machine type (e.g. q35)
	OSType         string // Optional guest OS type (default "l26")
	BIOS           string // Optional firmware (seabios or ovmf)
	SCSIHW         string // Optional SCSI controller (default "virtio-scsi-single")
	ReadBPS        int64  // Optional drive read throttle limit in bytes/sec
	ReadIOPS       int64  // Optional drive read throttle limit in IOPS
}

// DiskOverlay attaches a COW overlay to the same disk slot used by the
// protected source VM. Only backed-up disks are present here.
type DiskOverlay struct {
	Slot string
	Path string
	// Volume, when set, is the PVE volume ID of the overlay (for example
	// "certistack-scratch:17011/certistack-delta-....qcow2"). The disk is then
	// attached by volume ID through the API, which stock Proxmox VE permits
	// for a least-privilege token; Path is kept for evidence and cleanup.
	Volume string
}

// NIC is a sandbox NIC after net0: its slot (net1..net31), model and MAC.
type NIC struct {
	Slot  string
	Model string
	MAC   string
}

var additionalNICSlot = regexp.MustCompile(`^net([1-9]|[12][0-9]|3[01])$`)

// additionalNICStrings returns the PVE values for the NICs after net0, all
// on the isolated bridge with the PVE firewall on, like net0. net0MAC is net0's
// address in PVE's spelling, or empty when PVE is to choose it: no two NICs of
// a VM may hold one address, and none may hold an address no interface can.
func (cfg VMConfig) additionalNICStrings(net0MAC string) (map[string]string, error) {
	var registry macaddr.Registry
	if net0MAC != "" {
		registry.Claim(net0MAC, "net0")
	}
	values := make(map[string]string, len(cfg.AdditionalNICs))
	for _, nic := range cfg.AdditionalNICs {
		if !additionalNICSlot.MatchString(nic.Slot) || values[nic.Slot] != "" {
			return nil, fmt.Errorf("invalid or duplicate NIC slot %q", nic.Slot)
		}
		if !validNICModel(nic.Model) {
			return nil, fmt.Errorf("unsupported %s model %q", nic.Slot, nic.Model)
		}
		mac, err := macaddr.Canonical(nic.MAC)
		if err != nil {
			return nil, fmt.Errorf("invalid %s MAC address %q: %v", nic.Slot, nic.MAC, err)
		}
		if prior, ok := registry.Claim(mac, nic.Slot); !ok {
			return nil, fmt.Errorf("%s and %s both use MAC address %s; two NICs of one VM on the isolated bridge must not share an address", nic.Slot, prior, mac)
		}
		values[nic.Slot] = fmt.Sprintf("%s=%s,bridge=%s,firewall=1", nic.Model, mac, cfg.Bridge)
	}
	return values, nil
}

// FirmwareVolume attaches a disposable raw copy of a firmware state image
// in the slot the source VM used. Options are the allowlisted options that
// describe the image, such as "efitype=4m,pre-enrolled-keys=1".
type FirmwareVolume struct {
	Slot    string // "efidisk0" or "tpmstate0"
	Volume  string
	Options string
}

// overlayVolumeExpr accepts only CertiStack overlay volumes owned by a VM on
// a named storage, so a plan can never attach an arbitrary existing volume.
// Its second group is the slot, which must match the slot the volume is
// attached to.
var overlayVolumeExpr = regexp.MustCompile(`^[a-z][a-z0-9_.-]*[a-z0-9]:([1-9][0-9]*)/certistack-delta-vm[0-9]+-((?:ide|sata|scsi|virtio)[0-9]+)-[0-9]+-[0-9]+\.qcow2$`)

// firmwareVolumeExpr is the same guard for firmware state copies. Its
// second group is the slot, which must match the slot the volume is
// attached to.
var firmwareVolumeExpr = regexp.MustCompile(`^[a-z][a-z0-9_.-]*[a-z0-9]:([1-9][0-9]*)/certistack-delta-vm[0-9]+-(efidisk0|tpmstate0)-[0-9]+-[0-9]+\.raw$`)

// firmwareOptionExpr bounds the options passed through with a firmware
// volume; the values themselves were allowlisted when the source
// configuration was parsed.
var firmwareOptionExpr = regexp.MustCompile(`^(efitype=(2m|4m)|pre-enrolled-keys=[01]|ms-cert=[0-9a-z]{1,16}|version=v(1\.2|2\.0))$`)

// firmwareDriveString returns the PVE drive value for a firmware volume.
func firmwareDriveString(vmid int, firmware FirmwareVolume) (string, error) {
	m := firmwareVolumeExpr.FindStringSubmatch(firmware.Volume)
	if m == nil || m[1] != strconv.Itoa(vmid) || m[2] != firmware.Slot {
		return "", fmt.Errorf("invalid firmware volume %q for VM %d %s", firmware.Volume, vmid, firmware.Slot)
	}
	drive := firmware.Volume
	if firmware.Options != "" {
		for _, option := range strings.Split(firmware.Options, ",") {
			if !firmwareOptionExpr.MatchString(option) {
				return "", fmt.Errorf("invalid %s option %q", firmware.Slot, option)
			}
		}
		drive += "," + firmware.Options
	}
	return drive, nil
}

// overlayDriveString returns the PVE drive value for a disk overlay.
func overlayDriveString(vmid int, disk DiskOverlay, scsiHW string) (string, error) {
	if disk.Volume != "" {
		m := overlayVolumeExpr.FindStringSubmatch(disk.Volume)
		if m == nil || m[1] != strconv.Itoa(vmid) || m[2] != disk.Slot {
			return "", fmt.Errorf("invalid overlay volume %q for VM %d %s", disk.Volume, vmid, disk.Slot)
		}
		// The format follows from the volume name; stating it again could
		// conflict with PVE's own volume parsing.
		return fmt.Sprintf("%s,%s", disk.Volume, overlayDriveOptions(disk.Slot, scsiHW)), nil
	}
	if strings.ContainsAny(disk.Path, ",\r\n") {
		return "", fmt.Errorf("invalid overlay path for %s", disk.Slot)
	}
	return fmt.Sprintf("%s,format=qcow2,%s", disk.Path, overlayDriveOptions(disk.Slot, scsiHW)), nil
}

// overlayDriveOptions keeps restored guest data out of the cluster's own
// backups: a scheduled "all VMs" backup job that runs during a validation
// would otherwise copy every sandbox disk into a backup store and hold the
// VM's backup lock for minutes. With backup=0 it stores the configuration
// only. PVE honors iothread only on VirtIO block disks and on SCSI disks
// behind virtio-scsi-single; elsewhere it warns at VM start, so the option
// is set only where it applies.
//
// The overlay and its backing are read and written through the host page
// cache, and the guest's flushes are not forced to disk (cache=unsafe).
// QEMU opens a qcow2 backing file with its overlay's cache mode, so under
// PVE's default (cache=none, O_DIRECT) every read the guest made from the
// backup bypassed the pages the pre-boot integrity scan had cached for the
// mapped device and went back through the loop device, FUSE and the map
// daemon. A Windows boot through that path missed the service manager's
// 30 s start deadline; the same overlay over a local disk did not.
// Buffered writes also spare each first write to a cluster a synchronous
// copy-on-write. Nothing written to an overlay is kept: it is disposable,
// deleted at teardown, and the evidence comes from the read-only PBS map.
func overlayDriveOptions(slot, scsiHW string) string {
	bus, _, _ := diskslot.Parse(slot)
	if bus == "virtio" || (bus == "scsi" && scsiHW == "virtio-scsi-single") {
		return "discard=on,iothread=1,backup=0,cache=unsafe"
	}
	return "discard=on,backup=0,cache=unsafe"
}

// VMStatus represents the execution state of a VM in Proxmox VE.
type VMStatus struct {
	VMID      int    `json:"vmid"`
	Name      string `json:"name"`
	Status    string `json:"status"` // "running", "stopped", "paused"
	CPUs      int    `json:"cpus"`
	Memory    int64  `json:"maxmem"`
	Uptime    int64  `json:"uptime"`
	PID       int    `json:"pid"`
	QMPStatus string `json:"qmpstatus"`
	// RunningMachine and RunningQEMU are the machine version and QEMU
	// version the running VM uses, for example "pc-q35-11.0+pve0".
	RunningMachine string `json:"running-machine,omitempty"`
	RunningQEMU    string `json:"running-qemu,omitempty"`
}

// IsVMIDInUse reports whether any guest in the cluster already owns vmid.
// PVE VMIDs are cluster-wide even though many status endpoints are node-local.
func (c *Client) IsVMIDInUse(ctx context.Context, vmid int) (bool, error) {
	if err := vmlimits.CheckVMID(vmid); err != nil {
		return false, err
	}
	used, err := c.UsedVMIDs(ctx)
	if err != nil {
		return false, err
	}
	return used[vmid], nil
}

// UsedVMIDs is every VM and container ID in the cluster the token can see.
func (c *Client) UsedVMIDs(ctx context.Context) (map[int]bool, error) {
	// PVE answers an empty list as [] in "data". A reply with no data field, or
	// null, is not an empty cluster: it is a reply that carries no list, and
	// reading it as one would call every VMID free and confirm any 404 as the
	// VM's absence.
	var raw json.RawMessage
	if err := c.Do(ctx, "GET", "cluster/resources?type=vm", nil, &raw); err != nil {
		return nil, fmt.Errorf("list cluster VM resources: %w", err)
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, errors.New("list cluster VM resources: PVE's reply carries no data field, so it is not an answer that no VM exists")
	}
	var resources []struct {
		VMID *int `json:"vmid"`
	}
	if err := json.Unmarshal(raw, &resources); err != nil {
		return nil, fmt.Errorf("list cluster VM resources: %w", err)
	}
	used := make(map[int]bool, len(resources))
	for _, resource := range resources {
		// An entry that names no VMID (missing, null or zero) leaves the ID it
		// stood for out of the map: a list that cannot be read in full cannot
		// show which IDs are free or confirm a VM's absence.
		if resource.VMID == nil || *resource.VMID <= 0 {
			return nil, errors.New("list cluster VM resources: an entry of PVE's list names no VMID, so the list is not complete")
		}
		used[*resource.VMID] = true
	}
	return used, nil
}

// CreateVM provisions an ephemeral VM referencing the delta overlay and isolated SDN bridge.
// Injects ownership tags and description to guarantee non-destructive teardown safety.
// Returns the asynchronous task UPID.
// createRequest is a sandbox VM's create request, with what the local qm
// fallbacks need to make it again.
type createRequest struct {
	body                               map[string]interface{}
	cdroms                             []string
	disks                              []DiskOverlay
	netStr, tags, desc, ostype, scsiHW string
	cores, sockets, memory             int
}

// CreateParams are the parameters CreateVM sends PVE to create cfg's VM,
// for a plan to show exactly what a run will create.
func (cfg VMConfig) CreateParams() (map[string]interface{}, error) {
	req, err := cfg.createRequest()
	if err != nil {
		return nil, err
	}
	return req.body, nil
}

func (cfg VMConfig) createRequest() (createRequest, error) {
	if !validBridge(cfg.Bridge) {
		return createRequest{}, fmt.Errorf("invalid isolated bridge %q", cfg.Bridge)
	}
	// net0's address, in PVE's spelling; empty lets PVE choose one. Every layer
	// holds an address to the one rule (internal/macaddr): a request that
	// carries the all-zero, broadcast or a multicast address is refused here as
	// it is at the plan, because VMConfig is a public programmatic boundary.
	var net0MAC string
	if cfg.MAC != "" {
		canonical, err := macaddr.Canonical(cfg.MAC)
		if err != nil {
			return createRequest{}, fmt.Errorf("invalid net0 MAC address %q: %v", cfg.MAC, err)
		}
		net0MAC = canonical
	}

	// The hardware a backup's configuration may inherit is held to ranges
	// (internal/vmlimits); what a plan sets is too, and a VM is never
	// created with a value outside them.
	for _, field := range []struct {
		name            string
		value, min, max int
	}{
		{"cores", cfg.Cores, 1, vmlimits.MaxCores},
		{"sockets", cfg.Sockets, 1, vmlimits.MaxSockets},
		{"memory", cfg.MemoryMB, vmlimits.MinMemoryMB, vmlimits.MaxMemoryMB},
		{"balloon", cfg.BalloonMB, 1, vmlimits.MaxBalloonMB},
		{"CPU weight", cfg.CPUWeight, 1, vmlimits.MaxCPUWeight},
	} {
		if field.value != 0 && (field.value < field.min || field.value > field.max) {
			return createRequest{}, fmt.Errorf("invalid %s %d for VM %d: must be between %d and %d", field.name, field.value, cfg.VMID, field.min, field.max)
		}
	}

	hw := cfg.EffectiveHardware()
	ostype, cores, memory, sockets, scsiHW := hw.OSType, hw.Cores, hw.MemoryMB, hw.Sockets, hw.SCSIHW

	disks := cfg.overlays()
	if len(disks) == 0 {
		return createRequest{}, fmt.Errorf("at least one disk overlay is required")
	}

	seenSlots := make(map[string]bool, len(disks))

	// Format net0 string attached strictly to the isolated SDN VNet bridge.
	// Preserving the source model as well as its MAC keeps driver-bound Linux
	// interface names stable after recovery.
	nicModel := hw.NICModel
	if !validNICModel(nicModel) {
		return createRequest{}, fmt.Errorf("unsupported net0 model %q", nicModel)
	}
	netStr := fmt.Sprintf("%s,bridge=%s,firewall=1", nicModel, cfg.Bridge)
	if net0MAC != "" {
		netStr = fmt.Sprintf("%s=%s,bridge=%s,firewall=1", nicModel, net0MAC, cfg.Bridge)
	}

	// Ownership markers are a cleanup safety boundary. A caller may add its own
	// labels for audit context, but can never replace the exact CertiStack and
	// run identifiers recovery uses before destroying a VM.
	tags, desc, err := ownedMetadata(cfg.Tags, cfg.Description, cfg.RunID)
	if err != nil {
		return createRequest{}, err
	}

	reqBody := map[string]interface{}{
		"vmid":        cfg.VMID,
		"name":        cfg.Name,
		"tags":        tags,
		"description": desc,
		"ostype":      ostype,
		"cores":       cores,
		"sockets":     sockets,
		"cpu":         "host",
		"memory":      memory,
		"scsihw":      scsiHW,
		"net0":        netStr,
		"agent":       "enabled=1",
	}
	for _, disk := range disks {
		if disk.Slot == "" || (disk.Path == "" && disk.Volume == "") {
			return createRequest{}, fmt.Errorf("disk slot and overlay path or volume must not be empty")
		}
		if !diskslot.Valid(disk.Slot) {
			return createRequest{}, fmt.Errorf("invalid disk slot %q", disk.Slot)
		}
		if seenSlots[disk.Slot] {
			return createRequest{}, fmt.Errorf("duplicate disk slot %q", disk.Slot)
		}
		seenSlots[disk.Slot] = true

		// PVE accepts a host path as a drive value. Every source disk gets a
		// separate ephemeral COW overlay; never attach a source PBS map directly.
		driveStr, err := overlayDriveString(cfg.VMID, disk, scsiHW)
		if err != nil {
			return createRequest{}, err
		}
		if cfg.ReadBPS > 0 {
			driveStr = fmt.Sprintf("%s,bps_rd=%d", driveStr, cfg.ReadBPS)
		}
		if cfg.ReadIOPS > 0 {
			driveStr = fmt.Sprintf("%s,iops_rd=%d", driveStr, cfg.ReadIOPS)
		}
		reqBody[disk.Slot] = driveStr
	}
	bootOrder, err := cfg.bootOrder(disks)
	if err != nil {
		return createRequest{}, err
	}
	for _, firmware := range cfg.FirmwareVolumes {
		if seenSlots[firmware.Slot] {
			return createRequest{}, fmt.Errorf("duplicate disk slot %q", firmware.Slot)
		}
		seenSlots[firmware.Slot] = true
		driveStr, err := firmwareDriveString(cfg.VMID, firmware)
		if err != nil {
			return createRequest{}, err
		}
		reqBody[firmware.Slot] = driveStr
	}
	cdroms := cfg.emptyCDROMSlots(seenSlots)
	for _, slot := range cdroms {
		reqBody[slot] = emptyCDROM
	}
	nics, err := cfg.additionalNICStrings(net0MAC)
	if err != nil {
		return createRequest{}, err
	}
	for slot, value := range nics {
		reqBody[slot] = value
	}
	reqBody["boot"] = bootSetting(bootOrder)
	if cfg.Machine != "" {
		reqBody["machine"] = cfg.Machine
	}
	if cfg.BIOS != "" {
		reqBody["bios"] = cfg.BIOS
	}

	if cfg.BalloonMB > 0 {
		reqBody["balloon"] = cfg.BalloonMB
	} else if cfg.NoBalloon {
		reqBody["balloon"] = 0
	}
	if cfg.SMBIOS1 != "" {
		reqBody["smbios1"] = cfg.SMBIOS1
	}

	if cfg.CPUWeight > 0 {
		reqBody["cpuunits"] = cfg.CPUWeight
	}

	return createRequest{
		body: reqBody, cdroms: cdroms, disks: disks,
		netStr: netStr, tags: tags, desc: desc, ostype: ostype, scsiHW: scsiHW,
		cores: cores, sockets: sockets, memory: memory,
	}, nil
}

func (c *Client) CreateVM(ctx context.Context, node string, cfg VMConfig) (string, error) {
	if err := validateVMRequest(node, cfg.VMID); err != nil {
		return "", err
	}
	req, err := cfg.createRequest()
	if err != nil {
		return "", err
	}
	reqBody, cdroms, disks := req.body, req.cdroms, req.disks
	ostype, cores, sockets, memory, scsiHW, tags, desc, netStr := req.ostype, req.cores, req.sockets, req.memory, req.scsiHW, req.tags, req.desc, req.netStr

	path := fmt.Sprintf("nodes/%s/qemu", node)
	var upid string

	slog.Info("creating ephemeral VM", "vmid", cfg.VMID, "name", cfg.Name, "node", node, "bridge", cfg.Bridge, "tags", tags)
	err = c.Do(ctx, "POST", path, reqBody, &upid)
	if err != nil && rejectedMSCert(err, cfg.FirmwareVolumes) {
		// Proxmox VE 8 does not know efidisk0's ms-cert option (it only says
		// which Microsoft certificate generation the pre-enrolled keys come
		// from); the restored variable store carries the keys either way.
		slog.Warn("this Proxmox VE does not accept the efidisk0 ms-cert option; creating the VM without it", "vmid", cfg.VMID, "node", node)
		cfg.FirmwareVolumes = withoutMSCert(cfg.FirmwareVolumes)
		retry, retryErr := cfg.createRequest()
		if retryErr != nil {
			return "", retryErr
		}
		reqBody, cdroms, disks = retry.body, retry.cdroms, retry.disks
		err = c.Do(ctx, "POST", path, reqBody, &upid)
	}
	if err != nil {
		if isArbitraryPathPermissionDenied(err) && c.canUseLocalQM(node) {
			qmArgs := localQMCreateArgs(cfg, ostype, cores, sockets, memory, scsiHW, tags, desc, netStr, disks)
			slog.Warn("PVE API token cannot attach local COW paths; using local root qm create", "vmid", cfg.VMID, "node", node)
			if runErr := c.runQMFn(ctx, qmArgs); runErr != nil {
				if strings.Contains(runErr.Error(), "unable to associate path") {
					// Stock PVE attaches only disks that belong to a storage,
					// even for root; this is not a transient failure.
					return "", fmt.Errorf("failed to create VM %d: Proxmox VE only attaches disks that belong to a storage; set storage.overlay_storage (or --overlay-storage) to a file-based storage with images content. %s: %w", cfg.VMID, CreateOverlayStorageHint, runErr)
				}
				return "", fmt.Errorf("failed to create VM %d locally after PVE path permission denial: %w", cfg.VMID, runErr)
			}
			return fmt.Sprintf("%s%d", localQMTaskPrefix, cfg.VMID), nil
		}
		if len(cdroms) > 0 && isCDROMPermissionDenied(err) {
			// Only the empty CD-ROM drives need VM.Config.CDROM. Root's local
			// qm attaches them; without it the VM is created without them,
			// and the caller records which drives it has.
			if c.canUseLocalQM(node) {
				qmArgs := localQMCreateArgs(cfg, ostype, cores, sockets, memory, scsiHW, tags, desc, netStr, disks)
				slog.Warn("PVE API token cannot attach CD-ROM drives; using local root qm create", "vmid", cfg.VMID, "node", node)
				if runErr := c.runQMFn(ctx, qmArgs); runErr != nil {
					return "", fmt.Errorf("failed to create VM %d locally after the CD-ROM permission denial: %w", cfg.VMID, runErr)
				}
				return fmt.Sprintf("%s%d", localQMTaskPrefix, cfg.VMID), nil
			}
			slog.Warn("PVE API token cannot attach CD-ROM drives; creating the VM without them", "vmid", cfg.VMID, "slots", cdroms)
			for _, slot := range cdroms {
				delete(reqBody, slot)
			}
			if retryErr := c.Do(ctx, "POST", path, reqBody, &upid); retryErr != nil {
				return "", fmt.Errorf("failed to create VM %d on node %s: %w", cfg.VMID, node, retryErr)
			}
			return upid, nil
		}
		return "", fmt.Errorf("failed to create VM %d on node %s: %w", cfg.VMID, node, err)
	}

	return upid, nil
}

// rejectedMSCert reports PVE refusing the efidisk0 drive of a request that
// carried ms-cert, which is how a release that predates the option answers.
func rejectedMSCert(err error, firmware []FirmwareVolume) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest || apiErr.Errors["efidisk0"] == "" {
		return false
	}
	for _, volume := range firmware {
		if volume.Slot == "efidisk0" && hasMSCert(volume.Options) {
			return true
		}
	}
	return false
}

func hasMSCert(options string) bool {
	for _, option := range strings.Split(options, ",") {
		if strings.HasPrefix(option, "ms-cert=") {
			return true
		}
	}
	return false
}

// withoutMSCert returns the firmware volumes with the efidisk0 ms-cert option
// removed, leaving the caller's slice untouched.
func withoutMSCert(firmware []FirmwareVolume) []FirmwareVolume {
	out := make([]FirmwareVolume, len(firmware))
	for i, volume := range firmware {
		out[i] = volume
		if volume.Slot != "efidisk0" {
			continue
		}
		var kept []string
		for _, option := range strings.Split(volume.Options, ",") {
			if option != "" && !strings.HasPrefix(option, "ms-cert=") {
				kept = append(kept, option)
			}
		}
		out[i].Options = strings.Join(kept, ",")
	}
	return out
}

// emptyCDROM is an empty CD-ROM drive.
const emptyCDROM = "none,media=cdrom"

// emptyCDROMSlots returns the valid CD-ROM slots not taken by a disk or
// firmware state, in order.
func (cfg VMConfig) emptyCDROMSlots(taken map[string]bool) []string {
	var slots []string
	for _, slot := range cfg.EmptyCDROMs {
		if diskslot.Valid(slot) && !strings.HasPrefix(slot, "virtio") && !taken[slot] {
			taken[slot] = true
			slots = append(slots, slot)
		}
	}
	return slots
}

// isCDROMPermissionDenied reports PVE refusing a CD-ROM drive for lack of
// VM.Config.CDROM.
func isCDROMPermissionDenied(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden && strings.Contains(apiErr.Message, "VM.Config.CDROM")
}

// validNICModel accepts the NIC models Proxmox VE offers.
func validNICModel(model string) bool {
	switch model {
	case "virtio", "e1000", "e1000-82540em", "e1000-82544gc", "e1000-82545em", "e1000e", "igb",
		"i82551", "i82557b", "i82559er", "ne2k_pci", "ne2k_isa", "pcnet", "rtl8139", "vmxnet3":
		return true
	default:
		return false
	}
}

// validBridge permits ordinary PVE VNet/Linux bridge identifiers while
// rejecting the PVE net0 option delimiters. The bridge becomes part of a
// comma-delimited net0 value, so accepting a comma, equals sign, or whitespace
// would let an untrusted caller alter NIC behavior or escape the sandbox.
func validBridge(bridge string) bool {
	if strings.TrimSpace(bridge) == "" || strings.TrimSpace(bridge) != bridge {
		return false
	}
	return !strings.ContainsAny(bridge, ",=\r\n\t ")
}

// ownedMetadata derives or verifies the exact markers recovery needs. Tags
// and descriptions may be supplied by an API caller, but they must never make
// a created VM unrecoverable or weaken VMID-reuse protection.
func ownedMetadata(tags, description, runID string) (string, string, error) {
	if tags == "" {
		tags = "certistack"
		if runID != "" {
			tags += "," + runID
		}
	}
	if description == "" {
		description = "CertiStack Ephemeral DR VM; owner=certistack"
		if runID != "" {
			description += "; run_id=" + runID
		}
	}
	if !hasExactTag(tags, "certistack") || !hasExactDescriptionField(description, "owner", "certistack") {
		return "", "", errors.New("VM metadata must retain exact CertiStack ownership markers")
	}
	if runID != "" && (!hasExactTag(tags, runID) || !hasExactDescriptionField(description, "run_id", runID)) {
		return "", "", fmt.Errorf("VM metadata must retain exact run ownership marker %q", runID)
	}
	return tags, description, nil
}

// localQMCreateArgs produces the argument vector for a synchronous local
// `qm create`. It is used only after PVE explicitly rejects host paths for a
// non-root API identity and the runner has verified it is root on that node.
func localQMCreateArgs(cfg VMConfig, ostype string, cores, sockets, memory int, scsiHW, tags, desc, netStr string, disks []DiskOverlay) []string {
	args := []string{
		"create", strconv.Itoa(cfg.VMID),
		"--name", cfg.Name,
		"--tags", tags,
		"--description", desc,
		"--ostype", ostype,
		"--cores", strconv.Itoa(cores),
		"--sockets", strconv.Itoa(sockets),
		"--cpu", "host",
		"--memory", strconv.Itoa(memory),
		"--scsihw", scsiHW,
		"--net0", netStr,
		"--agent", "enabled=1",
	}
	for _, disk := range disks {
		drive, err := overlayDriveString(cfg.VMID, disk, scsiHW)
		if err != nil {
			drive = fmt.Sprintf("%s,format=qcow2,%s", disk.Path, overlayDriveOptions(disk.Slot, scsiHW))
		}
		if cfg.ReadBPS > 0 {
			drive = fmt.Sprintf("%s,bps_rd=%d", drive, cfg.ReadBPS)
		}
		if cfg.ReadIOPS > 0 {
			drive = fmt.Sprintf("%s,iops_rd=%d", drive, cfg.ReadIOPS)
		}
		args = append(args, "--"+disk.Slot, drive)
	}
	taken := make(map[string]bool, len(disks)+len(cfg.FirmwareVolumes))
	for _, disk := range disks {
		taken[disk.Slot] = true
	}
	for _, firmware := range cfg.FirmwareVolumes {
		taken[firmware.Slot] = true
		// CreateVM validated every firmware volume before falling back here.
		if drive, err := firmwareDriveString(cfg.VMID, firmware); err == nil {
			args = append(args, "--"+firmware.Slot, drive)
		}
	}
	for _, slot := range cfg.emptyCDROMSlots(taken) {
		args = append(args, "--"+slot, emptyCDROM)
	}
	bootOrder, _ := cfg.bootOrder(disks) // CreateVM validated it before falling back here
	// CreateVM validated the NICs before falling back here.
	net0MAC, _ := macaddr.Canonical(cfg.MAC)
	if nics, err := cfg.additionalNICStrings(net0MAC); err == nil {
		for _, nic := range cfg.AdditionalNICs {
			args = append(args, "--"+nic.Slot, nics[nic.Slot])
		}
	}
	args = append(args, "--boot", bootSetting(bootOrder))
	if cfg.Machine != "" {
		args = append(args, "--machine", cfg.Machine)
	}
	if cfg.BIOS != "" {
		args = append(args, "--bios", cfg.BIOS)
	}
	if cfg.BalloonMB > 0 {
		args = append(args, "--balloon", strconv.Itoa(cfg.BalloonMB))
	} else if cfg.NoBalloon {
		args = append(args, "--balloon", "0")
	}
	if cfg.SMBIOS1 != "" {
		args = append(args, "--smbios1", cfg.SMBIOS1)
	}
	if cfg.CPUWeight > 0 {
		args = append(args, "--cpuunits", strconv.Itoa(cfg.CPUWeight))
	}
	return args
}

func isArbitraryPathPermissionDenied(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) &&
		apiErr.StatusCode == 500 &&
		strings.Contains(strings.ToLower(apiErr.Message), "only root can pass arbitrary filesystem paths")
}

func (c *Client) canUseLocalQM(node string) bool {
	return c.isLocalNodeFn != nil && c.isRootFn != nil && c.runQMFn != nil &&
		c.isRootFn() && c.isLocalNodeFn(node)
}

func isLocalPveNode(node string) bool {
	if node == "" {
		return false
	}
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}
	return strings.EqualFold(shortNodeName(node), shortNodeName(hostname))
}

func shortNodeName(name string) string {
	return strings.SplitN(strings.TrimSpace(name), ".", 2)[0]
}

func processRunsAsRoot() bool {
	return os.Geteuid() == 0
}

func runLocalQM(ctx context.Context, args []string) error {
	qmCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err := process.CombinedOutput(process.CommandContext(qmCtx, "qm", args, false))
	if err == nil {
		return nil
	}
	if errors.Is(qmCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("qm create timed out: %w", qmCtx.Err())
	}
	return fmt.Errorf("qm create failed: %w: %s", err, strings.TrimSpace(string(out)))
}

// overlays are the VM's disk overlays: DiskOverlays, or the legacy single
// DeltaPath as scsi0.
func (cfg VMConfig) overlays() []DiskOverlay {
	if len(cfg.DiskOverlays) == 0 && cfg.DeltaPath != "" {
		return []DiskOverlay{{Slot: "scsi0", Path: cfg.DeltaPath}}
	}
	return cfg.DiskOverlays
}

// bootSetting is PVE's boot property for an order of disks.
func bootSetting(order []string) string {
	return "order=" + strings.Join(order, ";")
}

// bootOrder is the boot order of the sandbox VM: the boot disk first, then the
// rest of cfg.BootOrder that is one of the VM's disks, in that order. SeaBIOS
// exposes only the disks in the boot order, so a guest that reads /boot from a
// second disk needs it listed; anything that is not one of the VM's disks (a
// CD-ROM, net0, a disk left out, firmware state) is not, so the VM never tries
// the network or a disk it does not have.
//
// cfg.BootDisk, when set, must be one of the VM's disks and leads the order. A
// caller that gives no boot disk and no order gets PVE's first disk, which is
// what PVE boots without a boot order.
func (cfg VMConfig) bootOrder(disks []DiskOverlay) ([]string, error) {
	slots := make([]string, 0, len(disks))
	has := make(map[string]bool, len(disks))
	for _, disk := range disks {
		slots = append(slots, disk.Slot)
		has[disk.Slot] = diskslot.Valid(disk.Slot)
	}
	var order []string
	seen := make(map[string]bool, len(disks))
	add := func(slot string) {
		if has[slot] && !seen[slot] {
			seen[slot] = true
			order = append(order, slot)
		}
	}
	if cfg.BootDisk != "" {
		if !has[cfg.BootDisk] {
			return nil, fmt.Errorf("boot disk %q is not one of the VM's disks", cfg.BootDisk)
		}
		add(cfg.BootDisk)
	}
	for _, entry := range cfg.BootOrder {
		add(entry)
	}
	if len(order) == 0 {
		add(diskslot.First(slots))
	}
	return order, nil
}

// StartVM initiates execution of the virtual machine.
// Returns the asynchronous task UPID.
func (c *Client) StartVM(ctx context.Context, node string, vmid int) (string, error) {
	if err := validateVMRequest(node, vmid); err != nil {
		return "", err
	}
	path := fmt.Sprintf("nodes/%s/qemu/%d/status/start", node, vmid)
	var upid string

	slog.Info("starting VM", "vmid", vmid, "node", node)
	if err := c.Do(ctx, "POST", path, map[string]interface{}{}, &upid); err != nil {
		return "", fmt.Errorf("failed to start VM %d: %w", vmid, err)
	}

	return upid, nil
}

// StopVM forcefully halts the virtual machine immediately.
// Returns the asynchronous task UPID.
func (c *Client) StopVM(ctx context.Context, node string, vmid int) (string, error) {
	if err := validateVMRequest(node, vmid); err != nil {
		return "", err
	}
	path := fmt.Sprintf("nodes/%s/qemu/%d/status/stop", node, vmid)
	reqBody := map[string]interface{}{
		// Respect PVE's normal lock ownership for scoped API tokens. The local
		// root fallback in the orchestrator is reserved for a genuine stop
		// failure during CertiStack-owned cleanup.
		"timeout": 5,
	}
	var upid string

	slog.Info("stopping VM", "vmid", vmid, "node", node)
	if err := c.Do(ctx, "POST", path, reqBody, &upid); err != nil {
		return "", fmt.Errorf("failed to stop VM %d: %w", vmid, err)
	}
	// qmstop is a stop; hastop is what PVE runs for a VM its HA manager owns.
	if err := expectVMTask(upid, vmid, "stop", "qmstop", "hastop"); err != nil {
		return "", err
	}

	return upid, nil
}

// DestroyVM permanently deletes the ephemeral VM configuration.
// Safe teardown: targets only the specific VM without destroying unreferenced storage disks.
// Returns the asynchronous task UPID.
func (c *Client) DestroyVM(ctx context.Context, node string, vmid int) (string, error) {
	if err := validateVMRequest(node, vmid); err != nil {
		return "", err
	}
	path := fmt.Sprintf("nodes/%s/qemu/%d", node, vmid)
	var upid string

	slog.Info("destroying ephemeral VM", "vmid", vmid, "node", node)
	if err := c.Do(ctx, "DELETE", path, nil, &upid); err != nil {
		return "", fmt.Errorf("failed to destroy VM %d: %w", vmid, err)
	}
	if err := expectVMTask(upid, vmid, "destruction", "qmdestroy"); err != nil {
		return "", err
	}

	return upid, nil
}

// GetVMStatus retrieves the current runtime status of the VM.
func (c *Client) GetVMStatus(ctx context.Context, node string, vmid int) (*VMStatus, error) {
	if err := validateVMRequest(node, vmid); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("nodes/%s/qemu/%d/status/current", node, vmid)
	var status VMStatus

	if err := c.Do(ctx, "GET", path, nil, &status); err != nil {
		return nil, fmt.Errorf("failed to get status for VM %d: %w", vmid, err)
	}

	return &status, nil
}

// GetVMConfig retrieves the full VM configuration map from Proxmox VE.
func (c *Client) GetVMConfig(ctx context.Context, node string, vmid int) (map[string]interface{}, error) {
	if err := validateVMRequest(node, vmid); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("nodes/%s/qemu/%d/config", node, vmid)
	var cfg map[string]interface{}

	if err := c.Do(ctx, "GET", path, nil, &cfg); err != nil {
		return nil, fmt.Errorf("failed to get config for VM %d: %w", vmid, err)
	}

	return cfg, nil
}

// KeepRequestedMachine undoes the machine version PVE pins when it creates a
// Windows guest, which a restore does not do: qmrestore writes the backup's
// machine setting as it is, so an unversioned "q35" (or no setting, PVE's
// i440fx) is resolved to a version at every start. requested is the machine
// sent to CreateVM, "" for PVE's default. It returns the machine PVE had
// stored when that differed and was reset, "" when nothing changed.
func (c *Client) KeepRequestedMachine(ctx context.Context, node string, vmid int, requested string) (string, error) {
	cfg, err := c.GetVMConfig(ctx, node, vmid)
	if err != nil {
		return "", err
	}
	stored, _ := cfg["machine"].(string)
	if stored == requested {
		return "", nil
	}
	body := map[string]interface{}{"machine": requested}
	qmArgs := []string{"set", strconv.Itoa(vmid), "--machine", requested}
	if requested == "" {
		body = map[string]interface{}{"delete": "machine"}
		qmArgs = []string{"set", strconv.Itoa(vmid), "--delete", "machine"}
	}
	path := fmt.Sprintf("nodes/%s/qemu/%d/config", node, vmid)
	if err := c.Do(ctx, "PUT", path, body, nil); err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden || !c.canUseLocalQM(node) {
			return "", fmt.Errorf("reset VM %d machine from %q to the requested %q: %w", vmid, stored, requested, err)
		}
		if runErr := c.runQMFn(ctx, qmArgs); runErr != nil {
			return "", fmt.Errorf("reset VM %d machine from %q to the requested %q locally: %w", vmid, stored, requested, runErr)
		}
	}
	return stored, nil
}

// QEMUMachines lists the QEMU machine IDs the node can run, such as
// "pc-q35-11.0" and "pc-q35-11.0+pve2".
func (c *Client) QEMUMachines(ctx context.Context, node string) ([]string, error) {
	if node == "" {
		return nil, fmt.Errorf("node is required")
	}
	var machines []struct {
		ID string `json:"id"`
	}
	if err := c.Do(ctx, "GET", fmt.Sprintf("nodes/%s/capabilities/qemu/machines", node), nil, &machines); err != nil {
		return nil, fmt.Errorf("list QEMU machine versions on node %s: %w", node, err)
	}
	ids := make([]string, 0, len(machines))
	for _, machine := range machines {
		ids = append(ids, machine.ID)
	}
	return ids, nil
}

func validateVMRequest(node string, vmid int) error {
	// A VM ID outside PVE's range names no VM, so no request about it is
	// sent.
	if err := vmlimits.CheckVMID(vmid); err != nil {
		return err
	}
	return validateNodeName(node)
}

// IsCertiStackOwned validates exact base ownership markers; it never accepts a
// substring such as "not-certistack" or "owner=certistack-copy".
func (c *Client) IsCertiStackOwned(ctx context.Context, node string, vmid int) (bool, error) {
	cfg, err := c.GetVMConfig(ctx, node, vmid)
	if err != nil {
		return false, err
	}

	tags, _ := cfg["tags"].(string)
	desc, _ := cfg["description"].(string)

	isOwned := hasExactTag(tags, "certistack") && hasExactDescriptionField(desc, "owner", "certistack")
	return isOwned, nil
}

// IsCertiStackRunOwned additionally binds a VM to the precise journaled run.
// Recovery must use this instead of treating any CertiStack-labelled VM as
// safe to delete after a VMID has been reused.
func (c *Client) IsCertiStackRunOwned(ctx context.Context, node string, vmid int, runID string) (bool, error) {
	if strings.TrimSpace(runID) == "" {
		return false, errors.New("run ID is required for VM ownership verification")
	}
	cfg, err := c.GetVMConfig(ctx, node, vmid)
	if err != nil {
		return false, err
	}
	tags, _ := cfg["tags"].(string)
	desc, _ := cfg["description"].(string)
	return hasExactTag(tags, "certistack") && hasExactTag(tags, runID) &&
		hasExactDescriptionField(desc, "owner", "certistack") &&
		hasExactDescriptionField(desc, "run_id", runID), nil
}

func hasExactTag(tags, want string) bool {
	for _, tag := range strings.FieldsFunc(tags, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' }) {
		if tag == want {
			return true
		}
	}
	return false
}

func hasExactDescriptionField(description, key, want string) bool {
	for _, field := range strings.FieldsFunc(description, func(r rune) bool {
		return r == ';' || r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		if field == key+"="+want {
			return true
		}
	}
	return false
}

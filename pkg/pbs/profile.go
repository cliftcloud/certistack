// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/internal/diskslot"
	"github.com/cliftcloud/certistack/internal/macaddr"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/internal/vmlimits"
	"github.com/cliftcloud/certistack/pkg/attest"
)

// SourceDrive is one backed-up SCSI image, addressed by the PVE slot it must
// occupy when the recovered VM boots.
type SourceDrive struct {
	Slot    string
	Archive string
}

// VMProfile is the intentionally small, safe subset of source VM
// configuration that can be inherited into an isolated recovery VM. Network
// topology, host passthrough, hooks, startup policy, and PVE tags are never
// replayed; only net0's MAC and model are retained so a guest's local network
// profile can still identify its NIC after attachment to the isolated VNet.
type VMProfile struct {
	Cores     int
	Sockets   int
	MemoryMB  int
	BalloonMB int
	// NoBalloon is true for balloon: 0, a VM without a balloon device.
	NoBalloon bool
	// SMBIOS1 and Meta are the source's normalized SMBIOS identity and meta
	// information, and CDROMs its CD-ROM slots, as in VMLayout.
	SMBIOS1    string
	Meta       string
	CDROMs     []string
	CPUWeight  int
	Machine    string
	OSType     string
	BIOS       string
	SCSIHW     string
	MAC        string
	NICModel   string
	SourceTags []string
	// Name is the source VM's name, when it is a valid DNS name, and Agent
	// whether the source has the QEMU guest agent enabled. Neither is
	// inherited; init uses them to suggest a plan.
	Name   string
	Agent  bool
	Drives []SourceDrive
	// Firmware holds the backed-up UEFI variable store (efidisk0) and TPM
	// state (tpmstate0) of a UEFI source VM, in that order.
	Firmware []FirmwareImage
	// BootOrder is the source boot order ("order=" entries, or the legacy
	// bootdisk), including non-disk entries such as net0.
	BootOrder []string
	// CryptMode is the weakest crypt mode among the snapshot's disk
	// archives: encrypt, sign-only or none. SignatureVerified is true when
	// the key was passed, so the PBS client verified the manifest signature.
	CryptMode         string
	SignatureVerified bool
	// NICs are the source NICs other than net0.
	NICs []SourceNIC
	// ExcludedDisks are disks the source excludes from its backups
	// (backup=0), so no restore can include them.
	ExcludedDisks []string
	// Consistency is how consistent the backed-up disks were, as in VMLayout.
	Consistency BackupConsistency

	configuredDisks map[string]bool
	// DiskBytes are the backed-up disks' sizes, as in VMLayout.
	DiskBytes map[string]int64
	// ImageBytes are the sizes of the disks' images, as in VMLayout.
	ImageBytes map[string]int64
}

// FirmwareImage is a backed-up firmware state disk. Options keeps only the
// allowlisted PVE options that describe the image (efitype,
// pre-enrolled-keys and ms-cert for efidisk0; version for tpmstate0), never
// its storage location.
type FirmwareImage struct {
	Slot    string // "efidisk0" or "tpmstate0"
	Archive string // e.g. "drive-efidisk0" or "drive-tpmstate0-backup"
	Options string // e.g. "efitype=4m,pre-enrolled-keys=1" or "version=v2.0"
}

var (
	firmwareArchive = regexp.MustCompile(`^drive-(efidisk0|tpmstate0(?:-backup)?)\.img(?:\.fidx)?$`)
	safePVEValue    = regexp.MustCompile(`^[A-Za-z0-9._+:-]{1,128}$`)
	msCertValue     = regexp.MustCompile(`^[0-9a-z]{1,16}$`)
	// additionalNICKey is net1..net31; net0 is handled on its own.
	additionalNICKey = regexp.MustCompile(`^net([1-9]|[12][0-9]|3[01])$`)
)

// LoadVMProfile reads qemu-server.conf from the exact PBS snapshot and
// discovers every backed-up disk image, on any bus. The configuration blob is treated as
// untrusted input and only the allowlisted fields in VMProfile are parsed.
func (c *Client) LoadVMProfile(ctx context.Context, snapshot, scratchDir string) (VMProfile, error) {
	// The file list comes first: an encrypted snapshot needs its key even
	// for the configuration blob.
	files, err := c.snapshotFiles(ctx, snapshot)
	if err != nil {
		return VMProfile{}, err
	}
	if holdsContainerArchive(files) {
		return VMProfile{}, errContainerBackup
	}
	cryptMode, err := c.checkSnapshotKey(snapshot, files)
	if err != nil {
		return VMProfile{}, err
	}
	if err := c.checkKeyMatches(ctx, snapshot, cryptMode); err != nil {
		return VMProfile{}, err
	}
	data, err := c.restoreSourceConfig(ctx, snapshot, scratchDir, files)
	if err != nil {
		return VMProfile{}, err
	}
	profile, err := ParseVMProfile(data)
	if err != nil {
		return VMProfile{}, err
	}
	if profile.CryptMode, err = ParseSnapshotDiskCryptMode(files); err != nil {
		return VMProfile{}, err
	}
	profile.ImageBytes = ParseSnapshotImageBytes(files)
	profile.SignatureVerified = c.cfg.Keyfile != "" && cryptMode != CryptModeNone

	drives, err := ParseSnapshotDrivesJSON(files)
	if err != nil {
		return VMProfile{}, err
	}
	for slot := range profile.configuredDisks {
		if !containsDriveSlot(drives, slot) {
			return VMProfile{}, fmt.Errorf("source configuration requires backed-up %s, but it is absent from the snapshot", slot)
		}
	}
	if err := checkArchivesAreListed(drives, profile.configuredDisks, profile.ExcludedDisks); err != nil {
		return VMProfile{}, err
	}
	profile.Drives = drives
	if err := attachFirmwareArchives(files, profile.Firmware); err != nil {
		return VMProfile{}, err
	}
	// The log is read by the snapshot's strongest mode, not the weakest
	// disk's (profile.CryptMode, which is what evidence may claim): a snapshot
	// with any encrypted archive reads its log through the authenticated raw
	// route, which refuses a plaintext blob, instead of the decoded route.
	profile.Consistency = c.backupConsistency(ctx, snapshot, cryptMode)
	return profile, nil
}

// VMLayout is what every restore needs from the backup, whatever the plan
// inherits: the firmware (BIOS and, for a UEFI VM, its firmware state
// images), the boot order, and which disks were backed up.
type VMLayout struct {
	BIOS     string
	Firmware []FirmwareImage
	// Machine, SCSIHW and OSType decide whether the guest boots at all: a
	// Windows guest installed on q35 or an LSI controller may not boot on
	// i440fx or virtio-scsi, whose driver it may lack.
	Machine string
	SCSIHW  string
	OSType  string
	// NoBalloon is true when the source VM has no memory balloon device
	// (balloon: 0), which PVE would otherwise add to the sandbox VM.
	NoBalloon bool
	// SMBIOS1 is the source's SMBIOS identity (uuid and the vendor strings),
	// normalized; empty when the backup has none or it is not usable.
	SMBIOS1 string
	// CDROMs are the source's CD-ROM drive slots (ide, sata or scsi). A
	// restore keeps them, so the guest finds the same controllers and
	// drives; the sandbox attaches them empty.
	CDROMs []string
	// Meta is the source's meta information (creation-qemu, ctime),
	// normalized. PVE starts a Windows guest with an unversioned machine type
	// on the machine version of the QEMU that created it, so a restore
	// resolves it from this line.
	Meta string
	// Consistency is how consistent the backed-up disks were, from the
	// snapshot's backup log.
	Consistency BackupConsistency
	// BootOrder is the source boot order, non-disk entries included.
	BootOrder []string
	// Disks are the backed-up disk slots on any bus, in PVE order.
	Disks []string
	// DiskBytes are the backed-up disks' sizes, from their size= option,
	// where the configuration gives one. It is what PVE recorded when the disk
	// was created or last resized through it, so it can differ from the image
	// that was backed up (storage rounding, a resize outside PVE).
	DiskBytes map[string]int64
	// ImageBytes are the sizes of the backed-up disks' images, from the
	// snapshot's manifest, where it lists one (ParseSnapshotImageBytes). This
	// is the length a mapped image must have.
	ImageBytes map[string]int64
	// CryptMode is the weakest crypt mode among the snapshot's disk
	// archives; SignatureVerified is true when the key verified its manifest.
	CryptMode         string
	SignatureVerified bool
	// ExcludedDisks are disks the source excludes from its backups
	// (backup=0), so no restore can include them.
	ExcludedDisks []string
	// NICs are the source NICs other than net0.
	NICs []SourceNIC
	// MAC and NICModel are net0's identity, SourceTags the PVE tags, for
	// network recovery and evidence.
	MAC        string
	NICModel   string
	SourceTags []string
}

// LoadVMLayout reads only the layout of the exact PBS snapshot, for plans
// that do not inherit the rest of the source configuration. Firmware state
// is part of what was backed up (a UEFI VM restored without it cannot boot),
// the boot order says which disk to boot, and the disk list lets a partial
// restore be reported as partial. Every other setting in the file is
// ignored.
func (c *Client) LoadVMLayout(ctx context.Context, snapshot, scratchDir string) (VMLayout, error) {
	files, err := c.snapshotFiles(ctx, snapshot)
	if err != nil {
		return VMLayout{}, err
	}
	if holdsContainerArchive(files) {
		return VMLayout{}, errContainerBackup
	}
	cryptMode, err := c.checkSnapshotKey(snapshot, files)
	if err != nil {
		return VMLayout{}, err
	}
	if err := c.checkKeyMatches(ctx, snapshot, cryptMode); err != nil {
		return VMLayout{}, err
	}
	data, err := c.restoreSourceConfig(ctx, snapshot, scratchDir, files)
	if err != nil {
		return VMLayout{}, err
	}
	layout, err := ParseVMLayout(data)
	if err != nil {
		return VMLayout{}, err
	}
	if layout.CryptMode, err = ParseSnapshotDiskCryptMode(files); err != nil {
		return VMLayout{}, err
	}
	layout.ImageBytes = ParseSnapshotImageBytes(files)
	layout.SignatureVerified = c.cfg.Keyfile != "" && cryptMode != CryptModeNone
	if err := attachFirmwareArchives(files, layout.Firmware); err != nil {
		return VMLayout{}, err
	}
	// A disk the configuration marks as backed up must have its archive; a
	// snapshot without one is incomplete and would restore a partial VM.
	archives, err := ParseSnapshotDrivesJSON(files)
	if err != nil {
		return VMLayout{}, err
	}
	listed := make(map[string]bool, len(layout.Disks))
	for _, slot := range layout.Disks {
		if !containsDriveSlot(archives, slot) {
			return VMLayout{}, fmt.Errorf("source configuration requires backed-up %s, but it is absent from the snapshot", slot)
		}
		listed[slot] = true
	}
	if err := checkArchivesAreListed(archives, listed, layout.ExcludedDisks); err != nil {
		return VMLayout{}, err
	}
	// The log is read by the snapshot's strongest mode, not the weakest
	// disk's (profile.CryptMode, which is what evidence may claim): a snapshot
	// with any encrypted archive reads its log through the authenticated raw
	// route, which refuses a plaintext blob, instead of the decoded route.
	layout.Consistency = c.backupConsistency(ctx, snapshot, cryptMode)
	return layout, nil
}

// ParseVMLayout parses only bios, efidisk0, tpmstate0, machine, scsihw,
// ostype, balloon, smbios1, boot, bootdisk and the disk slots from a Proxmox qemu-server.conf,
// with the same rules as ParseVMProfile.
func ParseVMLayout(data []byte) (VMLayout, error) {
	if len(data) > maxRestoredConfigBytes {
		return VMLayout{}, errConfigTooLarge(len(data))
	}
	if err := checkConfigText(data); err != nil {
		return VMLayout{}, err
	}
	var layout VMLayout
	var boot, bootdisk string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			break // snapshot sections describe other states of the VM
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "bios":
			if value != "seabios" && value != "ovmf" {
				return VMLayout{}, fmt.Errorf("unsupported source BIOS %q", value)
			}
			layout.BIOS = value
		case "machine":
			machine, err := parseMachine(value)
			if err != nil {
				return VMLayout{}, err
			}
			layout.Machine = machine
		case "scsihw", "ostype":
			if !safePVEValue.MatchString(value) {
				return VMLayout{}, fmt.Errorf("invalid source %s %q", key, value)
			}
			if key == "scsihw" {
				layout.SCSIHW = value
			} else {
				layout.OSType = value
			}
		case "balloon":
			layout.NoBalloon = value == "0"
		case "smbios1":
			layout.SMBIOS1 = parseSMBIOS1(value)
		case "meta":
			layout.Meta = parseMeta(value)
		case "boot":
			boot = value
		case "bootdisk":
			bootdisk = value
		case "net0":
			// Only network recovery needs net0's identity, and it says so
			// when it is missing; a layout read never fails over it.
			if model, mac, err := sourceNIC(key, value); err == nil {
				layout.MAC, layout.NICModel = mac, model
			}
		case "tags":
			layout.SourceTags = splitSourceTags(value)
		case "efidisk0", "tpmstate0":
			image, err := parseFirmwareDisk(key, value)
			if err != nil {
				return VMLayout{}, err
			}
			layout.Firmware = append(layout.Firmware, image)
		default:
			if diskslot.Valid(key) && sourceDiskIsBackedUp(value) {
				layout.Disks = append(layout.Disks, key)
				if size, ok := diskSizeBytes(value); ok {
					if layout.DiskBytes == nil {
						layout.DiskBytes = map[string]int64{}
					}
					layout.DiskBytes[key] = size
				}
			} else if diskslot.Valid(key) && sourceDiskIsExcluded(value) {
				layout.ExcludedDisks = append(layout.ExcludedDisks, key)
			} else if sourceCDROM(key, value) {
				layout.CDROMs = append(layout.CDROMs, key)
			}
			// An unusable NIC keeps its slot without a model or MAC, so it is
			// reported as omitted, or refused if the plan asks to attach it.
			if nic, ok, nicErr := additionalNIC(key, value); ok && nicErr != nil {
				layout.NICs = append(layout.NICs, SourceNIC{Slot: key})
			} else if ok {
				layout.NICs = append(layout.NICs, nic)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return VMLayout{}, fmt.Errorf("read source VM configuration: %w", err)
	}
	sortNICs(layout.NICs)
	sort.Slice(layout.Firmware, func(i, j int) bool { return layout.Firmware[i].Slot < layout.Firmware[j].Slot })
	diskslot.Sort(layout.Disks)
	diskslot.Sort(layout.CDROMs)
	layout.BootOrder = diskslot.ParseBootOrder(boot, bootdisk)
	layout.SCSIHW, layout.OSType = withPVEDefaults(layout.SCSIHW, layout.OSType)
	return layout, nil
}

// restoreSourceConfig restores the snapshot's qemu-server.conf into a
// private temporary directory and returns its contents, at most
// maxRestoredConfigBytes of them. files is the snapshot's listing.
func (c *Client) restoreSourceConfig(ctx context.Context, snapshot, scratchDir string, files []byte) ([]byte, error) {
	if !validSnapshotPath(snapshot) {
		return nil, fmt.Errorf("invalid PBS snapshot path %q", snapshot)
	}
	if err := checkConfigSize(files); err != nil {
		return nil, err
	}
	if holdsNoConfiguration(files) {
		return nil, errNoConfiguration
	}
	if scratchDir == "" {
		scratchDir = sysutil.DefaultScratchDir
	}
	if !filepath.IsAbs(scratchDir) {
		return nil, fmt.Errorf("scratch directory must be absolute")
	}

	profileDir, err := os.MkdirTemp(scratchDir, "certistack-source-config-")
	if err != nil {
		return nil, fmt.Errorf("create source profile directory: %w", err)
	}
	defer os.RemoveAll(profileDir)
	// The restore client owns creation of this path and can refuse accidental
	// overwrite. The private parent directory is removed immediately after use.
	configPath := filepath.Join(profileDir, "qemu-server.conf")

	keyArgs, err := c.restoreKeyArgs(ctx, snapshot)
	if err != nil {
		return nil, err
	}
	args := append([]string{"restore"}, c.targetArgs()...)
	args = append(args, keyArgs...)
	args = append(args, snapshot, "qemu-server.conf.blob", configPath)
	if output, err := c.run(ctx, 30*time.Second, args...); err != nil {
		return nil, commandFailure("restore PBS VM configuration", err, []byte(output))
	}

	// The advertised size is only advice, and a compressed blob restores to
	// more than it lists: the file is opened once, must be a regular file, and
	// is read through the same limit, which is exceeded by one byte at most.
	data, err := attest.ReadRegularFile(configPath, "restored PBS VM configuration", maxRestoredConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("read restored PBS VM configuration: %w", err)
	}
	return data, nil
}

// maxRestoredConfigBytes bounds a VM configuration restored from a snapshot.
// A real one is a few KiB, and the cluster file system that holds them allows
// no file near this size; a snapshot whose configuration is larger is
// corrupt or hostile, and is refused before it is parsed, not parsed twice
// over as a string.
const maxRestoredConfigBytes = 1 << 20

// checkArchivesAreListed refuses a snapshot that holds a disk archive its
// configuration does not list as a backed-up disk: the configuration is then
// not that snapshot's (a file of another kind, or empty), and restoring the
// archive with its hardware would be a guess. listed holds the backed-up disk
// slots the configuration names, excluded the ones it marks backup=0.
func checkArchivesAreListed(archives []SourceDrive, listed map[string]bool, excluded []string) error {
	for _, drive := range archives {
		if listed[drive.Slot] {
			continue
		}
		if slices.Contains(excluded, drive.Slot) {
			return fmt.Errorf("the snapshot holds %s but its configuration excludes %s from backups (backup=0)", drive.Archive, drive.Slot)
		}
		return fmt.Errorf("the snapshot holds %s but its configuration lists no %s", drive.Archive, drive.Slot)
	}
	return nil
}

// errNotAConfiguration is the refusal of a configuration blob that is not
// text. A real qemu-server.conf is UTF-8 with tabs and line ends and, on the
// lines the parser reads, nothing else in the control range; anything else is
// a file of another kind, which the line parsers would read as a configuration
// with no keys.
var errNotAConfiguration = errors.New("the backup's VM configuration (qemu-server.conf) is not a Proxmox VE configuration: it holds binary data")

// checkConfigText refuses data that is not text: a NUL byte anywhere, and, on
// every line that is not a comment, invalid UTF-8 or a control character other
// than tab, CR and LF. A comment (a line starting with #) holds the VM's
// description, which the parser ignores and which can hold any character the
// operator typed, so a control character there does not refuse a real backup.
// The name: line is the other place a description's characters can reach the
// file: the parser keeps a name only when it is a DNS name, and drops any other.
func checkConfigText(data []byte) error {
	if bytes.IndexByte(data, 0) >= 0 {
		return errNotAConfiguration
	}
	for rest := data; len(rest) > 0; {
		line := rest
		if end := bytes.IndexByte(rest, '\n'); end >= 0 {
			line, rest = rest[:end], rest[end+1:]
		} else {
			rest = nil
		}
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("#")) {
			continue
		}
		if key, _, found := bytes.Cut(trimmed, []byte(":")); found && string(bytes.TrimSpace(key)) == "name" {
			continue
		}
		if !utf8.Valid(line) {
			return errNotAConfiguration
		}
		for _, r := range string(line) {
			if unicode.IsControl(r) && r != '\t' && r != '\r' {
				return errNotAConfiguration
			}
		}
	}
	return nil
}

func errConfigTooLarge(size int) error {
	return fmt.Errorf("the source VM configuration is %d bytes, more than the %d bytes a Proxmox VE configuration can be", size, maxRestoredConfigBytes)
}

// ParseSnapshotConfigBytes is the size `snapshot files` lists for the
// snapshot's qemu-server.conf.blob, and whether it lists a usable one. The
// size is of the blob as stored, so it advises, it does not bound: a blob
// restores to more than its stored size when it is compressed.
func ParseSnapshotConfigBytes(data []byte) (int64, bool) {
	var files []struct {
		Filename string          `json:"filename"`
		Size     json.RawMessage `json:"size"`
	}
	if json.Unmarshal(data, &files) != nil {
		return 0, false
	}
	var size int64
	found := false
	for _, file := range files {
		if file.Filename != "qemu-server.conf.blob" {
			continue
		}
		var number json.Number
		if json.Unmarshal(file.Size, &number) != nil {
			continue
		}
		n, err := number.Int64()
		if err != nil || n < 0 {
			continue
		}
		if !found || n > size {
			size, found = n, true
		}
	}
	return size, found
}

// errContainerBackup is the refusal of a snapshot that holds a container's
// file archive and no VM disk: PBS keeps a container's backup in a root.pxar
// (a split one in newer PBS: root.mpxar and root.ppxar), and nothing of a VM.
var errContainerBackup = errors.New("the backup holds a container's file archive (root.pxar), not a VM disk: CertiStack restore-tests VMs only")

var containerArchive = regexp.MustCompile(`^root\.[mp]?pxar(\.|$)`)

// holdsContainerArchive reports whether the snapshot's file list names a
// container's file archive and no VM disk image. A list that cannot be read is
// not that: it is left to the steps that read it next.
func holdsContainerArchive(files []byte) bool {
	var listed []struct {
		Filename string `json:"filename"`
	}
	if json.Unmarshal(files, &listed) != nil {
		return false
	}
	container := false
	for _, file := range listed {
		if _, disk := diskslot.ArchiveSlot(file.Filename); disk {
			return false
		}
		container = container || containerArchive.MatchString(file.Filename)
	}
	return container
}

// holdsDiskImage reports whether the snapshot has no file list to say
// otherwise, or lists a VM disk image. One that lists none is not a backup of
// a VM, whatever its group: a container's backup is a root.pxar and its
// configuration, and a restore-test has nothing to boot from it.
func (e snapshotListEntry) holdsDiskImage() bool {
	if e.Files == nil {
		return true
	}
	for _, file := range *e.Files {
		if _, disk := diskslot.ArchiveSlot(file.Filename); disk {
			return true
		}
	}
	return false
}

// errNoConfiguration is the refusal of a snapshot that lists no
// qemu-server.conf.blob. Every run reads the configuration, whatever
// use_backup_config says, so the plan has no way around it.
var errNoConfiguration = errors.New("the backup holds no VM configuration (qemu-server.conf): it is not a backup PVE made of a VM; choose a snapshot that a Proxmox VE backup job made of the VM")

// holdsNoConfiguration reports whether the snapshot's file list is a list that
// names no qemu-server.conf.blob. A listing that cannot be read is not that: it
// is left to the steps that read it next, which say what is wrong with it.
func holdsNoConfiguration(files []byte) bool {
	var listed []struct {
		Filename string `json:"filename"`
	}
	if json.Unmarshal(files, &listed) != nil {
		return false
	}
	for _, file := range listed {
		if file.Filename == "qemu-server.conf.blob" {
			return false
		}
	}
	return true
}

// checkConfigSize refuses a snapshot whose listing gives its configuration
// blob more bytes than a configuration can have, before anything is restored.
func checkConfigSize(files []byte) error {
	if size, listed := ParseSnapshotConfigBytes(files); listed && size > maxRestoredConfigBytes {
		return fmt.Errorf("the snapshot lists its VM configuration (qemu-server.conf.blob) at %d bytes, more than the %d bytes a Proxmox VE configuration can be; it is not restored", size, maxRestoredConfigBytes)
	}
	return nil
}

// attachFirmwareArchives fills in each firmware image's archive from the
// snapshot's file list, failing closed when one was configured but not
// backed up.
func attachFirmwareArchives(files []byte, firmware []FirmwareImage) error {
	if len(firmware) == 0 {
		return nil
	}
	archives, err := ParseSnapshotFirmwareJSON(files)
	if err != nil {
		return err
	}
	for i := range firmware {
		archive, found := archives[firmware[i].Slot]
		if !found {
			return fmt.Errorf("source configuration has %s, but the snapshot has no archive for it", firmware[i].Slot)
		}
		firmware[i].Archive = archive
	}
	return nil
}

// ParseSnapshotFirmwareJSON returns the firmware state archives in a
// snapshot, keyed by slot. PVE stores the TPM state as
// drive-tpmstate0-backup; drive-tpmstate0 is accepted as well.
func ParseSnapshotFirmwareJSON(data []byte) (map[string]string, error) {
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("parse PBS snapshot files JSON: %w", err)
	}
	filenames := make(map[string]bool)
	collectFilenames(decoded, filenames)
	archives := make(map[string]string)
	for filename := range filenames {
		match := firmwareArchive.FindStringSubmatch(filename)
		if match == nil {
			continue
		}
		slot := strings.TrimSuffix(match[1], "-backup")
		if previous, found := archives[slot]; found && previous != "drive-"+match[1] {
			return nil, fmt.Errorf("snapshot has two archives for %s", slot)
		}
		archives[slot] = "drive-" + match[1]
	}
	return archives, nil
}

func (c *Client) snapshotFiles(ctx context.Context, snapshot string) ([]byte, error) {
	if !validSnapshotPath(snapshot) {
		return nil, fmt.Errorf("invalid PBS snapshot path %q", snapshot)
	}
	// `snapshot files` and `snapshot list` take no key; passing one makes
	// the PBS client refuse the command.
	args := append([]string{"snapshot", "files"}, c.targetArgs()...)
	args = append(args, snapshot, "--output-format", "json")
	output, err := c.runLimited(ctx, 30*time.Second, pbsListOutputLimit, args...)
	if err != nil {
		// Here, and only here, the client's ENOENT means the snapshot has no
		// directory on PBS: a pinned snapshot that retention pruned, or one
		// that never existed. Elsewhere (a map, say) it means other things.
		if strings.Contains(output, snapshotMissing) {
			return nil, c.missingSnapshot(ctx, snapshot)
		}
		return nil, commandFailure("list PBS snapshot files", err, []byte(output))
	}
	return []byte(output), nil
}

// snapshotMissing is what proxmox-backup-client prints, and all it prints,
// for `snapshot files` of a snapshot PBS has no directory for ("Error:
// ENOENT: No such file or directory"; client 4.2.5, server 4.2.6).
const snapshotMissing = "ENOENT: No such file or directory"

// missingSnapshot explains a snapshot PBS has no directory for, from a new
// listing of its backup group: whether the group has no snapshots at all, or
// only this one is gone and which one is now the newest. The repository is
// never named: its user part can be a token identity.
func (c *Client) missingSnapshot(ctx context.Context, snapshot string) error {
	group := path.Dir(snapshot)
	where := "on PBS"
	if c.cfg.Namespace != "" {
		where = fmt.Sprintf("in PBS namespace %q", c.cfg.Namespace)
	}
	args := append([]string{"snapshot", "list", group, "--output-format", "json"}, c.targetArgs()...)
	output, err := c.run(ctx, 30*time.Second, args...)
	if err != nil {
		return fmt.Errorf("PBS snapshot %s does not exist %s (PBS has no such snapshot directory), and its backup group could not be listed to say more: %w; pin a current snapshot or use snapshot: latest", snapshot, where, listFailure("list PBS snapshots for "+group, err, []byte(output)))
	}
	listed, err := listedSnapshots([]byte(output), group)
	if err != nil {
		return fmt.Errorf("PBS snapshot %s does not exist %s (PBS has no such snapshot directory), and its backup group's listing could not be read: %w", snapshot, where, err)
	}
	switch {
	case len(listed) == 0:
		return fmt.Errorf("PBS snapshot %s does not exist %s: its backup group %s has no snapshots there, or none this PBS user may see; check source_vmid, the snapshot and the namespace", snapshot, where, group)
	case listed[snapshot]:
		return fmt.Errorf("PBS lists snapshot %s %s but has no directory for it; it was probably pruned while CertiStack read it: run again, pin a current snapshot, or use snapshot: latest", snapshot, where)
	}
	newest, _, err := latestCompleteSnapshot([]byte(output), group)
	if err != nil {
		return fmt.Errorf("PBS snapshot %s no longer exists %s (PBS retention may have pruned it), and %v; pin a snapshot that exists", snapshot, where, err)
	}
	return fmt.Errorf("PBS snapshot %s no longer exists %s; PBS retention may have pruned it. The newest snapshot of %s is %s: pin a current snapshot, or use snapshot: latest", snapshot, where, group, newest)
}

// listedSnapshots is every snapshot path a `snapshot list` of group shows,
// complete or not.
func listedSnapshots(data []byte, group string) (map[string]bool, error) {
	var entries []snapshotListEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse PBS snapshot list JSON: %w", err)
	}
	listed := make(map[string]bool)
	for _, entry := range entries {
		if entry.BackupType+"/"+entry.BackupID != group {
			continue
		}
		backupTime, err := parseBackupTime(entry.BackupTime)
		if err != nil {
			return nil, fmt.Errorf("parse backup time for %s: %w", group, err)
		}
		listed[group+"/"+backupTime.UTC().Format(time.RFC3339)] = true
	}
	return listed, nil
}

func (c *Client) run(ctx context.Context, fallbackTimeout time.Duration, args ...string) (string, error) {
	return c.runLimited(ctx, fallbackTimeout, pbsCommandOutputLimit, args...)
}

// runLimited is run with the ceiling on the client's output.
func (c *Client) runLimited(ctx context.Context, fallbackTimeout time.Duration, limit int, args ...string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, fallbackTimeout)
	defer cancel()
	cmd := c.command(commandCtx, args)
	output, err := process.CombinedOutputLimited(cmd, limit)
	return strings.TrimSpace(string(output)), err
}

// ParseVMProfile parses a Proxmox qemu-server.conf. It ignores every source
// setting outside the safe runtime profile. Every backed-up disk, on any
// bus, is recorded so LoadVMProfile can require its archive and CertiStack
// never silently drops a source data disk.
func ParseVMProfile(data []byte) (VMProfile, error) {
	if len(data) > maxRestoredConfigBytes {
		return VMProfile{}, errConfigTooLarge(len(data))
	}
	if err := checkConfigText(data); err != nil {
		return VMProfile{}, err
	}
	profile := VMProfile{configuredDisks: make(map[string]bool)}
	var err error
	var boot, bootdisk string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			break // snapshot and pending sections describe other states of the VM
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "cores":
			if profile.Cores, err = parseProfileInt("cores", value, 1, vmlimits.MaxCores); err != nil {
				return VMProfile{}, err
			}
		case "sockets":
			if profile.Sockets, err = parseProfileInt("sockets", value, 1, vmlimits.MaxSockets); err != nil {
				return VMProfile{}, err
			}
		case "memory":
			if profile.MemoryMB, err = parseProfileInt("memory", value, vmlimits.MinMemoryMB, vmlimits.MaxMemoryMB); err != nil {
				return VMProfile{}, err
			}
		case "balloon":
			if profile.BalloonMB, err = parseProfileInt("balloon", value, 0, vmlimits.MaxBalloonMB); err != nil {
				return VMProfile{}, err
			}
			profile.NoBalloon = profile.BalloonMB == 0
		case "smbios1":
			profile.SMBIOS1 = parseSMBIOS1(value)
		case "meta":
			profile.Meta = parseMeta(value)
		case "cpuunits":
			if profile.CPUWeight, err = parseProfileInt("cpuunits", value, 1, vmlimits.MaxCPUWeight); err != nil {
				return VMProfile{}, err
			}
		case "machine":
			if profile.Machine, err = parseMachine(value); err != nil {
				return VMProfile{}, err
			}
		case "ostype":
			if !safePVEValue.MatchString(value) {
				return VMProfile{}, fmt.Errorf("invalid source guest OS type %q", value)
			}
			profile.OSType = value
		case "bios":
			if value != "seabios" && value != "ovmf" {
				return VMProfile{}, fmt.Errorf("unsupported source BIOS %q", value)
			}
			profile.BIOS = value
		case "scsihw":
			if !safePVEValue.MatchString(value) {
				return VMProfile{}, fmt.Errorf("invalid source SCSI controller %q", value)
			}
			profile.SCSIHW = value
		case "tags":
			profile.SourceTags = splitSourceTags(value)
		case "name":
			if vmName.MatchString(value) {
				profile.Name = value
			}
		case "agent":
			profile.Agent = agentEnabled(value)
		case "boot":
			boot = value
		case "bootdisk":
			bootdisk = value
		case "net0":
			model, mac, macErr := sourceNIC(key, value)
			if macErr != nil {
				return VMProfile{}, macErr
			}
			profile.MAC = mac
			profile.NICModel = model
		case "efidisk0", "tpmstate0":
			image, imageErr := parseFirmwareDisk(key, value)
			if imageErr != nil {
				return VMProfile{}, imageErr
			}
			profile.Firmware = append(profile.Firmware, image)
		default:
			if diskslot.Valid(key) && sourceDiskIsBackedUp(value) {
				profile.configuredDisks[key] = true
				if size, ok := diskSizeBytes(value); ok {
					if profile.DiskBytes == nil {
						profile.DiskBytes = map[string]int64{}
					}
					profile.DiskBytes[key] = size
				}
			} else if diskslot.Valid(key) && sourceDiskIsExcluded(value) {
				profile.ExcludedDisks = append(profile.ExcludedDisks, key)
			} else if sourceCDROM(key, value) {
				profile.CDROMs = append(profile.CDROMs, key)
			}
			// As in ParseVMLayout: an unusable NIC after net0 keeps only
			// its slot, so it is reported as omitted, or refused if the plan
			// asks to attach it. It never refuses the VM on its own.
			if nic, ok, nicErr := additionalNIC(key, value); ok && nicErr != nil {
				profile.NICs = append(profile.NICs, SourceNIC{Slot: key})
			} else if ok {
				profile.NICs = append(profile.NICs, nic)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return VMProfile{}, fmt.Errorf("read source VM configuration: %w", err)
	}
	diskslot.Sort(profile.CDROMs)
	// efidisk0 sorts before tpmstate0, whatever the order in the file.
	sort.Slice(profile.Firmware, func(i, j int) bool { return profile.Firmware[i].Slot < profile.Firmware[j].Slot })
	sortNICs(profile.NICs)
	profile.BootOrder = diskslot.ParseBootOrder(boot, bootdisk)
	profile.SCSIHW, profile.OSType = withPVEDefaults(profile.SCSIHW, profile.OSType)
	return profile, nil
}

// withPVEDefaults fills in what PVE uses when the configuration has no
// scsihw or ostype line: the lsi controller and "other". A guest created
// without them runs on those, not on CertiStack's own defaults
// (virtio-scsi-single, l26), and a Windows guest on lsi may have no
// virtio-scsi driver.
func withPVEDefaults(scsiHW, osType string) (string, string) {
	if scsiHW == "" {
		scsiHW = "lsi"
	}
	if osType == "" {
		osType = "other"
	}
	return scsiHW, osType
}

var (
	smbiosUUID = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	// smbiosString is PVE's pattern for the SMBIOS strings, base64-encoded
	// or not.
	smbiosString = regexp.MustCompile(`^[A-Za-z0-9+/]{1,512}={0,2}$`)
)

// parseSMBIOS1 reads PVE's smbios1 property string. A restore keeps it
// (qmrestore regenerates the UUID only with --unique), and a guest can tell
// a changed SMBIOS identity from its own. The uuid is required and every
// other field must be one PVE accepts; unknown or unusable fields are
// dropped, and without a valid uuid nothing is carried, so the sandbox VM
// gets a new identity instead of the run failing.
func parseSMBIOS1(value string) string {
	var uuid string
	var fields []string
	for _, part := range strings.Split(value, ",") {
		name, option, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch name {
		case "uuid":
			if smbiosUUID.MatchString(option) {
				uuid = option
			}
		case "base64":
			if option == "0" || option == "1" {
				fields = append(fields, name+"="+option)
			}
		case "manufacturer", "product", "version", "serial", "sku", "family":
			if smbiosString.MatchString(option) {
				fields = append(fields, name+"="+option)
			}
		}
	}
	if uuid == "" {
		return ""
	}
	return strings.Join(append([]string{"uuid=" + uuid}, fields...), ",")
}

var (
	metaQEMUVersion = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3})?$`)
	metaCtime       = regexp.MustCompile(`^[0-9]{1,12}$`)
)

// parseMeta keeps the two fields of PVE's meta property: creation-qemu,
// the QEMU version that created the VM, and ctime. Anything else, or a
// value PVE would not have written, is dropped; without creation-qemu
// nothing is carried.
func parseMeta(value string) string {
	var qemu, ctime string
	for _, part := range strings.Split(value, ",") {
		name, option, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch {
		case name == "creation-qemu" && metaQEMUVersion.MatchString(option):
			qemu = option
		case name == "ctime" && metaCtime.MatchString(option):
			ctime = option
		}
	}
	if qemu == "" {
		return ""
	}
	if ctime == "" {
		return "creation-qemu=" + qemu
	}
	return "creation-qemu=" + qemu + ",ctime=" + ctime
}

// SMBIOSUUID returns the uuid of a normalized smbios1 string.
func SMBIOSUUID(smbios1 string) string {
	for _, part := range strings.Split(smbios1, ",") {
		if name, option, _ := strings.Cut(part, "="); name == "uuid" {
			return option
		}
	}
	return ""
}

// machineOptions are the machine property options carried over, with their
// allowed values. Any other option is dropped.
var machineOptions = map[string]map[string]bool{
	"viommu":    {"intel": true, "virtio": true},
	"enable-s3": {"0": true, "1": true},
	"enable-s4": {"0": true, "1": true},
}

// parseMachine reads PVE's machine property string ("[type=]<type>
// [,viommu=<intel|virtio>]..."). The type must be a plain PVE value; known
// options keep their allowlisted values and unknown ones are dropped, so a
// newer PVE option never refuses a VM.
func parseMachine(value string) (string, error) {
	parts := strings.Split(value, ",")
	machineType := strings.TrimPrefix(strings.TrimSpace(parts[0]), "type=")
	if !safePVEValue.MatchString(machineType) {
		return "", fmt.Errorf("invalid source machine type %q", value)
	}
	normalized := []string{machineType}
	for _, part := range parts[1:] {
		name, option, _ := strings.Cut(strings.TrimSpace(part), "=")
		if allowed, known := machineOptions[name]; known && allowed[option] {
			normalized = append(normalized, name+"="+option)
		}
	}
	return strings.Join(normalized, ","), nil
}

// parseFirmwareDisk keeps the options that describe a firmware state image
// and drops everything else (volume, size, format). A firmware disk left out
// of the backup fails closed: the source firmware state could not be
// reproduced, and a silently fresh variable store or TPM would validate a
// different machine than the one backed up.
func parseFirmwareDisk(key, value string) (FirmwareImage, error) {
	if !sourceDiskIsBackedUp(value) {
		return FirmwareImage{}, fmt.Errorf("source %s is excluded from the backup; its firmware state cannot be restored", key)
	}
	var options []string
	for i, part := range strings.Split(value, ",") {
		name, option, found := strings.Cut(strings.TrimSpace(part), "=")
		if i == 0 && (!found || name == "file") {
			continue // the source volume
		}
		switch {
		case key == "efidisk0" && name == "efitype":
			if option != "2m" && option != "4m" {
				return FirmwareImage{}, fmt.Errorf("unsupported source efidisk0 efitype %q", option)
			}
		case key == "efidisk0" && name == "pre-enrolled-keys":
			if option != "0" && option != "1" {
				return FirmwareImage{}, fmt.Errorf("invalid source efidisk0 pre-enrolled-keys %q", option)
			}
		case key == "efidisk0" && name == "ms-cert":
			if !msCertValue.MatchString(option) {
				return FirmwareImage{}, fmt.Errorf("invalid source efidisk0 ms-cert %q", option)
			}
		case key == "tpmstate0" && name == "version":
			if option != "v1.2" && option != "v2.0" {
				return FirmwareImage{}, fmt.Errorf("unsupported source tpmstate0 version %q", option)
			}
		default:
			continue
		}
		options = append(options, name+"="+option)
	}
	return FirmwareImage{Slot: key, Options: strings.Join(options, ",")}, nil
}

// sourceNIC extracts the model and L2 identity from the primary source NIC.
// Both are required to preserve guest-side interface naming; a MAC alone is
// not sufficient when a guest has a driver-bound connection profile.
func sourceNIC(key, value string) (string, string, error) {
	device := strings.TrimSpace(strings.SplitN(value, ",", 2)[0])
	model, rawMAC, ok := strings.Cut(device, "=")
	if !ok || model == "" || rawMAC == "" {
		return "", "", fmt.Errorf("source %s must declare a NIC model and MAC address", key)
	}
	if !supportedNICModels[model] {
		return "", "", fmt.Errorf("unsupported source %s model %q", key, model)
	}
	// The same rule as the plan and the PVE request: six octets that name one
	// interface, not the all-zero, broadcast or a multicast address.
	mac, err := macaddr.Canonical(rawMAC)
	if err != nil {
		return "", "", fmt.Errorf("invalid source %s MAC address %q: %v", key, rawMAC, err)
	}
	return model, mac, nil
}

// supportedNICModels are the NIC models Proxmox VE offers. The e1000
// variants matter for VMs migrated from VMware (e1000-82545em).
var supportedNICModels = map[string]bool{
	"virtio": true, "e1000": true, "e1000-82540em": true, "e1000-82544gc": true,
	"e1000-82545em": true, "e1000e": true, "igb": true, "i82551": true,
	"i82557b": true, "i82559er": true, "ne2k_pci": true, "ne2k_isa": true,
	"pcnet": true, "rtl8139": true, "vmxnet3": true,
}

// SourceNIC is a source NIC other than net0: its slot, model and MAC. Its
// bridge, VLAN and firewall settings are never replayed.
type SourceNIC struct {
	Slot  string
	Model string
	MAC   string
}

// additionalNIC parses netN (N >= 1). Another value (net0, anything else)
// reports ok false.
func additionalNIC(key, value string) (SourceNIC, bool, error) {
	if !additionalNICKey.MatchString(key) {
		return SourceNIC{}, false, nil
	}
	model, mac, err := sourceNIC(key, value)
	if err != nil {
		return SourceNIC{}, true, err
	}
	return SourceNIC{Slot: key, Model: model, MAC: mac}, true, nil
}

func sortNICs(nics []SourceNIC) {
	sort.Slice(nics, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.TrimPrefix(nics[i].Slot, "net"))
		b, _ := strconv.Atoi(strings.TrimPrefix(nics[j].Slot, "net"))
		return a < b
	})
}

// profileInts names, for each number a backup's configuration gives, the
// plan key that sets it, and its unit.
var profileInts = map[string]struct{ planKey, unit string }{
	"cores":    {"hardware_overrides.cores", ""},
	"sockets":  {"hardware_overrides.sockets", ""},
	"memory":   {"hardware_overrides.memory_mb", " MiB"},
	"balloon":  {"hardware_overrides.balloon_mb", " MiB"},
	"cpuunits": {"hardware_overrides.cpu_weight", ""},
}

// parseProfileInt reads a number of the backup's configuration within PVE's
// range. A refusal names the value, the range, and the way out: a plan that
// does not take its hardware from the backup (use_backup_config: false)
// never reads the value, and gives its own in the plan key.
func parseProfileInt(name, value string, minimum, maximum int) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err == nil && parsed >= minimum && parsed <= maximum {
		return parsed, nil
	}
	info := profileInts[name]
	wayOut := "; set use_backup_config: false"
	if info.planKey != "" {
		wayOut += " and " + info.planKey + " in the plan to give it yourself"
	}
	if err != nil {
		return 0, fmt.Errorf("the backup's configuration has %s %q, which is not a whole number (PVE allows %d to %d%s)%s", name, value, minimum, maximum, info.unit, wayOut)
	}
	relation := "more than"
	if parsed < minimum {
		relation = "less than"
	}
	return 0, fmt.Errorf("the backup's configuration has %s %d%s, %s PVE allows (%d to %d%s)%s", name, parsed, info.unit, relation, minimum, maximum, info.unit, wayOut)
}

func sourceDiskIsBackedUp(value string) bool {
	return !strings.Contains(value, "backup=0") && !strings.Contains(value, "media=cdrom")
}

// maxSourceDiskBytes bounds a disk size read from a backup's configuration
// at 1 PiB, far above any real VM disk, so that sizes, and a plan's sums of
// them, stay well inside int64.
const maxSourceDiskBytes = 1 << 50

// pveSize is the form PVE writes a disk size in: digits, an optional
// fraction, and an optional binary unit.
var pveSize = regexp.MustCompile(`^([0-9]{1,20})(\.[0-9]{1,20})?([KkMmGgTt]?)$`)

// diskSizeBytes reads a PVE drive's size= option ("size=40G"; K, M, G and T
// are binary units, and a bare number is bytes). A size that is not in that
// form, or is larger than any real disk, is unknown: it is reported as
// absent, never as a number. strconv.ParseFloat alone accepted NaN, Inf and
// exponents, whose conversion to int64 gave a negative size.
func diskSizeBytes(value string) (int64, bool) {
	for _, option := range strings.Split(value, ",") {
		size, ok := strings.CutPrefix(strings.TrimSpace(option), "size=")
		if !ok || size == "" {
			continue
		}
		match := pveSize.FindStringSubmatch(size)
		if match == nil {
			return 0, false
		}
		unit := float64(1)
		switch strings.ToUpper(match[3]) {
		case "K":
			unit = 1 << 10
		case "M":
			unit = 1 << 20
		case "G":
			unit = 1 << 30
		case "T":
			unit = 1 << 40
		}
		n, err := strconv.ParseFloat(match[1]+match[2], 64)
		if err != nil {
			return 0, false
		}
		bytes := n * unit
		// Checked before the conversion: a float beyond int64 converts to
		// an arbitrary (on amd64, the most negative) integer.
		if bytes < 0 || bytes > maxSourceDiskBytes {
			return 0, false
		}
		return int64(bytes), true
	}
	return 0, false
}

// sourceCDROM reports a CD-ROM drive; virtio has none.
func sourceCDROM(key, value string) bool {
	return diskslot.Valid(key) && !strings.HasPrefix(key, "virtio") && strings.Contains(value, "media=cdrom")
}

// sourceDiskIsExcluded reports a disk (not a CD-ROM) left out of backups.
func sourceDiskIsExcluded(value string) bool {
	return strings.Contains(value, "backup=0") && !strings.Contains(value, "media=cdrom")
}

// vmName is a PVE VM name: a DNS name.
var vmName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$`)

// agentEnabled reads PVE's agent option: "1", or "enabled=1" with other
// options after it.
func agentEnabled(value string) bool {
	first, _, _ := strings.Cut(value, ",")
	first = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(first), "enabled="))
	return first == "1" || first == "yes" || first == "on" || first == "true"
}

func splitSourceTags(value string) []string {
	var tags []string
	for _, tag := range strings.Split(value, ";") {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

// ParseSnapshotDrivesJSON extracts the disk image archives on every bus
// (drive-scsiN, drive-virtioN, drive-sataN, drive-ideN) returned by
// `proxmox-backup-client snapshot files --output-format json`, in PVE's
// disk order. Firmware state archives are not disks and are left out.
func ParseSnapshotDrivesJSON(data []byte) ([]SourceDrive, error) {
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("parse PBS snapshot files JSON: %w", err)
	}

	filenames := make(map[string]bool)
	collectFilenames(decoded, filenames)
	var drives []SourceDrive
	seen := make(map[string]bool)
	for filename := range filenames {
		slot, ok := diskslot.ArchiveSlot(filename)
		if !ok || seen[slot] {
			continue
		}
		seen[slot] = true
		drives = append(drives, SourceDrive{Slot: slot, Archive: "drive-" + slot})
	}
	sort.Slice(drives, func(i, j int) bool { return diskslot.Less(drives[i].Slot, drives[j].Slot) })
	if len(drives) == 0 {
		return nil, fmt.Errorf("snapshot contains no backed-up disk image archives")
	}
	return drives, nil
}

func collectFilenames(value any, names map[string]bool) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			collectFilenames(item, names)
		}
	case map[string]any:
		for key, item := range typed {
			if key == "filename" || key == "name" {
				if filename, ok := item.(string); ok {
					names[filename] = true
				}
			}
			collectFilenames(item, names)
		}
	case string:
		if _, ok := diskslot.ArchiveSlot(typed); ok || firmwareArchive.MatchString(typed) {
			names[typed] = true
		}
	}
}

func containsDriveSlot(drives []SourceDrive, slot string) bool {
	for _, drive := range drives {
		if drive.Slot == slot {
			return true
		}
	}
	return false
}

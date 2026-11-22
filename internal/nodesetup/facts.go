// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/internal/nodeidentity"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/sdn"
)

// NodeTools are the commands a run needs on the node, and the Debian package
// that provides each one a stock node may lack.
var NodeTools = []struct {
	Command string
	Package string // "" when every PVE node has it
}{
	{"qemu-img", ""},
	{"proxmox-backup-client", ""},
	{"ip", ""},
	{"guestfish", "libguestfs-tools"},
	{"nft", "nftables"},
}

// NodeFactsScript is the read-only script `certistack setup` runs on the node
// first. It changes nothing; it prints one key=value line per fact, and the
// node's storage.cfg in base64 so that no line of it can be taken for a fact.
// It asks proxmox-backup-client for its own version with an empty environment,
// so with no repository and no server contacted, as check's node layer does,
// and reads the SDN zones with pvesh as root (sdn.PveshZonesCall), which
// fails with "No 'get' handler defined" on a PVE without the SDN API. Neither
// command's error output reaches the operator.
const NodeFactsScript = `export LC_ALL=C
echo "pve_local=$(readlink /etc/pve/local 2>/dev/null)"
echo "pve_version=$(pveversion 2>/dev/null | head -n 1)"
if [ -e /etc/pve/corosync.conf ]; then echo cluster=1; echo "cluster_nodes=$(grep -c -E '^[[:space:]]*name:' /etc/pve/corosync.conf 2>/dev/null)"; else echo cluster=0; fi
if [ -e /dev/kvm ]; then echo kvm=1; else echo kvm=0; fi
echo "arch=$(uname -m)"
for t in qemu-img proxmox-backup-client ip guestfish nft apt-get pvesm pveum; do
  if command -v "$t" >/dev/null 2>&1; then echo "tool=$t"; fi
done
echo "root_source=$(findmnt -n -o SOURCE / 2>/dev/null)"
echo "vz_source=$(findmnt -n -o SOURCE -T /var/lib/vz 2>/dev/null)"
echo "vz_avail=$(df -B1 --output=avail /var/lib/vz 2>/dev/null | tail -n 1 | tr -d ' ')"
if [ -r /etc/pve/storage.cfg ]; then echo "storage_cfg=$(base64 -w 0 /etc/pve/storage.cfg)"; fi
cert=/etc/pve/local/pveproxy-ssl.pem
[ -r "$cert" ] || cert=/etc/pve/local/pve-ssl.pem
echo "cert_names=$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ')"
if openssl verify -CAfile /etc/pve/pve-root-ca.pem "$cert" >/dev/null 2>&1; then echo cert_cluster_ca=1; else echo cert_cluster_ca=0; fi
if command -v proxmox-backup-client >/dev/null 2>&1; then timeout 30 env -i PATH="$PATH" proxmox-backup-client version </dev/null 2>/dev/null | head -n 20 | sed 's/^/pbs_client_out=/'; fi
if command -v pvesh >/dev/null 2>&1; then if sdn_err=$(timeout 60 ` + sdn.PveshZonesCall + ` --output-format json </dev/null 2>&1 >/dev/null); then echo sdn_zones=read; else echo "sdn_zones_error=$(printf '%s\n' "$sdn_err" | head -n 1 | cut -c 1-200)"; fi; fi
echo facts_end=1
`

// NodeFacts are what NodeFactsScript reports.
type NodeFacts struct {
	Name       string // the node's name in PVE
	PVEVersion string // pveversion's first line
	Cluster    bool
	// ClusterNodes is how many nodes corosync.conf lists, 0 when the node is
	// standalone or the file could not be counted.
	ClusterNodes int
	KVM          bool
	Arch         string
	Tools        map[string]bool
	RootSource   string // the device of /
	VZSource     string // the device of /var/lib/vz
	VZAvail      int64  // bytes free under /var/lib/vz, -1 when unknown
	Storage      []StorageSection
	// CertNames are the DNS names and addresses the certificate the PVE API
	// serves is issued for (pveproxy-ssl.pem when an administrator installed
	// one, else pve-ssl.pem); empty when they could not be read.
	CertNames []string
	// CertByClusterCA reports whether the node's cluster CA signs that
	// certificate. One an administrator installed (ACME, a company CA) is not:
	// the cluster CA must then not be the one CertiStack trusts for it.
	CertByClusterCA bool
	// ClientVersion is the version proxmox-backup-client reports of itself; ""
	// when it was not read.
	ClientVersion string
	// SDNRead reports whether pvesh read the SDN zones; when it did not,
	// SDNError is the first line of its error ("" when it was not run).
	SDNRead  bool
	SDNError string
}

// PVERelease is the Proxmox VE version in PVEVersion, the one the PVE API
// reports ("8.0.3" of "pve-manager/8.0.3/bbf39933... (running kernel: ...)");
// "" when the line is not pveversion's.
func (f NodeFacts) PVERelease() string {
	rest, ok := strings.CutPrefix(f.PVEVersion, "pve-manager/")
	if !ok {
		return ""
	}
	version, _, _ := strings.Cut(rest, "/")
	return strings.TrimSpace(version)
}

// SDNMissing is the MissingError of a node whose PVE has no SDN API, as pvesh's
// read of the zones showed; nil when the read worked, was not made, or failed
// for another reason.
func (f NodeFacts) SDNMissing() *sdn.MissingError {
	if f.SDNRead || f.SDNError == "" {
		return nil
	}
	return sdn.MissingFromPvesh(f.SDNError)
}

// VZOnRootDisk reports whether /var/lib/vz is on the root disk.
func (f NodeFacts) VZOnRootDisk() bool {
	return SameDisk(f.VZSource, f.RootSource)
}

// SameDisk reports whether two findmnt SOURCE values are on the same disk: the
// same device (a btrfs subvolume's "[/subvol]" left out), or datasets of the
// same ZFS pool (PVE's ZFS layout mounts / and /var/lib/vz from rpool/ROOT/...
// and rpool/var-lib-vz).
func SameDisk(a, b string) bool {
	return a != "" && b != "" && diskOf(a) == diskOf(b)
}

func diskOf(source string) string {
	if i := strings.Index(source, "["); i > 0 {
		source = source[:i]
	}
	if !strings.HasPrefix(source, "/") {
		if pool, _, ok := strings.Cut(source, "/"); ok {
			return "zfs:" + pool
		}
		return "zfs:" + source
	}
	return source
}

// MissingPackages are the packages that provide the tools a run needs and the
// node lacks, in NodeTools order; a missing tool no package provides is
// reported by MissingTools.
func (f NodeFacts) MissingPackages() []string {
	var out []string
	for _, t := range NodeTools {
		if t.Package != "" && !f.Tools[t.Command] {
			out = append(out, t.Package)
		}
	}
	return out
}

// MissingTools are the tools a run needs that the node lacks and no package
// here installs: a PVE node always has them, so their absence means the host
// is not one.
func (f NodeFacts) MissingTools() []string {
	var out []string
	for _, t := range NodeTools {
		if t.Package == "" && !f.Tools[t.Command] {
			out = append(out, t.Command)
		}
	}
	return out
}

// ParseNodeFacts reads NodeFactsScript's output. It needs the script's end
// line, so that output cut short is not taken for a node without facts.
func ParseNodeFacts(output []byte) (NodeFacts, error) {
	facts := NodeFacts{Tools: map[string]bool{}, VZAvail: -1}
	ended := false
	var clientOutput []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 2*maxStorageConfigBytes)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "pve_local":
			if value != "" {
				name, err := nodeidentity.NameFromLinkTarget(value)
				if err != nil {
					return NodeFacts{}, fmt.Errorf("read the node's name from /etc/pve/local: %w", err)
				}
				facts.Name = name
			}
		case "pve_version":
			facts.PVEVersion = value
		case "cluster":
			facts.Cluster = value == "1"
		case "cluster_nodes":
			if n, err := strconv.Atoi(value); err == nil && n > 0 && n <= 1000 {
				facts.ClusterNodes = n
			}
		case "kvm":
			facts.KVM = value == "1"
		case "arch":
			facts.Arch = value
		case "tool":
			facts.Tools[value] = true
		case "root_source":
			facts.RootSource = value
		case "vz_source":
			facts.VZSource = value
		case "vz_avail":
			if n, err := strconv.ParseInt(value, 10, 64); err == nil && n >= 0 {
				facts.VZAvail = n
			}
		case "storage_cfg":
			data, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return NodeFacts{}, fmt.Errorf("read the node's storage.cfg: %w", err)
			}
			sections, err := ParseStorageConfig(data)
			if err != nil {
				return NodeFacts{}, err
			}
			facts.Storage = sections
		case "cert_names":
			facts.CertNames = parseCertNames(value)
		case "cert_cluster_ca":
			facts.CertByClusterCA = value == "1"
		case "pbs_client_out":
			clientOutput = append(clientOutput, value)
		case "sdn_zones":
			facts.SDNRead = value == "read"
		case "sdn_zones_error":
			facts.SDNError = value
		case "facts_end":
			ended = true
		}
	}
	if err := scanner.Err(); err != nil {
		return NodeFacts{}, fmt.Errorf("read the node's facts: %w", err)
	}
	if !ended {
		return NodeFacts{}, fmt.Errorf("the node's facts ended early: the script did not finish")
	}
	facts.ClientVersion, _ = pbs.ParseVersionOutput([]byte(strings.Join(clientOutput, "\n")))
	if facts.Name == "" {
		return NodeFacts{}, fmt.Errorf("the host has no /etc/pve/local: it is not a Proxmox VE node, or its cluster file system is not mounted")
	}
	return facts, nil
}

// parseCertNames reads openssl's subjectAltName list with the spaces taken out
// ("IPAddress:10.0.0.5,DNS:pve1"): the names and addresses, IP addresses in
// their canonical form.
func parseCertNames(value string) []string {
	var names []string
	for _, item := range strings.Split(value, ",") {
		kind, name, ok := strings.Cut(strings.TrimSpace(item), ":")
		if !ok || name == "" {
			continue
		}
		switch kind {
		case "DNS":
			names = append(names, strings.ToLower(name))
		case "IPAddress":
			if addr, err := netip.ParseAddr(name); err == nil {
				names = append(names, addr.String())
			}
		}
	}
	return names
}

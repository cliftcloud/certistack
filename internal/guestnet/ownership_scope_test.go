// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"strings"
	"testing"
)

// bothManagersEnabled is a guest that enables NetworkManager and
// systemd-networkd, the shape on which the owner of the recovered NIC is
// decided by which networkd files can select it.
func bothManagersEnabled(files map[string]string) map[string]string {
	return withFiles(map[string]string{
		"/usr/lib/systemd/system/NetworkManager.service":                       "[Unit]\n",
		"/etc/systemd/system/multi-user.target.wants/NetworkManager.service":   nmLink,
		"/lib/systemd/system/systemd-networkd.service":                         "[Unit]\n",
		"/etc/systemd/system/multi-user.target.wants/systemd-networkd.service": networkdLink,
	}, files)
}

// The interface name: a .network file that selects another interface
// by Name= does not make the guest ambiguous for a recovery of ens18. The unit
// tests of systemdMayMatchForName pass the name themselves; the line in Apply
// that hands the configured interface name to the detection (guest.iface =
// cfg.InterfaceName) could be removed with every test green, and a guest with a
// container network file for host0 then refused every recovery that named its
// interface.
func TestANetworkFileForAnotherInterfaceDoesNotBlockTheRecoveryOfANamedOne(t *testing.T) {
	files := bothManagersEnabled(map[string]string{
		"/etc/systemd/network/80-container-host0.network": "[Match]\nName=host0\n[Network]\nDHCP=yes\n",
	})
	run := func(interfaceName string) (Result, error) {
		guest := newMemGuest(t, files, networkManagerDir, systemdNetworkdDir)
		cfg := ownerConfig()
		cfg.InterfaceName = interfaceName
		return guest.adapter().Apply(context.Background(), cfg)
	}

	// With no name to compare, the file might select the NIC: the guest is
	// ambiguous, and CertiStack says so instead of guessing.
	if _, err := run(""); err == nil || !strings.Contains(err.Error(), "enables both NetworkManager and systemd-networkd") {
		t.Fatalf("with no interface name, err = %v, want the guest called ambiguous", err)
	}
	// Named ens18, the file for host0 cannot select it.
	result, err := run("ens18")
	if err != nil {
		t.Fatalf("a Name=host0 network file blocked the recovery of ens18: %v", err)
	}
	if result.Strategy != modeNetworkManager {
		t.Errorf("strategy %q, want %q", result.Strategy, modeNetworkManager)
	}
	// And a file that can select ens18 still counts.
	files["/etc/systemd/network/10-lan.network"] = "[Match]\nName=en*\n[Network]\nDHCP=yes\n"
	if _, err := run("ens18"); err == nil || !strings.Contains(err.Error(), "10-lan.network") {
		t.Errorf("a Name=en* network file did not make the guest ambiguous for ens18: %v", err)
	}
}

// The owner's scope: which networkd files can select the NIC is asked
// of the administrator's directory alone (/etc/systemd/network). A vendor
// .network under /usr/lib (a container host's, say) is a default the
// administrator's files and units override, and must not make a guest that
// runs NetworkManager ambiguous. The scan of every directory is what a
// recovery's profile placement needs and what the owner check must not use;
// removing the scope at the owner's call left the package green.
func TestAVendorNetworkFileDoesNotMakeTheGuestsOwnerAmbiguous(t *testing.T) {
	for _, dir := range []string{"/usr/lib/systemd/network", "/lib/systemd/network", "/usr/local/lib/systemd/network"} {
		t.Run(dir, func(t *testing.T) {
			guest := newMemGuest(t, bothManagersEnabled(map[string]string{
				dir + "/80-container-vz.network": "[Match]\nMACAddress=" + ownerMAC + "\n[Network]\nDHCP=yes\n",
			}), networkManagerDir)
			d := newDetection(guest.adapter(), []string{"/synthetic/owner-overlay.qcow2"}, ownerMAC)
			owner, err := d.networkManagerOwner(context.Background())
			if err != nil || owner != modeNetworkManager {
				t.Fatalf("owner = %q, err = %v; a vendor network file in %s made the guest ambiguous", owner, err, dir)
			}
		})
	}
	// The administrator's own directory still counts.
	guest := newMemGuest(t, bothManagersEnabled(map[string]string{
		"/etc/systemd/network/10-lan.network": "[Match]\nMACAddress=" + ownerMAC + "\n[Network]\nDHCP=yes\n",
	}), networkManagerDir)
	d := newDetection(guest.adapter(), []string{"/synthetic/owner-overlay.qcow2"}, ownerMAC)
	if _, err := d.networkManagerOwner(context.Background()); err == nil || !strings.Contains(err.Error(), "10-lan.network") {
		t.Errorf("a network file in /etc/systemd/network for the NIC's MAC did not make the guest ambiguous: %v", err)
	}
}

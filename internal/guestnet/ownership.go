// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
)

const (
	systemUnitDir      = "/etc/systemd/system"
	networkManagerUnit = "NetworkManager.service"
	networkdUnit       = "systemd-networkd.service"
	networkingUnit     = "networking.service"

	// OpenRC guests (Alpine) enable an init script by linking it into a runlevel directory.
	openrcRunlevelDir      = "/etc/runlevels"
	openrcNetworkingScript = "networking"
)

// unitAliases are the D-Bus aliases `systemctl enable` creates beside the
// multi-user.target.wants link of the network managers that have one.
var unitAliases = map[string]string{
	"dbus-org.freedesktop.NetworkManager.service": networkManagerUnit,
	"dbus-org.freedesktop.network1.service":       networkdUnit,
}

// strategyUnit is the service that must be able to start for a strategy's
// profile to be read. A netplan recovery definition is rendered for
// systemd-networkd. ifcfg profiles are read by NetworkManager or by the
// legacy network scripts, so no single unit decides.
func strategyUnit(strategy string) string {
	switch strategy {
	case modeNetworkManager:
		return networkManagerUnit
	case modeNetplan, modeSystemdNetworkd:
		return networkdUnit
	case modeIfupdown:
		return networkingUnit
	default:
		return ""
	}
}

// detection answers ownership questions about one overlay from its files,
// reading each piece of evidence at most once: every read is a guestfish
// appliance start.
type detection struct {
	a        *Adapter
	overlays []string
	mac      string
	iface    string // requested recovery name; empty means unknown offline

	system  map[string]bool // entries of /etc/systemd/system; nil until read
	wants   map[string]bool // multi-user.target.wants; nil until read
	masks   map[string]bool
	netplan *netplanConfig
	nm      *nmSettings // the guest's NetworkManager configuration; nil until read
	nmErr   error       // why it could not be evaluated
	// matching caches systemdFilesBefore by suffix and limit.
	matching map[string][]string
	dirs     map[string]bool
	lists    map[string][]string
}

func newDetection(a *Adapter, overlays []string, mac string) *detection {
	return &detection{a: a, overlays: overlays, mac: mac, masks: map[string]bool{}, dirs: map[string]bool{}, lists: map[string][]string{}}
}

func (d *detection) directoryExists(ctx context.Context, dir string) (bool, error) {
	if exists, known := d.dirs[dir]; known {
		return exists, nil
	}
	exists, err := d.a.directoryExists(ctx, d.overlays, dir)
	if err != nil {
		return false, dependencyError("inspect", err)
	}
	d.dirs[dir] = exists
	return exists, nil
}

func (d *detection) list(ctx context.Context, dir string) ([]string, error) {
	if entries, known := d.lists[dir]; known {
		return entries, nil
	}
	output, err := d.a.run(ctx, guestfishReadArgs(d.overlays, "ls", dir)...)
	if err != nil {
		return nil, dependencyError("list "+dir, err)
	}
	d.lists[dir] = listingEntries(output)
	return d.lists[dir], nil
}

func (d *detection) systemUnits(ctx context.Context) (map[string]bool, error) {
	if d.system != nil {
		return d.system, nil
	}
	system := map[string]bool{}
	exists, err := d.directoryExists(ctx, systemUnitDir)
	if err != nil {
		return nil, err
	}
	if exists {
		entries, err := d.list(ctx, systemUnitDir)
		if err != nil {
			return nil, err
		}
		for _, name := range entries {
			system[name] = true
		}
	}
	d.system = system
	return system, nil
}

// masked reports a unit systemd will never start: its name in
// /etc/systemd/system is a link to /dev/null or an empty file. Anything
// else there (an administrator's copy, a linked unit) is not a mask.
func (d *detection) masked(ctx context.Context, unit string) (bool, error) {
	if masked, known := d.masks[unit]; known {
		return masked, nil
	}
	system, err := d.systemUnits(ctx)
	if err != nil {
		return false, err
	}
	masked := false
	if system[unit] {
		file := path.Join(systemUnitDir, unit)
		output, err := d.a.run(ctx, guestfishReadArgs(d.overlays, "is-symlink", file)...)
		if err != nil {
			return false, dependencyError("inspect guest service "+unit, err)
		}
		if strings.EqualFold(strings.TrimSpace(output), "true") {
			target, err := d.a.run(ctx, guestfishReadArgs(d.overlays, "readlink", file)...)
			if err != nil {
				return false, dependencyError("inspect guest service "+unit, err)
			}
			target = strings.TrimSpace(target)
			if !path.IsAbs(target) {
				target = path.Join(systemUnitDir, target)
			}
			masked = path.Clean(target) == "/dev/null"
		} else {
			size, err := d.a.run(ctx, guestfishReadArgs(d.overlays, "filesize", file)...)
			if err != nil {
				return false, dependencyError("inspect guest service "+unit, err)
			}
			bytes, parseErr := strconv.ParseInt(strings.TrimSpace(size), 10, 64)
			masked = parseErr == nil && bytes == 0
		}
	}
	d.masks[unit] = masked
	return masked, nil
}

// enabled reports a unit `systemctl enable` has enabled: its D-Bus alias
// exists or multi-user.target wants it. A masked unit is never reported
// enabled.
func (d *detection) enabled(ctx context.Context, unit string) (bool, error) {
	if masked, err := d.masked(ctx, unit); err != nil || masked {
		return false, err
	}
	system, err := d.systemUnits(ctx)
	if err != nil {
		return false, err
	}
	for alias, aliased := range unitAliases {
		if aliased == unit && system[alias] {
			return true, nil
		}
	}
	if d.wants == nil {
		if d.wants, err = d.a.enabledUnits(ctx, d.overlays); err != nil {
			return false, err
		}
	}
	return d.wants[unit], nil
}

// ifupdownOwnsNetwork reports whether Debian-style ifupdown configures the
// guest: networking.service is enabled, systemd-networkd is not, and
// /etc/network/interfaces exists. Debian ships an empty /etc/systemd/network
// even when ifupdown owns the network, so a networkd profile there would
// never be read.
func (d *detection) ifupdownOwnsNetwork(ctx context.Context) (bool, error) {
	networking, err := d.enabled(ctx, networkingUnit)
	if err != nil || !networking {
		return false, err
	}
	if networkd, err := d.enabled(ctx, networkdUnit); err != nil || networkd {
		return false, err
	}
	exists, err := d.a.fileExists(ctx, d.overlays, ifupdownConfig)
	if err != nil {
		return false, dependencyError("inspect ifupdown configuration", err)
	}
	return exists, nil
}

// openrcIfupdownOwnsNetwork reports an OpenRC guest (Alpine) whose networking
// init script, which runs ifupdown, is linked into a runlevel and which has
// the /etc/network/interfaces file it reads. It is asked last: a guest that
// systemd or one of the other backends configures never pays for it.
func (d *detection) openrcIfupdownOwnsNetwork(ctx context.Context) (bool, error) {
	enabled, err := d.openrcNetworkingEnabled(ctx)
	if err != nil || !enabled {
		return false, err
	}
	exists, err := d.a.fileExists(ctx, d.overlays, ifupdownConfig)
	if err != nil {
		return false, dependencyError("inspect ifupdown configuration", err)
	}
	return exists, nil
}

// openrcNetworkingEnabled reports an OpenRC guest that starts its networking
// init script (ifupdown) at boot: `rc-update add networking boot` links it
// into /etc/runlevels/boot, and the default and sysinit runlevels count too.
func (d *detection) openrcNetworkingEnabled(ctx context.Context) (bool, error) {
	if exists, err := d.directoryExists(ctx, openrcRunlevelDir); err != nil || !exists {
		return false, err
	}
	for _, level := range []string{"boot", "default", "sysinit"} {
		dir := path.Join(openrcRunlevelDir, level)
		exists, err := d.directoryExists(ctx, dir)
		if err != nil {
			return false, err
		}
		if !exists {
			continue
		}
		entries, err := d.list(ctx, dir)
		if err != nil {
			return false, err
		}
		for _, name := range entries {
			if name == openrcNetworkingScript {
				return true, nil
			}
		}
	}
	return false, nil
}

func (d *detection) netplanConfig(ctx context.Context) (*netplanConfig, error) {
	if d.netplan != nil {
		return d.netplan, nil
	}
	config, err := d.readNetplan(ctx)
	if err != nil {
		return nil, err
	}
	d.netplan = config
	return config, nil
}

// maskedError names a mask that makes a backend unusable. The wording is
// shared by an explicit mode and by auto when nothing else remains.
func maskedError(unit, backend string) error {
	return fmt.Errorf("the guest's %s is masked (its unit is linked to /dev/null), so it never starts and would never read a %s recovery profile; use network_recovery.mode: auto or the backend the guest really runs, or preserve", unit, backend)
}

// networkManagerOwner decides between NetworkManager, whose configuration
// directory exists, and another backend with evidence that it configures
// the recovered NIC. It returns "" when NetworkManager is masked and so
// owns nothing. Directory presence alone never outweighs such evidence:
// a guest can keep NetworkManager's files while systemd-networkd runs. Where
// the guest configures the NIC with both and CertiStack cannot tell which is
// in charge, it is an error rather than a guess.
func (d *detection) networkManagerOwner(ctx context.Context) (string, error) {
	if masked, err := d.masked(ctx, networkManagerUnit); err != nil || masked {
		return "", err
	}
	// netplan renders a definition that can match the NIC for networkd and
	// tells NetworkManager to leave that device alone.
	if netplan, err := d.directoryExists(ctx, netplanDir); err != nil {
		return "", err
	} else if netplan {
		networkdMasked, err := d.masked(ctx, networkdUnit)
		if err != nil {
			return "", err
		}
		if !networkdMasked {
			config, err := d.netplanConfig(ctx)
			if err != nil {
				return "", err
			}
			if config.networkdMayConfigure(d.mac) {
				return modeNetplan, nil
			}
		}
	}
	networkd, err := d.enabled(ctx, networkdUnit)
	if err != nil {
		return "", err
	}
	if enabled, err := d.enabled(ctx, networkManagerUnit); err != nil {
		return "", err
	} else if enabled {
		if networkd {
			// Both run. NetworkManager configures the NIC unless a networkd
			// file also selects it; then either could be in charge.
			matching, err := d.systemdFilesBeforeIn(ctx, ".network", "", []string{systemdNetworkdDir})
			if err != nil {
				return "", err
			}
			if len(matching) > 0 {
				return "", fmt.Errorf("the guest enables both NetworkManager and systemd-networkd, and networkd files (%s) can match the recovered NIC, so CertiStack cannot tell which one configures it; set network_recovery.mode to networkmanager or systemd-networkd", strings.Join(matching, ", "))
			}
		}
		return modeNetworkManager, nil
	}
	// NetworkManager is installed but not enabled: an enabled networkd or
	// ifupdown is what configures the guest.
	if networkd {
		if exists, err := d.directoryExists(ctx, systemdNetworkdDir); err != nil {
			return "", err
		} else if exists {
			return modeSystemdNetworkd, nil
		}
	}
	if ifupdown, err := d.ifupdownOwnsNetwork(ctx); err != nil {
		return "", err
	} else if ifupdown {
		return modeIfupdown, nil
	}
	return modeNetworkManager, nil
}

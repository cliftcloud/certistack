// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
)

const victimPath = "/etc/victim"

func nmConfig() Config {
	cfg := multiDiskConfig(bootOverlayPath)
	cfg.Mode = modeNetworkManager
	return cfg
}

// requireVictimUntouched fails unless the unrelated file a symbolic link points
// at still has its contents, owner and mode.
func requireVictimUntouched(t *testing.T, guest *memGuest) {
	t.Helper()
	requireVictimContents(t, guest, victimContents)
}

const victimContents = "VICTIM-SENTINEL\n"

func requireVictimContents(t *testing.T, guest *memGuest, want string) {
	t.Helper()
	if got := guest.files[victimPath]; got != want {
		t.Fatalf("the unrelated file %s was overwritten: %q", victimPath, got)
	}
	if attr := guest.attrs[victimPath]; attr.uid != 1000 || attr.permBits() != 0o644 {
		t.Fatalf("the unrelated file %s was changed: owner %d, mode %04o", victimPath, attr.uid, attr.permBits())
	}
}

func victimGuest(t *testing.T, files map[string]string, dirs ...string) *memGuest {
	t.Helper()
	return victimGuestWith(t, victimContents, files, dirs...)
}

func victimGuestWith(t *testing.T, contents string, files map[string]string, dirs ...string) *memGuest {
	t.Helper()
	all := map[string]string{victimPath: contents}
	for name, contents := range files {
		all[name] = contents
	}
	guest := newMemGuest(t, all, dirs...)
	guest.attrs[victimPath] = memAttr{uid: 1000, gid: 1000}
	return guest
}

// The reported case. The only profile of an NetworkManager guest is
// owned by another user. cp -a gave the copy that owner, the upload reused the
// inode, and the only metadata step was chmod 0600, which grants exactly that
// owner read and write; NetworkManager ignores a keyfile another user can
// write, so the recovery connection was never applied although Apply
// reported success. The profile is now owned by root whatever the seed was.
func TestApplyMakesTheProfileRootOwnedWhateverTheSeedWas(t *testing.T) {
	cases := []struct {
		name string
		attr memAttr
	}{
		{"root-owned", memAttr{label: enforcingLabel}},
		{"owned by another user (the reporter's case)", memAttr{uid: 1000, gid: 1000, label: enforcingLabel}},
		{"another user's group only", memAttr{gid: 100, label: enforcingLabel}},
		{"group-writable", memAttr{perm: 0o660, label: enforcingLabel}},
		{"world-readable and world-writable", memAttr{uid: 1000, perm: 0o666, label: enforcingLabel}},
		{"setuid bits", memAttr{uid: 1000, perm: 0o4755, label: enforcingLabel}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const seedName = "00-nonroot.nmconnection"
			seed := networkManagerDir + "/" + seedName
			guest := newMemGuest(t, map[string]string{seed: "[connection]\nid=stale\n"}, networkManagerDir)
			guest.attrs[seed] = tc.attr
			if _, err := guest.adapter().Apply(context.Background(), nmConfig()); err != nil {
				t.Fatal(err)
			}
			batch := lastBatch(guest.calls)
			if !batchHasCommand(batch, "cp-a", seed, networkManagerProfile) || !batchHasCommand(batch, "chown", "0", "0", networkManagerProfile) {
				t.Fatalf("batch = %#v, want the seed copied and the owner set to root:root", batch)
			}
			got := guest.attrs[networkManagerProfile]
			if got.uid != 0 || got.gid != 0 || got.permBits() != 0o600 {
				t.Fatalf("the profile is owned by %d:%d with mode %04o, want root:root 0600", got.uid, got.gid, got.permBits())
			}
			if got.label != enforcingLabel {
				t.Fatalf("the profile's SELinux label = %q, want the seed's %q", got.label, enforcingLabel)
			}
			if guest.attrs[seed] != tc.attr {
				t.Fatal("the guest's own profile was changed")
			}
			if guest.kind(networkManagerProfile) != "file" {
				t.Fatalf("the profile is %q", guest.kind(networkManagerProfile))
			}
		})
	}
}

// dropCommands removes every command with the given name from a write batch,
// as if the guest silently did not carry it out.
func dropCommands(adapter *Adapter, names ...string) {
	inner := adapter.run
	adapter.run = func(ctx context.Context, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "--rw" {
			var kept [][]string
			batch := guestfishCommand(args)[1:]
			for len(batch) > 0 {
				end := slices.Index(batch, ":")
				if end < 0 {
					end = len(batch)
				}
				if !slices.Contains(names, batch[0]) {
					kept = append(kept, batch[:end])
				}
				if end == len(batch) {
					break
				}
				batch = batch[end+1:]
			}
			args = guestfishBatchArgs(guestfishOverlays(args), kept)
		}
		return inner(ctx, args...)
	}
}

// "refuse otherwise". When what is read back is not a regular file
// owned by root with the mode that was set, the run stops instead of booting a
// guest whose NetworkManager would ignore the profile.
func TestApplyRefusesAProfileItCannotShowIsRootOwned(t *testing.T) {
	seed := networkManagerDir + "/00-nonroot.nmconnection"
	setup := func(t *testing.T, attr memAttr) *Adapter {
		guest := newMemGuest(t, map[string]string{seed: "[connection]\n"}, networkManagerDir)
		guest.attrs[seed] = attr
		return guest.adapter()
	}
	t.Run("the owner was not set", func(t *testing.T) {
		adapter := setup(t, memAttr{uid: 1000, gid: 1000})
		dropCommands(adapter, "chown")
		_, err := adapter.Apply(context.Background(), nmConfig())
		if err == nil || !strings.Contains(err.Error(), networkManagerProfile) || !strings.Contains(err.Error(), "owned by root:root") || !strings.Contains(err.Error(), "owner 1000:1000") {
			t.Fatalf("Apply = %v, want the retained owner refused", err)
		}
	})
	t.Run("the mode was not set", func(t *testing.T) {
		adapter := setup(t, memAttr{})
		dropCommands(adapter, "chmod")
		_, err := adapter.Apply(context.Background(), nmConfig())
		if err == nil || !strings.Contains(err.Error(), "mode 0600") {
			t.Fatalf("Apply = %v, want the mode refused", err)
		}
	})
	t.Run("the read-back cannot be read", func(t *testing.T) {
		adapter := setup(t, memAttr{})
		inner := adapter.run
		adapter.run = func(ctx context.Context, args ...string) (string, error) {
			out, err := inner(ctx, args...)
			if slices.Contains(args, "lstat") {
				return "this is not a stat\n", err
			}
			return out, err
		}
		if _, err := adapter.Apply(context.Background(), nmConfig()); err == nil || !strings.Contains(err.Error(), "not a stat field") {
			t.Fatalf("Apply = %v, want the unreadable read-back refused", err)
		}
	})
}

// The first reported case. The recovery profile's own path is a
// symbolic link to another file of the guest. The upload followed it (guestfish
// opens with O_TRUNC and no O_NOFOLLOW) and chmod 0600 changed the target, and
// the destination stayed a link. Now the run refuses before it writes anything.
func TestApplyRefusesADestinationThatIsASymbolicLink(t *testing.T) {
	for _, target := range []string{victimPath, "/etc/not-there"} {
		t.Run(target, func(t *testing.T) {
			guest := victimGuest(t, map[string]string{
				networkManagerDir + "/existing.nmconnection": "[connection]\n",
				networkManagerProfile:                        "-> " + target,
			}, networkManagerDir)
			_, err := guest.adapter().Apply(context.Background(), nmConfig())
			if err == nil || !strings.Contains(err.Error(), networkManagerProfile) || !strings.Contains(err.Error(), "a symbolic link") {
				t.Fatalf("Apply = %v, want the symbolic link refused", err)
			}
			if guest.mutated() {
				t.Fatal("a write reached the overlay although the destination is a link")
			}
			requireVictimUntouched(t, guest)
			if guest.kind(networkManagerProfile) != "symlink" {
				t.Fatal("the link was replaced")
			}
		})
	}
}

// The second reported case. The profile to copy is a symbolic link:
// cp -a copies it as a link, and the upload that followed overwrote its target.
// A link is not a seed; the next regular file is, and with none the profile is
// created without one.
func TestApplyDoesNotSeedFromASymbolicLink(t *testing.T) {
	t.Run("the only candidate is a link", func(t *testing.T) {
		guest := victimGuest(t, map[string]string{networkManagerDir + "/00-link.nmconnection": "-> " + victimPath}, networkManagerDir)
		if _, err := guest.adapter().Apply(context.Background(), nmConfig()); err != nil {
			t.Fatal(err)
		}
		batch := lastBatch(guest.calls)
		for _, command := range [][]string{{"cp-a", networkManagerDir + "/00-link.nmconnection", networkManagerProfile}} {
			if batchHasCommand(batch, command...) {
				t.Fatalf("the link was copied: %#v", batch)
			}
		}
		requireVictimUntouched(t, guest)
		if guest.kind(networkManagerProfile) != "file" || guest.attrs[networkManagerProfile].uid != 0 {
			t.Fatalf("the profile is %q", guest.kind(networkManagerProfile))
		}
	})
	t.Run("a regular file after the link is chosen", func(t *testing.T) {
		regular := networkManagerDir + "/10-regular.nmconnection"
		guest := victimGuest(t, map[string]string{
			networkManagerDir + "/00-link.nmconnection": "-> " + victimPath,
			regular: "[connection]\n",
		}, networkManagerDir)
		guest.attrs[regular] = memAttr{label: enforcingLabel}
		if _, err := guest.adapter().Apply(context.Background(), nmConfig()); err != nil {
			t.Fatal(err)
		}
		if !batchHasCommand(lastBatch(guest.calls), "cp-a", regular, networkManagerProfile) {
			t.Fatalf("the regular profile was not the seed: %#v", lastBatch(guest.calls))
		}
		requireVictimUntouched(t, guest)
		if guest.attrs[networkManagerProfile].label != enforcingLabel {
			t.Fatal("the seed's label was not kept")
		}
	})
}

// A directory, device, pipe or socket is not a seed either, and where the
// profile itself belongs it is refused rather than written through or waited
// on (an upload to a pipe with no reader blocks).
func TestApplyAndSpecialFiles(t *testing.T) {
	kinds := map[string]string{"character device": "!chardev", "block device": "!blockdev", "named pipe": "!fifo", "socket": "!socket"}
	for name, marker := range kinds {
		t.Run("a "+name+" is not a seed", func(t *testing.T) {
			regular := networkManagerDir + "/z.nmconnection"
			guest := newMemGuest(t, map[string]string{networkManagerDir + "/a.nmconnection": marker, regular: "[connection]\n"}, networkManagerDir)
			if _, err := guest.adapter().Apply(context.Background(), nmConfig()); err != nil {
				t.Fatal(err)
			}
			if !batchHasCommand(lastBatch(guest.calls), "cp-a", regular, networkManagerProfile) {
				t.Fatalf("the regular file was not the seed: %#v", lastBatch(guest.calls))
			}
		})
		t.Run("a "+name+" is refused as the destination", func(t *testing.T) {
			guest := newMemGuest(t, map[string]string{networkManagerDir + "/a.nmconnection": "[connection]\n", networkManagerProfile: marker}, networkManagerDir)
			_, err := guest.adapter().Apply(context.Background(), nmConfig())
			if err == nil || !strings.Contains(err.Error(), networkManagerProfile) || !strings.Contains(err.Error(), name) {
				t.Fatalf("Apply = %v, want the %s refused", err, name)
			}
			if guest.mutated() {
				t.Fatal("a write was attempted")
			}
		})
	}
	t.Run("a directory is not a seed", func(t *testing.T) {
		regular := networkManagerDir + "/z.nmconnection"
		guest := newMemGuest(t, map[string]string{networkManagerDir + "/a.nmconnection/child": "x", regular: "[connection]\n"}, networkManagerDir)
		if _, err := guest.adapter().Apply(context.Background(), nmConfig()); err != nil {
			t.Fatal(err)
		}
		if !batchHasCommand(lastBatch(guest.calls), "cp-a", regular, networkManagerProfile) {
			t.Fatalf("the regular file was not the seed: %#v", lastBatch(guest.calls))
		}
	})
	t.Run("a directory is refused as the destination", func(t *testing.T) {
		guest := newMemGuest(t, map[string]string{networkManagerDir + "/a.nmconnection": "[connection]\n", networkManagerProfile + "/child": "x"}, networkManagerDir)
		_, err := guest.adapter().Apply(context.Background(), nmConfig())
		if err == nil || !strings.Contains(err.Error(), "a directory") {
			t.Fatalf("Apply = %v, want the directory refused", err)
		}
		if guest.mutated() {
			t.Fatal("a write was attempted")
		}
	})
}

// A destination that other names share would change them with it.
func TestApplyRefusesADestinationWithHardLinks(t *testing.T) {
	guest := newMemGuest(t, map[string]string{networkManagerDir + "/a.nmconnection": "[connection]\n", "/etc/cron.d/other": "OTHER\n"}, networkManagerDir)
	guest.hardLink("/etc/cron.d/other", networkManagerProfile)
	_, err := guest.adapter().Apply(context.Background(), nmConfig())
	if err == nil || !strings.Contains(err.Error(), networkManagerProfile) || !strings.Contains(err.Error(), "2 hard links") {
		t.Fatalf("Apply = %v, want the hard-linked destination refused", err)
	}
	if guest.mutated() || guest.files["/etc/cron.d/other"] != "OTHER\n" {
		t.Fatal("the other name of the inode was changed")
	}
}

// The control: a regular file of the same name from an earlier recovery is
// written in place, so its SELinux label stays, and it ends up root-owned.
func TestApplyWritesAnExistingRegularProfileInPlace(t *testing.T) {
	guest := newMemGuest(t, map[string]string{networkManagerProfile: "[connection]\nid=old\n"}, networkManagerDir)
	guest.attrs[networkManagerProfile] = memAttr{uid: 1000, label: enforcingLabel}
	if _, err := guest.adapter().Apply(context.Background(), nmConfig()); err != nil {
		t.Fatal(err)
	}
	got := guest.attrs[networkManagerProfile]
	if got.label != enforcingLabel || got.uid != 0 || got.gid != 0 || got.permBits() != 0o600 {
		t.Fatalf("the rewritten profile = %+v", got)
	}
	if strings.Contains(guest.files[networkManagerProfile], "id=old") {
		t.Fatal("the old content stayed")
	}
}

// A symbolic link among the parent directories is how the guest's own lookup
// goes (/etc/NetworkManager kept on another volume, say), so the profile is
// written where that lookup leads and the check looks at the entry there: a
// regular file or nothing is fine, a link at the redirected path is refused.
func TestParentDirectoryLinksAreFollowedAsTheGuestFollowsThem(t *testing.T) {
	const redirected = "/data/nm/system-connections"
	seed := redirected + "/a.nmconnection"
	t.Run("the profile lands where the guest's lookup leads", func(t *testing.T) {
		guest := newMemGuest(t, map[string]string{"/etc/NetworkManager": "-> /data/nm", seed: "[connection]\n"}, redirected)
		guest.attrs[seed] = memAttr{uid: 1000, label: enforcingLabel}
		if _, err := guest.adapter().Apply(context.Background(), nmConfig()); err != nil {
			t.Fatal(err)
		}
		landed := redirected + "/90-certistack-recovery.nmconnection"
		got := guest.attrs[landed]
		if guest.kind(landed) != "file" || got.uid != 0 || got.gid != 0 || got.permBits() != 0o600 || got.label != enforcingLabel {
			t.Fatalf("the profile at %s is a %s with %+v", landed, guest.kind(landed), got)
		}
	})
	t.Run("a link at the redirected path is refused", func(t *testing.T) {
		guest := victimGuest(t, map[string]string{
			"/etc/NetworkManager": "-> /data/nm",
			seed:                  "[connection]\n",
			redirected + "/90-certistack-recovery.nmconnection": "-> " + victimPath,
		}, redirected)
		_, err := guest.adapter().Apply(context.Background(), nmConfig())
		if err == nil || !strings.Contains(err.Error(), "a symbolic link") {
			t.Fatalf("Apply = %v, want the link refused", err)
		}
		if guest.mutated() {
			t.Fatal("a write reached the overlay")
		}
		requireVictimUntouched(t, guest)
	})
}

// Covers every fixed upload, not only the NetworkManager profile: each
// destination of each backend, with the optional files (interface link,
// diagnostics, firewall zone) switched on, is made a symbolic link in turn and
// must be refused with the unrelated file left alone.
func TestApplyRefusesEveryDestinationThatIsASymbolicLink(t *testing.T) {
	firewall := map[string]string{
		firewalldConfig:                  "DefaultZone=public\n",
		firewalldZoneDir + "/public.xml": "<zone>\n</zone>\n",
	}
	// The unrelated file has contents the adapter itself reads without a
	// complaint where it is read through the link (a firewalld zone, the main
	// interfaces file), so that the refusal that follows is the write check's.
	scenarios := []struct {
		name   string
		victim string
		files  map[string]string
		dirs   []string
		cfg    func(*Config)
	}{
		{"NetworkManager with every optional file", "<zone>\n</zone>\n", withFiles(firewall, map[string]string{networkManagerDir + "/a.nmconnection": "[connection]\n"}), []string{networkManagerDir, firewalldDir, firewalldZoneDir}, func(c *Config) {
			c.Mode, c.InterfaceName, c.CaptureDiagnostics = modeNetworkManager, "eth0", true
			c.ProbeIP, c.FirewallPorts = "10.100.0.1", []FirewallPort{{Protocol: "tcp", Port: 8080}}
		}},
		{"Netplan", victimContents, map[string]string{netplanDir + "/50-cloud-init.yaml": "network:\n  version: 2\n"}, []string{netplanDir}, func(c *Config) { c.Mode = modeNetplan }},
		{"systemd-networkd", victimContents, nil, []string{systemdNetworkdDir}, func(c *Config) { c.Mode = modeSystemdNetworkd; c.InterfaceName = "eth0" }},
		{"ifupdown", ifaceEnp, map[string]string{ifupdownConfig: ifaceEnp}, []string{ifupdownDir}, func(c *Config) { c.Mode = modeIfupdown }},
		{"ifcfg", victimContents, map[string]string{ifcfgDir + "/ifcfg-eth0": "DEVICE=eth0\n"}, []string{ifcfgDir}, func(c *Config) { c.Mode = modeIfcfg }},
	}
	for _, sc := range scenarios {
		cfg := multiDiskConfig(bootOverlayPath)
		sc.cfg(&cfg)

		// What a clean run writes: every cp -a and upload destination.
		clean := newMemGuest(t, sc.files, sc.dirs...)
		if _, err := clean.adapter().Apply(context.Background(), cfg); err != nil {
			t.Fatalf("%s: clean Apply: %v", sc.name, err)
		}
		destinations := collectWriteTargets(batchCommands(lastBatch(clean.calls))).destinations
		if len(destinations) == 0 {
			t.Fatalf("%s: no destinations found", sc.name)
		}
		for _, destination := range destinations {
			t.Run(sc.name+" "+destination, func(t *testing.T) {
				files := withFiles(sc.files, map[string]string{destination: "-> " + victimPath})
				guest := victimGuestWith(t, sc.victim, files, sc.dirs...)
				_, err := guest.adapter().Apply(context.Background(), cfg)
				if err == nil || !strings.Contains(err.Error(), destination) || !strings.Contains(err.Error(), "a symbolic link") {
					t.Fatalf("Apply = %v, want %s refused as a symbolic link", err, destination)
				}
				if guest.mutated() {
					t.Fatal("a write reached the overlay")
				}
				requireVictimContents(t, guest, sc.victim)
				if attr := guest.attrs[victimPath]; attr.uid != 1000 || attr.permBits() != 0o644 {
					t.Fatalf("the unrelated file was changed: owner %d, mode %04o", attr.uid, attr.permBits())
				}
			})
		}
	}
}

// batchCommands splits a recorded guestfish write batch back into commands.
func batchCommands(args []string) [][]string {
	var commands [][]string
	batch := guestfishCommand(args)[1:]
	for len(batch) > 0 {
		end := slices.Index(batch, ":")
		if end < 0 {
			end = len(batch)
		}
		commands = append(commands, batch[:end])
		if end == len(batch) {
			break
		}
		batch = batch[end+1:]
	}
	return commands
}

// The destination is looked at before the write and read back after it, in
// that order, each in one guestfish run.
func TestApplyChecksBeforeAndVerifiesAfterTheWrite(t *testing.T) {
	guest := newMemGuest(t, map[string]string{networkManagerDir + "/a.nmconnection": "[connection]\n"}, networkManagerDir)
	if _, err := guest.adapter().Apply(context.Background(), nmConfig()); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, call := range guest.calls {
		command := guestfishCommand(call)
		switch {
		case call[0] == "--rw":
			kinds = append(kinds, "write")
		case len(command) > 2 && command[0] == "--" && command[1] == "is-symlink":
			kinds = append(kinds, "check")
		case len(command) > 2 && command[0] == "--" && command[1] == "lstat":
			kinds = append(kinds, "verify")
		}
	}
	// What the guest's NetworkManager reads from is looked at first, the
	// seed when it is chosen, and again, with the destination, before the write.
	if want := []string{"check", "check", "check", "write", "verify"}; !slices.Equal(kinds, want) {
		t.Fatalf("checks and writes = %v, want %v", kinds, want)
	}
}

// guestfish refusing the write (an immutable file, a read-only filesystem)
// is the run's failure, and nothing is read back as if it had worked.
func TestApplyFailsWhenTheGuestRefusesTheWrite(t *testing.T) {
	guest := newMemGuest(t, map[string]string{networkManagerProfile: "[connection]\n"}, networkManagerDir)
	adapter := guest.adapter()
	inner := adapter.run
	refused := false
	adapter.run = func(ctx context.Context, args ...string) (string, error) {
		if refused {
			t.Fatalf("guestfish was called again after the refused write: %#v", args)
		}
		if args[0] == "--rw" {
			refused = true
			return "", fmt.Errorf("guestfish: upload: %s: Operation not permitted: exit status 1", networkManagerProfile)
		}
		return inner(ctx, args...)
	}
	_, err := adapter.Apply(context.Background(), nmConfig())
	if err == nil || !strings.Contains(err.Error(), "Operation not permitted") || !refused {
		t.Fatalf("Apply = %v, want the guest's refusal", err)
	}
}

// Only the first maxSeedCandidates profiles are looked at when choosing the
// seed; each costs seven questions in one guestfish run.
func TestSeedChoiceLooksAtABoundedNumberOfProfiles(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < maxSeedCandidates+10; i++ {
		files[fmt.Sprintf("%s/%03d.nmconnection", networkManagerDir, i)] = "[connection]\n"
	}
	guest := newMemGuest(t, files, networkManagerDir)
	detect := newDetection(guest.adapter(), []string{bootOverlayPath}, ownerMAC)
	seed, err := guest.adapter().profileSeedSource(context.Background(), detect, modeNetworkManager, networkManagerProfile)
	if err != nil || seed != networkManagerDir+"/000.nmconnection" {
		t.Fatalf("seed = %q, %v", seed, err)
	}
	asked := 0
	for _, call := range guest.calls {
		for _, arg := range call {
			if arg == "is-symlink" {
				asked++
			}
		}
	}
	if asked != maxSeedCandidates {
		t.Fatalf("%d profiles were looked at, want %d", asked, maxSeedCandidates)
	}
}

func TestParseGuestStats(t *testing.T) {
	block := func(mode, nlink, uid, gid int) string {
		return fmt.Sprintf("dev: 2049\nino: 7\nmode: %d\nnlink: %d\nuid: %d\ngid: %d\nrdev: 0\nsize: 3\nblksize: 4096\nblocks: 8\natime: 1\nmtime: 2\nctime: 3\n", mode, nlink, uid, gid)
	}
	stats, err := parseGuestStats(block(0o100600, 1, 0, 0)+block(0o120777, 2, 1000, 100), 2)
	if err != nil {
		t.Fatal(err)
	}
	if !stats[0].regular() || stats[0].uid != 0 || stats[0].mode&modePermissions != 0o600 || stats[1].regular() || stats[1].nlink != 2 || stats[1].uid != 1000 || stats[1].gid != 100 {
		t.Fatalf("stats = %+v", stats)
	}
	bad := map[string]struct {
		output string
		n      int
	}{
		"nothing":             {"", 1},
		"too few":             {block(0o100600, 1, 0, 0), 2},
		"too many":            {block(0o100600, 1, 0, 0) + block(0o100600, 1, 0, 0), 1},
		"not a stat":          {"hello\n", 1},
		"not a number":        {"dev: 1\nmode: abc\n", 1},
		"starts mid-block":    {"mode: 33188\nuid: 0\n", 1},
		"a missing field":     {"dev: 1\nmode: 33188\nnlink: 1\nuid: 0\n", 1},
		"an empty field name": {": 4\n", 1},
	}
	for name, tc := range bad {
		if _, err := parseGuestStats(tc.output, tc.n); err == nil {
			t.Errorf("%s: parseGuestStats accepted %q", name, tc.output)
		}
	}
}

func TestGuestFileKindsRefusesAnswersItCannotUse(t *testing.T) {
	answer := func(output string) *Adapter {
		return &Adapter{run: func(context.Context, ...string) (string, error) { return output, nil }}
	}
	paths := []string{"/a"}
	good := "false\nfalse\ntrue\nfalse\nfalse\nfalse\nfalse\n"
	kinds, err := answer(good).guestFileKinds(context.Background(), []string{bootOverlayPath}, paths)
	if err != nil || len(kinds) != 1 || kinds[0] != kindRegular {
		t.Fatalf("kinds = %v, %v", kinds, err)
	}
	for name, output := range map[string]string{
		"too few answers":  "false\n",
		"too many answers": good + "false\n",
		"an odd answer":    "maybe\nfalse\nfalse\nfalse\nfalse\nfalse\nfalse\n",
		"two kinds":        "true\nfalse\ntrue\nfalse\nfalse\nfalse\nfalse\n",
		"no output":        "",
	} {
		if _, err := answer(output).guestFileKinds(context.Background(), []string{bootOverlayPath}, paths); err == nil {
			t.Errorf("%s: accepted %q", name, output)
		}
	}
	absent, err := answer("false\nfalse\nfalse\nfalse\nfalse\nfalse\nfalse\n").guestFileKinds(context.Background(), []string{bootOverlayPath}, paths)
	if err != nil || absent[0] != "" {
		t.Fatalf("absent = %v, %v", absent, err)
	}
}

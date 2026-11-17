// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

const notAConfiguration = "the backup's VM configuration (qemu-server.conf) is not a Proxmox VE configuration: it holds binary data"

// randomBytes is 4 KiB of pseudo-random bytes, the same every run.
func randomBytes() []byte {
	data := make([]byte, 4096)
	rand.New(rand.NewSource(9906)).Read(data)
	return data
}

// A configuration blob that is not text would read as a configuration with no
// keys, and the run would take PVE's defaults (ostype other, scsihw lsi, 2
// cores, 2048 MiB) for a VM whose backup said nothing of them. Both
// parsers refuse a NUL byte anywhere, and invalid UTF-8 or a control character
// other than tab, CR and LF on a line that is not a comment, and accept what
// PVE writes.
func TestAConfigurationThatIsNotTextIsRefused(t *testing.T) {
	valid := "cores: 4\nmemory: 4096\nscsi0: local-lvm:vm-7011-disk-0,size=32G\n"
	noNUL := bytes.ReplaceAll(randomBytes(), []byte{0}, []byte("a"))
	for name, data := range map[string]string{
		"random bytes":                    string(randomBytes()),
		"random bytes without a NUL":      string(noNUL),
		"a NUL byte":                      valid + "\x00",
		"a NUL inside a comment":          "#a\x00b\n" + valid,
		"invalid UTF-8":                   valid + "tags: \xff\xfe\n",
		"an escape character":             valid + "tags: a\x1b[31mred\n",
		"a bell":                          "\x07" + valid,
		"a delete character":              valid + "tags: a\x7f\n",
		"a form feed":                     valid + "\x0c",
		"a control character after a tag": valid + "#note\ntags: a;b\x01\n",
	} {
		_, profileErr := ParseVMProfile([]byte(data))
		_, layoutErr := ParseVMLayout([]byte(data))
		for parser, err := range map[string]error{"ParseVMProfile": profileErr, "ParseVMLayout": layoutErr} {
			if err == nil || err.Error() != notAConfiguration {
				t.Errorf("%s: %s: err = %v, want %q", name, parser, err, notAConfiguration)
			}
		}
	}
	// What PVE writes: tabs, CRLF line ends, and non-ASCII text, even in a
	// comment.
	for name, data := range map[string]string{
		"tabs":          "cores:\t4\nscsi0: local:vm-1-disk-0,size=1G\n",
		"CRLF":          "cores: 4\r\nscsi0: local:vm-1-disk-0,size=1G\r\n",
		"a UTF-8 note":  "#Serveur de fichiers, \u00e9t\u00e9 \u65e5\u672c\ncores: 4\n",
		"an empty file": "",
	} {
		if _, err := ParseVMProfile([]byte(data)); err != nil {
			t.Errorf("%s: ParseVMProfile: %v", name, err)
		}
		if _, err := ParseVMLayout([]byte(data)); err != nil {
			t.Errorf("%s: ParseVMLayout: %v", name, err)
		}
	}
}

// ESC, CR and BEL in the description (the # lines, which the parser ignores)
// and in name:. A real backup whose VM description holds a control character
// is not refused for it: the configuration parses, and the name, which is no
// DNS name, is dropped. The same file with the
// control characters on a line the parser reads is not a configuration.
func TestAControlCharacterInADescriptionDoesNotRefuseTheConfiguration(t *testing.T) {
	const fixture9913 = "#\x1b[31mRED\x1b[0m chaos notes\x07\r\n" +
		"#\x1b]0;owned\x07 \xff\xfe\n" +
		"name: \x1b[31mred\x07\r\n" +
		"cores: 2\nmemory: 2048\nscsi0: local-lvm:vm-9913-disk-0,size=1G\n"
	profile, err := ParseVMProfile([]byte(fixture9913))
	if err != nil {
		t.Fatalf("ParseVMProfile: %v", err)
	}
	if profile.Name != "" || profile.Cores != 2 || !profile.configuredDisks["scsi0"] {
		t.Errorf("profile = name %q, cores %d, disks %v; want the name dropped and the rest read", profile.Name, profile.Cores, profile.configuredDisks)
	}
	if layout, err := ParseVMLayout([]byte(fixture9913)); err != nil || len(layout.Disks) != 1 {
		t.Errorf("ParseVMLayout = %+v, %v", layout, err)
	}
	// Through the loaders, with the snapshot's own disk.
	fakeBackupClient(t, listingWithConfigSize("200"), fixture9913)
	if layoutErr, profileErr, _ := loadBoth(t); layoutErr != nil || profileErr != nil {
		t.Errorf("loaders: layout %v, profile %v", layoutErr, profileErr)
	}
	// A NUL is binary data wherever it is, even in the description.
	if _, err := ParseVMProfile([]byte(fixture9913 + "#\x00\n")); err == nil || err.Error() != notAConfiguration {
		t.Errorf("a NUL in the description: %v", err)
	}
}

// A snapshot with 4 KiB of random bytes as its configuration
// and one disk archive. Both loaders refuse it with the reason, whatever the
// bytes happen to hold.
func TestASnapshotWhoseConfigurationIsBinaryIsRefusedByBothLoaders(t *testing.T) {
	fakeBackupClient(t, listingWithConfigSize("4096"), string(randomBytes()))
	layoutErr, profileErr, _ := loadBoth(t)
	for loader, err := range map[string]error{"LoadVMLayout": layoutErr, "LoadVMProfile": profileErr} {
		if err == nil || err.Error() != notAConfiguration {
			t.Errorf("%s: err = %v, want %q", loader, err, notAConfiguration)
		}
	}
}

// A configuration of text that lists none of the snapshot's disks is not that
// snapshot's configuration: the run would restore a disk the configuration
// never described, with the hardware of an empty file. An archive the
// configuration marks backup=0 is as unexpected.
func TestADiskArchiveTheConfigurationDoesNotListIsRefused(t *testing.T) {
	for name, tc := range map[string]struct{ config, want string }{
		"no disk line":  {"cores: 2\nmemory: 2048\n", "the snapshot holds drive-scsi0 but its configuration lists no scsi0"},
		"another slot":  {"scsi1: local:vm-1-disk-0,size=1G\n", "the snapshot holds drive-scsi0 but its configuration lists no scsi0"},
		"an empty file": {"", "the snapshot holds drive-scsi0 but its configuration lists no scsi0"},
		"excluded":      {"scsi0: local:vm-1-disk-0,size=1G,backup=0\n", "the snapshot holds drive-scsi0 but its configuration excludes scsi0 from backups (backup=0)"},
	} {
		t.Run(name, func(t *testing.T) {
			files := `[{"filename":"qemu-server.conf.blob","crypt-mode":"none","size":64},{"filename":"drive-scsi0.img.fidx","crypt-mode":"none","size":1048576}]`
			if name == "another slot" {
				files = `[{"filename":"qemu-server.conf.blob","crypt-mode":"none","size":64},{"filename":"drive-scsi0.img.fidx","crypt-mode":"none","size":1048576},{"filename":"drive-scsi1.img.fidx","crypt-mode":"none","size":1048576}]`
			}
			fakeBackupClient(t, files, tc.config)
			layoutErr, profileErr, _ := loadBoth(t)
			for loader, err := range map[string]error{"LoadVMLayout": layoutErr, "LoadVMProfile": profileErr} {
				if err == nil || err.Error() != tc.want {
					t.Errorf("%s: err = %v, want %q", loader, err, tc.want)
				}
			}
		})
	}
	// The control: a configuration that lists the archive's disk is accepted.
	fakeBackupClient(t, listingWithConfigSize("64"), "cores: 2\nscsi0: local:vm-1-disk-0,size=1G\n")
	if layoutErr, profileErr, _ := loadBoth(t); layoutErr != nil || profileErr != nil {
		t.Fatalf("a configuration that lists scsi0: layout %v, profile %v", layoutErr, profileErr)
	}
}

// A snapshot with no qemu-server.conf.blob: its file list says it holds none,
// so both loaders say so, instead of a bare "exit status 255", and no restore
// is tried. A listing that cannot be read leaves the decision to the steps
// after it.
func TestASnapshotWithoutAConfigurationSaysSoBeforeRestoring(t *testing.T) {
	const want = "the backup holds no VM configuration (qemu-server.conf): it is not a backup PVE made of a VM"
	log := fakeBackupClient(t, `[{"filename":"drive-scsi0.img.fidx","crypt-mode":"none","size":1048576},{"filename":"index.json.blob","crypt-mode":"none","size":300}]`, "scsi0: local:vm-1-disk-0,size=1G\n")
	layoutErr, profileErr, scratch := loadBoth(t)
	for loader, err := range map[string]error{"LoadVMLayout": layoutErr, "LoadVMProfile": profileErr} {
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%s: err = %v, want it to start %q", loader, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "withheld") {
			t.Errorf("%s: the reason is still hidden: %v", loader, err)
		}
	}
	if n := restoreCalls(t, log); n != 0 {
		t.Errorf("the configuration was restored %d times, want never", n)
	}
	mustBeEmpty(t, scratch)
}

const containerArchiveRefusal = "the backup holds a container's file archive (root.pxar), not a VM disk: CertiStack restore-tests VMs only"

// A vm/ group that holds a container's backup, a root.pxar and a pct
// configuration, whose first line would be refused as a VM's ("unsupported
// source net0 model "name""). Both loaders say what it is, before they read
// the configuration, whether or not the snapshot lists one under the VM's
// name; a snapshot that also holds a disk is not a container backup, and goes
// on.
func TestAContainersBackupIsNamedBeforeItsConfigurationIsRead(t *testing.T) {
	const pctConfig = "arch: amd64\nhostname: ct\nnet0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=dhcp\nostype: debian\nrootfs: local:9911/vm-9911-disk-0.raw,size=8G\n"
	for name, files := range map[string]string{
		"as PVE writes it":                  `[{"filename":"pct.conf.blob"},{"filename":"root.pxar.didx","size":1048576},{"filename":"index.json.blob"}]`,
		"with a qemu-server.conf.blob":      `[{"filename":"qemu-server.conf.blob"},{"filename":"root.pxar.didx","size":1048576},{"filename":"index.json.blob"}]`,
		"with the newer pxar archive names": `[{"filename":"pct.conf.blob"},{"filename":"root.mpxar.didx"},{"filename":"root.ppxar.didx"},{"filename":"index.json.blob"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			log := fakeBackupClient(t, files, pctConfig)
			layoutErr, profileErr, scratch := loadBoth(t)
			for loader, err := range map[string]error{"LoadVMLayout": layoutErr, "LoadVMProfile": profileErr} {
				if err == nil || err.Error() != containerArchiveRefusal {
					t.Errorf("%s: err = %v, want %q", loader, err, containerArchiveRefusal)
				}
			}
			if n := restoreCalls(t, log); n != 0 {
				t.Errorf("the configuration was restored %d times, want never", n)
			}
			mustBeEmpty(t, scratch)
		})
	}
	// A snapshot with a disk and a stray root.pxar is not a container backup.
	fakeBackupClient(t, `[{"filename":"qemu-server.conf.blob"},{"filename":"root.pxar.didx"},{"filename":"drive-scsi0.img.fidx"}]`, "cores: 2\nscsi0: local:vm-1-disk-0,size=1G\n")
	if layoutErr, profileErr, _ := loadBoth(t); layoutErr != nil || profileErr != nil {
		t.Errorf("a snapshot with a disk: layout %v, profile %v", layoutErr, profileErr)
	}
}

// init lists the VMs that have a complete backup. A group whose newest
// snapshot holds no disk image (a container's backup under vm/) is no VM
// backup, and was listed with "unknown" disks.
func TestParseVMBackupsJSONLeavesOutAGroupWithNoDiskImage(t *testing.T) {
	data := []byte(`[
	  {"backup-type":"vm","backup-id":"9911","backup-time":1790000000,"files":[{"filename":"pct.conf.blob"},{"filename":"root.pxar.didx","size":1048576},{"filename":"index.json.blob"}]},
	  {"backup-type":"vm","backup-id":"9912","backup-time":1790000000,"files":[{"filename":"qemu-server.conf.blob"},{"filename":"drive-efidisk0.img.fidx"},{"filename":"index.json.blob"}]},
	  {"backup-type":"vm","backup-id":"9913","backup-time":1790000000,"files":[{"filename":"qemu-server.conf.blob"},{"filename":"drive-scsi0.img.fidx","size":1048576},{"filename":"index.json.blob"}]}
	]`)
	backups, err := ParseVMBackupsJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 || backups[0].VMID != 9913 {
		t.Fatalf("listed %+v, want only VM 9913, the one with a disk image", backups)
	}
}

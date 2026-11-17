// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"strings"
	"testing"
)

const (
	nmCustomDir   = "/etc/NetworkManager/custom-connections"
	nmDropIn      = nmEtcConfDir + "/99-keyfile.conf"
	nmEL7         = "ID=centos\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"7.9\"\n"
	nmTestProfile = "90-certistack-recovery.nmconnection"
)

// loadsKeyfileAfter applies configuration files in the order given, as
// NetworkManager would read them, and reports whether keyfile is a loaded
// plugin.
func loadsKeyfileAfter(t *testing.T, files ...string) bool {
	t.Helper()
	var accumulated nmAccumulator
	for _, contents := range files {
		entries, err := parseNMConfig(contents)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if err := accumulated.apply("test.conf", entry); err != nil {
				t.Fatal(err)
			}
		}
	}
	settings := nmSettings{plugins: accumulated.plugins, pluginsSet: accumulated.pluginsSet}
	return settings.loadsKeyfile()
}

func nmSettingsOf(t *testing.T, guest *memGuest) (*nmSettings, error) {
	t.Helper()
	return newDetection(guest.adapter(), []string{bootOverlayPath}, ifcfgTestMAC).networkManagerSettings(context.Background())
}

func TestParseNMConfig(t *testing.T) {
	entries, err := parseNMConfig("\xef\xbb\xbf# comment\n\n[main]\nplugins = ifcfg-rh , keyfile\r\n  # indented comment\n[keyfile]\npath=/x\nunmanaged-devices=mac:00:11;interface-name:eth1\n[.config]\nenable=false\n")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.group+"/"+entry.key+"="+entry.value)
	}
	want := "main/plugins=ifcfg-rh , keyfile keyfile/path=/x keyfile/unmanaged-devices=mac:00:11;interface-name:eth1 .config/enable=false"
	if strings.Join(got, " ") != want {
		t.Fatalf("entries = %q\nwant      %q", strings.Join(got, " "), want)
	}
	for name, contents := range map[string]string{
		"a key before any group":     "plugins=keyfile\n[main]\n",
		"a line that is nothing":     "[main]\nplugins\n",
		"an empty key":               "[main]\n=keyfile\n",
		"an unterminated group":      "[main\nplugins=keyfile\n",
		"an empty group":             "[]\n",
		"nested brackets":            "[a[b]]\n",
		"a control character":        "[main]\nplugins=key\x01file\n",
		"invalid UTF-8":              "[main]\nplugins=\xff\n",
		"a group with trailing junk": "[main] x\n",
	} {
		if _, err := parseNMConfig(contents); err == nil {
			t.Errorf("%s: parsed without an error", name)
		}
	}
}

// The plugin list as NetworkManager merges it.
func TestNMPluginListMergesAsNetworkManagerDoes(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  bool
	}{
		{"nothing set is the distribution's default, which EL7 builds without keyfile", []string{"[main]\n"}, false},
		{"listed", []string{"[main]\nplugins=keyfile\n"}, true},
		{"listed after ifcfg-rh", []string{"[main]\nplugins=ifcfg-rh,keyfile\n"}, true},
		{"a later file replaces the list", []string{"[main]\nplugins=ifcfg-rh\n", "[main]\nplugins=keyfile\n"}, true},
		{"a later file replaces the list, dropping keyfile", []string{"[main]\nplugins=ifcfg-rh,keyfile\n", "[main]\nplugins=ifcfg-rh\n"}, false},
		{"plugins+= extends the list", []string{"[main]\nplugins=ifcfg-rh\n", "[main]\nplugins+=keyfile\n"}, true},
		{"plugins+= on the default", []string{"[main]\nplugins+=keyfile\n"}, true},
		{"plugins-= reduces the list", []string{"[main]\nplugins=ifcfg-rh,keyfile\n", "[main]\nplugins-=keyfile\n"}, false},
		{"plugins-= of another plugin keeps keyfile", []string{"[main]\nplugins=ifcfg-rh,keyfile\n", "[main]\nplugins-=ifcfg-rh\n"}, true},
		{"the last assignment of a key in a file wins", []string{"[main]\nplugins=keyfile\nplugins=ifcfg-rh\n"}, false},
		{"a section of another name does not count", []string{"[other]\nplugins=keyfile\n"}, false},
		{"an empty assignment empties the list", []string{"[main]\nplugins=keyfile\n", "[main]\nplugins=\n"}, false},
		{"another key does not count", []string{"[main]\nplugins-extra=keyfile\n"}, false},
		// Only "#" starts a comment in the key file format; ";plugins" is a key
		// of its own, not an assignment of plugins.
		{"a semicolon line is a key of its own", []string{"[main]\n;plugins=keyfile\n"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := loadsKeyfileAfter(t, tc.files...); got != tc.want {
				t.Fatalf("keyfile loaded = %v, want %v", got, tc.want)
			}
		})
	}
}

// NetworkManager can be told to keep its keyfile profiles in another
// directory; the profile goes there, not to the conventional one, which it
// then never reads.
func TestApplyWritesTheKeyfileWhereTheGuestsNetworkManagerReadsIt(t *testing.T) {
	custom := "[keyfile]\npath=" + nmCustomDir + "\n"
	want := nmCustomDir + "/" + nmTestProfile
	cases := []struct {
		name  string
		mode  string
		files map[string]string
		dirs  []string
	}{
		{"both directories, explicit mode", modeNetworkManager, map[string]string{networkManagerConf: custom, nmCustomDir + "/existing.nmconnection": "[connection]\nid=existing\n"}, []string{networkManagerDir, nmCustomDir}},
		{"both directories, auto", modeAuto, map[string]string{networkManagerConf: custom, nmCustomDir + "/existing.nmconnection": "[connection]\nid=existing\n"}, []string{networkManagerDir, nmCustomDir}},
		// Only the configured directory exists: the guest still has NetworkManager.
		{"only the configured directory, explicit mode", modeNetworkManager, map[string]string{networkManagerConf: custom}, []string{nmCustomDir}},
		{"only the configured directory, auto", modeAuto, map[string]string{networkManagerConf: custom}, []string{nmCustomDir}},
		{"configured by a snippet", modeNetworkManager, map[string]string{nmEtcConfDir + "/10-path.conf": custom}, []string{nmCustomDir}},
		{"configured by a vendor snippet", modeAuto, map[string]string{nmUsrLibConfDir + "/10-path.conf": custom}, []string{nmCustomDir}},
		{"with a trailing slash", modeNetworkManager, map[string]string{networkManagerConf: "[keyfile]\npath=" + nmCustomDir + "/\n"}, []string{nmCustomDir}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest := newMemGuest(t, tc.files, tc.dirs...)
			defaultBefore := map[string]string{}
			for name, contents := range guest.files {
				if strings.HasPrefix(name, networkManagerDir+"/") {
					defaultBefore[name] = contents
				}
			}
			cfg := multiDiskConfig(bootOverlayPath)
			cfg.Mode = tc.mode
			result, err := guest.adapter().Apply(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if result.Strategy != modeNetworkManager || result.Files[0] != want {
				t.Fatalf("result = %+v, want the profile at %s", result, want)
			}
			if !strings.Contains(guest.files[want], "autoconnect-priority=999") {
				t.Fatalf("nothing was written to %s", want)
			}
			if seed := nmCustomDir + "/existing.nmconnection"; guest.files[seed] != "" && !batchHasCommand(lastBatch(guest.calls), "cp-a", seed, want) {
				t.Fatalf("the profile was not seeded from the configured directory's own profile: %#v", lastBatch(guest.calls))
			}
			for name := range guest.files {
				if strings.HasPrefix(name, networkManagerDir+"/") && defaultBefore[name] == "" {
					t.Fatalf("%s was written to the conventional directory, which this guest's NetworkManager does not read", name)
				}
			}
		})
	}
}

// A configured directory that is not there is not "NetworkManager is
// present", and the conventional one beside it does not make up for it.
func TestAMissingConfiguredKeyfileDirectoryIsNotNetworkManager(t *testing.T) {
	files := map[string]string{networkManagerConf: "[keyfile]\npath=" + nmCustomDir + "\n"}
	guest := newMemGuest(t, files, networkManagerDir)
	cfg := multiDiskConfig(bootOverlayPath)
	cfg.Mode = modeNetworkManager
	_, err := guest.adapter().Apply(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "not present") || !strings.Contains(err.Error(), nmCustomDir) {
		t.Fatalf("Apply = %v, want the configured directory named as missing", err)
	}
	if guest.mutated() {
		t.Fatal("something was written")
	}
	cfg.Mode = modeAuto
	if _, err := guest.adapter().Apply(context.Background(), cfg); err == nil {
		t.Fatal("auto recovery wrote a profile into the conventional directory although NetworkManager reads another")
	}
}

// An EL7 guest's main file lists ifcfg-rh only; a snippet in conf.d overrides
// the list to keyfile. The adapter reads the snippet, takes the keyfile plugin
// for loaded and writes a keyfile profile, not an ifcfg one.
func TestEL7PluginListOverrideInADropInIsHonored(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{osReleaseFile: nmEL7, networkManagerConf: "[main]\nplugins=ifcfg-rh\n"}
	}
	cases := []struct {
		name     string
		mutate   func(map[string]string)
		strategy string
	}{
		{"main file only: ifcfg-rh", func(map[string]string) {}, modeIfcfg},
		{"a drop-in lists keyfile", func(f map[string]string) { f[nmDropIn] = "[main]\nplugins=keyfile\n" }, modeNetworkManager},
		{"a drop-in extends the list", func(f map[string]string) { f[nmDropIn] = "[main]\nplugins+=keyfile\n" }, modeNetworkManager},
		{"a drop-in in /run", func(f map[string]string) { f[nmRunConfDir+"/50.conf"] = "[main]\nplugins=keyfile\n" }, modeIfcfg},
		{"a vendor snippet is overridden by the main file", func(f map[string]string) { f[nmUsrLibConfDir+"/50.conf"] = "[main]\nplugins=keyfile\n" }, modeIfcfg},
		{"a drop-in drops keyfile again", func(f map[string]string) {
			f[networkManagerConf] = "[main]\nplugins=ifcfg-rh,keyfile\n"
			f[nmDropIn] = "[main]\nplugins-=keyfile\n"
		}, modeIfcfg},
		{"a later drop-in wins over an earlier one", func(f map[string]string) {
			f[nmEtcConfDir+"/10-a.conf"] = "[main]\nplugins=keyfile\n"
			f[nmEtcConfDir+"/20-b.conf"] = "[main]\nplugins=ifcfg-rh\n"
		}, modeIfcfg},
		{"a switched-off drop-in does not count", func(f map[string]string) {
			f[nmDropIn] = "[.config]\nenable=false\n[main]\nplugins=keyfile\n"
		}, modeIfcfg},
		{"a drop-in masked by an empty file of its name in /etc", func(f map[string]string) {
			f[nmUsrLibConfDir+"/99-keyfile.conf"] = "[main]\nplugins=keyfile\n"
			f[nmDropIn] = ""
		}, modeIfcfg},
		{"a drop-in masked by a link to /dev/null", func(f map[string]string) {
			f[nmUsrLibConfDir+"/99-keyfile.conf"] = "[main]\nplugins=keyfile\n"
			f[nmDropIn] = "-> /dev/null"
		}, modeIfcfg},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := base()
			tc.mutate(files)
			guest := newMemGuest(t, files, networkManagerDir, ifcfgDir)
			result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
			if err != nil {
				t.Fatal(err)
			}
			if result.Strategy != tc.strategy {
				t.Fatalf("strategy = %q, want %q (files: %v)", result.Strategy, tc.strategy, files)
			}
			if tc.strategy == modeNetworkManager && result.Files[0] != networkManagerProfile {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

// The reading order and the shadowing, on the settings directly.
func TestNetworkManagerConfigurationOrderAndShadowing(t *testing.T) {
	path := func(dir string) string { return "[keyfile]\npath=" + dir + "\n" }
	cases := []struct {
		name    string
		files   map[string]string
		wantDir string
	}{
		{"the default", nil, networkManagerDir},
		{"the main file", map[string]string{networkManagerConf: path("/a")}, "/a"},
		{"a vendor snippet", map[string]string{nmUsrLibConfDir + "/10.conf": path("/a")}, "/a"},
		{"/run overrides /usr/lib", map[string]string{nmUsrLibConfDir + "/10.conf": path("/a"), nmRunConfDir + "/10-b.conf": path("/b")}, "/b"},
		{"the main file overrides /run and /usr/lib", map[string]string{nmUsrLibConfDir + "/99.conf": path("/a"), nmRunConfDir + "/99.conf": path("/b"), networkManagerConf: path("/main")}, "/main"},
		{"/etc snippets override the main file", map[string]string{networkManagerConf: path("/main"), nmEtcConfDir + "/00.conf": path("/etc")}, "/etc"},
		{"snippets are read in file-name order", map[string]string{nmEtcConfDir + "/20-b.conf": path("/b"), nmEtcConfDir + "/10-a.conf": path("/a")}, "/b"},
		{"/etc shadows a /usr/lib snippet of the same name", map[string]string{nmUsrLibConfDir + "/10.conf": path("/vendor"), nmEtcConfDir + "/10.conf": "[main]\n"}, networkManagerDir},
		{"/run shadows a /usr/lib snippet of the same name", map[string]string{nmUsrLibConfDir + "/10.conf": path("/vendor"), nmRunConfDir + "/10.conf": "[main]\n"}, networkManagerDir},
		{"the internal file is read last", map[string]string{nmEtcConfDir + "/10.conf": path("/etc"), nmInternConf: path("/intern")}, "/intern"},
		{"only .conf files are snippets", map[string]string{nmEtcConfDir + "/10.conf.bak": path("/a"), nmEtcConfDir + "/10.txt": path("/b"), nmEtcConfDir + "/10.conf~": path("/c")}, networkManagerDir},
		{"a hidden .conf file is read", map[string]string{nmEtcConfDir + "/.10.conf": path("/hidden")}, "/hidden"},
		{"a link to /dev/null masks a snippet", map[string]string{nmEtcConfDir + "/10.conf": "-> /dev/null"}, networkManagerDir},
		{"a relative link to /dev/null masks a snippet", map[string]string{nmEtcConfDir + "/10.conf": "-> ../../../dev/null"}, networkManagerDir},
		{"the path may equal the default", map[string]string{networkManagerConf: path(networkManagerDir)}, networkManagerDir},
		{"a switched-off snippet does not count", map[string]string{nmEtcConfDir + "/10.conf": "[.config]\nenable=false\n" + path("/a")}, networkManagerDir},
		{"a switched-on snippet counts", map[string]string{nmEtcConfDir + "/10.conf": "[.config]\nenable=true\n" + path("/a")}, "/a"},
		{"a snippet conditioned on the version that sets nothing here is no problem", map[string]string{nmEtcConfDir + "/10.conf": "[.config]\nenable=nm-version-min:1.2\n[logging]\nlevel=INFO\n"}, networkManagerDir},
		{"the main file cannot be switched off", map[string]string{networkManagerConf: "[.config]\nenable=false\n" + path("/a")}, "/a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dirs := []string{networkManagerDir}
			guest := newMemGuest(t, tc.files, dirs...)
			settings, err := nmSettingsOf(t, guest)
			if err != nil {
				t.Fatal(err)
			}
			if settings.keyfileDir != tc.wantDir {
				t.Fatalf("keyfile directory = %q, want %q", settings.keyfileDir, tc.wantDir)
			}
		})
	}
}

// What cannot be evaluated is refused, naming the file, and nothing is written:
// the alternative is a successful Apply that put the profile where
// NetworkManager does not read it.
func TestNetworkManagerConfigurationThatCannotBeEvaluatedIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		dirs    []string
		wantErr string
	}{
		{"a malformed main file", map[string]string{networkManagerConf: "[main]\nplugins\n"}, nil, networkManagerConf},
		{"a malformed snippet", map[string]string{nmDropIn: "no group\n"}, nil, nmDropIn},
		{"a relative keyfile path", map[string]string{networkManagerConf: "[keyfile]\npath=connections\n"}, nil, "not an absolute path"},
		{"a keyfile path with a dot-dot", map[string]string{networkManagerConf: "[keyfile]\npath=/etc/NetworkManager/../x\n"}, nil, `contains ".."`},
		{"the root as keyfile path", map[string]string{networkManagerConf: "[keyfile]\npath=/\n"}, nil, "root directory"},
		{"a keyfile path with a backslash", map[string]string{networkManagerConf: "[keyfile]\npath=/etc/a\\sb\n"}, nil, "backslash"},
		{"an empty keyfile path", map[string]string{networkManagerConf: "[keyfile]\npath=\n"}, nil, "path is empty"},
		{"a modified keyfile path", map[string]string{networkManagerConf: "[keyfile]\npath+=/x\n"}, nil, "does not evaluate"},
		{"a version-conditional snippet that sets the plugins", map[string]string{nmDropIn: "[.config]\nenable=nm-version-min:1.2\n[main]\nplugins=keyfile\n"}, nil, "condition"},
		{"an environment-conditional snippet that sets the path", map[string]string{nmDropIn: "[.config]\nenable=env:TAG\n[keyfile]\npath=/x\n"}, nil, "condition"},
		{"a snippet directory that is a link", map[string]string{nmEtcConfDir: "-> /elsewhere"}, nil, "symbolic link"},
		{"a snippet that is a directory", map[string]string{nmEtcConfDir + "/x.conf/inner": "x"}, nil, "directory"},
		{"a snippet that is a link to a file", map[string]string{nmEtcConfDir + "/x.conf": "-> /usr/share/x.conf", "/usr/share/x.conf": "[main]\n"}, nil, "symbolic link"},
		{"a snippet that is a pipe", map[string]string{nmEtcConfDir + "/x.conf": "!fifo"}, nil, "named pipe"},
		{"a main file that is a link to a file", map[string]string{networkManagerConf: "-> /usr/share/nm.conf"}, nil, "symbolic link"},
	}
	for _, tc := range cases {
		for _, mode := range []string{modeNetworkManager, modeAuto} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				guest := newMemGuest(t, tc.files, append([]string{networkManagerDir}, tc.dirs...)...)
				cfg := multiDiskConfig(bootOverlayPath)
				cfg.Mode = mode
				_, err := guest.adapter().Apply(context.Background(), cfg)
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Apply = %v, want an error containing %q", err, tc.wantErr)
				}
				if guest.mutated() {
					t.Fatal("something was written")
				}
			})
		}
	}
}

// Reading the configuration stays cheap: every run is a guestfish appliance
// start. The files are told apart by what guestfish echoes between them, so a
// file that holds a made-up separator cannot stand for one.
func TestNetworkManagerConfigurationIsReadInFewGuestfishRuns(t *testing.T) {
	files := map[string]string{
		networkManagerConf:             "[main]\nplugins=keyfile\n",
		nmUsrLibConfDir + "/00-a.conf": "[main]\n",
		nmUsrLibConfDir + "/10-b.conf": "[logging]\nlevel=INFO\n",
		nmEtcConfDir + "/20-c.conf":    "[connectivity]\nuri=http://x\n",
		nmEtcConfDir + "/30-d.conf":    "-> /dev/null",
		nmInternConf:                   "[main]\nno-auto-default=*\n",
		nmRunConfDir + "/40-e.conf":    "[main]\nplugins=ifcfg-rh\n# certistack-end-0000\n",
	}
	guest := newMemGuest(t, files, networkManagerDir)
	settings, err := nmSettingsOf(t, guest)
	if err != nil {
		t.Fatal(err)
	}
	if settings.loadsKeyfile() != true || settings.keyfileDir != networkManagerDir {
		t.Fatalf("settings = %+v", settings)
	}
	// what exists, the listings, what each snippet is, the links, the contents.
	if len(guest.calls) != 5 {
		t.Fatalf("guestfish runs = %d, want 5: %#v", len(guest.calls), guest.calls)
	}
	bare := newMemGuest(t, nil, networkManagerDir)
	if _, err := nmSettingsOf(t, bare); err != nil || len(bare.calls) != 1 {
		t.Fatalf("a guest with no configuration file: %d runs (%v), want the single run the directory check always cost", len(bare.calls), err)
	}
}

// A malformed NetworkManager file beside a guest that NetworkManager does not
// configure is no reason to refuse that guest.
func TestAnUnreadableNetworkManagerConfigurationDoesNotBlockAnotherBackend(t *testing.T) {
	files := map[string]string{
		networkManagerConf:                "[main]\nplugins\n",
		"/etc/netplan/50-cloud-init.yaml": "network:\n  version: 2\n  ethernets:\n    ens18:\n      match:\n        macaddress: '" + strings.ToLower(ifcfgTestMAC) + "'\n      dhcp4: true\n",
	}
	guest := newMemGuest(t, files, networkManagerDir, netplanDir)
	result, err := guest.adapter().Apply(context.Background(), multiDiskConfig(bootOverlayPath))
	if err != nil {
		t.Fatal(err)
	}
	if result.Strategy != modeNetplan {
		t.Fatalf("strategy = %q, want netplan: networkd renders the definition, NetworkManager's files are not what configures the guest", result.Strategy)
	}
}

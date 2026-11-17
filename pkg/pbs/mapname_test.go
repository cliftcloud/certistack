// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A real map of vm/7214 scsi1 (losetup shows each literal backslash
// as \x5c): the file name is the escaped repository followed by this suffix.
const e13MapName = `backup\x40pbs\x21ci\x2dtoken\x40192.0.2.5\x3a8007\x3apbs\x2ddata\x3avm-7214-2026\x2d09\x2d27T03\x3a12\x3a59Z-drive\x2dscsi1.img`

func TestMapNameSuffixMatchesTheClientsName(t *testing.T) {
	for _, drive := range []string{"drive-scsi1.img.fidx", "drive-scsi1.img", "drive-scsi1"} {
		suffix, err := MapNameSuffix("vm/7214/2026-09-27T03:12:59Z", drive)
		if err != nil {
			t.Fatal(err)
		}
		if want := `\x3avm-7214-2026\x2d09\x2d27T03\x3a12\x3a59Z-drive\x2dscsi1.img`; suffix != want {
			t.Fatalf("%s: suffix %q, want %q", drive, suffix, want)
		}
		if !strings.HasSuffix(e13MapName, suffix) {
			t.Fatalf("the map name does not end with %q", suffix)
		}
	}
	// The whole name, from the repository it was given.
	if got := escapeUnit("backup@pbs!ci-token@192.0.2.5:8007:pbs-data:vm/7214/2026-09-27T03:12:59Z/drive-scsi1.img"); got != e13MapName {
		t.Fatalf("escapeUnit = %q, want %q", got, e13MapName)
	}
}

func TestMapNameSuffixRefusesBadInput(t *testing.T) {
	for _, tc := range [][2]string{{"../etc", "drive-scsi0.img"}, {"vm/1/2026-01-01T00:00:00Z", "a/b"}} {
		if _, err := MapNameSuffix(tc[0], tc[1]); err == nil {
			t.Errorf("MapNameSuffix(%q, %q) accepted", tc[0], tc[1])
		}
	}
}

// envOf is the environment variables Owner reads from a command's env.
func envOf(env []string) map[string]string {
	vars := map[string]string{}
	for _, kv := range env {
		if name, value, ok := strings.Cut(kv, "="); ok && (name == "PBS_REPOSITORY" || name == "PBS_NAMESPACE") {
			vars[name] = value
		}
	}
	return vars
}

// Recovery recognizes a map process by the exact command line Map
// runs and by what it maps from. Map's own command, whatever the
// configuration, parses back to the source a run journals for it.
func TestParseMapCommandRecognizesTheMapsOwnCommand(t *testing.T) {
	const snapshot = "vm/7214/2026-09-27T03:12:59Z"
	for _, cfg := range []Config{
		{Repository: "backup@pbs!ci-token@192.0.2.5:pbs-data", Namespace: "team-a"},
		{Repository: "backup@pbs!ci-token@192.0.2.5:pbs-data", Keyfile: "/run/certistack/key.json"},
		{},
	} {
		c := New(cfg)
		var keyArgs []string
		if cfg.Keyfile != "" {
			keyArgs = []string{"--keyfile", cfg.Keyfile}
		}
		argv := append([]string{"proxmox-backup-client"}, c.mapArgs(snapshot, "drive-scsi1.img", keyArgs)...)
		m, ok := ParseMapCommand(argv)
		if !ok || m.Snapshot != snapshot || m.Archive != "drive-scsi1.img" {
			t.Fatalf("%v: ParseMapCommand = %+v, %v", argv, m, ok)
		}
		want, err := c.MapOwner(snapshot, "drive-scsi1.img.fidx")
		if err != nil {
			t.Fatal(err)
		}
		if got := m.Owner(envOf(c.buildEnv())); got != want {
			t.Fatalf("%v: owner %s, want the journaled %s", argv, got, want)
		}
		// The namespace is in the command line, so the owner does not depend on the
		// environment; the option beats the variable.
		if m.HasNamespace != (cfg.Namespace != "") || m.Namespace != cfg.Namespace {
			t.Fatalf("%v: namespace %q (%v), want %q", argv, m.Namespace, m.HasNamespace, cfg.Namespace)
		}
		if cfg.Namespace != "" {
			for name, env := range map[string]map[string]string{
				"no variable":      {"PBS_REPOSITORY": cfg.Repository},
				"another variable": {"PBS_REPOSITORY": cfg.Repository, "PBS_NAMESPACE": "team-b"},
			} {
				if got := m.Owner(env); got != want {
					t.Fatalf("%v with %s: owner %s, want the journaled %s", argv, name, got, want)
				}
			}
		}
	}
	// The --name=value form reads the same.
	m, ok := ParseMapCommand([]string{"/usr/bin/proxmox-backup-client", "map", "--keyfile=/k", "--repository=r@pbs@h:s", "--ns=team-a/sub", "vm/1/2026-09-27T03:00:00Z", "drive-scsi0.img"})
	if !ok || m.Repository != "r@pbs@h:s" || !m.HasRepository || m.Namespace != "team-a/sub" || !m.HasNamespace {
		t.Fatalf("inline options: %+v, %v", m, ok)
	}
	// A namespace that begins with "-" is joined to the option, and reads back.
	dash := New(Config{Repository: "r@pbs@h:s", Namespace: "-odd"})
	m, ok = ParseMapCommand(append([]string{"proxmox-backup-client"}, dash.mapArgs("vm/1/2026-09-27T03:00:00Z", "drive-scsi0.img", nil)...))
	if !ok || m.Namespace != "-odd" || strings.Contains(strings.Join(dash.mapArgs("vm/1/2026-09-27T03:00:00Z", "drive-scsi0.img", nil), " "), "--ns -odd") {
		t.Fatalf("a namespace that begins with a dash: %+v, %v", m, ok)
	}
}

// A map an earlier build started has no --ns, only PBS_NAMESPACE. It is still
// CertiStack's form, and is owned by the variable's value, which is what that
// build journaled.
func TestParseMapCommandStillReadsAMapWithoutNs(t *testing.T) {
	const snapshot = "vm/7214/2026-09-27T03:12:59Z"
	m, ok := ParseMapCommand([]string{"proxmox-backup-client", "map", "--repository", "r@pbs@h:s", snapshot, "drive-scsi1.img"})
	if !ok || m.HasNamespace {
		t.Fatalf("ParseMapCommand = %+v, %v", m, ok)
	}
	if got, want := m.Owner(map[string]string{"PBS_REPOSITORY": "other", "PBS_NAMESPACE": "team-a"}), MapOwner("r@pbs@h:s", "team-a", snapshot, "drive-scsi1.img"); got != want {
		t.Fatalf("owner %s, want %s", got, want)
	}
	if got, want := m.Owner(nil), MapOwner("r@pbs@h:s", "", snapshot, "drive-scsi1.img"); got != want {
		t.Fatalf("owner without a variable %s, want %s", got, want)
	}
	// A map of another namespace is not this one's: the option decides, though
	// the variable names the run's namespace.
	foreign, ok := ParseMapCommand([]string{"proxmox-backup-client", "map", "--repository", "r@pbs@h:s", "--ns", "team-b", snapshot, "drive-scsi1.img"})
	if !ok || foreign.Owner(map[string]string{"PBS_NAMESPACE": "team-a"}) == MapOwner("r@pbs@h:s", "team-a", snapshot, "drive-scsi1.img") ||
		foreign.Owner(nil) != MapOwner("r@pbs@h:s", "team-b", snapshot, "drive-scsi1.img") {
		t.Fatalf("a map of another namespace: %+v, %v", foreign, ok)
	}
}

// Command lines that name map, the snapshot and the archive but are
// not a map as a run starts it.
func TestParseMapCommandRefusesOtherCommands(t *testing.T) {
	const snapshot, archive = "vm/7214/2026-09-27T03:12:59Z", "drive-scsi1.img"
	for name, argv := range map[string][]string{
		"a restore whose target is named map": {"proxmox-backup-client", "restore", "--repository", "r", snapshot, archive, "map"},
		"two namespaces":                      {"proxmox-backup-client", "map", "--repository", "r", "--ns", "team-a", "--ns=team-b", snapshot, archive},
		"an empty namespace":                  {"proxmox-backup-client", "map", "--repository", "r", "--ns", "", snapshot, archive},
		"an empty inline namespace":           {"proxmox-backup-client", "map", "--repository", "r", "--ns=", snapshot, archive},
		"a namespace without a value":         {"proxmox-backup-client", "map", snapshot, archive, "--ns"},
		"a namespace after the snapshot":      {"proxmox-backup-client", "map", snapshot, "--ns", "team-a", archive},
		"a look-alike of the namespace":       {"proxmox-backup-client", "map", "--repository", "r", "--namespace", "team-a", snapshot, archive},
		"a verbose map":                       {"proxmox-backup-client", "map", "--verbose", snapshot, archive},
		"an extra argument":                   {"proxmox-backup-client", "map", snapshot, archive, "extra"},
		"a missing archive":                   {"proxmox-backup-client", "map", "--repository", "r", snapshot},
		"an option after the snapshot":        {"proxmox-backup-client", "map", snapshot, "--repository", "r"},
		"two repositories":                    {"proxmox-backup-client", "map", "--repository", "r", "--repository=s", snapshot, archive},
		"a repository without a value":        {"proxmox-backup-client", "map", snapshot, archive, "--repository"},
		"another program":                     {"/usr/bin/vim", "map", snapshot, archive},
		"map not the subcommand":              {"proxmox-backup-client", "snapshot", "map", snapshot, archive},
	} {
		if m, ok := ParseMapCommand(argv); ok {
			t.Errorf("%s: parsed as %+v", name, m)
		}
	}
}

// Maps of one snapshot and archive from different repositories or
// namespaces have different owners, and the owner never holds the
// repository.
func TestMapOwnerSeparatesSources(t *testing.T) {
	const snapshot, archive = "vm/7214/2026-09-27T03:12:59Z", "drive-scsi1.img"
	a := MapOwner("u@pbs!tok@repo-a:store", "team-a", snapshot, archive)
	for _, other := range []string{
		MapOwner("u@pbs!tok@repo-b:store", "team-a", snapshot, archive),
		MapOwner("u@pbs!tok@repo-a:store", "team-b", snapshot, archive),
		MapOwner("u@pbs!tok@repo-a:store", "", snapshot, archive),
		MapOwner("u@pbs!tok@repo-a:storeteam-a", "", snapshot, archive),
	} {
		if other == a {
			t.Fatal("two sources share an owner")
		}
	}
	if len(a) != 64 || strings.Contains(a, "tok") {
		t.Fatalf("owner %q", a)
	}
	// Without --repository, the client reads PBS_REPOSITORY.
	m := MapCommand{Snapshot: snapshot, Archive: archive}
	if m.Owner(map[string]string{"PBS_REPOSITORY": "u@pbs!tok@repo-a:store", "PBS_NAMESPACE": "team-a"}) != a {
		t.Fatal("PBS_REPOSITORY is not the repository of a map without --repository")
	}
}

func TestEscapeUnitLeadingDot(t *testing.T) {
	if got := escapeUnit(".a.b"); got != `\x2ea.b` {
		t.Fatalf("escapeUnit(.a.b) = %q", got)
	}
}

// A map's token is 128 random bits in hex, and only that form goes
// into a client's environment.
func TestNewMapTokenIsFreshAndValid(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		token, err := NewMapToken()
		if err != nil || !validMapToken(token) || seen[token] {
			t.Fatalf("token %q, %v (seen %v)", token, err, seen[token])
		}
		seen[token] = true
	}
	for _, bad := range []string{"", "abc", strings.Repeat("g", 32), strings.Repeat("A", 32), strings.Repeat("a", 33), "0123456789abcdef0123456789abcde\x00"} {
		if validMapToken(bad) {
			t.Errorf("token %q accepted", bad)
		}
		if bad == "" {
			continue
		}
		if _, err := New(Config{}).MapWithToken(context.Background(), "vm/1/2026-09-27T03:00:00Z", "drive-scsi0", bad); err == nil || !strings.Contains(err.Error(), "invalid PBS map token") {
			t.Errorf("MapWithToken accepted the token %q: %v", bad, err)
		}
	}
}

// The token reaches the client's process, whose daemon inherits it,
// as MapTokenEnv, beside the repository and namespace a run's map reads
// from; a Map without a token adds none. The command line is the form
// ParseMapCommand recognizes.
func TestMapWithTokenGivesTheClientItsToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "call.log")
	script := "#!/bin/sh\n{ echo \"$*\"; env; } > " + log + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	client := New(Config{Repository: "u@pbs!tok@pbs.example:store", Namespace: "team-a", Password: "secret"})
	const snapshot = "vm/7214/2026-09-27T03:12:59Z"

	run := func(token string) (string, map[string]string) {
		t.Helper()
		_ = os.Remove(log)
		var err error
		if token == "" {
			_, err = client.Map(context.Background(), snapshot, "drive-scsi1")
		} else {
			_, err = client.MapWithToken(context.Background(), snapshot, "drive-scsi1", token)
		}
		if err == nil {
			t.Fatal("the failing client mapped")
		}
		data, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		env := map[string]string{}
		for _, line := range lines[1:] {
			if name, value, ok := strings.Cut(line, "="); ok {
				env[name] = value
			}
		}
		return lines[0], env
	}

	token, err := NewMapToken()
	if err != nil {
		t.Fatal(err)
	}
	args, env := run(token)
	if !strings.Contains(args, "--ns team-a ") {
		t.Fatalf("the map's command line %q lacks --ns team-a: the 3.x client ignores PBS_NAMESPACE", args)
	}
	if env[MapTokenEnv] != token || env["PBS_NAMESPACE"] != "team-a" || env["PBS_REPOSITORY"] != "u@pbs!tok@pbs.example:store" {
		t.Fatalf("client environment = %v", env)
	}
	m, ok := ParseMapCommand(append([]string{"proxmox-backup-client"}, strings.Fields(args)...))
	want, err := client.MapOwner(snapshot, "drive-scsi1")
	if err != nil || !ok || m.Owner(env) != want {
		t.Fatalf("command line %q: parsed %v, owner %s, want %s (%v)", args, ok, m.Owner(env), want, err)
	}
	if _, env := run(""); env[MapTokenEnv] != "" {
		t.Fatalf("a map without a token carries %q", env[MapTokenEnv])
	}
}

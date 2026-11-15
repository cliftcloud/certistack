// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestinspect

import (
	"context"
	"errors"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/guestnet"
	"github.com/cliftcloud/certistack/pkg/initplan"
)

// fakeGuest answers Gather over an in-memory guest the way ImageReader
// answers it over a real one: files ("-> target" is a symbolic link, followed
// inside the guest), directories (those with entries, and dirs), a find that
// lists entries without following links, and a read that fails for what is
// not a readable file. It records every request.
type fakeGuest struct {
	files    map[string]string
	dirs     map[string]bool
	requests []guestnet.ReadRequest
	err      error
}

func (g *fakeGuest) resolve(p string) (string, bool) {
	for i := 0; i < 8; i++ {
		contents, ok := g.files[p]
		if !ok {
			return "", false
		}
		target, link := strings.CutPrefix(contents, "-> ")
		if !link {
			return contents, true
		}
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(p), target)
		}
		p = target
	}
	return "", false
}

func (g *fakeGuest) isDir(p string) bool {
	if g.dirs[p] {
		return true
	}
	for name := range g.files {
		if strings.HasPrefix(name, p+"/") {
			return true
		}
	}
	for dir := range g.dirs {
		if strings.HasPrefix(dir, p+"/") {
			return true
		}
	}
	return false
}

func (g *fakeGuest) Gather(_ context.Context, req guestnet.ReadRequest) (guestnet.ReadResult, error) {
	g.requests = append(g.requests, req)
	result := guestnet.ReadResult{IsFile: map[string]bool{}, IsDir: map[string]bool{}, Found: map[string][]string{}, Content: map[string]string{}, Failed: map[string]string{}}
	if g.err != nil {
		return result, g.err
	}
	for _, f := range req.Files {
		_, ok := g.resolve(f)
		result.IsFile[f] = ok
	}
	for _, d := range req.Dirs {
		result.IsDir[d] = g.isDir(d)
	}
	for _, d := range req.Find {
		seen := map[string]bool{}
		for name := range g.files {
			if rest, ok := strings.CutPrefix(name, d+"/"); ok {
				parts := strings.Split(rest, "/")
				for i := range parts {
					seen[strings.Join(parts[:i+1], "/")] = true
				}
			}
		}
		for dir := range g.dirs {
			if rest, ok := strings.CutPrefix(dir, d+"/"); ok {
				seen[rest] = true
			}
		}
		var entries []string
		for entry := range seen {
			entries = append(entries, entry)
		}
		sort.Strings(entries)
		result.Found[d] = entries
	}
	for _, f := range req.Read {
		if contents, ok := g.resolve(f); ok {
			result.Content[f] = contents
		} else {
			result.Failed[f] = "not found"
		}
	}
	return result, nil
}

// read is every file the inspection asked to read.
func (g *fakeGuest) read() []string {
	var files []string
	for _, req := range g.requests {
		files = append(files, req.Read...)
	}
	return files
}

func rockyGuest() *fakeGuest {
	return &fakeGuest{files: map[string]string{
		"/etc/os-release":     "-> ../usr/lib/os-release",
		"/usr/lib/os-release": "NAME=\"Rocky Linux\"\nVERSION=\"9.4 (Blue Onyx)\"\nID=\"rocky\"\nPRETTY_NAME=\"Rocky Linux 9.4 (Blue Onyx)\"\n",
		"/etc/systemd/system/multi-user.target.wants/nginx.service":      "-> /usr/lib/systemd/system/nginx.service",
		"/etc/systemd/system/multi-user.target.wants/sshd.service":       "-> /usr/lib/systemd/system/sshd.service",
		"/etc/systemd/system/multi-user.target.wants/crond.service":      "-> /usr/lib/systemd/system/crond.service",
		"/etc/systemd/system/getty.target.wants/getty@tty1.service":      "-> /usr/lib/systemd/system/getty@.service",
		"/etc/systemd/system/dbus-org.freedesktop.nm-dispatcher.service": "-> /usr/lib/systemd/system/NetworkManager-dispatcher.service",
		"/usr/lib/systemd/system/nginx.service":                          "[Unit]\n",
		"/usr/lib/systemd/system/sshd.service":                           "[Unit]\n",
		"/etc/nginx/nginx.conf":                                          rockyNginx,
		"/etc/nginx/mime.types":                                          "types {\n}\n",
		"/etc/ssh/sshd_config":                                           "Include /etc/ssh/sshd_config.d/*.conf\n#Port 22\n",
		"/etc/ssh/sshd_config.d/50-redhat.conf":                          "Include /etc/crypto-policies/back-ends/opensshserver.config\nSyslogFacility AUTHPRIV\n",
		"/etc/ssh/ssh_host_ed25519_key":                                  "-----BEGIN OPENSSH PRIVATE KEY-----\n",
	}, dirs: map[string]bool{"/etc/nginx/conf.d": true, "/etc/nginx/default.d": true}}
}

func debianGuest() *fakeGuest {
	return &fakeGuest{files: map[string]string{
		"/etc/os-release":     "-> ../usr/lib/os-release",
		"/usr/lib/os-release": "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\n",
		"/etc/systemd/system/multi-user.target.wants/nginx.service": "-> /lib/systemd/system/nginx.service",
		"/etc/systemd/system/multi-user.target.wants/ssh.service":   "-> /lib/systemd/system/ssh.service",
		"/etc/systemd/system/sshd.service":                          "-> /lib/systemd/system/ssh.service",
		"/lib/systemd/system/ssh.service":                           "[Unit]\n",
		"/lib/systemd/system/nginx.service":                         "[Unit]\n",
		"/etc/nginx/nginx.conf":                                     debianNginx,
		"/etc/nginx/mime.types":                                     "types {\n}\n",
		"/etc/nginx/sites-available/default":                        debianNginxDefault,
		"/etc/nginx/sites-enabled/default":                          "-> /etc/nginx/sites-available/default",
		"/etc/nginx/modules-enabled/50-mod-http-geoip.conf":         "-> /usr/share/nginx/modules-available/mod-http-geoip.conf",
		"/etc/ssh/sshd_config":                                      "Include /etc/ssh/sshd_config.d/*.conf\n#Port 22\nKbdInteractiveAuthentication no\n",
		"/etc/ssh/ssh_host_rsa_key":                                 "-----BEGIN OPENSSH PRIVATE KEY-----\n",
	}, dirs: map[string]bool{"/etc/nginx/conf.d": true, "/etc/ssh/sshd_config.d": true}}
}

// services is each service as "unit listeners" in order.
func services(findings initplan.GuestFindings) string {
	var out []string
	for _, service := range findings.Services {
		out = append(out, service.Unit+" "+listeners(service))
	}
	return strings.Join(out, "; ")
}

// The two guests of the demo node: Rocky 9 and Debian 12 with nginx as
// packaged. Inspection finds nginx on port 80 on every address and sshd on
// 22, in at most three passes, and never reads a host key.
func TestDetectPackagedNginxGuests(t *testing.T) {
	for _, tc := range []struct {
		name  string
		guest *fakeGuest
		os    string
		want  string
	}{
		{"Rocky Linux 9", rockyGuest(), "Rocky Linux 9.4 (Blue Onyx)", "nginx.service *:80/http [::]:80/http; sshd.service *:22"},
		{"Debian 12", debianGuest(), "Debian GNU/Linux 12 (bookworm)", "nginx.service *:80/http [::]:80/http; ssh.service *:22"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := Detect(context.Background(), tc.guest)
			if err != nil {
				t.Fatal(err)
			}
			if findings.OS != tc.os || services(findings) != tc.want {
				t.Fatalf("found %q: %s; want %q: %s (notes %q)", findings.OS, services(findings), tc.os, tc.want, findings.Notes)
			}
			if n := len(tc.guest.requests); n > 3 {
				t.Errorf("%d passes, want at most three", n)
			}
			for _, file := range tc.guest.read() {
				if strings.Contains(file, "_key") {
					t.Errorf("the inspection read %s", file)
				}
			}
		})
	}
}

// A Debian guest with the four other services, as packaged and as changed:
// MariaDB on localhost, a PostgreSQL cluster that listens everywhere through
// conf.d, Redis on localhost, and Apache with a redirect. MariaDB's
// debian.cnf, which holds a password and which the server does not include,
// is never read; nor is any data directory beyond postgresql.auto.conf.
func TestDetectDebianServices(t *testing.T) {
	guest := &fakeGuest{files: map[string]string{
		"/etc/os-release": "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
		"/etc/systemd/system/multi-user.target.wants/mariadb.service":      "-> /lib/systemd/system/mariadb.service",
		"/etc/systemd/system/multi-user.target.wants/postgresql.service":   "-> /lib/systemd/system/postgresql.service",
		"/etc/systemd/system/multi-user.target.wants/redis-server.service": "-> /lib/systemd/system/redis-server.service",
		"/etc/systemd/system/multi-user.target.wants/apache2.service":      "-> /lib/systemd/system/apache2.service",
		"/etc/systemd/system/mysql.service":                                "-> /lib/systemd/system/mariadb.service",
		"/lib/systemd/system/mariadb.service":                              "[Unit]\n",
		"/etc/mysql/my.cnf":                                                "-> /etc/alternatives/my.cnf",
		"/etc/alternatives/my.cnf":                                         "-> /etc/mysql/mariadb.cnf",
		"/etc/mysql/mariadb.cnf":                                           "[client-server]\n!includedir /etc/mysql/conf.d/\n!includedir /etc/mysql/mariadb.conf.d/\n",
		"/etc/mysql/mariadb.conf.d/50-server.cnf":                          "[mysqld]\nbind-address = 127.0.0.1\n",
		"/etc/mysql/debian.cnf":                                            "[client]\npassword = secret\n",
		"/etc/postgresql/15/main/postgresql.conf":                          "data_directory = '/var/lib/postgresql/15/main'\nport = 5432\ninclude_dir = 'conf.d'\n",
		"/etc/postgresql/15/main/start.conf":                               "auto\n",
		"/etc/postgresql/15/main/conf.d/net.conf":                          "listen_addresses = '*'\n",
		"/etc/postgresql/15/main/pg_hba.conf":                              "host all all 0.0.0.0/0 scram-sha-256\n",
		"/etc/redis/redis.conf":                                            "bind 127.0.0.1 -::1\nport 6379\nrequirepass not-for-init\n",
		"/etc/apache2/apache2.conf":                                        debianApache,
		"/etc/apache2/ports.conf":                                          debianPorts,
		"/etc/apache2/sites-enabled/000-default.conf":                      "<VirtualHost *:80>\nRedirect permanent / https://www.example/\n</VirtualHost>\n",
		"/etc/apache2/mods-enabled/mpm_event.load":                         "LoadModule mpm_event_module x\n",
	}}
	findings, err := Detect(context.Background(), guest)
	if err != nil {
		t.Fatal(err)
	}
	want := "apache2.service *:80/http=301; mariadb.service 127.0.0.1:3306; postgresql@15-main.service *:5432; redis-server.service 127.0.0.1:6379 ::1:6379"
	if got := services(findings); got != want {
		t.Fatalf("found %s\nwant  %s\n(notes %q)", got, want, findings.Notes)
	}
	for _, file := range guest.read() {
		if file == "/etc/mysql/debian.cnf" || file == "/etc/postgresql/15/main/pg_hba.conf" {
			t.Errorf("the inspection read %s, which no service's configuration includes", file)
		}
	}
	if len(guest.requests) > 3 {
		t.Errorf("%d passes", len(guest.requests))
	}
}

// A unit enabled and masked does not run: it is left out, and the findings
// say why.
func TestDetectLeavesOutAMaskedUnit(t *testing.T) {
	guest := debianGuest()
	guest.files["/etc/systemd/system/multi-user.target.wants/apache2.service"] = "-> /lib/systemd/system/apache2.service"
	guest.files["/etc/systemd/system/apache2.service"] = "-> /dev/null"
	guest.files["/etc/apache2/apache2.conf"] = "Listen 80\n"
	findings, err := Detect(context.Background(), guest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(services(findings), "apache2") || !strings.Contains(strings.Join(findings.Notes, "\n"), "apache2.service is enabled but masked") {
		t.Fatalf("found %s, notes %q", services(findings), findings.Notes)
	}
}

// A guest with nothing init knows enabled is found with no service, and
// said so.
func TestDetectFindsNothing(t *testing.T) {
	guest := &fakeGuest{files: map[string]string{
		"/etc/os-release": "PRETTY_NAME=\"Alpine Linux v3.20\"\n",
		"/etc/systemd/system/multi-user.target.wants/crond.service": "x",
	}}
	findings, err := Detect(context.Background(), guest)
	if err != nil || len(findings.Services) != 0 || findings.OS != "Alpine Linux v3.20" {
		t.Fatalf("findings %+v, err %v", findings, err)
	}
	if len(guest.requests) != 2 {
		t.Errorf("%d passes, want two: nothing is left to read", len(guest.requests))
	}
}

// Disks without os-release or systemd are not a Linux system to read; a
// reader that cannot open the disks is the error.
func TestDetectRefusals(t *testing.T) {
	if _, err := Detect(context.Background(), &fakeGuest{files: map[string]string{"/Windows/System32/config/SYSTEM": "x"}}); !errors.Is(err, ErrNotLinux) {
		t.Fatalf("a Windows disk: %v", err)
	}
	failure := errors.New("guestfish could not open the backed-up disks")
	if _, err := Detect(context.Background(), &fakeGuest{err: failure}); !errors.Is(err, failure) {
		t.Fatalf("a reader that fails: %v", err)
	}
}

// RHEL-family PostgreSQL from PGDG lives in /var/lib/pgsql/<version>/data,
// whose files are asked for by name; and an include deeper than one level is
// noted, not followed.
func TestDetectPGDGAndDeepIncludes(t *testing.T) {
	guest := &fakeGuest{files: map[string]string{
		"/etc/os-release": "PRETTY_NAME=\"AlmaLinux 9.4\"\n",
		"/etc/systemd/system/multi-user.target.wants/postgresql-16.service": "x",
		"/etc/systemd/system/multi-user.target.wants/nginx.service":         "x",
		"/var/lib/pgsql/16/data/postgresql.conf":                            "listen_addresses = '0.0.0.0'\nport = 5433\n",
		"/var/lib/pgsql/16/data/postgresql.auto.conf":                       "# Do not edit\n",
		"/etc/nginx/nginx.conf":                                             "http { include /etc/nginx/conf.d/*.conf; }",
		"/etc/nginx/conf.d/app.conf":                                        "server { listen 8080; include /etc/nginx/conf.d/inner/*.conf; }",
		"/etc/nginx/conf.d/inner/x.conf":                                    "listen 9090;",
	}}
	findings, err := Detect(context.Background(), guest)
	if err != nil {
		t.Fatal(err)
	}
	if got := services(findings); got != "nginx.service *:8080/http; postgresql-16.service 0.0.0.0:5433" {
		t.Fatalf("found %s", got)
	}
	if !strings.Contains(strings.Join(findings.Notes, "\n"), "/etc/nginx/conf.d/inner/*.conf, which was not followed") {
		t.Fatalf("notes %q", findings.Notes)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package guestinspect finds the services a Linux guest runs from a few of
// its files, read-only: its OS identity (os-release), the systemd units it
// enables (the *.wants directories of /etc/systemd/system), and the listen
// configuration of the services init --inspect knows: nginx, the Apache HTTP
// Server, PostgreSQL, MariaDB or MySQL, Redis and sshd. It reads through a
// Source, which on a node is guestnet's ImageReader over a backup's PBS map,
// so it never opens a disk itself, and it reads only configuration files of
// those services, never their data, keys or credentials files.
package guestinspect

import (
	"context"
	"errors"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/cliftcloud/certistack/internal/guestnet"
	"github.com/cliftcloud/certistack/pkg/initplan"
)

// Source reads a guest's files: guestnet.ImageReader on a node.
type Source interface {
	Gather(ctx context.Context, req guestnet.ReadRequest) (guestnet.ReadResult, error)
}

// maxIncludeDepth is how deep includes are followed: a service's main
// configuration file is depth 0 and the files it includes are read; what an
// included file includes is not, and the findings say so.
const maxIncludeDepth = 1

// maxReadFiles bounds the files one inspection reads after the main ones.
const maxReadFiles = 160

const systemdDir = "/etc/systemd/system"

var osReleaseFiles = []string{"/etc/os-release", "/usr/lib/os-release"}

// configTrees are the directories listed (find) to resolve the services'
// includes and find their files. None holds data, and only names are listed.
var configTrees = []string{"/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/mysql", "/etc/my.cnf.d", "/etc/redis", "/etc/ssh", "/etc/postgresql"}

// mainFiles are the services' own configuration files at their fixed paths.
func mainFiles() []string {
	files := []string{
		nginxPrefix + "/nginx.conf",
		apacheLayouts["apache2.service"].main, apacheLayouts["httpd.service"].main,
		"/etc/my.cnf", "/etc/mysql/my.cnf",
		"/etc/redis/redis.conf", "/etc/redis.conf",
		sshdConfig,
		"/var/lib/pgsql/data/postgresql.conf", "/var/lib/pgsql/data/postgresql.auto.conf",
	}
	for _, version := range pgVersions {
		dir := "/var/lib/pgsql/" + version + "/data"
		files = append(files, dir+"/postgresql.conf", dir+"/postgresql.auto.conf")
	}
	return files
}

// ErrNotLinux is a guest whose disks hold no os-release and no systemd
// configuration: not a Linux system an inspection can read.
var ErrNotLinux = errors.New("the backed-up disks hold no /etc/os-release and no /etc/systemd/system, so this is not a Linux system init can inspect")

// Detect reads the guest through src, in at most three passes (each one
// guestfish launch on a node): which of the known files and directories
// exist; the OS identity, the listings of the configuration trees and the
// main configuration files; then the files those include and the units'
// masks. It never reads a file it was not led to by a service's own
// configuration.
func Detect(ctx context.Context, src Source) (initplan.GuestFindings, error) {
	var findings initplan.GuestFindings
	known := mainFiles()
	first, err := src.Gather(ctx, guestnet.ReadRequest{Files: append(append([]string(nil), osReleaseFiles...), known...), Dirs: append([]string{systemdDir}, configTrees...)})
	if err != nil {
		return findings, err
	}
	osRelease := ""
	for _, file := range osReleaseFiles {
		if first.IsFile[file] {
			osRelease = file
			break
		}
	}
	if osRelease == "" && !first.IsDir[systemdDir] {
		return findings, ErrNotLinux
	}

	second := guestnet.ReadRequest{}
	for _, dir := range append([]string{systemdDir}, configTrees...) {
		if first.IsDir[dir] {
			second.Find = append(second.Find, dir)
		}
	}
	if osRelease != "" {
		second.Read = append(second.Read, osRelease)
	}
	for _, file := range known {
		if first.IsFile[file] {
			second.Read = append(second.Read, file)
		}
	}
	read, err := src.Gather(ctx, second)
	if err != nil {
		return findings, err
	}
	fs := newFileSet()
	for _, file := range known {
		fs.present[file] = first.IsFile[file]
	}
	merge(fs, read)
	findings.OS = osName(fs.content[osRelease])

	units, masks := enabledUnits(fs.trees[systemdDir])
	if len(units) == 0 {
		findings.Notes = append(findings.Notes, "no enabled systemd unit was found in "+systemdDir)
	}
	// What the services' configuration includes, and whether an enabled unit
	// is masked, is the third pass.
	plans := servicePlans(fs, units)
	parseAll(fs, plans)
	// A Debian cluster's postgresql.conf is found only in the listing, so it
	// is read in this pass, and with it its conf.d, which the packaged
	// postgresql.conf includes (include_dir = 'conf.d'): its settings count
	// only if the file does include them.
	for _, plan := range plans {
		if plan.pg.startConf != "" {
			files, _ := fs.filesIn(path.Join(path.Dir(plan.pg.conf), "conf.d"), ".conf")
			for _, file := range files {
				fs.wanted[file] = true
			}
		}
	}
	third := guestnet.ReadRequest{Files: masks}
	for _, file := range sortedKeys(fs.wanted) {
		if len(third.Read) == maxReadFiles {
			break
		}
		third.Read = append(third.Read, file)
	}
	// A cluster's postgresql.auto.conf in its default data directory is read
	// last: it is not listed, and when it is not there the read fails at the
	// end of the pass, which costs no launch.
	for _, plan := range plans {
		if plan.pg.autoConf != "" && !fs.exists(plan.pg.autoConf) && strings.HasPrefix(plan.pg.autoConf, "/var/lib/postgresql/") {
			third.Read = append(third.Read, plan.pg.autoConf)
		}
	}
	if len(third.Files)+len(third.Read) > 0 {
		more, err := src.Gather(ctx, third)
		if err != nil {
			return findings, err
		}
		merge(fs, more)
		for _, mask := range masks {
			if !more.IsFile[mask] {
				unit := strings.TrimPrefix(mask, systemdDir+"/")
				delete(units, unit)
				findings.Notes = append(findings.Notes, unit+" is enabled but masked ("+mask+" is not a unit file)")
			}
		}
		plans = servicePlans(fs, units)
	}
	fs.wanted, fs.notes = map[string]bool{}, nil
	findings.Services = parseAll(fs, plans)
	for _, file := range sortedKeys(fs.wanted) {
		fs.note(file + " was not read (an inspection reads a bounded set of files, in three passes)")
	}
	findings.Notes = append(findings.Notes, fs.notes...)
	return findings, nil
}

// merge adds what a pass read to fs.
func merge(fs *fileSet, result guestnet.ReadResult) {
	for dir, entries := range result.Found {
		fs.trees[dir] = entries
	}
	for file, contents := range result.Content {
		fs.content[file] = contents
		delete(fs.wanted, file)
	}
	for file, reason := range result.Failed {
		fs.failed[file] = reason
		delete(fs.wanted, file)
	}
	for file, isFile := range result.IsFile {
		if isFile {
			fs.present[file] = true
		}
	}
}

// unitName is what a systemd unit's name looks like.
var unitName = regexp.MustCompile(`^[A-Za-z0-9:_.@-]+\.(service|socket)$`)

// enabledUnits are the units linked in a *.wants or *.requires directory of
// /etc/systemd/system, from its listing, and the paths to check for a mask:
// a unit of the same name directly in /etc/systemd/system, which masks it
// when it is not a unit file (a link to /dev/null).
func enabledUnits(entries []string) (map[string]bool, []string) {
	units := map[string]bool{}
	top := map[string]bool{}
	for _, entry := range entries {
		parts := strings.Split(entry, "/")
		switch {
		case len(parts) == 1:
			top[parts[0]] = true
		case len(parts) == 2 && (strings.HasSuffix(parts[0], ".wants") || strings.HasSuffix(parts[0], ".requires")) && unitName.MatchString(parts[1]):
			if _, _, ok := unitKind(parts[1]); ok {
				units[parts[1]] = true
			}
		}
	}
	var masks []string
	for _, unit := range sortedKeys(units) {
		if top[unit] {
			masks = append(masks, systemdDir+"/"+unit)
		}
	}
	return units, masks
}

// unitKind is the service an enabled unit runs, and the instance it names.
func unitKind(unit string) (kind, instance string, ok bool) {
	name, _, _ := strings.Cut(unit, ".")
	base, instance, _ := strings.Cut(name, "@")
	switch {
	case base == "nginx" && strings.HasSuffix(unit, ".service") && instance == "":
		return initplan.ServiceNginx, "", true
	case (base == "apache2" || base == "httpd") && strings.HasSuffix(unit, ".service") && instance == "":
		return initplan.ServiceApache, "", true
	case base == "postgresql" && strings.HasSuffix(unit, ".service"):
		return initplan.ServicePostgreSQL, instance, true
	case strings.HasPrefix(unit, "postgresql-") && strings.HasSuffix(unit, ".service"):
		version := strings.TrimSuffix(strings.TrimPrefix(unit, "postgresql-"), ".service")
		return initplan.ServicePostgreSQL, "pgdg:" + version, true
	case (base == "mariadb" || base == "mysql" || base == "mysqld") && strings.HasSuffix(unit, ".service"):
		return initplan.ServiceMariaDB, instance, true
	case (base == "redis" || base == "redis-server") && strings.HasSuffix(unit, ".service"):
		return initplan.ServiceRedis, instance, true
	case (base == "ssh" || base == "sshd") && instance == "":
		return initplan.ServiceSSH, "", true
	}
	return "", "", false
}

// servicePlan is one service to parse: its kind and unit, and for
// PostgreSQL the cluster, for Redis its configuration file.
type servicePlan struct {
	kind, unit string
	pg         pgCluster
	redisFile  string
}

// servicePlans are the services of the enabled units, one each, in a fixed
// order: the same configuration is not parsed twice for two names of one
// service (ssh.service and ssh.socket, mariadb.service and mysql.service).
func servicePlans(fs *fileSet, units map[string]bool) []servicePlan {
	var plans []servicePlan
	seen := map[string]bool{}
	add := func(plan servicePlan, key string) {
		if !seen[key] {
			seen[key] = true
			plans = append(plans, plan)
		}
	}
	for _, unit := range sortedKeys(units) {
		kind, instance, _ := unitKind(unit)
		switch kind {
		case initplan.ServiceNginx, initplan.ServiceSSH:
			add(servicePlan{kind: kind, unit: unit}, kind)
		case initplan.ServiceApache:
			add(servicePlan{kind: kind, unit: unit}, unit)
		case initplan.ServiceMariaDB:
			add(servicePlan{kind: kind, unit: unit}, kind)
		case initplan.ServiceRedis:
			file := redisConfigFile(fs, instance)
			add(servicePlan{kind: kind, unit: unit, redisFile: file}, "redis:"+file)
		case initplan.ServicePostgreSQL:
			for _, cluster := range pgClusters(fs, unit, instance) {
				add(servicePlan{kind: kind, unit: cluster.unit, pg: cluster}, "pg:"+cluster.conf)
			}
		}
	}
	return plans
}

// redisConfigFile is the configuration file of a Redis unit: Debian's
// /etc/redis/redis.conf (redis-<instance>.conf for an instance), the RHEL
// family's /etc/redis/redis.conf or /etc/redis.conf.
func redisConfigFile(fs *fileSet, instance string) string {
	candidates := []string{"/etc/redis/redis.conf", "/etc/redis.conf"}
	if instance != "" {
		candidates = []string{"/etc/redis/redis-" + instance + ".conf", "/etc/redis/" + instance + ".conf"}
	}
	for _, candidate := range candidates {
		if fs.exists(candidate) {
			return candidate
		}
	}
	return ""
}

// pgClusters are the clusters a PostgreSQL unit runs: Debian's
// postgresql.service runs every cluster under /etc/postgresql (and
// postgresql@<version>-<name> one of them), the RHEL family's postgresql
// the one in /var/lib/pgsql/data and postgresql-<version> the PGDG one in
// /var/lib/pgsql/<version>/data.
func pgClusters(fs *fileSet, unit, instance string) []pgCluster {
	if version, ok := strings.CutPrefix(instance, "pgdg:"); ok {
		dir := "/var/lib/pgsql/" + version + "/data"
		return []pgCluster{{unit: unit, conf: dir + "/postgresql.conf", autoConf: dir + "/postgresql.auto.conf"}}
	}
	if _, debian := fs.trees["/etc/postgresql"]; debian {
		var clusters []pgCluster
		for _, entry := range fs.trees["/etc/postgresql"] {
			parts := strings.Split(entry, "/")
			if len(parts) != 3 || parts[2] != "postgresql.conf" {
				continue
			}
			name := parts[0] + "-" + parts[1]
			if instance != "" && instance != name {
				continue
			}
			dir := "/etc/postgresql/" + parts[0] + "/" + parts[1]
			clusters = append(clusters, pgCluster{
				unit:      "postgresql@" + name + ".service",
				conf:      dir + "/postgresql.conf",
				autoConf:  "/var/lib/postgresql/" + parts[0] + "/" + parts[1] + "/postgresql.auto.conf",
				startConf: dir + "/start.conf",
			})
		}
		sort.Slice(clusters, func(i, j int) bool { return clusters[i].conf < clusters[j].conf })
		return clusters
	}
	return []pgCluster{{unit: unit, conf: "/var/lib/pgsql/data/postgresql.conf", autoConf: "/var/lib/pgsql/data/postgresql.auto.conf"}}
}

// parseAll parses each planned service with what fs holds.
func parseAll(fs *fileSet, plans []servicePlan) []initplan.Service {
	var services []initplan.Service
	for _, plan := range plans {
		switch plan.kind {
		case initplan.ServiceNginx:
			services = append(services, parseNginx(fs, plan.unit))
		case initplan.ServiceApache:
			services = append(services, parseApache(fs, plan.unit))
		case initplan.ServicePostgreSQL:
			services = append(services, parsePostgres(fs, plan.pg))
		case initplan.ServiceMariaDB:
			services = append(services, parseMySQL(fs, plan.unit))
		case initplan.ServiceRedis:
			services = append(services, parseRedis(fs, plan.unit, plan.redisFile))
		case initplan.ServiceSSH:
			services = append(services, parseSSHD(fs, plan.unit))
		}
	}
	return services
}

// osName is the guest's own name for its system: PRETTY_NAME, else NAME and
// VERSION_ID, from os-release.
func osName(osRelease string) string {
	values := map[string]string{}
	for _, line := range strings.Split(osRelease, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found {
			values[key] = unquote(strings.TrimSpace(value))
		}
	}
	name := values["PRETTY_NAME"]
	if name == "" {
		name = strings.TrimSpace(values["NAME"] + " " + values["VERSION_ID"])
	}
	if len(name) > 80 {
		name = name[:80]
	}
	return name
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

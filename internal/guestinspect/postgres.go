// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestinspect

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// pgCluster is one PostgreSQL cluster: the unit that runs it, its
// postgresql.conf, the postgresql.auto.conf ALTER SYSTEM writes in its data
// directory, and (Debian) its start.conf.
type pgCluster struct {
	unit      string
	conf      string
	autoConf  string
	startConf string
}

// pgSettings are the settings that decide where the server listens.
type pgSettings struct {
	port        int
	portFile    string
	listen      string
	listenSet   bool
	listenFile  string
	dataDir     string
	dataDirFile string
}

// pgVersions are the major versions whose RHEL-family PGDG layout
// (/var/lib/pgsql/<version>/data) an inspection looks for.
var pgVersions = []string{"9.6", "10", "11", "12", "13", "14", "15", "16", "17", "18"}

// parsePostgres reads a cluster's postgresql.conf, what it includes, and then
// postgresql.auto.conf, for port and listen_addresses. The server's own
// defaults are port 5432 on localhost only.
func parsePostgres(fs *fileSet, cluster pgCluster) initplan.Service {
	service := initplan.Service{Kind: initplan.ServicePostgreSQL, Unit: cluster.unit}
	if cluster.startConf != "" {
		if text, ok := fs.read(cluster.startConf); ok {
			if mode := pgStartMode(text); mode == "manual" || mode == "disabled" {
				service.NoTCP = fmt.Sprintf("its %s says %s, so it does not start with the guest", cluster.startConf, mode)
				return service
			}
		}
	}
	settings := pgSettings{}
	if !pgFile(fs, cluster.conf, 0, &settings) {
		service.Notes = append(service.Notes, cluster.conf+" was not found or could not be read; PostgreSQL's defaults (port 5432, localhost only) are assumed")
	} else {
		service.Config = cluster.conf
	}
	autoConf := cluster.autoConf
	if settings.dataDir != "" && autoConf != "" && path.Join(settings.dataDir, "postgresql.auto.conf") != autoConf {
		fs.note(fmt.Sprintf("data_directory in %s is %s, so ALTER SYSTEM settings (its postgresql.auto.conf) were not read", settings.dataDirFile, settings.dataDir))
		autoConf = ""
	}
	if autoConf != "" && fs.exists(autoConf) {
		pgFile(fs, autoConf, maxIncludeDepth, &settings)
	}
	port, portText, portFile := 5432, "port 5432 (the default)", ""
	if settings.port != 0 {
		port, portText, portFile = settings.port, fmt.Sprintf("port = %d", settings.port), settings.portFile
	}
	if !settings.listenSet {
		service.Defaulted = true
		service.Listeners = append(service.Listeners, initplan.Listener{Address: "localhost", Port: port, File: portFile, Text: "no listen_addresses (localhost only, the default), " + portText})
		return service
	}
	if strings.TrimSpace(settings.listen) == "" {
		service.NoTCP = "listen_addresses is empty in " + settings.listenFile + " (Unix-domain sockets only)"
		return service
	}
	for _, address := range strings.Split(settings.listen, ",") {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		service.Listeners = append(service.Listeners, initplan.Listener{Address: address, Port: port, File: settings.listenFile, Text: fmt.Sprintf("listen_addresses = '%s', %s", settings.listen, portText)})
	}
	return service
}

// pgFile reads one configuration file into settings, with the files its
// include, include_if_exists and include_dir name in their place, at depths
// below maxIncludeDepth. It reports whether the file was read.
func pgFile(fs *fileSet, file string, depth int, settings *pgSettings) bool {
	text, ok := fs.read(file)
	if !ok {
		return false
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(pgStripComment(raw))
		if line == "" {
			continue
		}
		end := strings.IndexAny(line, " \t=")
		if end < 0 {
			continue
		}
		name := strings.ToLower(line[:end])
		value := pgValue(strings.TrimPrefix(strings.TrimSpace(line[end:]), "="))
		switch name {
		case "port":
			if n, err := strconv.Atoi(value); err == nil && n > 0 && n <= 65535 {
				settings.port, settings.portFile = n, file
			}
		case "listen_addresses":
			settings.listen, settings.listenSet, settings.listenFile = value, true, file
		case "data_directory":
			settings.dataDir, settings.dataDirFile = value, file
		case "include", "include_if_exists", "include_dir":
			target := resolve(path.Dir(file), value)
			if depth >= maxIncludeDepth {
				fs.note(fmt.Sprintf("%s includes %s, which was not followed (included files are read one level deep)", file, target))
				continue
			}
			if name != "include_dir" {
				pgFile(fs, target, depth+1, settings)
				continue
			}
			files, known := fs.filesIn(target, ".conf")
			if !known {
				fs.note(fmt.Sprintf("%s includes %s, outside the files inspected, which was not read", file, target))
				continue
			}
			for _, included := range files {
				pgFile(fs, included, depth+1, settings)
			}
		}
	}
	return true
}

// pgStripComment is a line without its "#" comment; a "#" in a quoted value
// is kept.
func pgStripComment(line string) string {
	quoted := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			quoted = !quoted
		case '#':
			if !quoted {
				return line[:i]
			}
		}
	}
	return line
}

// pgValue is a setting's value: a quoted string (a doubled single quote and \'
// are a quote in it), or the first word.
func pgValue(rest string) string {
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "'") {
		if fields := strings.Fields(rest); len(fields) > 0 {
			return fields[0]
		}
		return ""
	}
	var value strings.Builder
	for i := 1; i < len(rest); i++ {
		switch {
		case rest[i] == '\\' && i+1 < len(rest):
			i++
			value.WriteByte(rest[i])
		case rest[i] == '\'' && i+1 < len(rest) && rest[i+1] == '\'':
			i++
			value.WriteByte('\'')
		case rest[i] == '\'':
			return value.String()
		default:
			value.WriteByte(rest[i])
		}
	}
	return value.String()
}

// pgStartMode is the mode a Debian cluster's start.conf names: auto, manual
// or disabled.
func pgStartMode(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return strings.ToLower(line)
		}
	}
	return "auto"
}

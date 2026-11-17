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

// mysqlMains are the option files MariaDB and MySQL read on Linux, in the
// order they read them: a later value wins.
var mysqlMains = []string{"/etc/my.cnf", "/etc/mysql/my.cnf"}

// mysqlServerGroup reports whether an option group is read by the server:
// [mysqld], [mariadb], [mariadbd], [server], [client-server], [galera], and
// their version-suffixed forms ([mariadb-10.11]).
func mysqlServerGroup(group string) bool {
	for _, name := range []string{"mysqld", "mariadb", "mariadbd", "server"} {
		if group == name || strings.HasPrefix(group, name+"-") {
			return true
		}
	}
	return group == "client-server" || group == "galera"
}

// mysqlSettings are the options that decide where the server listens.
type mysqlSettings struct {
	port           int
	portFile       string
	bind           string
	bindFile       string
	skipNetworking bool
	skipFile       string
}

// parseMySQL reads MariaDB's or MySQL's option files for port, bind-address
// and skip-networking. The server's own defaults are port 3306 on every
// address.
func parseMySQL(fs *fileSet, unit string) initplan.Service {
	service := initplan.Service{Kind: initplan.ServiceMariaDB, Unit: unit}
	settings := mysqlSettings{}
	read := false
	for _, main := range mysqlMains {
		if !fs.exists(main) {
			continue
		}
		if mysqlFile(fs, main, 0, &settings) {
			read = true
			if service.Config == "" {
				service.Config = main
			}
		}
	}
	if !read {
		service.Notes = append(service.Notes, "no option file (/etc/my.cnf, /etc/mysql/my.cnf) was read; the server's defaults are assumed")
	}
	if settings.skipNetworking {
		service.NoTCP = "skip-networking in " + settings.skipFile
		return service
	}
	port, portText, file := 3306, "port 3306 (the default)", settings.bindFile
	if settings.port != 0 {
		port, portText, file = settings.port, fmt.Sprintf("port = %d", settings.port), settings.portFile
	}
	if settings.bind == "" {
		service.Defaulted = settings.port == 0
		service.Listeners = append(service.Listeners, initplan.Listener{Port: port, File: file, Text: portText + ", no bind-address (every address)"})
		return service
	}
	for _, address := range strings.Split(settings.bind, ",") {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		service.Listeners = append(service.Listeners, initplan.Listener{Address: address, Port: port, File: settings.bindFile, Text: "bind-address = " + settings.bind + ", " + portText})
	}
	return service
}

// mysqlFile reads one option file into settings, with the files its
// !include and !includedir name in their place, at depths below
// maxIncludeDepth. It reports whether the file was read.
func mysqlFile(fs *fileSet, file string, depth int, settings *mysqlSettings) bool {
	text, ok := fs.read(file)
	if !ok {
		return false
	}
	group := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
			continue
		case strings.HasPrefix(line, "!include"):
			mysqlInclude(fs, file, line, depth, settings)
			continue
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			group = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if !mysqlServerGroup(group) {
			continue
		}
		key, value, hasValue := strings.Cut(line, "=")
		key = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "_", "-")
		key = strings.TrimPrefix(key, "loose-")
		value = mysqlValue(value)
		switch key {
		case "port":
			if n, err := strconv.Atoi(value); err == nil && n > 0 && n <= 65535 {
				settings.port, settings.portFile = n, file
			}
		case "bind-address":
			settings.bind, settings.bindFile = value, file
		case "skip-networking":
			settings.skipNetworking = !hasValue || mysqlTrue(value)
			settings.skipFile = file
		}
	}
	return true
}

func mysqlInclude(fs *fileSet, file, line string, depth int, settings *mysqlSettings) {
	words := strings.Fields(line)
	if len(words) < 2 {
		return
	}
	directive := words[0]
	target := resolve(path.Dir(file), strings.Join(words[1:], " "))
	if depth >= maxIncludeDepth {
		fs.note(fmt.Sprintf("%s includes %s, which was not followed (included files are read one level deep)", file, target))
		return
	}
	if directive == "!includedir" {
		files, known := fs.filesIn(target, ".cnf")
		if !known {
			fs.note(fmt.Sprintf("%s includes %s, outside the files inspected, which was not read", file, target))
			return
		}
		for _, included := range files {
			mysqlFile(fs, included, depth+1, settings)
		}
		return
	}
	mysqlFile(fs, target, depth+1, settings)
}

// mysqlValue is an option's value: its quotes taken off, and a comment after
// an unquoted value left out.
func mysqlValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 0 && (value[0] == '"' || value[0] == '\'') {
		if end := strings.IndexByte(value[1:], value[0]); end >= 0 {
			return value[1 : end+1]
		}
		return value[1:]
	}
	if i := strings.IndexByte(value, '#'); i >= 0 {
		value = value[:i]
	}
	return strings.TrimSpace(value)
}

func mysqlTrue(value string) bool {
	switch strings.ToLower(value) {
	case "0", "off", "false", "no":
		return false
	}
	return true
}

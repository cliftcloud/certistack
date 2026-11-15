// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestinspect

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// redisSettings are the settings that decide where Redis listens.
type redisSettings struct {
	port, tlsPort         int
	portSet               bool
	portFile, tlsPortFile string
	bind                  []string
	bindFile              string
}

// parseRedis reads a Redis configuration file, and what it includes, for
// port, tls-port and bind. Redis's own defaults are port 6379 on every
// address; the packaged files bind to localhost.
func parseRedis(fs *fileSet, unit, file string) initplan.Service {
	service := initplan.Service{Kind: initplan.ServiceRedis, Unit: unit}
	settings := redisSettings{port: 6379}
	if file == "" || !redisFile(fs, file, 0, &settings) {
		service.Notes = append(service.Notes, "no configuration file of it was read; Redis's defaults (port 6379, every address) are assumed")
		service.Defaulted = true
	} else {
		service.Config = file
	}
	addresses := settings.bind
	bindText := "no bind (every address)"
	if len(addresses) == 0 {
		addresses = []string{""}
	} else {
		bindText = "bind " + strings.Join(settings.bind, " ")
	}
	portText := fmt.Sprintf("port %d", settings.port)
	if !settings.portSet {
		portText += " (the default)"
	}
	for _, address := range addresses {
		if settings.port > 0 {
			service.Listeners = append(service.Listeners, initplan.Listener{Address: address, Port: settings.port, File: firstOf(settings.bindFile, settings.portFile), Text: bindText + ", " + portText})
		}
		if settings.tlsPort > 0 {
			service.Listeners = append(service.Listeners, initplan.Listener{Address: address, Port: settings.tlsPort, TLS: true, File: settings.tlsPortFile, Text: fmt.Sprintf("%s, tls-port %d", bindText, settings.tlsPort)})
		}
	}
	if len(service.Listeners) == 0 {
		service.NoTCP = "port 0 in " + settings.portFile + " and no tls-port"
	}
	return service
}

func redisFile(fs *fileSet, file string, depth int, settings *redisSettings) bool {
	text, ok := fs.read(file)
	if !ok {
		return false
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words := fields(line)
		if len(words) < 2 {
			continue
		}
		switch strings.ToLower(words[0]) {
		case "port":
			if n, err := strconv.Atoi(words[1]); err == nil && n >= 0 && n <= 65535 {
				settings.port, settings.portSet, settings.portFile = n, true, file
			}
		case "tls-port":
			if n, err := strconv.Atoi(words[1]); err == nil && n >= 0 && n <= 65535 {
				settings.tlsPort, settings.tlsPortFile = n, file
			}
		case "bind":
			settings.bind, settings.bindFile = nil, file
			for _, address := range words[1:] {
				// "-" marks an address Redis may skip when it is not there.
				settings.bind = append(settings.bind, strings.TrimPrefix(address, "-"))
			}
		case "include":
			target := resolve("/etc/redis", words[1])
			if depth >= maxIncludeDepth {
				fs.note(fmt.Sprintf("%s includes %s, which was not followed (included files are read one level deep)", file, target))
				continue
			}
			matches, known := fs.glob(target)
			if !known {
				fs.note(fmt.Sprintf("%s includes %s, outside the files inspected, which was not read", file, target))
				continue
			}
			for _, match := range matches {
				redisFile(fs, match, depth+1, settings)
			}
		}
	}
	return true
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestinspect

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

const sshdConfig = "/etc/ssh/sshd_config"

// sshdSettings are the Port and ListenAddress settings, which accumulate.
type sshdSettings struct {
	ports    []int
	portsAt  []string
	listens  []string
	listenAt []string
}

// parseSSHD reads sshd_config, and the files its Include names in their
// place, for Port and ListenAddress. sshd's own default is port 22 on every
// address.
func parseSSHD(fs *fileSet, unit string) initplan.Service {
	service := initplan.Service{Kind: initplan.ServiceSSH, Unit: unit}
	settings := sshdSettings{}
	if sshdFile(fs, sshdConfig, 0, &settings) {
		service.Config = sshdConfig
	} else {
		service.Notes = append(service.Notes, sshdConfig+" was not found or could not be read; sshd's default (port 22, every address) is assumed")
	}
	ports, portText, portFile := settings.ports, "", ""
	if len(ports) == 0 {
		ports, portText = []int{22}, "Port 22 (the default)"
		service.Defaulted = len(settings.listens) == 0
	} else {
		var words []string
		for _, p := range ports {
			words = append(words, "Port "+strconv.Itoa(p))
		}
		portText, portFile = strings.Join(words, ", "), settings.portsAt[0]
	}
	if len(settings.listens) == 0 {
		for _, port := range ports {
			service.Listeners = append(service.Listeners, initplan.Listener{Port: port, File: portFile, Text: portText + ", no ListenAddress (every address)"})
		}
		return service
	}
	for i, spec := range settings.listens {
		host, port := sshdListen(spec)
		if port != 0 {
			service.Listeners = append(service.Listeners, initplan.Listener{Address: host, Port: port, File: settings.listenAt[i], Text: "ListenAddress " + spec})
			continue
		}
		for _, p := range ports {
			service.Listeners = append(service.Listeners, initplan.Listener{Address: host, Port: p, File: settings.listenAt[i], Text: "ListenAddress " + spec + ", " + portText})
		}
	}
	return service
}

func sshdFile(fs *fileSet, file string, depth int, settings *sshdSettings) bool {
	text, ok := fs.read(file)
	if !ok {
		return false
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "Keyword argument" or "Keyword=argument".
		keyword, rest := line, ""
		if i := strings.IndexAny(line, " \t="); i >= 0 {
			keyword, rest = line[:i], strings.TrimLeft(line[i:], " \t")
			rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
		}
		words := fields(rest)
		if len(words) == 0 {
			continue
		}
		switch strings.ToLower(keyword) {
		case "port":
			if n, err := strconv.Atoi(words[0]); err == nil && n > 0 && n <= 65535 {
				settings.ports = append(settings.ports, n)
				settings.portsAt = append(settings.portsAt, file)
			}
		case "listenaddress":
			settings.listens = append(settings.listens, words[0])
			settings.listenAt = append(settings.listenAt, file)
		case "include":
			for _, pattern := range words {
				target := resolve("/etc/ssh", pattern)
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
					sshdFile(fs, match, depth+1, settings)
				}
			}
		}
	}
	return true
}

// sshdListen reads a ListenAddress: host, host:port, [IPv6]:port, or a bare
// IPv6 address. port is 0 when it names none.
func sshdListen(spec string) (string, int) {
	switch {
	case strings.HasPrefix(spec, "["):
		end := strings.Index(spec, "]")
		if end < 0 {
			return spec, 0
		}
		host := spec[:end+1]
		if port, err := strconv.Atoi(strings.TrimPrefix(spec[end+1:], ":")); err == nil && port > 0 && port <= 65535 {
			return host, port
		}
		return host, 0
	case strings.Count(spec, ":") == 1:
		i := strings.Index(spec, ":")
		if port, err := strconv.Atoi(spec[i+1:]); err == nil && port > 0 && port <= 65535 {
			return spec[:i], port
		}
	}
	return spec, 0
}

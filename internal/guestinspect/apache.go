// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestinspect

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// apacheLayouts are the two layouts of the Apache HTTP Server's packages:
// Debian's apache2 and the RHEL family's httpd, by unit.
var apacheLayouts = map[string]struct{ root, main string }{
	"apache2.service": {"/etc/apache2", "/etc/apache2/apache2.conf"},
	"httpd.service":   {"/etc/httpd", "/etc/httpd/conf/httpd.conf"},
}

// apacheDirective is one line of Apache's configuration, or a section
// (<Name args> ... </Name>) with what it holds.
type apacheDirective struct {
	name    string // lower case
	args    []string
	isBlock bool
	block   []apacheDirective
	file    string
}

// apacheParse reads Apache's line syntax: a backslash at the end of a line
// continues it, "#" starts a comment line, and a section opens with <Name
// args> and closes with </Name>.
func apacheParse(text, file string) []apacheDirective {
	var lines []string
	var current strings.Builder
	for _, raw := range strings.Split(text, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if strings.HasSuffix(raw, "\\") {
			current.WriteString(strings.TrimSuffix(raw, "\\"))
			current.WriteByte(' ')
			continue
		}
		current.WriteString(raw)
		lines = append(lines, current.String())
		current.Reset()
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	pos := 0
	return apacheSection(lines, file, &pos)
}

func apacheSection(lines []string, file string, pos *int) []apacheDirective {
	var directives []apacheDirective
	for *pos < len(lines) {
		line := strings.TrimSpace(lines[*pos])
		*pos++
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "</"):
			return directives
		case strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">"):
			words := fields(strings.TrimSuffix(strings.TrimPrefix(line, "<"), ">"))
			if len(words) == 0 {
				continue
			}
			d := apacheDirective{name: strings.ToLower(words[0]), args: words[1:], isBlock: true, file: file}
			d.block = apacheSection(lines, file, pos)
			directives = append(directives, d)
		default:
			words := fields(line)
			if len(words) > 0 {
				directives = append(directives, apacheDirective{name: strings.ToLower(words[0]), args: words[1:], file: file})
			}
		}
	}
	return directives
}

// apacheLoad parses file and puts what its Include and IncludeOptional
// directives name in their place (a directory: every file beneath it), at
// depths below maxIncludeDepth.
func apacheLoad(fs *fileSet, root, file string, depth int) ([]apacheDirective, bool) {
	text, ok := fs.read(file)
	if !ok {
		return nil, false
	}
	return apacheExpand(fs, root, apacheParse(text, file), depth), true
}

func apacheExpand(fs *fileSet, root string, directives []apacheDirective, depth int) []apacheDirective {
	var out []apacheDirective
	for _, d := range directives {
		if d.isBlock {
			d.block = apacheExpand(fs, root, d.block, depth)
			out = append(out, d)
			continue
		}
		if (d.name != "include" && d.name != "includeoptional") || len(d.args) != 1 {
			out = append(out, d)
			continue
		}
		pattern := resolve(root, d.args[0])
		if depth >= maxIncludeDepth {
			fs.note(fmt.Sprintf("%s includes %s, which was not followed (included files are read one level deep)", d.file, pattern))
			continue
		}
		var matches []string
		if fs.isDir(pattern) {
			matches = fs.filesUnder(pattern)
		} else {
			var known bool
			if matches, known = fs.glob(pattern); !known {
				fs.note(fmt.Sprintf("%s includes %s, outside the files inspected, which was not read", d.file, pattern))
				continue
			}
		}
		for _, match := range matches {
			if included, ok := apacheLoad(fs, root, match, depth+1); ok {
				out = append(out, included...)
			}
		}
	}
	return out
}

// apacheConditionals are the sections Listen and LoadModule may be inside.
var apacheConditionals = map[string]bool{"ifmodule": true, "ifdefine": true, "ifversion": true, "iffile": true, "ifdirective": true, "ifsection": true}

// apacheBuiltIn are modules every Apache build has, whether or not a
// LoadModule names them.
var apacheBuiltIn = map[string]bool{"core_module": true, "so_module": true, "http_module": true, "mpm_common_module": true}

// apacheModuleName is a module's identifier in an IfModule test: "ssl_module"
// as it is, "mod_ssl.c" as "ssl_module".
func apacheModuleName(name string) string {
	if strings.HasPrefix(name, "mod_") && strings.HasSuffix(name, ".c") {
		return strings.TrimSuffix(strings.TrimPrefix(name, "mod_"), ".c") + "_module"
	}
	return name
}

// apacheVHost is a <VirtualHost> section: its addresses and directives.
type apacheVHost struct {
	addresses []string
	block     []apacheDirective
}

// parseApache reads the Apache HTTP Server's configuration for its Listen
// directives, whether each port is HTTPS, and what its default virtual host
// answers "/" with.
func parseApache(fs *fileSet, unit string) initplan.Service {
	service := initplan.Service{Kind: initplan.ServiceApache, Unit: unit}
	layout := apacheLayouts[unit]
	text, ok := fs.read(layout.main)
	if !ok {
		service.Notes = append(service.Notes, layout.main+" was not found or could not be read")
		return service
	}
	root := layout.root
	for _, d := range apacheParse(text, layout.main) {
		if d.name == "serverroot" && len(d.args) == 1 {
			root = resolve("/", d.args[0])
		}
	}
	directives, _ := apacheLoad(fs, root, layout.main, 0)
	service.Config = layout.main

	loaded := map[string]bool{}
	apacheWalk(directives, func(d apacheDirective) {
		if d.name == "loadmodule" && len(d.args) >= 1 {
			loaded[d.args[0]] = true
		}
	}, nil, nil)
	if len(loaded) == 0 {
		service.Notes = append(service.Notes, "no LoadModule was read, so every <IfModule> section was taken as active")
	}
	active := func(section apacheDirective) bool {
		if section.name != "ifmodule" || len(section.args) == 0 || len(loaded) == 0 {
			return true
		}
		name, negated := strings.CutPrefix(section.args[0], "!")
		name = apacheModuleName(name)
		return (loaded[name] || apacheBuiltIn[name]) != negated
	}
	var vhosts []apacheVHost
	var listens []apacheDirective
	var topLevel []apacheDirective
	apacheWalk(directives, func(d apacheDirective) {
		switch d.name {
		case "listen":
			listens = append(listens, d)
		default:
			topLevel = append(topLevel, d)
		}
	}, active, func(vhost apacheDirective) {
		vhosts = append(vhosts, apacheVHost{addresses: vhost.args, block: vhost.block})
	})
	for _, d := range listens {
		l, ok := apacheListen(d.args)
		if !ok {
			continue
		}
		l.File, l.Text = d.file, "Listen "+strings.Join(d.args, " ")
		vhost, found := apacheDefaultVHost(vhosts, l.Port)
		if found && apacheSSLEngine(vhost.block) {
			l.TLS = true
		}
		if found {
			l.Status = apacheStatus(vhost.block)
		} else {
			l.Status = apacheStatus(topLevel)
		}
		service.Listeners = append(service.Listeners, l)
	}
	if len(service.Listeners) == 0 {
		service.NoTCP = "its configuration has no Listen directive"
	}
	return service
}

// apacheWalk calls visit for each directive outside sections, descending
// into the conditional sections that active allows (all of them when active
// is nil), and calls vhost for each <VirtualHost> it reaches.
func apacheWalk(directives []apacheDirective, visit func(apacheDirective), active func(apacheDirective) bool, vhost func(apacheDirective)) {
	for _, d := range directives {
		switch {
		case !d.isBlock:
			visit(d)
		case apacheConditionals[d.name]:
			if active == nil || active(d) {
				apacheWalk(d.block, visit, active, vhost)
			}
		case d.name == "virtualhost" && vhost != nil:
			vhost(d)
		}
	}
}

// apacheListen reads Listen [address:]port [protocol]. A port is HTTPS when
// the protocol says https, or when it is 443 and says nothing.
func apacheListen(args []string) (initplan.Listener, bool) {
	l := initplan.Listener{HTTP: true}
	if len(args) == 0 {
		return l, false
	}
	spec := args[0]
	host, port := "", spec
	switch {
	case strings.HasPrefix(spec, "["):
		end := strings.Index(spec, "]:")
		if end < 0 {
			return l, false
		}
		host, port = spec[:end+1], spec[end+2:]
	case strings.Contains(spec, ":"):
		i := strings.LastIndex(spec, ":")
		host, port = spec[:i], spec[i+1:]
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return l, false
	}
	l.Address, l.Port = host, n
	switch {
	case len(args) > 1:
		l.TLS = strings.EqualFold(args[1], "https")
	default:
		l.TLS = n == 443
	}
	return l, true
}

// apacheDefaultVHost is the virtual host that answers a request for the
// sandbox address on port: the first whose addresses name that port on every
// address (*, _default_, 0.0.0.0, [::]).
func apacheDefaultVHost(vhosts []apacheVHost, port int) (apacheVHost, bool) {
	for _, vhost := range vhosts {
		for _, address := range vhost.addresses {
			host, p := address, ""
			if i := strings.LastIndex(address, ":"); i >= 0 && !strings.HasSuffix(address, "]") {
				host, p = address[:i], address[i+1:]
			}
			if p != "" && p != "*" && p != strconv.Itoa(port) {
				continue
			}
			if (initplan.Listener{Address: host}).Scope() == initplan.ScopeAll {
				return vhost, true
			}
		}
	}
	return apacheVHost{}, false
}

func apacheSSLEngine(block []apacheDirective) bool {
	for _, d := range block {
		if d.name == "sslengine" && len(d.args) == 1 && strings.EqualFold(d.args[0], "on") {
			return true
		}
	}
	return false
}

// apacheRedirectStatus is a Redirect directive's status word or number.
func apacheRedirectStatus(word string) (int, bool) {
	switch strings.ToLower(word) {
	case "permanent":
		return 301, true
	case "temp":
		return 302, true
	case "seeother":
		return 303, true
	case "gone":
		return 410, true
	}
	if n, err := strconv.Atoi(word); err == nil && n >= 200 && n <= 599 {
		return n, true
	}
	return 0, false
}

// apacheStatus is the status a virtual host (or the main server) answers "/"
// with when its own directives say: a Redirect of "/", a RedirectMatch whose
// pattern matches "/", or a RewriteRule that redirects "/" with no
// RewriteCond before it (a condition, such as one on the host name, may not
// hold for a request to the sandbox address). 0 when it does not say.
func apacheStatus(block []apacheDirective) int {
	conditioned := false
	for _, d := range block {
		switch d.name {
		case "redirect":
			status, target := 302, d.args
			if len(target) == 3 {
				s, ok := apacheRedirectStatus(target[0])
				if !ok {
					continue
				}
				status, target = s, target[1:]
			}
			if len(target) >= 1 && target[0] == "/" {
				return status
			}
		case "redirectpermanent", "redirecttemp":
			if len(d.args) >= 1 && d.args[0] == "/" {
				if d.name == "redirectpermanent" {
					return 301
				}
				return 302
			}
		case "redirectmatch":
			status, args := 302, d.args
			if len(args) == 3 {
				s, ok := apacheRedirectStatus(args[0])
				if !ok {
					continue
				}
				status, args = s, args[1:]
			}
			if len(args) >= 1 {
				if re, err := regexp.Compile(args[0]); err == nil && re.MatchString("/") {
					return status
				}
			}
		case "rewritecond":
			conditioned = true
		case "rewriterule":
			if !conditioned && len(d.args) >= 3 && !strings.HasPrefix(d.args[0], "!") {
				if status, ok := apacheRewriteStatus(d.args[2]); ok {
					if re, err := regexp.Compile(d.args[0]); err == nil && re.MatchString("/") {
						return status
					}
				}
			}
			conditioned = false
		}
	}
	return 0
}

// apacheRewriteStatus is the status of a RewriteRule's flags that redirect:
// R (302), R=permanent (301), R=NNN.
func apacheRewriteStatus(flags string) (int, bool) {
	flags = strings.TrimSuffix(strings.TrimPrefix(flags, "["), "]")
	for _, flag := range strings.Split(flags, ",") {
		name, value, hasValue := strings.Cut(strings.TrimSpace(flag), "=")
		if !strings.EqualFold(name, "R") && !strings.EqualFold(name, "redirect") {
			continue
		}
		if !hasValue {
			return 302, true
		}
		return apacheRedirectStatus(value)
	}
	return 0, false
}

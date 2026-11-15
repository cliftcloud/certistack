// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestinspect

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// nginxPrefix is where a distribution's nginx resolves a relative include.
const nginxPrefix = "/etc/nginx"

// ngxDirective is one directive of an nginx configuration: its name and
// arguments, and the directives of its block when it has one.
type ngxDirective struct {
	name    string
	args    []string
	isBlock bool
	block   []ngxDirective
	file    string
}

// ngxToken is a word, or one of ";", "{" and "}" (punct).
type ngxToken struct {
	text  string
	punct bool
}

// ngxTokens splits nginx's syntax: words separated by white space, quoted
// strings with backslash escapes, "#" comments that start a token, and the
// punctuation ";", "{" and "}".
func ngxTokens(text string) []ngxToken {
	var tokens []ngxToken
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == ';' || c == '{' || c == '}':
			tokens = append(tokens, ngxToken{text: string(c), punct: true})
			i++
		case c == '"' || c == '\'':
			var word strings.Builder
			i++
			for i < len(text) && text[i] != c {
				if text[i] == '\\' && i+1 < len(text) {
					i++
				}
				word.WriteByte(text[i])
				i++
			}
			i++ // the closing quote
			tokens = append(tokens, ngxToken{text: word.String()})
		default:
			var word strings.Builder
			for i < len(text) && !strings.ContainsRune(" \t\r\n;{}", rune(text[i])) {
				if text[i] == '\\' && i+1 < len(text) {
					i++
				}
				word.WriteByte(text[i])
				i++
			}
			tokens = append(tokens, ngxToken{text: word.String()})
		}
	}
	return tokens
}

// ngxParse builds the directives of tokens, up to the "}" that ends the
// block they are in.
func ngxParse(tokens []ngxToken, file string, pos *int) []ngxDirective {
	var directives []ngxDirective
	var words []string
	for *pos < len(tokens) {
		token := tokens[*pos]
		*pos++
		switch {
		case !token.punct:
			words = append(words, token.text)
		case token.text == ";":
			if len(words) > 0 {
				directives = append(directives, ngxDirective{name: words[0], args: words[1:], file: file})
			}
			words = nil
		case token.text == "{":
			d := ngxDirective{isBlock: true, file: file}
			if len(words) > 0 {
				d.name, d.args = words[0], words[1:]
			}
			d.block = ngxParse(tokens, file, pos)
			directives = append(directives, d)
			words = nil
		case token.text == "}":
			return directives
		}
	}
	return directives
}

// ngxLoad parses file and puts the files its include directives name in
// their place, for a file at depth below maxIncludeDepth: includes inside an
// included file are not followed, and are noted.
func ngxLoad(fs *fileSet, file string, depth int) ([]ngxDirective, bool) {
	text, ok := fs.read(file)
	if !ok {
		return nil, false
	}
	pos := 0
	return ngxExpand(fs, ngxParse(ngxTokens(text), file, &pos), depth), true
}

func ngxExpand(fs *fileSet, directives []ngxDirective, depth int) []ngxDirective {
	var out []ngxDirective
	for _, d := range directives {
		if d.isBlock {
			d.block = ngxExpand(fs, d.block, depth)
			out = append(out, d)
			continue
		}
		if d.name != "include" || len(d.args) != 1 {
			out = append(out, d)
			continue
		}
		pattern := resolve(nginxPrefix, d.args[0])
		if depth >= maxIncludeDepth {
			fs.note(fmt.Sprintf("%s includes %s, which was not followed (included files are read one level deep)", d.file, pattern))
			continue
		}
		matches, known := fs.glob(pattern)
		if !known {
			fs.note(fmt.Sprintf("%s includes %s, outside the files inspected, which was not read", d.file, pattern))
			continue
		}
		for _, match := range matches {
			if included, ok := ngxLoad(fs, match, depth+1); ok {
				out = append(out, included...)
			}
		}
	}
	return out
}

// ngxServer is a server block of http (or stream) and what it listens on.
type ngxServer struct {
	http      bool
	listeners []initplan.Listener
	defaults  map[int]bool // ports it is the default server of
	status    int          // what it answers "/" with, when it says
}

// parseNginx reads nginx's configuration, from nginx.conf and what it
// includes, for the listen directives of its http and stream servers.
func parseNginx(fs *fileSet, unit string) initplan.Service {
	service := initplan.Service{Kind: initplan.ServiceNginx, Unit: unit}
	main := nginxPrefix + "/nginx.conf"
	directives, ok := ngxLoad(fs, main, 0)
	if !ok {
		service.Notes = append(service.Notes, main+" was not found or could not be read")
		return service
	}
	service.Config = main
	var servers []ngxServer
	for _, top := range directives {
		if !top.isBlock || (top.name != "http" && top.name != "stream") {
			continue
		}
		for _, d := range top.block {
			if d.isBlock && d.name == "server" {
				servers = append(servers, ngxReadServer(d, top.name == "http"))
			}
		}
	}
	// A request to the sandbox address is answered, for each port, by the
	// default server of the port's wildcard listeners: the one that says
	// default_server, else the first.
	statusOf := map[int]int{}
	for _, server := range servers {
		if !server.http {
			continue
		}
		for _, l := range server.listeners {
			if l.Scope() != initplan.ScopeAll {
				continue
			}
			if _, set := statusOf[l.Port]; !set || server.defaults[l.Port] {
				statusOf[l.Port] = server.status
			}
		}
	}
	for _, server := range servers {
		for _, l := range server.listeners {
			if l.HTTP {
				l.Status = statusOf[l.Port]
			}
			service.Listeners = append(service.Listeners, l)
		}
	}
	if len(servers) == 0 {
		service.NoTCP = "its configuration has no http or stream server"
	}
	return service
}

// ngxReadServer reads a server block: its listen directives (an http server
// without one listens on *:80), whether it uses TLS, and the status it
// answers "/" with.
func ngxReadServer(d ngxDirective, http bool) ngxServer {
	server := ngxServer{http: http, defaults: map[int]bool{}}
	tlsAll := false
	for _, inner := range d.block {
		if inner.name == "ssl" && len(inner.args) == 1 && inner.args[0] == "on" {
			tlsAll = true
		}
	}
	for _, inner := range d.block {
		if inner.name != "listen" || len(inner.args) == 0 {
			continue
		}
		l, isDefault, ok := ngxListen(inner.args, http)
		if !ok {
			continue
		}
		l.TLS = l.TLS || tlsAll
		l.File, l.Text = inner.file, "listen "+strings.Join(inner.args, " ")
		if isDefault {
			server.defaults[l.Port] = true
		}
		server.listeners = append(server.listeners, l)
	}
	if http && len(server.listeners) == 0 {
		server.listeners = append(server.listeners, initplan.Listener{Port: 80, HTTP: true, TLS: tlsAll, File: d.file, Text: "a server block without listen (nginx listens on *:80)"})
	}
	if http {
		server.status = ngxStatus(d.block)
	}
	return server
}

// ngxListen reads one listen directive: address and port (a port alone is
// every address; an address alone is port 80), ssl, and default_server. A
// unix socket, a QUIC (UDP) listener, and what cannot be read are left out.
func ngxListen(args []string, http bool) (initplan.Listener, bool, bool) {
	l := initplan.Listener{HTTP: http}
	isDefault := false
	for _, flag := range args[1:] {
		switch {
		case flag == "ssl":
			l.TLS = true
		case flag == "quic":
			return l, false, false
		case flag == "default_server" || flag == "default":
			isDefault = true
		}
	}
	spec := args[0]
	if strings.HasPrefix(spec, "unix:") {
		return l, false, false
	}
	host, port := spec, ""
	switch {
	case strings.HasPrefix(spec, "["):
		end := strings.Index(spec, "]")
		if end < 0 {
			return l, false, false
		}
		host, port = spec[:end+1], strings.TrimPrefix(spec[end+1:], ":")
	case isPort(spec):
		host, port = "", spec
	case strings.Contains(spec, ":"):
		i := strings.LastIndex(spec, ":")
		host, port = spec[:i], spec[i+1:]
	}
	if port == "" {
		if !http {
			return l, false, false
		}
		port = "80"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return l, false, false
	}
	l.Address, l.Port = host, n
	return l, isDefault, true
}

// ngxStatus is the status a server block answers "/" with when its own
// configuration says: a return at the server level or in the location of
// "/", or a rewrite of everything with permanent or redirect. 0 when it does
// not say, or when the answer is not an HTTP status (return 444 closes the
// connection).
func ngxStatus(block []ngxDirective) int {
	if status, ok := ngxReturn(block); ok {
		return status
	}
	for _, d := range block {
		if d.name == "rewrite" && len(d.args) >= 3 && (d.args[0] == "^" || d.args[0] == "^/" || d.args[0] == "^(.*)$" || d.args[0] == "^/(.*)$" || d.args[0] == "^/(.*)") {
			switch d.args[2] {
			case "permanent":
				return 301
			case "redirect":
				return 302
			}
		}
	}
	for _, d := range block {
		if d.isBlock && d.name == "location" && (len(d.args) == 1 && d.args[0] == "/" || len(d.args) == 2 && d.args[0] == "=" && d.args[1] == "/") {
			if status, ok := ngxReturn(d.block); ok {
				return status
			}
		}
	}
	return 0
}

// ngxReturn is a block's own return directive: its code, or 302 for a
// return of a URL alone.
func ngxReturn(block []ngxDirective) (int, bool) {
	for _, d := range block {
		if d.name != "return" || d.isBlock || len(d.args) == 0 {
			continue
		}
		code, err := strconv.Atoi(d.args[0])
		if err != nil {
			if strings.HasPrefix(d.args[0], "http://") || strings.HasPrefix(d.args[0], "https://") || strings.HasPrefix(d.args[0], "$scheme") {
				return 302, true
			}
			return 0, true
		}
		if code < 200 || code > 599 {
			return 0, true
		}
		return code, true
	}
	return 0, false
}

func isPort(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

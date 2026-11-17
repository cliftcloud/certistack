// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package initplan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/pkg/progress"
)

// maxServiceProbes is the most probes an inspected VM gets. Past it, the
// services are kept in servicePriority order and the rest are named.
const maxServiceProbes = 6

// servicePriority orders what an inspection finds, most likely what the VM
// is for first: web servers, then databases, then caches. sshd comes last,
// and is probed only when nothing else can be.
var servicePriority = map[string]int{ServiceNginx: 0, ServiceApache: 1, ServicePostgreSQL: 2, ServiceMariaDB: 3, ServiceRedis: 4, ServiceSSH: 5}

// probeTimeoutSec is what init gives each probe it writes, as it gives the
// SSH probe: no startup_grace_period_sec is written, so a probe starts at once
// and passes at the first answer within it.
const probeTimeoutSec = 300

// serviceName is how the plan names a service.
func serviceName(s Service) string {
	switch s.Kind {
	case ServiceApache:
		if base, _, _ := strings.Cut(s.Unit, "."); base != "" {
			return guestText(base)
		}
		return "Apache"
	case ServicePostgreSQL:
		return "PostgreSQL"
	case ServiceMariaDB:
		return "MariaDB/MySQL"
	case ServiceRedis:
		return "Redis"
	}
	return s.Kind
}

// wireProbe is one probe init writes for a found service.
type wireProbe struct {
	service  Service
	kind     string // "http" or "tcp"
	listener Listener
	status   int
	comments []string
}

func (p wireProbe) description() string {
	name := serviceName(p.service)
	switch {
	case p.kind == "http":
		return fmt.Sprintf("%s answers HTTP on port %d at the sandbox address", name, p.listener.Port)
	case p.service.Kind == ServiceSSH:
		if p.listener.Port == 22 {
			return "SSH answers on the sandbox address"
		}
		return fmt.Sprintf("SSH answers on port %d at the sandbox address", p.listener.Port)
	case p.listener.TLS && p.listener.HTTP:
		return fmt.Sprintf("%s accepts TCP connections on HTTPS port %d at the sandbox address", name, p.listener.Port)
	}
	return fmt.Sprintf("%s accepts TCP connections on port %d at the sandbox address", name, p.listener.Port)
}

// probeChoice is what init writes under an inspected Linux VM's probes:
// the comments above them, the probes, and a line for the command's notes.
type probeChoice struct {
	header []string
	probes []wireProbe
	// fallback is why the VM keeps the SSH probe on port 22, "" when its
	// probes come from what was found.
	fallback string
	summary  string
}

// sortedServices are the found services in servicePriority order, then by
// unit.
func sortedServices(services []Service) []Service {
	sorted := append([]Service(nil), services...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if servicePriority[sorted[i].Kind] != servicePriority[sorted[j].Kind] {
			return servicePriority[sorted[i].Kind] < servicePriority[sorted[j].Kind]
		}
		return sorted[i].Unit < sorted[j].Unit
	})
	return sorted
}

// chooseListener is the listener a probe of s targets, and the probe's
// kind: for a web server, plain HTTP on every address (port 80 first) is an
// http probe, else HTTPS on every address (443 first) a tcp probe; for the
// others, every address first. A listener bound to one address of the guest's
// own network is probed too, with a comment: it may not answer on the
// sandbox address. why says why there is none.
func chooseListener(s Service) (l Listener, kind string, why string) {
	if s.NoTCP != "" {
		return Listener{}, "", guestText(s.NoTCP)
	}
	var all, specific, loopback []Listener
	for _, listener := range s.Listeners {
		switch listener.Scope() {
		case ScopeAll:
			all = append(all, listener)
		case ScopeAddress:
			specific = append(specific, listener)
		default:
			loopback = append(loopback, listener)
		}
	}
	preferred := func(candidates []Listener, tls bool, port int) (Listener, bool) {
		var match []Listener
		for _, c := range candidates {
			if c.TLS == tls {
				match = append(match, c)
			}
		}
		sort.SliceStable(match, func(i, j int) bool {
			if (match[i].Port == port) != (match[j].Port == port) {
				return match[i].Port == port
			}
			return match[i].Port < match[j].Port
		})
		if len(match) == 0 {
			return Listener{}, false
		}
		return match[0], true
	}
	if l, ok := preferred(all, false, 80); ok {
		if l.HTTP {
			return l, "http", ""
		}
		return l, "tcp", ""
	}
	if l, ok := preferred(all, true, 443); ok {
		return l, "tcp", ""
	}
	if len(specific) > 0 {
		return specific[0], "tcp", ""
	}
	if len(loopback) > 0 {
		var addresses []string
		for _, l := range loopback {
			addresses = append(addresses, guestText(l.Address)+":"+strconv.Itoa(l.Port))
		}
		return Listener{}, "", "it listens only on the guest's loopback (" + strings.Join(dedupe(addresses), ", ") + "), which no probe from the sandbox network reaches"
	}
	return Listener{}, "", "no listen setting of it was found"
}

// evidence is where a service was found: its unit and what its configuration
// says, file by file.
func evidence(s Service) string {
	parts := []string{"enabled unit " + guestText(s.Unit)}
	byFile := map[string][]string{}
	var files []string
	for _, l := range s.Listeners {
		if _, seen := byFile[l.File]; !seen {
			files = append(files, l.File)
		}
		byFile[l.File] = append(byFile[l.File], guestText(l.Text))
	}
	for _, file := range files {
		texts := strings.Join(dedupe(byFile[file]), ", ")
		if file == "" {
			parts = append(parts, texts)
			continue
		}
		parts = append(parts, texts+" in "+guestText(file))
	}
	if s.NoTCP != "" {
		parts = append(parts, guestText(s.NoTCP))
	}
	return strings.Join(parts, "; ")
}

func dedupe(values []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// chooseProbes decides what an inspected Linux VM is checked on. found is
// the node's answer for it, nil when there is none; notInspected is why,
// then.
func chooseProbes(found *InspectedVM, notInspected string) probeChoice {
	sshFallback := func(choice probeChoice, why string) probeChoice {
		choice.fallback = why
		choice.summary = why
		return choice
	}
	if found == nil || found.Skipped != "" || found.Failed != "" {
		why := notInspected
		switch {
		case found != nil && found.Skipped != "":
			why = found.Skipped
		case found != nil && found.Failed != "":
			why = found.Failed
		}
		if why == "" {
			why = "the node gave no answer for it"
		}
		why = "not inspected: " + guestText(why)
		return sshFallback(probeChoice{header: []string{capitalize(why) + "."}}, why)
	}
	backup := "Inspected backup " + guestText(found.Snapshot)
	if found.OS != "" {
		backup += " (" + guestText(found.OS) + ")"
	}
	backup += ", read-only"

	var probes []wireProbe
	var unprobed, also, notes []string
	var ssh *wireProbe
	usedPorts := map[int]string{}
	for _, s := range sortedServices(found.Services) {
		l, kind, why := chooseListener(s)
		name := serviceName(s)
		if kind == "" {
			unprobed = append(unprobed, fmt.Sprintf("%s (%s) is not probed: %s.", name, guestText(s.Unit), why))
			continue
		}
		p := wireProbe{service: s, kind: kind, listener: l, status: l.Status}
		p.comments = append(p.comments, name+": "+evidence(s)+".")
		if l.Scope() == ScopeAddress {
			p.comments = append(p.comments, fmt.Sprintf("It is bound to %s, an address of the guest's own network that the sandbox does not give it, so this probe fails until it also listens on every address.", guestText(l.Address)))
		}
		switch {
		case kind == "http" && p.status == 0:
			p.status = 200
			p.comments = append(p.comments, "expected_status 200 is assumed: change it if / answers with a redirect or a login.")
		case kind == "http":
			p.comments = append(p.comments, fmt.Sprintf("expected_status %d is what its configuration answers / with.", p.status))
		case l.TLS && l.HTTP:
			p.comments = append(p.comments, "HTTPS is checked as TCP: an http probe with tls: true verifies the certificate, which must name the sandbox address or a server_name and chain to a CA the node trusts.")
		}
		if s.Kind == ServiceSSH {
			if ssh == nil {
				ssh = &p
			}
			continue
		}
		if first, taken := usedPorts[l.Port]; taken {
			also = append(also, fmt.Sprintf("%s also listens on port %d, which the %s probe checks.", name, l.Port, first))
			continue
		}
		if len(probes) == maxServiceProbes {
			notes = append(notes, name+" ("+guestText(s.Unit)+")")
			continue
		}
		usedPorts[l.Port] = name
		probes = append(probes, p)
	}

	var foundNames []string
	for _, s := range sortedServices(found.Services) {
		foundNames = append(foundNames, serviceName(s))
	}
	foundText := "found " + strings.Join(dedupe(foundNames), ", ")
	if len(foundNames) == 0 {
		foundText = "found no service init knows (nginx, Apache, PostgreSQL, MariaDB/MySQL, Redis, sshd) enabled"
	}

	if len(probes) == 0 {
		header := []string{backup + ": " + foundText + "."}
		header = append(header, unprobed...)
		header = append(header, notesOf(found)...)
		if ssh != nil {
			choice := probeChoice{header: header, probes: []wireProbe{*ssh}}
			choice.summary = fmt.Sprintf("only sshd was found to probe (port %d)", ssh.listener.Port)
			return choice
		}
		return sshFallback(probeChoice{header: header}, "inspection found no service it can probe")
	}

	header := []string{backup + ": " + foundText + ". CHANGE: confirm these probes check what this VM is for."}
	if ssh != nil {
		header = append(header, fmt.Sprintf("sshd (port %d) was also found; it is not probed, since the probes below reach the guest over the same network.", ssh.listener.Port))
	}
	header = append(header, unprobed...)
	header = append(header, also...)
	if len(notes) > 0 {
		header = append(header, fmt.Sprintf("%d more service(s) were found and are not probed (at most %d probes are written, web servers first, then databases, then Redis): %s.", len(notes), maxServiceProbes, strings.Join(notes, ", ")))
	}
	header = append(header, notesOf(found)...)
	var summaries []string
	for _, p := range probes {
		summaries = append(summaries, fmt.Sprintf("%s %s %d", serviceName(p.service), strings.ToUpper(p.kind), p.listener.Port))
	}
	return probeChoice{header: header, probes: probes, summary: strings.Join(summaries, ", ")}
}

// notesOf are what the inspection says it did not read or follow, as
// comment sentences, at most three, with a count of the rest.
func notesOf(found *InspectedVM) []string {
	var notes []string
	for _, s := range found.Services {
		notes = append(notes, s.Notes...)
	}
	notes = append(notes, found.Notes...)
	notes = dedupe(notes)
	var out []string
	for i, note := range notes {
		if i == 3 {
			out = append(out, fmt.Sprintf("(%d more note(s) of what was not read.)", len(notes)-3))
			break
		}
		out = append(out, "Note: "+guestText(note)+".")
	}
	return out
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// writeComment writes text as comment lines at indent, wrapped near 78
// columns. text is already safe for a comment (guestText or init's own).
func writeComment(w func(string, ...any), indent, text string) {
	// Text from the node or the guest goes through the terminal's filter: a
	// line break in it would end the comment and start plan keys.
	text = progress.SingleLine(text)
	width := 78 - len(indent) - 2
	if width < 30 {
		width = 30
	}
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && len(line)+1+len(word) > width {
			w("%s# %s", indent, line)
			line = ""
		}
		if line == "" {
			line = word
		} else {
			line += " " + word
		}
	}
	if line != "" {
		w("%s# %s", indent, line)
	}
}

// writeProbe writes one probe of a choice, for the guest at address.
func writeProbe(w func(string, ...any), p wireProbe, address string) {
	for _, comment := range p.comments {
		writeComment(w, "          ", comment)
	}
	w(`          - type: %s`, q(p.kind))
	w("            target_ip: %s", q(address))
	w("            port: %d", p.listener.Port)
	if p.kind == "http" {
		w(`            path: "/"`)
		w("            expected_status: %d", p.status)
	}
	w("            timeout_sec: %d", probeTimeoutSec)
	w("            description: %s", q(progress.SingleLine(p.description())))
}

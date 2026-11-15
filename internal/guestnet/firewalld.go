// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
)

// zoneDocument is a firewalld zone file read with a real XML parser: where
// its one zone element sits in the original bytes, so the probe rules can be
// spliced in without rewriting anything else, and a comparable form of the
// zone's attributes and direct children, so the result can be checked.
type zoneDocument struct {
	startTagEnd int // offset just past the zone start tag
	endTag      int // offset of the zone end tag (startTagEnd when self-closing)
	selfClosing bool
	attrs       string
	children    []string
	interfaces  []string
	sources     []string // addresses, networks and MACs; ipsets as "ipset:<name>"
	rules       []zoneRule
}

// parseZoneDocument accepts what firewalld's own parser accepts for the
// parts CertiStack relies on: exactly one top-level <zone> element and
// nothing but comments, processing instructions and whitespace around it.
// Comments and CDATA are never mistaken for markup, so a commented-out
// "</zone>" or "<zone/>" cannot attract the probe rules.
func parseZoneDocument(doc string) (zoneDocument, error) {
	var zone zoneDocument
	decoder := xml.NewDecoder(strings.NewReader(doc))
	depth, roots := 0, 0
	var child *strings.Builder
	var rule *zoneRule
	for {
		before := int(decoder.InputOffset())
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return zoneDocument{}, err
		}
		after := int(decoder.InputOffset())
		switch t := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
				if roots > 1 {
					return zoneDocument{}, fmt.Errorf("more than one top-level element")
				}
				if t.Name.Space != "" || t.Name.Local != "zone" {
					return zoneDocument{}, fmt.Errorf("the top-level element is <%s>, not <zone>", elementName(t.Name))
				}
				zone.attrs = canonicalAttrs(t.Attr)
				zone.startTagEnd = after
			} else {
				if depth == 1 {
					child = &strings.Builder{}
					recordZoneBinding(&zone, t)
					if t.Name.Space == "" && t.Name.Local == "rule" {
						rule = newZoneRule(t)
					}
				} else if depth == 2 && rule != nil {
					rule.record(t)
				}
				child.WriteString("<" + elementName(t.Name) + canonicalAttrs(t.Attr) + ">")
			}
			depth++
		case xml.EndElement:
			depth--
			if depth == 0 {
				zone.endTag = before
				zone.selfClosing = before == after
				continue
			}
			child.WriteString("</" + elementName(t.Name) + ">")
			if depth == 1 {
				zone.children = append(zone.children, child.String())
				if rule != nil {
					zone.rules = append(zone.rules, *rule)
					rule = nil
				}
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			switch {
			case depth == 0 && strings.Trim(text, "\uFEFF") != "":
				return zoneDocument{}, fmt.Errorf("text outside the zone element")
			case depth == 1 && text != "":
				zone.children = append(zone.children, "#text:"+text)
			case depth > 1 && text != "":
				child.WriteString("#text:" + text)
			}
		}
	}
	if roots == 0 {
		return zoneDocument{}, fmt.Errorf("no zone element")
	}
	return zone, nil
}

func elementName(name xml.Name) string {
	if name.Space == "" {
		return name.Local
	}
	return name.Space + ":" + name.Local
}

func canonicalAttrs(attrs []xml.Attr) string {
	pairs := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		pairs = append(pairs, fmt.Sprintf(" %s=%q", elementName(attr.Name), attr.Value))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "")
}

// recordZoneBinding keeps the zone's own interface and source bindings (its
// direct <interface> and <source> children; those inside rich rules are
// match conditions, not bindings).
func recordZoneBinding(zone *zoneDocument, element xml.StartElement) {
	if element.Name.Space != "" {
		return
	}
	for _, attr := range element.Attr {
		switch {
		case element.Name.Local == "interface" && attr.Name.Local == "name":
			zone.interfaces = append(zone.interfaces, attr.Value)
		case element.Name.Local == "source" && attr.Name.Local == "address":
			zone.sources = append(zone.sources, attr.Value)
		case element.Name.Local == "source" && attr.Name.Local == "ipset":
			zone.sources = append(zone.sources, "ipset:"+attr.Value)
		}
	}
}

// zoneRule is one rich rule of a zone, kept as far as it decides whether
// firewalld drops or rejects the probe's traffic before an accept rule of
// the same priority can admit it: it evaluates a zone's deny rules before its
// allow rules, and a rule with a negative priority before both.
type zoneRule struct {
	family   string
	priority int
	action   string // accept, drop, reject or mark
	source   *zoneRuleSource
	matches  []zoneRuleMatch
}

type zoneRuleSource struct {
	address string
	mac     string
	ipset   string
	invert  bool
}

// zoneRuleMatch is a condition element of a rich rule other than its source
// and action (service, port, protocol, destination, ...).
type zoneRuleMatch struct {
	kind     string
	port     string
	protocol string // a port's protocol, or a protocol element's value
}

func newZoneRule(element xml.StartElement) *zoneRule {
	rule := &zoneRule{}
	for _, attr := range element.Attr {
		switch attr.Name.Local {
		case "family":
			rule.family = attr.Value
		case "priority":
			if priority, err := strconv.Atoi(strings.TrimSpace(attr.Value)); err == nil {
				rule.priority = priority
			}
		}
	}
	return rule
}

func (r *zoneRule) record(element xml.StartElement) {
	attr := func(name string) string {
		for _, a := range element.Attr {
			if a.Name.Local == name {
				return a.Value
			}
		}
		return ""
	}
	switch element.Name.Local {
	case "accept", "drop", "reject", "mark":
		r.action = element.Name.Local
	case "source":
		invert := strings.EqualFold(attr("invert"), "yes") || strings.EqualFold(attr("invert"), "true")
		r.source = &zoneRuleSource{address: attr("address"), mac: attr("mac"), ipset: attr("ipset"), invert: invert}
	case "log", "audit", "nflog", "limit":
		// Side effects of the action, not conditions.
	case "port":
		r.matches = append(r.matches, zoneRuleMatch{kind: "port", port: attr("port"), protocol: attr("protocol")})
	case "protocol":
		r.matches = append(r.matches, zoneRuleMatch{kind: "protocol", protocol: attr("value")})
	default:
		r.matches = append(r.matches, zoneRuleMatch{kind: element.Name.Local})
	}
}

// blocks reports the declared port a deny rule certainly stops for the probe
// address, "" when it does not or cannot be told: only what is certain
// counts, so a rule is never blamed for a probe it would let through.
func (r zoneRule) blocks(probe net.IP, ports []FirewallPort) string {
	if (r.action != "drop" && r.action != "reject") || r.priority > 0 || r.family == "ipv6" {
		return ""
	}
	if r.source != nil {
		if r.source.invert || r.source.mac != "" || r.source.ipset != "" || !addressIncludes(r.source.address, probe) {
			return ""
		}
	}
	for _, port := range ports {
		if r.coversPort(port) {
			return fmt.Sprintf("%d/%s", port.Port, port.Protocol)
		}
	}
	return ""
}

func (r zoneRule) coversPort(port FirewallPort) bool {
	switch len(r.matches) {
	case 0:
		return true
	case 1:
		match := r.matches[0]
		switch match.kind {
		case "protocol":
			return match.protocol == port.Protocol
		case "port":
			if match.protocol != port.Protocol {
				return false
			}
			first, last, found := strings.Cut(match.port, "-")
			if !found {
				last = first
			}
			low, lowErr := strconv.Atoi(strings.TrimSpace(first))
			high, highErr := strconv.Atoi(strings.TrimSpace(last))
			return lowErr == nil && highErr == nil && low <= port.Port && port.Port <= high
		}
	}
	return false
}

func (r zoneRule) String() string {
	text := r.action
	if r.source != nil {
		text += " from " + r.source.address
	}
	for _, match := range r.matches {
		switch match.kind {
		case "port":
			text += " port " + match.port + "/" + match.protocol
		case "protocol":
			text += " protocol " + match.protocol
		default:
			text += " " + match.kind
		}
	}
	if r.priority != 0 {
		text += " priority " + strconv.Itoa(r.priority)
	}
	return text
}

// addressIncludes reports that a zone or rule source address (an IP or a
// network) certainly contains the probe address.
func addressIncludes(address string, probe net.IP) bool {
	if _, network, err := net.ParseCIDR(address); err == nil {
		return network.Contains(probe)
	}
	ip := net.ParseIP(address)
	return ip != nil && ip.Equal(probe)
}

// deniesProbe describes a rich rule of the zone that drops or rejects the
// probe address's traffic to a declared port ahead of the accept rules the
// recovery adds, "" when there is none. Only rules that certainly do count;
// rules whose match cannot be evaluated offline (services, ipsets, MACs,
// destinations) are not blamed.
func (z zoneDocument) deniesProbe(probe net.IP, ports []FirewallPort) string {
	for _, rule := range z.rules {
		if port := rule.blocks(probe, ports); port != "" {
			return fmt.Sprintf("its rich rule \"%s\" drops or rejects the probe's traffic to %s and firewalld evaluates it before an accept rule", rule, port)
		}
	}
	return ""
}

// mergeFirewallProbeRules adds the probe rules to the guest's zone XML as the
// last children of its zone element and changes nothing else: attributes
// (such as target), everything the zone already allows, comments and
// formatting stay byte for byte. The result is parsed again and must keep
// every original child and end with exactly the probe rules; anything else
// is an error before the overlay is touched.
func mergeFirewallProbeRules(zoneXML, probeIP string, ports []FirewallPort) (string, error) {
	zone, err := parseZoneDocument(zoneXML)
	if err != nil {
		return "", err
	}
	if probe := net.ParseIP(probeIP); probe != nil {
		if denied := zone.deniesProbe(probe, ports); denied != "" {
			return "", errors.New(denied)
		}
	}
	rules := firewallProbeRules(probeIP, ports)
	var merged string
	if zone.selfClosing {
		// "<zone .../>" becomes "<zone ...>" + rules + "</zone>".
		merged = zoneXML[:zone.startTagEnd-len("/>")] + ">\n" + rules + "</zone>" + zoneXML[zone.startTagEnd:]
	} else {
		at := zone.endTag
		lineStart := strings.LastIndex(zoneXML[:at], "\n") + 1
		if strings.TrimSpace(zoneXML[lineStart:at]) == "" {
			at = lineStart // before the end tag's own indentation
		} else {
			rules = "\n" + rules
		}
		merged = zoneXML[:at] + rules + zoneXML[at:]
	}
	probe, err := parseZoneDocument("<zone>" + firewallProbeRules(probeIP, ports) + "</zone>")
	if err != nil {
		return "", err
	}
	result, err := parseZoneDocument(merged)
	want := append(append([]string(nil), zone.children...), probe.children...)
	if err != nil || result.attrs != zone.attrs || strings.Join(result.children, "\x00") != strings.Join(want, "\x00") {
		return "", fmt.Errorf("adding the probe rules would not keep the zone's own policy intact")
	}
	return merged, nil
}

// guestZones is the guest's firewalld zone configuration as firewalld loads
// it: a zone under /etc/firewalld/zones replaces the vendor zone of the same
// name under /usr/lib/firewalld/zones.
type guestZones struct {
	etc    map[string]string       // administrator zones: name -> contents
	parsed map[string]zoneDocument // administrator zones, parsed
	vendor map[string]bool         // vendor zone names
}

func (z guestZones) defined(name string) bool {
	_, admin := z.etc[name]
	return admin || z.vendor[name]
}

// readGuestZones reads every administrator zone (they carry the interface
// and source bindings: firewall-cmd --permanent writes the whole zone there)
// and lists the vendor zones. When one administrator zone fails to load,
// firewalld (1.3.3, fw.py start) abandons its whole /etc configuration for
// the stock one, so an unreadable zone is an error here: rules added beside
// it would never apply.
func (a *Adapter) readGuestZones(ctx context.Context, overlays []string) (guestZones, error) {
	zones := guestZones{etc: map[string]string{}, parsed: map[string]zoneDocument{}, vendor: map[string]bool{}}
	for _, dir := range []string{firewalldSystemZones, firewalldZoneDir} {
		exists, err := a.directoryExists(ctx, overlays, dir)
		if err != nil {
			return guestZones{}, dependencyError("inspect guest firewall zones", err)
		}
		if !exists {
			continue
		}
		entries, err := a.run(ctx, guestfishReadArgs(overlays, "ls", dir)...)
		if err != nil {
			return guestZones{}, dependencyError("list guest firewall zones", err)
		}
		for _, entry := range listingEntries(entries) {
			name, isZone := strings.CutSuffix(entry, ".xml")
			if dir == firewalldSystemZones {
				if isZone && validFirewalldZone(name) {
					zones.vendor[name] = true
				}
				continue
			}
			if !isZone {
				// firewalld combines the zone files in a subdirectory of
				// /etc/firewalld/zones into one zone; backups (*.xml.old)
				// and other files are ignored.
				if strings.Contains(entry, ".") {
					continue
				}
				if combined, err := a.directoryExists(ctx, overlays, path.Join(dir, entry)); err != nil {
					return guestZones{}, dependencyError("inspect guest firewall zones", err)
				} else if combined {
					return guestZones{}, fmt.Errorf("guest firewalld combines the zone files in %s into one zone, which CertiStack does not merge; use network_recovery.mode: preserve", path.Join(dir, entry))
				}
				continue
			}
			file := path.Join(dir, entry)
			if !validFirewalldZone(name) {
				return guestZones{}, fmt.Errorf("guest firewalld zone file %s does not have a safe zone name; use network_recovery.mode: preserve", file)
			}
			contents, err := a.run(ctx, guestfishReadArgs(overlays, "cat", file)...)
			if err != nil {
				return guestZones{}, dependencyError("read guest firewall zone", err)
			}
			parsed, err := parseZoneDocument(contents)
			if err != nil {
				return guestZones{}, fmt.Errorf("guest firewalld zone %s is not a zone document CertiStack can read (%v); firewalld falls back to its stock configuration when a zone fails to load, so the probe rules would not apply; fix the zone or use network_recovery.mode: preserve", file, err)
			}
			zones.etc[name], zones.parsed[name] = contents, parsed
		}
	}
	return zones, nil
}

// effectiveDefaultZone mirrors firewalld's start-up check: a DefaultZone that
// names no defined zone is replaced by public, external or block, in that
// order. Writing a zone of that name instead would make it exist, and the
// guest's default policy would become the probe rules alone.
func effectiveDefaultZone(configured string, zones guestZones) (string, error) {
	if zones.defined(configured) {
		return configured, nil
	}
	for _, fallback := range []string{"public", "external", "block"} {
		if zones.defined(fallback) {
			return fallback, nil
		}
	}
	return "", fmt.Errorf("guest firewalld defines neither its DefaultZone %q nor a public, external or block zone; use network_recovery.mode: preserve", configured)
}

// probeZones lists the zones that can receive the probe's traffic, the
// default zone first: firewalld dispatches a packet to a zone bound to its
// source address, then to one bound to its interface, and only then to the
// default zone. A zone bound to the probe's address or to any interface
// (the recovered NIC's name in the sandbox is not known offline) gets the
// same rules; a zone bound to a MAC address or an ipset cannot be ruled out
// offline and gets them too. Every rule admits only the probe address to the
// declared ports, so a zone the probe never reaches is unchanged in effect.
// Vendor zones carry no bindings of their own.
func probeZones(defaultZone string, zones guestZones, probeIP net.IP) []string {
	selected := []string{defaultZone}
	names := make([]string, 0, len(zones.parsed))
	for name := range zones.parsed {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		zone := zones.parsed[name]
		if name != defaultZone && (len(zone.interfaces) > 0 || sourcesMayInclude(zone.sources, probeIP)) {
			selected = append(selected, name)
		}
	}
	return selected
}

func sourcesMayInclude(sources []string, probeIP net.IP) bool {
	for _, source := range sources {
		if strings.HasPrefix(source, "ipset:") {
			return true
		}
		if _, network, err := net.ParseCIDR(source); err == nil {
			if network.Contains(probeIP) {
				return true
			}
			continue
		}
		if ip := net.ParseIP(source); ip != nil {
			if ip.Equal(probeIP) {
				return true
			}
			continue
		}
		return true // a MAC address, or a form this check does not know
	}
	return false
}

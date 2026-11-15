// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestnet

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
)

// parsedZone is what a zone document says, read with a plain XML parser as
// firewalld's own reader would see it (comments and CDATA are not elements).
type parsedZone struct {
	XMLName  xml.Name `xml:"zone"`
	Target   string   `xml:"target,attr"`
	Services []struct {
		Name string `xml:"name,attr"`
	} `xml:"service"`
	Ports []struct {
		Port     string `xml:"port,attr"`
		Protocol string `xml:"protocol,attr"`
	} `xml:"port"`
	Interfaces []struct {
		Name string `xml:"name,attr"`
	} `xml:"interface"`
	Rules []struct {
		Family string `xml:"family,attr"`
		Source struct {
			Address string `xml:"address,attr"`
		} `xml:"source"`
		Port struct {
			Port     string `xml:"port,attr"`
			Protocol string `xml:"protocol,attr"`
		} `xml:"port"`
		Accept *struct{} `xml:"accept"`
	} `xml:"rule"`
}

func readZone(t *testing.T, content string) parsedZone {
	t.Helper()
	decoder := xml.NewDecoder(strings.NewReader(content))
	for {
		if _, err := decoder.Token(); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("zone is not well-formed XML: %v\n%s", err, content)
		}
	}
	var zone parsedZone
	if err := xml.Unmarshal([]byte(content), &zone); err != nil {
		t.Fatalf("zone does not parse: %v\n%s", err, content)
	}
	return zone
}

// probeRuleCount is the number of accept rules for the probe address and
// port, as a parser sees them.
func (z parsedZone) probeRuleCount(probe, port string) int {
	count := 0
	for _, rule := range z.Rules {
		if rule.Source.Address == probe && rule.Port.Port == port && rule.Accept != nil {
			count++
		}
	}
	return count
}

const (
	probeIP   = "10.100.0.1"
	probePort = "8080"
)

var probePorts = []FirewallPort{{Protocol: "tcp", Port: 8080}}

// firewalldGuest is a guest with firewalld and the given administrator
// zones under /etc/firewalld/zones.
func firewalldGuest(t *testing.T, conf string, zones map[string]string, vendor ...string) *memGuest {
	t.Helper()
	files := map[string]string{}
	if conf != "" {
		files[firewalldConfig] = conf
	}
	for name, contents := range zones {
		files[firewalldZoneDir+"/"+name+".xml"] = contents
	}
	for _, name := range vendor {
		files[firewalldSystemZones+"/"+name+".xml"] = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<zone>\n  <short>" + name + "</short>\n</zone>\n"
	}
	return newMemGuest(t, files, firewalldDir, firewalldZoneDir)
}

func writeProbeRules(t *testing.T, guest *memGuest) ([]string, error) {
	t.Helper()
	return guest.adapter().writeFirewallProbeRule(context.Background(), []string{"/synthetic/overlay.qcow2"}, t.TempDir(), probeIP, probePorts)
}

// The probe rule is merged into the zone element, not into text that
// looks like one. Valid documents with unusual but legal markup keep their
// policy and gain exactly one effective probe rule.
func TestFirewallMergeKeepsPolicyForValidZoneXML(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		target   string
		services int
		ports    int
	}{
		{"ordinary", `<zone target="DROP"><service name="ssh"/><port port="8088" protocol="tcp"/></zone>`, "DROP", 1, 1},
		{"self-closing", `<zone target="DROP"/>`, "DROP", 0, 0},
		{"whitespace in the end tag", `<zone target="DROP"><service name="ssh"/><port port="8088" protocol="tcp"/></zone >`, "DROP", 1, 1},
		{"end tag text in a trailing comment", `<zone target="DROP"><port port="8088" protocol="tcp"/></zone><!-- example ends with </zone> -->`, "DROP", 0, 1},
		{"self-closing text in a leading comment", `<!-- example <zone/> --><zone target="DROP"/>`, "DROP", 0, 0},
		{"end tag text in a comment inside the zone", "<zone target=\"DROP\">\n  <!-- was </zone> -->\n  <service name=\"ssh\"/>\n</zone>\n", "DROP", 1, 0},
		{"end tag text in CDATA", "<zone target=\"DROP\">\n  <description><![CDATA[ends with </zone>]]></description>\n  <service name=\"ssh\"/>\n</zone>\n", "DROP", 1, 0},
		{"declaration, comments and a byte order mark", "\uFEFF<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!-- managed by hand -->\n<zone target=\"DROP\">\n  <service name=\"ssh\"/>\n</zone>\n<!-- end -->\n", "DROP", 1, 0},
		{"single-quoted attribute on several lines", "<zone\n    target='DROP'\n    >\n  <port port='8088' protocol='tcp'/>\n</zone>\n", "DROP", 0, 1},
		{"zone start tag with a space before the slash", `<zone target="DROP" />`, "DROP", 0, 0},
		{"a rich rule of its own", "<zone>\n  <rule family=\"ipv4\">\n    <source address=\"10.9.0.0/16\"/>\n    <port port=\"22\" protocol=\"tcp\"/>\n    <accept/>\n  </rule>\n</zone>\n", "", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := parseAny(t, tc.input)
			merged, err := mergeFirewallProbeRules(tc.input, probeIP, probePorts)
			if err != nil {
				t.Fatal(err)
			}
			zone := readZone(t, merged)
			if zone.Target != tc.target || len(zone.Services) != tc.services || len(zone.Ports) != tc.ports {
				t.Fatalf("policy changed: target %q, %d services, %d ports; want %q, %d, %d\n%s", zone.Target, len(zone.Services), len(zone.Ports), tc.target, tc.services, tc.ports, merged)
			}
			if zone.probeRuleCount(probeIP, probePort) != 1 {
				t.Fatalf("the zone has %d effective probe rules, want 1:\n%s", zone.probeRuleCount(probeIP, probePort), merged)
			}
			after := parseAny(t, merged)
			if after.attrs != before.attrs || len(after.children) != len(before.children)+1 || strings.Join(after.children[:len(before.children)], "\x00") != strings.Join(before.children, "\x00") {
				t.Fatalf("the zone's own children changed:\nbefore %q\nafter  %q", before.children, after.children)
			}
			// Nothing but the probe rule is added: the rest is the input, byte
			// for byte (a self-closing zone gains an end tag).
			rules := firewallProbeRules(probeIP, probePorts)
			if !before.selfClosing && strings.Replace(merged, rules, "", 1) != tc.input && strings.Replace(merged, "\n"+rules, "", 1) != tc.input {
				t.Fatalf("more than the probe rule changed:\n%q\nfrom\n%q", merged, tc.input)
			}
		})
	}
}

func parseAny(t *testing.T, doc string) zoneDocument {
	t.Helper()
	zone, err := parseZoneDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	return zone
}

// A document that is not one zone element is refused before the
// overlay is touched, not replaced by a zone of the probe rules alone.
func TestFirewallMergeRefusesDocumentsFirewalldWouldNotLoad(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":                   "",
		"only a comment":          "<!-- <zone/> -->",
		"text":                    "not xml",
		"another element":         "<policy/>",
		"two zones":               "<zone/><zone/>",
		"text after the zone":     "<zone/>junk",
		"unclosed":                "<zone target=\"DROP\">\n<service name=\"ssh\"/>\n",
		"mismatched end tag":      "<zone></zon>",
		"an undeclared namespace": "<x:zone/>",
	} {
		t.Run(name, func(t *testing.T) {
			if merged, err := mergeFirewallProbeRules(doc, probeIP, probePorts); err == nil {
				t.Fatalf("accepted a document that is not a zone:\n%s", merged)
			}
			guest := firewalldGuest(t, "DefaultZone=public\n", map[string]string{"public": doc})
			if _, err := writeProbeRules(t, guest); err == nil || !strings.Contains(err.Error(), "public.xml") {
				t.Fatalf("error = %v, want the zone file named", err)
			}
			if guest.mutated() {
				t.Fatal("the overlay was written although the zone cannot be merged")
			}
		})
	}
}

// The probe's traffic is handled by the zone bound to its source
// address, else by the zone bound to the NIC, else by the default zone. The
// rule goes to every zone that can be the one.
func TestFirewallProbeRulesReachTheZonesThatHandleTheProbe(t *testing.T) {
	zone := func(binding string) string {
		return "<zone target=\"DROP\"><short>Internal</short>" + binding + "</zone>\n"
	}
	cases := []struct {
		name     string
		internal string
		other    map[string]string
		want     []string // zones that gain the probe rule
	}{
		{"default zone only", zone(""), nil, []string{"public"}},
		{"internal zone bound to an interface", zone(`<interface name="ens18"/>`), nil, []string{"internal", "public"}},
		{"internal zone bound to a network holding the probe", zone(`<source address="10.0.0.0/8"/>`), nil, []string{"internal", "public"}},
		{"internal zone bound to the probe address", zone(`<source address="10.100.0.1"/>`), nil, []string{"internal", "public"}},
		{"internal zone bound to another network", zone(`<source address="192.168.0.0/16"/>`), nil, []string{"public"}},
		{"internal zone bound to another address", zone(`<source address="10.100.0.2"/>`), nil, []string{"public"}},
		{"internal zone bound to an IPv6 network", zone(`<source address="fd00::/8"/>`), nil, []string{"public"}},
		{"internal zone bound to an ipset", zone(`<source ipset="office"/>`), nil, []string{"internal", "public"}},
		{"internal zone bound to a MAC address", zone(`<source address="02:aa:bb:cc:dd:ee"/>`), nil, []string{"internal", "public"}},
		{"a source only inside a rich rule is no binding", zone(`<rule family="ipv4"><source address="10.0.0.0/8"/><accept/></rule>`), nil, []string{"public"}},
		{"several bound zones", zone(`<interface name="ens18"/>`), map[string]string{"work": zone(`<source address="10.100.0.0/24"/>`), "dmz": zone(`<source address="172.16.0.0/12"/>`)}, []string{"internal", "public", "work"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zones := map[string]string{"public": "<zone target=\"DROP\"><short>Public</short></zone>\n", "internal": tc.internal}
			for name, contents := range tc.other {
				zones[name] = contents
			}
			guest := firewalldGuest(t, "DefaultZone=public\n", zones)
			before := map[string]string{}
			for name := range zones {
				before[name] = guest.files[firewalldZoneDir+"/"+name+".xml"]
			}
			written, err := writeProbeRules(t, guest)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for name := range zones {
				content := guest.files[firewalldZoneDir+"/"+name+".xml"]
				if readZone(t, content).probeRuleCount(probeIP, probePort) == 1 {
					got = append(got, name)
				} else if content != before[name] {
					t.Fatalf("zone %s changed without gaining the probe rule:\n%s", name, content)
				}
			}
			if !sameSet(got, tc.want) {
				t.Fatalf("probe rule in zones %v, want %v", got, tc.want)
			}
			if len(written) != len(tc.want) {
				t.Fatalf("reported files %v, want one per zone %v", written, tc.want)
			}
			for _, name := range tc.want {
				if !contains(written, firewalldZoneDir+"/"+name+".xml") {
					t.Fatalf("reported files %v lack zone %s", written, name)
				}
			}
			// Everything a zone had before is still there, target included.
			for name, original := range before {
				if got := readZone(t, guest.files[firewalldZoneDir+"/"+name+".xml"]); got.Target != readZone(t, original).Target {
					t.Fatalf("zone %s lost its target", name)
				}
			}
		})
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	return true
}

func contains(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}

// The reported fixtures through Apply, on the networkd adapter it used:
// the internal zone is byte-for-byte unchanged only when nothing binds it.
func TestApplyAddsTheProbeRuleToTheBoundZoneToo(t *testing.T) {
	for _, tc := range []struct {
		name        string
		binding     string
		wantChanged bool
	}{
		{"default-zone control", "", false},
		{"interface-bound zone", `<interface name="ens18"/>`, true},
		{"source-bound zone", `<source address="10.0.0.0/8"/>`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			internal := "<zone target=\"DROP\"><short>Internal</short>" + tc.binding + "</zone>\n"
			guest := newMemGuest(t, map[string]string{
				firewalldConfig:                    "DefaultZone=public\n",
				firewalldZoneDir + "/public.xml":   "<zone target=\"DROP\"><short>Public</short></zone>\n",
				firewalldZoneDir + "/internal.xml": internal,
			}, systemdNetworkdDir, firewalldDir, firewalldZoneDir)
			cfg := Config{VMID: 990076, Overlays: []string{"/synthetic/zone-overlay.qcow2"}, MAC: "02:00:00:00:00:76", Address: "10.100.0.10", CIDR: "10.100.0.0/24", Mode: modeSystemdNetworkd, OnlyNIC: true, ProbeIP: probeIP, FirewallPorts: probePorts}
			result, err := guest.adapter().Apply(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if got := readZone(t, guest.files[firewalldZoneDir+"/public.xml"]).probeRuleCount(probeIP, probePort); got != 1 {
				t.Fatalf("public zone has %d probe rules", got)
			}
			changed := guest.files[firewalldZoneDir+"/internal.xml"] != internal
			if changed != tc.wantChanged {
				t.Fatalf("internal zone changed = %v, want %v", changed, tc.wantChanged)
			}
			if changed && readZone(t, guest.files[firewalldZoneDir+"/internal.xml"]).probeRuleCount(probeIP, probePort) != 1 {
				t.Fatalf("internal zone lacks the probe rule:\n%s", guest.files[firewalldZoneDir+"/internal.xml"])
			}
			for _, zone := range []string{"public", "internal"} {
				if want := zone == "public" || tc.wantChanged; want != contains(result.Files, firewalldZoneDir+"/"+zone+".xml") {
					t.Fatalf("result files %v do not describe the zones written", result.Files)
				}
			}
		})
	}
}

// A vendor zone bound to nothing is copied under /etc first (keeping
// its label), an administrator zone is edited in place, and both are found
// by the binding of the administrator zone.
func TestFirewallVendorAndAdministratorZones(t *testing.T) {
	guest := firewalldGuest(t, "", map[string]string{
		"corp": "<zone target=\"DROP\">\n  <interface name=\"ens18\"/>\n  <service name=\"ssh\"/>\n</zone>\n",
	}, "public", "internal", "drop")
	written, err := writeProbeRules(t, guest)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSet(written, []string{firewalldZoneDir + "/public.xml", firewalldZoneDir + "/corp.xml"}) {
		t.Fatalf("written = %v", written)
	}
	if !batchHasCommand(lastBatch(guest.calls), "cp-a", firewalldSystemZones+"/public.xml", firewalldZoneDir+"/public.xml") {
		t.Fatalf("the vendor zone was not copied first: %v", lastBatch(guest.calls))
	}
	if _, wrote := guest.files[firewalldZoneDir+"/internal.xml"]; wrote {
		t.Fatal("a vendor zone that binds nothing was copied")
	}
	if got := readZone(t, guest.files[firewalldZoneDir+"/corp.xml"]); got.Target != "DROP" || len(got.Services) != 1 || got.probeRuleCount(probeIP, probePort) != 1 {
		t.Fatalf("corp zone:\n%s", guest.files[firewalldZoneDir+"/corp.xml"])
	}
}

// firewalld replaces a DefaultZone that names no defined zone at start-up
// (public, else external, else block). Writing a zone of that name would
// define it and turn the guest's default policy into the probe rules alone.
func TestFirewallDefaultZoneThatIsNotDefined(t *testing.T) {
	guest := firewalldGuest(t, "DefaultZone=ghost\n", nil, "public", "external", "block")
	written, err := writeProbeRules(t, guest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(written, []string{firewalldZoneDir + "/public.xml"}) {
		t.Fatalf("written = %v, want the zone firewalld really uses", written)
	}
	if _, defined := guest.files[firewalldZoneDir+"/ghost.xml"]; defined {
		t.Fatal("a zone named by the undefined DefaultZone was created")
	}

	guest = firewalldGuest(t, "DefaultZone=ghost\n", nil, "external", "block")
	if written, err = writeProbeRules(t, guest); err != nil || !reflect.DeepEqual(written, []string{firewalldZoneDir + "/external.xml"}) {
		t.Fatalf("written = %v, %v; want external", written, err)
	}

	guest = firewalldGuest(t, "DefaultZone=ghost\n", nil, "dmz")
	if _, err = writeProbeRules(t, guest); err == nil || !strings.Contains(err.Error(), "ghost") || guest.mutated() {
		t.Fatalf("error = %v; want a refusal naming the DefaultZone before any write", err)
	}
}

// firewalld.conf is read as firewalld reads it.
func TestFirewalldDefaultZoneParsing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		conf    string
		want    string
		wantErr bool
	}{
		{"absent file", "", "public", false},
		{"not set", "# DefaultZone=work\nCleanupOnExit=yes\n", "public", false},
		{"set", "DefaultZone=work\n", "work", false},
		{"spaces around the equal sign", "DefaultZone = work \n", "work", false},
		{"first definition counts", "DefaultZone=work\nDefaultZone=home\n", "work", false},
		{"an empty value is ignored", "DefaultZone=\nDefaultZone=home\n", "home", false},
		{"key case matters", "defaultzone=work\n", "public", false},
		{"semicolon comment", ";DefaultZone=work\nDefaultZone=home\n", "home", false},
		{"a second equal sign is an invalid line", "DefaultZone=work=x\nDefaultZone=home\n", "home", false},
		{"quotes are part of the value", "DefaultZone=\"work\"\n", "", true},
		{"a path is not a zone", "DefaultZone=../../unsafe\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			if tc.conf != "" {
				files[firewalldConfig] = tc.conf
			}
			guest := newMemGuest(t, files, firewalldDir)
			got, err := guest.adapter().firewalldDefaultZone(context.Background(), []string{"/synthetic/overlay.qcow2"})
			if tc.wantErr != (err != nil) || got != tc.want {
				t.Fatalf("zone = %q, error = %v; want %q, error %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// firewalld reads a zone directory under /etc/firewalld/zones as one zone,
// and drops its whole user configuration when a zone file does not load.
func TestFirewallZonesFirewalldCombinesOrCannotLoad(t *testing.T) {
	guest := firewalldGuest(t, "DefaultZone=public\n", map[string]string{"public": "<zone/>"})
	guest.files[firewalldZoneDir+"/office/base.xml"] = "<zone/>"
	if _, err := writeProbeRules(t, guest); err == nil || !strings.Contains(err.Error(), "combines") || guest.mutated() {
		t.Fatalf("error = %v, mutated = %v", err, guest.mutated())
	}

	guest = firewalldGuest(t, "DefaultZone=public\n", map[string]string{"public": "<zone/>", "broken": "<zone><service name=\"ssh\"></zone>"})
	if _, err := writeProbeRules(t, guest); err == nil || !strings.Contains(err.Error(), "broken.xml") || !strings.Contains(err.Error(), "stock configuration") || guest.mutated() {
		t.Fatalf("error = %v, mutated = %v", err, guest.mutated())
	}

	// Backups and other files are ignored by firewalld.
	guest = firewalldGuest(t, "DefaultZone=public\n", map[string]string{"public": "<zone/>"})
	guest.files[firewalldZoneDir+"/public.xml.old"] = "not xml"
	guest.files[firewalldZoneDir+"/notes.txt"] = "not xml"
	if _, err := writeProbeRules(t, guest); err != nil {
		t.Fatal(err)
	}
}

// The probe rules reach a zone with a deny rule ahead of them only when that
// rule cannot stop the probe; a rule that certainly does is reported instead
// of adding an accept rule that never applies.
func TestFirewallDenyRulesAheadOfTheProbeRule(t *testing.T) {
	deny := func(rule string) string {
		return "<zone target=\"DROP\">\n  " + rule + "\n</zone>\n"
	}
	cases := []struct {
		name    string
		zone    string
		blocked bool
	}{
		{"drop everything from the probe's network", deny(`<rule family="ipv4"><source address="10.0.0.0/8"/><drop/></rule>`), true},
		{"reject the declared port", deny(`<rule><port port="8080" protocol="tcp"/><reject/></rule>`), true},
		{"drop a port range holding it", deny(`<rule family="ipv4"><source address="10.100.0.1"/><port port="8000-8100" protocol="tcp"/><drop/></rule>`), true},
		{"drop all tcp", deny(`<rule><protocol value="tcp"/><drop/></rule>`), true},
		{"a negative priority is evaluated first too", deny(`<rule priority="-10"><source address="10.0.0.0/8"/><drop/></rule>`), true},
		{"a positive priority is evaluated after the accept rules", deny(`<rule priority="10"><source address="10.0.0.0/8"/><drop/></rule>`), false},
		{"another network", deny(`<rule family="ipv4"><source address="192.168.0.0/16"/><drop/></rule>`), false},
		{"another port", deny(`<rule><port port="22" protocol="tcp"/><reject/></rule>`), false},
		{"another protocol", deny(`<rule><port port="8080" protocol="udp"/><reject/></rule>`), false},
		{"an IPv6 rule", deny(`<rule family="ipv6"><source address="fd00::/8"/><drop/></rule>`), false},
		{"an accept rule", deny(`<rule><source address="10.0.0.0/8"/><accept/></rule>`), false},
		{"an inverted source cannot be told", deny(`<rule><source address="192.168.0.0/16" invert="True"/><drop/></rule>`), false},
		{"a service cannot be told", deny(`<rule><service name="http"/><reject/></rule>`), false},
		{"an ipset cannot be told", deny(`<rule><source ipset="banned"/><drop/></rule>`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := mergeFirewallProbeRules(tc.zone, probeIP, probePorts)
			if tc.blocked {
				if err == nil || !strings.Contains(err.Error(), "8080/tcp") {
					t.Fatalf("error = %v, want the rule reported", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if readZone(t, merged).probeRuleCount(probeIP, probePort) != 1 {
				t.Fatalf("no probe rule:\n%s", merged)
			}
		})
	}
}

func TestProbeZonesAndSources(t *testing.T) {
	zones := guestZones{parsed: map[string]zoneDocument{
		"a": {interfaces: []string{"eth0"}},
		"b": {sources: []string{"10.0.0.0/8"}},
		"c": {sources: []string{"192.168.0.0/16", "fd00::/8"}},
		"d": {sources: []string{"ipset:banned"}},
		"e": {sources: []string{"02:aa:bb:cc:dd:ee"}},
		"f": {sources: []string{"10.0.0.0/255.0.0.0"}},
		"g": {},
	}}
	got := probeZones("public", zones, net.ParseIP(probeIP).To4())
	if want := []string{"public", "a", "b", "d", "e", "f"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("probeZones = %v, want %v", got, want)
	}
	// The default zone is never listed twice.
	zones.parsed["public"] = zoneDocument{interfaces: []string{"eth0"}}
	if got := probeZones("public", zones, net.ParseIP(probeIP).To4()); got[0] != "public" || contains(got[1:], "public") {
		t.Fatalf("probeZones = %v", got)
	}
}

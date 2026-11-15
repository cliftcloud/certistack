// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package initplan

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// nginxService is nginx as Rocky Linux 9 packages it.
func nginxService() Service {
	return Service{Kind: ServiceNginx, Unit: "nginx.service", Config: "/etc/nginx/nginx.conf", Listeners: []Listener{
		{Port: 80, HTTP: true, File: "/etc/nginx/nginx.conf", Text: "listen 80"},
		{Address: "[::]", Port: 80, HTTP: true, File: "/etc/nginx/nginx.conf", Text: "listen [::]:80"},
	}}
}

func sshService(port int) Service {
	return Service{Kind: ServiceSSH, Unit: "sshd.service", Listeners: []Listener{{Port: port, File: "/etc/ssh/sshd_config", Text: fmt.Sprintf("Port %d", port)}}}
}

func inspectedWith(services ...Service) *InspectedVM {
	return &InspectedVM{SourceVMID: 100, Snapshot: "vm/100/2026-09-27T03:00:00Z", GuestFindings: GuestFindings{OS: "Rocky Linux 9.4 (Blue Onyx)", Services: services}}
}

// probes is a choice's probes as "kind port[=status]".
func probes(c probeChoice) string {
	var out []string
	for _, p := range c.probes {
		s := fmt.Sprintf("%s %d", p.kind, p.listener.Port)
		if p.kind == "http" {
			s += fmt.Sprintf("=%d", p.status)
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

func TestChooseProbes(t *testing.T) {
	loopback := func(kind, unit string, port int) Service {
		return Service{Kind: kind, Unit: unit, Listeners: []Listener{{Address: "127.0.0.1", Port: port, Text: "bind 127.0.0.1"}}}
	}
	all := func(kind, unit string, port int) Service {
		return Service{Kind: kind, Unit: unit, Listeners: []Listener{{Port: port}}}
	}
	for _, tc := range []struct {
		name     string
		found    *InspectedVM
		probes   string
		ssh      bool
		comments []string // each must be in the header or a probe's comments
	}{
		{"nginx as packaged, and sshd, which is not probed", inspectedWith(nginxService(), sshService(22)), "http 80=200", false,
			[]string{"found nginx, sshd. CHANGE: confirm", "sshd (port 22) was also found", "nginx: enabled unit nginx.service; listen 80, listen [::]:80 in /etc/nginx/nginx.conf.", "expected_status 200 is assumed"}},
		{"a redirect the configuration shows", inspectedWith(Service{Kind: ServiceNginx, Unit: "nginx.service", Listeners: []Listener{{Port: 80, HTTP: true, Status: 301}}}), "http 80=301", false,
			[]string{"expected_status 301 is what its configuration answers"}},
		{"HTTPS only is checked as TCP", inspectedWith(Service{Kind: ServiceApache, Unit: "httpd.service", Listeners: []Listener{{Port: 443, HTTP: true, TLS: true}}}), "tcp 443", false,
			[]string{"HTTPS is checked as TCP"}},
		{"a service bound to one address is probed, with a warning", inspectedWith(Service{Kind: ServicePostgreSQL, Unit: "postgresql.service", Listeners: []Listener{{Address: "10.20.0.5", Port: 5432}}}), "tcp 5432", false,
			[]string{"bound to 10.20.0.5", "fails until it also listens on every address"}},
		{"loopback services are not probed, and sshd is the probe", inspectedWith(loopback(ServiceMariaDB, "mariadb.service", 3306), loopback(ServiceRedis, "redis-server.service", 6379), sshService(2222)), "tcp 2222", true,
			[]string{"MariaDB/MySQL (mariadb.service) is not probed: it listens only on the guest's loopback (127.0.0.1:3306)", "found MariaDB/MySQL, Redis, sshd"}},
		{"nothing found: the SSH probe stays, and says why", inspectedWith(), "", true,
			[]string{"found no service init knows"}},
		{"not inspected: the SSH probe stays, with the reason", &InspectedVM{SourceVMID: 100, Snapshot: "vm/100/2026-09-27T03:00:00Z", Skipped: "the node's memory is 93% used"}, "", true,
			[]string{"Not inspected: the node's memory is 93% used."}},
		{"a service without TCP", inspectedWith(Service{Kind: ServiceMariaDB, Unit: "mariadb.service", NoTCP: "skip-networking in /etc/my.cnf"}, all(ServiceRedis, "redis.service", 6379)), "tcp 6379", false,
			[]string{"MariaDB/MySQL (mariadb.service) is not probed: skip-networking in /etc/my.cnf."}},
		{"two services on one port: the first by priority", inspectedWith(Service{Kind: ServiceApache, Unit: "apache2.service", Listeners: []Listener{{Port: 80, HTTP: true}}}, nginxService()), "http 80=200", false,
			[]string{"apache2 also listens on port 80, which the nginx probe checks."}},
		{"more than six services: six probes, in priority order", inspectedWith(
			all(ServiceRedis, "redis-server@a.service", 6380), all(ServiceRedis, "redis-server@b.service", 6381), all(ServiceRedis, "redis-server@c.service", 6382),
			all(ServicePostgreSQL, "postgresql@15-main.service", 5432), all(ServicePostgreSQL, "postgresql@16-main.service", 5433),
			all(ServiceMariaDB, "mariadb.service", 3306), nginxService(), sshService(22)), "http 80=200, tcp 5432, tcp 5433, tcp 3306, tcp 6380, tcp 6381", false,
			[]string{"1 more service(s) were found and are not probed", "Redis (redis-server@c.service)"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			choice := chooseProbes(tc.found, "")
			if got := probes(choice); got != tc.probes {
				t.Errorf("probes %q, want %q", got, tc.probes)
			}
			if choice.checksSSH() != tc.ssh {
				t.Errorf("checks SSH %v, want %v", choice.checksSSH(), tc.ssh)
			}
			text := strings.Join(choice.header, "\n")
			for _, p := range choice.probes {
				text += "\n" + strings.Join(p.comments, "\n")
			}
			for _, want := range tc.comments {
				if !strings.Contains(text, want) {
					t.Errorf("comments lack %q:\n%s", want, text)
				}
			}
		})
	}
}

// What the guest wrote reaches the plan only as printable ASCII on one line:
// a unit or file name with a newline cannot end the comment and write YAML.
func TestGuestTextCannotWriteYAML(t *testing.T) {
	found := inspectedWith(Service{Kind: ServiceNginx, Unit: "nginx.service", Listeners: []Listener{{Port: 80, HTTP: true, File: "/etc/nginx/x\n          - type: \"qga\"\n            command: \"ping\"", Text: "listen 80\u202e"}}})
	found.OS = "Evil\nOS"
	d := discovered()
	res, err := Compose(d, Options{Written: backupTime, Inspect: true, Inspection: &Inspection{VMs: []InspectedVM{*found}}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.LoadFromReader(bytes.NewReader(res.YAML))
	if err != nil {
		t.Fatalf("plan does not load: %v\n%s", err, res.YAML)
	}
	for _, p := range plan.Tiers[0].VMs[0].Probes {
		if p.Type == "qga" {
			t.Fatalf("the guest's text wrote a probe:\n%s", res.YAML)
		}
	}
	if strings.Contains(string(res.YAML), "\u202e") || strings.Contains(string(res.YAML), "Evil\nOS") {
		t.Fatalf("guest text reached the plan as written:\n%s", res.YAML)
	}
}

// With --inspect, each VM's probes come from what was found and the plan
// validates as written. VMs init does not inspect say why, and keep their probe.
func TestComposeWithInspection(t *testing.T) {
	d := discovered()
	inspection := &Inspection{Journaled: true, CleanupVerified: true, VMs: []InspectedVM{
		*inspectedWith(nginxService(), sshService(22)),
		{SourceVMID: 106, Snapshot: "vm/106/2026-09-27T03:00:00Z", Failed: "libguestfs found no operating system on the backed-up disks"},
	}}
	res, err := Compose(d, Options{Written: backupTime, Inspect: true, Inspection: inspection})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.LoadFromReader(bytes.NewReader(res.YAML))
	if err != nil {
		t.Fatalf("plan does not load: %v\n%s", err, res.YAML)
	}
	vms := plan.Tiers[0].VMs
	if p := vms[0].Probes; len(p) != 1 || p[0].Type != "http" || p[0].Port != 80 || p[0].ExpectedStatus != 200 || p[0].Path != "/" || p[0].TimeoutSec != 300 || p[0].TargetIP != "192.0.2.10" {
		t.Fatalf("VM 100's probes %+v", p)
	}
	if p := vms[3].Probes; len(p) != 1 || p[0].Type != "tcp" || p[0].Port != 22 {
		t.Fatalf("VM 106's probes %+v, want the SSH probe", p)
	}
	// The comments as one line each, whatever their wrapping.
	text := strings.ReplaceAll(string(res.YAML), "\n          # ", " ")
	for _, want := range []string{
		" Inspected backup vm/100/2026-09-27T03:00:00Z (Rocky Linux 9.4 (Blue Onyx)), read-only: found nginx, sshd. CHANGE: confirm these probes check what this VM is for.",
		" Not inspected: libguestfs found no operating system on the backed-up disks.",
		" Not inspected: init --inspect reads Linux guests, and this is a Windows guest.",
		" Not inspected: init --inspect reads Linux guests, and this is guest OS type other.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("plan lacks %q:\n%s", want, text)
		}
	}
	notes := strings.Join(res.Notes, "\n")
	for _, want := range []string{
		"Linux VMs checked on the services found in their newest backup (confirm each is what the VM is for): 100 (web-01): nginx HTTP 80.",
		"Linux VMs checked on SSH until you change it to the service each one provides: " + vmLabel(d.VMs[6]) + ": not inspected: libguestfs found no operating system",
		"Not inspected (init --inspect reads the Linux guests the sandbox gives an address): 101 (dc-01): a Windows guest; 103 (fw): guest OS type other.",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	if res.InspectHint {
		t.Error("the --inspect hint is given to a plan written with --inspect")
	}
}

// A node that refused (its lock was held) leaves every Linux VM on SSH, each
// saying why.
func TestComposeWhenTheNodeRefusedTheInspection(t *testing.T) {
	res, err := Compose(discovered(), Options{Written: backupTime, Inspect: true, Inspection: &Inspection{Refused: "another CertiStack operation holds the node's host lock"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ReplaceAll(string(res.YAML), "\n          # ", " "), " Not inspected: another CertiStack operation holds the node's host lock.") {
		t.Fatalf("plan:\n%s", res.YAML)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "100 (web-01): not inspected: another CertiStack operation holds the node's host lock") {
		t.Fatalf("notes %q", res.Notes)
	}
}

// Without --inspect the plan is what it was, and the hint says --inspect
// exists.
func TestComposeWithoutInspectionOffersIt(t *testing.T) {
	res, err := Compose(discovered(), Options{Written: backupTime})
	if err != nil {
		t.Fatal(err)
	}
	if !res.InspectHint || strings.Contains(string(res.YAML), "nspect") {
		t.Fatalf("hint %v, plan:\n%s", res.InspectHint, res.YAML)
	}
}

func TestInspectionTargetsAreTheLinuxVMsWithAnAddress(t *testing.T) {
	targets := InspectionTargets(discovered(), "")
	if fmt.Sprint(targets) != "[{100 vm/100/2026-09-27T03:00:00Z} {106 vm/106/2026-09-27T03:00:00Z}]" {
		t.Fatalf("targets %v", targets)
	}
	if err := ValidateInspectRequest(InspectRequest{Node: "pve1", Targets: targets}); err != nil {
		t.Fatal(err)
	}
	for name, req := range map[string]InspectRequest{
		"no targets":          {Node: "pve1"},
		"another VM's backup": {Node: "pve1", Targets: []InspectTarget{{SourceVMID: 100, Snapshot: "vm/101/2026-09-27T03:00:00Z"}}},
		"not a snapshot":      {Node: "pve1", Targets: []InspectTarget{{SourceVMID: 100, Snapshot: "vm/100/latest"}}},
		"twice":               {Node: "pve1", Targets: []InspectTarget{targets[0], targets[0]}},
		"a bad node":          {Node: "pve 1", Targets: targets},
	} {
		if err := ValidateInspectRequest(req); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The node's answer is held to the request: only the VMs asked about, each
// once, for the backup asked about. What is beyond init's use is dropped.
func TestCheckInspection(t *testing.T) {
	req := InspectRequest{Node: "pve1", Targets: []InspectTarget{{SourceVMID: 100, Snapshot: "vm/100/2026-09-27T03:00:00Z"}}}
	good := &Inspection{VMs: []InspectedVM{{SourceVMID: 100, Snapshot: "vm/100/2026-09-27T03:00:00Z", GuestFindings: GuestFindings{Services: []Service{
		{Kind: "nginx", Unit: "nginx.service", Listeners: []Listener{{Port: 80, Status: 101}, {Port: 70000}}},
		{Kind: "telnet", Unit: "telnet.socket"},
	}}}}}
	if err := CheckInspection(req, good); err != nil {
		t.Fatal(err)
	}
	if s := good.VMs[0].Services; len(s) != 1 || len(s[0].Listeners) != 1 || s[0].Listeners[0].Status != 0 {
		t.Fatalf("checked services %+v", s)
	}
	for name, in := range map[string]*Inspection{
		"a VM not asked about": {VMs: []InspectedVM{{SourceVMID: 101, Snapshot: "vm/101/2026-09-27T03:00:00Z"}}},
		"another backup":       {VMs: []InspectedVM{{SourceVMID: 100, Snapshot: "vm/100/2026-01-01T00:00:00Z"}}},
		"twice":                {VMs: []InspectedVM{{SourceVMID: 100, Snapshot: "vm/100/2026-09-27T03:00:00Z"}, {SourceVMID: 100, Snapshot: "vm/100/2026-09-27T03:00:00Z"}}},
	} {
		if err := CheckInspection(req, in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import "testing"

// shellInjections are what a careless paste or a hostile value could carry into
// a flag. Each is appended to a valid value, so the test proves the value is
// refused for the metacharacter and not for being short or empty.
var shellInjections = map[string]string{
	"semicolon":            ";id",
	"semicolon and space":  "; reboot",
	"command substitution": "$(id)",
	"dollar variable":      "$HOME",
	"backtick":             "`id`",
	"newline":              "\nid",
	"carriage return":      "\rid",
	"single quote":         "'",
	"double quote":         `"`,
	"ampersand":            "&&id",
	"pipe":                 "|id",
	"redirect":             ">/etc/passwd",
	"backslash":            `\`,
	"space":                " id",
	"tab":                  "\tid",
	"hash":                 "#",
	"glob":                 "*",
	"NUL":                  "\x00",
}

// Every flag the script is built from refuses every one of them, so no value
// can change what a command of the printed script means.
func TestRBACParamsRefuseShellMetacharactersInEveryFlag(t *testing.T) {
	flags := map[string]func(p *RBACParams, value string){
		"--node":             func(p *RBACParams, v string) { p.Node = "pve1" + v },
		"--overlay-storage":  func(p *RBACParams, v string) { p.OverlayStorage = "scratch" + v },
		"--zone":             func(p *RBACParams, v string) { p.Zones = []string{"csSb01" + v} },
		"--sandbox-zones[1]": func(p *RBACParams, v string) { p.Zones = []string{"csSb01", "csSb02" + v} },
		"--pbs-datastore":    func(p *RBACParams, v string) { p.PBSDatastore = "datastore1" + v },
		"--pbs-namespace":    func(p *RBACParams, v string) { p.PBSDatastore, p.PBSNamespace = "datastore1", "prod"+v },
		"--pbs-namespace (second level)": func(p *RBACParams, v string) {
			p.PBSDatastore, p.PBSNamespace = "datastore1", "prod/dc1"+v
		},
	}
	good := RBACParams{Node: "pve1", OverlayStorage: "scratch", Zones: []string{"csSb01", "csSb02"}, PBSDatastore: "datastore1", PBSNamespace: "prod/dc1"}
	if _, err := RBACScript(good); err != nil {
		t.Fatalf("the baseline is refused: %v", err)
	}
	for flag, set := range flags {
		for name, injection := range shellInjections {
			p := good
			p.Zones = append([]string(nil), good.Zones...)
			set(&p, injection)
			script, err := RBACScript(p)
			if err == nil {
				t.Errorf("%s accepted a value with a %s (%q)", flag, name, injection)
			}
			if script != "" {
				t.Errorf("%s with a %s still produced a script", flag, name)
			}
		}
	}
}

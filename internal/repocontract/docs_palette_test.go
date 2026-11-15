// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"math"
	"os"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// materialPrimaries are the solid primary colours of the pinned MkDocs
// Material theme (requirements-docs.txt, 9.7.7; palette.*.min.css): the
// header's and navigation's background (fg) and the text on it (bg), which
// the theme also uses for ordinary links on a light page (fg on white). A
// primary that is not here has no known pair, so the test refuses it rather
// than guess.
var materialPrimaries = map[string][2]string{
	"red":         {"#ef5552", "#ffffff"},
	"pink":        {"#e92063", "#ffffff"},
	"purple":      {"#ab47bd", "#ffffff"},
	"deep purple": {"#7e56c2", "#ffffff"},
	"indigo":      {"#4051b5", "#ffffff"},
	"blue":        {"#2094f3", "#ffffff"},
	"light blue":  {"#02a6f2", "#ffffff"},
	"cyan":        {"#00bdd6", "#ffffff"},
	"teal":        {"#009485", "#ffffff"},
	"green":       {"#4cae4f", "#ffffff"},
	"light green": {"#8bc34b", "#ffffff"},
	"lime":        {"#cbdc38", "#000000"},
	"yellow":      {"#ffec3d", "#000000"},
	"amber":       {"#ffc105", "#000000"},
	"orange":      {"#ffa724", "#000000"},
	"deep orange": {"#ff6e42", "#ffffff"},
	"brown":       {"#795649", "#ffffff"},
	"grey":        {"#757575", "#ffffff"},
	"blue grey":   {"#546d78", "#ffffff"},
}

// relativeLuminance is the WCAG 2 definition for an #rrggbb colour.
func relativeLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	if len(hex) != 7 || hex[0] != '#' {
		t.Fatalf("not an #rrggbb colour: %q", hex)
	}
	var channel [3]float64
	for i := range channel {
		v, err := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		if err != nil {
			t.Fatalf("not an #rrggbb colour: %q", hex)
		}
		c := float64(v) / 255
		if c <= 0.03928 {
			channel[i] = c / 12.92
		} else {
			channel[i] = math.Pow((c+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*channel[0] + 0.7152*channel[1] + 0.0722*channel[2]
}

func contrastRatio(t *testing.T, a, b string) float64 {
	t.Helper()
	la, lb := relativeLuminance(t, a), relativeLuminance(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// The documentation theme's primary colour carries the header and navigation
// text, and, on the light page, every ordinary link. WCAG 2 asks 4.5:1 for such
// text; the light blue the site used gave white text 2.71:1 (audit F126). Every
// palette entry of mkdocs.yml must give its text, and a link on the light
// page, at least that, and the logo and favicon settings stay.
func TestDocsPaletteGivesTextAtLeastFourPointFiveToOne(t *testing.T) {
	data, err := os.ReadFile(repoFile("mkdocs.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Theme struct {
			Logo    string `yaml:"logo"`
			Favicon string `yaml:"favicon"`
			Palette []struct {
				Scheme  string `yaml:"scheme"`
				Primary string `yaml:"primary"`
			} `yaml:"palette"`
		} `yaml:"theme"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Theme.Palette) == 0 {
		t.Fatal("mkdocs.yml has no theme.palette")
	}
	for _, entry := range config.Theme.Palette {
		name := strings.ToLower(strings.TrimSpace(entry.Primary))
		if name == "custom" {
			checkCustomPalette(t, entry.Scheme)
			continue
		}
		pair, known := materialPrimaries[name]
		if !known {
			t.Errorf("palette %q uses primary %q, whose colours this test does not know: add them from the theme's palette stylesheet", entry.Scheme, entry.Primary)
			continue
		}
		if ratio := contrastRatio(t, pair[0], pair[1]); ratio < 4.5 {
			t.Errorf("palette %q: header text %s on primary %q (%s) is %.2f:1, below 4.5:1", entry.Scheme, pair[1], entry.Primary, pair[0], ratio)
		}
		if entry.Scheme == "default" {
			if ratio := contrastRatio(t, pair[0], "#ffffff"); ratio < 4.5 {
				t.Errorf("palette %q: a link in primary %q (%s) on the white page is %.2f:1, below 4.5:1", entry.Scheme, entry.Primary, pair[0], ratio)
			}
		}
	}
	if config.Theme.Logo != "assets/icon.png" || config.Theme.Favicon != "assets/icon.png" {
		t.Errorf("logo %q and favicon %q, want both assets/icon.png", config.Theme.Logo, config.Theme.Favicon)
	}
}

// customPaletteCSS is the stylesheet that defines a "custom" primary: the
// theme then takes the header colours and the link colour from CSS variables.
const customPaletteCSS = "docs/stylesheets/extra.css"

// cssVariables reads the custom properties of one selector's block, in order.
func cssVariables(css, selector string) map[string]string {
	vars := map[string]string{}
	for rest := css; ; {
		at := strings.Index(rest, selector)
		if at < 0 {
			return vars
		}
		rest = rest[at+len(selector):]
		open, end := strings.Index(rest, "{"), strings.Index(rest, "}")
		if open < 0 || end < open || strings.TrimSpace(rest[:open]) != "" {
			continue
		}
		for _, decl := range strings.Split(rest[open+1:end], ";") {
			name, value, ok := strings.Cut(decl, ":")
			if name = strings.TrimSpace(name); ok && strings.HasPrefix(name, "--") {
				vars[name] = strings.TrimSpace(value)
			}
		}
	}
}

// checkCustomPalette applies the same 4.5:1 rule to a "custom" primary: the
// header text on the header, and a link on the page (white for the light
// scheme, the page background for the dark one).
func checkCustomPalette(t *testing.T, scheme string) {
	t.Helper()
	data, err := os.ReadFile(repoFile(customPaletteCSS))
	if err != nil {
		t.Fatalf("palette %q uses primary \"custom\", which needs %s: %v", scheme, customPaletteCSS, err)
	}
	css := string(data)
	root := cssVariables(css, ":root")
	own := cssVariables(css, `[data-md-color-scheme="`+scheme+`"]`)
	resolve := func(name string) string {
		value, seen := own[name], 0
		if value == "" {
			value = root[name]
		}
		for strings.HasPrefix(value, "var(") && seen < 8 {
			inner := strings.TrimSuffix(strings.TrimPrefix(value, "var("), ")")
			if v := own[inner]; v != "" {
				value = v
			} else {
				value = root[inner]
			}
			seen++
		}
		return value
	}
	header, text, link := resolve("--md-primary-fg-color"), resolve("--md-primary-bg-color"), resolve("--md-typeset-a-color")
	page := "#ffffff"
	if scheme != "default" {
		page = resolve("--md-default-bg-color")
	}
	for _, c := range []struct{ what, value string }{{"--md-primary-fg-color", header}, {"--md-primary-bg-color", text}, {"--md-typeset-a-color", link}, {"the page background", page}} {
		if len(c.value) != 7 || c.value[0] != '#' {
			t.Fatalf("palette %q: %s in %s is %q, want an #rrggbb colour", scheme, c.what, customPaletteCSS, c.value)
		}
	}
	if ratio := contrastRatio(t, header, text); ratio < 4.5 {
		t.Errorf("palette %q: header text %s on %s is %.2f:1, below 4.5:1", scheme, text, header, ratio)
	}
	if ratio := contrastRatio(t, link, page); ratio < 4.5 {
		t.Errorf("palette %q: a link %s on the page %s is %.2f:1, below 4.5:1", scheme, link, page, ratio)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// without is a LookPath that finds every program but the ones named.
func without(names ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		for _, missing := range names {
			if name == missing {
				return "", errors.New("not found")
			}
		}
		return "/usr/bin/" + name, nil
	}
}

func toolsLayer(t *testing.T, s Settings, lookPath func(string) (string, error)) Layer {
	t.Helper()
	p, _ := probes()
	p.LookPath = lookPath
	report := RunThrough(context.Background(), s, p, LayerTools)
	if len(report.Layers) != 1 || report.Layers[0].Name != LayerTools {
		t.Fatalf("report = %+v", report)
	}
	return report.Layers[0]
}

// nft contains the sandbox probe address and ip puts it on the bridge: a node
// without either fails the tools layer, with the package that provides it.
func TestToolsLayerNeedsNftAndIP(t *testing.T) {
	for _, tc := range []struct {
		missing string
		pkg     string
	}{{"nft", "nftables"}, {"ip", "iproute2"}} {
		layer := toolsLayer(t, Settings{}, without(tc.missing))
		if layer.Status != StatusFailed || layer.Code != CodeToolsMissing {
			t.Fatalf("a node without %s: %+v", tc.missing, layer)
		}
		if len(layer.Missing) != 1 || layer.Missing[0].Name != tc.missing || layer.Missing[0].Package != tc.pkg {
			t.Errorf("missing = %+v, want %s from %s", layer.Missing, tc.missing, tc.pkg)
		}
		if !strings.Contains(layer.Detail, tc.missing) {
			t.Errorf("detail does not name %s: %s", tc.missing, layer.Detail)
		}
	}
	// Every missing tool is named at once, not one per run.
	layer := toolsLayer(t, Settings{}, without("nft", "guestfish", "ip"))
	if len(layer.Missing) != 3 {
		t.Errorf("missing = %+v, want three", layer.Missing)
	}
}

func TestToolsLayerPassingNamesWhatItFound(t *testing.T) {
	layer := toolsLayer(t, Settings{}, without())
	if layer.Status != StatusPassed {
		t.Fatalf("layer = %+v", layer)
	}
	for _, want := range []string{"qemu-img", "proxmox-backup-client", "guestfish", "ip", "nft"} {
		if !strings.Contains(layer.Detail, want) {
			t.Errorf("the pass does not name %s: %s", want, layer.Detail)
		}
	}
}

// A plan with no wire probe never puts an address on the sandbox bridge, so nft
// is not required for it, as doctor does not require it; the other tools still
// are.
func TestToolsLayerSkipsNftForAPlanWithoutWireProbes(t *testing.T) {
	s := Settings{NoWireProbes: true}
	layer := toolsLayer(t, s, without("nft"))
	if layer.Status != StatusPassed {
		t.Fatalf("nft was required for a plan without wire probes: %+v", layer)
	}
	if !strings.Contains(layer.Detail, "nft") || !strings.Contains(layer.Detail, "no wire probe") {
		t.Errorf("the pass does not say nft was not needed: %s", layer.Detail)
	}
	for _, missing := range []string{"ip", "qemu-img", "guestfish", "proxmox-backup-client"} {
		if layer := toolsLayer(t, s, without(missing)); layer.Status != StatusFailed {
			t.Errorf("a plan without wire probes passed without %s", missing)
		}
	}
	// With nft there, nothing is said about it being optional.
	layer = toolsLayer(t, s, without())
	if strings.Contains(layer.Detail, "no wire probe") {
		t.Errorf("nft is there, but the pass says it was not needed: %s", layer.Detail)
	}
}

// The tools layer verifies every program the node preflight (certistack doctor)
// requires. This reads the preflight's source for them, as the documentation
// contract tests do, so a tool added there without being added here fails.
func TestToolsLayerCoversWhatThePreflightRequires(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "preflight", "preflight_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tool := range Tools {
		have[tool.Name] = true
	}
	quoted := regexp.MustCompile(`"([a-z][a-z0-9-]+)"`)
	var found []string
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "exec.LookPath(") && !strings.Contains(line, "range []string{") {
			continue
		}
		for _, m := range quoted.FindAllStringSubmatch(line, -1) {
			found = append(found, m[1])
			if !have[m[1]] {
				t.Errorf("the node preflight requires %s, which the tools layer of certistack check does not verify", m[1])
			}
		}
	}
	if len(found) < 4 {
		t.Fatalf("read only %v from the preflight; the pattern this test reads has changed", found)
	}
}

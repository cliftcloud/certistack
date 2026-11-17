// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package qga

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Characters that can hide or reorder text, spelled by code point so the test
// source holds none of them literally.
var (
	rlo  = string(rune(0x202e)) // right-to-left override
	lre  = string(rune(0x202a)) // left-to-right embedding
	pdf  = string(rune(0x202c))
	rle  = string(rune(0x202b))
	lro  = string(rune(0x202d))
	lri  = string(rune(0x2066)) // left-to-right isolate
	rli  = string(rune(0x2067))
	fsi  = string(rune(0x2068))
	pdi  = string(rune(0x2069))
	lrm  = string(rune(0x200e)) // left-to-right mark
	rlm  = string(rune(0x200f))
	alm  = string(rune(0x061c)) // Arabic letter mark
	zwsp = string(rune(0x200b)) // zero width space
	zwnj = string(rune(0x200c))
	zwj  = string(rune(0x200d))
	wj   = string(rune(0x2060)) // word joiner
	bom  = string(rune(0xfeff)) // byte order mark
	lsep = string(rune(0x2028)) // line separator
	psep = string(rune(0x2029)) // paragraph separator
	nel  = string(rune(0x0085)) // C1 next line
	csi  = string(rune(0x009b)) // C1 control sequence introducer
)

// cannedAgent answers guest-sync with its id and every other command from
// replies (an unknown command is an agent error).
func cannedAgent(t *testing.T, replies map[string]any) string {
	t.Helper()
	return qgaTestSocket(t, func(reader *bufio.Reader, encoder *json.Encoder) {
		for {
			request, err := readRawQGARequest(reader)
			if err != nil {
				return
			}
			command, _ := request["execute"].(string)
			var reply any
			if command == "guest-sync" {
				arguments, _ := request["arguments"].(map[string]any)
				reply = map[string]any{"return": arguments["id"]}
			} else if canned, ok := replies[command]; ok {
				reply = canned
			} else {
				reply = map[string]any{"error": map[string]any{"class": "CommandNotFound", "desc": "unexpected command " + command}}
			}
			if err := encoder.Encode(reply); err != nil {
				return
			}
		}
	})
}

// noHazards fails the test if text still holds a character that can hide or
// reorder what a reader sees, or is not valid UTF-8.
func noHazards(t *testing.T, what, text string) {
	t.Helper()
	if !utf8.ValidString(text) {
		t.Errorf("%s is not valid UTF-8", what)
	}
	for _, hazard := range []string{"\x1b", "\x00", csi, nel, rlo, lre, lri, pdi, lrm, rlm, alm, zwsp, bom, lsep, psep} {
		if strings.Contains(text, hazard) {
			t.Errorf("%s holds %U", what, []rune(hazard)[0])
		}
	}
}

// A guest can answer guest-get-host-name with a 2 MiB name that starts with a
// terminal escape sequence and carries a right-to-left override. The probe
// may pass (no expected_output), but the name that goes into the signed
// Detail and the terminal is bounded and cleaned.
func TestQGAHostNameProbeBoundsAndCleansWhatTheGuestSays(t *testing.T) {
	hostile := "\x1b[2J" + rlo + strings.Repeat("A", 2<<20)
	for _, tc := range []struct {
		name, command, expected string
		required                bool
	}{
		{"hostname, nothing expected", "hostname", "", true},
		{"hostname, expected text inside it", "hostname", "AAAA", true},
		{"guest-get-host-name", "guest-get-host-name", "", true},
		{"optional probe", "hostname", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := cannedAgent(t, map[string]any{"guest-get-host-name": map[string]any{"return": map[string]any{"host-name": hostile}}})
			res := NewQGAProber(socket, tc.command, tc.expected, tc.required, 5*time.Second, "hostname").Probe(context.Background())
			if res.Passed {
				t.Fatalf("a 2 MiB host name with an escape sequence passed: %d bytes of detail", len(res.Detail))
			}
			if len(res.Error)+len(res.Detail) > 1024 {
				t.Fatalf("the signed result holds %d bytes of the guest's text, want it bounded", len(res.Error)+len(res.Detail))
			}
			noHazards(t, "error", res.Error)
			noHazards(t, "detail", res.Detail)
			if !strings.Contains(res.Error, "not a host name") {
				t.Fatalf("error = %q, want it to say the answer is not a host name", res.Error)
			}
		})
	}
}

func TestQGAHostNameRejectsWhatNoHostNameIs(t *testing.T) {
	for name, hostName := range map[string]string{
		"escape sequence":            "web\x1b[31m01",
		"right-to-left override":     "web" + rlo + "10",
		"bidirectional isolate":      "web" + lri + "01",
		"zero width space":           "web" + zwsp + "01",
		"byte order mark":            bom + "web01",
		"line separator":             "web" + lsep + "01",
		"newline in the middle":      "web\n01",
		"tab in the middle":          "web\t01",
		"NUL":                        "web\x0001",
		"invalid UTF-8":              "web\xff\xfe01",
		"256 bytes":                  strings.Repeat("a", maxHostNameBytes+1),
		"a 2 MiB name":               strings.Repeat("a", 2<<20),
		"C1 control (CSI)":           "web" + csi + "01",
		"only the escape and spaces": " \x1b ",
	} {
		t.Run(name, func(t *testing.T) {
			socket := cannedAgent(t, map[string]any{"guest-get-host-name": map[string]any{"return": map[string]any{"host-name": hostName}}})
			client, err := DialContext(context.Background(), socket, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			got, err := client.GetHostNameContext(context.Background())
			if !errors.Is(err, ErrInvalidHostName) || got != "" {
				t.Fatalf("host name %q = %q, %v; want ErrInvalidHostName", name, got, err)
			}
			if len(err.Error()) > 1024 {
				t.Errorf("the error holds %d bytes of the guest's text", len(err.Error()))
			}
			noHazards(t, "error", err.Error())
		})
	}
}

// What a host name can be still passes, exactly as the guest wrote it.
func TestQGAHostNameKeepsRealHostNames(t *testing.T) {
	for _, hostName := range []string{
		"cs-web01",
		"WEB-01.Corp.Example.COM",
		"m" + string(rune(0xfc)) + "nchen-01",
		"db_01",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61),
		strings.Repeat("h", maxHostNameBytes),
	} {
		socket := cannedAgent(t, map[string]any{"guest-get-host-name": map[string]any{"return": map[string]any{"host-name": "  " + hostName + "\n"}}})
		client, err := DialContext(context.Background(), socket, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		got, err := client.GetHostNameContext(context.Background())
		client.Close()
		if err != nil || got != hostName {
			t.Errorf("host name %q = %q, %v", hostName, got, err)
		}
	}
}

// The probe matches the host name case-sensitively, as documented: Windows
// reports the NetBIOS name in upper case.
func TestQGAHostNameProbeMatchesCaseSensitively(t *testing.T) {
	agent := func() string {
		return cannedAgent(t, map[string]any{"guest-get-host-name": map[string]any{"return": map[string]any{"host-name": "WEB01"}}})
	}
	if res := NewQGAProber(agent(), "hostname", "WEB", true, 2*time.Second, "upper").Probe(context.Background()); !res.Passed {
		t.Fatalf("a matching case failed: %+v", res)
	}
	if res := NewQGAProber(agent(), "hostname", "web", true, 2*time.Second, "lower").Probe(context.Background()); res.Passed || !strings.Contains(res.Error, "hostname mismatch") {
		t.Fatalf("another case passed or failed oddly: %+v", res)
	}
}

// An agent error carries the agent's text, which a guest chooses.
func TestQGAAgentErrorTextIsBoundedAndCleaned(t *testing.T) {
	hostile := "\x1b[2J" + rlo + strings.Repeat("E", 3<<20)
	socket := cannedAgent(t, map[string]any{"guest-ping": map[string]any{"error": map[string]any{"class": "GenericError", "desc": hostile}}})
	res := NewQGAProber(socket, "ping", "", true, 5*time.Second, "ping").Probe(context.Background())
	if res.Passed {
		t.Fatalf("a failing ping passed: %+v", res)
	}
	if len(res.Error) > maxReportOutputBytes+256 {
		t.Fatalf("the agent's 3 MiB error text became a %d byte probe error", len(res.Error))
	}
	noHazards(t, "error", res.Error)
	if !strings.Contains(res.Error, "QGA guest-ping failed") || !strings.Contains(res.Error, "(truncated)") {
		t.Fatalf("error = %.120q, want the failure named and the text marked as cut", res.Error)
	}
}

// The agent's interface inventory is printed and signed by the live network
// diagnostic: names and addresses are cleaned where they are read.
func TestQGANetworkInterfacesAreCleanedWhereTheyAreRead(t *testing.T) {
	socket := cannedAgent(t, map[string]any{"guest-network-get-interfaces": map[string]any{"return": []any{
		map[string]any{
			"name":             "eth0\x1b[31m" + rlo + strings.Repeat("N", 10<<10),
			"hardware-address": "aa:bb:cc:dd:ee:ff" + zwsp,
			"ip-addresses":     []any{map[string]any{"ip-address": "10.70.0.15\x1b[0m", "ip-address-type": "ipv4", "prefix": 24}},
		},
	}}})
	client, err := DialContext(context.Background(), socket, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	interfaces, err := client.GetNetworkInterfacesContext(context.Background(), 2*time.Second)
	if err != nil || len(interfaces) != 1 {
		t.Fatalf("interfaces = %+v, %v", interfaces, err)
	}
	iface := interfaces[0]
	noHazards(t, "name", iface.Name)
	if len(iface.Name) > maxReportOutputBytes+32 {
		t.Errorf("the interface name is %d bytes", len(iface.Name))
	}
	if iface.HardwareAddress != "aa:bb:cc:dd:ee:ff" || iface.IPAddresses[0].IPAddress != "10.70.0.15[0m" {
		t.Errorf("hardware address %q, address %q: want the hazardous characters gone and the rest kept", iface.HardwareAddress, iface.IPAddresses[0].IPAddress)
	}
}

// The in-guest network probe prints the guest's stderr in its error.
func TestQGANetworkProberBoundsAndCleansStderr(t *testing.T) {
	stderr := base64.StdEncoding.EncodeToString([]byte("\x1b[2J" + rlo + strings.Repeat("S", 512<<10)))
	socket := cannedAgent(t, map[string]any{
		"guest-exec":        map[string]any{"return": map[string]any{"pid": 5}},
		"guest-exec-status": map[string]any{"return": map[string]any{"exited": true, "exitcode": 1, "err-data": stderr}},
	})
	res := NewTCPNetworkProber(socket, "10.70.0.20", 22, 3*time.Second, "tcp").Probe(context.Background())
	if res.Passed {
		t.Fatalf("a failing command passed: %+v", res)
	}
	if len(res.Error) > maxReportOutputBytes+256 {
		t.Fatalf("a 512 KiB stderr became a %d byte probe error", len(res.Error))
	}
	noHazards(t, "error", res.Error)
}

func TestCleanGuestTextDropsWhatCanHideOrReorderText(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"plain text kept":               {"eth0 aa:bb:cc 10.0.0.1/24", "eth0 aa:bb:cc 10.0.0.1/24"},
		"newline and tab kept":          {"a\tb\nc", "a\tb\nc"},
		"carriage return dropped":       {"a\r\nb", "a\nb"},
		"escape dropped":                {"ok\x1b[31mred", "ok[31mred"},
		"C1 controls dropped":           {"a" + nel + "b" + csi + "c", "abc"},
		"DEL dropped":                   {"a\x7fb", "ab"},
		"bidi embeddings and overrides": {"a" + lre + rle + pdf + lro + rlo + "b", "ab"},
		"bidi isolates":                 {"a" + lri + rli + fsi + pdi + "b", "ab"},
		"directional marks":             {"a" + lrm + rlm + alm + "b", "ab"},
		"zero width and joiners":        {"a" + zwsp + zwnj + zwj + wj + bom + "b", "ab"},
		"line and paragraph separators": {"a" + lsep + "b" + psep + "c", "abc"},
		"invalid UTF-8 replaced":        {"a\xffb", "a" + string(rune(0xfffd)) + "b"},
		"non-ASCII text kept":           {"caf" + string(rune(0xe9)) + " " + string(rune(0x4e16)) + string(rune(0x754c)), "caf" + string(rune(0xe9)) + " " + string(rune(0x4e16)) + string(rune(0x754c))},
	} {
		if got := CleanGuestText(tc.in); got != tc.want {
			t.Errorf("%s: CleanGuestText(%q) = %q, want %q", name, tc.in, got, tc.want)
		}
	}
}

func TestSanitizeGuestTextCutsAtACharacterBoundary(t *testing.T) {
	// A two-byte character straddling the limit must not be cut in half: the
	// cut text would be invalid UTF-8 in a signed JSON report.
	e := string(rune(0xe9))
	for _, prefix := range []int{maxReportOutputBytes - 2, maxReportOutputBytes - 1, maxReportOutputBytes} {
		in := strings.Repeat("a", prefix) + strings.Repeat(e, 100)
		got := SanitizeGuestText(in)
		if !utf8.ValidString(got) {
			t.Errorf("prefix %d: the cut text is not valid UTF-8", prefix)
		}
		if len(got) > maxReportOutputBytes+len("...(truncated)") || !strings.HasSuffix(got, "...(truncated)") {
			t.Errorf("prefix %d: length %d, suffix %q", prefix, len(got), got[len(got)-14:])
		}
	}
	if got := SanitizeGuestText(strings.Repeat("a", maxReportOutputBytes)); strings.Contains(got, "truncated") {
		t.Errorf("text exactly at the limit was marked as cut")
	}
}

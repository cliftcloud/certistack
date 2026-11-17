// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package httptarget

import (
	"strings"
	"testing"
)

// Unusual but valid targets reach the server as written, and so do the
// ordinary ones; what would be altered or lost is refused with the reason.
func TestProblem(t *testing.T) {
	for _, tc := range []struct{ target, want string }{
		{"/", ""},
		{"/health", ""},
		{"/health?check=database&mode=deep", ""},
		{"/tenant/a%2Fb/health", ""},
		{"/health%3Fcheck=database", ""},
		{"/health%23database", ""},
		{"/health%252Fdatabase", ""},
		{"/a%7eb/%5Bx%5D?q=%20y&empty=", ""},
		{"/health?", ""},
		{"/a b", ""},
		{"/café", ""},
		{`/a"b`, ""},
		{"/health?q=café", ""},
		{"//double/slash", ""},
		{"health", `must start with "/"`},
		{"/health#database", "must not contain '#'"},
		{"/health%23#", "must not contain '#'"},
		{"/health?check=a b", "space in its query"},
		{"/a%2Fb c", `would be sent as "/a/b%20c"`},
		{"/café%2Fx", "percent-escapes and other characters"},
		{"/health%zz", "is not a valid request target"},
		{"/health%", "is not a valid request target"},
		{"/a\nb", "control character"},
		{"/a\x7fb", "control character"},
	} {
		got := Problem(tc.target)
		if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("Problem(%q) = %q, want %q", tc.target, got, tc.want)
		}
	}
}

func TestSentIsWhatTheServerReceives(t *testing.T) {
	for target, want := range map[string]string{
		"/health?check=database": "/health?check=database",
		"/tenant/a%2Fb/health":   "/tenant/a%2Fb/health",
		"/a b":                   "/a%20b",
		"/café":                  "/caf%C3%A9",
		"/health?q=café":         "/health?q=café",
	} {
		if got := Sent(target); got != want {
			t.Errorf("Sent(%q) = %q, want %q", target, got, want)
		}
	}
}

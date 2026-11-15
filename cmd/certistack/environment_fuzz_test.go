// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secretNames are the variables whose values are credentials.
var secretNames = []string{"PVE_TOKEN_SECRET", "PBS_PASSWORD", "PBS_ENCRYPTION_PASSWORD", "CERTISTACK_API_TOKEN"}

// FuzzControllerEnvironmentFile reads any file as the controller's environment
// file: it never panics, and a secret written in it (as a secret variable's
// value, quoted or not, with text around it, pasted on a line of its own, or
// under a typed variable's name) is never in the error or in a note it prints.
func FuzzControllerEnvironmentFile(f *testing.F) {
	f.Add("PVE_URL=https://pve1.example.com:8006\nPVE_TOKEN_ID=certistack@pve!automation\n", 0, "", "")
	f.Add("CERTISTACK_SSH_PORT=22\n", 1, "\"", "\" # comment")
	f.Add("export PVE_URL=x\n", 2, "'", "")
	f.Add("\xef\xbb\xbfPBS_REPOSITORY=a@pbs!b@host:8007:ds\r\n", 3, "", " #note")
	f.Add("", 4, "", "")
	f.Add("PVE_URL=https://h:8006\n", 5, "x", "y")
	f.Fuzz(func(t *testing.T, text string, where int, before, after string) {
		const secret = "Zq7SecretValueKx9"
		var line string
		switch uint(where) % 6 {
		case 0, 1, 2, 3:
			line = secretNames[uint(where)%4] + "=" + before + secret + after
		case 4:
			line = before + secret + after // pasted without a name
		default:
			line = "CERTISTACK_SSH_PORT=" + before + secret + after // under the wrong name
		}
		if strings.Contains(before+after, "\n") {
			return // the secret is then not one value
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "controller.env")
		if err := os.WriteFile(path, []byte(text+"\n"+line+"\n"+text), 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := loadControllerEnvironmentFile(path)
		if err != nil {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the error shows the secret: %v", err)
			}
			return
		}
		for _, note := range file.notes {
			if strings.Contains(note, secret) {
				t.Fatalf("a note shows the secret: %s", note)
			}
		}
	})
}

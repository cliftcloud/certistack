// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeEnvironmentFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.env")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A secret pasted into the file without its NAME= has its first part taken
// for a variable name, and the "unsupported variable" error quoted it back:
// into the terminal, a CI log, a ticket. Only something shaped like a
// variable name is quoted; the line number says where to look for the rest.
func TestEnvironmentFileDoesNotEchoAPastedSecret(t *testing.T) {
	for name, tc := range map[string]struct {
		line   string
		secret string // what must not appear in the error
	}{
		"a base64 secret, as the reporter pasted it": {"c2VjcmV0LXRva2VuLTEyMzQ1Ng==", "c2VjcmV0LXRva2VuLTEyMzQ1Ng"},
		"a secret of capitals and digits":            {"AKIAIOSFODNN7EXAMPLE=wJalrXUtnFEMI", "AKIAIOSFODNN7EXAMPLE"},
		"a long capital base64 value":                {"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789==", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789"},
		"a token with dots":                          {"eyJhbGciOiJIUzI1NiJ9.e30.abc123=", "eyJhbGciOiJIUzI1NiJ9"},
		"a pve token secret value alone":             {"3f2b6c1e-8a44-4b0e-9d1f-0c5a7e2d9b11=x", "3f2b6c1e-8a44-4b0e-9d1f-0c5a7e2d9b11"},
		"a lower-case name":                          {"pve_token_secret=hunter2", "pve_token_secret"},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeEnvironmentFile(t, []byte("# a comment\nPVE_URL=https://pve.example:8006\n"+tc.line+"\n"))
			for _, allowed := range []map[string]struct{}{controllerEnvironmentNames, workerEnvironmentNames} {
				_, err := parseEnvironmentFile(path, allowed, "controller")
				if err == nil {
					t.Fatal("a line that is not NAME=VALUE with a supported name was accepted")
				}
				if strings.Contains(err.Error(), tc.secret) || strings.Contains(err.Error(), tc.line) {
					t.Fatalf("the error quotes the pasted text: %v", err)
				}
				if !strings.Contains(err.Error(), "line 3") {
					t.Errorf("the error does not say which line: %v", err)
				}
			}
		})
	}

	// A mistyped name is what the error is for, and is still quoted, with
	// its line.
	path := writeEnvironmentFile(t, []byte("PVE_URL=https://pve.example:8006\nPVE_TOKEN_SECERT=x\n"))
	_, err := parseEnvironmentFile(path, controllerEnvironmentNames, "controller")
	if err == nil || !strings.Contains(err.Error(), `unsupported controller environment variable "PVE_TOKEN_SECERT" on line 2`) {
		t.Errorf("a mistyped name: %v", err)
	}
	// A name of the right shape that the file does not allow is quoted too.
	path = writeEnvironmentFile(t, []byte("CERTISTACK_NOT_A_SETTING=1\n"))
	if _, err := parseEnvironmentFile(path, workerEnvironmentNames, "node worker"); err == nil || !strings.Contains(err.Error(), `"CERTISTACK_NOT_A_SETTING" on line 1`) {
		t.Errorf("an unsupported name: %v", err)
	}
}

// A file saved by a Windows editor can start with a byte order mark; the
// refusal named a variable made of an invisible character, and the plan, key
// and keyring loaders already accept the mark. UTF-16, which PowerShell's
// redirection writes, is told apart and refused in words.
func TestEnvironmentFileAcceptsAByteOrderMark(t *testing.T) {
	bom := string([]byte{0xef, 0xbb, 0xbf}) // U+FEFF as UTF-8
	for name, content := range map[string]string{
		"a BOM, then a variable":           bom + "PVE_URL=https://pve.example:8006\n",
		"a BOM, then a comment":            bom + "# written on Windows\nPVE_URL=https://pve.example:8006\n",
		"a BOM, CRLF line ends":            bom + "PVE_URL=https://pve.example:8006\r\nPBS_REPOSITORY=backup@pbs!t@pbs.example:store\r\n",
		"no BOM":                           "PVE_URL=https://pve.example:8006\n",
		"a BOM and a quoted first value":   bom + "PVE_URL=\"https://pve.example:8006\"\n",
		"a BOM on a file of comments only": bom + "# nothing set\n",
	} {
		t.Run(name, func(t *testing.T) {
			values, err := parseEnvironmentFile(writeEnvironmentFile(t, []byte(content)), controllerEnvironmentNames, "controller")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(content, "PVE_URL") && values["PVE_URL"] != "https://pve.example:8006" {
				t.Errorf("PVE_URL = %q", values["PVE_URL"])
			}
			if strings.HasPrefix(content, bom) && strings.Contains(content, "PBS_REPOSITORY") && values["PBS_REPOSITORY"] != "backup@pbs!t@pbs.example:store" {
				t.Errorf("PBS_REPOSITORY = %q", values["PBS_REPOSITORY"])
			}
		})
	}
	// A mark that is not at the start of the file is no mark.
	if _, err := parseEnvironmentFile(writeEnvironmentFile(t, []byte("PVE_URL=https://pve.example:8006\n"+bom+"PBS_PASSWORD=x\n")), controllerEnvironmentNames, "controller"); err == nil {
		t.Error("a byte order mark in the middle of the file was ignored")
	}

	for name, content := range map[string][]byte{
		"UTF-16 little endian": append([]byte{0xff, 0xfe}, utf16le("PVE_URL=https://pve.example:8006\r\n")...),
		"UTF-16 big endian":    append([]byte{0xfe, 0xff}, utf16be("PVE_URL=https://pve.example:8006\r\n")...),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseEnvironmentFile(writeEnvironmentFile(t, content), controllerEnvironmentNames, "controller")
			if err == nil || !strings.Contains(err.Error(), "UTF-16") || !strings.Contains(err.Error(), "save it as UTF-8") {
				t.Fatalf("a UTF-16 file: %v", err)
			}
			if strings.Contains(err.Error(), "\x00") || strings.Contains(err.Error(), "PVE_URL") {
				t.Errorf("the error quotes the file: %q", err)
			}
		})
	}

	// The loader that sets the environment takes it the same way.
	if runtime.GOOS != "windows" {
		t.Setenv("PVE_URL", "")
		path := writeEnvironmentFile(t, []byte(bom+"PVE_URL=https://pve.example:8006\n"))
		if err := applyTestControllerEnvironment(t, path); err != nil {
			t.Fatal(err)
		}
		if got := os.Getenv("PVE_URL"); got != "https://pve.example:8006" {
			t.Errorf("PVE_URL = %q", got)
		}
	}
}

func utf16le(text string) []byte {
	var out []byte
	for _, r := range text {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func utf16be(text string) []byte {
	var out []byte
	for _, r := range text {
		out = append(out, byte(r>>8), byte(r))
	}
	return out
}

// `certistack version foo bar` printed the version and exited zero: its
// arguments were discarded, as they had been for doctor, plan, run and recover.
// A command that takes none refuses one.
func TestVersionRefusesArguments(t *testing.T) {
	var out strings.Builder
	if err := runRoot(t, &out, "version"); err != nil || !strings.Contains(out.String(), "certistack ") {
		t.Fatalf("version: %v, %q", err, out.String())
	}
	for _, args := range [][]string{{"version", "foo"}, {"version", "foo", "bar"}} {
		out.Reset()
		err := runRoot(t, &out, args...)
		if err == nil || !strings.Contains(err.Error(), `unknown command "foo"`) {
			t.Errorf("%v: err = %v", args, err)
		}
		if out.Len() != 0 {
			t.Errorf("%v printed the version anyway: %q", args, out.String())
		}
		if exitCodeForError(err) == 0 {
			t.Errorf("%v exits zero", args)
		}
	}
}

// A name that is not one of CertiStack's, PATH or HTTP_PROXY from a shell
// profile say, is refused as "not shaped like a variable name" without a word
// of what is wrong. It says the name is not a setting and where the settings
// are, and keeps refusing. A value pasted without its name is still never
// quoted.
func TestAnEnvironmentLineWithAnotherProgramsNameSaysItIsNotASetting(t *testing.T) {
	const rest = " is not a CertiStack setting; an environment file holds only the settings in docs/configuration.md (it is read literally, not as a shell script)"
	for line, name := range map[string]string{
		"PATH=/usr/local/bin:/usr/bin": "PATH",
		"HOME=/root":                   "HOME",
		"LANG=C.UTF-8":                 "LANG",
		"DEBUG=1":                      "DEBUG",
		"HTTP_PROXY=http://proxy:3128": "HTTP_PROXY",
		"LD_LIBRARY_PATH=/opt/lib":     "LD_LIBRARY_PATH",
		"export PATH=/usr/bin":         "PATH",
	} {
		path := writeEnvironmentFile(t, []byte("PVE_URL=https://pve.example:8006\n"+line+"\n"))
		for _, allowed := range []map[string]struct{}{controllerEnvironmentNames, workerEnvironmentNames} {
			_, err := parseEnvironmentFile(path, allowed, "controller")
			if err == nil {
				t.Errorf("%s: a name that is not a setting was accepted", line)
				continue
			}
			if !strings.Contains(err.Error(), name+rest) || !strings.Contains(err.Error(), "on line 2") {
				t.Errorf("%s: %v", line, err)
			}
			if strings.Contains(err.Error(), "/usr") || strings.Contains(err.Error(), "proxy") || strings.Contains(err.Error(), "not shaped like") {
				t.Errorf("%s: the message quotes the value or still says the name is not shaped like a variable name: %v", line, err)
			}
		}
	}
	// A line that is not a name at all, or a secret without its name, is still not quoted.
	for _, line := range []string{"c2VjcmV0LXRva2VuLTEyMzQ1Ng==", "AKIAIOSFODNN7EXAMPLE=wJalrXUtnFEMI", "path=/usr/bin", "my setting=1"} {
		path := writeEnvironmentFile(t, []byte("PVE_URL=https://pve.example:8006\n"+line+"\n"))
		_, err := parseEnvironmentFile(path, controllerEnvironmentNames, "controller")
		if err == nil || strings.Contains(err.Error(), "not a CertiStack setting") {
			t.Errorf("%s: %v", line, err)
		}
	}
}

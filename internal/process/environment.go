// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package process

import "os"

const fallbackPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

var minimalEnvironmentNames = []string{
	"PATH",
	"HOME",
	"LANG",
	"LC_ALL",
	"TMPDIR",
	"XDG_RUNTIME_DIR",
	"USER",
	"LOGNAME",
	"TERM",
}

var pbsEnvironmentNames = []string{
	"PBS_PASSWORD",
	"PBS_PASSWORD_FILE",
	"PBS_ENCRYPTION_PASSWORD",
	"PBS_ENCRYPTION_PASSWORD_FILE",
	"PBS_FINGERPRINT",
	"PBS_REPOSITORY",
	"PBS_NAMESPACE",
}

// MinimalEnvironment returns the small environment needed by node-local tools.
// Connection credentials are intentionally excluded.
func MinimalEnvironment() []string {
	env := make([]string, 0, len(minimalEnvironmentNames)+1)
	hasPath := false
	for _, name := range minimalEnvironmentNames {
		value, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		env = append(env, name+"="+value)
		if name == "PATH" {
			hasPath = true
		}
	}
	if !hasPath {
		env = append(env, "PATH="+fallbackPath)
	}
	return env
}

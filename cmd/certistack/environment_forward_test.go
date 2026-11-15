// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/controller"
)

// Follow-up: what the controller writes into the worker's runtime.env
// is always a file the worker's own parser accepts. A typed value the worker
// would refuse ("no", "yes" and "on" for PVE_TLS_INSECURE, which an earlier
// version read as false) is refused by the controller, naming the variable,
// instead of being staged on the node first.
func TestControllerNeverWritesAWorkerEnvironmentTheWorkerRefuses(t *testing.T) {
	base := map[string]string{
		"PVE_URL": "https://pve:8006", "PVE_TOKEN_ID": "a@pve!t", "PVE_TOKEN_SECRET": "x",
		"PBS_REPOSITORY": "a@pbs!t@pbs:8007:ds", "PBS_PASSWORD": "y", "CERTISTACK_PROGRESS_EVENTS": "1",
	}
	for _, name := range []string{"PVE_TLS_INSECURE", "CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB"} {
		for _, value := range []string{"true", "false", "1", "0", "TRUE"} {
			values := map[string]string{name: value}
			for k, v := range base {
				values[k] = v
			}
			data, err := controller.EncodeWorkerEnvironment(values)
			if err != nil {
				t.Fatalf("%s=%s refused by the controller: %v", name, value, err)
			}
			if _, err := parseEnvironmentFile(writeEnvFile(t, string(data)), workerEnvironmentNames, "node worker"); err != nil {
				t.Errorf("%s=%s: the controller wrote a file its worker refuses: %v", name, value, err)
			}
		}
		for _, value := range []string{"yes", "no", "on", "treu"} {
			values := map[string]string{name: value}
			for k, v := range base {
				values[k] = v
			}
			if _, err := controller.EncodeWorkerEnvironment(values); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("%s=%s was written for the worker, which refuses it: %v", name, value, err)
			}
		}
	}
}

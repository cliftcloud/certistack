// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"fmt"
	"os"

	"github.com/cliftcloud/certistack/internal/envtypes"
)

// forwardedTypedEnvironment are the typed variables the controller copies
// from its own environment into the worker's runtime.env.
var forwardedTypedEnvironment = []string{envtypes.InsecureTLS, envtypes.InsecureTLSLabOpt, envtypes.AllowTestMode}

// checkInheritedTypedEnvironment applies to the controller's inherited
// environment the rule the worker applies to its own file, before anything is
// staged on the node. A value the controller forwarded and the worker then
// refused ("PVE_TLS_INSECURE=no" from a service manager, which an earlier
// version read as false) failed only after a workspace was staged on the node.
// The error names the variable and what it accepts.
func checkInheritedTypedEnvironment() error {
	for _, name := range forwardedTypedEnvironment {
		if err := envtypes.Check(name, os.Getenv(name)); err != nil {
			return fmt.Errorf("controller environment variable %s: %w", name, err)
		}
	}
	return nil
}

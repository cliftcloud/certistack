// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"os"

	"github.com/cliftcloud/certistack/internal/envtypes"
)

// envPortOrDefault is the SSH port an inherited environment variable gives,
// the default when it is not set, and an error when it is set to something
// that is not a port: it used to fall back to the default without a word.
func envPortOrDefault(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	port, err := envtypes.ParsePort(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return port, nil
}

// envBoolDefault is the yes or no an inherited environment variable gives,
// the default when it is not set, and an error when it is set to something
// else.
func envBoolDefault(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := envtypes.ParseBoolean(value)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

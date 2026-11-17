// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"reflect"
	"testing"
)

func applyTestControllerEnvironment(t *testing.T, path string) error {
	t.Helper()
	restore, err := useCommandEnvironment(path, false)
	if err == nil {
		t.Cleanup(restore)
	}
	return err
}

func applyTestWorkerEnvironment(t *testing.T, path string) error {
	t.Helper()
	restore, err := useCommandEnvironment(path, true)
	if err == nil {
		t.Cleanup(restore)
	}
	return err
}

func TestEnvironmentLoadersLeaveTheProcessEnvironmentUnchanged(t *testing.T) {
	t.Setenv("PVE_URL", "https://inherited.example:8006")
	t.Setenv("PBS_PASSWORD", "inherited-synthetic-value")
	file := writeEnvFile(t, "PVE_URL=https://file.example:8006\n")
	before := os.Environ()
	for name, load := range map[string]func(string) (map[string]string, error){
		"controller": loadControllerEnvironment, "worker": loadWorkerEnvironment,
	} {
		values, err := load(file)
		if err != nil {
			t.Fatal(err)
		}
		if values["PVE_URL"] != "https://file.example:8006" || values["PBS_PASSWORD"] != "" {
			t.Fatalf("%s returned inherited values: %v", name, values)
		}
		if !reflect.DeepEqual(before, os.Environ()) {
			t.Fatalf("%s changed the process environment", name)
		}
	}
}

func TestCommandEnvironmentRestoresUnsetAndEmptyValues(t *testing.T) {
	t.Setenv("PVE_URL", "https://inherited.example:8006")
	t.Setenv("PBS_PASSWORD", "")
	t.Setenv("PBS_NAMESPACE", "")
	_ = os.Unsetenv("PBS_NAMESPACE")
	file := writeEnvFile(t, "PVE_URL=https://file.example:8006\nPBS_PASSWORD=synthetic\nPBS_NAMESPACE=changed\n")
	restore, err := useCommandEnvironment(file, false)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PVE_URL") != "https://file.example:8006" {
		t.Fatal("command values were not applied")
	}
	restore()
	if os.Getenv("PVE_URL") != "https://inherited.example:8006" {
		t.Fatal("inherited URL was lost")
	}
	if value, present := os.LookupEnv("PBS_PASSWORD"); !present || value != "" {
		t.Fatal("empty value was lost")
	}
	if _, present := os.LookupEnv("PBS_NAMESPACE"); present {
		t.Fatal("unset value was not restored")
	}
}

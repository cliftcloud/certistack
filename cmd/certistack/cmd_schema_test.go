// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// `schema` prints exactly the schema the config package builds (a golden file
// there holds it), as one JSON document, and nothing else.
func TestSchemaCommandPrintsThePlanSchema(t *testing.T) {
	stdout, stderr, err := runReportCommand(t, "schema")
	if err != nil || stderr != "" {
		t.Fatalf("err = %v, stderr = %q", err, stderr)
	}
	if stdout != string(config.PlanSchemaJSON()) {
		t.Error("the command's output is not the config package's schema")
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(stdout), &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema = %v", schema["$schema"])
	}
	golden, err := os.ReadFile(filepath.Join("..", "..", "pkg", "config", "testdata", "plan.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(golden), "\r\n", "\n") != stdout {
		t.Error("the command's output differs from pkg/config/testdata/plan.schema.json")
	}
}

func TestSchemaCommandTakesNoArgumentsAndHelpsAnEditorUser(t *testing.T) {
	if stdout, _, err := runReportCommand(t, "schema", "plan.yaml"); err == nil || stdout != "" || exitCodeForError(err) != exitCodeInfrastructure {
		t.Errorf("an argument was accepted: %v %q", err, stdout)
	}
	help, _, err := runReportCommand(t, "schema", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"certistack schema > certistack-plan.schema.json", "# yaml-language-server: $schema=./certistack-plan.schema.json", "does not\nreplace validate"} {
		if !strings.Contains(help, want) {
			t.Errorf("the help lacks %q:\n%s", want, help)
		}
	}
	// The failure to write the schema is a failure of the command.
	cmd := schemaCmd()
	cmd.SetOut(&fullDiskWriter{budget: 10})
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil || exitCodeForError(err) != exitCodeInfrastructure {
		t.Errorf("a full disk: %v", err)
	}
}

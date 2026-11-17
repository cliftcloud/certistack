// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// reportField resolves a dotted report path as the reports page writes it
// ("vm_records[].source_disks[]", "teardown_evidence.all_cleaned") through the
// JSON names of attest.Report, and reports whether every step exists.
func reportField(path string) bool {
	typ := reflect.TypeOf(attest.Report{})
	for _, step := range strings.Split(path, ".") {
		name := strings.TrimSuffix(step, "[]")
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			return false
		}
		found := false
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if tag, _, _ := strings.Cut(field.Tag.Get("json"), ","); tag == name {
				typ, found = field.Type, true
				break
			}
		}
		if !found {
			return false
		}
		if strings.HasSuffix(step, "[]") {
			if k := typ.Kind(); k != reflect.Slice && k != reflect.Array {
				return false
			}
		}
	}
	return true
}

// docs/reports.md names the report schema the code writes, and every field its
// "Main fields" table names is a field of the report the code writes, so a new
// schema version or a renamed field fails here until the page follows.
func TestReportsPageNamesTheSchemaAndTheFieldsTheCodeWrites(t *testing.T) {
	fields := section(t, readRepoText(t, "docs", "reports.md"), "Main fields")
	if want := "The report schema is `" + attest.CurrentReportSchemaVersion + "`."; !strings.Contains(fields, want) {
		t.Errorf("the Main fields section of docs/reports.md does not say %q", want)
	}
	row := regexp.MustCompile("(?m)^\\| (`[^|]+`) \\|")
	name := regexp.MustCompile("`([a-z_.\\[\\]]+)`")
	checked := 0
	for _, cell := range row.FindAllStringSubmatch(fields, -1) {
		for _, m := range name.FindAllStringSubmatch(cell[1], -1) {
			checked++
			if !reportField(m[1]) {
				t.Errorf("docs/reports.md lists the report field %s, which attest.Report does not have", m[1])
			}
		}
	}
	if checked < 15 {
		t.Fatalf("read only %d fields from the Main fields table; the layout this test reads has changed", checked)
	}
	// The resolver itself: a field that exists and one that does not.
	if !reportField("vm_records[].probe_results[]") || reportField("vm_records[].no_such_field") {
		t.Fatal("reportField does not resolve report paths")
	}
}

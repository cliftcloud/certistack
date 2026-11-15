// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The privileges a run checks are exactly the documented CertiStackRole's
// (terraform/main.tf, docs/manual-setup.md): the check can't ask
// for more than the docs grant, nor miss one they list.
func TestRunPrivilegesAreTheDocumentedRole(t *testing.T) {
	tf, err := os.ReadFile(filepath.Join("..", "..", "terraform", "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)privileges = \[(.*?)\]`).FindSubmatch(tf)
	if block == nil {
		t.Fatal("no privileges list in terraform/main.tf")
	}
	var documented []string
	for _, m := range regexp.MustCompile(`"([A-Za-z.]+)"`).FindAllSubmatch(block[1], -1) {
		documented = append(documented, string(m[1]))
	}
	seen := map[string]bool{}
	for _, req := range RunPrivileges("pve1", []int{9001}, "csSb01", "csVn01", true, "certistack-scratch") {
		for _, priv := range append(append([]string(nil), req.Required...), req.Advisory...) {
			seen[priv] = true
		}
	}
	var checked []string
	for priv := range seen {
		checked = append(checked, priv)
	}
	sort.Strings(documented)
	sort.Strings(checked)
	if strings.Join(checked, ",") != strings.Join(documented, ",") {
		t.Fatalf("checked privileges %v, documented role %v", checked, documented)
	}
}

// The under-privileged test token: every missing privilege is listed
// at once, the required ones apart from the advisory ones.
func TestMissingPrivilegesListsEveryGap(t *testing.T) {
	all := `"VM.Allocate":1,"VM.Audit":1,"VM.PowerMgmt":1,"VM.Console":1,"VM.Config.Disk":1,"VM.Config.CPU":1,"VM.Config.Memory":1,"VM.Config.Network":1,"VM.Config.Options":1,"VM.Config.HWType":1,"VM.Config.CDROM":1,"SDN.Allocate":1,"SDN.Audit":1,"SDN.Use":1,"Sys.Audit":1,"Datastore.AllocateSpace":1,"Datastore.Audit":1`
	under := strings.NewReplacer(`"SDN.Allocate":1,`, "", `"VM.Allocate":1,`, "", `"VM.Config.CDROM":1,`, "").Replace(all)
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		paths = append(paths, path)
		_, _ = w.Write([]byte(`{"data":{"` + path + `":{` + under + `}}}`))
	}))
	defer server.Close()
	client := NewClient(Config{BaseURL: server.URL})
	missing, err := client.MissingPrivileges(context.Background(), RunPrivileges("pve1", []int{9001}, "csSb01", "csVn01", true, "certistack-scratch"))
	if err != nil {
		t.Fatal(err)
	}
	required, advisory := DescribeMissingPrivileges(missing)
	for _, want := range []string{"SDN.Allocate on /sdn ", "SDN.Allocate on /sdn/zones ", "VM.Allocate on /vms/9001 "} {
		if !strings.Contains(required, want) {
			t.Errorf("required gaps lack %q: %s", want, required)
		}
	}
	if advisory != "VM.Config.CDROM on /vms/9001 (to create, configure, start and destroy the sandbox VM)" {
		t.Errorf("advisory gaps = %q", advisory)
	}
	if !strings.Contains(strings.Join(paths, " "), "/sdn/zones/csSb01/csVn01") || !strings.Contains(strings.Join(paths, " "), "/storage/certistack-scratch") {
		t.Errorf("paths checked: %v", paths)
	}

	// A pre-provisioned sandbox needs no SDN.Allocate.
	missing, err = client.MissingPrivileges(context.Background(), RunPrivileges("pve1", []int{9001}, "csSb01", "csVn01", false, ""))
	if err != nil {
		t.Fatal(err)
	}
	if required, _ := DescribeMissingPrivileges(missing); strings.Contains(required, "SDN.Allocate") {
		t.Errorf("pre-provisioned sandbox asked for SDN.Allocate: %s", required)
	}

	// It reads the zone from PVE's zone list, which needs SDN.Audit on the
	// zone, and that gap is named.
	noAudit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		privs := all
		if path == "/sdn/zones/csSb01" {
			privs = `"SDN.Use":1`
		}
		_, _ = w.Write([]byte(`{"data":{"` + path + `":{` + privs + `}}}`))
	}))
	defer noAudit.Close()
	missing, err = NewClient(Config{BaseURL: noAudit.URL}).MissingPrivileges(context.Background(), RunPrivileges("pve1", []int{9001}, "csSb01", "csVn01", false, ""))
	if err != nil {
		t.Fatal(err)
	}
	if required, _ := DescribeMissingPrivileges(missing); !strings.Contains(required, "SDN.Audit on /sdn/zones/csSb01 ") {
		t.Errorf("pre-provisioned zone without SDN.Audit: required gaps %q", required)
	}
}

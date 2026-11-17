// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/cliftcloud/certistack/pkg/config"
	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS (winnt.h), what SDDL "FA" grants.
const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1FF

func testUserSID(t *testing.T) *windows.SID {
	t.Helper()
	user, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	return user
}

// assertOwnerOnlyACL checks that path has a protected ACL, so nothing is
// inherited from its directory, with one entry: full control for the current
// account, which also owns the file.
func assertOwnerOnlyACL(t *testing.T, path string) {
	t.Helper()
	user := testUserSID(t)
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s: ACL is not protected from inheritance (%s)", path, sd)
	}
	owner, _, err := sd.Owner()
	if err != nil || !owner.Equals(user) {
		t.Errorf("%s: owner %v (err %v), want the current account %v", path, owner, err, user)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s: no ACL (err %v)", path, err)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("%s: %d ACL entries (%s), want exactly one", path, dacl.AceCount, sd)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !sid.Equals(user) || ace.Mask != fileAllAccess {
		t.Fatalf("%s: ACL %s, want only full control for %v", path, sd, user)
	}
}

func setACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// On Windows, where mode 0600 does not restrict access, a report is created
// with an explicit owner-only ACL instead of inheriting its directory's ACL, even
// in a directory that grants others access, and a forced overwrite keeps it.
func TestWindowsReportsGetOwnerOnlyACL(t *testing.T) {
	user := testUserSID(t)
	dir := t.TempDir()
	// A directory whose inheritable ACL lets every local user read new files.
	setACL(t, dir, "D:P(A;OICI;FA;;;"+user.String()+")(A;OICI;FR;;;BU)")

	report := BuildReport(&config.Plan{PlanID: "windows-acl"}, "node1", time.Second, true, nil, "")
	reportPath := filepath.Join(dir, "report.json")
	if err := report.Save(reportPath); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnlyACL(t, reportPath)

	replacement := BuildReport(&config.Plan{PlanID: "windows-acl"}, "node1", 2*time.Second, false, nil, "")
	if err := replacement.SaveWithForce(reportPath, true); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnlyACL(t, reportPath)
}

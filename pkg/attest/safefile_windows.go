// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows does not apply Unix permission bits: os.Chmod(0600) only clears
// the read-only attribute, and a new file inherits its directory's access
// control list. A report is therefore created with an explicit, protected ACL
// that grants only the current account.

// openInput opens path for reading. Unless follow is set it does not follow a
// symbolic link or other reparse point at the leaf; the caller's check of the
// opened file then refuses anything but a regular file.
func openInput(path string, follow bool) (*os.File, error) {
	if follow {
		return os.Open(path)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

// createExclusive creates path for writing, failing if any entry already
// exists there. An ownerOnly file is created with a protected ACL that grants
// only the current account, so the secret is never in a file that inherited
// wider access, not even between creation and a later ACL change.
func createExclusive(path string, perm os.FileMode, ownerOnly bool) (*os.File, error) {
	if !ownerOnly {
		return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	}
	user, err := currentUserSID()
	if err != nil {
		return nil, fmt.Errorf("create %s: identify the current account for its access list: %w", path, err)
	}
	sd, err := windows.SecurityDescriptorFromString(ownerOnlySDDL(user))
	if err != nil {
		return nil, fmt.Errorf("create %s: build its owner-only access list: %w", path, err)
	}
	attributes := &windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0,
		attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

// ownerOnlySDDL makes user the owner and the only account in a protected
// (not inherited) ACL, with full control.
func ownerOnlySDDL(user *windows.SID) string {
	return fmt.Sprintf("O:%sD:P(A;;FA;;;%s)", user, user)
}

func currentUserSID() (*windows.SID, error) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tokenUser.User.Sid.Copy()
}

// replaceFile atomically renames from over to, flushed before it returns.
func replaceFile(from, to string) error {
	return moveFile(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// renameNoReplace atomically renames from to to, failing if to exists.
func renameNoReplace(from, to string) error {
	return moveFile(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func moveFile(from, to string, flags uint32) error {
	fromName, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	toName, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	if err := windows.MoveFileEx(fromName, toName, flags); err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}

// syncDirectory has nothing to do on Windows: MOVEFILE_WRITE_THROUGH flushes
// the rename, and a directory handle cannot be flushed.
func syncDirectory(string) error {
	return nil
}

// linkUnsupported is not reached on Windows, which renames without replacing
// natively.
func linkUnsupported(error) bool {
	return false
}

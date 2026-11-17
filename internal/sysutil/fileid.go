// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"errors"
	"fmt"
	"os"

	"github.com/cliftcloud/certistack/internal/journal"
)

// ErrNotOurs marks a path that holds a file other than the one this run
// created there. Nothing that wraps it removed anything.
var ErrNotOurs = errors.New("the file at the path is not the one this run created")

// ErrPublishExists marks PublishNoReplace's refusal: something already exists
// at the destination, and it is left as it is.
var ErrPublishExists = errors.New("a file already exists at the destination")

// FileState is what a path holds compared with a recorded file identity.
type FileState int

const (
	// FileAbsent: nothing is at the path.
	FileAbsent FileState = iota
	// FileSame: the path holds the recorded file.
	FileSame
	// FileOther: the path holds something else (another file, a symlink, a
	// directory): not this run's.
	FileOther
)

// CheckFileIdentity says what path holds compared with want. The path itself
// is examined, never what a symlink at it points to.
func CheckFileIdentity(path string, want journal.FileIdentity) (FileState, error) {
	got, err := FileIdentityOf(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return FileAbsent, nil
	case errors.Is(err, errNotRegular):
		return FileOther, nil
	case err != nil:
		return FileAbsent, err
	}
	if got.Dev != want.Dev || got.Ino != want.Ino {
		return FileOther, nil
	}
	// The creation time, where both sides have one, tells the file from a
	// later one that reuses its inode number.
	if got.BtimeNS != 0 && want.BtimeNS != 0 && got.BtimeNS != want.BtimeNS {
		return FileOther, nil
	}
	return FileSame, nil
}

var errNotRegular = errors.New("not a regular file")

// RemoveIfSame unlinks path only while it still holds the file want names. A
// path that is already gone is removed. A path that holds anything else is left
// alone, and the error wraps ErrNotOurs. The check and the unlink are two
// steps: a file put at the path in the moments between them is not excluded.
func RemoveIfSame(path string, want journal.FileIdentity) error {
	state, err := CheckFileIdentity(path, want)
	if err != nil {
		return fmt.Errorf("inspect %s before removing it: %w", path, err)
	}
	switch state {
	case FileAbsent:
		return nil
	case FileOther:
		return fmt.Errorf("left %s in place: %w", path, ErrNotOurs)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

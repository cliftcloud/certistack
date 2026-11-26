// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// The most that is read from each kind of trust or evidence input. Each is far
// above what a valid file needs and far below what could exhaust memory, and
// it is enforced while reading: a larger or still-growing file is refused
// after at most one byte more than its limit was read.
const (
	// MaxPublicKeyFileBytes bounds a public key file (65 bytes as a hex line).
	MaxPublicKeyFileBytes = 4 << 10
	// MaxKeyringFileBytes bounds a keyring: thousands of signers, each under 300 bytes.
	MaxKeyringFileBytes = 1 << 20
	// A report is bounded by MaxReportFileBytes and the structure limits that
	// go with it, in reportscan.go.
)

// utf8BOM starts a file that a Windows editor saved as UTF-8 with a signature.
var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// fileStep runs at the named points between a check and the operation that
// relies on it; an error it returns fails that operation. It does nothing in
// the product. Tests replace it to change a directory entry at exactly that
// point, to fail a step, or to stop a write there as a crash would, without
// depending on timing.
var fileStep = func(step, path string) error { return nil }

// ReadRegularFile reads a keyring, a public key file or a report. what names
// the file in errors. The file must be a regular file of at most limit bytes:
// a named pipe, a device, a directory or a socket is refused without waiting
// on it, and a file larger than limit, or one that grows past it while being
// read, is refused after reading at most one byte more than limit. The file
// is opened once and every check is made on the opened file, so an entry that
// is replaced after it was inspected is refused, not read. A symbolic link to
// a regular file is followed, as these files are not secret and a link to a
// mounted secret store is a common way to supply them.
func ReadRegularFile(path, what string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s %s: %w", what, path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, notRegularFileError(what, path, info.Mode())
	}
	// On Windows, Stat records only the path and looks up the file's identity at
	// its first comparison: make Windows record this file's identity now.
	_ = os.SameFile(info, info)
	if err := fileStep("input-inspected", path); err != nil {
		return nil, err
	}

	f, err := openInput(path, true)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s %s: %w", what, path, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot read %s %s: %w", what, path, err)
	}
	if !opened.Mode().IsRegular() {
		return nil, notRegularFileError(what, path, opened.Mode())
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%s %s was replaced while it was being opened; nothing was read from it", what, path)
	}
	if opened.Size() > limit {
		return nil, fmt.Errorf("%s %s is larger than the %d bytes a %s can be", what, path, limit, what)
	}
	if err := fileStep("input-opened", path); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s %s: %w", what, path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s %s is larger than the %d bytes a %s can be", what, path, limit, what)
	}
	return data, nil
}

// notRegularFileError names what a path holds that is not a regular file.
func notRegularFileError(what, path string, mode os.FileMode) error {
	kind := "not a regular file"
	switch {
	case mode.IsDir():
		kind = "a directory"
	case mode&os.ModeNamedPipe != 0:
		kind = "a named pipe"
	case mode&os.ModeSocket != 0:
		kind = "a socket"
	case mode&os.ModeDevice != 0:
		kind = "a device"
	}
	return fmt.Errorf("%s %s is %s, not a regular file", what, path, kind)
}

// checkDestination refuses a path a write must not replace: a
// symbolic link, anything but a regular file, or an existing file without
// force. It reports whether a file exists there. Publication re-establishes
// the no-overwrite rule atomically, so this check only gives a clear error
// before anything is written.
func checkDestination(path, kind string, force bool) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect %s %s: %w", kind, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("refusing symbolic-link %s: %s", kind, path)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s path is not a regular file: %s", kind, path)
	}
	if !force {
		return true, fmt.Errorf("%s %s already exists; it is replaced only when forced", kind, path)
	}
	return true, nil
}

// stagingPath names the file a write is staged in before it is renamed into
// place. The name is fixed rather than random: a write interrupted by a crash
// leaves a file an operator can find beside its destination, and two writers
// of one destination collide instead of racing.
func stagingPath(path string) string {
	return path + ".new"
}

// stagedFile is a complete, synced replacement for path, written beside it
// under its staging name and not yet visible at path.
type stagedFile struct {
	path      string
	staging   string
	data      []byte
	perm      os.FileMode
	ownerOnly bool
	info      os.FileInfo
}

// stageFile writes data under path's staging name, created exclusively (so
// it never follows or reuses an existing entry) with perm, or on Windows an
// explicit owner-only ACL when ownerOnly is set, and syncs it to disk.
func stageFile(path string, data []byte, perm os.FileMode, ownerOnly bool) (*stagedFile, error) {
	staging := stagingPath(path)
	f, err := createExclusive(staging, perm, ownerOnly)
	if errors.Is(err, fs.ErrExist) {
		return nil, &stagingExistsError{staging: staging, path: path}
	}
	if err != nil {
		return nil, err
	}
	s := &stagedFile{path: path, staging: staging, data: data, perm: perm, ownerOnly: ownerOnly}
	if err := writeSynced(f, data, perm); err != nil {
		_ = f.Close()
		s.discard()
		return nil, fmt.Errorf("write %s: %w", staging, err)
	}
	if s.info, err = f.Stat(); err != nil {
		_ = f.Close()
		s.discard()
		return nil, fmt.Errorf("inspect %s: %w", staging, err)
	}
	if err := f.Close(); err != nil {
		s.discard()
		return nil, fmt.Errorf("close %s: %w", staging, err)
	}
	return s, nil
}

// stagingExistsError reports a staging file left by an earlier write, or held
// by one still running. It says nothing more than that: a report's staging file
// is just deleted.
type stagingExistsError struct{ staging, path string }

func (e *stagingExistsError) Error() string {
	return fmt.Sprintf("%s already exists: an earlier write of %s was interrupted, or another is still running. "+
		"If none is running, that file is the unfinished write: delete it and retry", e.staging, e.path)
}

// writeSynced sets a newly created file's exact mode (the umask may have
// narrowed it), writes data, and flushes it to stable storage.
func writeSynced(f *os.File, data []byte, perm os.FileMode) error {
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// discard removes the staged file after a failed write, unless it was
// published after all.
func (s *stagedFile) discard() {
	if !s.isPublished() {
		_ = os.Remove(s.staging)
	}
}

// publish makes the staged file visible at its destination with one atomic
// rename, replacing an existing file only when replace is set, then syncs the
// directory so the rename survives a crash. A rename replaces the directory
// entry itself: a symbolic link planted at the destination after it was
// checked is replaced, never written through. An error usually means nothing
// was published; if only the directory sync failed, the file is in place,
// which the caller tells apart with isPublished.
func (s *stagedFile) publish(replace bool) error {
	if err := fileStep("publishing", s.path); err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if replace {
		if err := replaceFile(s.staging, s.path); err != nil {
			return err
		}
		return syncDirectory(dir)
	}
	err := noReplaceRename(s.staging, s.path)
	if errors.Is(err, errNoAtomicNoReplace) {
		// This filesystem supports neither a no-replace rename nor hard links.
		// Create the destination exclusively and write it in place: it still
		// never overwrites a file, but a crash here can leave it partly
		// written. The staging file is a second copy of the content, which for
		// a private key must not stay behind, and its presence would refuse the
		// next write: it goes now, whatever publication left in its place.
		err = s.writeInPlace()
		if err == nil {
			_ = os.Remove(s.staging)
		}
	}
	if errors.Is(err, fs.ErrExist) {
		// Another writer published the same path after this one checked it:
		// the no-replace publication refused, as it must.
		return fmt.Errorf("%s already exists; it is replaced only when forced: %w", s.path, err)
	}
	if err != nil {
		return err
	}
	return syncDirectory(dir)
}

// writeInPlace is publish's fallback for filesystems without an atomic
// no-replace operation.
func (s *stagedFile) writeInPlace() error {
	f, err := createExclusive(s.path, s.perm, s.ownerOnly)
	if err != nil {
		return err
	}
	if err := writeSynced(f, s.data, s.perm); err != nil {
		_ = f.Close()
		_ = os.Remove(s.path)
		return err
	}
	if info, err := f.Stat(); err == nil {
		s.info = info
	}
	return f.Close()
}

// isPublished reports whether path still names the file this stage published.
func (s *stagedFile) isPublished() bool {
	info, err := os.Lstat(s.path)
	return err == nil && s.info != nil && os.SameFile(info, s.info)
}

// noReplaceRename is renameNoReplace; tests replace it to reach the fallback
// for filesystems without an atomic no-replace publication.
var noReplaceRename = renameNoReplace

// errNoAtomicNoReplace reports a filesystem without an atomic way to publish
// a file only if its destination does not exist.
var errNoAtomicNoReplace = errors.New("no atomic no-replace rename on this filesystem")

// linkNoReplace publishes from at to with a hard link, which fails if to
// exists, and then removes the staging name.
func linkNoReplace(from, to string) error {
	if err := os.Link(from, to); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return err
		}
		if linkUnsupported(err) {
			return errNoAtomicNoReplace
		}
		return err
	}
	// The destination is published; a staging name left behind by a failed
	// removal is a second link to the same file, which the next write names.
	_ = os.Remove(from)
	return nil
}

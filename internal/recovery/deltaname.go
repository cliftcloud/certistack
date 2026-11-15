// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"path/filepath"
	"regexp"
)

// deltaName is the form of the name of every disposable disk file a run makes
// (an overlay, a firmware copy, a local copy of a disk, and the staging file
// each is first written to): certistack-delta-... or certistack-copy-....
var deltaName = regexp.MustCompile(`^certistack-(delta|copy)-.`)

// DeltaRemovableByPath is whether recovery removes a journaled disk file that
// has no recorded identity by its path: only an absolute, clean path whose name
// is one a run gives its disk files. A path is not proof of anything, so a
// journal that names anything else (a corrupt or hand-edited one) has the file
// left in place.
func DeltaRemovableByPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && deltaName.MatchString(filepath.Base(path))
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A worker result that passed every check of the controller but could not be
// signed is kept the way a refused one is (out of the reach of anything that
// reads reports), under a first line that says what happened: not the refused
// result's banner, "failed the controller's checks", which would be wrong for
// a result the signer, not the checks, stopped.
func TestSaveUnsignedResultSaysTheResultPassedAndTheSigningFailed(t *testing.T) {
	dir := t.TempDir()
	path, err := SaveUnsignedResult(dir, "run-0123", "sign controller report: the signing service is down", []byte(`{"all_passed":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, RefusedResultSuffix) || filepath.Base(filepath.Dir(path)) != RefusedDirName {
		t.Errorf("kept at %s: it must sit where a refused result sits", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasPrefix(text, UnsignedResultBanner+"\n") {
		t.Errorf("the file starts with %.120q, want the banner %q", text, UnsignedResultBanner)
	}
	if strings.Contains(strings.SplitN(text, "\n", 2)[0], "failed the controller's checks") {
		t.Errorf("the banner says the result failed the controller's checks: %q", text)
	}
	if !strings.HasPrefix(UnsignedResultBanner, "REFUSED, NOT EVIDENCE") {
		t.Errorf("the banner %q must still open as a refused result does, for anything that looks for it", UnsignedResultBanner)
	}
	for _, want := range []string{"Reason: sign controller report: the signing service is down", RefusedRawMarker, `{"all_passed":true}`} {
		if !strings.Contains(text, want) {
			t.Errorf("the file lacks %q", want)
		}
	}
	// A refused result keeps its own banner.
	refused, err := SaveRefusedResult(dir, "run-0456", "the report names node x", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	refusedText, err := os.ReadFile(refused)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(refusedText), RefusedBanner+"\n") {
		t.Errorf("a refused result starts with %.120q", refusedText)
	}
}

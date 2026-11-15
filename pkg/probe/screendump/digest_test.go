// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package screendump

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe/qmp"
)

// qmpServer is a QMP monitor on a unix socket in a short temporary directory.
// Its screendump writes frame to the requested file and answers with an error
// when fail is set, after the file is written, as QEMU can when it runs out of
// space part way through.
func qmpServer(t *testing.T, frame []byte, fail bool) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cs-qmp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "qmp.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader, encoder := bufio.NewReader(conn), json.NewEncoder(conn)
				if err := encoder.Encode(map[string]any{"QMP": map[string]any{}}); err != nil {
					return
				}
				for {
					line, err := reader.ReadBytes('\n')
					if err != nil {
						return
					}
					var command map[string]any
					if err := json.Unmarshal(line, &command); err != nil {
						return
					}
					reply := map[string]any{"return": map[string]any{}, "id": command["id"]}
					if command["execute"] == "screendump" {
						arguments, _ := command["arguments"].(map[string]any)
						filename, _ := arguments["filename"].(string)
						if err := os.WriteFile(filename, frame, 0o600); err != nil {
							return
						}
						if fail {
							reply = map[string]any{"error": map[string]any{"class": "GenericError", "desc": "no space left"}, "id": command["id"]}
						}
					}
					if err := encoder.Encode(reply); err != nil {
						return
					}
				}
			}()
		}
	}()
	return path
}

func onePixel(value byte) []byte {
	return append([]byte("P6\n1 1\n255\n"), value, value, value)
}

func capture(t *testing.T, frame []byte, fail bool) (*Artifact, string, error) {
	t.Helper()
	client, err := qmp.Dial(qmpServer(t, frame, fail), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	scratch := t.TempDir()
	if err := os.Chmod(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := Capture(context.Background(), client, 9930, scratch)
	return artifact, scratch, err
}

// A capture carries the SHA-256 of the PNG it encoded (the bytes its
// Base64 field holds and its scratch copy holds), so two frames that differ
// only in their pixels are told apart, and the same frame gives the same
// digest.
func TestCaptureRecordsTheDigestOfTheImage(t *testing.T) {
	black, scratch, err := capture(t, onePixel(0), false)
	if err != nil {
		t.Fatal(err)
	}
	white, _, err := capture(t, onePixel(255), false)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := capture(t, onePixel(0), false)
	if err != nil {
		t.Fatal(err)
	}
	if black.SHA256 == white.SHA256 || black.SHA256 != again.SHA256 {
		t.Fatalf("digests: black %s, white %s, black again %s", black.SHA256, white.SHA256, again.SHA256)
	}
	png, err := base64.StdEncoding.DecodeString(black.Base64)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(png)
	if black.SHA256 != hex.EncodeToString(sum[:]) || black.PNGSize != len(png) {
		t.Fatalf("digest %s of %d bytes, want the SHA-256 of the %d-byte PNG", black.SHA256, black.PNGSize, len(png))
	}
	onDisk, err := os.ReadFile(black.PNGPath)
	if err != nil {
		t.Fatal(err)
	}
	if diskSum := sha256.Sum256(onDisk); hex.EncodeToString(diskSum[:]) != black.SHA256 {
		t.Fatal("the scratch PNG is not the image the digest names")
	}
	// The raw frame QEMU wrote is gone; only the PNG copy remains for the
	// caller to remove.
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(black.PNGPath) {
		t.Fatalf("scratch directory holds %d entries, want only the PNG", len(entries))
	}
}

// A screendump that fails after QEMU began to write the frame leaves
// nothing behind, and neither does a frame that cannot be converted.
func TestCaptureLeavesNoFileWhenItFails(t *testing.T) {
	for name, tc := range map[string]struct {
		frame []byte
		fail  bool
	}{
		"the command fails after the frame was written": {onePixel(0), true},
		"the frame is not a PPM":                        {[]byte("not an image"), false},
		"the frame is cut short":                        {[]byte("P6\n4 4\n255\n\x00"), false},
	} {
		t.Run(name, func(t *testing.T) {
			artifact, scratch, err := capture(t, tc.frame, tc.fail)
			if err == nil || artifact != nil {
				t.Fatalf("capture = %+v, %v, want an error", artifact, err)
			}
			entries, readErr := os.ReadDir(scratch)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("a failed capture left %d file(s) in the scratch directory", len(entries))
			}
		})
	}
}

// The private PNG is written to the scratch directory after the frame
// is converted. When that write fails part way (a full disk leaves the first
// part of the file), the half-written file is removed, because nothing else
// would: the caller tracks only the path it is given, and an artifact without a
// path has none. The capture still returns the image it encoded, in memory,
// with its digest, so the report can say which image was seen.
func TestCaptureRemovesAHalfWrittenPNG(t *testing.T) {
	orig := writeFile
	t.Cleanup(func() { writeFile = orig })
	var attempted string
	writeFile = func(path string, data []byte, perm os.FileMode) error {
		attempted = path
		if err := os.WriteFile(path, data[:len(data)/2], perm); err != nil {
			t.Fatal(err)
		}
		return syscall.ENOSPC
	}

	artifact, scratch, err := capture(t, onePixel(0), false)
	if err != nil {
		t.Fatalf("capture = %v: a PNG that could not be saved does not fail the capture", err)
	}
	if attempted == "" || filepath.Dir(attempted) != scratch {
		t.Fatalf("the PNG was written to %q, want a file in %s", attempted, scratch)
	}
	if artifact.PNGPath != "" {
		t.Fatalf("PNGPath = %q, want none: the file is not an artifact", artifact.PNGPath)
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the failed write left %d file(s) in the scratch directory (the half-written PNG)", len(entries))
	}
	png, err := base64.StdEncoding.DecodeString(artifact.Base64)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(png)
	if artifact.SHA256 != hex.EncodeToString(sum[:]) || artifact.PNGSize != len(png) || len(png) < 2 {
		t.Fatalf("digest %s of %d bytes does not name the %d-byte PNG the capture holds", artifact.SHA256, artifact.PNGSize, len(png))
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Reading the next chunk and hashing (and handing on) the one before it run at
// the same time, and the scan reads and hashes exactly the same bytes in the
// same order. The image comes through a pipe one piece at a time, and the work
// on each chunk puts the next piece into the pipe and waits until the scan has
// read it: a scan that read only after the work on the chunk before had ended
// would never read it. No clock is involved, so a loaded machine cannot fail
// it (the timed test it replaces took 1.65 s against a limit of 0.58 s with
// the load at 7.6 on 8 CPUs).
func TestScanOverlapsReadingWithTheWorkOnTheChunkBefore(t *testing.T) {
	// A piece is at most PIPE_BUF, so each write lands whole and the read
	// after it takes the whole piece.
	const pieces, pieceSize = 30, 4096
	content := make([]byte, 0, pieces*pieceSize)
	for i := 0; len(content) < pieces*pieceSize; i++ {
		content = append(content, fmt.Sprintf("certistack scan overlap %06d\n", i)...)
	}
	content = content[:pieces*pieceSize]
	sum := sha256.Sum256(content)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	raw, err := r.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	// queued is how many bytes wait in the pipe, unread by the scan.
	// (TIOCINQ is FIONREAD on Linux.)
	queued := func() (int, error) {
		var n int
		var ioctlErr error
		if err := raw.Control(func(fd uintptr) { n, ioctlErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ) }); err != nil {
			return 0, err
		}
		return n, ioctlErr
	}
	written := 0
	writePiece := func() error {
		_, err := w.Write(content[written*pieceSize : (written+1)*pieceSize])
		written++
		return err
	}
	if err := writePiece(); err != nil {
		t.Fatal(err)
	}

	var got bytes.Buffer
	calls := 0
	digest, total, err := readMappedImage(context.Background(), r, nil, func(p []byte, off int64) error {
		if int64(got.Len()) != off { // in order, no gap, no repeat
			return errors.New("chunk out of order")
		}
		got.Write(p)
		calls++
		if written == pieces {
			return w.Close()
		}
		if err := writePiece(); err != nil {
			return err
		}
		// A hang guard only: the scan's reader is waiting on the pipe.
		deadline := time.Now().Add(time.Minute)
		for {
			n, err := queued()
			if err != nil {
				return fmt.Errorf("count the bytes in the pipe: %w", err)
			}
			if n == 0 {
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("the scan did not read the next chunk while the chunk at %d was being worked on: %d bytes still wait in the pipe", off, n)
			}
			time.Sleep(time.Millisecond)
		}
	})
	if err != nil || digest != hex.EncodeToString(sum[:]) || total != int64(len(content)) || !bytes.Equal(got.Bytes(), content) {
		t.Fatalf("scan = %s / %d / %v, want %s / %d / nil", digest, total, err, hex.EncodeToString(sum[:]), len(content))
	}
	if calls != pieces {
		t.Fatalf("%d chunks handed on, want one per piece, %d", calls, pieces)
	}
}

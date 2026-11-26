// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The full-integrity scan reads a mapped image one 4 MiB chunk at a time, in
// order, through a loop device over the PBS map's FUSE file. Each read waits
// for a PBS round trip, so the scan is bound by latency (about 40 MB/s of
// image per disk with an idle PBS and node), and a 230 GiB disk takes more
// than an hour.
//
// The read-ahead overlaps those round trips. A few workers read the chunks
// that lie just ahead of the scan into the page cache; the scan itself is
// unchanged and still reads, hashes and checks every byte in order. A
// read-ahead error is ignored on purpose: the scan reaches the same chunk, fails
// the same way and reports it. Nothing the read-ahead reads is used as data.

const (
	// readaheadChunk is the unit a worker reads: the scan's own chunk size.
	readaheadChunk = 4 << 20
	// defaultReadaheadWorkers is how many chunks may be in flight at once.
	defaultReadaheadWorkers = 8
	// readaheadWindow is how many chunks (256 MiB) the workers may be ahead of
	// the scan, so the cache they fill stays small.
	readaheadWindow = 64
	// maxReadaheadWorkers bounds CERTISTACK_SCAN_READAHEAD.
	maxReadaheadWorkers = 32
)

// readaheadWorkers is the number of read-ahead workers: eight by default;
// CERTISTACK_SCAN_READAHEAD sets it (0 or 1 turns the read-ahead off, the
// largest accepted value is 32). An invalid value leaves the default.
//
// The setting is deliberately worker-local and not a supported operator
// option: no env-file key and no controller forwarding carries it to the
// worker, so only someone starting a worker by hand with it in the process
// environment (testing and development) changes it. Supporting it would mean
// adding it to the env-file allowlists, the worker environment and the docs.
func readaheadWorkers() int {
	v := os.Getenv("CERTISTACK_SCAN_READAHEAD")
	if v == "" {
		return defaultReadaheadWorkers
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return defaultReadaheadWorkers
	}
	if n > maxReadaheadWorkers {
		return maxReadaheadWorkers
	}
	return n
}

// imageReadahead reads ahead of a scan. consumed is called once for each chunk
// the scan finishes; stop ends the workers.
type imageReadahead struct {
	tokens chan struct{}
	done   chan struct{}
	wg     sync.WaitGroup
	once   sync.Once
	// consumedTo is how far the scan has read and released the image.
	consumedTo atomic.Int64
}

// startReadahead starts workers reading chunk-sized pieces of ra (size bytes)
// in order, never more than window chunks ahead of the chunks consumed. It
// returns nil when there is nothing to overlap (fewer than two workers or an
// image that is one chunk or less).
func startReadahead(ra io.ReaderAt, size int64, chunk, workers, window int) *imageReadahead {
	if ra == nil || workers < 2 || chunk <= 0 || window < workers || size <= int64(chunk) {
		return nil
	}
	chunks := (size + int64(chunk) - 1) / int64(chunk)
	p := &imageReadahead{tokens: make(chan struct{}, window), done: make(chan struct{})}
	for i := 0; i < window; i++ {
		p.tokens <- struct{}{}
	}
	var next int64
	for w := 0; w < workers; w++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			buf := make([]byte, chunk)
			for {
				select {
				case <-p.tokens:
				case <-p.done:
					return
				}
				i := atomic.AddInt64(&next, 1) - 1
				if i >= chunks {
					return
				}
				// A chunk the scan has already passed is not read: a worker
				// held up between taking it and reading it would read it from
				// PBS a second time and leave it cached after the scan
				// released it. Its slot goes back, so the workers catch up
				// with the scan instead of stalling behind it.
				if (i+1)*int64(chunk) <= p.consumedTo.Load() {
					select {
					case p.tokens <- struct{}{}:
					default:
					}
					continue
				}
				// The error is ignored: a chunk that cannot be read fails the
				// scan itself, with its error, when the scan reaches it.
				_, _ = ra.ReadAt(buf, i*int64(chunk))
			}
		}()
	}
	return p
}

// consumed frees one slot: the scan has finished another chunk, and has read
// and released the image up to upTo.
func (p *imageReadahead) consumed(upTo int64) {
	if p == nil {
		return
	}
	for {
		at := p.consumedTo.Load()
		if upTo <= at || p.consumedTo.CompareAndSwap(at, upTo) {
			break
		}
	}
	select {
	case p.tokens <- struct{}{}:
	default:
	}
}

// stop ends the workers. A worker waiting on PBS in a read cannot be
// interrupted from here, so stop waits for them only as long as a canceled
// scan waits for its own read, and then leaves them to finish on their own.
func (p *imageReadahead) stop() {
	if p == nil {
		return
	}
	p.once.Do(func() { close(p.done) })
	finished := make(chan struct{})
	go func() { p.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(readCancelGrace):
	}
}

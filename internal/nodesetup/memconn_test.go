// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodesetup

import (
	"io"
	"net"
	"sync"
	"time"
)

// memBuffer is one direction of an in-memory connection. Unlike net.Pipe it
// buffers, which an SSH handshake needs: both ends write their version string
// before either reads.
type memBuffer struct {
	mu     sync.Mutex
	cond   *sync.Cond
	data   []byte
	closed bool
}

func newMemBuffer() *memBuffer {
	b := &memBuffer{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *memBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	b.data = append(b.data, p...)
	b.cond.Broadcast()
	return len(p), nil
}

func (b *memBuffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.data) == 0 && !b.closed {
		b.cond.Wait()
	}
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

func (b *memBuffer) close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.cond.Broadcast()
}

// memConn is one end of an in-memory connection; closing either end closes both
// directions. It has no deadlines: a test ends a wait by closing the end.
type memConn struct {
	in, out *memBuffer
}

// memPipe returns the two ends of a buffered in-memory connection.
func memPipe() (net.Conn, net.Conn) {
	a, b := newMemBuffer(), newMemBuffer()
	return &memConn{in: a, out: b}, &memConn{in: b, out: a}
}

func (c *memConn) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *memConn) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *memConn) Close() error {
	c.in.close()
	c.out.close()
	return nil
}
func (c *memConn) LocalAddr() net.Addr              { return memAddr{} }
func (c *memConn) RemoteAddr() net.Addr             { return memAddr{} }
func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

type memAddr struct{}

func (memAddr) Network() string { return "mem" }
func (memAddr) String() string  { return "mem" }

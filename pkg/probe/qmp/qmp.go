// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package qmp provides a client for the QEMU Monitor Protocol (QMP) over UNIX domain sockets.
package qmp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/cliftcloud/certistack/pkg/probe"
)

const maxResponseLineBytes = 4 << 20

// commandTimeout bounds one QMP command's exchange on the socket.
var commandTimeout = 15 * time.Second

// readResponseLine reads one newline-terminated message, starting with
// partial, the part of a message an earlier read already consumed. When the
// read fails partway (a timeout), it returns what it has read so the caller
// can resume at the same message boundary instead of reading the rest of
// that message as a new one.
func readResponseLine(reader *bufio.Reader, partial []byte) (line, rest []byte, err error) {
	line = append(make([]byte, 0, reader.Size()), partial...)
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > maxResponseLineBytes-len(line) {
			return nil, nil, fmt.Errorf("QMP response exceeds maximum size of %d bytes", maxResponseLineBytes)
		}
		line = append(line, fragment...)
		if err == nil {
			return line, nil, nil
		}
		if err != bufio.ErrBufferFull {
			return nil, line, err
		}
	}
}

// DefaultSocketPath returns the standard Proxmox VE QMP socket path for a VMID.
func DefaultSocketPath(vmid int) string {
	return fmt.Sprintf("/var/run/qemu-server/%d.qmp", vmid)
}

// Client manages a QMP session with a QEMU virtual machine process.
type Client struct {
	conn    net.Conn
	reader  *bufio.Reader
	encoder *json.Encoder
	mu      sync.Mutex
	// lastID numbers the commands sent; QEMU echoes each command's id in
	// its reply, which is how a reply is matched to its command.
	lastID uint64
	// partial is a message a timed-out read had begun to receive.
	partial []byte
}

// readLine reads the next message, resuming one a failed read began.
func (c *Client) readLine() ([]byte, error) {
	line, rest, err := readResponseLine(c.reader, c.partial)
	c.partial = rest
	return line, err
}

// bound limits one exchange to timeout and to ctx: the socket deadline is
// the earlier of the two, and ctx ending interrupts a pending read or
// write. The returned done restores an unbounded socket and returns why
// ctx ended, if it has: a reply read after that does not count.
func (c *Client) bound(ctx context.Context, timeout time.Duration) (done func() error) {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = c.conn.SetDeadline(deadline)
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		_ = c.conn.SetDeadline(time.Unix(1, 0))
	})
	return func() error {
		if !stop() {
			<-interrupted
		}
		_ = c.conn.SetDeadline(time.Time{})
		return probe.Expired(ctx)
	}
}

// Dial establishes a connection to the QMP UNIX socket and completes capability negotiation.
func Dial(socketPath string, timeout time.Duration) (*Client, error) {
	return DialContext(context.Background(), socketPath, timeout)
}

// DialContext is Dial within ctx. timeout bounds the connection and the
// greeting, and capability negotiation takes at most a command's time;
// none of them goes past ctx's deadline.
func DialContext(ctx context.Context, socketPath string, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to dial QMP socket at %s: %w", socketPath, err)
	}

	c := &Client{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		encoder: json.NewEncoder(conn),
	}

	// 1. Read QMP greeting banner with deadline
	var greeting struct {
		QMP map[string]interface{} `json:"QMP"`
	}
	done := c.bound(ctx, timeout)
	line, err := c.readLine()
	if late := done(); late != nil {
		err = late
	}
	if err != nil {
		c.conn.Close()
		return nil, fmt.Errorf("failed to read QMP greeting from %s: %w", socketPath, err)
	}
	if err := json.Unmarshal(line, &greeting); err != nil {
		c.conn.Close()
		return nil, fmt.Errorf("failed to parse QMP greeting: %w", err)
	}
	if greeting.QMP == nil {
		c.conn.Close()
		return nil, fmt.Errorf("invalid QMP greeting: missing QMP object")
	}

	// 2. Negotiate capabilities
	if _, err := c.ExecuteContext(ctx, "qmp_capabilities", nil); err != nil {
		c.conn.Close()
		return nil, fmt.Errorf("failed to negotiate QMP capabilities: %w", err)
	}

	slog.Debug("QMP capability negotiation completed", "socket", socketPath)
	return c, nil
}

// Close disconnects from the QMP socket.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Execute sends a command to QEMU and returns the raw JSON "return" object.
// Asynchronous events emitted by QEMU are automatically skipped.
//
// Every command carries an id, which QEMU echoes in its reply. A command
// that timed out still gets its reply later, on the same connection; the
// next command reads past it by its id, so a stale reply (a "running"
// sampled before the timeout) can never answer a fresh query.
func (c *Client) Execute(cmd string, args map[string]interface{}) (json.RawMessage, error) {
	return c.ExecuteContext(context.Background(), cmd, args)
}

// ExecuteContext is Execute within ctx: ctx ending interrupts the exchange,
// and a reply that arrives after it ended is an error, however good.
func (c *Client) ExecuteContext(ctx context.Context, cmd string, args map[string]interface{}) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Bound the exchange so an unresponsive guest/socket cannot hang it.
	done := c.bound(ctx, commandTimeout)
	result, err := c.execute(cmd, args)
	if late := done(); late != nil {
		if err == nil {
			return nil, fmt.Errorf("QMP reply to '%s' arrived too late to count: %w", cmd, late)
		}
		return nil, fmt.Errorf("QMP command '%s' interrupted: %w", cmd, late)
	}
	return result, err
}

func (c *Client) execute(cmd string, args map[string]interface{}) (json.RawMessage, error) {
	c.lastID++
	id := fmt.Sprintf("certistack-%d", c.lastID)
	req := map[string]interface{}{
		"execute": cmd,
		"id":      id,
	}
	if args != nil {
		req["arguments"] = args
	}

	if err := c.encoder.Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send QMP command '%s': %w", cmd, err)
	}

	for {
		line, err := c.readLine()
		if err != nil {
			return nil, fmt.Errorf("failed to read QMP response for '%s': %w", cmd, err)
		}

		var resp struct {
			ID     json.RawMessage `json:"id"`
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Class string `json:"class"`
				Desc  string `json:"desc"`
			} `json:"error"`
			Event string `json:"event"`
		}

		if err := json.Unmarshal(line, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse QMP response for '%s': %w", cmd, err)
		}

		// Skip asynchronous event notifications
		if resp.Event != "" {
			continue
		}

		if len(resp.ID) == 0 {
			return nil, fmt.Errorf("invalid QMP response for '%s': it carries no command id", cmd)
		}
		var replyID string
		if err := json.Unmarshal(resp.ID, &replyID); err != nil || replyID != id {
			slog.Debug("discarding QMP reply to an earlier command", "command", cmd, "reply_id", string(resp.ID))
			continue
		}

		if resp.Error != nil {
			return nil, fmt.Errorf("QMP error (%s): %s", resp.Error.Class, resp.Error.Desc)
		}
		if len(resp.Return) == 0 || string(resp.Return) == "null" {
			return nil, fmt.Errorf("invalid QMP response for '%s': missing return value", cmd)
		}

		return resp.Return, nil
	}
}

// StatusResult models the output of QMP query-status.
type StatusResult struct {
	Running    bool   `json:"running"`
	SingleStep bool   `json:"singlestep"`
	Status     string `json:"status"` // "running", "paused", "shutdown", "internal-error"
}

// QueryStatus queries QEMU for the current execution status of the VM.
func (c *Client) QueryStatus() (*StatusResult, error) {
	return c.QueryStatusContext(context.Background())
}

// QueryStatusContext is QueryStatus within ctx: a status that arrives after
// ctx ended is an error.
func (c *Client) QueryStatusContext(ctx context.Context) (*StatusResult, error) {
	res, err := c.ExecuteContext(ctx, "query-status", nil)
	if err != nil {
		return nil, err
	}

	var status StatusResult
	if err := json.Unmarshal(res, &status); err != nil {
		return nil, fmt.Errorf("failed to unmarshal query-status response: %w", err)
	}

	return &status, nil
}

// Screendump captures the virtual framebuffer to a file on the host (typically PPM format).
func (c *Client) Screendump(outputPath string) error {
	return c.ScreendumpContext(context.Background(), outputPath)
}

// ScreendumpContext is Screendump within ctx: ctx ending interrupts the wait
// for QEMU's reply instead of leaving it to the command timeout, and a reply
// that arrives after ctx ended is an error. The file may still be
// written by QEMU afterwards; the caller removes what it asked for.
func (c *Client) ScreendumpContext(ctx context.Context, outputPath string) error {
	args := map[string]interface{}{
		"filename": outputPath,
	}
	_, err := c.ExecuteContext(ctx, "screendump", args)
	if err != nil {
		return fmt.Errorf("screendump command failed: %w", err)
	}
	return nil
}

// WaitForRunning polls query-status until the VM reaches the "running" state.
// Failure to achieve running state within timeout triggers a fatal VM boot failure.
// Each query is bounded by the wait, so a "running" that arrives after the
// timeout or after ctx is canceled does not count.
func (c *Client) WaitForRunning(ctx context.Context, pollInterval, timeout time.Duration) error {
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctxTimeout.Done():
			return fmt.Errorf("VM failed to reach running status within %v: %w", timeout, ctxTimeout.Err())
		case <-ticker.C:
			status, err := c.QueryStatusContext(ctxTimeout)
			if err != nil {
				if late := probe.Expired(ctxTimeout); late != nil {
					return fmt.Errorf("VM failed to reach running status within %v: %w", timeout, late)
				}
				slog.Debug("QMP query-status poll error (retrying)", "error", err)
				continue
			}

			if status.Running && status.Status == "running" {
				slog.Info("VM achieved running hypervisor status", "status", status.Status)
				return nil
			}
		}
	}
}

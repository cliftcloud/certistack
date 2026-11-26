// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package qga provides a client for the QEMU Guest Agent JSON-RPC channel.
package qga

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/internal/qgacommand"
	"github.com/cliftcloud/certistack/pkg/probe"
)

const (
	maxResponseLineBytes = 4 << 20
	maxGuestOutputBytes  = 1 << 20
	// maxReportOutputBytes bounds how much guest-controlled stdout/stderr
	// text is embedded in a probe's Error/Detail fields, which flow directly
	// into the report. maxGuestOutputBytes already bounds what is
	// decoded from the wire, but that limit exists to protect the worker
	// process's memory, not to size a report field; a hostile or malformed
	// guest answering with up to 1 MiB of text per probe should not be able
	// to inflate the report by that much, across every probe on every VM in
	// the plan.
	maxReportOutputBytes = 4 << 10
	// maxSyncDiscardBytes bounds the earlier data guest-sync reads past
	// while it looks for its own reply.
	maxSyncDiscardBytes = 2 * maxResponseLineBytes
	// maxSyncID bounds guest-sync ids, which are 1 or more: an absent or
	// null return value decodes to 0 and must never match. The
	// range stops at 2^53-1, the largest integer every JSON reader keeps
	// exactly, and is wide enough that a reply an earlier client left in the
	// channel cannot echo this client's id by chance.
	maxSyncID = 1<<53 - 1
)

// newSyncID picks the id one guest-sync handshake sends: in [1, maxSyncID].
func newSyncID() int64 {
	return rand.Int63n(maxSyncID) + 1
}

// CleanGuestText makes text a guest controls fit to print and to record. Guest
// text reaches the report and the operator's terminal, so it is cleaned
// wherever it enters them: invalid UTF-8 becomes U+FFFD, and every character
// that could hide or reorder what a reader sees is dropped (control characters
// other than newline and tab, so no terminal escape sequence survives; the
// Unicode format characters, which include the bidirectional controls; and
// the line and paragraph separators).
func CleanGuestText(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == '\u2028', r == '\u2029':
			return -1
		}
		return r
	}, s)
}

// SanitizeGuestText is CleanGuestText bounded to maxReportOutputBytes, cut at
// a character boundary: the form in which guest-controlled text is embedded in
// a probe result. The full text is still available at the point this is
// called; only what goes into the report is capped.
func SanitizeGuestText(s string) string {
	s = CleanGuestText(s)
	if len(s) <= maxReportOutputBytes {
		return s
	}
	cut := maxReportOutputBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...(truncated)"
}

// truncateForReport is the name this package's callers use for
// SanitizeGuestText.
func truncateForReport(s string) string { return SanitizeGuestText(s) }

func readResponseLine(reader *bufio.Reader) ([]byte, error) {
	line := make([]byte, 0, reader.Size())
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > maxResponseLineBytes-len(line) {
			return nil, fmt.Errorf("QGA response exceeds maximum size of %d bytes", maxResponseLineBytes)
		}
		line = append(line, fragment...)
		if err == nil {
			return line, nil
		}
		if err != bufio.ErrBufferFull {
			return nil, err
		}
	}
}

// agentReply is the envelope of a QGA reply: a success carries a "return"
// member and a failure an "error" member. Presence decides, so a reply with
// neither (an empty object, null, unrelated JSON) is not a success.
type agentReply struct {
	Return json.RawMessage `json:"return"`
	Error  *struct {
		Desc string `json:"desc"`
	} `json:"error"`
}

// decodeReply checks the envelope of the reply to command and decodes its
// return value into result. An agent error, a missing or null return value,
// and a return value of the wrong shape are all errors.
func decodeReply(line []byte, command string, result any) error {
	var reply agentReply
	if err := json.Unmarshal(line, &reply); err != nil {
		return fmt.Errorf("failed to unmarshal %s response: %w", command, err)
	}
	if reply.Error != nil {
		// The agent's own words reach the probe's error, and so the report.
		return &AgentError{Command: command, Desc: SanitizeGuestText(reply.Error.Desc)}
	}
	if len(reply.Return) == 0 || string(reply.Return) == "null" {
		return fmt.Errorf("QGA %s reply has no return value", command)
	}
	if err := json.Unmarshal(reply.Return, result); err != nil {
		return fmt.Errorf("failed to unmarshal %s response: %w", command, err)
	}
	return nil
}

// AgentError is the guest agent refusing or failing a command: its reply held
// an "error" member. Desc is the agent's own text, cleaned and bounded.
type AgentError struct {
	Command string
	Desc    string
}

func (e *AgentError) Error() string {
	return fmt.Sprintf("QGA %s error: %s", e.Command, e.Desc)
}

func decodeGuestOutput(encoded string) ([]byte, error) {
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))
	decoded, err := io.ReadAll(io.LimitReader(decoder, maxGuestOutputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(decoded) > maxGuestOutputBytes {
		decoded = decoded[:maxGuestOutputBytes]
	}
	return decoded, nil
}

// DefaultSocketPath returns the standard Proxmox VE QGA socket path for a VMID.
func DefaultSocketPath(vmid int) string {
	return fmt.Sprintf("/var/run/qemu-server/%d.qga", vmid)
}

// Client interacts with the in-guest QEMU Guest Agent over a UNIX domain socket.
type Client struct {
	conn    net.Conn
	reader  *bufio.Reader
	encoder *json.Encoder
	mu      sync.Mutex
	// broken is the failure that left the stream out of step with the
	// commands sent (a send or read that failed partway, a timeout): the
	// failed command's reply can still arrive, so no later command may read
	// the next line as its own until Sync has read past it.
	broken error
}

// lost records a failure that leaves the stream out of step, and returns it.
func (c *Client) lost(err error) error {
	c.broken = err
	return err
}

// usable fails when an earlier exchange left the stream out of step.
func (c *Client) usable() error {
	if c.broken != nil {
		return fmt.Errorf("qga: session unusable after an earlier failure (%v)", c.broken)
	}
	return nil
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

// call sends one command and reads the next line as its reply, within
// timeout and ctx. A failed send or read leaves the stream out of step, so
// it marks the session lost; a reply that arrives after ctx ended is an
// error, however good.
func (c *Client) call(ctx context.Context, timeout time.Duration, command string, arguments map[string]interface{}) ([]byte, error) {
	if err := c.usable(); err != nil {
		return nil, err
	}
	req := map[string]interface{}{"execute": command}
	if arguments != nil {
		req["arguments"] = arguments
	}
	done := c.bound(ctx, timeout)
	var line []byte
	step, err := "send "+command, c.encoder.Encode(req)
	if err == nil {
		step = "read " + command + " response"
		line, err = readResponseLine(c.reader)
	}
	late := done()
	if err != nil {
		if late != nil {
			err = late // the socket failed because ctx ended
		}
		return nil, c.lost(fmt.Errorf("failed to %s: %w", step, err))
	}
	if late != nil {
		return nil, fmt.Errorf("reply to %s arrived too late to count: %w", command, late)
	}
	return line, nil
}

// Dial connects to the QGA UNIX socket and completes the guest-sync handshake.
func Dial(socketPath string, timeout time.Duration) (*Client, error) {
	return DialContext(context.Background(), socketPath, timeout)
}

// DialContext is Dial within ctx: the connection and the handshake each
// take at most timeout, and never past ctx's deadline.
func DialContext(ctx context.Context, socketPath string, timeout time.Duration) (*Client, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("qga: failed to connect to socket %s: %w", socketPath, err)
	}

	c := &Client{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		encoder: json.NewEncoder(conn),
	}

	// Perform guest-sync handshake
	if err := c.SyncContext(ctx, timeout); err != nil {
		c.conn.Close()
		return nil, fmt.Errorf("%w: %w", errSyncHandshake, err)
	}

	return c, nil
}

// Close closes the underlying socket connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Sync performs the guest-sync protocol handshake. The channel can still
// hold replies to an earlier client's commands, or the tail of one, when
// this client connects. As the guest-sync contract says, the client reads
// past everything until the reply that echoes its own id; after that reply
// the stream is in step. Reading past is bounded by the timeout and by
// maxSyncDiscardBytes.
func (c *Client) Sync(timeout time.Duration) error {
	return c.SyncContext(context.Background(), timeout)
}

// SyncContext is Sync within ctx: a reply after ctx ends does not count.
func (c *Client) SyncContext(ctx context.Context, timeout time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	done := c.bound(ctx, timeout)
	err := c.sync()
	if late := done(); late != nil {
		if err == nil {
			err = fmt.Errorf("guest-sync reply arrived too late to count: %w", late)
		} else {
			err = fmt.Errorf("qga: guest-sync interrupted: %w", late)
		}
	}
	if err != nil {
		return c.lost(err)
	}
	c.broken = nil
	return nil
}

func (c *Client) sync() error {
	syncID := newSyncID()
	req := map[string]interface{}{
		"execute": "guest-sync",
		"arguments": map[string]interface{}{
			"id": syncID,
		},
	}

	if err := c.encoder.Encode(req); err != nil {
		return fmt.Errorf("qga: failed to send command: %w", err)
	}

	discarded, agentError := 0, ""
	for {
		line, err := readResponseLine(c.reader)
		if err != nil {
			if agentError != "" {
				// The agent refused a request, perhaps this one: say so.
				err = fmt.Errorf("%w (an earlier reply was the agent error %q)", err, truncateForReport(agentError))
			}
			return fmt.Errorf("qga: failed to read guest-sync response: %w", err)
		}
		var reply agentReply
		if json.Unmarshal(line, &reply) == nil {
			// The reply is ours only when it carries an integer return
			// member equal to our id and no error member. A missing return
			// member is not a zero, and null is not an id.
			var id int64
			if reply.Error == nil && len(reply.Return) > 0 && json.Unmarshal(reply.Return, &id) == nil && id == syncID {
				return nil
			}
			if reply.Error != nil {
				agentError = reply.Error.Desc
			}
		}
		discarded += len(line)
		if discarded > maxSyncDiscardBytes {
			return fmt.Errorf("qga: no guest-sync response in %d bytes of earlier data", discarded)
		}
		slog.Debug("QGA guest-sync read past an earlier reply", "bytes", len(line))
	}
}

// Ping sends guest-ping over the QGA JSON-RPC channel.
func (c *Client) Ping(timeout time.Duration) error {
	return c.PingContext(context.Background(), timeout)
}

// PingContext is Ping within ctx: a reply after ctx ends does not count.
func (c *Client) PingContext(ctx context.Context, timeout time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	line, err := c.call(ctx, timeout, "guest-ping", nil)
	if err != nil {
		return err
	}
	// guest-ping succeeds with {"return": {}}. Any other shape, however
	// well-formed its JSON, is not evidence that the agent answered.
	var ret map[string]json.RawMessage
	return decodeReply(line, "guest-ping", &ret)
}

// GetHostName retrieves the guest hostname via QGA JSON-RPC guest-get-host-name.
func (c *Client) GetHostName() (string, error) {
	return c.GetHostNameContext(context.Background())
}

// maxHostNameBytes is the longest host name there is: a fully qualified DNS
// name is at most 253 characters, and the agent reports no more than 255.
const maxHostNameBytes = 255

// ErrInvalidHostName marks a guest-get-host-name answer that is no host name:
// empty, longer than any host name, or made of characters no host name has.
var ErrInvalidHostName = errors.New("QGA guest-get-host-name returned something that is not a host name")

// GetHostNameContext is GetHostName within ctx: a reply after ctx ends does
// not count. The name is guest-controlled text bound for the report and a
// terminal, so one that is empty, longer than a host name can be, or holds
// control, format or invalid UTF-8 characters is refused with
// ErrInvalidHostName (its text, cleaned and bounded, is in the error).
func (c *Client) GetHostNameContext(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	line, err := c.call(ctx, 5*time.Second, "guest-get-host-name", nil)
	if err != nil {
		return "", err
	}

	var ret struct {
		HostName string `json:"host-name"`
	}
	if err := decodeReply(line, "guest-get-host-name", &ret); err != nil {
		return "", err
	}

	hostName := strings.TrimSpace(ret.HostName)
	switch {
	case hostName == "":
		return "", fmt.Errorf("QGA guest-get-host-name returned an empty hostname: %w", ErrInvalidHostName)
	case len(hostName) > maxHostNameBytes:
		return "", fmt.Errorf("QGA guest-get-host-name returned %d bytes, more than any host name (at most %d); it starts %q: %w",
			len(hostName), maxHostNameBytes, SanitizeGuestText(hostName[:min(len(hostName), 64)]), ErrInvalidHostName)
	case CleanGuestText(hostName) != hostName || strings.ContainsAny(hostName, "\n\t") || strings.ContainsRune(hostName, utf8.RuneError):
		return "", fmt.Errorf("QGA guest-get-host-name returned control, format or invalid UTF-8 characters, which no host name has: %q: %w",
			SanitizeGuestText(hostName), ErrInvalidHostName)
	}
	return hostName, nil
}

// ExecResult holds the final outcome of an executed guest process.
type ExecResult struct {
	Exited   bool
	ExitCode int
	// Signaled is true when the process ended abnormally: killed by a signal
	// on Linux, or by an unhandled exception on Windows. Signal then holds
	// that number and ExitCode is -1, so a caller that tests only ExitCode
	// still sees a failure, never a normal exit 0.
	Signaled bool
	Signal   int
	Stdout   string
	Stderr   string
}

// Succeeded reports whether the process exited normally with code 0.
func (r *ExecResult) Succeeded() bool {
	return r != nil && r.Exited && !r.Signaled && r.ExitCode == 0
}

// Outcome says how the process ended, for a probe's error text: "exited
// with code 3", "was terminated by signal 9", or on Windows "was
// terminated by exception 0xC0000005".
func (r *ExecResult) Outcome() string {
	if !r.Signaled {
		return fmt.Sprintf("exited with code %d", r.ExitCode)
	}
	// Linux signal numbers are small; Windows reports the NTSTATUS code of
	// the unhandled exception, which is at least 0xC0000000.
	if r.Signal > 0 && r.Signal < 256 {
		return fmt.Sprintf("was terminated by signal %d", r.Signal)
	}
	return fmt.Sprintf("was terminated by exception 0x%08X", uint32(r.Signal))
}

// NetworkInterface is the narrow, read-only network inventory returned by the
// standard guest-network-get-interfaces QGA command.
type NetworkInterface struct {
	Name            string `json:"name"`
	HardwareAddress string `json:"hardware-address"`
	IPAddresses     []struct {
		IPAddress string `json:"ip-address"`
		Prefix    int    `json:"prefix"`
	} `json:"ip-addresses"`
}

// GetNetworkInterfaces reads the guest's current interface addresses without
// invoking guest-exec. It remains available on hardened guests that disable
// arbitrary command execution through QGA.
func (c *Client) GetNetworkInterfaces(timeout time.Duration) ([]NetworkInterface, error) {
	return c.GetNetworkInterfacesContext(context.Background(), timeout)
}

// GetNetworkInterfacesContext is GetNetworkInterfaces within ctx: ctx ending
// interrupts the read, and a reply after it ended does not count.
func (c *Client) GetNetworkInterfacesContext(ctx context.Context, timeout time.Duration) ([]NetworkInterface, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	line, err := c.call(ctx, timeout, "guest-network-get-interfaces", nil)
	if err != nil {
		return nil, err
	}
	var interfaces []NetworkInterface
	if err := decodeReply(line, "guest-network-get-interfaces", &interfaces); err != nil {
		return nil, err
	}
	// Names and addresses are guest text that the diagnostic prints and records.
	for i := range interfaces {
		interfaces[i].Name = SanitizeGuestText(interfaces[i].Name)
		interfaces[i].HardwareAddress = SanitizeGuestText(interfaces[i].HardwareAddress)
		for j := range interfaces[i].IPAddresses {
			interfaces[i].IPAddresses[j].IPAddress = SanitizeGuestText(interfaces[i].IPAddresses[j].IPAddress)
		}
	}
	return interfaces, nil
}

// Exec runs a shell command inside a POSIX guest and waits for completion.
func (c *Client) Exec(ctx context.Context, command string, pollInterval, timeout time.Duration) (*ExecResult, error) {
	return c.ExecArgv(ctx, "/bin/sh", []string{"-c", command}, pollInterval, timeout)
}

// ExecArgv runs one program with a literal argument list, without a shell,
// and waits for completion. The guest agent resolves a bare program name
// through its PATH, which is how Windows programs such as sc.exe are found.
func (c *Client) ExecArgv(ctx context.Context, path string, args []string, pollInterval, timeout time.Duration) (*ExecResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Issue guest-exec with deadline
	line, err := c.call(ctx, 10*time.Second, "guest-exec", map[string]interface{}{
		"path":           path,
		"arg":            args,
		"capture-output": true,
	})
	if err != nil {
		return nil, err
	}

	var execRet struct {
		PID int `json:"pid"`
	}
	if err := decodeReply(line, "guest-exec", &execRet); err != nil {
		return nil, err
	}

	pid := execRet.PID
	if pid == 0 {
		return nil, fmt.Errorf("guest-exec returned invalid PID 0")
	}

	// 2. Poll guest-exec-status until completion
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}
	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctxTimeout.Done():
			return nil, fmt.Errorf("timed out waiting for guest process PID %d to exit: %w", pid, ctxTimeout.Err())
		case <-ticker.C:
			statusLine, err := c.call(ctxTimeout, 10*time.Second, "guest-exec-status", map[string]interface{}{"pid": pid})
			if err != nil {
				if late := probe.Expired(ctxTimeout); late != nil {
					return nil, fmt.Errorf("timed out waiting for guest process PID %d to exit: %w", pid, late)
				}
				return nil, err
			}

			// exitcode and signal are optional: the agent sends exactly one of
			// them once the process has ended, exitcode for a normal exit and
			// signal for a kill or crash. Their presence is what tells the two
			// apart, so they are decoded as pointers.
			var status struct {
				Exited   bool   `json:"exited"`
				ExitCode *int   `json:"exitcode"`
				Signal   *int   `json:"signal"`
				OutData  string `json:"out-data"`
				ErrData  string `json:"err-data"`
			}
			if err := decodeReply(statusLine, "guest-exec-status", &status); err != nil {
				return nil, err
			}

			if status.Exited {
				stdoutBytes, err := decodeGuestOutput(status.OutData)
				if err != nil {
					return nil, fmt.Errorf("decode guest-exec stdout: %w", err)
				}
				stderrBytes, err := decodeGuestOutput(status.ErrData)
				if err != nil {
					return nil, fmt.Errorf("decode guest-exec stderr: %w", err)
				}

				result := &ExecResult{
					Exited: true,
					Stdout: string(stdoutBytes),
					Stderr: string(stderrBytes),
				}
				switch {
				case status.Signal != nil && status.ExitCode != nil:
					return nil, fmt.Errorf("guest agent reported both exit code %d and signal %d for PID %d", *status.ExitCode, *status.Signal, pid)
				case status.Signal != nil:
					result.Signaled, result.Signal, result.ExitCode = true, *status.Signal, -1
				case status.ExitCode != nil:
					result.ExitCode = *status.ExitCode
				default:
					return nil, fmt.Errorf("guest agent reported PID %d exited without an exit code or signal", pid)
				}
				return result, nil
			}
		}
	}
}

// QGAProber evaluates in-guest service state via the QGA channel.
type QGAProber struct {
	SocketPath     string
	Command        string
	ExpectedOutput string
	Required       bool
	Timeout        time.Duration
	Description    string
}

// NewQGAProber creates an in-guest QGA prober.
func NewQGAProber(socketPath, cmd, expectedOutput string, required bool, timeout time.Duration, desc string) *QGAProber {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &QGAProber{
		SocketPath:     socketPath,
		Command:        cmd,
		ExpectedOutput: expectedOutput,
		Required:       required,
		Timeout:        timeout,
		Description:    desc,
	}
}

// IsPingCommand reports whether a plan's QGA command is the agent ping. Plan
// validation accepts the command after trimming its surrounding space, so
// the prober compares it the same way.
func IsPingCommand(command string) bool {
	switch strings.TrimSpace(command) {
	case "ping", "guest-ping":
		return true
	}
	return false
}

// Probe executes the command inside the guest. When the guest agent is not
// available and the plan does not require it, the probe is skipped.
func (p *QGAProber) Probe(ctx context.Context) probe.Result {
	start := time.Now()

	res := probe.Result{
		Type:        "qga",
		Target:      p.Command,
		Description: p.Description,
	}
	command := strings.TrimSpace(p.Command)

	// A ping answers with an empty object: there is no output for
	// expected_output to match, so a ping that carries one asserts something
	// it cannot check. Plan validation refuses it; a probe built any other
	// way fails, whether or not the agent is there to answer.
	if IsPingCommand(command) && p.ExpectedOutput != "" {
		res.Error = fmt.Sprintf("a QGA guest-ping has no output to match against expected_output %q: it passes when the agent answers; remove expected_output, or check the guest with hostname, systemctl is-active <service>, or sc query <service>", truncateForReport(p.ExpectedOutput))
		return res
	}

	// The agent runs any command outside its fast paths as "/bin/sh -c" in the
	// guest, so a command that is not on the allowlist plan validation applies
	// is refused here too, before the agent is asked, whatever built the probe
	// and whether or not the agent is there to be asked.
	if !qgacommand.Allowed(command) {
		res.Error = fmt.Sprintf("the guest command %q is not one a probe may run: it must be %s; arbitrary guest shell commands are not permitted", truncateForReport(p.Command), qgacommand.Description)
		return res
	}

	client, err := DialContext(ctx, p.SocketPath, 5*time.Second)
	if err != nil {
		res.Duration = time.Since(start)
		if p.Required {
			res.Passed = false
			res.Error = fmt.Sprintf("required QGA channel is unavailable: %v%s", err, unavailableAdvice(err))
			return res
		}
		// An agent the plan does not require may be missing: the probe is
		// skipped, and the verdict rests on the network probes.
		slog.Warn("QGA socket unavailable, skipping the guest-agent probe", "socket", p.SocketPath, "error", err)
		res.Skipped = true
		res.Passed = true // Skipped probes do not fail the overall plan
		res.Detail = fmt.Sprintf("QGA skipped (channel unavailable): %v%s", err, unavailableAdvice(err))
		return res
	}
	defer client.Close()

	// Direct QGA RPC fast-paths
	if command == "hostname" || command == "guest-get-host-name" {
		hostName, hErr := client.GetHostNameContext(ctx)
		if errors.Is(hErr, ErrInvalidHostName) {
			// The agent answered, and what it answered is not a host name:
			// asking the guest to run `hostname` instead would only get the
			// same text back through a longer path.
			res.Duration = time.Since(start)
			res.Error = hErr.Error()
			return res
		}
		if hErr == nil {
			res.Duration = time.Since(start)
			hostName = strings.TrimSpace(hostName)
			if p.ExpectedOutput != "" && !strings.Contains(hostName, p.ExpectedOutput) {
				res.Passed = false
				res.Error = fmt.Sprintf("hostname mismatch: expected substring %q, got %q", p.ExpectedOutput, hostName)
				return res
			}
			res.Passed = true
			res.Detail = fmt.Sprintf("matched %q via QGA get-host-name (%s)", p.ExpectedOutput, hostName)
			return res
		}
	} else if IsPingCommand(command) {
		if pErr := client.PingContext(ctx, p.Timeout); pErr != nil {
			res.Duration = time.Since(start)
			res.Passed = false
			res.Error = fmt.Sprintf("QGA guest-ping failed: %v", pErr)
			return res
		}
		res.Duration = time.Since(start)
		res.Passed = true
		res.Detail = "QGA guest-ping responsive"
		return res
	}

	if service, ok := WindowsServiceQuery(command); ok {
		return p.probeWindowsService(ctx, client, service, start, res)
	}

	execRes, err := client.Exec(ctx, command, 500*time.Millisecond, p.Timeout)
	res.Duration = time.Since(start)

	if err != nil {
		// Fallback: if guest-exec is disabled by guest policy (e.g. default
		// Rocky/RHEL), a hostname assertion can still be answered through
		// get-host-name. No other command may fall back: matching the host
		// name would silently replace a service assertion such as
		// "systemctl is-active postgresql" with an unrelated check.
		if (command == "hostname" || command == "guest-get-host-name") && strings.Contains(err.Error(), "disabled") {
			if hostName, hErr := client.GetHostNameContext(ctx); hErr == nil {
				hostName = strings.TrimSpace(hostName)
				if p.ExpectedOutput == "" || strings.Contains(hostName, p.ExpectedOutput) {
					res.Passed = true
					res.Detail = fmt.Sprintf("guest-exec disabled; matched %q via QGA get-host-name (%s)", p.ExpectedOutput, hostName)
					return res
				}
			}
		}
		res.Passed = false
		res.Error = fmt.Sprintf("QGA execution failed: %v%s", err, execAdvice(err))
		return res
	}

	if !execRes.Succeeded() {
		res.Passed = false
		// Many status commands answer on stdout ("systemctl is-active" prints
		// "inactive"); fall back to it when stderr is empty so the evidence
		// carries the guest's actual answer. A command killed by a signal
		// fails even when its output holds the expected text.
		stream, output := "stderr", strings.TrimSpace(execRes.Stderr)
		if output == "" {
			stream, output = "stdout", strings.TrimSpace(execRes.Stdout)
		}
		res.Error = fmt.Sprintf("in-guest command %s: %s=%s", execRes.Outcome(), stream, truncateForReport(output))
		return res
	}

	stdout := strings.TrimSpace(execRes.Stdout)
	if p.ExpectedOutput != "" && !strings.Contains(stdout, p.ExpectedOutput) {
		res.Passed = false
		res.Error = fmt.Sprintf("output mismatch: expected substring %q, got %q", p.ExpectedOutput, truncateForReport(stdout))
		return res
	}

	res.Passed = true
	res.Detail = fmt.Sprintf("exit code 0; matched %q in output (%s)", p.ExpectedOutput, truncateForReport(stdout))
	return res
}

// WindowsServiceQuery recognizes the plan command "sc query <service>" and
// returns the service name. Plan validation restricts the name; this only
// splits the command.
func WindowsServiceQuery(command string) (string, bool) {
	fields := strings.Fields(command)
	if len(fields) != 3 || fields[0] != "sc" || fields[1] != "query" {
		return "", false
	}
	return fields[2], true
}

// windowsServiceRunning is SERVICE_RUNNING, the state code sc.exe prints on
// its state line ("STATE : 4  RUNNING").
const windowsServiceRunning = 4

// windowsServiceStates names the SERVICE_STATUS dwCurrentState codes. The
// report states a code's name from this table, never guest-supplied text.
var windowsServiceStates = map[int]string{
	1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING", 4: "RUNNING",
	5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED",
}

// windowsServiceStateLine finds the state line by its value, not its label:
// the label is translated on some Windows locales ("STATUS" in German),
// while the code and the English state name are not.
var windowsServiceStateLine = regexp.MustCompile(`:\s*([1-7])\s+(STOPPED|START_PENDING|STOP_PENDING|RUNNING|CONTINUE_PENDING|PAUSE_PENDING|PAUSED)\b`)

// probeWindowsService runs sc.exe directly (no shell) and passes only when
// the service's STATE is RUNNING. sc.exe exits 0 for a stopped service too,
// so the exit code alone proves only that the service exists.
func (p *QGAProber) probeWindowsService(ctx context.Context, client *Client, service string, start time.Time, res probe.Result) probe.Result {
	execRes, err := client.ExecArgv(ctx, "sc.exe", []string{"query", service}, 500*time.Millisecond, p.Timeout)
	res.Duration = time.Since(start)
	if err != nil {
		res.Error = fmt.Sprintf("QGA execution of sc.exe failed: %v%s", err, execAdvice(err))
		return res
	}
	stdout := strings.TrimSpace(execRes.Stdout)
	if !execRes.Succeeded() {
		// 1060: the service is not installed in the restored guest.
		res.Error = fmt.Sprintf("sc query %s %s: %s", service, execRes.Outcome(), truncateForReport(stdout))
		return res
	}
	state, found := windowsServiceState(stdout)
	switch {
	case !found:
		res.Error = fmt.Sprintf("sc query %s printed no service state: %s", service, truncateForReport(stdout))
	case state != windowsServiceRunning:
		res.Error = fmt.Sprintf("Windows service %s is %s (state %d), not RUNNING", service, windowsServiceStates[state], state)
	case p.ExpectedOutput != "" && !strings.Contains(stdout, p.ExpectedOutput):
		res.Error = fmt.Sprintf("Windows service %s is RUNNING, but the output lacks %q: %s", service, p.ExpectedOutput, truncateForReport(stdout))
	default:
		res.Passed = true
		res.Detail = fmt.Sprintf("Windows service %s is RUNNING (sc.exe query via QGA)", service)
		if p.ExpectedOutput != "" {
			// The substring is an assertion of its own, beyond RUNNING: two
			// plans that require different ones must not give the same result.
			res.Detail += fmt.Sprintf("; the output contained the expected %q", truncateForReport(p.ExpectedOutput))
		}
	}
	return res
}

// windowsServiceState finds sc.exe's state line ("STATE : 4  RUNNING") and
// returns its code. The code and name must agree, so text that merely
// mentions a state name cannot pass for one.
func windowsServiceState(output string) (int, bool) {
	for _, line := range strings.Split(output, "\n") {
		m := windowsServiceStateLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		code, _ := strconv.Atoi(m[1])
		if windowsServiceStates[code] != m[2] {
			return 0, false
		}
		return code, true
	}
	return 0, false
}

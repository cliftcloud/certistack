// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package controller runs CertiStack validations from a management host.
//
// It uses the PVE API for normal control-plane operations through the node
// worker and SSH only to bootstrap a short-lived worker in /run. No daemon,
// database, credential, or report is installed persistently on a hypervisor.
package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cliftcloud/certistack/internal/envtypes"
	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
	progresspkg "github.com/cliftcloud/certistack/pkg/progress"
	"github.com/cliftcloud/certistack/pkg/pve"
	"github.com/cliftcloud/certistack/pkg/runphase"
	"github.com/google/uuid"
)

const (
	// maxWorkerJSON bounds a worker's result. A failing VM's record carries a
	// screenshot of its framebuffer, about 0.5 MB as base64 (a test report of
	// 8 failing Windows VMs is 5 MB), so the result of a large fleet that
	// fails grows with it, and losing it would lose the evidence of the very
	// run that failed. 64 MiB holds about a hundred failing VMs. The bound is
	// there to protect the controller's memory from a runaway or hostile worker,
	// which needs about four times the result at once (the bytes, the decoded
	// report, the signed and the saved copies); a fleet of more failing VMs
	// than that should be split into plans, or its failures fetched from the
	// node's log, not held in memory as one document.
	maxWorkerJSON = 64 << 20
	// maxWorkerStderr bounds the copy of a worker's stderr kept for errors.
	maxWorkerStderr = 32 << 20
	// maxPendingProgressBytes bounds progressReporter.pending. Stderr bytes
	// reach it via a best-effort MultiWriter tap; without its own bound, a
	// node worker that streams stderr without ever writing a newline would
	// grow controller memory without limit until maxWorkerStderr ends the
	// command.
	maxPendingProgressBytes = 1 << 20
	// maxWorkerProgressBytes is what the controller shows of a worker's
	// progress in all: the lines it renders, time stamps included. Test runs
	// show 0.15 MB typically and 0.4 MB at most (a fleet),
	// while each event may carry 4 KiB, so a worker that goes on past this is
	// not reporting progress. What it says after that is not shown,
	// and the run's report and the node's log keep the detail.
	maxWorkerProgressBytes = 16 << 20
	// A PVE stop/destroy task can take a few minutes, especially when a large
	// recovery tier is unwinding.  Cancellation therefore remains attached to
	// cleanup long enough for the worker's normal LIFO teardown to finish.  We
	// only use the journal-recovery fallback after that graceful window has
	// actually been exhausted.
	interruptionCleanupTimeout = 20 * time.Minute
	// unverifiedCleanupReason is the failure_reason of a report whose cleanup
	// the controller could not verify; the worker's own words for its own
	// unverified cleanup are the same.
	unverifiedCleanupReason     = "temporary CertiStack resource cleanup could not be verified; recovery journal retained"
	gracefulWorkerStopTimeout   = 15 * 60
	forcedWorkerStopWaitSeconds = 30
	workerLeaseDurationSeconds  = 90
	// A worker's supervisor exits with its worker's own status, except for
	// these, which the controller can tell apart from any status of a
	// worker: it could not keep the recovery log, the worker was
	// still running forcedWorkerStopWaitSeconds after SIGKILL, or
	// it could not read the worker's result. It refuses to start a
	// worker with 125 and 126.
	supervisorLogNotKeptStatus       = 122
	supervisorWorkerStuckStatus      = 123
	supervisorResultUnreadableStatus = 124
	// The worker command is often silent for minutes, through a grace or
	// soak wait, so only ssh's own keepalive notices a node that crashed,
	// rebooted or lost its network: it asks for a reply after
	// sshServerAliveInterval seconds without traffic and gives up after
	// sshServerAliveCountMax unanswered asks. Without it, TCP keepalive
	// noticed after about two hours.
	sshServerAliveInterval = 15
	sshServerAliveCountMax = 4
	sshDeadPeerSeconds     = sshServerAliveInterval * sshServerAliveCountMax
	sshConnectTimeout      = 20
	// maxSSHErrorDetail bounds the remote stderr an error carries.
	maxSSHErrorDetail = 4 << 10
)

// commandPipeDelay is how long a command's pipes may stay open after the
// command has ended or been stopped. A variable so that a test can shorten it.
var commandPipeDelay = 10 * time.Second

// ErrControllerMaterialCleanupUnverified is what Run's error wraps when it
// could not verify that the controller's own material on the node was removed
// after the run: the run's workspace (its worker, environment and results),
// the retained workspace's encryption key, or the SSH staging directory. It
// concerns the credentials the controller staged, whatever the validation's
// outcome; a caller tells it from a failed validation with errors.Is.
var ErrControllerMaterialCleanupUnverified = errors.New("temporary controller material cleanup was not verified")

// A completed run's journal check waits out another operation's host lock,
// rechecking between these bounds, within interruptionCleanupTimeout. After
// losing contact with the node, the controller retries it between the
// nodeRetry bounds, within the same timeout.
var (
	hostLockRetryInitial     = 5 * time.Second
	hostLockRetryMax         = time.Minute
	nodeRetryInitial         = 5 * time.Second
	nodeRetryMax             = 30 * time.Second
	workerLeaseRenewInterval = 20 * time.Second
	workerLeaseRenewTimeout  = 10 * time.Second
	// leaseWarnAfter is how long lease renewals may fail before the
	// operator is told.
	leaseWarnAfter = 2 * workerLeaseRenewInterval
)

var (
	sshHostExpr = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]*$`)
	sshUserExpr = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,31}$`)
	pveNodeExpr = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)
)

// SSHConfig identifies the single PVE node that will execute one temporary
// worker. KnownHostsFile is mandatory: the controller never disables SSH host
// key verification.
type SSHConfig struct {
	Host           string
	User           string
	Port           int
	IdentityFile   string
	KnownHostsFile string
	UseSudo        bool
}

// RunOptions describes one remote validation initiated by the controller.
// Paths other than OutputDir are paths on the PVE node.
type RunOptions struct {
	SSH        SSHConfig
	PlanPath   string
	NodeName   string
	ScratchDir string
	StateDir   string
	OutputDir  string
	// Signer, when set, attests the report after the controller has checked the
	// worker's evidence and before the report is saved (see attest.Signer), and is
	// called exactly once. The Community Edition sets none and the report is saved
	// unsigned, after every one of the controller's checks all the same; the
	// Enterprise Edition supplies a signer whose key never leaves the controller.
	Signer attest.Signer
	// OverlayStorage, when set, overrides the plan's storage.overlay_storage
	// on the worker.
	OverlayStorage string
	// Sandbox, for a check only, is the plan's network: the worker judges its
	// range against the node (Executor.Check).
	Sandbox *config.Network
	// NoWireProbes, for a check only, says the plan has no wire probe, so the
	// worker does not require nft of the node (Executor.Check).
	NoWireProbes bool
	// SkipIntegrity requests the test-only worker fast path. The worker marks
	// its returned evidence and the controller signs that marker into the final
	// report, so it cannot be confused with a full integrity validation.
	SkipIntegrity bool
	// CleanupContext is canceled only when the operator explicitly abandons
	// interruption cleanup. A nil context keeps the normal bounded cleanup
	// behavior for library callers that do not expose a second signal.
	CleanupContext context.Context
	Build          BuildInfo
	// Writer receives the run's progress. Run writes to it from a goroutine of
	// its own, through a bounded queue, so that a Writer that stops taking
	// output delays nothing of the run, its cleanup included: lines that do
	// not fit the queue are dropped and counted, and Run waits a few seconds
	// for what is queued when it ends. A Writer that is stuck in a call is not
	// waited for, and may be written to until that call returns.
	Writer io.Writer

	// sshClient is the address the SSH session reaches the node from, as the
	// node sees it (nodeSSHClient), for the worker's sandbox check: the sandbox
	// range must not hold it. Empty when the node did not say.
	sshClient string
}

// BuildInfo identifies the controller that initiated a validation.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
	// ExecutableSHA256 is the SHA-256 of the executable uploaded to run as the
	// node worker. Run sets it after staging, from the staged copy; a value
	// given by the caller is replaced.
	ExecutableSHA256 string
}

// Result records the local report path and the returned remote evidence.
type Result struct {
	Report     *attest.Report
	ReportPath string
}

// commandRunner is small so all command construction is unit-testable without
// opening an SSH connection.
type commandRunner interface {
	Run(context.Context, string, []string) ([]byte, error)
}

// streamingCommandRunner preserves the worker's machine-readable stdout while
// forwarding its operational stderr to the controller user in real time.
// Implementations that only satisfy commandRunner remain usable in tests.
type streamingCommandRunner interface {
	RunWithStderr(context.Context, string, []string, io.Writer) ([]byte, error)
}

// scriptCommandRunner is a streamingCommandRunner that also hands back the
// standard output of a command that failed. RunNodeScript needs it: a setup
// script can print a token's secret, once, and then fail on a later step.
type scriptCommandRunner interface {
	RunKeepingStdout(context.Context, string, []string, io.Writer) ([]byte, error)
}

type osCommandRunner struct{}

func (osCommandRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	return runCommand(ctx, name, args, nil)
}

func (osCommandRunner) RunWithStderr(ctx context.Context, name string, args []string, progress io.Writer) ([]byte, error) {
	return runCommand(ctx, name, args, progress)
}

func (osCommandRunner) RunKeepingStdout(ctx context.Context, name string, args []string, progress io.Writer) ([]byte, error) {
	return runCommandOutput(ctx, name, args, progress, true)
}

func runCommand(ctx context.Context, name string, args []string, progress io.Writer) ([]byte, error) {
	return runCommandOutput(ctx, name, args, progress, false)
}

// runCommandOutput is runCommand; with keepStdout a command that fails still
// returns what it wrote to standard output (within the limit), with the error.
func runCommandOutput(ctx context.Context, name string, args []string, progress io.Writer, keepStdout bool) ([]byte, error) {
	// A command that writes more than the controller keeps is stopped when it
	// does, not after it has ended on its own, if it ever does: its
	// output is an error already, and the node's worker is stopped and its
	// journal recovered by the caller, as after any lost connection.
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	cmd := process.CommandContext(ctx, name, args, false)
	// A program the command started and left holding its pipes, such as an ssh
	// connection-sharing master, must not hold the controller after the command
	// has ended or been stopped.
	cmd.WaitDelay = commandPipeDelay
	var stdout, stderr limitedBuffer
	stdout.limit, stdout.onExceeded = maxWorkerJSON, stop
	stderr.limit, stderr.onExceeded = maxWorkerStderr, stop
	cmd.Stdout = &stdout
	if progress == nil {
		cmd.Stderr = &stderr
	} else {
		// Progress must never be able to break the worker RPC or suppress the
		// bounded local stderr copy used in errors.
		cmd.Stderr = io.MultiWriter(&stderr, bestEffortWriter{progress})
	}
	err := process.Run(cmd)
	if stdout.exceeded {
		return nil, fmt.Errorf("%s output exceeded %d bytes; the command was stopped (a worker's result of about a hundred failing VMs, whose screenshots are most of it, is the largest the controller holds)", name, maxWorkerJSON)
	}
	if stderr.exceeded {
		return nil, fmt.Errorf("%s error output exceeded %d bytes; the command was stopped", name, maxWorkerStderr)
	}
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if progress != nil {
			detail = streamedErrorDetail(detail, sshTransportFailed(err))
		}
		var kept []byte
		if keepStdout {
			kept = stdout.Bytes()
		}
		return kept, fmt.Errorf("%s failed: %w: %s", name, err, detail)
	}
	return stdout.Bytes(), nil
}

// streamedErrorDetail is what an error keeps of a streamed command's
// stderr. The operator has seen its progress events already, so they are
// dropped. When ssh lost the connection, only ssh's own reason, the last
// line, is kept: the rest is the run's earlier output, not the cause
// (one run ended with a 10 KB error line).
func streamedErrorDetail(stderr string, transportFailed bool) string {
	var lines []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), progresspkg.EventPrefix) {
			continue
		}
		// The worker's stderr is not the controller's: nothing in it drives
		// the operator's terminal.
		if line = progresspkg.SingleLine(line); line == "" {
			continue
		}
		lines = append(lines, line)
	}
	if transportFailed && len(lines) > 0 {
		// ssh's reason is its own last line. When that line is the worker's log
		// (the worker was killed, and ssh said nothing), there is no reason.
		lines = lines[len(lines)-1:]
		if isWorkerLogLine(lines[0]) {
			lines = nil
		}
	}
	detail := strings.Join(lines, "\n")
	if len(detail) > maxSSHErrorDetail {
		detail = "..." + detail[len(detail)-maxSSHErrorDetail:]
	}
	return detail
}

// sshTransportFailed reports whether ssh itself failed, which it signals
// with exit status 255: it could not connect, or it lost the connection.
// Any other status is the remote command's own.
func sshTransportFailed(err error) bool {
	var exit interface{ ExitCode() int }
	return errors.As(err, &exit) && exit.ExitCode() == 255
}

type bestEffortWriter struct{ target io.Writer }

func (w bestEffortWriter) Write(p []byte) (int, error) {
	if w.target != nil {
		_, _ = w.target.Write(p)
	}
	return len(p), nil
}

// limitedBuffer keeps the first limit bytes written to it and notes that it
// was given more. It holds its buffer in a field, not embedded: exec.Cmd
// copies a command's output with io.Copy, which uses the ReadFrom of a
// destination that has one, and an embedded bytes.Buffer's ReadFrom would
// have bypassed Write and the limit altogether.
type limitedBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
	// onExceeded, when set, is called once, when a write first goes over the
	// limit.
	onExceeded func()
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit > 0 && b.buf.Len()+len(p) > b.limit {
		remaining := b.limit - b.buf.Len()
		if remaining > 0 {
			_, _ = b.buf.Write(p[:remaining])
		}
		if !b.exceeded && b.onExceeded != nil {
			b.onExceeded()
		}
		b.exceeded = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *limitedBuffer) String() string { return b.buf.String() }

// Executor bootstraps and invokes a one-run node worker.
type Executor struct {
	runner commandRunner
}

// progressReporter serializes controller messages, worker stderr, and a
// heartbeat. It never receives worker stdout, which remains the protected JSON
// response channel. It renders into a bounded queue that a goroutine of its
// own writes to the operator's writer (progressSink), so that neither the
// command whose stderr it receives nor the control path ever waits for the
// writer, and it shows no more of a worker's progress than
// maxWorkerProgressBytes.
type progressReporter struct {
	sink          *progressSink
	mu            sync.Mutex
	startedAt     time.Time
	lastActivity  time.Time
	lastHeartbeat time.Time
	lastStage     string
	lastMessage   string
	// phaseStage ("Phase 4 of 9") and phaseStarted are the phase of the run
	// that began last, and when: the heartbeat says how long it has been going.
	phaseStage   string
	phaseStarted time.Time
	pending      []byte
	// budget is the most the worker's rendered progress may come to; shown is
	// what has been rendered, and suppressed the worker's events since then,
	// which are not.
	budget     int
	shown      int
	suppressed int
}

func newProgressReporter(writer io.Writer) *progressReporter {
	now := time.Now()
	return &progressReporter{sink: newProgressSink(writer), startedAt: now, lastActivity: now, budget: maxWorkerProgressBytes}
}

func (p *progressReporter) status(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.renderLocked("INFO", "", fmt.Sprintf(format, args...))
}

// notice shows a line of the controller's own as it is, one line whatever it
// holds: a warning about cleanup, for one, which has no time stamp or level.
func (p *progressReporter) notice(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sink.put(progresspkg.SingleLine(fmt.Sprintf(format, args...)) + "\n")
}

func (p *progressReporter) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending = append(p.pending, data...)
	for {
		newline := bytes.IndexByte(p.pending, '\n')
		if newline < 0 {
			break
		}
		line := strings.TrimSpace(string(p.pending[:newline]))
		p.pending = p.pending[newline+1:]
		event, ok := progresspkg.DecodeLine(line)
		if !ok {
			continue
		}
		p.renderWorkerEventLocked(event.Level, event.Stage, event.Message)
	}
	if len(p.pending) > maxPendingProgressBytes {
		// No newline has appeared within the bound, so this cannot be a
		// legitimate progress-event or worker-log line. Discard it instead of
		// growing without limit for the rest of the run; the bounded stderr
		// copy used for error reporting is unaffected.
		p.pending = nil
	}
	return len(data), nil
}

// renderWorkerEventLocked shows an event of the worker while its progress is
// within budget. The first event over it is said so once, and the rest are
// counted: the worker is the less trusted tier, and can say as much as the
// connection carries.
func (p *progressReporter) renderWorkerEventLocked(level, stage, message string) {
	line := p.lineLocked(level, stage, message)
	if p.shown+len(line) > p.budget {
		if p.suppressed == 0 {
			p.sink.put(fmt.Sprintf("warning: the node worker's progress is over the %d bytes the controller shows, so the rest of it is not shown. The run goes on; its report and the node's log have the detail\n", p.budget))
		}
		p.suppressed++
		return
	}
	p.shown += len(line)
	p.sink.put(line)
	p.lastActivity = time.Now()
	p.lastStage = stage
	p.lastMessage = message
	if runphase.IsStage(stage) {
		p.phaseStage, p.phaseStarted = stage, p.lastActivity
	}
}

// phase shows a phase of the run that is the controller's own, and notes when
// it began.
func (p *progressReporter) phase(announcement runphase.Announcement, note string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.renderLocked("INFO", announcement.Stage(), announcement.Message(note))
	p.phaseStage, p.phaseStarted = announcement.Stage(), p.lastActivity
}

func (p *progressReporter) renderLocked(level, stage, message string) {
	p.renderLineLocked(level, stage, message)
	p.lastActivity = time.Now()
	p.lastStage = stage
	p.lastMessage = message
}

func (p *progressReporter) renderLineLocked(level, stage, message string) {
	p.sink.put(p.lineLocked(level, stage, message))
}

func (p *progressReporter) lineLocked(level, stage, message string) string {
	elapsed := time.Since(p.startedAt).Round(time.Second)
	hours := int(elapsed / time.Hour)
	minutes := int(elapsed/time.Minute) % 60
	seconds := int(elapsed/time.Second) % 60
	stageLabel := ""
	if stage != "" {
		stageLabel = "[" + progresspkg.SingleLine(stage) + "] "
	}
	// Whatever a guest or the worker influenced in message is one line here,
	// so it cannot forge a line of the log.
	return fmt.Sprintf("[%02d:%02d:%02d] %s %s%s\n", hours, minutes, seconds, strings.ToUpper(progresspkg.SingleLine(level)), stageLabel, progresspkg.SingleLine(message))
}

func (p *progressReporter) success(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.renderLocked("SUCCESS", "", fmt.Sprintf(format, args...))
}

// warning shows a warning without making it the phase the heartbeat names.
func (p *progressReporter) warning(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.renderLineLocked("WARN", "", fmt.Sprintf(format, args...))
	p.lastActivity = time.Now()
}

func (p *progressReporter) failure(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.renderLocked("ERROR", "", fmt.Sprintf(format, args...))
}

// emit has fn write to the operator's writer itself, after the lines already
// rendered, and returns its error. It gives up after progressFlushTimeout:
// what a writer that does not answer is given then is lost, and saying so is
// the error.
func (p *progressReporter) emit(fn func(io.Writer) error) error {
	return p.sink.do(progressFlushTimeout, fn)
}

// close shows what is left and ends the reporter: nothing is written after
// it, unless the writer is stuck in a write it has not returned from. It
// returns what the writer did wrong, if anything, for a run that failed to
// add to its error: a run that passed is not failed by its terminal.
func (p *progressReporter) close() error {
	p.mu.Lock()
	if p.suppressed > 0 {
		p.sink.put(fmt.Sprintf("warning: %d events of the node worker's progress were not shown\n", p.suppressed))
		p.suppressed = 0
	}
	p.mu.Unlock()
	p.sink.close(progressFlushTimeout)
	return p.sink.problem()
}

func (p *progressReporter) startHeartbeat() func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				p.mu.Lock()
				if now.Sub(p.lastActivity) >= 30*time.Second && now.Sub(p.lastHeartbeat) >= 30*time.Second {
					p.renderLineLocked("INFO", "", p.heartbeatMessageLocked())
					p.lastHeartbeat = now
				}
				p.mu.Unlock()
			}
		}
	}()
	return func() { close(done) }
}

func (p *progressReporter) heartbeatMessageLocked() string {
	if p.lastMessage == "" {
		return "Still working on the node worker; no action is required."
	}
	// The last line is shown again as it was, less the time it said was left:
	// that was true when it was said, and the heartbeat repeats it later.
	phase := runphase.WithoutEstimate(p.lastMessage)
	if p.lastStage != "" {
		phase = "[" + p.lastStage + "] " + phase
	}
	message := "Still working: " + phase
	if p.phaseStage == "" {
		return message
	}
	// How long the phase has been going is the one time the controller can
	// give for work whose end it cannot see.
	elapsed := runphase.Elapsed(time.Since(p.phaseStarted))
	if p.lastStage == p.phaseStage {
		return fmt.Sprintf("%s (%s so far)", message, elapsed)
	}
	return fmt.Sprintf("%s (%s so far in %s)", message, elapsed, p.phaseStage)
}

// NewExecutor returns an SSH-backed controller executor.
func NewExecutor() *Executor {
	return &Executor{runner: osCommandRunner{}}
}

// Run uploads the controller binary and a narrowly scoped runtime environment
// to a mode-0700 /run directory, executes node-run, collects only its JSON
// evidence, then removes the temporary workspace. The report is signed and
// stored on the controller, so its private key never leaves the management
// host.
func (e *Executor) Run(ctx context.Context, opts RunOptions) (result *Result, retErr error) {
	if e == nil || e.runner == nil {
		return nil, errors.New("controller executor is not initialized")
	}
	if opts.SkipIntegrity && os.Getenv("CERTISTACK_ALLOW_TEST_MODE") != "1" {
		return nil, errors.New("SkipIntegrity requires CERTISTACK_ALLOW_TEST_MODE=1")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cleanupParent := opts.CleanupContext
	if cleanupParent == nil {
		cleanupParent = context.Background()
	}
	if err := validateOptions(&opts); err != nil {
		return nil, err
	}
	if opts.Writer == nil {
		opts.Writer = io.Discard
	}
	progress := newProgressReporter(opts.Writer)
	// The last thing Run does: what the writer did wrong is told in the error
	// of a run that failed, where an operator whose output has broken still
	// gets it, and is not made an error of a run that passed.
	defer func() {
		if problem := progress.close(); problem != nil && retErr != nil {
			retErr = errors.Join(retErr, problem)
		}
	}()
	runStartedAt := time.Now()
	progress.status("Preparing validation on PVE node %q.", opts.NodeName)

	// The plan is read once: the digest the report records is of the
	// very bytes this run's plan was parsed from (plan_sha256).
	plan, planSHA256, err := config.LoadFromFileWithDigest(opts.PlanPath)
	if err != nil {
		return nil, fmt.Errorf("load validation plan: %w", err)
	}
	if err := resolveScratchDir(&opts, plan); err != nil {
		return nil, err
	}
	// A sandbox range that holds the PVE API or the PBS server by address is
	// refused here, before a worker is staged: the node routes the whole range
	// to the sandbox once the probe address is up, and the run would lose its
	// connection. The node checks again, resolving names as it does.
	repository := os.Getenv("PBS_REPOSITORY")
	if repository == "" {
		repository = plan.Storage.PBSRepository
	}
	if err := preflight.CheckSandboxRangeByAddress(ctx, plan, os.Getenv("PVE_URL"), repository); err != nil {
		return nil, interruptedBeforeWorker(ctx, progress, opts.NodeName, err)
	}
	// Check what the controller needs after the run before it contacts the
	// node: an unwritable report directory found only after validation would
	// lose the evidence with the workspace.
	if err := checkReportDirectoryWritable(opts.OutputDir, plan.PlanID); err != nil {
		return nil, err
	}
	localStage, err := os.MkdirTemp("", "certistack-controller-")
	if err != nil {
		return nil, fmt.Errorf("create controller staging directory in %s (set TMPDIR to a writable private directory, such as the controller container's /tmp/certistack tmpfs): %w", os.TempDir(), err)
	}
	defer os.RemoveAll(localStage)
	if err := os.Chmod(localStage, 0700); err != nil {
		return nil, fmt.Errorf("secure controller staging directory: %w", err)
	}
	if err := e.checkNodeArchitecture(ctx, opts.SSH); err != nil {
		return nil, interruptedBeforeWorker(ctx, progress, opts.NodeName, err)
	}
	// A report from a node whose clock is too far from the controller's is
	// refused when the run ends, with the evidence of the whole run: find that
	// out before anything is started on the node.
	if err := e.checkNodeClock(ctx, opts.SSH, opts.NodeName, progress); err != nil {
		return nil, interruptedBeforeWorker(ctx, progress, opts.NodeName, err)
	}

	workspaceRoot, err := workerWorkspaceRoot(opts.StateDir)
	if err != nil {
		return nil, err
	}
	workspace := path.Join(workspaceRoot, uuid.NewString())
	staging := path.Join("/tmp", "certistack-controller-"+path.Base(workspace))
	workspaceRemovable := true
	// keepWorkspaceForLog is set when the node said it could not keep the
	// recovery log beside its journal: the workspace's progress file is the
	// log's only other copy, so the controller never removes the workspace
	// then, and removes its credentials instead.
	keepWorkspaceForLog := false
	// nodeUnreachable is set once cleanup gave up on a node that did not
	// answer: nothing more is tried over SSH.
	nodeUnreachable := false
	// warn is one line of the operator's output, whatever error text it holds.
	warn := func(format string, args ...any) {
		progress.notice(format, args...)
	}
	defer func() {
		if nodeUnreachable {
			warn("warning: node %s cannot be reached, so the controller removed nothing there. If the node still has this run's workspace (%s), its next CertiStack run recovers what the run left, then removes the workspace's credentials.", opts.NodeName, workspace)
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var cleanupErrs []error
		if workspaceRemovable && keepWorkspaceForLog {
			warn("warning: retaining temporary node workspace %s: the node could not keep this run's recovery log, and its worker-progress.log is the log's only copy; removing only the workspace's credentials", workspace)
			if cleanupErr := e.scrubWorkspaceCredentials(cleanupCtx, opts.SSH, workspaceRoot, workspace, "the node could not keep this run's recovery log, so its workspace, which holds the log, was kept"); cleanupErr != nil {
				warn("warning: could not remove the credentials from the retained workspace %s: %v", workspace, cleanupErr)
				cleanupErrs = append(cleanupErrs, cleanupErr)
			}
		} else if workspaceRemovable {
			if cleanupErr := e.removeWorkspace(cleanupCtx, opts.SSH, workspaceRoot, workspace); cleanupErr != nil {
				warn("warning: could not remove temporary node workspace %s: %v", workspace, cleanupErr)
				cleanupErrs = append(cleanupErrs, cleanupErr)
			}
		} else {
			warn("warning: retaining temporary node workspace %s because automatic resource cleanup could not be verified", workspace)
			// Recovery needs the retained worker and its environment, never the
			// backup encryption key, which decrypts every backup made with it.
			if os.Getenv("CERTISTACK_PBS_KEYFILE") != "" {
				if cleanupErr := e.removeRetainedKey(cleanupCtx, opts.SSH, workspaceRoot, workspace); cleanupErr != nil {
					warn("warning: could not remove the PBS encryption key from the retained workspace %s: %v", workspace, cleanupErr)
					cleanupErrs = append(cleanupErrs, cleanupErr)
				}
			}
		}
		if cleanupErr := e.removeStaging(cleanupCtx, opts.SSH, staging); cleanupErr != nil {
			warn("warning: could not remove temporary SSH staging directory: %v", cleanupErr)
			cleanupErrs = append(cleanupErrs, cleanupErr)
		}
		if len(cleanupErrs) > 0 {
			cleanupErr := fmt.Errorf("%w: %w", ErrControllerMaterialCleanupUnverified, errors.Join(cleanupErrs...))
			if retErr == nil {
				retErr = cleanupErr
			} else {
				retErr = errors.Join(retErr, cleanupErr)
			}
		}
	}()

	if err := e.stageWorkspace(ctx, opts, plan, localStage, workspaceRoot, workspace, staging); err != nil {
		return nil, interruptedBeforeWorker(ctx, progress, opts.NodeName, err)
	}
	// The report names the executable that was uploaded to run as the
	// worker, so its build identity (a label) can be checked against a digest.
	workerSHA256, err := fileSHA256(filepath.Join(localStage, stagedWorkerName))
	if err != nil {
		return nil, fmt.Errorf("record the worker executable digest: %w", err)
	}
	opts.Build.ExecutableSHA256 = workerSHA256
	progress.status("Temporary node worker staged; streaming node phases below.")

	opts.sshClient = e.nodeSSHClient(ctx, opts.SSH)
	nodeRunCommand := buildNodeRunCommand(workspace, opts)
	leasePath := path.Join(workspace, "controller.lease")
	if err := e.createWorkerLease(ctx, opts.SSH, workspaceRoot, workspace, leasePath); err != nil {
		return nil, interruptedBeforeWorker(ctx, progress, opts.NodeName, err)
	}
	workerUnit, err := workerUnitName(workspaceRoot, workspace)
	if err != nil {
		return nil, err
	}
	// The node's boot ID tells, after contact is lost, whether it rebooted.
	bootID := e.nodeBootID(ctx, opts.SSH)
	// Lease warnings concern the run; once it has ended, cleanup reports.
	var workerEnded atomic.Bool
	stopLease := e.startWorkerLease(cleanupParent, opts.SSH, workspaceRoot, workspace, leasePath, func(format string, args ...interface{}) {
		if !workerEnded.Load() {
			progress.warning(format, args...)
		}
	})
	defer stopLease()
	workerCommand := e.supervisedWorkerCommand(
		opts.SSH,
		workerUnit,
		workspaceRoot,
		workspace,
		path.Join(workspace, "worker.pid"),
		leasePath,
		opts.StateDir,
		path.Join(workspace, "runtime.env"),
		path.Join(workspace, "worker-result.json"),
		path.Join(workspace, "worker-progress.log"),
		nodeRunCommand,
	)
	stopHeartbeat := progress.startHeartbeat()
	resultData, err := e.remoteCommandWithProgress(ctx, opts.SSH, workerCommand, progress)
	// ssh that never connected never started the worker, so it is started
	// again. Were it started after all, its unit name is the run's own and a
	// second start fails instead of running twice.
	for _, wait := range setupRetries {
		if err == nil || ctx.Err() != nil || !workerNeverStarted(err) {
			break
		}
		progress.warning("Could not start the worker on node %s (%s); trying again in %s.", opts.NodeName, sshReason(err), roughly(wait))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
			resultData, err = e.remoteCommandWithProgress(ctx, opts.SSH, workerCommand, progress)
		}
	}
	stopHeartbeat()
	workerEnded.Store(true)
	// A worker that reported success but whose result cannot be used may
	// have reached allocation, or finished its cleanup, without saying so:
	// its journal is checked, and recovered when it is not clean, before the
	// workspace goes, as for a worker whose connection was lost.
	// The same holds for a worker that reports it refused the run: the
	// controller does not take its word that it created nothing.
	var nodeResult nodeapi.RunResult
	if err == nil {
		nodeResult, err = decodeNodeResult(resultData)
	}
	if err != nil {
		contact := nodeContact{name: opts.NodeName, bootID: bootID, progress: progress}
		contact.workerStuck = remoteStatus(err) == supervisorWorkerStuckStatus
		if remoteStatus(err) == supervisorLogNotKeptStatus || strings.Contains(err.Error(), recoveryLogNotKeptMessage) {
			keepWorkspaceForLog = true
			progress.failure("The node could not keep this run's recovery log. Its workspace on node %s, whose worker-progress.log is the log's only copy, is kept; the controller removes only its credentials.", opts.NodeName)
		}
		neverStarted := ctx.Err() == nil && workerNeverStarted(err)
		reconnected := false
		if neverStarted {
			progress.failure("Could not start the worker on node %s: %s. Checking that nothing was left there.", opts.NodeName, sshReason(err))
		} else if ctx.Err() == nil && sshTransportFailed(err) {
			if e.nodeAnswersAtOnce(ctx, opts.SSH) {
				// The node is up: its worker ended, or only the connection was cut.
				reconnected = true
				progress.failure("The ssh connection to node %s ended, but the node answers: it has not crashed or lost its network. Checking what the worker left.", opts.NodeName)
			} else {
				contact.lost = true
				progress.failure("Lost contact with node %s: %s. The node may have crashed, rebooted or lost its network. Its temporary resources are cleaned up as soon as it answers; waiting up to %s.", opts.NodeName, sshReason(err), roughly(interruptionCleanupTimeout))
			}
		}
		var found journalOutcome
		contact.outcome = &found
		cleanupCtx, cancel := context.WithTimeout(cleanupParent, interruptionCleanupTimeout)
		selfCleaned, cleanupErr := e.reconcileInterruptedWorker(cleanupCtx, opts.SSH, workspaceRoot, workspace, opts.StateDir, contact)
		cancel()
		// A run that returned no evidence is not signed for, and a journal
		// with no record of it means it recorded no resource: said as that,
		// not as a recovery that did not happen.
		reconciled := "temporary node resources were reconciled before exit"
		if found.noRecord {
			reconciled = "the node's journal holds no record of this run, so it had created no temporary resources"
		}
		if cleanupErr != nil {
			workspaceRemovable = false
			var unreachable *nodeUnreachableError
			if errors.As(cleanupErr, &unreachable) {
				nodeUnreachable = true
				recoverCommand := e.recoverCommand(opts.SSH, workspace, opts.StateDir)
				progress.failure("Node %s did not answer within %s, so this run's temporary resources could not be cleaned up from here. If the node is running but unreachable, it stops the run and cleans up by itself once the worker's lease is %d s old. If it rebooted, its next CertiStack run recovers them before it starts; to recover them sooner, run on the node: %s", opts.NodeName, roughly(unreachable.waited), workerLeaseDurationSeconds, strings.Join(recoverCommand, " "))
				if contact.lost {
					return nil, fmt.Errorf("lost contact with node %s during the run, and it %w", opts.NodeName, unreachable)
				}
				return nil, fmt.Errorf("could not clean up after the run: node %s %w", opts.NodeName, unreachable)
			}
			if errors.Is(cleanupErr, errWorkerStillRunning) {
				progress.failure("The node worker on %s cannot be stopped: it is still running after SIGTERM and SIGKILL, which only a process stuck in the kernel (for example in uninterruptible I/O) survives. Its journal and workspace are kept, and nothing is recovered while it runs, because it may run on and use what recovery would remove. Once it has ended, the node recovers the run's journal by itself; until then the node's host lock stays held, and no CertiStack run or recovery can start there. Check the node's storage and, if the process does not end, reboot the node: its next CertiStack run then recovers the journal.", opts.NodeName)
				return nil, fmt.Errorf("the node worker on %s could not be stopped and its temporary resources are not cleaned up: %w", opts.NodeName, cleanupErr)
			}
			progress.failure("Automatic interruption cleanup could not be verified: %v", cleanupErr)
			return nil, fmt.Errorf("node worker connection ended and automatic cleanup could not be verified: %w", cleanupErr)
		}
		if ctx.Err() != nil {
			progress.failure("Controller interruption received; %s.", reconciled)
			return nil, ctx.Err()
		}
		if reconnected {
			if message, endErr, ok := workerEnd(opts.NodeName, workerUnit, found.workerStop, reconciled, err); ok {
				progress.failure("%s", message)
				return nil, endErr
			}
		}
		if contact.lost && selfCleaned {
			progress.failure("The run on node %s ended when contact was lost. Once the worker's lease expired, the node stopped the run and cleaned up by itself; its journal confirms it.", opts.NodeName)
			return nil, fmt.Errorf("lost contact with node %s during the run: %w", opts.NodeName, err)
		}
		if contact.lost {
			if found.noRecord {
				progress.failure("The run on node %s ended when contact was lost; %s.", opts.NodeName, reconciled)
			} else {
				progress.failure("The run on node %s ended when contact was lost; its temporary resources were reconciled once the node answered.", opts.NodeName)
			}
			return nil, fmt.Errorf("lost contact with node %s during the run: %w", opts.NodeName, err)
		}
		if neverStarted {
			return nil, fmt.Errorf("could not start the worker on node %s: %w", opts.NodeName, err)
		}
		var unusable *unusableResultError
		if errors.As(err, &unusable) {
			progress.failure("The node worker's result cannot be used (%s), so no report was written. Its journal was checked before the workspace was removed: %s.", unusable.reason, reconciled)
			return nil, fmt.Errorf("node worker returned an unusable result: %w", err)
		}
		var refused *workerRefusedError
		if errors.As(err, &refused) {
			progress.failure("Node worker refused validation before evidence could be created: %s", refused.reason)
			return nil, fmt.Errorf("node worker failed before producing evidence: %s", refused.reason)
		}
		if contact.workerStuck {
			progress.failure("The node worker on %s did not end after SIGKILL, but has ended since; its journal was recovered.", opts.NodeName)
			return nil, fmt.Errorf("the node worker on %s did not end after SIGKILL: %w", opts.NodeName, err)
		}
		progress.failure("Node worker connection ended; %s.", reconciled)
		return nil, fmt.Errorf("run node worker: %w", err)
	}
	// The controller checks teardown on every run against this run's own
	// record on the node rather than signing the worker's report on its word
	// alone: a faulty, replayed or mismatched worker report (all_cleaned: true
	// while a restored VM, its overlay or its loop device is still live, or
	// another run's record) is not signed as a clean teardown. The check
	// reads the node's own files, which the root worker also writes, so it
	// does not stand against a worker that is itself hostile: the node, where
	// the worker runs as root, is trusted, and the controller makes no
	// independent observation of the node's resources here.
	// reconcileCompletedWorker's underlying "<worker> recover"
	// call is a fast, safe no-op when the worker's own durable journal is
	// already phase "cleaned"; it performs real reconciliation only when it
	// is not, so this adds no meaningful cost to the common successful case.
	evidence := nodeResult.Report.TeardownEvidence
	if evidence == nil {
		evidence = &attest.TeardownEvidence{}
		nodeResult.Report.TeardownEvidence = evidence
	}
	// The run's last phase is the controller's own. The list is the node
	// worker's, worked out from the same plan, so the numbers agree.
	if announcement, ok := runphase.NewTracker(runphase.Steps(plan, runphase.Options{SkipIntegrity: opts.SkipIntegrity})).Begin(runphase.Signing, 0); ok {
		progress.phase(announcement, "")
	}
	progress.status("Independently verifying the node worker's durable resource journal before writing the report.")
	cleanupCtx, cancel := context.WithTimeout(cleanupParent, interruptionCleanupTimeout)
	teardownErr := e.reconcileCompletedWorker(cleanupCtx, opts.SSH, workspaceRoot, workspace, opts.StateDir, journalCheck{
		runID: workerRunID(workspace),
		waiting: func() {
			progress.status("Another CertiStack operation holds the node's host lock; waiting to verify this run's journal.")
		},
		progress: progress,
	})
	cancel()
	if teardownErr != nil {
		// The workspace includes the exact runtime environment needed for a
		// later safe retry. Do not erase that evidence or credentials until
		// every journaled resource has been proven absent.
		workspaceRemovable = false
		var unproven *journalUnprovenError
		if errors.As(teardownErr, &unproven) {
			progress.failure("The controller cannot verify that this run cleaned up after itself: %s. Whether resources remain is not known; the report records the cleanup as unverified (all_cleaned and journal_recovery_verified false). The protected node workspace is kept for now; the node removes it, or at least its credentials, once this controller has been gone for %d s. On node %s, check the recovery journal (certistack inspect --state-dir %s) and the cluster for this run's sandbox VM, overlays and maps.",
				unproven.reason, workerLeaseDurationSeconds, opts.NodeName, opts.StateDir)
		} else {
			progress.failure("Some temporary resources could not be removed%s. The protected node workspace is kept so they can be recovered: on node %s, run: %s. Once this controller has been gone for %d s, the node retries the recovery by itself, then removes the workspace, or, if the recovery fails again, the workspace's credentials. The node's next CertiStack run tries this recovery first and refuses to start if it fails. The report's cleanup errors and the node's %s have the details.",
				leftoverSteps(evidence.CleanupErrors), opts.NodeName, strings.Join(e.recoverCommand(opts.SSH, workspace, opts.StateDir), " "), workerLeaseDurationSeconds, path.Join(opts.StateDir, "logs", path.Base(workspace)+".log"))
		}
		// The signed report must reflect what the controller could verify,
		// never what the worker merely claimed: overwrite any all_cleaned:
		// true the worker may have reported, so that a faulty, replayed or
		// mismatched worker report does not become a signed "clean teardown"
		// attestation the controller was unable to confirm against the
		// node's journal.
		evidence.AllCleaned = false
		evidence.OrphanSweepClean = false
		evidence.JournalRecoveryVerified = false
		evidence.CleanupErrors = append(evidence.CleanupErrors, teardownErr.Error())
	} else {
		evidence.InitialCleanupErrors = append(evidence.InitialCleanupErrors, evidence.CleanupErrors...)
		evidence.AllCleaned = true
		evidence.OrphanSweepClean = true
		evidence.CleanupErrors = nil
		evidence.JournalRecoveryVerified = true
		evidence.VerifiedAt = time.Now().UTC().Format(time.RFC3339)
		progress.status("Journal recovery verified: all recorded temporary resources are clean.")
	}
	// The worker's report is signed as the controller's own words, so it
	// must be what was asked for: this run, on this node, in the requested
	// mode, for the plan's population.
	if reportErr := checkWorkerReport(nodeResult.Report, reportExpectation{
		plan: plan, node: opts.NodeName, runID: workerRunID(workspace), skipIntegrity: opts.SkipIntegrity,
		startedAt: runStartedAt, now: time.Now(), workerError: nodeResult.Error,
	}); reportErr != nil {
		progress.failure("The node worker's report was refused, and no report was written: %v. %s", reportErr, keepRefusedResult(opts.OutputDir, workerRunID(workspace), reportErr, resultData))
		if teardownErr != nil {
			return nil, fmt.Errorf("%w; the run's temporary resource cleanup could not be verified either: %s", reportErr, lastErrorLine(teardownErr))
		}
		return nil, reportErr
	}
	// A run whose cleanup this controller could not verify did not pass,
	// whatever its VMs showed: all_passed says so too, as the worker's own
	// verdict does when it cannot prove its cleanup (runner's
	// requireVerifiedTeardown). The worker's report was checked above as it
	// came; its VM records keep what they showed.
	if teardownErr != nil && nodeResult.Report.AllPassed {
		nodeResult.Report.AllPassed = false
		if nodeResult.Report.FailureReason == "" {
			nodeResult.Report.FailureReason = unverifiedCleanupReason
		} else {
			nodeResult.Report.FailureReason += "; " + unverifiedCleanupReason
		}
	}
	progress.status("Node worker returned validation evidence; writing the report.")

	reportPath, err := prepareReport(nodeResult.Report, plan.PlanID, planSHA256, opts)
	if err != nil {
		var refusal refusedReportError
		var signing signingFailedError
		switch {
		case errors.As(err, &refusal):
			progress.failure("The node worker's report was refused, and no report was written: %v. %s", err, keepRefusedResult(opts.OutputDir, workerRunID(workspace), err, resultData))
		case errors.As(err, &signing):
			// The run happened and its resources are gone; the report is not
			// written unsigned in the place of the one that could not be signed.
			progress.failure("The report could not be signed, so none was written: %v. %s", err, keepUnsignedResult(opts.OutputDir, workerRunID(workspace), err, resultData))
		}
		return nil, err
	}
	if err := nodeResult.Report.Save(reportPath); err != nil {
		// The report directory was writable before the run, so this is a
		// late failure such as a full disk. The worker's result is removed
		// with the node workspace, so keep the report recoverable: return it
		// and print it, whole, on the progress stream.
		saveErr := fmt.Errorf("save controller report %s: %w", reportPath, err)
		if teardownErr != nil {
			saveErr = fmt.Errorf("%w; the run's temporary resource cleanup could not be verified either: %s", saveErr, lastErrorLine(teardownErr))
		}
		progress.failure("%v. The complete report follows; save the JSON between the markers, read it with report show, and check it with verify-report.", saveErr)
		// The progress stream is best effort, but this copy may be the only
		// one there is: what keeps it from being written is an error of the
		// run.
		if emitErr := progress.emit(func(w io.Writer) error { return WriteUnsavedReport(w, nodeResult.Report) }); emitErr != nil {
			saveErr = errors.Join(saveErr, fmt.Errorf("%w (%v); the report exists only in memory, as Result.Report", ErrEmergencyReportNotWritten, emitErr))
		}
		return &Result{Report: nodeResult.Report}, saveErr
	}
	if teardownErr != nil {
		// The error's detail is the recovery's whole output; its last line
		// is what failed, and the report and the node's log keep the rest.
		progress.failure("Report saved at %s; temporary resource cleanup could not be verified: %s", reportPath, lastErrorLine(teardownErr))
		return &Result{Report: nodeResult.Report, ReportPath: reportPath}, fmt.Errorf("DR validation ended with unverified temporary resource cleanup: %s", lastErrorLine(teardownErr))
	}
	if nodeResult.Error == "" && !nodeResult.Report.AllPassed {
		// Never announce or return success for a report that does not claim
		// a pass, even if an older or misbehaving worker omitted the error.
		nodeResult.Error = progresspkg.SingleLine(nodeResult.Report.FailureReason)
		if nodeResult.Error == "" {
			nodeResult.Error = "validation report does not record a pass"
		}
	}
	if strings.HasPrefix(nodeResult.Error, "interrupted") {
		// A signal stopped the worker (the node shutting down, or an
		// operator): the run was interrupted, not failed.
		interrupted := &NodeInterruptedError{Reason: nodeResult.Error}
		progress.failure("Report saved at %s; the run was interrupted: %s", reportPath, interrupted)
		return &Result{Report: nodeResult.Report, ReportPath: reportPath}, interrupted
	}
	if nodeResult.Error != "" {
		progress.failure("Report saved at %s; validation failed: %s", reportPath, nodeResult.Error)
		return &Result{Report: nodeResult.Report, ReportPath: reportPath}, fmt.Errorf("DR validation failed: %s", nodeResult.Error)
	}
	if nodeResult.Report.ValidationMode == attest.ValidationModeTestSkipIntegrity {
		progress.status("Test-only mode skipped full mapped-PBS integrity verification; this report is not production compliance evidence.")
		progress.success("Service recovery smoke test passed | duration: %.1fs | report: %s", nodeResult.Report.RTOSeconds, reportPath)
	} else {
		progress.success("DR validation plan passed | duration: %.1fs | report: %s", nodeResult.Report.RTOSeconds, reportPath)
	}
	return &Result{Report: nodeResult.Report, ReportPath: reportPath}, nil
}

// unusableResultError is a worker result the controller cannot decode: it is
// empty, is not JSON, or names neither a report nor an error.
type unusableResultError struct {
	reason string
}

func (e *unusableResultError) Error() string { return e.reason }

// workerRefusedError is a worker that says it refused the run before it made
// any evidence.
type workerRefusedError struct {
	reason string
}

func (e *workerRefusedError) Error() string { return e.reason }

// maxUnusableResultSample bounds how much of a result the controller cannot
// decode an error and the operator's terminal show.
const maxUnusableResultSample = 200

// decodeNodeResult decodes a worker's result. It fails with an
// *unusableResultError for output that is not a result, and with a
// *workerRefusedError for a result that has an error and no report: neither
// leaves evidence to sign, and both need the journal check before the
// workspace is removed.
func decodeNodeResult(data []byte) (nodeapi.RunResult, error) {
	var result nodeapi.RunResult
	if len(bytes.TrimSpace(data)) == 0 {
		return result, &unusableResultError{reason: "it is empty"}
	}
	if err := json.Unmarshal(data, &result); err != nil {
		sample := data
		if len(sample) > maxUnusableResultSample {
			sample = sample[:maxUnusableResultSample]
		}
		return nodeapi.RunResult{}, &unusableResultError{reason: fmt.Sprintf("%v; it begins %q", err, sample)}
	}
	// The error is the worker's word, and it ends in the operator's log and
	// in this command's error: one line, whatever it holds.
	result.Error = progresspkg.SingleLine(result.Error)
	if result.Report == nil {
		if result.Error == "" {
			return nodeapi.RunResult{}, &unusableResultError{reason: "it has neither a report nor an error"}
		}
		return nodeapi.RunResult{}, &workerRefusedError{reason: result.Error}
	}
	return result, nil
}

// remoteStatus is the exit status of the remote command a failed ssh ran, or
// -1 when there is none. 255 is ssh's own.
func remoteStatus(err error) int {
	var exit interface{ ExitCode() int }
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}

type stagedFile struct {
	local      string
	remoteName string
	mode       string
}

func writeWorkerPlan(path string, plan *config.Plan) error {
	data, err := config.MarshalWorkerPlan(plan)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write plan: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("secure plan: %w", err)
	}
	return nil
}

func validateOptions(opts *RunOptions) error {
	if err := validateTarget(opts); err != nil {
		return err
	}
	if opts.OutputDir == "" {
		opts.OutputDir = "/var/lib/certistack/reports"
	}
	if err := pathOptionProblem("--output", opts.OutputDir, true); err != nil {
		return err
	}
	return nil
}

// pathOptionProblem says what is wrong with a path option that must be a
// clean absolute path, or nil when it is one: the flag and the value as the
// operator gave them, and what to give instead. A local path (the controller's)
// is made absolute from the working directory; a remote one (the node's) has no
// working directory to start from here, so only its form is said.
func pathOptionProblem(flag, value string, local bool) error {
	shown := shownPathValue(value)
	switch {
	case strings.ContainsAny(value, "\x00\r\n"):
		return fmt.Errorf("%s %s holds a control character", flag, shown)
	case !local && strings.Contains(value, "\\"):
		return fmt.Errorf("%s %s holds a backslash", flag, shown)
	case value == "/":
		return fmt.Errorf("%s / must be a directory of its own, not the root", flag)
	case local && !filepath.IsAbs(value):
		if abs, err := filepath.Abs(value); err == nil {
			return fmt.Errorf("%s %s is not an absolute path; use %s", flag, shown, shownPathValue(abs))
		}
		return fmt.Errorf("%s %s is not an absolute path; start it with /", flag, shown)
	case !local && !strings.HasPrefix(value, "/"):
		return fmt.Errorf("%s %s is not an absolute path on the node; start it with /, as in %s", flag, shown, remotePathExample(flag))
	case local && (filepath.Clean(value) != value || strings.Contains(value, "..")):
		return fmt.Errorf("%s %s is not a clean path (no .., //, ./ or trailing /); use %s", flag, shown, shownPathValue(filepath.Clean(value)))
	case !local && (path.Clean(value) != value || strings.Contains(value, "..")):
		return fmt.Errorf("%s %s is not a clean path (no .., //, ./ or trailing /); use %s", flag, shown, shownPathValue(path.Clean(value)))
	}
	return nil
}

// absolutePathProblem is pathOptionProblem for a local path that need only be
// absolute (the ssh files).
func absolutePathProblem(flag, value string) error {
	if filepath.IsAbs(value) {
		return nil
	}
	if abs, err := filepath.Abs(value); err == nil {
		return fmt.Errorf("%s %s is not an absolute path; use %s", flag, shownPathValue(value), shownPathValue(abs))
	}
	return fmt.Errorf("%s %s is not an absolute path; start it with /", flag, shownPathValue(value))
}

// remotePathExample is a path on the node that fits the flag.
func remotePathExample(flag string) string {
	if flag == "--state-dir" {
		return "/var/lib/certistack"
	}
	return defaultRemoteScratchDir
}

// shownPathValue is a path as it is shown in a message: as given, or quoted
// when it holds a space, a quote or a control character, so that none of them
// reaches the operator's terminal.
func shownPathValue(value string) string {
	for _, r := range value {
		if r <= ' ' || r == '"' || r == '\'' || r == 0x7f {
			return strconv.Quote(value)
		}
	}
	return value
}

// validateTarget checks what every controller operation on a node needs:
// the plan, the node, SSH and the remote paths. A plan writes no report, so
// it needs no output directory.
func validateTarget(opts *RunOptions) error {
	if opts == nil {
		return errors.New("controller run options are required")
	}
	if strings.TrimSpace(opts.PlanPath) == "" {
		return errors.New("plan path is required")
	}
	return validateNode(opts)
}

// validateNode checks what an operation on a node needs besides a plan:
// the node, SSH and the remote paths.
func validateNode(opts *RunOptions) error {
	if strings.TrimSpace(opts.NodeName) == "" {
		return errors.New("PVE node name is required")
	}
	if !pveNodeExpr.MatchString(opts.NodeName) {
		return fmt.Errorf("invalid PVE node name %+q", opts.NodeName)
	}
	// Before any I/O: a typed value the worker would refuse is refused here.
	if err := checkInheritedTypedEnvironment(); err != nil {
		return err
	}
	if err := validateSSHConfig(opts.SSH); err != nil {
		return err
	}
	if opts.StateDir == "" {
		opts.StateDir = "/var/lib/certistack"
	}
	if opts.ScratchDir != "" {
		if err := pathOptionProblem("--scratch", opts.ScratchDir, false); err != nil {
			return err
		}
	}
	if err := pathOptionProblem("--state-dir", opts.StateDir, false); err != nil {
		return err
	}
	if err := refuseSharedTemporaryDirectory("state", opts.StateDir); err != nil {
		return err
	}
	if err := refuseSharedTemporaryDirectory("scratch", opts.ScratchDir); err != nil {
		return err
	}
	if opts.OverlayStorage != "" && !config.ValidPVEStorageID(opts.OverlayStorage) {
		return fmt.Errorf("invalid overlay storage ID %q", opts.OverlayStorage)
	}
	return nil
}

// defaultRemoteScratchDir is used when neither --scratch (or
// CERTISTACK_SCRATCH_DIR) nor the plan's storage.scratch_dir names one.
const defaultRemoteScratchDir = "/var/lib/certistack/scratch"

// resolveScratchDir applies the documented precedence: an explicit flag or
// environment value, then the plan's storage.scratch_dir, then the default.
func resolveScratchDir(opts *RunOptions, plan *config.Plan) error {
	opts.ScratchDir = config.EffectiveScratchDir(opts.ScratchDir, plan, defaultRemoteScratchDir)
	if err := pathOptionProblem("--scratch", opts.ScratchDir, false); err != nil {
		return err
	}
	return refuseSharedTemporaryDirectory("scratch", opts.ScratchDir)
}

// refuseSharedTemporaryDirectory refuses a node state or scratch directory
// (what) that is one of the node's shared temporary directories.
func refuseSharedTemporaryDirectory(what, p string) error {
	for _, shared := range sharedTemporaryDirectories {
		if p == shared {
			return fmt.Errorf("%s is a shared temporary directory and cannot be the node's %s directory; choose a private path, such as the default under /var/lib/certistack", p, what)
		}
	}
	return nil
}

func safeRemoteAbsolutePath(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.Contains(p, "..") && !strings.ContainsAny(p, "\x00\r\n\\") && p != "/"
}

func safeLocalAbsolutePath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.Contains(p, "..") && !strings.ContainsAny(p, "\x00\r\n") && p != "/" && p != `\`
}

func buildNodeRunCommand(workspace string, opts RunOptions) []string {
	command := []string{
		path.Join(workspace, "certistack-node"), "node-run",
		"--plan", path.Join(workspace, "plan.yaml"),
		"--node", opts.NodeName,
		"--scratch", opts.ScratchDir,
		"--state-dir", opts.StateDir,
		"--output", path.Join(workspace, "reports"),
		"--env-file", path.Join(workspace, "runtime.env"),
		"--run-id", workerRunID(workspace),
	}
	if opts.OverlayStorage != "" {
		command = append(command, "--overlay-storage", opts.OverlayStorage)
	}
	if opts.SkipIntegrity {
		command = append(command, "--skip-integrity")
	}
	if opts.sshClient != "" {
		command = append(command, "--ssh-client", opts.sshClient)
	}
	return command
}

// workerWorkspaceRoot intentionally lives beneath the node state directory,
// rather than /run. Hardened PVE hosts commonly mount /run with noexec; the
// state directory is the already-approved worker-owned execution area and is
// cleaned after each run.
func workerWorkspaceRoot(stateDir string) (string, error) {
	root := path.Join(stateDir, "workers")
	if !safeRemoteAbsolutePath(root) {
		return "", errors.New("node worker workspace root must be a clean non-root absolute path")
	}
	return root, nil
}

// ValidSSHHost is whether host can be the SSH host of a controller: a host name
// or an address, of letters, digits, '.', '-' and ':', starting with a letter or
// a digit so that it can never read as an option. An IPv6 address is written
// without brackets; one in brackets starts with '[' and is refused. `certistack
// check` judges CERTISTACK_SSH_HOST with it in layer 1, by the rule every
// connection applies.
func ValidSSHHost(host string) bool { return sshHostExpr.MatchString(host) }

// ValidSSHUser is whether user can be the SSH account of a controller: a Unix
// user name of at most 32 characters.
func ValidSSHUser(user string) bool { return sshUserExpr.MatchString(user) }

func validateSSHConfig(cfg SSHConfig) error {
	if !sshHostExpr.MatchString(cfg.Host) {
		return fmt.Errorf("invalid SSH host %s", envtypes.Quoted(cfg.Host))
	}
	if !sshUserExpr.MatchString(cfg.User) {
		return fmt.Errorf("invalid SSH user %s", envtypes.Quoted(cfg.User))
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("invalid SSH port %d", cfg.Port)
	}
	if cfg.KnownHostsFile == "" {
		return errors.New("an absolute SSH known_hosts path is required (--ssh-known-hosts)")
	}
	if err := absolutePathProblem("--ssh-known-hosts", cfg.KnownHostsFile); err != nil {
		return err
	}
	if info, err := os.Stat(cfg.KnownHostsFile); err != nil {
		return fmt.Errorf("read SSH known_hosts file: %w", err)
	} else if info.IsDir() {
		return errors.New("SSH known_hosts path must be a file")
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("SSH known_hosts path %s is not a regular file but %s, which ssh would wait on; point CERTISTACK_SSH_KNOWN_HOSTS at the file itself", cfg.KnownHostsFile, sysutil.FileKind(info.Mode()))
	} else if err := sysutil.UnsafeToTrust(cfg.KnownHostsFile, info, sysutil.KnownHostsWhat, sysutil.KnownHostsRisk); err != nil {
		return err
	}
	if cfg.IdentityFile != "" {
		if err := absolutePathProblem("--ssh-identity", cfg.IdentityFile); err != nil {
			return err
		}
		if info, err := os.Stat(cfg.IdentityFile); err != nil {
			return fmt.Errorf("read SSH identity file: %w", err)
		} else if info.IsDir() {
			return errors.New("SSH identity path must be a file")
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("SSH identity path %s is not a regular file but %s, which ssh would wait on; point CERTISTACK_SSH_IDENTITY at the private key file", cfg.IdentityFile, sysutil.FileKind(info.Mode()))
		} else if err := sysutil.UnsafeToTrust(cfg.IdentityFile, info, sysutil.IdentityWhat, sysutil.IdentityRisk); err != nil {
			return err
		}
	}
	return nil
}

func workerBinary() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate controller executable for worker bootstrap: %w", err)
	}
	return exePath, nil
}

func controllerRuntimeEnv(workspace string) (map[string]string, error) {
	required := []string{"PVE_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET", "PBS_REPOSITORY", "PBS_PASSWORD"}
	values := make(map[string]string, len(required)+4)
	for _, name := range required {
		value := os.Getenv(name)
		if value == "" {
			return nil, fmt.Errorf("controller secret environment variable %s is required", name)
		}
		values[name] = value
	}
	if err := checkInheritedTypedEnvironment(); err != nil {
		return nil, err
	}
	for _, name := range []string{"PVE_TLS_INSECURE", pve.InsecureTLSLabOptInEnv, "PBS_FINGERPRINT", "PBS_NAMESPACE", "PBS_ENCRYPTION_PASSWORD"} {
		if value := os.Getenv(name); value != "" {
			values[name] = value
		}
	}
	if os.Getenv("CERTISTACK_PBS_KEYFILE") != "" {
		values["CERTISTACK_PBS_KEYFILE"] = path.Join(workspace, pbsKeyfileName)
	}
	if os.Getenv("CERTISTACK_ALLOW_TEST_MODE") == "1" {
		values["CERTISTACK_ALLOW_TEST_MODE"] = "1"
	}
	if os.Getenv("CERTISTACK_PVE_CA_SOURCE") != "" {
		values["CERTISTACK_PVE_CA_SOURCE"] = path.Join(workspace, "pve-ca.pem")
	}
	// The worker's stdout is reserved for its single JSON result. Opt in to a
	// small stderr event stream so the controller can render operator-friendly
	// live progress without parsing or trusting arbitrary log output.
	values[progresspkg.EnvironmentEvents] = "1"
	return values, nil
}

// pbsKeyfileName is the PBS encryption key's name in the worker workspace.
const pbsKeyfileName = "pbs-encryption.key"

// checkKeyfileSource checks the controller's copy of the PBS encryption key
// before it is staged. Staging uses readKeyfileSource directly so it copies
// only bytes read from the checked file descriptor.
func checkKeyfileSource(p string) error {
	_, err := readKeyfileSource(p)
	return err
}

// WorkerEnvironmentKeys are the variables the controller may write into a
// node worker's environment file, in order. The worker accepts only an
// allowlist, so each must be on it.
var WorkerEnvironmentKeys = []string{"PVE_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET", "PVE_TLS_INSECURE", pve.InsecureTLSLabOptInEnv, "CERTISTACK_PVE_CA_SOURCE", "PBS_REPOSITORY", "PBS_PASSWORD", "PBS_FINGERPRINT", "PBS_NAMESPACE", "CERTISTACK_PBS_KEYFILE", "PBS_ENCRYPTION_PASSWORD", "CERTISTACK_ALLOW_TEST_MODE", progresspkg.EnvironmentEvents}

func writeEnvFile(targetPath string, values map[string]string) error {
	data, err := EncodeWorkerEnvironment(values)
	if err != nil {
		return err
	}
	return os.WriteFile(targetPath, data, 0600)
}

// EncodeWorkerEnvironment is the worker environment file for values, in
// WorkerEnvironmentKeys order. The worker reads it with the same parser as
// an operator's dotenv file, which trims a value's surrounding whitespace
// and takes a leading quote as the start of a quoted value. A value that
// either would change is written between double quotes: the parser removes
// exactly the outer pair and keeps everything between, internal quotes
// included, so every value reaches the worker byte for byte. NUL, CR and LF
// cannot be written in this format and are refused.
func EncodeWorkerEnvironment(values map[string]string) ([]byte, error) {
	var b strings.Builder
	for _, key := range WorkerEnvironmentKeys {
		value, ok := values[key]
		if !ok {
			continue
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("environment value %s contains a prohibited control character", key)
		}
		// The file is never one the worker's own parser would refuse.
		if err := envtypes.Check(key, value); err != nil {
			return nil, fmt.Errorf("environment variable %s: %w", key, err)
		}
		b.WriteString(key)
		b.WriteByte('=')
		if value != strings.TrimSpace(value) || strings.HasPrefix(value, `"`) || strings.HasPrefix(value, "'") {
			value = `"` + value + `"`
		}
		b.WriteString(value)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

func copyFile(source, destination string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// stagePVECA copies the controller's optional PVE TLS CA into the private
// worker staging directory. Unlike the worker binary, the CA is operator
// input: it must be a bounded regular file, so a FIFO cannot hold the
// controller and a huge file cannot consume memory or be sent to the node. A
// certificate is public, so attest.ReadRegularFile deliberately follows a
// symlink to a regular file.
func stagePVECA(source, destination string) (retErr error) {
	data, err := attest.ReadRegularFile(source, "PVE TLS CA file", pve.MaxCAFileBytes)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			_ = out.Close()
			_ = os.Remove(destination)
		}
	}()
	if n, err := out.Write(data); err != nil {
		return err
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	if err := out.Close(); err != nil {
		return err
	}
	return nil
}

func (e *Executor) sshBaseArgs(cfg SSHConfig) []string {
	args := append(sshOptions(cfg), "-p", strconv.Itoa(normalizedPort(cfg.Port)))
	if cfg.IdentityFile != "" {
		args = append(args, "-i", cfg.IdentityFile)
	}
	return args
}

// sshOptions are the options every ssh and scp to the node uses.
func sshOptions(cfg SSHConfig) []string {
	return []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + cfg.KnownHostsFile,
		"-o", "IdentitiesOnly=yes",
		"-o", "ConnectTimeout=" + strconv.Itoa(sshConnectTimeout),
		"-o", "ServerAliveInterval=" + strconv.Itoa(sshServerAliveInterval),
		"-o", "ServerAliveCountMax=" + strconv.Itoa(sshServerAliveCountMax),
	}
}

func normalizedPort(port int) int {
	if port == 0 {
		return 22
	}
	return port
}

func (e *Executor) target(cfg SSHConfig) string {
	return cfg.User + "@" + cfg.Host
}

// scpTarget is user@host in the form scp reads: an IPv6 literal is bracketed
// (user@[2001:db8::1]), because scp splits "user@host:path" at the first colon
// after the host and would take 2001 for the host of an unbracketed literal.
// ssh itself takes the literal as it is.
func scpTarget(cfg SSHConfig) string {
	host := cfg.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return cfg.User + "@" + host
}

func (e *Executor) remoteCommand(ctx context.Context, cfg SSHConfig, command []string) ([]byte, error) {
	return e.remoteCommandWithProgress(ctx, cfg, command, nil)
}

func (e *Executor) remoteCommandWithProgress(ctx context.Context, cfg SSHConfig, command []string, progress io.Writer) ([]byte, error) {
	if len(command) == 0 {
		return nil, errors.New("remote command is empty")
	}
	args := e.sshBaseArgs(cfg)
	args = append(args, e.target(cfg))
	for _, arg := range command {
		args = append(args, shellQuote(arg))
	}
	var (
		output []byte
		err    error
	)
	if progressRunner, ok := e.runner.(streamingCommandRunner); ok && progress != nil {
		output, err = progressRunner.RunWithStderr(ctx, "ssh", args, progress)
	} else {
		output, err = e.runner.Run(ctx, "ssh", args)
	}
	if err != nil {
		return nil, fmt.Errorf("SSH command on %s: %w", cfg.Host, err)
	}
	return output, nil
}

// SSH transmits all remote command arguments as one string interpreted by the
// remote login shell. Quote every argument explicitly so a controller option
// cannot become additional shell syntax on the PVE node.
func shellQuote(arg string) string {
	return "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
}

// setupRetries are the waits between tries of an idempotent setup step
// whose connection to the node failed. A busy sshd (MaxStartups) or a
// network blip should not cost a run before it starts: in testing, one scp of
// the worker lost its connection and failed a run in 30 s.
var setupRetries = []time.Duration{2 * time.Second, 5 * time.Second}

// connectionFailed reports whether ssh or scp lost, or could not make, its
// connection to the node, as opposed to the remote command failing. ssh
// says so with exit status 255; scp exits 1 and names it.
func connectionFailed(err error) bool {
	if err == nil {
		return false
	}
	if sshTransportFailed(err) {
		return true
	}
	message := err.Error()
	for _, sign := range []string{"lost connection", "Connection closed by", "Connection reset by", "kex_exchange_identification", "Connection timed out"} {
		if strings.Contains(message, sign) {
			return true
		}
	}
	return false
}

// retrySetup runs an idempotent setup step, and again after a short wait
// while its connection to the node fails.
func retrySetup(ctx context.Context, step func() error) error {
	err := step()
	for _, wait := range setupRetries {
		if !connectionFailed(err) {
			return err
		}
		if ctx.Err() != nil {
			return setupInterrupted(ctx, err)
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return setupInterrupted(ctx, err)
		case <-timer.C:
		}
		err = step()
	}
	return err
}

// setupInterrupted is the error of a setup step whose retry the context ended:
// the connection failure that made it retry, and the context's error, so that
// an interrupt during the wait is the interruption it is (exit status 130) and
// not the connection failure that preceded it. A
// failure that already is the context's error is not wrapped again.
func setupInterrupted(ctx context.Context, last error) error {
	cause := ctx.Err()
	if cause == nil || errors.Is(last, cause) {
		return last
	}
	return fmt.Errorf("%w; stopped retrying because the run was interrupted: %w", last, cause)
}

// remoteSetupCommand is remoteCommand for an idempotent setup step.
func (e *Executor) remoteSetupCommand(ctx context.Context, cfg SSHConfig, command []string) ([]byte, error) {
	var output []byte
	err := retrySetup(ctx, func() error {
		var err error
		output, err = e.remoteCommand(ctx, cfg, command)
		return err
	})
	return output, err
}

// createStaging creates the SSH user's private staging directory in /tmp.
// A path that already exists is used only if it is a private directory of
// that user, as a retried creation leaves it; any other directory, or a
// symbolic link, found there is refused.
func (e *Executor) createStaging(ctx context.Context, cfg SSHConfig, staging string) error {
	_, err := e.remoteSetupCommand(ctx, cfg, []string{"/bin/sh", "-c", privateDirectoriesScript(staging)})
	if err != nil {
		return fmt.Errorf("create temporary SSH staging directory: %w", err)
	}
	return nil
}

func (e *Executor) copyToStaging(ctx context.Context, cfg SSHConfig, local, staging string) error {
	args := append([]string{"-q", "-p"}, sshOptions(cfg)...)
	args = append(args, "-P", strconv.Itoa(normalizedPort(cfg.Port)))
	if cfg.IdentityFile != "" {
		args = append(args, "-i", cfg.IdentityFile)
	}
	args = append(args, local, scpTarget(cfg)+":"+staging+"/")
	// Copying the same file again into the same place is harmless.
	if err := retrySetup(ctx, func() error {
		_, err := e.runner.Run(ctx, "scp", args)
		return err
	}); err != nil {
		return fmt.Errorf("copy worker input to %s: %w", cfg.Host, err)
	}
	return nil
}

func (e *Executor) privilegePrefix(cfg SSHConfig) []string {
	if cfg.UseSudo {
		return []string{"/usr/bin/sudo", "-n"}
	}
	return nil
}

// supervisedWorkerCommand runs the node worker beneath a small remote
// supervisor. The supervisor records the exact child PID and expires a
// controller-renewed lease if the controller host disappears abruptly. It is
// launched as a transient system service rather than an SSH-session child: a
// hardened PVE host may reap an entire SSH session cgroup, even after setsid.
// The service stores the node result and progress in its protected workspace,
// tails progress while the controller is connected, and emits exactly the
// result JSON when the worker completes, or fails when it cannot read it.
//
// Nothing it does depends on the controller surviving. A worker that fails
// or is killed before it finishes has its journal recovered at once,
// whatever it wrote. A worker that ends before its lease expires
// leaves a lease watch behind (leaseWatchScript), which cleans up after a
// controller that is gone: the run's resources, and then its workspace or
// at least the credentials in it. The lease and the
// cleanup grace are measured on the boot clock, so a wall-clock step
// neither expires nor extends them.
func (e *Executor) supervisedWorkerCommand(cfg SSHConfig, unitName, workspaceRoot, workspace, pidPath, leasePath, stateDir, envPath, resultPath, progressPath string, nodeRunCommand []string) []string {
	if len(nodeRunCommand) == 0 || !safeRemoteAbsolutePath(workspaceRoot) || path.Dir(workspace) != workspaceRoot || uuid.Validate(path.Base(workspace)) != nil {
		return nil
	}
	workerPath := nodeRunCommand[0]
	variables := workspaceShellVariables(leasePath, workerPath, stateDir, envPath, progressPath, workspace)
	script := supervisorScript(variables, pidPath, resultPath, workspace, nodeRunCommand)
	return append(e.privilegePrefix(cfg), systemdRunCommand(unitName, "--property=KillMode=control-group", "/bin/sh", "-c", script)...)
}

// systemdWord is s as one word of a systemd-run command line. systemd
// substitutes environment variables in each word of a service's command
// before its program starts, and does not leave alone what it does not know:
// it deletes it. A shell script that reaches systemd-run as a word loses
// "${proc_stat##*\) }" altogether (no supervisor could tell its worker
// from another process, and stopped it). "$$" is systemd's own spelling of one
// "$", so doubling each one hands the program exactly s, whatever the
// systemd version and whatever it does with the forms it knows. "%" needs
// nothing: a transient service's command has no specifiers.
func systemdWord(s string) string {
	return strings.ReplaceAll(s, "$", "$$")
}

// systemdRunCommand is the command line that starts a transient service
// unit with systemd-run, on the node, and waits for it with its output piped
// back: command is the service's own command line, each word escaped for
// systemd (systemdWord). The unit gets a description of its own: without one
// systemd names it after its command line, and on systemd 252 (Debian 12, so
// Proxmox VE 8) that name, script and newlines included, is written into the
// unit file, where reading it back logs dozens of "Invalid section header"
// and "Missing '='" lines for every run.
func systemdRunCommand(unitName string, options ...string) []string {
	command := []string{"/usr/bin/systemd-run", "--unit", systemdWord(unitName), "--description=CertiStack node run", "--collect", "--wait", "--pipe", "--quiet"}
	for _, word := range options {
		command = append(command, systemdWord(word))
	}
	return command
}

// launcherCanary makes a script that its launcher altered on the way to the
// shell refuse to start, instead of running in a way that looks like
// something else. The controller escapes the script for systemd
// (systemdWord); were that ever not enough, for instance on a systemd that
// also expanded the specifiers "%h" and "%%", or were a script launched by
// other means, the two sides of the comparison would differ. The right-hand
// side is split so that the launcher cannot alter it the way it alters the
// left.
const launcherCanary = `launcher_canary='${launcher_canary##x}%h%%'
if [ "$launcher_canary" != '$''{launcher_canary##x}%''h%''%' ]; then
  printf 'this script was altered by the program that started it, so it cannot run; refusing to start\n' >&2
  exit 126
fi`

// supervisorScript is the shell script a worker's supervisor runs: what
// systemd-run gives to sh -c, once systemd has undone the escaping of
// systemdWord. Its lease watch is a script in a variable of its own, which
// the supervisor hands to systemd-run again, so it is escaped once for that
// second launch and, with the rest, once more for the first.
func supervisorScript(variables, pidPath, resultPath, workspace string, nodeRunCommand []string) string {
	watch := systemdWord(leaseWatchScript(variables))
	return fmt.Sprintf(`umask 077
# The controller's session may end at any time, and stdout and stderr, which
# belong to it, then have no reader. A write to them fails with an error the
# script goes on from, instead of ending it: SIGPIPE is ignored, as systemd
# ignores it for a service.
trap '' PIPE
%s
%s
pid_file=%s
boot_file=%s
result_file=%s
event_prefix=%s
lease_seconds=%d
grace_seconds=%d
kill_wait_seconds=%d
status_log_not_kept=%d
status_worker_stuck=%d
status_result_unreadable=%d
result_write_seconds=%d
abandoned_write_seconds=%d
tick=1
%s
%s
if [ ! -r "$lease_file" ]; then
  printf 'controller lease is missing; refusing worker start\n' >&2
  exit 126
fi
{ IFS=' .' read -r now _ < /proc/uptime; } 2>/dev/null || now=
case "$now" in
  ''|*[!0-9]*)
    printf 'the boot clock (/proc/uptime) cannot be read; refusing worker start\n' >&2
    exit 126 ;;
esac
lease_stamp
renewed_at=$now
last_stamp=$stamp
: > "$result_file"
: > "$progress_file"
/usr/bin/tail -n 0 -F "$progress_file" >&2 &
tail_pid=$!
proc_start "$tail_pid"
tail_ticks=$ticks
# Appending, so the worker's writes do not overwrite the notices this
# script appends to the same file.
%s > "$result_file" 2>> "$progress_file" &
worker_pid=$!
# The worker's start time identifies it from here on. It is read before
# this shell waits for any command, so before the shell can have reaped the
# worker, after which its PID can be another program's. Each
# worker_alive check and the kill builtin after it run in this shell, with
# no wait, and so no reaping, between them.
proc_start "$worker_pid"
worker_ticks=$ticks
worker_alive() {
  same_process "$worker_pid" "$worker_ticks"
}
# The node's boot ID is recorded beside the worker's PID, and before it, so
# that a PID file never lacks the boot it belongs to. A PID recorded in an
# earlier boot names whichever program the node started since, and the
# worker's stop reads the record to tell.
record_worker() {
  IFS= read -r boot_identity < /proc/sys/kernel/random/boot_id || return 1
  /usr/bin/printf '%%s\n' "$boot_identity" > "$boot_file" || return 1
  /usr/bin/printf '%%s\n' "$worker_pid" > "$pid_file"
}
worker_status=
log_status=0
if [ -z "$worker_ticks" ]; then
  if [ -e "/proc/$worker_pid" ]; then
    # It is there but its start time cannot be read: stop it rather than run
    # it unwatched.
    printf 'the worker cannot be identified in /proc; stopping it\n' >> "$progress_file"
    kill -TERM "$worker_pid" 2>/dev/null
    worker_status=125
  fi
  # Otherwise the worker has already ended and the shell has reaped it (dash
  # reaps a finished background job on its own): the wait below returns its
  # exit status.
elif ! record_worker; then
  worker_alive && kill -TERM "$worker_pid" 2>/dev/null
  worker_status=125
fi
lease_expired=0
cleanup_deadline=
killed_at=
worker_stuck=
# The lease watch takes over the lease in a service of its own: this one's
# processes end with this script. It gets the worker's identity, to recover
# nothing while the worker still runs, and ends as soon as the controller
# removes the workspace.
watch_script=%s
start_watch() {
  if ! %s --unit %s --collect --quiet /bin/sh -c "$watch_script" certistack-lease-watch "$renewed_at" "$last_stamp" "$worker_pid" "$worker_ticks" >> "$progress_file" 2>&1; then
    printf "could not start the lease watch; should the controller be gone, the node's next CertiStack run removes this workspace's credentials\n" >> "$progress_file"
  fi
}
terminate_worker() {
  if [ "$lease_expired" -eq 0 ]; then
    printf 'controller session ended; starting worker cleanup\n' >> "$progress_file"
    lease_expired=1
    boot_now
    cleanup_deadline=$((now + grace_seconds))
  fi
  worker_alive && kill -TERM "$worker_pid" 2>/dev/null
}
trap 'terminate_worker' INT TERM
while [ -z "$worker_status" ] && worker_alive; do
  boot_now
  lease_stamp
  if [ -n "$stamp" ] && [ "$stamp" != "$last_stamp" ]; then
    last_stamp=$stamp
    renewed_at=$now
  fi
  if [ "$lease_expired" -eq 0 ] && { [ -z "$stamp" ] || [ "$((now - renewed_at))" -gt "$lease_seconds" ]; }; then
    printf 'controller lease expired; starting worker cleanup\n' >> "$progress_file"
    lease_expired=1
    cleanup_deadline=$((now + grace_seconds))
    worker_alive && kill -TERM "$worker_pid" 2>/dev/null
  fi
  if [ "$lease_expired" -eq 1 ] && [ "$now" -ge "$cleanup_deadline" ]; then
    if [ -z "$killed_at" ]; then
      killed_at=$now
      printf 'worker cleanup grace period exhausted; killing the worker before recovering its journal\n' >> "$progress_file"
      worker_alive && kill -KILL "$worker_pid" 2>/dev/null
    elif [ "$((now - killed_at))" -ge "$kill_wait_seconds" ]; then
      # SIGKILL cannot be caught: a worker still there this long after it is
      # stuck in the kernel, for example in uninterruptible I/O.
      worker_stuck=1
      break
    fi
  fi
  /bin/sleep 1
done
set +e
# The tail shows the controller the progress file. It is ended only once it is
# known to be the tail this script started, and waited for only then: a tail
# that cannot be identified cannot be told to end, and waiting for one that
# does not would hold this service for ever. The service's control group
# ends whatever is left with the service.
stop_tail() {
  if same_process "$tail_pid" "$tail_ticks"; then
    kill "$tail_pid" 2>/dev/null
    wait "$tail_pid" 2>/dev/null
  fi
}
if [ -n "$worker_stuck" ]; then
  # Waiting for it would hold this service, and recovery, for as long as the
  # kernel holds the worker. Recovery is not started either: the worker may
  # run on when the kernel lets it go, and recovery must not act on
  # resources it still uses. The workspace and the journal stay; the lease
  # watch recovers them once the worker has ended.
  proc_start "$worker_pid"
  { IFS= read -r stuck_wchan < "/proc/$worker_pid/wchan"; } 2>/dev/null || stuck_wchan=
  stuck_message="The node worker (PID $worker_pid, state ${state:-unknown}, waiting in ${stuck_wchan:-unknown}) is still running $kill_wait_seconds s after SIGKILL, so its journal is not recovered; recovery starts only once it has ended, and until then the node's host lock stays held. The workspace and the journal are kept."
  /usr/bin/printf '%%s{"level":"ERROR","stage":"Recovery","message":"%%s"}\n' "$event_prefix" "$stuck_message" >> "$progress_file"
  keep_log
  start_watch
  /bin/sleep 1
  stop_tail
  printf '%%s\n' "$stuck_message" >&2
  exit "$status_worker_stuck"
fi
wait "$worker_pid"
waited=$?
worker_status=${worker_status:-$waited}
if [ "$lease_expired" -eq 1 ]; then
  stop_tail
  "$worker" recover --state-dir "$state_dir" --env-file "$env_file" >> "$progress_file" 2>&1
  recovery_status=$?
  keep_log
  log_status=$?
  # Whatever ends this branch before the workspace is removed leaves the
  # controller gone: nobody is left to use the credentials, and no lease
  # watch is left to remove them.
  # The result is opened now, so that it can still be read once the
  # workspace, which holds it, is gone.
  result_open=
  if [ -f "$result_file" ] && [ -r "$result_file" ] && command exec 9< "$result_file"; then
    result_open=1
  fi
  problem=
  problem_status=1
  if [ "$recovery_status" -ne 0 ]; then
    problem="the controller's lease expired and the recovery of this run's journal failed. The journal keeps what the run left, and the node's next CertiStack run recovers it before it starts"
    problem_status=$recovery_status
  elif ! /usr/bin/touch "$recovery_marker"; then
    problem="the controller's lease expired and the recovery marker could not be written"
  elif [ "$log_status" -ne 0 ]; then
    problem="the controller's lease expired and this run's journal was recovered, but its recovery log could not be kept in $log_dir; worker-progress.log in this workspace keeps it"
    problem_status=$status_log_not_kept
  elif [ -z "$result_open" ]; then
    printf 'CertiStack could not read the node worker result %%s\n' "$result_file" >&2
    problem="the controller's lease expired and the worker's result could not be read"
    problem_status=$status_result_unreadable
  fi
  if [ -z "$problem" ]; then
    /usr/bin/rm -rf -- "$workspace"
    # Only now does the supervisor write the result to stdout, which is the
    # controller's session and may have ended: what that write does changes
    # nothing of what has happened here, neither the workspace nor the
    # status. It is bounded, for a stdout that is open and never read.
    /usr/bin/timeout -k 5 "$abandoned_write_seconds" /usr/bin/cat <&9 2>/dev/null
    exit "$worker_status"
  fi
  scrub_credentials "$problem"
  exit "$problem_status"
fi
if [ "$worker_status" -ne 0 ]; then
  # The worker failed or was killed before it finished. Whatever it wrote,
  # its journal may still record a sandbox VM, maps and addresses: recover
  # them now, whether or not the controller survived to do it; a
  # surviving controller then finds the journal clean. The workspace stays
  # for the controller to remove. Recovery's progress streams to the
  # controller, if it is still attached, and is kept beside the journal.
  if [ "$worker_status" -gt 128 ]; then
    /usr/bin/printf '%%s{"level":"WARN","stage":"Recovery","message":"The node worker ended by signal %%d before it finished; recovering its journal."}\n' "$event_prefix" "$((worker_status - 128))" >> "$progress_file"
  else
    /usr/bin/printf '%%s{"level":"WARN","stage":"Recovery","message":"The node worker failed with exit status %%d; recovering its journal."}\n' "$event_prefix" "$worker_status" >> "$progress_file"
  fi
  "$worker" recover --state-dir "$state_dir" --env-file "$env_file" >> "$progress_file" 2>&1
  keep_log
  log_status=$?
  /bin/sleep 1
fi
start_watch
stop_tail
if [ ! -f "$result_file" ] || [ ! -r "$result_file" ]; then
  # An unreadable result must not reach the controller as an empty success.
  printf 'CertiStack could not read the node worker result %%s\n' "$result_file" >&2
  exit "$status_result_unreadable"
fi
if ! /usr/bin/timeout -k 5 "$result_write_seconds" /usr/bin/cat -- "$result_file"; then
  printf 'CertiStack could not write the node worker result to the controller\n' >&2
  exit "$status_result_unreadable"
fi
if [ "$log_status" -ne 0 ]; then
  # The workspace holds the only other copy of the recovery log, and the
  # controller must not remove it.
  exit "$status_log_not_kept"
fi
exit "$worker_status"
`, launcherCanary, variables, shellQuote(pidPath), shellQuote(workerBootPath(pidPath)), shellQuote(resultPath), shellQuote(progresspkg.EventPrefix), workerLeaseDurationSeconds, gracefulWorkerStopTimeout,
		forcedWorkerStopWaitSeconds, supervisorLogNotKeptStatus, supervisorWorkerStuckStatus, supervisorResultUnreadableStatus,
		resultWriteSeconds, abandonedResultWriteSeconds,
		workerShellFunctions, processIdentityFunctions, shellCommand(nodeRunCommand),
		shellQuote(watch), shellQuote(leaseWatchLauncher), shellQuote(leaseWatchUnitName(workspace)))
}

// resultWriteSeconds bounds how long the supervisor writes a worker's result
// to a controller that is connected; abandonedResultWriteSeconds bounds the
// same write when the controller's lease expired, and it is a variable so a
// test can shorten it. Both stop a stdout that is open and never read from
// holding the supervisor.
const resultWriteSeconds = 600

var abandonedResultWriteSeconds = 30

// recoveryLogNotKeptMessage starts the notice a supervisor gives when it
// could not keep a recovery log beside the journal. The controller reads it
// from the supervisor's error too, so that a workspace that holds the log's
// only other copy is never removed.
const recoveryLogNotKeptMessage = "CertiStack could not keep the recovery log"

// leaseWatchLauncher starts a lease watch as a transient service of its
// own on the node. Tests that run the supervisor script replace it.
var leaseWatchLauncher = "/usr/bin/systemd-run"

// workerCollectionSeconds is the longest a live controller takes to collect
// a finished worker: its journal check and any recovery run within
// interruptionCleanupTimeout, and removing the workspace takes seconds.
const workerCollectionSeconds = int((interruptionCleanupTimeout + 10*time.Minute) / time.Second)

// survivorWaitSeconds is how long the lease watch waits for a worker that
// survived SIGKILL to end before it removes the workspace's credentials and
// leaves the journal for the node's next run.
const survivorWaitSeconds = 3600

// leaseWatchUnitName is the lease watch's transient service.
func leaseWatchUnitName(workspace string) string {
	return "certistack-watch-" + path.Base(workspace)
}

// leaseWatchScript is the lease watch a supervisor leaves behind when its
// worker ends before the controller's lease expires. It
// gets the supervisor's last renewal time on the boot clock and the lease
// stamp then as $1 and $2, and the worker's PID and start time as $3 and $4,
// and ends as soon as the workspace is gone: a live controller removes it
// once it has the result and a clean journal.
// When the lease has not been renewed for workerLeaseDurationSeconds, or
// the controller has had workerCollectionSeconds, the controller is taken
// to be gone. The watch then recovers the run's journal and removes the
// workspace, keeping the log; when recovery fails it removes only the
// credentials, and the journal keeps what is left for the node's next run.
// It starts no recovery while the worker still runs, which a worker that
// survived SIGKILL does: it waits up to survivorWaitSeconds for that
// process to end, and then removes only the credentials and ends.
func leaseWatchScript(variables string) string {
	return fmt.Sprintf(`umask 077
%s
%s
lease_seconds=%d
collect_seconds=%d
survivor_seconds=%d
status_log_not_kept=%d
status_worker_stuck=%d
tick=5
%s
%s
now=0
boot_now
started_at=$now
renewed_at=$1
last_stamp=$2
survivor_pid=$3
survivor_ticks=$4
case "$renewed_at" in
  ''|*[!0-9]*) renewed_at=$now ;;
esac
while [ -d "$workspace" ]; do
  boot_now
  lease_stamp
  # A missing lease renews nothing: the controller removes it with the
  # workspace.
  if [ -n "$stamp" ] && [ "$stamp" != "$last_stamp" ]; then
    last_stamp=$stamp
    renewed_at=$now
  fi
  if [ "$((now - renewed_at))" -gt "$lease_seconds" ] || [ "$((now - started_at))" -gt "$collect_seconds" ]; then
    break
  fi
  /bin/sleep 5
done
if [ -n "$survivor_pid" ] && [ -n "$survivor_ticks" ]; then
  # Nothing is recovered while the worker may run on, and the wait for it is
  # bounded, because the workspace holds credentials: when the worker is still
  # there after survivor_seconds, the credentials go and the journal keeps
  # what the run left for the node's next run, which recovers it once the
  # worker has ended.
  waiting_since=$now
  while [ -d "$workspace" ] && same_process "$survivor_pid" "$survivor_ticks"; do
    boot_now
    if [ "$((now - waiting_since))" -gt "$survivor_seconds" ]; then
      scrub_credentials "the node worker (PID $survivor_pid) was still running $survivor_seconds s after the controller's lease expired, and nothing is recovered while it may run. The journal keeps what the run left, and the node's next CertiStack run recovers it once the worker has ended"
      exit "$status_worker_stuck"
    fi
    /bin/sleep 5
  done
fi
if [ ! -d "$workspace" ]; then
  exit 0
fi
printf 'the controller did not collect the finished worker while its lease lasted; recovering its journal\n' >> "$progress_file"
recovery_status=1
if [ -x "$worker" ] && [ -r "$env_file" ]; then
  "$worker" recover --state-dir "$state_dir" --env-file "$env_file" >> "$progress_file" 2>&1
  recovery_status=$?
fi
keep_log
log_status=$?
problem=
problem_status=1
if [ "$recovery_status" -ne 0 ]; then
  problem="the controller did not collect the finished worker while its lease lasted, and the recovery of this run's journal failed. The journal keeps what the run left, and the node's next CertiStack run recovers it before it starts"
elif ! /usr/bin/touch "$recovery_marker"; then
  problem="the controller did not collect the finished worker while its lease lasted, and the recovery marker could not be written"
elif [ "$log_status" -ne 0 ]; then
  problem="the controller did not collect the finished worker while its lease lasted; this run's journal was recovered, but its recovery log could not be kept in $log_dir, and worker-progress.log in this workspace keeps it"
  problem_status=$status_log_not_kept
fi
if [ -z "$problem" ]; then
  /usr/bin/rm -rf -- "$workspace"
  exit 0
fi
scrub_credentials "$problem"
exit "$problem_status"
`, launcherCanary, variables, workerLeaseDurationSeconds, workerCollectionSeconds, survivorWaitSeconds, supervisorLogNotKeptStatus, supervisorWorkerStuckStatus, workerShellFunctions, processIdentityFunctions)
}

// workspaceShellVariables are the shell variables that name a worker's
// files, for its supervisor and lease watch.
func workspaceShellVariables(leasePath, workerPath, stateDir, envPath, progressPath, workspace string) string {
	return fmt.Sprintf(`lease_file=%s
worker=%s
state_dir=%s
env_file=%s
key_file=%s
progress_file=%s
workspace=%s
recovery_marker=%s
log_dir="$state_dir/logs"`, shellQuote(leasePath), shellQuote(workerPath), shellQuote(stateDir), shellQuote(envPath), shellQuote(path.Join(workspace, pbsKeyfileName)), shellQuote(progressPath), shellQuote(workspace), shellQuote(path.Join(workspace, "recovered.ok")))
}

// workerShellFunctions are the shell functions a worker's supervisor and
// lease watch share.
//
// boot_now sets now to the whole seconds since boot, from /proc/uptime: the
// boot clock, which counts time suspended and is never stepped. Lease and
// grace are measured on it, never on the wall clock, which can be set
// forward or back. Should it become unreadable, now advances by
// the caller's polling interval (tick) per call.
//
// lease_stamp sets stamp to the lease file's modification time, with its
// nanoseconds, or to nothing when the file cannot be read. The controller
// renews the lease by touching it, so any change of the stamp is a renewal,
// whatever time it names: its age is counted on the boot clock from when
// the change was seen.
//
// keep_log saves the worker's and recovery's progress beside the journal
// before the workspace goes: it says what recovery did, and holds no
// credentials. It is written to a file of its own, flushed, and renamed into
// place, so the log is whole or absent; it fails, and says so, when any step
// does, and the caller must then keep the workspace, whose progress file is
// the only other copy.
//
// scrub_credentials removes the workspace's credentials, its environment,
// the PBS encryption key and the worker binary that would use them, and
// leaves a note saying when and why ($1). Logs and results stay.
const workerShellFunctions = `boot_now() {
  { IFS=' .' read -r boot _ < /proc/uptime; } 2>/dev/null || boot=
  case "$boot" in
    ''|*[!0-9]*) now=$((now + tick)) ;;
    *) now=$boot ;;
  esac
}
lease_stamp() {
  stamp=$(/usr/bin/stat -c %y -- "$lease_file" 2>/dev/null) || stamp=
}
keep_log() {
  kept_log="$log_dir/$(/usr/bin/basename "$workspace").log"
  if /usr/bin/mkdir -p -m 0700 -- "$log_dir" &&
    /usr/bin/cp -- "$progress_file" "$kept_log.part" &&
    /usr/bin/sync -- "$kept_log.part" &&
    /usr/bin/mv -fT -- "$kept_log.part" "$kept_log" &&
    /usr/bin/sync -- "$log_dir"; then
    return 0
  fi
  /usr/bin/rm -f -- "$kept_log.part"
  kept_log_message="` + recoveryLogNotKeptMessage + ` $kept_log; the workspace's worker-progress.log holds the only other copy"
  printf '%s\n' "$kept_log_message" >> "$progress_file"
  printf '%s\n' "$kept_log_message" >&2
  return 1
}
scrub_credentials() {
  /usr/bin/rm -f -- "$env_file" "$key_file" "$worker" &&
    /usr/bin/printf "Credentials removed (runtime.env, pbs-encryption.key, certistack-node) by the node at %s: %s. Logs and results are kept.\n" "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" > "$workspace/credentials-removed.txt"
}`

func workerUnitName(workspaceRoot, workspace string) (string, error) {
	if !safeRemoteAbsolutePath(workspaceRoot) || path.Dir(workspace) != workspaceRoot || uuid.Validate(path.Base(workspace)) != nil {
		return "", errors.New("refusing to create a system service outside an exact worker workspace")
	}
	return "certistack-worker-" + path.Base(workspace), nil
}

func shellCommand(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

// createWorkerLease creates the exact private lease file before a worker is
// started. It deliberately rejects a non-UUID workspace and never uses a
// pattern or a shared state path.
func (e *Executor) createWorkerLease(ctx context.Context, cfg SSHConfig, workspaceRoot, workspace, leasePath string) error {
	if !safeRemoteAbsolutePath(workspaceRoot) || path.Dir(workspace) != workspaceRoot || uuid.Validate(path.Base(workspace)) != nil || path.Dir(leasePath) != workspace {
		return errors.New("refusing to create a worker lease outside an exact workspace")
	}
	if _, err := e.remoteSetupCommand(ctx, cfg, append(e.privilegePrefix(cfg), "/usr/bin/install", "-m", "0600", "/dev/null", leasePath)); err != nil {
		return fmt.Errorf("create controller worker lease: %w", err)
	}
	return nil
}

// startWorkerLease refreshes the exact lease in a separate SSH operation.
// The primary worker command intentionally has no dependency on this control
// connection: if the controller vanishes, the remote supervisor observes the
// stale file and performs its own graceful, journal-backed cleanup.
//
// Renewals that keep failing mean the node cannot be reached, so warn tells
// the operator after leaseWarnAfter, and again once contact is back.
//
// parent ends the renewals when the controller has stopped working for the
// run: Run passes the context of its own cleanup and verification, not the
// run's, which a first Ctrl-C cancels while the controller goes on for as
// long as it takes to stop the worker, wait for the node's host lock and
// verify the journal. A lease that lapsed then would let the node's lease
// watch act on a journal the controller is verifying, and scrub the
// credentials the controller's recovery needs.
func (e *Executor) startWorkerLease(parent context.Context, cfg SSHConfig, workspaceRoot, workspace, leasePath string, warn func(format string, args ...interface{})) func() {
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }
	interval, warnAfter, renewTimeout := workerLeaseRenewInterval, leaseWarnAfter, workerLeaseRenewTimeout
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		renewed := time.Now()
		warned := false
		for {
			select {
			case <-done:
				return
			case <-parent.Done():
				return
			case <-ticker.C:
				leaseCtx, cancel := context.WithTimeout(context.Background(), renewTimeout)
				err := e.renewWorkerLease(leaseCtx, cfg, workspaceRoot, workspace, leasePath)
				timedOut := errors.Is(leaseCtx.Err(), context.DeadlineExceeded)
				cancel()
				switch {
				case err == nil:
					if warned {
						warn("Contact with node %s is back; the worker's lease is renewed.", cfg.Host)
					}
					renewed, warned = time.Now(), false
				case !warned && time.Since(renewed) >= warnAfter:
					reason := sshReason(err)
					if timedOut {
						reason = "no answer within " + roughly(renewTimeout)
					}
					warn("Cannot reach node %s over SSH to renew the worker's lease (%s); it was last renewed %s ago. The node may have crashed, rebooted or lost its network. A node that runs on without contact stops the run and cleans up by itself once the lease is %d s old.",
						cfg.Host, reason, roughly(time.Since(renewed)), workerLeaseDurationSeconds)
					warned = true
				}
			}
		}
	}()
	return stop
}

// workerNeverStarted reports an ssh that failed before its session began,
// so its remote command never ran: the connection was refused or timed
// out, the name did not resolve, or the server closed it before the key
// exchange. A session that began and was then lost ("client_loop: ...",
// "Connection to X closed by remote host", "Timeout, server not
// responding") may have started it.
func workerNeverStarted(err error) bool {
	if !sshTransportFailed(err) {
		return false
	}
	reason := sshReason(err)
	if strings.HasPrefix(reason, "client_loop") {
		return false
	}
	for _, sign := range []string{"ssh: connect to host ", "kex_exchange_identification", "during banner exchange", "Could not resolve hostname"} {
		if strings.Contains(reason, sign) {
			return true
		}
	}
	return strings.HasPrefix(reason, "Connection closed by ") || strings.HasPrefix(reason, "Connection reset by ")
}

// leftoverSteps names the teardown steps that failed, from the worker's
// cleanup errors ("<step>: <error>"), as " (<step>; <step>)".
func leftoverSteps(cleanupErrors []string) string {
	var steps []string
	for _, e := range cleanupErrors {
		step, _, _ := strings.Cut(e, ": ")
		if step != "" && len(step) <= 120 {
			steps = append(steps, step)
		}
	}
	if len(steps) == 0 {
		return ""
	}
	return " (" + strings.Join(steps, "; ") + ")"
}

// lastErrorLine is err's last non-empty line, at most 400 bytes.
func lastErrorLine(err error) string {
	lines := strings.Split(strings.TrimSpace(err.Error()), "\n")
	line := strings.TrimSpace(lines[len(lines)-1])
	if len(line) > 400 {
		line = line[:400] + "..."
	}
	return line
}

// sshReason is why ssh failed, in ssh's own words when it gave them: the
// last line of its stderr.
func sshReason(err error) string {
	lines := strings.Split(strings.TrimSpace(err.Error()), "\n")
	line := strings.TrimSpace(lines[len(lines)-1])
	const status = "exit status 255: "
	if i := strings.LastIndex(line, status); i >= 0 && i+len(status) < len(line) {
		line = strings.TrimRight(line[i+len(status):], ".")
	}
	if isWorkerLogLine(line) {
		return sshSaidNothing
	}
	return line
}

// sshSaidNothing is sshReason's answer when the last line of the error is the
// worker's log and not ssh's: ssh gave no reason of its own.
const sshSaidNothing = "ssh gave no reason of its own"

// workerLogLineExpr matches a line of the worker's structured log, which the node
// worker writes to its stderr as "time=... level=INFO msg=...".
var workerLogLineExpr = regexp.MustCompile(`^(?:time=\S+\s+)?level=(?:DEBUG|INFO|WARN|ERROR)(?:\s|$)`)

// isWorkerLogLine reports whether line is the worker's log, which ssh carries
// back on the stderr of its session: not ssh's own words.
func isWorkerLogLine(line string) bool {
	return workerLogLineExpr.MatchString(strings.TrimSpace(line))
}

// nodePromptAnswer is how long the controller waits for the node to answer the
// one try that tells a worker that ended from a node that is gone.
var nodePromptAnswer = 8 * time.Second

// nodeAnswersAtOnce reports whether the node answers a trivial command now.
// After ssh ended with status 255 it tells a node that is up, whose worker
// ended or whose connection was cut, from one that crashed, rebooted or lost
// its network.
func (e *Executor) nodeAnswersAtOnce(ctx context.Context, cfg SSHConfig) bool {
	tryCtx, cancel := context.WithTimeout(ctx, nodePromptAnswer)
	defer cancel()
	_, err := e.remoteCommand(tryCtx, cfg, []string{"/usr/bin/true"})
	return err == nil
}

// workerEnd is what to say, and to return, when ssh ended with status 255
// and the node answered at once, once the worker's stop was decided (stop is
// the stop script's answer): the worker had already ended (killed or crashed),
// or it still ran and the controller stopped it. ok is false for any other
// answer, which the caller words as before. cause is ssh's error, kept for
// errors.As and not repeated, as it ends in the worker's own log line.
func workerEnd(node, unit, stop, reconciled string, cause error) (message string, err error, ok bool) {
	var what string
	switch stop {
	case "gone":
		what = fmt.Sprintf("the node worker on node %s ended without a result (killed or crashed); the node itself answered", node)
	case "stopped":
		what = fmt.Sprintf("the ssh connection to node %s ended while the node worker was still running, and the node answered again at once; the controller stopped the worker", node)
	default:
		return "", nil, false
	}
	where := "journalctl -u " + unit
	message = fmt.Sprintf("%s%s. Its log is on the node: %s; %s.", strings.ToUpper(what[:1]), what[1:], where, reconciled)
	return message, &workerEndedError{text: fmt.Sprintf("%s (its log is on the node: %s)", what, where), cause: cause}, true
}

// workerEndedError is workerEnd's error.
type workerEndedError struct {
	text  string
	cause error
}

func (e *workerEndedError) Error() string { return e.text }
func (e *workerEndedError) Unwrap() error { return e.cause }

func (e *Executor) renewWorkerLease(ctx context.Context, cfg SSHConfig, workspaceRoot, workspace, leasePath string) error {
	if !safeRemoteAbsolutePath(workspaceRoot) || path.Dir(workspace) != workspaceRoot || uuid.Validate(path.Base(workspace)) != nil || path.Dir(leasePath) != workspace {
		return errors.New("refusing to renew a worker lease outside an exact workspace")
	}
	if _, err := e.remoteCommand(ctx, cfg, append(e.privilegePrefix(cfg), "/usr/bin/touch", leasePath)); err != nil {
		return fmt.Errorf("renew controller worker lease: %w", err)
	}
	return nil
}

// reconcileInterruptedWorker makes transport loss and user cancellation
// fail-safe. It signals only the PID recorded by this workspace after proving
// /proc identifies the exact staged binary, waits for graceful LIFO teardown,
// then invokes journal recovery with the same literal environment file. A
// worker that no longer runs is not signalled, and its journal is recovered
// at once. If recovery cannot be verified, the protected workspace remains
// available for investigation instead of guessing at customer resources.
//
// A node that cannot be reached is retried until ctx ends, so a node that
// crashed or rebooted is cleaned up as soon as it answers. selfCleaned
// reports that the node had already recovered the run by itself, as its
// supervisor does once the lease expires.
func (e *Executor) reconcileInterruptedWorker(ctx context.Context, cfg SSHConfig, workspaceRoot, workspace, stateDir string, contact nodeContact) (selfCleaned bool, err error) {
	if !safeRemoteAbsolutePath(workspaceRoot) || path.Dir(workspace) != workspaceRoot || uuid.Validate(path.Base(workspace)) != nil || !safeRemoteAbsolutePath(stateDir) {
		return false, errors.New("refusing interruption cleanup for invalid worker paths")
	}

	pidPath := path.Join(workspace, "worker.pid")
	workerPath := path.Join(workspace, "certistack-node")
	graceSeconds := gracefulWorkerStopTimeout
	if contact.workerStuck {
		graceSeconds = 0
	}
	stopScript := workerStopScriptWithin(pidPath, workerPath, graceSeconds)
	stopCommand := append(e.privilegePrefix(cfg), "/bin/sh", "-c", stopScript)
	output, err := e.remoteCommand(ctx, cfg, stopCommand)
	for sshTransportFailed(err) {
		if waitErr := e.untilNodeAnswers(ctx, cfg, contact, err); waitErr != nil {
			return false, fmt.Errorf("stop recorded node worker: %w", waitErr)
		}
		output, err = e.remoteCommand(ctx, cfg, stopCommand)
	}
	if err != nil {
		return false, fmt.Errorf("stop recorded node worker: %w", err)
	}
	if contact.bootID != "" {
		if now := e.nodeBootID(ctx, cfg); now != "" && now != contact.bootID {
			contact.status("Node %s rebooted during the run (its boot ID changed): the worker and its sandbox stopped with it. Recovering the resources the run recorded.", contact.name)
		}
	}
	switch strings.TrimSpace(string(output)) {
	case "absent":
		// No PID file: the worker never started, or its supervisor already
		// recovered the run and removed the workspace, as a node cut off
		// from the controller does once the lease expires. The
		// journal tells which, below.
	case "stopped":
		// Continue to durable reconciliation below.
	case "gone":
		// The recorded worker no longer runs: its process is gone (killed,
		// or dead with its SSH session), or its PID now belongs to another
		// program. There is nothing to stop, and nothing unrelated is
		// signalled. Its journal is reconciled below all the same, now
		// rather than at the node's next run: recovery takes the host lock,
		// which a live worker would hold, and acts only on the identities
		// the journal recorded.
	case "still-running":
		return false, errWorkerStillRunning
	default:
		return false, fmt.Errorf("unexpected recorded node-worker stop result %q", strings.TrimSpace(string(output)))
	}

	// An interrupted worker returned no evidence; without a journal it
	// created no resource.
	var outcome journalOutcome
	err = e.reconcileCompletedWorker(ctx, cfg, workspaceRoot, workspace, stateDir, journalCheck{runID: workerRunID(workspace), noRecordIsClean: true, progress: contact.progress, outcome: &outcome})
	outcome.workerStop = strings.TrimSpace(string(output))
	if contact.outcome != nil {
		*contact.outcome = outcome
	}
	if err != nil {
		return false, fmt.Errorf("reconcile interrupted node-worker journal: %w", err)
	}
	// Only the supervisor's lease-expiry recovery removes the workspace, PID
	// file and all, after marking this run's journal cleaned.
	return strings.TrimSpace(string(output)) == "absent" && outcome.ownCleaned && !outcome.recovered, nil
}

// errWorkerStillRunning is a worker that ignored SIGTERM and SIGKILL: it is
// stuck in the kernel, for example in uninterruptible I/O.
var errWorkerStillRunning = errors.New("recorded node worker remained running after graceful and forced stop")

// nodeContact is what interruption cleanup knows of the node: its name, its
// boot ID before the run ("" when unknown), whether contact with it was
// lost, whether the node's supervisor reported the worker stuck, and where
// to tell the operator.
type nodeContact struct {
	name        string
	bootID      string
	lost        bool
	workerStuck bool
	progress    *progressReporter
	// outcome, when set, receives what the journal check found.
	outcome *journalOutcome
}

func (c nodeContact) status(format string, args ...interface{}) {
	if c.progress != nil {
		c.progress.status(format, args...)
	}
}

// untilNodeAnswers waits for a node ssh could not reach (failure), trying
// it with a trivial command until it answers or ctx ends. A try is quick,
// so one the deadline kills was still connecting, unlike the stop script,
// which can rightly run for minutes. It tells the operator it is waiting,
// then at most once a minute, and when the node answers again. A node that
// has not answered by ctx's deadline is a *nodeUnreachableError.
func (e *Executor) untilNodeAnswers(ctx context.Context, cfg SSHConfig, contact nodeContact, failure error) error {
	started := time.Now()
	wait := nodeRetryInitial
	var told time.Time
	for {
		if told.IsZero() || time.Since(told) >= time.Minute {
			left := "until cleanup is abandoned"
			if deadline, ok := ctx.Deadline(); ok {
				left = "for up to " + roughly(time.Until(deadline))
			}
			contact.status("Node %s does not answer (%s); retrying %s.", contact.name, sshReason(failure), left)
			told = time.Now()
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nodeGaveUp(ctx, started, failure)
		case <-timer.C:
		}
		if wait *= 2; wait > nodeRetryMax {
			wait = nodeRetryMax
		}
		_, err := e.remoteCommand(ctx, cfg, []string{"/usr/bin/true"})
		switch {
		case err == nil:
			contact.status("Node %s answers again after %s; cleaning up.", contact.name, roughly(time.Since(started)))
			return nil
		case sshTransportFailed(err):
			failure = err
		case ctx.Err() != nil:
			return nodeGaveUp(ctx, started, failure)
		default:
			return err
		}
	}
}

// nodeUnreachableError is cleanup giving up, at its deadline, on a node
// that did not answer.
type nodeUnreachableError struct {
	waited time.Duration
	last   error // ssh's last failure to reach it
}

func (e *nodeUnreachableError) Error() string {
	return fmt.Sprintf("did not answer within %s (%s)", roughly(e.waited), sshReason(e.last))
}

func (e *nodeUnreachableError) Unwrap() error { return e.last }

// nodeGaveUp is why waiting for the node ended with ctx: its deadline, or
// the operator abandoning cleanup.
func nodeGaveUp(ctx context.Context, started time.Time, failure error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &nodeUnreachableError{waited: time.Since(started), last: failure}
	}
	return fmt.Errorf("waiting for the node ended (%v): %w", ctx.Err(), failure)
}

// roughly is d for an operator: whole minutes from a minute on, else
// seconds.
func roughly(d time.Duration) string {
	if d >= time.Minute {
		return fmt.Sprintf("%d min", int(d.Round(time.Minute)/time.Minute))
	}
	return fmt.Sprintf("%d s", int(d.Round(time.Second)/time.Second))
}

// nodeBootID is the node's boot ID, or "" when it cannot be read.
func (e *Executor) nodeBootID(ctx context.Context, cfg SSHConfig) string {
	output, err := e.remoteCommand(ctx, cfg, []string{"/usr/bin/cat", "/proc/sys/kernel/random/boot_id"})
	if err != nil {
		return ""
	}
	id := strings.TrimSpace(string(output))
	if uuid.Validate(id) != nil {
		return ""
	}
	return id
}

// recoverCommand is the command that recovers a retained workspace's run on
// the node, as an operator would type it there.
func (e *Executor) recoverCommand(cfg SSHConfig, workspace, stateDir string) []string {
	var command []string
	if cfg.UseSudo {
		command = append(command, "sudo")
	}
	return append(command, path.Join(workspace, "certistack-node"), "recover", "--state-dir", stateDir, "--env-file", path.Join(workspace, "runtime.env"))
}

// workerStopScript stops the worker recorded in pidPath, if it is still the
// workspace's own binary, and prints the outcome: absent (never started),
// gone (no longer running, or the PID now belongs to another program, which
// is never signalled), stopped, or still-running.
//
// The worker is identified once, by its binary and its start time, and
// every later signal and liveness check uses an open /proc directory of that
// process, the boot ID its supervisor recorded when it started it (the PID
// of an earlier boot is nobody's), and its start time and executable. The
// open directory retains the kernel's process identity even if its PID is
// reused in the same start tick. Shell signalling still has a
// check-to-signal interval; atomic signalling would require a pidfd rather
// than a numeric PID.
func workerStopScript(pidPath, workerPath string) string {
	return workerStopScriptWithin(pidPath, workerPath, gracefulWorkerStopTimeout)
}

// workerStopScriptWithin is workerStopScript with the given time, in
// seconds, for the worker to end after SIGTERM before it gets SIGKILL. A
// supervisor that reports a worker it could not kill has given it that time
// already, so the controller only checks once more.
func workerStopScriptWithin(pidPath, workerPath string, graceSeconds int) string {
	return fmt.Sprintf(`pid_file=%s
boot_file=%s
worker=%s
if [ ! -r "$pid_file" ]; then
  printf 'absent\n'
  exit 0
fi
pid=$(/usr/bin/tr -cd '0-9' < "$pid_file")
case "$pid" in
  '') printf 'gone\n'; exit 0 ;;
esac
# The boot the worker started in is the one its supervisor recorded beside
# the PID. A node that has booted since has started other programs under the
# PIDs of the boot before, so the recorded PID names no worker: it is gone
# with that boot. A worker whose supervisor recorded no boot is judged by its
# binary and start time alone, in the boot the node is in.
IFS= read -r current_boot < /proc/sys/kernel/random/boot_id || { printf 'gone\n'; exit 0; }
{ IFS= read -r worker_boot < "$boot_file"; } 2>/dev/null || worker_boot=
[ -n "$worker_boot" ] || worker_boot=$current_boot
if [ "$worker_boot" != "$current_boot" ]; then
  printf 'gone\n'
  exit 0
fi
# Pin the kernel process object: paths through this descriptor never switch
# to a replacement process that receives the same numeric PID.
{ command exec 9< "/proc/$pid"; } 2>/dev/null || { printf 'gone\n'; exit 0; }
pinned_proc_dir=/proc/$$/fd/9
%s
# The start time before and after reading the binary is the same, so the
# binary read is this process's.
proc_start "$pid"
identity=$ticks
exe=$(/usr/bin/readlink "$pinned_proc_dir/exe" 2>/dev/null) || exe=
proc_start "$pid"
if [ -z "$identity" ] || [ "$ticks" != "$identity" ] || [ "$state" = Z ] || { [ "$exe" != "$worker" ] && [ "$exe" != "$worker (deleted)" ]; }; then
  printf 'gone\n'
  exit 0
fi
running() {
  same_process "$pid" "$identity" || return 1
  IFS= read -r current_boot < /proc/sys/kernel/random/boot_id || return 1
  [ "$current_boot" = "$worker_boot" ] || return 1
  current_exe=$(/usr/bin/readlink "$pinned_proc_dir/exe" 2>/dev/null) || return 1
  [ "$current_exe" = "$exe" ] || return 1
  same_process "$pid" "$identity"
}
running && kill -TERM "$pid" 2>/dev/null
remaining=%d
while running && [ "$remaining" -gt 0 ]; do
  /bin/sleep 1
  remaining=$((remaining - 1))
done
if running; then
  kill -KILL "$pid" 2>/dev/null
  remaining=%d
  while running && [ "$remaining" -gt 0 ]; do
    /bin/sleep 1
    remaining=$((remaining - 1))
  done
fi
if running; then
  printf 'still-running\n'
else
  printf 'stopped\n'
fi
`, shellQuote(pidPath), shellQuote(workerBootPath(pidPath)), shellQuote(workerPath), processIdentityFunctions, graceSeconds, forcedWorkerStopWaitSeconds)
}

// workerBootPath is where a worker's supervisor records the boot ID of the
// node beside the worker's PID file, which the worker's stop compares with
// the node's boot at the time.
func workerBootPath(pidPath string) string {
	return strings.TrimSuffix(pidPath, ".pid") + ".boot"
}

// processIdentityFunctions are shell functions that tell a process from
// another that reuses its PID, by its start time in /proc/<pid>/stat, which
// the kernel fixes when the process is created. proc_start sets ticks and
// state to the start time and state of process $1, or both to nothing when
// there is none; the command name before them may hold spaces and
// parentheses, so the fields are read after its last ") ". same_process
// reports whether process $1 still runs and started at $2 (a zombie has
// ended). Both run only builtins. A script that sets pinned_proc_dir (the
// worker's stop does) has every read go through that open directory, whatever
// PID it asks about, so it may ask about no other process.
const processIdentityFunctions = `proc_start() {
  ticks=
  state=
  proc_stat_path=/proc/$1/stat
  [ -z "${pinned_proc_dir:-}" ] || proc_stat_path=$pinned_proc_dir/stat
  { IFS= read -r proc_stat < "$proc_stat_path"; } 2>/dev/null || return 0
  set -- ${proc_stat##*\) }
  if [ "$#" -ge 20 ]; then
    state=$1
    shift 19
    ticks=$1
  fi
}
same_process() {
  proc_start "$1"
  [ -n "$ticks" ] && [ "$ticks" = "$2" ] && [ "$state" != Z ] && [ "$state" != X ]
}`

// workerRunID is the run ID a worker records in its journal: derived from
// its private workspace, so the controller can tell that journal from any
// other run's.
func workerRunID(workspace string) string {
	return "run-" + path.Base(workspace)
}

// reconcileCompletedWorker verifies, and if need be reconciles, the durable
// journal of this exact worker run. It runs after every worker RPC that
// returns evidence, regardless of what that evidence claims: the controller
// does not sign a worker's own all_cleaned assertion without independently
// confirming it against the worker's durable, node-local journal.
//
// The journal (active.json) is node-wide and holds one run's record, so by
// the time this runs a later run may have replaced it. Only a record that
// names this run proves anything of it (see checkJournal): its own journal,
// cleaned; or, when a later run has replaced it, the transition record that
// run kept of this run's clean journal. Only this run's own journal, not yet
// clean, needs "<worker> recover", which takes the host lock: while another
// CertiStack operation holds it, the check waits and reads the journal again.
// That operation either recovers this journal itself before it starts, and
// then keeps its transition, or releases the lock.
//
// A journal that is missing, or names another run without its transition, is
// no proof: the check fails with a *journalUnprovenError, unless the caller
// asked for noRecordIsClean, which is for a run that returned no evidence.
func (e *Executor) reconcileCompletedWorker(ctx context.Context, cfg SSHConfig, workspaceRoot, workspace, stateDir string, check journalCheck) error {
	if !safeRemoteAbsolutePath(workspaceRoot) || path.Dir(workspace) != workspaceRoot || uuid.Validate(path.Base(workspace)) != nil || !safeRemoteAbsolutePath(stateDir) {
		return errors.New("refusing completed-worker cleanup for invalid worker paths")
	}
	workerPath := path.Join(workspace, "certistack-node")
	recoverCommand := append(e.privilegePrefix(cfg), workerPath, "recover", "--state-dir", stateDir, "--env-file", path.Join(workspace, "runtime.env"))
	wait := hostLockRetryInitial
	for {
		verdict, err := e.checkJournal(ctx, cfg, stateDir, check)
		if err != nil {
			return fmt.Errorf("verify completed worker journal: %w", err)
		}
		switch verdict.proof {
		case proofOwnCleaned, proofTransition:
			return nil
		case proofNone:
			if check.noRecordIsClean {
				if check.outcome != nil {
					check.outcome.noRecord = true
				}
				return nil
			}
			return &journalUnprovenError{runID: check.runID, reason: verdict.reason}
		}
		workspacePresent, err := e.remotePathExists(ctx, cfg, workspace)
		if err != nil {
			return fmt.Errorf("check completed worker workspace: %w", err)
		}
		if !workspacePresent {
			return errors.New("completed worker workspace is absent but its journal is not cleaned")
		}
		if check.outcome != nil {
			check.outcome.recovered = true
		}
		// Recovery reports each action as a progress event: the operator sees
		// what it cleaned up.
		if check.progress != nil {
			_, err = e.remoteCommandWithProgress(ctx, cfg, recoverCommand, check.progress)
		} else {
			_, err = e.remoteCommand(ctx, cfg, recoverCommand)
		}
		if err == nil {
			// "recover" acts on whatever journal the node holds, which may
			// no longer be this run's: only a journal that shows this run
			// clean verifies it.
			verdict, checkErr := e.checkJournal(ctx, cfg, stateDir, check)
			if checkErr != nil {
				return fmt.Errorf("verify the journal after recovery: %w", checkErr)
			}
			if verdict.proof == proofOwnCleaned || verdict.proof == proofTransition {
				return nil
			}
			return &journalUnprovenError{runID: check.runID, reason: "recovery reported success, but afterwards " + verdict.describe()}
		}
		if !strings.Contains(err.Error(), journal.LockHeldMessage) {
			if verdict, checkErr := e.checkJournal(ctx, cfg, stateDir, check); checkErr == nil && (verdict.proof == proofOwnCleaned || verdict.proof == proofTransition) {
				return nil
			}
			return fmt.Errorf("reconcile completed node-worker journal: %w", err)
		}
		if check.waiting != nil {
			check.waiting()
			check.waiting = nil
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("reconcile completed node-worker journal: another CertiStack operation still holds the host lock: %w", ctx.Err())
		case <-timer.C:
		}
		if wait *= 2; wait > hostLockRetryMax {
			wait = hostLockRetryMax
		}
	}
}

// remoteInspectionError is a remote lookup that established neither that a
// path is present nor that it is absent: the node's filesystem refused or
// failed the lookup (permission, I/O, a symlink loop, a component that is not a
// directory), or the probe did not answer in a form that can be read. It is
// never evidence of absence: callers keep the run's workspace and report the
// recovery state as unresolved.
type remoteInspectionError struct {
	path   string
	detail string
}

func (e *remoteInspectionError) Error() string {
	if e.detail == "" {
		return fmt.Sprintf("could not inspect %s on the node", e.path)
	}
	return fmt.Sprintf("could not inspect %s on the node: %s", e.path, e.detail)
}

// remotePathProbeScript answers "present", "absent" or "unknown <why>" for one
// path. "[ -e path ]" is false for a path that does not exist and for one
// whose lookup failed, so a false test is classified by what the filesystem
// said when the lookup was repeated: only "No such file or directory" is
// absence. Every other failure, and a lookup that cannot be run at all, is
// unknown. A path that appears between the two lookups is present.
func remotePathProbeScript(remotePath string) string {
	quoted := shellQuote(remotePath)
	return fmt.Sprintf(`if [ -e %[1]s ]; then /usr/bin/printf 'present\n'; else why=$(LC_ALL=C /usr/bin/stat -L -c %%F -- %[1]s 2>&1); status=$?; if [ "$status" -eq 0 ]; then /usr/bin/printf 'present\n'; else case "$why" in *': No such file or directory') /usr/bin/printf 'absent\n';; *) /usr/bin/printf 'unknown %%s\n' "$why" | /usr/bin/head -c 512;; esac; fi; fi`, quoted)
}

// remotePathExists is a remote existence probe with three outcomes: present
// (true, nil), definitely absent (false, nil) and unknown (false, a
// *remoteInspectionError, or the error of the command that could not run). An
// error is never to be read as "absent".
func (e *Executor) remotePathExists(ctx context.Context, cfg SSHConfig, remotePath string) (bool, error) {
	if !safeRemoteAbsolutePath(remotePath) {
		return false, errors.New("refusing to inspect an unsafe remote path")
	}
	// The state directory and every workspace are root-only (0700): probe
	// them as the worker's privileged identity, or a sudo account would see
	// everything in them as absent.
	output, err := e.remoteCommand(ctx, cfg, append(e.privilegePrefix(cfg), "/bin/sh", "-c", remotePathProbeScript(remotePath)))
	if err != nil {
		return false, err
	}
	answer := strings.TrimSpace(string(output))
	switch {
	case answer == "present":
		return true, nil
	case answer == "absent":
		return false, nil
	case answer == "unknown" || strings.HasPrefix(answer, "unknown "):
		return false, &remoteInspectionError{path: remotePath, detail: strings.TrimSpace(strings.TrimPrefix(answer, "unknown"))}
	default:
		return false, &remoteInspectionError{path: remotePath, detail: fmt.Sprintf("unexpected answer %q", answer)}
	}
}

// journalProof is what the node's journal shows of one run's cleanup.
type journalProof int

const (
	// proofNone: nothing in the node's state names this run. The journal is
	// missing, names another run, or names none, and the node holds no
	// transition record for this run.
	proofNone journalProof = iota
	// proofOwnCleaned: the journal is this run's own, and it is cleaned.
	proofOwnCleaned
	// proofTransition: the journal is another run's, and the node holds the
	// transition record that run kept of this run's clean journal, by which
	// it replaced it.
	proofTransition
	// proofOwnPending: the journal is this run's own and is not cleaned: it
	// records resources "<worker> recover" can act on.
	proofOwnPending
)

// journalVerdict is the result of checkJournal: what the node's state proves
// of the run, and, when nothing does, why not.
type journalVerdict struct {
	proof  journalProof
	reason string
}

// describe is the verdict for a sentence that says what the journal shows.
func (v journalVerdict) describe() string {
	switch v.proof {
	case proofOwnPending:
		return "the run's own journal is still not cleaned"
	case proofNone:
		return v.reason
	}
	return "the journal shows the run clean"
}

// journalUnprovenError is the node's journal not showing that a run left
// nothing behind. That says nothing of whether resources remain, which the
// controller cannot tell: it is no verification, and is never signed as one.
type journalUnprovenError struct {
	runID  string
	reason string
}

func (e *journalUnprovenError) Error() string {
	return fmt.Sprintf("the node's recovery journal does not show that run %s cleaned up after itself: %s", e.runID, e.reason)
}

// checkJournal reads the node's journal, without the host lock, and says
// what it proves of the run check.runID: that its own journal is cleaned, or
// pending (recover can act on it), or that the node holds a transition record
// of the run's clean journal. It proves nothing from a journal that is
// missing, that names no run, or that names another run: such a record does
// not say what became of this run's resources, and no phase, timestamp or
// run ID of a foreign record can.
func (e *Executor) checkJournal(ctx context.Context, cfg SSHConfig, stateDir string, check journalCheck) (journalVerdict, error) {
	if !safeRemoteAbsolutePath(stateDir) {
		return journalVerdict{}, errors.New("refusing to inspect an unsafe remote state directory")
	}
	if check.runID == "" {
		return journalVerdict{}, errors.New("no run ID to verify the journal against")
	}
	journalPath := path.Join(stateDir, "active.json")
	present, err := e.remotePathExists(ctx, cfg, journalPath)
	if err != nil {
		return journalVerdict{}, err
	}
	reason := "the journal is missing"
	if present {
		output, err := e.remoteCommand(ctx, cfg, append(e.privilegePrefix(cfg), "/usr/bin/cat", journalPath))
		if err != nil {
			return journalVerdict{}, err
		}
		var record struct {
			RunID string `json:"run_id"`
			Phase string `json:"phase"`
		}
		if err := json.Unmarshal(output, &record); err != nil {
			return journalVerdict{}, fmt.Errorf("decode active recovery journal: %w", err)
		}
		switch {
		case record.RunID == check.runID && record.Phase == "cleaned":
			if check.outcome != nil {
				check.outcome.ownCleaned = true
			}
			return journalVerdict{proof: proofOwnCleaned}, nil
		case record.RunID == check.runID:
			return journalVerdict{proof: proofOwnPending}, nil
		case record.RunID == "":
			reason = "the journal names no run"
		default:
			reason = fmt.Sprintf("the journal names another run (%s)", record.RunID)
		}
	}
	// The journal is not this run's. A later run replaces only a clean
	// journal, and keeps a record of it when it does.
	transitionPath := path.Join(stateDir, journal.TransitionsDir, check.runID+".json")
	kept, err := e.remotePathExists(ctx, cfg, transitionPath)
	if err != nil {
		return journalVerdict{}, err
	}
	if !kept {
		return journalVerdict{proof: proofNone, reason: reason + ", and the node holds no record of this run's journal having been clean when a later run replaced it"}, nil
	}
	output, err := e.remoteCommand(ctx, cfg, append(e.privilegePrefix(cfg), "/usr/bin/cat", transitionPath))
	if err != nil {
		return journalVerdict{}, err
	}
	var transition journal.Transition
	if err := json.Unmarshal(output, &transition); err != nil || transition.RunID != check.runID || transition.Phase != "cleaned" || transition.SupersededBy == "" {
		return journalVerdict{proof: proofNone, reason: reason + ", and the node's record of this run's journal is not a valid record that it was clean"}, nil
	}
	if check.outcome != nil {
		check.outcome.transition = true
	}
	return journalVerdict{proof: proofTransition}, nil
}

// journalCheck is what the controller knows when it verifies a worker run's
// journal: the run's ID, whether a run without a record is taken as having
// created nothing, and what to report once when the check must wait for the
// host lock.
type journalCheck struct {
	runID string
	// noRecordIsClean is for a run that returned no evidence: nothing signs
	// its cleanup, and a run journals every resource before it creates it,
	// so without any record of the run it created none. A run that returned
	// evidence has a record, and its absence is never a verification.
	noRecordIsClean bool
	waiting         func()
	// progress, when set, shows recovery's progress events.
	progress *progressReporter
	// outcome, when set, receives what the check found.
	outcome *journalOutcome
}

// journalOutcome is what a journal check found: this run's own journal
// already cleaned, a transition record of it, no record of the run at all,
// and whether the controller ran recovery.
type journalOutcome struct {
	ownCleaned bool
	transition bool
	noRecord   bool
	recovered  bool
	// workerStop is what the stop of the recorded worker found: "gone" (it no
	// longer ran), "stopped" (it ran and was stopped), or "absent".
	workerStop string
}

func (e *Executor) installWorkspace(ctx context.Context, cfg SSHConfig, stateDir, workspaceRoot, staging, workspace string, files []stagedFile) error {
	prefix := e.privilegePrefix(cfg)
	// The state directory, its "workers" child and the workspace are each
	// created 0700 when absent: the node worker's own EnsurePrivateDirectory
	// check requires the state directory to be exactly 0700. One that exists
	// is checked, never changed: GNU install -d would set the mode of an
	// existing directory, so a state directory of /tmp would lose its sticky,
	// world-writable mode before the worker refused it.
	if _, err := e.remoteSetupCommand(ctx, cfg, append(prefix, "/bin/sh", "-c", privateDirectoriesScript(stateDir, workspaceRoot, workspace))); err != nil {
		return fmt.Errorf("create protected node workspace: %w", err)
	}
	for _, file := range files {
		command := append([]string{}, prefix...)
		command = append(command, "/usr/bin/install", "-m", file.mode, path.Join(staging, file.remoteName), path.Join(workspace, file.remoteName))
		if _, err := e.remoteSetupCommand(ctx, cfg, command); err != nil {
			return fmt.Errorf("install worker input %s: %w", file.remoteName, err)
		}
	}
	return nil
}

// privateDirectoriesScript is a shell script that makes each of dirs, in
// order, a private directory of the user it runs as, and changes nothing
// that exists: an absent directory is created with mode 0700, and one that
// exists must already be a directory of that user with mode 0700. No
// component of any path may be a symbolic link. These are the node worker's
// own EnsurePrivateDirectory rules; the script refuses, with exit status 3
// and the reason, what the worker would refuse, before anything is changed.
func privateDirectoriesScript(dirs ...string) string {
	return fmt.Sprintf(`refuse() {
  /usr/bin/printf 'CertiStack refuses the directory %%s and changes nothing there: %%s\n' "$1" "$2" >&2
  exit 3
}
for dir in %s; do
  component=$dir
  while [ -n "$component" ] && [ "$component" != / ]; do
    if [ -L "$component" ]; then
      refuse "$dir" "$component is a symbolic link. Choose a path without one."
    fi
    component=${component%%/*}
  done
  if [ -e "$dir" ] || [ -L "$dir" ]; then
    if [ ! -d "$dir" ]; then
      refuse "$dir" "it exists and is not a directory."
    fi
    owner_mode=$(/usr/bin/stat -c '%%u %%a' -- "$dir") || exit 3
    if [ "$owner_mode" != "$(/usr/bin/id -u) 700" ]; then
      refuse "$dir" "it exists and is not private (owner and mode: $owner_mode). Choose an absent path, which CertiStack creates private, or one with mode 0700 owned by the user CertiStack runs as."
    fi
  elif ! /usr/bin/mkdir -p -m 0700 -- "$dir"; then
    exit 1
  fi
done
`, shellCommand(dirs))
}

// sharedTemporaryDirectories are the node's world-writable scratch areas.
// The worker refuses them as a state or scratch directory (sysutil's
// private-directory rules), so the controller refuses them before it
// contacts the node.
var sharedTemporaryDirectories = []string{"/tmp", "/var/tmp", "/dev/shm"}

// removeRetainedKey deletes the staged PBS encryption key from a workspace
// kept for recovery, and proves it is gone.
func (e *Executor) removeRetainedKey(ctx context.Context, cfg SSHConfig, workspaceRoot, workspace string) error {
	if !safeRemoteAbsolutePath(workspaceRoot) || path.Dir(workspace) != workspaceRoot || uuid.Validate(path.Base(workspace)) != nil {
		return errors.New("refusing to touch an invalid remote workspace")
	}
	key := path.Join(workspace, pbsKeyfileName)
	if _, err := e.remoteCommand(ctx, cfg, append(e.privilegePrefix(cfg), "/usr/bin/rm", "-f", key)); err != nil {
		return err
	}
	_, err := e.remoteCommand(ctx, cfg, append(e.privilegePrefix(cfg), "/usr/bin/test", "!", "-e", key))
	return err
}

// scrubWorkspaceCredentials removes the credentials of a workspace that is
// kept, its environment, the PBS encryption key and the worker binary, proves
// they are gone, and leaves a note saying when and why, unless the node left
// one. Its logs and results stay.
func (e *Executor) scrubWorkspaceCredentials(ctx context.Context, cfg SSHConfig, workspaceRoot, workspace, reason string) error {
	if !safeRemoteAbsolutePath(workspaceRoot) || path.Dir(workspace) != workspaceRoot || uuid.Validate(path.Base(workspace)) != nil {
		return errors.New("refusing to touch an invalid remote workspace")
	}
	credentials := []string{path.Join(workspace, "runtime.env"), path.Join(workspace, pbsKeyfileName), path.Join(workspace, "certistack-node")}
	note := path.Join(workspace, "credentials-removed.txt")
	text := fmt.Sprintf("Credentials removed (runtime.env, pbs-encryption.key, certistack-node) by the controller at %s: %s. Logs and results are kept.", time.Now().UTC().Format(time.RFC3339), reason)
	script := fmt.Sprintf(`/usr/bin/rm -f -- %s || exit 1
for file in %s; do
  [ ! -e "$file" ] || exit 1
done
[ -e %s ] || /usr/bin/printf '%%s\n' %s > %s
`, shellCommand(credentials), shellCommand(credentials), shellQuote(note), shellQuote(text), shellQuote(note))
	_, err := e.remoteCommand(ctx, cfg, append(e.privilegePrefix(cfg), "/bin/sh", "-c", script))
	return err
}

func (e *Executor) removeWorkspace(ctx context.Context, cfg SSHConfig, workspaceRoot, workspace string) error {
	if !safeRemoteAbsolutePath(workspaceRoot) || path.Dir(workspace) != workspaceRoot || uuid.Validate(path.Base(workspace)) != nil {
		return errors.New("refusing to remove an invalid remote workspace")
	}

	// A completed node worker can briefly leave the SSH daemon or its remote
	// filesystem busy. This directory contains the short-lived worker and its
	// runtime environment, so treating a single transport interruption as a
	// completed cleanup is unacceptable. Retry only the exact UUID workspace
	// that this invocation created, then prove it is absent.
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("remove temporary node workspace: %w", err)
		}
		if _, err := e.remoteCommand(ctx, cfg, append(e.privilegePrefix(cfg), "/usr/bin/rm", "-rf", workspace)); err != nil {
			lastErr = err
		} else if _, err := e.remoteCommand(ctx, cfg, append(e.privilegePrefix(cfg), "/usr/bin/test", "!", "-e", workspace)); err != nil {
			lastErr = fmt.Errorf("verify temporary node workspace removal: %w", err)
		} else {
			return nil
		}

		if attempt < 3 {
			backoff := time.Duration(attempt) * time.Second
			select {
			case <-ctx.Done():
				return fmt.Errorf("remove temporary node workspace: %w", ctx.Err())
			case <-time.After(backoff):
			}
		}
	}
	return fmt.Errorf("remove temporary node workspace after 3 attempts: %w", lastErr)
}

func (e *Executor) removeStaging(ctx context.Context, cfg SSHConfig, staging string) error {
	if !strings.HasPrefix(staging, "/tmp/certistack-controller-") || strings.Contains(staging, "..") {
		return errors.New("refusing to remove an invalid SSH staging directory")
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("remove temporary SSH staging directory: %w", err)
		}
		if _, err := e.remoteCommand(ctx, cfg, []string{"/usr/bin/rm", "-rf", staging}); err != nil {
			lastErr = err
		} else if _, err := e.remoteCommand(ctx, cfg, []string{"/usr/bin/test", "!", "-e", staging}); err != nil {
			lastErr = fmt.Errorf("verify temporary SSH staging directory removal: %w", err)
		} else {
			return nil
		}
		if attempt < 3 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("remove temporary SSH staging directory: %w", ctx.Err())
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
	}
	return fmt.Errorf("remove temporary SSH staging directory after 3 attempts: %w", lastErr)
}

// signingFailedError is a Signer that failed, or left a signature that does not
// verify. Its message is the wrapped error's.
type signingFailedError struct{ error }

func (e signingFailedError) Unwrap() error { return e.error }

// prepareReport checks the worker's report identity, adds the controller's
// build identity and the digest of the plan file it read, and has opts.Signer, when
// there is one, sign it. It returns the path the report must be saved at.
func prepareReport(report *attest.Report, expectedPlanID, planSHA256 string, opts RunOptions) (string, error) {
	if report == nil {
		return "", errors.New("cannot persist an empty report")
	}
	// What the worker's report says that the controller will not sign is a
	// refusal, whose raw result the caller keeps (refusedReportError).
	if report.PlanID != expectedPlanID {
		return "", refusedReportError{fmt.Errorf("worker report plan ID %q does not match loaded plan %q", report.PlanID, expectedPlanID)}
	}
	if err := uuid.Validate(report.ReportID); err != nil {
		return "", refusedReportError{fmt.Errorf("worker report ID is not a UUID: %w", err)}
	}
	reportPath, err := safeControllerReportPath(opts.OutputDir, report.PlanID, report.ReportID)
	if err != nil {
		return "", err
	}
	// Build identity is controller evidence and must be part of what is signed,
	// not appended after the signature is generated.
	report.EngineVersion = opts.Build.Version
	report.GitCommit = opts.Build.Commit
	report.BuildDate = opts.Build.BuildDate
	// The controller read the plan; the worker only ran it, so this is never
	// taken from the worker's report: whatever it carried is replaced.
	report.PlanSHA256 = planSHA256
	report.WorkerSHA256 = opts.Build.ExecutableSHA256
	// With no signer (the Community Edition) the report is saved as it is.
	if err := attest.ApplySigner(report, opts.Signer); err != nil {
		return "", signingFailedError{fmt.Errorf("sign controller report: %w", err)}
	}
	// The JSON report is the evidence. Human-readable HTML/PDF binders are
	// rendered on demand by the Enterprise daemon, never written here.
	return reportPath, nil
}

// checkReportDirectoryWritable creates the plan's report directory and
// proves a file can be written there, the way Report.Save will write it. A
// Community report is unsigned, so the directories' permissions are all that
// keep it as the run wrote it: the report directory and the plan's directory
// in it are refused when group or other users can write them, since any of
// them could replace a failed run's report with a passing one.
func checkReportDirectoryWritable(outputDir, planID string) error {
	probePath, err := safeControllerReportPath(outputDir, planID, "write-check")
	if err != nil {
		return err
	}
	dir := filepath.Dir(probePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("prepare controller report directory %s: %w", dir, err)
	}
	if runtime.GOOS != "windows" {
		for _, checked := range []string{filepath.Clean(outputDir), dir} {
			info, err := os.Stat(checked)
			if err != nil {
				return fmt.Errorf("inspect controller report directory %s: %w", checked, err)
			}
			if perm := info.Mode().Perm(); perm&0o022 != 0 {
				return fmt.Errorf("controller report directory %s can be written by group or other users (mode %04o), and any of them could replace a report with one that says something else; make it yours alone: chmod 700 %s", checked, perm, checked)
			}
		}
	}
	probe, err := os.CreateTemp(dir, ".certistack-write-check-")
	if err != nil {
		return fmt.Errorf("controller report directory %s is not writable: %w", dir, err)
	}
	name := probe.Name()
	closeErr := probe.Close()
	if removeErr := os.Remove(name); removeErr != nil {
		return fmt.Errorf("remove controller report directory write check %s: %w", name, removeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("controller report directory %s is not writable: %w", dir, closeErr)
	}
	return nil
}

// ErrEmergencyReportNotWritten is what Run's error wraps, next to the error
// that kept the report from being saved, when the emergency copy of the signed
// report could not be written to the operator's output either: the report then
// exists only in memory, as Result.Report, and a caller must keep it or the
// run's evidence is gone.
var ErrEmergencyReportNotWritten = errors.New("the emergency copy of the unsaved report could not be written either")

// WriteUnsavedReport writes a report that could not be saved to w, whole and
// between markers, so an operator can recover it from a terminal or job log.
// It fails when the report cannot be encoded or w does not take all of it, and
// says how much it took.
func WriteUnsavedReport(w io.Writer, report *attest.Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the unsaved report: %w", err)
	}
	block := []byte("-----BEGIN CERTISTACK REPORT-----\n" + string(data) + "\n-----END CERTISTACK REPORT-----\n")
	n, err := w.Write(block)
	if err == nil && n != len(block) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("wrote %d of %d bytes of the report: %w", n, len(block), err)
	}
	return nil
}

// interruptedBeforeWorker is the error of a step of Run before the worker is
// started on the node. When the run's context has ended, the step failed
// because of it, whatever it reports: an ssh child the cancellation killed
// says "signal: killed", which reads as an SSH failure. The run then ends as
// the interruption it is, with the context's error (exit status 130), and
// what the step left on the node (the staging directory, the workspace) is
// removed by Run's cleanup, as after any other step; a removal that cannot be
// verified is still reported with it. A step that failed while the context
// was live keeps its own error.
func interruptedBeforeWorker(ctx context.Context, progress *progressReporter, node string, err error) error {
	if err == nil || ctx.Err() == nil {
		return err
	}
	progress.failure("Controller interruption received before the worker started on node %s; nothing was started there.", node)
	return ctx.Err()
}

// unameMachines maps a Go GOARCH to what `uname -m` reports on a Linux node.
var unameMachines = map[string][]string{
	"amd64": {"x86_64"},
	"arm64": {"aarch64", "arm64"},
}

// checkNodeArchitecture refuses to upload a worker the node cannot execute.
// The controller uploads its own executable as the node worker, so its build
// must match the PVE node: an arm64 controller cannot drive an x86_64 node.
func (e *Executor) checkNodeArchitecture(ctx context.Context, cfg SSHConfig) error {
	output, err := e.remoteSetupCommand(ctx, cfg, []string{"/usr/bin/uname", "-m"})
	if err != nil {
		return fmt.Errorf("determine PVE node architecture: %w", err)
	}
	return CheckArchitecture(cfg, strings.TrimSpace(string(output)))
}

// CheckArchitecture refuses a node whose `uname -m` (machine) this controller
// build cannot run a worker on: the controller uploads its own executable.
func CheckArchitecture(cfg SSHConfig, machine string) error {
	for _, supported := range unameMachines[runtime.GOARCH] {
		if machine == supported {
			return nil
		}
	}
	return fmt.Errorf("PVE node %s reports architecture %q, but this controller is a linux/%s build and uploads itself as the node worker; run the controller build for the node's architecture (certistack-linux-amd64 or the controller container image for x86_64 Proxmox VE)", cfg.Host, machine, runtime.GOARCH)
}

func safeControllerReportPath(outputDir, planID, reportID string) (string, error) {
	reportPath := attest.DefaultReportPath(outputDir, planID, reportID)
	base, err := filepath.Abs(outputDir)
	if err != nil {
		return "", fmt.Errorf("resolve controller report directory: %w", err)
	}
	pathAbs, err := filepath.Abs(reportPath)
	if err != nil {
		return "", fmt.Errorf("resolve controller report path: %w", err)
	}
	rel, err := filepath.Rel(base, pathAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("controller report path escapes output directory")
	}
	return reportPath, nil
}

// stageWorkspace installs a node worker's workspace: the worker binary, the
// plan, the protected runtime environment and, when configured, the PVE CA
// and the PBS encryption key. They go through a private staging directory
// into workspace, which the caller removes. Run and Plan stage alike.
func (e *Executor) stageWorkspace(ctx context.Context, opts RunOptions, plan *config.Plan, localStage, workspaceRoot, workspace, staging string) error {
	worker, err := workerBinary()
	if err != nil {
		return err
	}
	stageWorker := filepath.Join(localStage, "certistack-node")
	if err := copyFile(worker, stageWorker, 0700); err != nil {
		return fmt.Errorf("stage node worker: %w", err)
	}
	files := []stagedFile{{local: stageWorker, remoteName: "certistack-node", mode: "0700"}}
	// init stages no plan: it discovers what to write one from.
	if plan != nil {
		stagePlan := filepath.Join(localStage, "plan.yaml")
		if err := writeWorkerPlan(stagePlan, plan); err != nil {
			return fmt.Errorf("stage validation plan: %w", err)
		}
		files = append(files, stagedFile{local: stagePlan, remoteName: "plan.yaml", mode: "0600"})
	}

	stageEnv := filepath.Join(localStage, "runtime.env")
	runtimeEnv, err := controllerRuntimeEnv(workspace)
	if err != nil {
		return err
	}
	if err := writeEnvFile(stageEnv, runtimeEnv); err != nil {
		return fmt.Errorf("write protected worker environment: %w", err)
	}
	files = append(files, stagedFile{local: stageEnv, remoteName: "runtime.env", mode: "0600"})
	if caSource := os.Getenv("CERTISTACK_PVE_CA_SOURCE"); caSource != "" {
		stageCA := filepath.Join(localStage, "pve-ca.pem")
		if err := stagePVECA(caSource, stageCA); err != nil {
			return fmt.Errorf("stage PVE CA file: %w", err)
		}
		files = append(files, stagedFile{local: stageCA, remoteName: "pve-ca.pem", mode: "0600"})
	}
	if keySource := os.Getenv("CERTISTACK_PBS_KEYFILE"); keySource != "" {
		// The key reaches the node only inside the run's private workspace,
		// which is removed after the run like the rest of it.
		stageKey := filepath.Join(localStage, pbsKeyfileName)
		if err := stagePBSKeyfile(keySource, stageKey, os.Getenv("PBS_ENCRYPTION_PASSWORD")); err != nil {
			return fmt.Errorf("stage PBS encryption key: %w", err)
		}
		files = append(files, stagedFile{local: stageKey, remoteName: pbsKeyfileName, mode: "0600"})
	}

	if err := e.createStaging(ctx, opts.SSH, staging); err != nil {
		return err
	}
	for _, file := range files {
		if err := e.copyToStaging(ctx, opts.SSH, file.local, staging); err != nil {
			return err
		}
	}
	if err := e.installWorkspace(ctx, opts.SSH, opts.StateDir, workspaceRoot, staging, workspace, files); err != nil {
		return err
	}
	if err := e.removeStaging(ctx, opts.SSH, staging); err != nil {
		return err
	}
	return nil
}

// NodeInterruptedError is a node worker stopped by a signal, as its result
// says: the node shutting down, or an operator. It is a context.Canceled,
// so the CLI reports an interruption, not a failed validation.
type NodeInterruptedError struct {
	Reason string // the worker's error, "interrupted: …" or "interrupted by …"
}

func (e *NodeInterruptedError) Error() string {
	if rest, ok := strings.CutPrefix(e.Reason, "interrupted: "); ok {
		return rest
	}
	if rest, ok := strings.CutPrefix(e.Reason, "interrupted by "); ok {
		return "the node worker received " + rest
	}
	return e.Reason
}

func (e *NodeInterruptedError) Unwrap() error { return context.Canceled }

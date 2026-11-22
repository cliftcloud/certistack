// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Manager decides whether the report is on and carries it out. The zero value
// of every field but Version is the production setting.
type Manager struct {
	// Version is the CertiStack version string the report carries.
	Version string
	// StatePath overrides DefaultStatePath (tests).
	StatePath string
	// Getenv overrides os.Getenv (tests).
	Getenv func(string) string
	// Now overrides time.Now (tests).
	Now func() time.Time
	// Timeout overrides SendTimeout (tests).
	Timeout time.Duration
}

func (m *Manager) getenv(name string) string {
	if m.Getenv != nil {
		return m.Getenv(name)
	}
	return os.Getenv(name)
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) path() (string, error) {
	if m.StatePath != "" {
		return m.StatePath, nil
	}
	return DefaultStatePath()
}

// Decision is whether the report is on, and why.
type Decision struct {
	Enabled bool
	// Environment: on only because CERTISTACK_TELEMETRY says so, with no stored
	// yes. The install (random id, salt, clusters, last send) is kept in the
	// state file like a stored answer's, so the report counts once and goes at
	// most once a day; no answer is stored. Where the file cannot be kept, the
	// decision is off instead.
	Environment bool
	// Forced: the environment decided, so the user is never asked.
	Forced bool
	Reason string
	// Unwritable says why the state file cannot be written, for an opt-in
	// through the environment that is off only because of it; "" otherwise.
	Unwritable string
	// KeptByEnvironment: off here, because this process does not set
	// CERTISTACK_TELEMETRY, but the state file holds the install that runs
	// which set it keep (a scheduled unit's), and those runs report.
	KeptByEnvironment bool
}

// Snapshot is the decision with what it was made from.
type Snapshot struct {
	Decision Decision
	Path     string
	PathErr  error
	State    State
	Status   StateStatus
}

// Resolve applies the controls strongest first: DO_NOT_TRACK or
// CERTISTACK_TELEMETRY off forces off; CERTISTACK_TELEMETRY on enables it,
// keeping an install in the state file, and is off where that cannot be done
// (no configuration directory, an unreadable file, a directory that cannot be
// written); otherwise the stored answer decides. A missing file is never
// asked, which is off; a corrupt one is off.
func (m *Manager) Resolve() Snapshot {
	var snap Snapshot
	snap.Path, snap.PathErr = m.path()
	if snap.PathErr == nil {
		snap.State, snap.Status = ReadState(snap.Path)
	}
	stored := snap.PathErr == nil && snap.Status == StateOK && snap.State.Enabled

	control, why := EnvControl(m.getenv)
	switch {
	case control == ControlOff:
		snap.Decision = Decision{Forced: true, Reason: why + ", which overrides any stored answer"}
	case control == ControlOn && stored:
		snap.Decision = Decision{Enabled: true, Forced: true, Reason: "you enabled it (" + why + " agrees)"}
	case control == ControlOn:
		snap.Decision = m.environmentDecision(snap, why)
	case snap.PathErr != nil:
		snap.Decision = Decision{Reason: "there is no per-user configuration directory to keep an answer in"}
	case snap.Status == StateCorrupt:
		snap.Decision = Decision{Reason: "the state file is unreadable or inconsistent, so it counts as off (certistack telemetry reset clears it)"}
	case stored:
		snap.Decision = Decision{Enabled: true, Reason: "you enabled it (certistack telemetry disable turns it off)"}
	case snap.Status == StateOK && snap.State.HasInstall():
		// Only the environment opt-in keeps an install with no yes stored:
		// runs that set it report, though this process does not.
		reason := environmentInstallReason(snap.Path, snap.State)
		if snap.State.Answered {
			reason = "you chose not to share (certistack telemetry enable turns it on), but " + reason
		}
		snap.Decision = Decision{Reason: reason, KeptByEnvironment: true}
	case snap.Status == StateOK && snap.State.Answered:
		snap.Decision = Decision{Reason: "you chose not to share (certistack telemetry enable turns it on)"}
	default:
		snap.Decision = Decision{Reason: "off by default: you have not been asked yet"}
	}
	return snap
}

// environmentInstallReason says what an install kept by CERTISTACK_TELEMETRY=1
// does, to a process that does not set the variable.
func environmentInstallReason(path string, st State) string {
	sent := "nothing sent yet"
	if st.LastSent != "" {
		sent = "last sent " + st.LastSent
	}
	return "the state at " + path + " holds an install kept by " + VarTelemetry + "=1 (" + sent + "): reports are sent by runs that set it, such as the scheduled unit; this shell does not set it"
}

// environmentDecision is CERTISTACK_TELEMETRY=1 with no stored yes. The report
// keeps what makes it once a day, so it is on only where that can be kept.
func (m *Manager) environmentDecision(snap Snapshot, why string) Decision {
	off := func(because string) Decision {
		return Decision{Forced: true, Reason: why + ", but " + because + ", so nothing is sent"}
	}
	switch {
	case snap.PathErr != nil:
		d := off("there is no per-user configuration directory to keep the install in")
		d.Unwritable = snap.PathErr.Error()
		return d
	case snap.Status == StateCorrupt:
		return off("the state file is unreadable or inconsistent (certistack telemetry reset clears it)")
	}
	if err := canWriteBeside(snap.Path); err != nil {
		d := off(err.Error())
		d.Unwritable = err.Error()
		return d
	}
	return Decision{Enabled: true, Environment: true, Forced: true, Reason: why + " enables it; the install id and the time of the last report are kept in the state file, and no answer is stored"}
}

// canWriteBeside says whether a file can be made next to path, in the nearest
// directory that exists. It makes and removes one empty file and leaves no
// directory behind.
func canWriteBeside(path string) error {
	dir := filepath.Dir(path)
	for {
		info, err := os.Stat(dir)
		switch {
		case err == nil:
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", dir)
			}
			f, err := os.CreateTemp(dir, ".certistack-write-test-*")
			if err != nil {
				var pathErr *fs.PathError
				if errors.As(err, &pathErr) {
					err = pathErr.Err
				}
				return fmt.Errorf("%s cannot be written (%v)", dir, err)
			}
			name := f.Name()
			_ = f.Close()
			_ = os.Remove(name)
			return nil
		case errors.Is(err, fs.ErrNotExist):
			parent := filepath.Dir(dir)
			if parent == dir {
				return fmt.Errorf("%s does not exist", dir)
			}
			dir = parent
		default:
			var pathErr *fs.PathError
			if errors.As(err, &pathErr) {
				err = pathErr.Err
			}
			return fmt.Errorf("%s cannot be reached (%v)", dir, err)
		}
	}
}

// Endpoint is the URL a report would go to, or why it would go nowhere.
func (m *Manager) Endpoint() (string, error) { return ResolveEndpoint(m.getenv) }

func (m *Manager) payload(st State) Payload {
	return Payload{
		InstallID:    st.InstallID,
		Version:      SanitizeVersion(m.Version),
		ClusterCount: len(st.Clusters),
		LastTestRun:  st.LastTestRun,
		BusinessUse:  st.BusinessUse,
	}
}

// Show is the exact request body that would be sent now: nil when the report
// is off. For the environment opt-in before its first report there is no
// install yet, so the install id shown is a sample, random on each call;
// Snapshot.State has no install then, and the first report makes the real one.
func (m *Manager) Show() (Snapshot, []byte, error) {
	snap := m.Resolve()
	if !snap.Decision.Enabled {
		return snap, nil, nil
	}
	st := snap.State
	if snap.Decision.Environment {
		if st.HasInstall() {
			st.BusinessUse = EnvBusiness(m.getenv)
		} else {
			var err error
			if st, err = NewEnvironmentInstall(false, EnvBusiness(m.getenv)); err != nil {
				return snap, nil, err
			}
		}
	}
	return snap, m.payload(st).Encode(), nil
}

// Enable stores a yes. An installation that is already enabled keeps its
// install id, salt and cluster set; only the business answer changes. So does
// the install an opt-in through the environment has kept: the yes joins it, and
// the server counts it once.
func (m *Manager) Enable(business bool) (State, error) {
	path, err := m.path()
	if err != nil {
		return State{}, err
	}
	unlock, err := lockState(path)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	st, status := ReadState(path)
	switch {
	case status == StateOK && st.Enabled:
	case status == StateOK && st.HasInstall():
		st.Answered, st.Enabled = true, true
	default:
		if st, err = NewInstall(business); err != nil {
			return State{}, err
		}
	}
	st.BusinessUse = business
	return st, WriteState(path, st)
}

// Disable stores a no and forgets the install id, salt and cluster set. It
// returns the install id it forgot, "" if there was none.
func (m *Manager) Disable() (string, error) {
	path, err := m.path()
	if err != nil {
		return "", err
	}
	unlock, err := lockState(path)
	if err != nil {
		return "", err
	}
	defer unlock()
	old, _ := ReadState(path)
	return old.InstallID, WriteState(path, Declined())
}

// ResetResult is what Reset did: the state file it looked at, whether there
// was one to delete, and the install id it forgot ("" when none).
type ResetResult struct {
	Path      string
	Deleted   bool
	InstallID string
}

// Reset deletes the state file: the answers and the install id are forgotten
// and the user will be asked again. Where there is no state file it deletes
// nothing, and says so in Deleted, so that nobody is told a file was removed
// that was never there.
func (m *Manager) Reset() (ResetResult, error) {
	path, err := m.path()
	if err != nil {
		return ResetResult{}, err
	}
	unlock, err := lockState(path)
	if err != nil {
		return ResetResult{Path: path}, err
	}
	defer unlock()
	result := ResetResult{Path: path}
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return result, nil
		}
		return result, fmt.Errorf("look at %s: %w", path, err)
	}
	old, _ := ReadState(path)
	if err := DeleteState(path); err != nil {
		return result, err
	}
	result.Deleted, result.InstallID = true, old.InstallID
	return result, nil
}

// ShouldPrompt is the first-run question's gate: a command that really runs
// something, both stdin and stderr at a terminal, CI unset, the environment
// silent, and no stored answer. Corrupt state is not asked about, because the
// answer would overwrite a file the user may want to look at.
func (m *Manager) ShouldPrompt(command string, stdinTerminal, stderrTerminal bool) bool {
	if !PromptCommands[command] || !stdinTerminal || !stderrTerminal || m.getenv("CI") != "" {
		return false
	}
	snap := m.Resolve()
	if snap.Decision.Forced || snap.PathErr != nil {
		return false
	}
	return snap.Status == StateMissing || (snap.Status == StateOK && !snap.State.Answered)
}

// PromptCommands are the commands that may ask: the ones that do real work.
// version, help, completion, verify-report and telemetry itself never ask.
var PromptCommands = map[string]bool{"run": true, "plan": true, "doctor": true, "init": true}

// Record stores the answers to the first-run questions.
func (m *Manager) Record(a Answer) error {
	path, err := m.path()
	if err != nil {
		return err
	}
	unlock, err := lockState(path)
	if err != nil {
		return err
	}
	defer unlock()
	if !a.Share {
		return WriteState(path, Declined())
	}
	if old, status := ReadState(path); status == StateOK && old.HasInstall() && !old.Enabled {
		// The environment kept an install before the question was asked.
		old.Answered, old.Enabled, old.BusinessUse = true, true, a.Business
		return WriteState(path, old)
	}
	st, err := NewInstall(a.Business)
	if err != nil {
		return err
	}
	return WriteState(path, st)
}

// Completed is a finished restore test as the report may know it.
type Completed struct {
	// Cluster is the identity of the PVE cluster the run knows: the SHA-256 of
	// the cluster CA certificate the controller pins, else the node name. It is
	// hashed with the install's salt and never sent.
	Cluster  string
	TestedAt time.Time
}

// Outcome says what AfterRun did. The caller logs it, and warns only when
// StateProblem is set.
type Outcome struct {
	Sent bool
	// Why is the reason nothing was sent, or what failed.
	Why string
	Err error
	// StateProblem is set when the report is on (a stored yes, or
	// CERTISTACK_TELEMETRY=1) and nothing was sent because the state file,
	// StatePath, could not be written: why it could not. A report that is on
	// and cannot keep its state is never sent, and the run says so once
	// (UnwritableWarning), since an opt-in that sends nothing and says nothing
	// is an opt-in nobody can tell is broken.
	StateProblem string
	StatePath    string
}

// UnwritableFix is how to give an account without a writable home a state file
// it can write; the telemetry page (#service-accounts) says the same.
const UnwritableFix = "Set XDG_CONFIG_HOME to a directory this account can write, for example in a systemd unit Environment=XDG_CONFIG_HOME=%S/certistack (https://certistack.dev/docs/telemetry/#service-accounts)."

// UnwritableWarning is the one line a run prints when the report is on but its
// state file could not be written, so nothing was sent; "" for any other
// outcome.
func (o Outcome) UnwritableWarning() string {
	if o.StateProblem == "" {
		return ""
	}
	file := "the state file " + o.StatePath
	if o.StatePath == "" {
		file = "the state file"
	}
	return fmt.Sprintf("Warning: no usage statistics were sent: they are on, but %s could not be written (%s). %s", file, o.StateProblem, UnwritableFix)
}

// AfterRun is the one place a report is sent. It does nothing unless the
// decision is enabled, sends at most one report per Interval for an install
// kept in the state file (a stored yes, or the install an opt-in through the
// environment keeps), and never retries. Where the state cannot be read, locked
// or written, nothing is sent. ctx bounds the wait; the caller gives it
// ExitBudget.
func (m *Manager) AfterRun(ctx context.Context, run Completed) Outcome {
	snap := m.Resolve()
	if !snap.Decision.Enabled {
		return Outcome{Why: "disabled: " + snap.Decision.Reason, StateProblem: snap.Decision.Unwritable, StatePath: snap.Path}
	}
	endpoint, err := ResolveEndpoint(m.getenv)
	if err != nil {
		return Outcome{Why: "the endpoint is not acceptable", Err: err}
	}
	now := m.now().UTC()
	tested := run.TestedAt
	if tested.IsZero() {
		tested = now
	}
	business := EnvBusiness(m.getenv)
	record := func(st *State) error {
		if snap.Decision.Environment && !st.Enabled {
			st.BusinessUse = business // the environment answers; a stored yes keeps its own
		}
		if err := st.AddCluster(run.Cluster); err != nil {
			return err
		}
		if date := tested.UTC().Format(DateLayout); date > st.LastTestRun {
			st.LastTestRun = date
		}
		return nil
	}
	st, ended := m.reserve(ctx, snap, now, record)
	if ended != nil {
		return *ended
	}
	if err := ctx.Err(); err != nil {
		return Outcome{Why: "interrupted", Err: err}
	}
	client := Client{URL: endpoint, UserAgent: UserAgentPrefix + SanitizeVersion(m.Version), Timeout: m.Timeout}
	if err := client.Send(ctx, m.payload(st).Encode()); err != nil {
		return Outcome{Why: "the report was not delivered", Err: err}
	}
	return Outcome{Sent: true}
}

// reserve is AfterRun's step on the state file, taken under the lock from the
// state as it is then. The decision to report was made from a state read
// without the lock, and the user may have opted out, reset or set up anew
// since, or another run may have finished and sent. So the state is read again:
// an opt-out wins (nothing of this run is written, nothing is sent), what
// another run recorded is kept, and the day's attempt goes to the one run that
// finds it due. For the environment opt-in the install is made here, the first
// time, and kept without an answer; a state file that cannot be read, locked or
// written ends the run without a send, and so does a lock still held when ctx
// ends. It returns the state to report from, or the outcome that ends the run.
// The send itself is made after the lock is let go. A report authorized here can still be delivered when the user opts out a
// moment later, as one already in flight can; the opt-out cannot recall it, and
// no later run reports.
func (m *Manager) reserve(ctx context.Context, snap Snapshot, now time.Time, record func(*State) error) (State, *Outcome) {
	unlock, err := lockStateContext(ctx, snap.Path)
	if err != nil {
		return State{}, &Outcome{Why: "could not lock the telemetry state, so nothing was recorded or sent", Err: err}
	}
	defer unlock()
	st, status := ReadState(snap.Path)
	if snap.Decision.Environment {
		switch {
		case status == StateCorrupt:
			return State{}, &Outcome{Why: "the telemetry state file is unreadable or inconsistent, so nothing was recorded or sent (certistack telemetry reset clears it)"}
		case status == StateOK && (st.Enabled || st.HasInstall()):
			// A yes was stored meanwhile, or an earlier run kept the install.
		default:
			// The first report: make the install and keep it, with the answer
			// the file already held (a stored no stays a no).
			if st, err = NewEnvironmentInstall(status == StateOK && st.Answered, false); err != nil {
				return State{}, &Outcome{Why: "could not make an install id", Err: err}
			}
		}
	} else if status != StateOK || !st.Enabled || st.InstallID != snap.State.InstallID {
		return State{}, &Outcome{Why: "disabled: telemetry was turned off, reset or set up anew while this run was finishing, so nothing was recorded or sent"}
	}
	if err := record(&st); err != nil {
		return State{}, &Outcome{Why: "could not record the cluster", Err: err}
	}
	due := true
	if last, err := time.Parse(time.RFC3339, st.LastSent); err == nil {
		delta := now.Sub(last)
		due = delta >= Interval || delta <= -Interval
	}
	if !due {
		if err := WriteState(snap.Path, st); err != nil {
			return State{}, &Outcome{Why: "could not record the run, so nothing was sent", Err: err, StateProblem: err.Error(), StatePath: snap.Path}
		}
		return State{}, &Outcome{Why: "a report was already sent in the last 24 hours"}
	}
	// The attempt is recorded before it is made: a server that is down or
	// slow costs one wait a day, not one per run, and a state that cannot
	// be written sends nothing.
	st.LastSent = now.Format(time.RFC3339)
	if err := WriteState(snap.Path, st); err != nil {
		return State{}, &Outcome{Why: "could not record the send, so none was made", Err: err, StateProblem: err.Error(), StatePath: snap.Path}
	}
	return st, nil
}

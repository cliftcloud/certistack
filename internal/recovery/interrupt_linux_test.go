//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

// The command's first interrupt reached nothing of local recovery: it could not
// end the PVE work (a five-minute budget of its own), the watched steps or the
// reads, and the second interrupt could not cut a started command short. These
// tests drive the context-taking entry with fakes.

// interruptWithin is how long a wait that an interrupt ends may take to end.
const interruptWithin = 5 * time.Second

// recoverInBackground runs RecoverLockedContext and returns what it answers.
func recoverInBackground(ctx, abandon context.Context, stateDir string) <-chan error {
	done := make(chan error, 1)
	go func() { done <- RecoverLockedContext(ctx, abandon, stateDir) }()
	return done
}

// endsWithin waits for a recovery to answer.
func endsWithin(t *testing.T, done <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(interruptWithin):
		t.Fatalf("recovery did not end within %s of %s", interruptWithin, what)
		return nil
	}
}

// requireUnresolved checks that an interrupted recovery left the journal
// unresolved and said why.
func requireUnresolved(t *testing.T, stateDir string) journal.Record {
	t.Helper()
	after := journalPhase(t, stateDir)
	if after.Phase == "cleaned" || after.Phase != "cleanup_failed" {
		t.Fatalf("journal phase = %q, want cleanup_failed (the interrupted recovery left it unresolved)", after.Phase)
	}
	if !strings.Contains(strings.Join(after.CleanupErrors, "\n"), "interrupted") {
		t.Fatalf("journal cleanup errors = %q, want them to say recovery was interrupted", after.CleanupErrors)
	}
	return after
}

// blockingPVE is a PVE that answers a request for a VM only when released: the
// first request tells started, and a request whose client gave up ends.
func blockingPVE(t *testing.T) (started <-chan struct{}) {
	t.Helper()
	release := make(chan struct{})
	first := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(first) })
		select {
		case <-r.Context().Done():
		case <-release:
		}
		http.Error(w, "released", http.StatusServiceUnavailable)
	}))
	t.Cleanup(func() { close(release); server.Close() })
	t.Setenv("PVE_URL", server.URL)
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "synthetic-token")
	t.Setenv("PVE_TLS_INSECURE", "")
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", "")
	return first
}

// The PVE phase has a five-minute budget of its own: an operator's interrupt
// has to end it, with the VM and everything it uses still journaled.
func TestInterruptEndsTheWaitOnPVEAndLeavesTheJournalUnresolved(t *testing.T) {
	started := blockingPVE(t)
	stateDir, overlay, _ := depsJournal(t, journal.Process{}, true)
	previous := pveRecoveryTimeout
	pveRecoveryTimeout = time.Minute // far beyond the test: only the interrupt can end the wait
	t.Cleanup(func() { pveRecoveryTimeout = previous })

	ctx, interrupt := context.WithCancel(context.Background())
	defer interrupt()
	done := recoverInBackground(ctx, context.Background(), stateDir)
	select {
	case <-started:
	case <-time.After(interruptWithin):
		t.Fatal("recovery never asked PVE about the recorded VM")
	}
	interrupt()
	err := endsWithin(t, done, "the interrupt")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("recovery = %v, want an interrupted outcome (wrapping context.Canceled), so the command exits 130", err)
	}
	after := requireUnresolved(t, stateDir)
	if len(after.VMs) != 1 || len(after.HostAddresses) != 1 || len(after.Loops) != 1 {
		t.Fatalf("journal = %+v, want the VM and what it uses still recorded", after)
	}
	if _, statErr := os.Stat(overlay); statErr != nil {
		t.Fatalf("overlay removed while the VM was not confirmed gone: %v", statErr)
	}
}

// An interrupt that arrived before recovery started anything must not make it
// start: a recorded QEMU process is not killed, a recorded overlay not removed,
// a recorded address not touched, and the journal stays unresolved.
func TestInterruptBeforeRecoveryStartsStartsNothing(t *testing.T) {
	vmRecoveryPVE(t, "") // the VM is gone
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	identity, err := process.ProcessIdentity(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if identity.BootID, err = process.CurrentBootID(); err != nil {
		t.Skipf("no boot identity on this host: %v", err)
	}
	stateDir, overlay, consumer := depsJournal(t, identity, true)
	_ = consumer.Close()
	withIdentity, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	withIdentity.SetHostAddressIdentity("csVn01", "10.100.0.1/24", 5, 41) // what recovery could remove
	if err := journal.Write(filepath.Join(stateDir, "active.json"), withIdentity); err != nil {
		t.Fatal(err)
	}
	_, calls := hostShims(t, 5, 41)

	ctx, interrupt := context.WithCancel(context.Background())
	interrupt()
	err = endsWithin(t, recoverInBackground(ctx, context.Background(), stateDir), "start")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("recovery = %v, want an interrupted outcome", err)
	}
	if !runs(child.Process.Pid) {
		t.Fatal("an interrupted recovery killed a recorded QEMU process it had not started to stop")
	}
	if _, statErr := os.Stat(overlay); statErr != nil {
		t.Fatalf("an interrupted recovery removed the overlay: %v", statErr)
	}
	if got := calls(); got != "" {
		t.Fatalf("an interrupted recovery ran host commands:\n%s", got)
	}
	after := requireUnresolved(t, stateDir)
	if len(after.HostAddresses) != 1 || len(after.DeltaFiles) != 1 || after.VMs[0].Process.PID != child.Process.Pid {
		t.Fatalf("journal = %+v, want everything still recorded", after)
	}
}

// Stopping what holds a PBS map's loop is a watched step with a three-minute
// bound: the interrupt ends it, and the loop stays recorded.
func TestInterruptEndsTheStopOfWhatHoldsALoop(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	maps := hostWithProcs(t, root, noSignal(t))
	log := fakeLoopTools(t, "exit 19")
	recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
	maps.add("loop7", maps.runDir, "repo"+scsi1Tail, time.Time{})
	journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}}, resolvedIntent(at, "/dev/loop7"))

	waiting := make(chan struct{})
	previous := releaseLoopHolders
	t.Cleanup(func() { releaseLoopHolders = previous })
	releaseLoopHolders = func(ctx context.Context, device string, _ []sysutil.LoopIdentity) ([]sysutil.LoopHolder, error) {
		close(waiting)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Second): // far beyond the test
			return nil, nil
		}
	}

	ctx, interrupt := context.WithCancel(context.Background())
	defer interrupt()
	done := recoverInBackground(ctx, context.Background(), stateDir)
	select {
	case <-waiting:
	case <-time.After(interruptWithin):
		t.Fatal("recovery never began to stop what holds the loop")
	}
	interrupt()
	err := endsWithin(t, done, "the interrupt")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("recovery = %v, want an interrupted outcome", err)
	}
	if calls := callsIn(log); strings.Contains(calls, "losetup") {
		t.Fatalf("the loop was detached after the interrupt:\n%s", calls)
	}
	after := requireUnresolved(t, stateDir)
	if len(after.Loops) != 1 {
		t.Fatalf("journal = %+v, want the loop still recorded", after)
	}
}

// The wait for a loop detach that never returns ends at the interrupt, and the
// hung-detach remedy (aborting the map's FUSE connection) is not taken for an
// operator's interrupt.
func TestInterruptEndsTheWaitForALoopDetach(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	maps := hostWithProcs(t, root, noSignal(t))
	log := fakeLoopTools(t, "exit 19")
	recordHolders(t, log, nil, nil)
	// A losetup that is asked and does not return for a while.
	hung := "#!/bin/sh\nprintf 'losetup %s\\n' \"$*\" >> '" + log + "'\nexec /bin/sleep 8\n"
	if err := os.WriteFile(filepath.Join(filepath.Dir(log), "losetup"), []byte(hung), 0o755); err != nil {
		t.Fatal(err)
	}
	recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
	maps.add("loop7", maps.runDir, "repo"+scsi1Tail, time.Time{})
	journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}}, resolvedIntent(at, "/dev/loop7"))

	ctx, interrupt := context.WithCancel(context.Background())
	defer interrupt()
	done := recoverInBackground(ctx, context.Background(), stateDir)
	deadline := time.Now().Add(interruptWithin)
	for !strings.Contains(callsIn(log), "losetup -d /dev/loop7") {
		if time.Now().After(deadline) {
			t.Fatal("recovery never asked for the detach")
		}
		time.Sleep(10 * time.Millisecond)
	}
	interrupt()
	err := endsWithin(t, done, "the interrupt")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("recovery = %v, want an interrupted outcome", err)
	}
	if !strings.Contains(err.Error(), "/dev/loop7") {
		t.Fatalf("recovery = %v, want the loop that was left named", err)
	}
	after := requireUnresolved(t, stateDir)
	if len(after.Loops) != 1 {
		t.Fatalf("journal = %+v, want the loop still recorded", after)
	}
	// Not "hung": the detach was waited for for a fraction of the watchdog.
	if strings.Contains(err.Error(), "stuck in the kernel") {
		t.Fatalf("recovery = %v: an interrupt is not a hung detach", err)
	}
}

// slowHostShims is hostShims whose `ip -o link show` (the first command of a
// probe address's removal) takes delay before it answers; with delay "forever"
// it never answers, and only being killed ends it.
func slowHostShims(t *testing.T, ifindex int, handle uint64, delay string) (calls func() string) {
	t.Helper()
	_, calls = hostShims(t, ifindex, handle)
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	wait := "/bin/sleep " + delay
	if delay == "forever" {
		wait = "exec /bin/sleep 600"
	}
	slow := `#!/bin/sh
dir=$(dirname "$0")
echo "ip $*" >> "$dir/calls"
case "$*" in
"-o link show dev "*)
  ` + wait + `
  i=$(cat "$dir/ifindex")
  echo "$i: $5: <BROADCAST> mtu 1500"
  exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(ip, []byte(slow), 0o755); err != nil {
		t.Fatal(err)
	}
	return calls
}

// The second interrupt cuts short the commands of a probe address's removal
// that is running: the address stays recorded, and nothing is called cleaned.
func TestSecondInterruptCutsShortAHostCommandThatIsRunning(t *testing.T) {
	calls := slowHostShims(t, 5, 41, "forever")
	address := journal.TrackedHostAddress{Interface: "csVnReuse", CIDR: "10.100.77.1/24", IfIndex: 5, TableHandle: 41}
	stateDir := hostAddressJournal(t, address)

	first, interrupt := context.WithCancel(context.Background())
	second, abandon := context.WithCancel(context.Background())
	defer interrupt()
	defer abandon()
	done := recoverInBackground(first, second, stateDir)
	deadline := time.Now().Add(interruptWithin)
	for !strings.Contains(calls(), "ip -o link show") {
		if time.Now().After(deadline) {
			t.Fatal("recovery never began the removal")
		}
		time.Sleep(10 * time.Millisecond)
	}
	interrupt()
	abandon()
	err := endsWithin(t, done, "the second interrupt")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("recovery = %v, want an interrupted outcome", err)
	}
	if strings.Contains(calls(), "delete") {
		t.Fatalf("the abandoned removal went on:\n%s", calls())
	}
	after := requireUnresolved(t, stateDir)
	if len(after.HostAddresses) != 1 {
		t.Fatalf("journal = %+v, want the address still recorded", after)
	}
}

// The first interrupt alone does not cut a started removal short: the address
// and its table are removed together or the table is left without its address,
// so what is begun is finished, and the journal says so when it is complete.
func TestFirstInterruptLetsAStartedAddressRemovalFinish(t *testing.T) {
	calls := slowHostShims(t, 5, 41, "1")
	address := journal.TrackedHostAddress{Interface: "csVnReuse", CIDR: "10.100.77.1/24", IfIndex: 5, TableHandle: 41}
	stateDir := hostAddressJournal(t, address)

	first, interrupt := context.WithCancel(context.Background())
	defer interrupt()
	done := recoverInBackground(first, context.Background(), stateDir)
	deadline := time.Now().Add(interruptWithin)
	for !strings.Contains(calls(), "ip -o link show") {
		if time.Now().After(deadline) {
			t.Fatal("recovery never began the removal")
		}
		time.Sleep(10 * time.Millisecond)
	}
	interrupt()
	if err := endsWithin(t, done, "the interrupt"); err != nil {
		t.Fatalf("recovery = %v: the removal it had begun was the last thing it had to do", err)
	}
	got := calls()
	if !strings.Contains(got, "ip address delete 10.100.77.1/24 dev csVnReuse") || !strings.Contains(got, "nft delete table inet handle 41") {
		t.Fatalf("recovery calls:\n%s\nwant the begun removal finished", got)
	}
	if after := journalPhase(t, stateDir); after.Phase != "cleaned" {
		t.Fatalf("journal phase = %q, want cleaned: everything was done", after.Phase)
	}
}

// With live contexts the context-taking entry is the same recovery.
func TestRecoverLockedContextWithLiveContextsIsTheSameRecovery(t *testing.T) {
	_, calls := hostShims(t, 5, 41)
	stateDir := hostAddressJournal(t, journal.TrackedHostAddress{Interface: "csVnReuse", CIDR: "10.100.77.1/24", IfIndex: 5, TableHandle: 41})
	if err := RecoverLockedContext(context.Background(), context.Background(), stateDir); err != nil {
		t.Fatal(err)
	}
	got := calls()
	if !strings.Contains(got, "ip address delete 10.100.77.1/24 dev csVnReuse") || !strings.Contains(got, "nft delete table inet handle 41") {
		t.Fatalf("recovery calls:\n%s", got)
	}
	if after := journalPhase(t, stateDir); after.Phase != "cleaned" {
		t.Fatalf("journal phase = %q, want cleaned", after.Phase)
	}
}

// Recover and RecoverLocked keep their signatures: the Enterprise daemon calls
// recovery.Recover(stateDir) and the node worker RecoverLocked.
var (
	_ func(string) error = Recover
	_ func(string) error = RecoverLocked
)

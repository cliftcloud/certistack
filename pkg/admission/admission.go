// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package admission provides a controller to evaluate host resource utilization.
package admission

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/progress"
)

// Config holds admission control thresholds.
type Config struct {
	MaxHostRAMPercent     float64
	MaxHostIOWaitPercent  float64
	DeferRetryIntervalSec int
	MaxDeferRetries       int
}

// Controller evaluates host resource utilization against configured
// thresholds before permitting DR simulation execution.
type Controller struct {
	cfg Config

	mu   sync.Mutex
	last Evaluation
}

// The decisions an Evaluation records. They are the vocabulary a signed
// report uses (attest.AdmissionEvaluation), so a verifier can tell a grant
// from each way a run was refused.
const (
	// DecisionGranted: every limit held at the last check.
	DecisionGranted = "granted"
	// DecisionDeniedRAM: the share of memory in use already exceeded the limit.
	DecisionDeniedRAM = "denied_ram"
	// DecisionDeniedIOWait: the measured I/O wait exceeded the limit.
	DecisionDeniedIOWait = "denied_iowait"
	// DecisionDeniedIOWaitUnmeasured: no usable I/O wait sample could be taken,
	// and unknown load is not idle load.
	DecisionDeniedIOWaitUnmeasured = "denied_iowait_unmeasured"
	// DecisionDeniedProjectedRAM: current use plus the recovery reservation
	// would exceed the limit.
	DecisionDeniedProjectedRAM = "denied_projected_ram"
	// DecisionNeverAdmissible: the reservation alone exceeds the limit on this
	// node's total memory, so no wait can admit the run.
	DecisionNeverAdmissible = "never_admissible"
	// DecisionMetricsUnavailable: the host's memory or CPU counters could not
	// be read.
	DecisionMetricsUnavailable = "metrics_unavailable"
	// DecisionPreflightDeniedMemory: available memory cannot hold the requested
	// recovery reservation before orchestration starts.
	DecisionPreflightDeniedMemory = "preflight_denied_memory"
)

// KnownDecision reports whether decision is one this package records.
func KnownDecision(decision string) bool {
	switch decision {
	case DecisionGranted, DecisionDeniedRAM, DecisionDeniedIOWait, DecisionDeniedIOWaitUnmeasured,
		DecisionDeniedProjectedRAM, DecisionNeverAdmissible, DecisionMetricsUnavailable, DecisionPreflightDeniedMemory:
		return true
	}
	return false
}

// Evaluation is what the most recent admission check measured and decided. A
// run that is deferred is checked again after each retry interval, so Checks
// counts the evaluations, and the measurements are those of the last one: the
// check that granted the run, or the one that refused it last.
//
// A measurement a check did not reach is zero, and Decision says which were
// taken: DecisionNeverAdmissible read only the node's memory;
// DecisionDeniedIOWaitUnmeasured has no I/O wait; DecisionMetricsUnavailable
// has none of them.
type Evaluation struct {
	Checks   int
	Decision string
	// HostTotalMiB and HostAvailableMiB are MemTotal and MemAvailable of
	// /proc/meminfo, in MiB, as read for the recovery reservation. They are
	// read after the I/O wait sample, which takes about half a second, so they
	// can differ a little from the reading HostRAMPercent comes from.
	HostTotalMiB         float64
	HostAvailableMiB     float64
	RequiredAvailableMiB float64 // preflight reservation, zero for ordinary admission
	// HostRAMPercent is the share of memory in use when the check first read
	// it ((MemTotal-MemAvailable)/MemTotal).
	HostRAMPercent float64
	// HostIOWaitPercent is the share of all CPU time spent in iowait over one
	// sampling interval of /proc/stat (half a second; a sample that is not
	// usable is taken again, up to three intervals).
	HostIOWaitPercent float64
	// ProjectedRAMPercent is the share of memory in use once the recovery
	// reservation is added to the use at the time of the second memory
	// reading; it is what is held to the RAM limit. Without a reservation it is
	// HostRAMPercent.
	ProjectedRAMPercent float64
}

// Evaluation returns the most recent check's measurements and decision.
// Checks is zero when no check ran.
func (c *Controller) Evaluation() Evaluation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// record stores a finished check's evaluation, counting it.
func (c *Controller) record(ev Evaluation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ev.Checks = c.last.Checks + 1
	c.last = ev
}

// The readings a check takes, replaced by tests.
var (
	readRAMCapacity = readRAMCapacityMB
	readRAMUsage    = readRAMUsagePercent
	readIOWait      = readIOWaitPercent
)

// ErrAdmissionDenied is returned when host resource thresholds are exceeded.
var ErrAdmissionDenied = errors.New("admission denied")

// ErrMaxRetriesExceeded is returned when all retry attempts are exhausted.
var ErrMaxRetriesExceeded = errors.New("max admission retries exceeded")

// ErrNeverAdmissible means no wait can admit the run: the plan's sandbox
// VMs alone need more memory than the RAM limit lets this node hold, even
// idle. Admission refuses it at once instead of deferring and retrying.
var ErrNeverAdmissible = errors.New("the plan can never be admitted on this node")

// ReservationFits reports, as ErrNeverAdmissible, a recovery reservation
// that the node's total memory cannot hold within maxPercent, whatever else
// runs on it. A node whose memory cannot be read is not judged.
func ReservationFits(reservedMemoryMB int, maxPercent float64) error {
	_, _, err := reservationCheck(reservedMemoryMB, maxPercent)
	return err
}

// reservationCheck is ReservationFits that also returns the node's memory as
// it read it (zero when it could not be read, which is not judged).
func reservationCheck(reservedMemoryMB int, maxPercent float64) (totalMB, availableMB float64, err error) {
	totalMB, availableMB, readErr := readRAMCapacity()
	if readErr != nil || totalMB <= 0 {
		return 0, 0, nil
	}
	return totalMB, availableMB, reservationFits(totalMB, reservedMemoryMB, maxPercent)
}

func reservationFits(totalMB float64, reservedMemoryMB int, maxPercent float64) error {
	limitMB := totalMB * maxPercent / 100
	if totalMB <= 0 || maxPercent <= 0 || float64(reservedMemoryMB) <= limitMB {
		return nil
	}
	return fmt.Errorf("%w: its sandbox VMs reserve %s of memory (all tiers stay up until teardown), more than this node can ever hold within max_host_ram_percent %.0f%% of its %s (%s); split the plan into smaller ones or run it on a node with more memory",
		ErrNeverAdmissible, gibibytes(float64(reservedMemoryMB)), maxPercent, gibibytes(totalMB), gibibytes(limitMB))
}

func gibibytes(mb float64) string {
	return fmt.Sprintf("%.0f GiB", mb/1024)
}

// New creates a controller with the given thresholds.
func New(cfg Config) *Controller {
	return &Controller{cfg: cfg}
}

// AvailableMemoryMB returns the node's available memory (MemAvailable) in
// MiB.
func AvailableMemoryMB() (float64, error) {
	_, availableMB, err := readRAMCapacity()
	return availableMB, err
}

// ReadMetrics samples host RAM and CPU I/O wait without evaluating admission.
// Enterprise uses this exported API for its status endpoint; a status sample
// is not an admission grant.
func (c *Controller) ReadMetrics(ctx context.Context) (ramPercent, ioWaitPercent float64, err error) {
	ram, err := readRAMUsage()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read RAM usage: %w", err)
	}

	ioWait, err := readIOWait(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read IO wait: %w", err)
	}

	return ram, ioWait, nil
}

// PreflightMemory evaluates the available-memory gate and records the exact
// sample that decided it. It does not sample CPU load or grant admission.
func PreflightMemory(requiredMiB int, maxPercent float64) (Evaluation, error) {
	total, available, err := readRAMCapacity()
	evaluation := Evaluation{Checks: 1, Decision: DecisionMetricsUnavailable, RequiredAvailableMiB: float64(requiredMiB)}
	if err != nil {
		return evaluation, fmt.Errorf("read host memory for preflight: %w", err)
	}
	if total <= 0 || available < 0 || available > total {
		return evaluation, fmt.Errorf("host memory counters are not usable")
	}
	evaluation.HostTotalMiB, evaluation.HostAvailableMiB = total, available
	evaluation.HostRAMPercent = (total - available) / total * 100
	evaluation.ProjectedRAMPercent = (total - available + float64(requiredMiB)) / total * 100
	if err := reservationFits(total, requiredMiB, maxPercent); err != nil {
		evaluation.Decision = DecisionNeverAdmissible
		return evaluation, err
	}
	if available < float64(requiredMiB) {
		evaluation.Decision = DecisionPreflightDeniedMemory
		return evaluation, fmt.Errorf("available RAM %.0f MB is below required %d MB", available, requiredMiB)
	}
	// A successful preflight is not an admission grant. Its caller records only
	// failures, and the orchestrator later performs the full admission check.
	evaluation.Checks = 0
	return evaluation, nil
}

// Check evaluates current host resource utilization.
// Returns nil if admission is granted.
// Returns a wrapped ErrAdmissionDenied with details if thresholds are exceeded.
func (c *Controller) Check(ctx context.Context) error {
	return c.check(ctx, 0)
}

// CheckWithReservedMemory evaluates current host load together with the RAM
// that the plan's VMs will reserve together (every verified tier stays running
// until the end, so the last one boots while all earlier ones are resident).
// The reservation is deliberately conservative: it prevents a low-idle-utilization host from
// admitting a plan that would exceed its configured cap as soon as sandbox
// VMs begin to boot. Zero reserves nothing, as Check does; a negative
// reservation is refused with an error (fail closed), never treated as none.
func (c *Controller) CheckWithReservedMemory(ctx context.Context, reservedMemoryMB int) error {
	return c.check(ctx, reservedMemoryMB)
}

// validLimits refuses limits that plan validation never accepts, for callers
// that build a Config themselves: a NaN limit compares false with every
// measurement, so it would admit any load.
func (cfg Config) validLimits() error {
	for _, limit := range []struct {
		name  string
		value float64
	}{{"max_host_ram_percent", cfg.MaxHostRAMPercent}, {"max_host_iowait_percent", cfg.MaxHostIOWaitPercent}} {
		if !(limit.value > 0 && limit.value <= 100) {
			return fmt.Errorf("admission limit %s is %v; it must be a number above 0 and at most 100", limit.name, limit.value)
		}
	}
	if interval := cfg.DeferRetryIntervalSec; interval <= 0 || interval > config.MaxDurationSec {
		return fmt.Errorf("admission retry interval is %d seconds; it must be between 1 and %d", interval, config.MaxDurationSec)
	}
	if cfg.MaxDeferRetries < 0 || cfg.MaxDeferRetries > config.MaxDeferRetries {
		return fmt.Errorf("admission retries are %d; they must be between 0 and %d", cfg.MaxDeferRetries, config.MaxDeferRetries)
	}
	return nil
}

func (c *Controller) check(ctx context.Context, reservedMemoryMB int) error {
	if err := c.cfg.validLimits(); err != nil {
		return err
	}
	// Zero means no reservation; a negative one is a caller's error, and is
	// refused (not retried, not a denial) rather than run as no reservation.
	if reservedMemoryMB < 0 {
		return fmt.Errorf("recovery RAM reservation must not be negative (got %d MiB)", reservedMemoryMB)
	}
	var ev Evaluation
	defer func() { c.record(ev) }()
	return c.evaluate(ctx, reservedMemoryMB, &ev)
}

// evaluate is one check. It fills ev with what it measures and decides as it
// goes, so every way out, a grant or a refusal, leaves the evidence of how far
// the check got.
func (c *Controller) evaluate(ctx context.Context, reservedMemoryMB int, ev *Evaluation) error {
	if reservedMemoryMB > 0 {
		totalMB, availableMB, err := reservationCheck(reservedMemoryMB, c.cfg.MaxHostRAMPercent)
		if err != nil {
			ev.Decision = DecisionNeverAdmissible
			ev.HostTotalMiB, ev.HostAvailableMiB = totalMB, availableMB
			progress.Error("Admission", "%v", err)
			return err
		}
	}
	ramPercent, err := readRAMUsage()
	if err != nil {
		ev.Decision = DecisionMetricsUnavailable
		return fmt.Errorf("failed to read host metrics: failed to read RAM usage: %w", err)
	}
	ev.HostRAMPercent = ramPercent
	ioWaitPercent, err := readIOWait(ctx)
	if errors.Is(err, ErrIOWaitUnknown) {
		// Unknown load is not idle load: defer, as for a limit exceeded.
		ev.Decision = DecisionDeniedIOWaitUnmeasured
		err = fmt.Errorf("failed to read IO wait: %w", err)
		progress.Warn("Admission", "Host admission deferred: %v.", err)
		return fmt.Errorf("%w: %w", ErrAdmissionDenied, err)
	}
	if err != nil {
		ev.Decision = DecisionMetricsUnavailable
		return fmt.Errorf("failed to read host metrics: failed to read IO wait: %w", err)
	}
	ev.HostIOWaitPercent = ioWaitPercent
	// Without a reservation nothing is projected: the use now is what is held
	// to the limit.
	ev.ProjectedRAMPercent = ramPercent

	if ramPercent > c.cfg.MaxHostRAMPercent {
		ev.Decision = DecisionDeniedRAM
		progress.Warn("Admission", "Host admission deferred: RAM %.1f%% exceeds the %.1f%% limit.", ramPercent, c.cfg.MaxHostRAMPercent)
		return fmt.Errorf("%w: RAM usage %.2f%% exceeds max %.2f%%", ErrAdmissionDenied, ramPercent, c.cfg.MaxHostRAMPercent)
	}

	if ioWaitPercent > c.cfg.MaxHostIOWaitPercent {
		ev.Decision = DecisionDeniedIOWait
		progress.Warn("Admission", "Host admission deferred: IO wait %.1f%% exceeds the %.1f%% limit.", ioWaitPercent, c.cfg.MaxHostIOWaitPercent)
		return fmt.Errorf("%w: IO wait %.2f%% exceeds max %.2f%%", ErrAdmissionDenied, ioWaitPercent, c.cfg.MaxHostIOWaitPercent)
	}
	if reservedMemoryMB > 0 {
		totalMB, availableMB, err := readRAMCapacity()
		if err != nil {
			ev.Decision = DecisionMetricsUnavailable
			return fmt.Errorf("read host RAM capacity for recovery reservation: %w", err)
		}
		projectedPercent, err := projectedRAMPercent(totalMB, availableMB, reservedMemoryMB)
		if err != nil {
			ev.Decision = DecisionMetricsUnavailable
			return fmt.Errorf("calculate projected recovery RAM: %w", err)
		}
		ev.HostTotalMiB, ev.HostAvailableMiB, ev.ProjectedRAMPercent = totalMB, availableMB, projectedPercent
		if projectedPercent > c.cfg.MaxHostRAMPercent {
			ev.Decision = DecisionDeniedProjectedRAM
			progress.Warn("Admission", "Host admission deferred: current available RAM %.0f MiB plus recovery reservation %d MiB would reach %.1f%% (max %.1f%%).", availableMB, reservedMemoryMB, projectedPercent, c.cfg.MaxHostRAMPercent)
			return fmt.Errorf("%w: recovery reservation %d MiB plus current host usage would reach %.2f%% of %.0f MiB, exceeding max %.2f%%", ErrAdmissionDenied, reservedMemoryMB, projectedPercent, totalMB, c.cfg.MaxHostRAMPercent)
		}
		ev.Decision = DecisionGranted
		progress.Info("Admission", "Recovery RAM reservation %d MiB projects host RAM to %.1f%% (max %.1f%%) → ADMISSION GRANTED", reservedMemoryMB, projectedPercent, c.cfg.MaxHostRAMPercent)
		return nil
	}
	ev.Decision = DecisionGranted
	progress.Info("Admission", "Host admission check: RAM %.1f%% (max %.1f%%), IO wait %.1f%% (max %.1f%%) → ADMISSION GRANTED", ramPercent, c.cfg.MaxHostRAMPercent, ioWaitPercent, c.cfg.MaxHostIOWaitPercent)

	return nil
}

func projectedRAMPercent(totalMB, availableMB float64, reservedMemoryMB int) (float64, error) {
	if totalMB <= 0 {
		return 0, errors.New("host total RAM must be positive")
	}
	if availableMB < 0 || availableMB > totalMB {
		return 0, errors.New("host available RAM is outside the total RAM range")
	}
	if reservedMemoryMB < 0 {
		return 0, errors.New("recovery RAM reservation must not be negative")
	}
	return ((totalMB - availableMB + float64(reservedMemoryMB)) / totalMB) * 100, nil
}

// WaitForAdmission retries Check() up to MaxDeferRetries times,
// sleeping DeferRetryIntervalSec between attempts.
// Returns nil on first successful check.
// Returns ErrMaxRetriesExceeded if all retries are exhausted.
// Respects context cancellation.
func (c *Controller) WaitForAdmission(ctx context.Context) error {
	return c.waitForAdmission(ctx, 0)
}

// WaitForAdmissionWithReservedMemory retries admission while considering the
// RAM reservation of all the plan's VMs together. A negative reservation is
// refused at once, as CheckWithReservedMemory refuses it.
func (c *Controller) WaitForAdmissionWithReservedMemory(ctx context.Context, reservedMemoryMB int) error {
	return c.waitForAdmission(ctx, reservedMemoryMB)
}

func (c *Controller) waitForAdmission(ctx context.Context, reservedMemoryMB int) error {
	var denied error
	for i := 0; i <= c.cfg.MaxDeferRetries; i++ {
		err := c.check(ctx, reservedMemoryMB)
		if err == nil {
			return nil
		}

		if errors.Is(err, ErrAdmissionDenied) {
			slog.Warn("admission check failed, retrying", "attempt", i+1, "max_retries", c.cfg.MaxDeferRetries, "error", err)
			denied = err
		} else {
			return err
		}

		if i == c.cfg.MaxDeferRetries {
			break
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(c.cfg.DeferRetryIntervalSec) * time.Second):
		}
	}

	// The last refusal says why, an unmeasurable I/O wait included.
	return fmt.Errorf("%w (last: %v)", ErrMaxRetriesExceeded, denied)
}

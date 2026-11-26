// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package pbs manages block-level image mapping from Proxmox Backup Server (PBS).
package pbs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

// Config holds connection and credential configuration for PBS.
type Config struct {
	Repository  string // e.g., "root@pam@pbs.local:datastore1" or "user@pbs!token@host:8007:datastore"
	Password    string // API token secret or password (passed via PBS_PASSWORD)
	Fingerprint string // TLS certificate SHA256 fingerprint for self-signed certificates
	Keyfile     string // Optional encryption key file path (--keyfile)
	// Namespace is the optional PBS namespace. It is handed to the client both
	// as --ns on every command that takes one and as PBS_NAMESPACE: the 3.x
	// client (every PVE 8 node's) ignores the variable, and without --ns it
	// reads the root namespace.
	Namespace string
	// EncryptionPassword unlocks a password-protected Keyfile (passed via
	// PBS_ENCRYPTION_PASSWORD).
	EncryptionPassword string
}

// Client wraps proxmox-backup-client commands to map and unmap remote backups.
type Client struct {
	cfg Config

	mu sync.Mutex
	// cryptModes caches each snapshot's crypt mode, which decides whether
	// the key is passed to its restores and maps.
	cryptModes map[string]string
	// groupFingerprints caches each backup group's snapshot key
	// fingerprints, for the wrong-key check.
	groupFingerprints map[string]map[string]string
	// clientLogReader replaces the PBS API read of a snapshot's backup log
	// in tests.
	clientLogReader func(ctx context.Context, snapshot string) ([]byte, error)
	// blobKeyLoaded, blobKeyValue and blobKeyErr cache the raw key read from
	// the key file for decrypting an encrypted snapshot's backup log.
	blobKeyLoaded bool
	blobKeyValue  *[32]byte
	blobKeyErr    error
}

// New creates a new PBS block mapping client.
func New(cfg Config) *Client {
	return &Client{cfg: cfg, cryptModes: make(map[string]string)}
}

// ResolveSnapshot converts a latest selector into the newest immutable PBS
// snapshot path. Pinned snapshot paths are returned unchanged so an operator
// can intentionally replay a historical recovery test.
//
// A latest selector is either the literal "latest" with a source VM ID, or a
// group selector such as "vm/100/latest".
func (c *Client) ResolveSnapshot(ctx context.Context, selector string, sourceVMID int) (string, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return "", fmt.Errorf("snapshot selector must not be empty")
	}

	group := ""
	switch {
	case selector == "latest":
		if sourceVMID <= 0 {
			return "", fmt.Errorf("source VM ID is required when snapshot is latest")
		}
		group = fmt.Sprintf("vm/%d", sourceVMID)
	case strings.HasSuffix(selector, "/latest"):
		group = strings.TrimSuffix(selector, "/latest")
	default:
		if !validSnapshotPath(selector) {
			return "", fmt.Errorf("invalid PBS snapshot path %q", selector)
		}
		return selector, nil
	}

	return c.LatestSnapshot(ctx, group)
}

// LatestSnapshot resolves the latest completed snapshot in one PBS backup
// group. PBS does not promise ordering of list output, so the newest
// backup-time is selected explicitly from JSON output.
func (c *Client) LatestSnapshot(ctx context.Context, group string) (string, error) {
	if !validBackupGroup(group) {
		return "", fmt.Errorf("invalid PBS backup group %q", group)
	}

	args := append([]string{"snapshot", "list", group, "--output-format", "json"}, c.targetArgs()...)

	// The operation's own limit holds under any caller deadline: the earlier
	// of the two wins, so a daemon run budget of hours does not turn a hung
	// client into a hang of hours.
	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := c.command(listCtx, args)
	output, err := process.CombinedOutputLimited(cmd, pbsListOutputLimit)
	if err != nil {
		return "", listFailure("list PBS snapshots for "+group, err, output)
	}

	snapshot, skipped, err := latestCompleteSnapshot(output, group)
	if err != nil {
		return "", err
	}
	for _, incomplete := range skipped {
		slog.Warn("skipping incomplete PBS snapshot newer than the resolved latest (aborted backup: no manifest)",
			"group", group, "incomplete", incomplete, "resolved", snapshot)
	}
	slog.Info("resolved latest PBS snapshot", "group", group, "snapshot", snapshot)
	return snapshot, nil
}

// manifestName is the snapshot manifest a backup writes when it completes.
// PBS keeps an aborted backup's partial files, but never its manifest, and
// such a snapshot cannot be restored.
const manifestName = "index.json.blob"

type snapshotFile struct {
	Filename string `json:"filename"`
	// Size is the file's size as the snapshot list reports it: for a disk
	// image archive (.img.fidx) the image's length.
	Size int64 `json:"size"`
}

type snapshotListEntry struct {
	BackupType string          `json:"backup-type"`
	BackupID   string          `json:"backup-id"`
	BackupTime json.RawMessage `json:"backup-time"`
	// Files is nil when the client does not report it; that snapshot is
	// treated as complete.
	Files *[]snapshotFile `json:"files"`
}

func (e snapshotListEntry) complete() bool {
	if e.Files == nil {
		return true
	}
	for _, file := range *e.Files {
		if file.Filename == manifestName {
			return true
		}
	}
	return false
}

// ParseLatestSnapshotJSON extracts the latest completed snapshot from the
// structured output of `proxmox-backup-client snapshot list <group>
// --output-format json`.
func ParseLatestSnapshotJSON(data []byte, group string) (string, error) {
	snapshot, _, err := latestCompleteSnapshot(data, group)
	return snapshot, err
}

// latestCompleteSnapshot also returns the incomplete snapshots that are newer
// than the one it resolved, so the caller can say what it skipped.
func latestCompleteSnapshot(data []byte, group string) (string, []string, error) {
	parts := strings.Split(group, "/")
	if !validBackupGroup(group) {
		return "", nil, fmt.Errorf("invalid PBS backup group %q", group)
	}

	var entries []snapshotListEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return "", nil, fmt.Errorf("parse PBS snapshot list JSON: %w", err)
	}

	var latest time.Time
	var incomplete []time.Time
	found := false
	for _, entry := range entries {
		if entry.BackupType != parts[0] || entry.BackupID != parts[1] {
			continue
		}
		backupTime, err := parseBackupTime(entry.BackupTime)
		if err != nil {
			return "", nil, fmt.Errorf("parse backup time for %s/%s: %w", entry.BackupType, entry.BackupID, err)
		}
		if !entry.complete() {
			incomplete = append(incomplete, backupTime)
			continue
		}
		if !found || backupTime.After(latest) {
			latest = backupTime
			found = true
		}
	}
	if !found {
		if len(incomplete) > 0 {
			return "", nil, fmt.Errorf("no complete snapshot in PBS backup group %s: %d incomplete (aborted) snapshot(s) have no manifest", group, len(incomplete))
		}
		return "", nil, fmt.Errorf("no snapshots found for PBS backup group %s", group)
	}

	var skipped []string
	for _, t := range incomplete {
		if t.After(latest) {
			skipped = append(skipped, fmt.Sprintf("%s/%s", group, t.UTC().Format(time.RFC3339)))
		}
	}
	return fmt.Sprintf("%s/%s", group, latest.UTC().Format(time.RFC3339)), skipped, nil
}

func parseBackupTime(raw json.RawMessage) (time.Time, error) {
	value := strings.TrimSpace(string(raw))
	if value == "" || value == "null" {
		return time.Time{}, fmt.Errorf("backup-time is missing")
	}
	if unixSeconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(unixSeconds, 0).UTC(), nil
	}
	if unquoted, err := strconv.Unquote(value); err == nil {
		if unixSeconds, err := strconv.ParseInt(unquoted, 10, 64); err == nil {
			return time.Unix(unixSeconds, 0).UTC(), nil
		}
		if parsed, err := time.Parse(time.RFC3339, unquoted); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid backup-time %s", value)
}

func validBackupGroup(group string) bool {
	parts := strings.Split(group, "/")
	if len(parts) != 2 || parts[0] != "vm" {
		return false
	}
	_, ok := canonicalVMID(parts[1])
	return ok
}

// canonicalVMID reads a VM ID written as a canonical positive decimal: Atoi
// also reads "+7001" and "07001" as 7001, which the report-side rules refuse
// (attest.snapshotGroup), so the client refuses them as well.
func canonicalVMID(text string) (int, bool) {
	id, err := strconv.Atoi(text)
	if err != nil || id <= 0 || strconv.Itoa(id) != text {
		return 0, false
	}
	return id, true
}

// SnapshotVMID returns the ID of the VM whose backup an immutable snapshot
// path ("vm/100/2026-03-30T02:00:00Z") is.
func SnapshotVMID(snapshot string) (int, bool) {
	if !validSnapshotPath(snapshot) {
		return 0, false
	}
	return canonicalVMID(strings.Split(snapshot, "/")[1])
}

func validSnapshotPath(snapshot string) bool {
	parts := strings.Split(snapshot, "/")
	if len(parts) != 3 || !validBackupGroup(strings.Join(parts[:2], "/")) {
		return false
	}
	_, err := time.Parse(time.RFC3339, parts[2])
	return err == nil
}

func normalizeDriveArchive(drive string) (string, error) {
	drive = strings.TrimSuffix(drive, ".fidx")
	if !strings.HasSuffix(drive, ".img") {
		drive += ".img"
	}
	base := strings.TrimSuffix(drive, ".img")
	// A base that still ends in an index or image suffix ("x.img.fidx.fidx")
	// names no archive; refuse it rather than pass PBS a mangled name.
	if base == "" || base[0] == '-' || strings.HasSuffix(base, ".img") || strings.HasSuffix(base, ".fidx") || strings.HasSuffix(base, ".didx") {
		return "", fmt.Errorf("invalid PBS drive archive %q", drive)
	}
	for _, r := range base {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return "", fmt.Errorf("invalid PBS drive archive %q", drive)
		}
	}
	return drive, nil
}

// Map maps a remote backup snapshot drive archive to a local loopback device.
// The snapshot path should be of the format: "vm/100/2026-03-30T02:00:00Z"
// The drive archive should be of the format: "drive-scsi0" or "drive-scsi0.img"
// Returns the allocated loop device path (e.g., "/dev/loop0").
func (c *Client) Map(ctx context.Context, snapshot, drive string) (string, error) {
	return c.MapWithToken(ctx, snapshot, drive, "")
}

// MapWithToken is Map for a map whose intent the run journaled with token
// (NewMapToken). The client's process, and the daemon it forks, carry the
// token in their environment (MapTokenEnv), so that recovery can tell them
// from another operation's map of the same snapshot and archive.
// An empty token adds nothing.
func (c *Client) MapWithToken(ctx context.Context, snapshot, drive, token string) (string, error) {
	if token != "" && !validMapToken(token) {
		return "", fmt.Errorf("invalid PBS map token")
	}
	if !validSnapshotPath(snapshot) {
		return "", fmt.Errorf("invalid PBS snapshot path %q", snapshot)
	}
	driveArchive, err := normalizeDriveArchive(drive)
	if err != nil {
		return "", err
	}

	keyArgs, err := c.keyArgs(ctx, snapshot)
	if err != nil {
		return "", err
	}
	args := c.mapArgs(snapshot, driveArchive, keyArgs)

	// Do not log the repository: its user component can disclose an API-token
	// identity, and logs are routinely copied into controller evidence bundles.
	slog.Info("mapping PBS backup image", "snapshot", snapshot, "drive", driveArchive)

	mapCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cmd := c.command(mapCtx, args)
	if token != "" {
		cmd.Env = append(cmd.Env, MapTokenEnv+"="+token)
	}

	output, err := process.CombinedOutputLimited(cmd, pbsCommandOutputLimit)
	outStr := string(output)
	if err != nil {
		return "", commandFailure("map PBS backup image", err, output)
	}

	loopDev, err := sysutil.ExtractLoopDevice(outStr)
	if err != nil {
		return "", fmt.Errorf("parse mapped PBS loop device: %w (client output withheld)", err)
	}

	slog.Info("PBS snapshot successfully mapped", "device", loopDev, "snapshot", snapshot)
	return loopDev, nil
}

// stillRecorded says, right before something is done to loopDevice, whether
// it still backs the file recorded for the map (sysutil.LoopBacking, journaled
// when the map was made). A loop number can be reused by another operation's
// map or an ordinary loop once the run's map is gone: it is then not the
// run's, and nothing is signaled or detached. A device that is gone
// is released already (false, nil); one whose identity cannot be established
// is an error.
func stillRecorded(loopDevice, backing string) (bool, error) {
	if !strings.HasPrefix(loopDevice, "/dev/loop") {
		return false, fmt.Errorf("cannot tell which map %s belongs to: only a loop device has a backing identity", loopDevice)
	}
	state, err := sysutil.CheckLoop(loopDevice, backing)
	switch {
	case err != nil:
		return false, fmt.Errorf("cannot establish that %s is still the run's PBS map, so it is left alone: %w", loopDevice, err)
	case state == sysutil.LoopReused:
		return false, fmt.Errorf("%s: %w", loopDevice, sysutil.ErrLoopReused)
	}
	return state == sysutil.LoopRecorded, nil
}

// Unmap releases the local loopback device previously mapped by Map, whose
// backing file was recorded as backing when the map was made. It does nothing
// to a device that is gone, and returns sysutil.ErrLoopReused, having done
// nothing, for one that backs another file now: the identity is checked before
// the map's daemon is stopped, and again before the detach, so that a failure
// of the first never widens what the second may touch.
//
// It does not run proxmox-backup-client unmap: the client rereads the map's
// pid file and signals that bare PID, which can by then be another process.
// The caller says with stopDaemon how the map's daemon is to be
// stopped, which it does only once it has shown the process the pid file names
// to be the map's own daemon (recovery.StopMapDaemon verifies it again and
// signals it through a pidfd); nil is for a map with no daemon of the run's to
// stop, and only the verified detach runs (Detach). A stopDaemon that fails
// leaves the loop attached: its error is the answer. The daemon releases its
// loop as it exits, so a loop that is gone afterwards is released.
func (c *Client) Unmap(ctx context.Context, loopDevice, backing string, stopDaemon func() error) error {
	if !sysutil.ValidMappedDevice(loopDevice) {
		return fmt.Errorf("invalid mapped device %q", loopDevice)
	}
	if stopDaemon != nil {
		if recorded, err := stillRecorded(loopDevice, backing); err != nil || !recorded {
			return err
		}
		slog.Info("stopping the PBS map's daemon", "device", loopDevice)
		if err := stopDaemon(); err != nil {
			return err
		}
	}
	return c.Detach(ctx, loopDevice, backing)
}

// Detach detaches loopDevice with losetup -d, only while it still backs the
// file recorded for the map. A device that is gone counts as detached; one
// that backs another file now is not touched (sysutil.ErrLoopReused).
func (c *Client) Detach(ctx context.Context, loopDevice, backing string) error {
	recorded, err := stillRecorded(loopDevice, backing)
	if err != nil || !recorded {
		return err
	}
	if err := sysutil.DetachLoop(ctx, loopDevice); err != nil {
		return err
	}
	slog.Info("PBS loop device unmapped", "device", loopDevice)
	return nil
}

// RestoreImage restores one backed-up image archive, such as a UEFI variable
// store or TPM state, to target as a raw file. It is meant for the small
// firmware images a sandbox VM must be able to write: a mapped image is
// read-only, and PVE keeps TPM state only in raw volumes. target must not
// exist. The client checks every chunk against its digest while restoring,
// so a read error is an integrity failure.
func (c *Client) RestoreImage(ctx context.Context, snapshot, archive, target string) error {
	if !validSnapshotPath(snapshot) {
		return fmt.Errorf("invalid PBS snapshot path %q", snapshot)
	}
	imageArchive, err := normalizeDriveArchive(archive)
	if err != nil {
		return err
	}
	if !path.IsAbs(target) { // node paths are Linux paths
		return fmt.Errorf("restore target %q is not an absolute path", target)
	}
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("restore target %s already exists", target)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect restore target %s: %w", target, err)
	}

	keyArgs, err := c.restoreKeyArgs(ctx, snapshot)
	if err != nil {
		return err
	}
	args := append([]string{"restore"}, c.targetArgs()...)
	args = append(args, keyArgs...)
	args = append(args, snapshot, imageArchive, target)
	slog.Info("restoring PBS firmware image", "snapshot", snapshot, "archive", imageArchive)
	if output, err := c.run(ctx, 2*time.Minute, args...); err != nil {
		return commandFailure("restore PBS image "+imageArchive, err, []byte(output))
	}
	return nil
}

// VerifySummary records the cryptographic verification outcome of a PBS backup snapshot.
type VerifySummary struct {
	Snapshot           string    `json:"snapshot"`
	VerifiedAt         time.Time `json:"verified_at"`
	ChunksVerified     int       `json:"chunks_verified"`
	ChecksumMismatches int       `json:"checksum_mismatches"`
	ChunkModifications int       `json:"chunk_modifications"`
	Passed             bool      `json:"passed"`
	Detail             string    `json:"detail"`
	BytesRead          int64     `json:"bytes_read,omitempty"`
}

// VerifyMappedImage reads every byte through an already-mapped PBS image and
// calculates a SHA-256 digest. The PBS map reader validates the manifest and
// fetched chunks while servicing reads, so a read error is a hard verification
// failure. This deliberately does not mistake `snapshot files` output for an
// integrity check; server-side PBS verification remains a separate operation.
//
// want is what is known of the disk's length (see DiskSize). The image passes
// only when its size is the size the snapshot's manifest records, the scan reads
// exactly that many bytes with no clean end earlier, and the size is the same
// after the scan as before it: a map that is short, or long, or changes under
// the scan is a failure with the numbers, never "verified". A
// configuration size that differs from the manifest's is noted in the evidence,
// not a failure.
func VerifyMappedImage(ctx context.Context, snapshot, loopDevice string, want DiskSize) (*VerifySummary, string, error) {
	return verifyMappedImage(ctx, snapshot, loopDevice, want, nil)
}

// VerifyMappedImageWithProgress has the same verification semantics as
// VerifyMappedImage and invokes progress after each additional GiB read. The
// callback receives only a byte count; it must not use or expose credentials,
// repository strings, or image content.
func VerifyMappedImageWithProgress(ctx context.Context, snapshot, loopDevice string, want DiskSize, progress func(bytesVerified int64)) (*VerifySummary, string, error) {
	return verifyMappedImage(ctx, snapshot, loopDevice, want, progress)
}

const verificationProgressInterval = int64(1 << 30)

func verifyMappedImage(ctx context.Context, snapshot, loopDevice string, want DiskSize, progress func(bytesVerified int64)) (*VerifySummary, string, error) {
	if !validSnapshotPath(snapshot) || !sysutil.ValidMappedDevice(loopDevice) {
		return nil, "", fmt.Errorf("invalid PBS snapshot path or mapped device")
	}

	f, err := os.Open(loopDevice)
	if err != nil {
		return nil, "", fmt.Errorf("open mapped PBS image %s: %w", loopDevice, err)
	}
	defer f.Close()
	return verifyOpenImage(ctx, snapshot, f, want, progress)
}

// mappedImageSize is the size of an open mapped image (a block device or a
// file), from where its end is.
func mappedImageSize(f *os.File) (int64, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("size mapped PBS image: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("rewind mapped PBS image: %w", err)
	}
	return size, nil
}

func verifyOpenImage(ctx context.Context, snapshot string, f *os.File, want DiskSize, progress func(bytesVerified int64)) (*VerifySummary, string, error) {
	size, err := mappedImageSize(f)
	if err != nil {
		return nil, "", err
	}
	note, err := checkMappedSize(size, want)
	if err != nil {
		return nil, "", err
	}
	digest, total, err := hashMappedImage(ctx, f, progress)
	if err != nil {
		return nil, "", err
	}
	if total != size {
		return nil, "", fmt.Errorf("read %d of the %d bytes of the mapped PBS image before a clean end of file: the image is not complete", total, size)
	}
	if after, err := mappedImageSize(f); err != nil {
		return nil, "", err
	} else if after != size {
		return nil, "", fmt.Errorf("the mapped PBS image changed size during the scan: %d bytes before, %d after", size, after)
	}
	summary := &VerifySummary{
		Snapshot:   snapshot,
		VerifiedAt: time.Now().UTC(),
		Passed:     true,
		Detail:     fmt.Sprintf("full mapped image read (%d bytes; %s); SHA-256 %s", total, note, digest),
		BytesRead:  total,
	}
	return summary, digest, nil
}

// dropScannedPages releases a range the scan has read from the mapped
// device's own page cache. The device is a loop device over the map's FUSE
// file, so a buffered read caches each block twice: once for the device and
// once for the FUSE file. Only the FUSE file's copy outlives the scan (the
// kernel drops a block device's cache when its last opener closes it), and
// it is the copy the sandbox's boot reads. The device's copy would only
// compete with it for memory while the scan runs.
var dropScannedPages = dropDevicePages

// hashMappedImage reads f to its end and returns the SHA-256 of its content
// and the number of bytes read.
func hashMappedImage(ctx context.Context, f *os.File, progress func(bytesVerified int64)) (string, int64, error) {
	return readMappedImage(ctx, f, progress, nil)
}

// scanBuffers is how many 4 MiB buffers the scan's two halves share: one being
// read, one being hashed, one in between. One makes the scan strictly serial;
// tests that act between a chunk's processing and the next read use that.
var scanBuffers = 3

// readMappedImage is hashMappedImage that also hands each chunk and its
// offset to onChunk, when set, before the chunk's pages are released. It
// stops when ctx ends, a read in progress included, and never reports a
// read that ended after that as complete.
func readMappedImage(ctx context.Context, f *os.File, progress func(bytesVerified int64), onChunk func(p []byte, off int64) error) (string, int64, error) {
	h := sha256.New()
	var total int64
	nextProgress := verificationProgressInterval
	reader := startImageReader(f)
	defer reader.stop()
	ahead := startImageReadahead(f)
	defer ahead.stop()

	// The scan has two halves that overlap: reading a chunk (a wait on PBS
	// through the loop device and FUSE) and hashing it (CPU: SHA-256 runs at
	// about 100 MB/s on a CPU without AVX2). A second goroutine hashes, hands
	// each chunk to onChunk, releases its pages and reports progress, one chunk
	// after another in order, while this one reads the next chunk. Every byte
	// is still read once and hashed once, in order.
	buffers := scanBuffers
	if buffers < 1 {
		buffers = 1
	}
	free := make(chan []byte, buffers)
	for i := 0; i < buffers; i++ {
		free <- make([]byte, 4<<20)
	}
	work := make(chan scanChunk, buffers)
	procDone := make(chan struct{})
	var (
		procMu  sync.Mutex
		procErr error
	)
	failure := func() error {
		procMu.Lock()
		defer procMu.Unlock()
		return procErr
	}
	go func() {
		defer close(procDone)
		for c := range work {
			if failure() == nil {
				if err := func() error {
					if _, err := h.Write(c.buf[:c.n]); err != nil {
						return fmt.Errorf("hash mapped PBS image: %w", err)
					}
					if onChunk != nil {
						if err := onChunk(c.buf[:c.n], total); err != nil {
							return err
						}
					}
					dropScannedPages(f, total, int64(c.n))
					total += int64(c.n)
					ahead.consumed(total)
					reportVerificationProgress(total, &nextProgress, progress)
					return nil
				}(); err != nil {
					procMu.Lock()
					procErr = err
					procMu.Unlock()
				}
			}
			free <- c.buf
		}
	}()
	// finish ends the second goroutine once it has handled what was handed to
	// it, so that nothing of the scan runs after this function returns.
	finish := func() error {
		close(work)
		<-procDone
		return failure()
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = finish()
			return "", 0, fmt.Errorf("read mapped PBS image: %w", err)
		}
		var buf []byte
		select {
		case buf = <-free:
		case <-ctx.Done():
			_ = finish()
			return "", 0, fmt.Errorf("read mapped PBS image: %w", ctx.Err())
		}
		if err := failure(); err != nil {
			_ = finish()
			return "", 0, err
		}
		chunk, err := reader.read(ctx, buf)
		if err != nil {
			_ = finish()
			return "", 0, err
		}
		n, readErr := chunk.n, chunk.err
		if n > 0 {
			work <- scanChunk{buf: buf, n: n}
		} else {
			free <- buf
		}
		if readErr == io.EOF {
			// An end reached after cancellation is not a completed scan.
			if err := ctx.Err(); err != nil {
				_ = finish()
				return "", 0, fmt.Errorf("read mapped PBS image: %w", err)
			}
			break
		}
		if readErr != nil {
			_ = finish()
			return "", 0, fmt.Errorf("read mapped PBS image %s: %w", f.Name(), readErr)
		}
	}
	if err := finish(); err != nil {
		return "", 0, err
	}
	if ahead != nil {
		// A read-ahead worker held up between its check and its read can still
		// read a chunk the scan has just released. Once the workers are done,
		// the whole image is released once more, so the scan leaves none of
		// it cached.
		ahead.stop()
		dropDevicePages(f, 0, total)
	}
	return hex.EncodeToString(h.Sum(nil)), total, nil
}

// scanChunk is one chunk read and waiting to be hashed.
type scanChunk struct {
	buf []byte
	n   int
}

// startImageReadahead starts the read-ahead for a scan of f, which must be
// positioned at its start; it returns nil (no read-ahead) when f cannot be
// sized, is not at its start, or the read-ahead is turned off.
func startImageReadahead(f *os.File) *imageReadahead {
	workers := readaheadWorkers()
	if workers < 2 {
		return nil
	}
	if at, err := f.Seek(0, io.SeekCurrent); err != nil || at != 0 {
		return nil
	}
	size, err := mappedImageSize(f) // leaves f at its start
	if err != nil || size <= 0 {
		return nil
	}
	return startReadahead(f, size, readaheadChunk, workers, readaheadWindow)
}

// readCancelGrace is how long a canceled scan waits for its read in
// progress. A read of a mapped image waits on PBS through the loop device and
// FUSE, and nothing in this process can interrupt it; most finish within
// this. One that does not is left to finish on its own: releasing the map,
// as teardown does, fails it.
var readCancelGrace = 5 * time.Second

// imageReader reads a mapped image on a goroutine of its own, one chunk at a
// time on request, so the scan can stop when its context ends while a read
// is still waiting. The goroutine also holds the thread the NUMA spread
// moves: the CPU a read is queued from decides where its page cache lands.
type imageReader struct {
	f       *os.File
	next    chan []byte
	results chan imageRead
}

type imageRead struct {
	n   int
	err error
}

// startImageReader starts the goroutine that reads f. Each read is into the
// buffer the caller hands it; that buffer belongs to the reader while the read
// is in progress, and to the caller after the result.
func startImageReader(f *os.File) *imageReader {
	r := &imageReader{f: f, next: make(chan []byte), results: make(chan imageRead, 1)}
	go func() {
		spread := startScanSpread(f.Name())
		defer spread.stop()
		var total int64
		for buf := range r.next {
			n, err := f.Read(buf)
			// results holds one: this never waits, even for a caller gone.
			r.results <- imageRead{n: n, err: err}
			total += int64(n)
			spread.at(total)
		}
	}()
	return r
}

// read reads the next chunk into buf. When ctx ends first, it waits up to
// readCancelGrace for the read, then returns ctx's error; that read's data
// is never used.
func (r *imageReader) read(ctx context.Context, buf []byte) (imageRead, error) {
	select {
	case r.next <- buf:
	case <-ctx.Done():
		return imageRead{}, fmt.Errorf("read mapped PBS image: %w", ctx.Err())
	}
	select {
	case chunk := <-r.results:
		return chunk, nil
	case <-ctx.Done():
	}
	canceled := fmt.Errorf("read mapped PBS image: %w", ctx.Err())
	select {
	case <-r.results:
		return imageRead{}, canceled
	case <-time.After(readCancelGrace):
		slog.Warn("a canceled scan's read of a mapped PBS image is still waiting; it ends when the map is released", "device", r.f.Name(), "waited", readCancelGrace)
		return imageRead{}, fmt.Errorf("%w (a read of %s was still waiting %v later; it ends when the PBS map is released)", canceled, r.f.Name(), readCancelGrace)
	}
}

// stop ends the reader once any read in progress returns.
func (r *imageReader) stop() { close(r.next) }

func reportVerificationProgress(total int64, next *int64, progress func(int64)) {
	if progress == nil || next == nil || total < *next {
		return
	}
	progress(total)
	for *next <= total {
		*next += verificationProgressInterval
	}
}

// The most a proxmox-backup-client command's output may be before it is
// stopped: 4 MiB for everything that prints a line or a small report (map,
// unmap, restore, key and manifest commands), 16 MiB for the JSON listings of
// snapshots and of a snapshot's files, which grow with the repository. Output
// beyond the limit is neither kept nor parsed.
const (
	pbsCommandOutputLimit = 4 << 20
	pbsListOutputLimit    = 16 << 20
)

// commandFailure deliberately withholds client output. PBS tools can echo a
// repository URL or authentication context on failures, and such errors flow
// into controller logs, reports, and support bundles.
func commandFailure(operation string, err error, output []byte) error {
	// A client that wrote more than its limit was stopped, and only the first
	// bytes were kept: its output is withheld like any other.
	if errors.Is(err, process.ErrOutputLimit) {
		return fmt.Errorf("%s: the PBS client wrote more output than CertiStack accepts and was stopped (client output withheld; the first %d bytes were kept): %w", operation, len(output), err)
	}
	for _, known := range knownClientFailures {
		if strings.Contains(string(output), known.marker) {
			return fmt.Errorf("%s: %s", operation, known.reason)
		}
	}
	// A failure with a known cause is reported as that cause, in fixed words
	// that hold nothing of the output (clientfailure.go).
	if reason, ok := classifyClientFailure(output); ok {
		return &namedFailure{message: operation + ": " + reason, cause: err}
	}
	if len(output) == 0 {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s: %w (client output withheld; %d bytes)", operation, err, len(output))
}

// knownClientFailures are proxmox-backup-client refusals whose cause the
// operator must see. The client's output stays withheld; each is reported in
// CertiStack's own words.
var knownClientFailures = []struct{ marker, reason string }{
	{"wrong password?", "PBS_ENCRYPTION_PASSWORD does not unlock CERTISTACK_PBS_KEYFILE (wrong passphrase)"},
	{"Passphrase is too short", "PBS_ENCRYPTION_PASSWORD is too short to be the key's passphrase"},
	{"no password input mechanism available", "CERTISTACK_PBS_KEYFILE is protected by a passphrase: set PBS_ENCRYPTION_PASSWORD"},
	// A snapshot whose file list claims a signature but whose manifest has
	// none, or whose signature the key does not verify, is what a tampered
	// backup looks like: PBS refuses it and so does CertiStack.
	{"manifest has no signature", "the snapshot's manifest carries no signature although its file list claims one, and PBS refused to trust it"},
	{"wrong signature in manifest", "the snapshot's manifest signature does not verify with CERTISTACK_PBS_KEYFILE (a wrong key or a tampered manifest)"},
	{"wrong key - ", "CERTISTACK_PBS_KEYFILE is not the key this snapshot's manifest was made with"},
	{"missing key - manifest was created with key", "the snapshot's manifest was made with a key although its file list says it is not protected, and PBS refused it (a tampered file list, or a backup in a mixed state)"},
}

// targetArgs are the options that name what a client command reads: the
// repository and the namespace. The namespace goes as --ns, which every
// command that lists, restores or maps takes, because the 3.x client (the one
// on every PVE 8 node) ignores PBS_NAMESPACE and silently reads the root
// namespace; 4.x honors the variable, and buildEnv still sets it. Only
// `unmap`, `version` and `group list` take no --ns: none is given them, and
// none of them reads backup data of a namespace.
func (c *Client) targetArgs() []string {
	var args []string
	if c.cfg.Repository != "" {
		args = append(args, "--repository", c.cfg.Repository)
	}
	return append(args, c.namespaceArgs()...)
}

// namespaceArgs is --ns for the configured namespace, or nothing when there is
// none. A namespace that begins with "-" is joined to the option, so that it
// cannot be read as an option of its own.
func (c *Client) namespaceArgs() []string {
	switch ns := c.cfg.Namespace; {
	case ns == "":
		return nil
	case strings.HasPrefix(ns, "-"):
		return []string{"--ns=" + ns}
	default:
		return []string{"--ns", ns}
	}
}

// command prepares one proxmox-backup-client invocation with this client's
// scoped environment. It is killed if the worker dies, so an interrupted run
// cannot leave a restore writing a file (possibly TPM state) or a map
// creating a loop device after crash recovery has already reconciled the
// journal. Run it with process.CombinedOutput.
func (c *Client) command(ctx context.Context, args []string) *exec.Cmd {
	cmd := process.CommandContext(ctx, "proxmox-backup-client", args, false)
	cmd.Env = c.buildEnv()
	return cmd
}

// noClientConfig is where every PBS client invocation is told its
// configuration lives: a path with nothing under it, and nothing that can be
// created there. proxmox-backup-client looks for a default encryption key
// (and master public key) in its per-user configuration directories, found
// from HOME, XDG_CONFIG_HOME and XDG_CONFIG_DIRS, and uses one it finds in
// place of no key. A run must not depend on what the service account's home
// holds, so the client is pointed at no configuration at all.
const noClientConfig = "/dev/null"

// clientEnvironment is the minimal process environment with the PBS client's
// configuration lookup pointed at nothing.
func clientEnvironment() []string {
	var env []string
	for _, entry := range process.MinimalEnvironment() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "HOME", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS":
			continue
		}
		env = append(env, entry)
	}
	return append(env, "HOME="+noClientConfig, "XDG_CONFIG_HOME="+noClientConfig, "XDG_CONFIG_DIRS="+noClientConfig)
}

// buildEnv returns process environment variables with PBS credentials injected.
// The namespace is set here too, though only the 4.x client reads it: the
// commands that take --ns are given it by targetArgs, which is what the 3.x
// client obeys.
func (c *Client) buildEnv() []string {
	env := clientEnvironment()
	if c.cfg.Repository != "" {
		env = append(env, fmt.Sprintf("PBS_REPOSITORY=%s", c.cfg.Repository))
	}
	if c.cfg.Password != "" {
		env = append(env, fmt.Sprintf("PBS_PASSWORD=%s", c.cfg.Password))
	}
	if c.cfg.Fingerprint != "" {
		env = append(env, fmt.Sprintf("PBS_FINGERPRINT=%s", c.cfg.Fingerprint))
	}
	if c.cfg.Namespace != "" {
		env = append(env, fmt.Sprintf("PBS_NAMESPACE=%s", c.cfg.Namespace))
	}
	if c.cfg.EncryptionPassword != "" {
		env = append(env, fmt.Sprintf("PBS_ENCRYPTION_PASSWORD=%s", c.cfg.EncryptionPassword))
	}
	return env
}

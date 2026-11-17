// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const configSnapshot = "vm/7011/2026-09-27T03:00:00Z"

// paddedConfig is a valid VM configuration of exactly total bytes: ordinary
// fields followed by short comment lines, so that the per-line limit is not
// what stops it.
func paddedConfig(t *testing.T, total int) string {
	t.Helper()
	const base = "cores: 4\nsockets: 2\nmemory: 4096\nbios: seabios\nscsihw: virtio-scsi-single\nostype: l26\nscsi0: local-lvm:vm-7011-disk-0,size=32G\n"
	pad := total - len(base)
	if pad < 0 {
		t.Fatalf("total %d is smaller than the base configuration", total)
	}
	config := base + strings.Repeat("#\n", pad/2) + strings.Repeat("#", pad%2)
	if len(config) != total {
		t.Fatalf("configuration has %d bytes, want %d", len(config), total)
	}
	return config
}

// listingWithConfigSize is a snapshot listing whose configuration blob has the
// given size entry (a JSON value, or "" to list none) and one disk.
func listingWithConfigSize(size string) string {
	entry := `{"filename":"qemu-server.conf.blob","crypt-mode":"none"`
	if size != "" {
		entry += `,"size":` + size
	}
	entry += "}"
	return "[" + entry + `,{"filename":"drive-scsi0.img.fidx","crypt-mode":"none","size":34359738368}]`
}

// loadBoth runs both loaders on the snapshot against the same fake client and
// returns their errors and the scratch directory they used.
func loadBoth(t *testing.T) (layoutErr, profileErr error, scratch string) {
	t.Helper()
	scratch = t.TempDir()
	client := &Client{}
	_, layoutErr = client.LoadVMLayout(context.Background(), configSnapshot, scratch)
	_, profileErr = client.LoadVMProfile(context.Background(), configSnapshot, scratch)
	return layoutErr, profileErr, scratch
}

func restoreCalls(t *testing.T, log string) int {
	t.Helper()
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(calls), "qemu-server.conf.blob")
}

func mustBeEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the scratch directory still holds %d entries after the load, e.g. %s", len(entries), entries[0].Name())
	}
}

// A 16 MiB configuration that its listing advertises at 16 MiB. A listing
// that advertises more than a configuration can be is refused by both loaders
// before anything is restored, so neither restores, reads and copies all of
// it.
func TestAnAdvertisedConfigurationOverTheLimitIsNeverRestored(t *testing.T) {
	const configBytes = 16 << 20
	log := fakeBackupClient(t, listingWithConfigSize(fmt.Sprint(configBytes)), paddedConfig(t, configBytes))
	layoutErr, profileErr, scratch := loadBoth(t)
	for name, err := range map[string]error{"LoadVMLayout": layoutErr, "LoadVMProfile": profileErr} {
		if err == nil || !strings.Contains(err.Error(), "lists its VM configuration") || !strings.Contains(err.Error(), fmt.Sprint(maxRestoredConfigBytes)) {
			t.Errorf("%s: err %v, want the listed size refused with the limit named", name, err)
		}
	}
	if n := restoreCalls(t, log); n != 0 {
		t.Errorf("the configuration was restored %d times, want never", n)
	}
	mustBeEmpty(t, scratch)
}

// The listing is advice. A configuration that restores to more than
// the limit is refused whatever the listing says, lists nothing, or cannot be
// read as a number, and one of exactly the limit is accepted; the private
// restore directory is gone either way.
func TestARestoredConfigurationOverTheLimitIsRefusedWhateverTheListingSays(t *testing.T) {
	for name, size := range map[string]string{
		"a small size":      "1024",
		"no size":           "",
		"a size of null":    "null",
		"a size of text":    `"large"`,
		"a negative size":   "-1",
		"a fractional size": "1.5",
		"at the limit":      fmt.Sprint(maxRestoredConfigBytes),
	} {
		t.Run(name, func(t *testing.T) {
			log := fakeBackupClient(t, listingWithConfigSize(size), paddedConfig(t, maxRestoredConfigBytes+1))
			layoutErr, profileErr, scratch := loadBoth(t)
			for loader, err := range map[string]error{"LoadVMLayout": layoutErr, "LoadVMProfile": profileErr} {
				if err == nil || !strings.Contains(err.Error(), "is larger than the") {
					t.Errorf("%s: err %v, want the oversized restore refused", loader, err)
				}
			}
			if n := restoreCalls(t, log); n != 2 {
				t.Errorf("restore calls = %d, want 2 (the listing gave no reason to refuse)", n)
			}
			mustBeEmpty(t, scratch)
		})
	}

	log := fakeBackupClient(t, listingWithConfigSize("1024"), paddedConfig(t, maxRestoredConfigBytes))
	layoutErr, profileErr, scratch := loadBoth(t)
	if layoutErr != nil || profileErr != nil {
		t.Fatalf("a configuration of exactly %d bytes: layout %v, profile %v", maxRestoredConfigBytes, layoutErr, profileErr)
	}
	if n := restoreCalls(t, log); n != 2 {
		t.Errorf("restore calls = %d, want 2", n)
	}
	mustBeEmpty(t, scratch)
}

// The restored object must be a regular file. A client that leaves a
// named pipe at the path is refused at once, not waited on.
func TestARestoredConfigurationThatIsNotARegularFileIsRefused(t *testing.T) {
	fakeBackupClient(t, listingWithConfigSize("1024"), "cores: 1\n")
	dir := strings.Split(os.Getenv("PATH"), ":")[0]
	script := filepath.Join(dir, "proxmox-backup-client")
	text, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	// Where the fake client copies the configuration into place, have it make
	// a named pipe there instead.
	copyConfig := regexp.MustCompile(`cp \S+/qemu-server\.conf "\$last"`)
	replaced := copyConfig.ReplaceAllLiteralString(string(text), `mkfifo "$last"`)
	if replaced == string(text) {
		t.Fatal("the fake client was not changed")
	}
	if err := os.WriteFile(script, []byte(replaced), 0o755); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	scratch := t.TempDir()
	go func() {
		_, err := (&Client{}).LoadVMLayout(context.Background(), configSnapshot, scratch)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "read restored PBS VM configuration") {
			t.Fatalf("err %v, want the named pipe refused", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reading a named pipe as the restored configuration did not return")
	}
	mustBeEmpty(t, scratch)
}

// The parsers keep the same total limit for any caller, and their
// behaviour at the boundary is exact.
func TestTheConfigurationParsersHaveATotalLimit(t *testing.T) {
	if _, err := ParseVMLayout([]byte(paddedConfig(t, maxRestoredConfigBytes))); err != nil {
		t.Errorf("ParseVMLayout at the limit: %v", err)
	}
	if _, err := ParseVMProfile([]byte(paddedConfig(t, maxRestoredConfigBytes))); err != nil {
		t.Errorf("ParseVMProfile at the limit: %v", err)
	}
	if _, err := ParseVMLayout([]byte(paddedConfig(t, maxRestoredConfigBytes+1))); err == nil || !strings.Contains(err.Error(), "more than the") {
		t.Errorf("ParseVMLayout one byte over: %v", err)
	}
	if _, err := ParseVMProfile([]byte(paddedConfig(t, maxRestoredConfigBytes+1))); err == nil || !strings.Contains(err.Error(), "more than the") {
		t.Errorf("ParseVMProfile one byte over: %v", err)
	}
}

func TestParseSnapshotConfigBytes(t *testing.T) {
	for name, tc := range map[string]struct {
		listing string
		want    int64
		listed  bool
	}{
		"a size":                    {listingWithConfigSize("2048"), 2048, true},
		"zero":                      {listingWithConfigSize("0"), 0, true},
		"no size":                   {listingWithConfigSize(""), 0, false},
		"a numeric string":          {listingWithConfigSize(`"2048"`), 2048, true},
		"text":                      {listingWithConfigSize(`"large"`), 0, false},
		"negative":                  {listingWithConfigSize("-5"), 0, false},
		"not a listing":             {`{"files":[]}`, 0, false},
		"invalid JSON":              {`[`, 0, false},
		"no configuration at all":   {`[{"filename":"drive-scsi0.img.fidx","size":99}]`, 0, false},
		"two entries, larger wins":  {`[{"filename":"qemu-server.conf.blob","size":10},{"filename":"qemu-server.conf.blob","size":9000000}]`, 9000000, true},
		"another file's size alone": {`[{"filename":"fw.conf.blob","size":9000000}]`, 0, false},
	} {
		got, listed := ParseSnapshotConfigBytes([]byte(tc.listing))
		if got != tc.want || listed != tc.listed {
			t.Errorf("%s: ParseSnapshotConfigBytes = %d, %v; want %d, %v", name, got, listed, tc.want, tc.listed)
		}
	}
}

// The restore of the configuration is interruptible. A client that has written
// part of the configuration and then hangs is stopped when the caller cancels,
// both loaders return at once with the restore as the step that failed and
// nothing of the partial file, the client process is gone, and the private
// restore directory is removed. Without the cancellation the loaders wait out
// the restore's 30-second limit with the client running on.
func TestCancellingTheRestoreOfTheConfigurationStopsItAndLeavesNothing(t *testing.T) {
	loaders := map[string]func(ctx context.Context, scratch string) (any, error){
		"LoadVMLayout": func(ctx context.Context, scratch string) (any, error) {
			return (&Client{}).LoadVMLayout(ctx, configSnapshot, scratch)
		},
		"LoadVMProfile": func(ctx context.Context, scratch string) (any, error) {
			return (&Client{}).LoadVMProfile(ctx, configSnapshot, scratch)
		},
	}
	for name, load := range loaders {
		t.Run(name, func(t *testing.T) {
			fakeBackupClient(t, listingWithConfigSize("1024"), "cores: 1\n")
			pidFile := filepath.Join(t.TempDir(), "restore.pid")
			script := filepath.Join(strings.Split(os.Getenv("PATH"), ":")[0], "proxmox-backup-client")
			text, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			// Where the fake client copies the configuration into place, have it
			// write the start of one, record its process ID, and stay.
			copyConfig := regexp.MustCompile(`cp \S+/qemu-server\.conf "\$last"`)
			hung := copyConfig.ReplaceAllLiteralString(string(text), `printf 'cores: 2
' > "$last"; echo $$ > `+pidFile+`; exec sleep 300`)
			if hung == string(text) {
				t.Fatal("the fake client was not changed")
			}
			if err := os.WriteFile(script, []byte(hung), 0o755); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			scratch := t.TempDir()
			type outcome struct {
				result any
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				result, err := load(ctx, scratch)
				done <- outcome{result, err}
			}()

			// Wait until the restore is running.
			var pid int
			deadline := time.Now().Add(10 * time.Second)
			for pid == 0 && time.Now().Before(deadline) {
				if data, err := os.ReadFile(pidFile); err == nil {
					pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
				}
				time.Sleep(10 * time.Millisecond)
			}
			if pid == 0 {
				t.Fatal("the restore never started")
			}
			defer func() {
				if process, err := os.FindProcess(pid); err == nil {
					_ = process.Kill() // whatever a failing run left behind
				}
			}()

			cancel()
			select {
			case got := <-done:
				if got.err == nil || !strings.Contains(got.err.Error(), "restore PBS VM configuration") {
					t.Errorf("err = %v, want the restore reported as stopped", got.err)
				}
				if layout, ok := got.result.(VMLayout); ok && (layout.BIOS != "" || len(layout.Disks) != 0) {
					t.Errorf("the partial configuration was used: %+v", layout)
				}
				if profile, ok := got.result.(VMProfile); ok && profile.Cores != 0 {
					t.Errorf("the partial configuration was used: %+v", profile)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("cancelling the context did not stop the restore")
			}
			if ctx.Err() == nil {
				t.Error("the context was not cancelled")
			}
			// The client is gone, not left running.
			if _, err := os.Stat("/proc/self"); err == nil {
				gone := false
				for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
					if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); os.IsNotExist(err) {
						gone = true
						break
					}
				}
				if !gone {
					t.Errorf("the PBS client (process %d) is still running after the cancellation", pid)
				}
			}
			mustBeEmpty(t, scratch)
		})
	}
}

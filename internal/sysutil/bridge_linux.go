//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ifupdownLockFile is the lock ifreload, ifup and ifdown hold for their
// whole run; procLocks lists the kernel's file locks. Tests replace both.
var (
	ifupdownLockFile = "/run/network/.lock"
	procLocks        = "/proc/locks"
)

// ifupdownRunning reports whether ifupdown2 is at work on the node. It
// reads who holds ifupdown2's lock, and never takes it: ifupdown2 locks
// without waiting and would fail. The process name is no help: ifreload is
// a Python script started through env, so its comm is "python3".
// Without the lock file, it looks for an ifupdown2 command line.
func ifupdownRunning() bool {
	busy, unknown := ifupdownState()
	return busy || unknown != ""
}

// ifupdownState is ifupdownRunning with the reason it cannot say: unknown is
// set when neither the lock nor the process list could be read in full, and the
// answer false is then not evidence that ifupdown2 is idle.
func ifupdownState() (busy bool, unknown string) {
	if held, known := ifupdownLockHeld(); known {
		return held, ""
	}
	return ifupdownProcessState()
}

// ifupdownLockHeld reports whether a process holds a lock on ifupdown2's
// lock file, from /proc/locks ("1: FLOCK ADVISORY WRITE 812 00:19:1234 0
// EOF"; a waiting lock has "->" after its number). known is false when the
// lock file or /proc/locks cannot be read.
func ifupdownLockHeld() (held, known bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(ifupdownLockFile, &st); err != nil {
		return false, false
	}
	dev := uint64(st.Dev)
	major := (dev >> 8 & 0xfff) | (dev >> 32 & ^uint64(0xfff))
	minor := (dev & 0xff) | (dev >> 12 & ^uint64(0xff))
	want := fmt.Sprintf("%02x:%02x:%d", major, minor, st.Ino)
	data, err := os.ReadFile(procLocks)
	if err != nil {
		return false, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[1] == "->" {
			continue
		}
		for _, field := range fields {
			if field == want {
				return true, true
			}
		}
	}
	return false, true
}

// ifupdownProcessState looks for ifreload, ifup or ifdown by command
// line: the program, or the script an interpreter runs. A process that ended
// while the list was read is nothing; a process list or a command line that
// cannot be read for any other reason leaves the answer unknown.
func ifupdownProcessState() (running bool, unknown string) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return false, "the process list cannot be read: " + err.Error()
	}
	unreadable := 0
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(procDir, entry.Name(), "cmdline"))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ESRCH) {
				unreadable++
			}
			continue
		}
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		for i := 0; i < len(args) && i < 2; i++ {
			if ifupdownTools[filepath.Base(args[i])] {
				return true, ""
			}
		}
	}
	if unreadable > 0 {
		return false, fmt.Sprintf("%d process command lines cannot be read", unreadable)
	}
	return false, ""
}

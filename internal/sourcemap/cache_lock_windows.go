// Copyright 2026 Erst Users
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sourcemap

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

const (
	// LockFileEx flags
	LOCKFILE_EXCLUSIVE_LOCK   = 0x00000002
	LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
)

// Error codes from Windows
const (
	ERROR_LOCK_VIOLATION = 0x21
)

func (sc *SourceCache) acquireLock(entryPath string, exclusive bool) (*os.File, error) {
	lp := sc.lockPath(entryPath)
	lf, err := os.OpenFile(lp, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %q: %w", lp, err)
	}

	// Set the file to not inherit by child processes (Windows best practice for locks)
	if err := windows.SetHandleInformation(windows.Handle(lf.Fd()), windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		// Non-fatal, but log warning in production
	}

	var flags uint32 = 0
	if exclusive {
		flags |= LOCKFILE_EXCLUSIVE_LOCK
	}

	// Lock the entire file (offset 0, length 0 means entire file)
	// Retry with exponential backoff to handle contention
	var attempts int
	for {
		err := windows.LockFileEx(windows.Handle(lf.Fd()), flags, 0, 1, 0, &windows.Overlapped{})
		if err == nil {
			return lf, nil
		}

		// Check if it's a lock violation (another process holds the lock)
		if err == windows.ErrLockViolation || err.(windows.Errno) == ERROR_LOCK_VIOLATION {
			attempts++
			if attempts >= 10 {
				_ = lf.Close()
				return nil, fmt.Errorf("timeout waiting for lock on %q: %w", lp, err)
			}
			// Exponential backoff: 1ms, 2ms, 4ms, 8ms, 16ms...
			sleepMs := 1 << (attempts - 1)
			if sleepMs > 100 {
				sleepMs = 100
			}
			windows.Sleep(uint32(sleepMs))
			continue
		}

		// Other error - fail
		_ = lf.Close()
		return nil, fmt.Errorf("LockFileEx failed on %q: %w", lp, err)
	}
}

func (sc *SourceCache) releaseLock(lf *os.File) {
	// Unlock the entire file
	windows.UnlockFile(windows.Handle(lf.Fd()), 0, 0, 1, 0)
	_ = lf.Close()
}

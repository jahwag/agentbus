//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package bus

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type databaseLock struct {
	file *os.File
}

func acquireDatabaseLock(path string) (*databaseLock, error) {
	if path == ":memory:" {
		return &databaseLock{}, nil
	}
	// Lock the database inode itself. A path-adjacent lock file can be bypassed
	// with symlink or hardlink aliases, which would admit a second daemon and
	// break in-process wakeups (and can split SQLite WAL sidecars).
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrDatabaseInUse
		}
		return nil, err
	}
	return &databaseLock{file: file}, nil
}

func (l *databaseLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(unlockErr, closeErr)
}

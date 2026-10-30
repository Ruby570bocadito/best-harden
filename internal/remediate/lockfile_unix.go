//go:build !windows

package remediate

import (
	"errors"
	"os"
	"syscall"
)

// tryLockFile toma un bloqueo exclusivo del fichero sin esperar. El sistema
// lo libera solo si el proceso muere: no hay bloqueos abandonados.
func tryLockFile(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

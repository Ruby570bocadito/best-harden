//go:build !windows

package remediate

import (
	"errors"
	"syscall"
)

// processAlive indica si existe un proceso con ese PID (señal 0: no envía
// nada, solo comprueba). EPERM significa que existe pero es de otro usuario.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

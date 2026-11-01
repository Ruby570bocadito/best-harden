//go:build linux

package schedule

// New devuelve el planificador del sistema.
func New() (Scheduler, error) { return newUnix(), nil }

// NewDeadman devuelve cómo armar el dead-man switch en este sistema.
func NewDeadman() (Deadman, error) { return newUnix(), nil }

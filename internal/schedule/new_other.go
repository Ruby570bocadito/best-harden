//go:build !linux && !windows

package schedule

// New devuelve el planificador del sistema.
func New() (Scheduler, error) { return nil, ErrUnsupported }

// NewDeadman devuelve cómo armar el dead-man switch en este sistema.
func NewDeadman() (Deadman, error) { return nil, ErrUnsupported }

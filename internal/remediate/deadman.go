package remediate

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// SpawnDeadman lanza "adarve deadman <id>" como proceso independiente:
// sobrevive al cierre de la terminal o de la sesión, pero no a un reinicio.
// Es el último recurso cuando no se puede armar como tarea del sistema (ver
// armDeadman en internal/cli).
func SpawnDeadman(storeDir, id string, timeout time.Duration) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(storeDir, id, "deadman.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(exe, "deadman", id, "--timeout", timeout.String())
	cmd.Stdout, cmd.Stderr = logf, logf
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

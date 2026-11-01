package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/config"
	"github.com/Ruby570bocadito/adarve/internal/remediate"
	"github.com/Ruby570bocadito/adarve/internal/report"
	"github.com/Ruby570bocadito/adarve/internal/schedule"
)

// armDeadman arma el dead-man switch del cambio id. Primero como tarea del
// sistema (un servicio de systemd o una tarea de SYSTEM del Programador de
// tareas), que sobrevive al cierre de la sesión y a un reinicio. Si no se
// puede, como proceso independiente, que solo sobrevive al cierre de la
// sesión, y lo avisa.
func armDeadman(s report.Style, storeDir, id string, timeout time.Duration) error {
	err := armDeadmanTask(id)
	if err == nil {
		fmt.Printf("  %s %s\n", s.Dim("·"), s.Dim("Dead-man switch armado como tarea del sistema: actúa aunque se corte la sesión o se reinicie el equipo."))
		return nil
	}
	fmt.Printf("  %s El dead-man switch no sobrevivirá a un reinicio (%s): no reinicies el equipo hasta confirmar o hasta que venza el plazo.\n",
		s.Yellow(report.Sym("⚠")), report.Clean(err.Error()))
	return remediate.SpawnDeadman(storeDir, id, timeout)
}

func armDeadmanTask(id string) error {
	// La tarea del sistema no hereda el entorno: con ADARVE_HOME (que con
	// privilegios exige --trust-env) no encontraría estas instantáneas.
	if config.Env("HOME") != "" {
		return errors.New("con ADARVE_HOME solo se puede armar como proceso independiente")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	// La tarea arranca como SYSTEM o root en cada inicio: si un usuario sin
	// privilegios puede sustituir el ejecutable, obtiene esos privilegios.
	if err := schedule.SafeExecutable(exe); err != nil {
		return err
	}
	d, err := schedule.NewDeadman()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := d.ArmDeadman(ctx, exe, id); err != nil {
		_ = d.DisarmDeadman(ctx, id, true) // que no quede armado a medias
		return err
	}
	return nil
}

// disarmDeadman retira la tarea del sistema del dead-man switch, si la hay.
// Con stop, también detiene la que espera al plazo.
func disarmDeadman(id string, stop bool) error {
	d, err := schedule.NewDeadman()
	if err != nil {
		return nil // sin tareas del sistema: no hay nada que retirar
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return d.DisarmDeadman(ctx, id, stop)
}

// runDeadman es «adarve deadman <id>». Como tarea del sistema arranca ya y
// en cada inicio del equipo hasta que se desarma, y no tiene consola: lo
// que hace queda en snapshots/<id>/deadman.log.
func runDeadman(id string, timeout time.Duration) error {
	if !remediate.ValidChangeID(id) {
		return fmt.Errorf("ID de cambio inválido: %q", id)
	}
	store := snapshotStore()
	logf := deadmanLogger(store.Dir, id)
	logf("dead-man switch en marcha")
	done, err := remediate.RunDeadman(context.Background(), store, id, timeout)
	switch {
	case err != nil && done:
		logf("nada que vigilar: " + err.Error())
	case err != nil:
		logf("error: " + err.Error() + ". Sigue armado: se reintentará en el siguiente arranque (o usa adarve rollback " + id + ")")
	default:
		logf(deadmanOutcome(store, id))
	}
	if done {
		if err := disarmDeadman(id, false); err != nil {
			logf("no se pudo retirar la tarea del dead-man switch: " + err.Error())
		}
	}
	if err != nil {
		return &ExitError{Code: 1}
	}
	return nil
}

// deadmanOutcome resume en qué quedó el acceso remoto del cambio.
func deadmanOutcome(store *remediate.Store, id string) string {
	m, err := store.Load(id)
	switch {
	case err != nil:
		return "terminado"
	case m.DeadmanFired:
		return "acceso remoto no confirmado a tiempo: cambios de acceso remoto deshechos"
	case m.Confirmed:
		return "acceso remoto confirmado: no hay nada que deshacer"
	}
	return "no queda nada que deshacer"
}

func deadmanLogger(dir, id string) func(string) {
	path := filepath.Join(dir, id, "deadman.log")
	return func(msg string) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return
		}
		defer f.Close()
		fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), msg)
	}
}

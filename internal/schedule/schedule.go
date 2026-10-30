// Package schedule programa el análisis diario de Bastion en el planificador
// del sistema: el Programador de tareas en Windows y un temporizador de
// systemd (o cron, si no hay systemd) en Linux. La tarea ejecuta
// "bastion schedule run", que guarda un escaneo y un análisis de superficie
// y anota el resultado en schedule.log.
package schedule

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ErrUnsupported indica que no hay planificador conocido en este sistema.
var ErrUnsupported = errors.New("la programación no está disponible en este sistema")

// Status describe la tarea programada.
type Status struct {
	Enabled   bool   `json:"enabled"`
	Mechanism string `json:"mechanism,omitempty"` // Programador de tareas, systemd, cron
	At        string `json:"at,omitempty"`        // HH:MM
	Command   string `json:"command,omitempty"`
	NextRun   string `json:"next_run,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

var reAt = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// ValidAt comprueba una hora HH:MM (24 h).
func ValidAt(at string) error {
	if !reAt.MatchString(at) {
		return fmt.Errorf("hora %q no válida: usa HH:MM en formato de 24 horas, p. ej. 09:00", at)
	}
	return nil
}

// Run es una ejecución anotada en schedule.log.
type Run struct {
	Time      time.Time `json:"time"`
	ScanScore int       `json:"scan_score"`
	// ScanUnscored indica que no se pudo evaluar ningún control (ScanScore 0
	// no es una puntuación).
	ScanUnscored bool `json:"scan_unscored,omitempty"`
	SurfaceScore int  `json:"surface_score"`
	// Regressions cuenta los controles que han pasado de superados a
	// fallidos y NewExposure, los cambios que aumentan la exposición, desde
	// el análisis anterior.
	Regressions int      `json:"regressions"`
	NewExposure int      `json:"new_exposure"`
	Errors      []string `json:"errors,omitempty"`
	// NotifyErrors son los avisos que no se pudieron dar (Visor de eventos
	// o syslog, webhook). No cambian el resultado de la ejecución.
	NotifyErrors []string `json:"notify_errors,omitempty"`
}

// maxLog es el número de ejecuciones que se conservan en schedule.log.
const maxLog = 400

// LogPath es el fichero de ejecuciones dentro del directorio de datos.
func LogPath(dataDir string) string { return filepath.Join(dataDir, "schedule.log") }

// AppendRun añade una ejecución al registro (JSON por línea) y recorta las
// más antiguas.
func AppendRun(path string, r Run) error {
	runs, _ := ReadRuns(path)
	runs = append(runs, r)
	if len(runs) > maxLog {
		runs = runs[len(runs)-maxLog:]
	}
	var b strings.Builder
	for _, x := range runs {
		line, err := json.Marshal(x)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadRuns lee el registro de ejecuciones, de la más antigua a la última.
func ReadRuns(path string) ([]Run, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Run
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Run
		if json.Unmarshal(sc.Bytes(), &r) == nil && !r.Time.IsZero() {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}

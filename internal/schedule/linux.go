package schedule

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Unix (Linux): temporizador de systemd si el sistema arranca con systemd;
// si no, una entrada en /etc/cron.d. root y run se sustituyen en las
// pruebas para no tocar el sistema.
type unixScheduler struct {
	root string // prefijo de rutas ("" en un sistema real)
	run  func(ctx context.Context, name string, args ...string) (string, error)
}

const (
	unitName    = "adarve-scan"
	servicePath = "/etc/systemd/system/adarve-scan.service"
	timerPath   = "/etc/systemd/system/adarve-scan.timer"
	cronPath    = "/etc/cron.d/adarve"

	// La plantilla del dead-man switch: una instancia por cambio,
	// adarve-deadman@<cambio>.service.
	deadmanTemplate = "/etc/systemd/system/adarve-deadman@.service"

	// El análisis programado de Bastion, el nombre anterior de Adarve.
	legacyUnit    = "bastion-scan"
	legacyService = "/etc/systemd/system/bastion-scan.service"
	legacyTimer   = "/etc/systemd/system/bastion-scan.timer"
	legacyCron    = "/etc/cron.d/bastion"
)

// removeLegacy retira el análisis programado de Bastion, que ejecutaría un
// binario antiguo (o ya desinstalado).
func (u *unixScheduler) removeLegacy(ctx context.Context) {
	if _, err := os.Stat(u.path(legacyTimer)); err == nil {
		_, _ = u.run(ctx, "systemctl", "disable", "--now", legacyUnit+".timer")
		_ = os.Remove(u.path(legacyTimer))
		_ = os.Remove(u.path(legacyService))
		_, _ = u.run(ctx, "systemctl", "daemon-reload")
	}
	_ = os.Remove(u.path(legacyCron))
}

// newUnix lo usa new_linux.go; este fichero se compila en todas las plataformas
// para poder probar el planificador con systemd y cron en cualquier sistema.
//
//lint:ignore U1000 se usa en Linux (new_linux.go)
func newUnix() *unixScheduler {
	return &unixScheduler{run: func(ctx context.Context, name string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return string(out), nil
	}}
}

func (u *unixScheduler) path(p string) string { return filepath.Join(u.root, p) }

func (u *unixScheduler) systemd() bool {
	fi, err := os.Stat(u.path("/run/systemd/system"))
	return err == nil && fi.IsDir()
}

func serviceUnit(exe string) string {
	return fmt.Sprintf(`# Creado por «adarve schedule enable». Se elimina con «adarve schedule disable».
[Unit]
Description=Adarve: escaneo y superficie de ataque diarios
After=network-online.target

[Service]
Type=oneshot
ExecStart=%s schedule run
Nice=10
IOSchedulingClass=idle
# Un análisis colgado no debe bloquear el temporizador para siempre.
TimeoutStartSec=1h
# 3: la exposición ha crecido (queda anotado en schedule.log).
SuccessExitStatus=3
`, systemdQuote(exe))
}

func timerUnit(at string) string {
	return fmt.Sprintf(`# Creado por «adarve schedule enable». Se elimina con «adarve schedule disable».
[Unit]
Description=Adarve: análisis diario

[Timer]
OnCalendar=*-*-* %s:00
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
`, at)
}

func cronEntry(exe, at string) string {
	hh, mm, _ := strings.Cut(at, ":")
	return fmt.Sprintf("# Creado por «adarve schedule enable». Se elimina con «adarve schedule disable».\n"+
		"%s %s * * * root %s schedule run >/dev/null 2>&1\n", strings.TrimPrefix(mm, "0"), strings.TrimPrefix(hh, "0"), shellQuote(exe))
}

// systemdQuote escribe una ruta para ExecStart: entre comillas si tiene
// espacios y con % y $ escapados (systemd los expande como especificadores
// y variables).
func systemdQuote(p string) string {
	p = strings.NewReplacer("%", "%%", "$", "$$").Replace(p)
	if strings.ContainsAny(p, " \t\"\\'") {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p) + `"`
	}
	return p
}

// shellQuote escribe una ruta para la orden de una línea de cron: entre
// comillas simples si hace falta y con % escapado (cron lo convierte en un
// salto de línea incluso entre comillas).
func shellQuote(p string) string {
	q := p
	if strings.ContainsAny(p, " \t'\"$`\\;&|<>()*?#~!{}[]") {
		q = "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
	}
	return strings.ReplaceAll(q, "%", `\%`)
}

func (u *unixScheduler) Enable(ctx context.Context, exe, at string) (Status, error) {
	u.removeLegacy(ctx)
	if u.systemd() {
		if err := writeFile(u.path(servicePath), serviceUnit(exe)); err != nil {
			return Status{}, err
		}
		if err := writeFile(u.path(timerPath), timerUnit(at)); err != nil {
			return Status{}, err
		}
		_ = os.Remove(u.path(cronPath)) // por si se programó antes sin systemd
		if _, err := u.run(ctx, "systemctl", "daemon-reload"); err != nil {
			return Status{}, err
		}
		if _, err := u.run(ctx, "systemctl", "enable", "--now", unitName+".timer"); err != nil {
			return Status{}, err
		}
		return u.Get(ctx)
	}
	if err := writeFile(u.path(cronPath), cronEntry(exe, at)); err != nil {
		return Status{}, err
	}
	return u.Get(ctx)
}

func (u *unixScheduler) Disable(ctx context.Context) error {
	u.removeLegacy(ctx)
	if _, err := os.Stat(u.path(timerPath)); err == nil {
		_, _ = u.run(ctx, "systemctl", "disable", "--now", unitName+".timer")
		for _, p := range []string{timerPath, servicePath} {
			if err := os.Remove(u.path(p)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		_, _ = u.run(ctx, "systemctl", "daemon-reload")
	}
	if err := os.Remove(u.path(cronPath)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (u *unixScheduler) Get(ctx context.Context) (Status, error) {
	if b, err := os.ReadFile(u.path(timerPath)); err == nil {
		st := Status{Enabled: true, Mechanism: "systemd (" + unitName + ".timer)", At: timerAt(string(b))}
		if svc, err := os.ReadFile(u.path(servicePath)); err == nil {
			for _, l := range strings.Split(string(svc), "\n") {
				if strings.HasPrefix(l, "ExecStart=") {
					st.Command = strings.TrimPrefix(l, "ExecStart=")
				}
			}
		}
		if out, err := u.run(ctx, "systemctl", "is-enabled", unitName+".timer"); err != nil || strings.TrimSpace(out) != "enabled" {
			st.Enabled = false
			st.Detail = "el temporizador existe pero no está activado: adarve schedule enable lo activa"
		}
		if out, err := u.run(ctx, "systemctl", "show", "-p", "NextElapseUSecRealtime", "--value", unitName+".timer"); err == nil {
			st.NextRun = strings.TrimSpace(out)
		}
		return st, nil
	}
	if b, err := os.ReadFile(u.path(cronPath)); err == nil {
		st := Status{Enabled: true, Mechanism: "cron (" + cronPath + ")"}
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) >= 7 && !strings.HasPrefix(l, "#") {
				hh, err1 := strconv.Atoi(f[1])
				mm, err2 := strconv.Atoi(f[0])
				if err1 == nil && err2 == nil {
					st.At = fmt.Sprintf("%02d:%02d", hh, mm)
				}
				st.Command = strings.Join(f[6:], " ")
			}
		}
		return st, nil
	}
	return Status{}, nil
}

// timerAt extrae HH:MM de OnCalendar=*-*-* HH:MM:00.
func timerAt(unit string) string {
	for _, l := range strings.Split(unit, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "OnCalendar=*-*-* "); ok && len(v) >= 5 {
			return v[:5]
		}
	}
	return ""
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func deadmanUnitName(id string) string { return "adarve-deadman@" + id + ".service" }

// deadmanUnit es la plantilla del dead-man switch. Type=simple: arrancarla
// no espera al plazo, ni en el inicio del equipo.
func deadmanUnit(exe string) string {
	return fmt.Sprintf(`# Creado por «adarve harden --include-remote». Cada cambio de acceso remoto
# activa una instancia (adarve-deadman@<cambio>.service) que se desactiva al
# confirmarlo o al deshacerlo.
[Unit]
Description=Adarve: dead-man switch del acceso remoto (%%i)
After=local-fs.target

[Service]
Type=simple
ExecStart=%s deadman %%i

[Install]
WantedBy=multi-user.target
`, systemdQuote(exe))
}

// ArmDeadman activa adarve-deadman@<id>.service: arranca ya y en cada
// inicio del equipo. Como servicio de systemd queda fuera de la sesión SSH,
// así que tampoco lo termina logind al cerrarla (KillUserProcesses=yes).
func (u *unixScheduler) ArmDeadman(ctx context.Context, exe, id string) error {
	if err := checkDeadmanID(id); err != nil {
		return err
	}
	if !u.systemd() {
		return fmt.Errorf("%w: el sistema no arranca con systemd", ErrUnsupported)
	}
	if err := writeFile(u.path(deadmanTemplate), deadmanUnit(exe)); err != nil {
		return err
	}
	if _, err := u.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err := u.run(ctx, "systemctl", "enable", "--now", deadmanUnitName(id))
	return err
}

func (u *unixScheduler) DisarmDeadman(ctx context.Context, id string, stop bool) error {
	if err := checkDeadmanID(id); err != nil {
		return err
	}
	if _, err := os.Stat(u.path(deadmanTemplate)); err != nil || !u.systemd() {
		return nil // no se armó como servicio de systemd
	}
	args := []string{"disable"}
	if stop {
		args = append(args, "--now")
	}
	_, err := u.run(ctx, "systemctl", append(args, deadmanUnitName(id))...)
	return err
}
